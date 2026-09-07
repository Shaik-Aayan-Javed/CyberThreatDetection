# Defect Register

Every defect found by an internal audit of the ingest, feature and detection
layers, with root cause and remedy. Recorded here rather than left for a
reviewer to find.

Line references are to modules and functions rather than absolute line numbers,
because several of these have been fixed and the numbers have moved.

**Status summary — 7 fixed, 16 open.**

| # | Defect | Layer | Severity | Status |
|---|---|---|---|---|
| 1 | Unbounded flow table (OOM under spoofed flood) | ingest | **Critical** | **Fixed** |
| 2 | "Learned" baseline was a permanent floor clamp | features | **Critical** | **Fixed** |
| 3 | `completion_ratio` returned 1.0 with no SYNs — dead model feature | features | **Critical** | **Fixed** |
| 4 | Baseline medians polluted by pure-destination rows | features | Medium | **Fixed** |
| 5 | Dead warm-up branch in `Metric.value` | features | Low | **Fixed** |
| 6 | `_last_sweep = 0.0` made sweep throttle epoch-sensitive | ingest | Low | **Fixed** |
| 7 | Training population is 94% responders, not monitored hosts | features | **Critical** | Open — documented |
| 8 | DNS visible only on UDP/53, query side, first question | ingest | High | **Fixed** |
| 9 | DNS-based beaconing unreachable by construction | features | High | Open |
| 10 | Windower files packets into the wrong window after a gap | ingest | High | Open |
| 11 | No fragment reassembly, no tunnel decap, ICMPv6 misclassified | ingest | High | Open |
| 12 | `split_domain` over-merges unlisted public suffixes | detectors | High | Open |
| 13 | SYN flood detector cannot fire on non-TCP floods | detectors | High | Open |
| 14 | `flush()` gives the trailing window a non-nominal duration | ingest | Medium | Open |
| 15 | Empty windows are never emitted | ingest | Medium | Open |
| 16 | `malformed` conflates "not IP" with "corrupt" | ingest | Medium | Open |
| 17 | ICMP/OTHER collapse to one flow per host pair | ingest | Medium | Open |
| 18 | Blanket `except Exception` hides parser bugs | ingest | Medium | Open |
| 19 | Flow expiry driven by capture time only | ingest | Medium | Open |
| 20 | Four baselines declared but never observed | features | Medium | Open |
| 21 | Amplification ratio is unrepresentable | features | Medium | Open |
| 22 | DGA and tunnelling indistinguishable to a machine | detectors | Medium | Open |
| 23 | `spoofed` is a label, not a gate | detectors | Medium | Open |

Several open defects — 11, 17, 19 and part of 16 — have **zero observable
impact on the synthetic captures** and pass every check in `tools/selftest.py`.
They are real-traffic defects. Defect 18 is the mechanism that would keep them
invisible in production.

---

## Fixed

### 1. Unbounded flow table — OOM under a spoofed flood *(Critical)*

**What.** `FlowTable` evicted only on a 120 s idle timeout, swept at most once
per 30 s of capture time, with no cap on `len(self.flows)`.

**Why.** Eviction was purely `last_ts < now - idle_timeout`. Under a spoofed SYN
flood every record is *recent and short-lived*, so nothing is ever eligible —
timeouts are not a defence against cardinality. Worse, the sweep trigger was
capture time, which barely advances while millions of packets arrive.

**Impact.** At 100k unique-source pps, ~15 M records (≈400–600 B each) accumulate
before the first eviction is even eligible. The monitor dies during the attack it
exists to report.

**Fix (applied).** Three layers in `ingest/flows.py`: an active timeout
(`MAX_DURATION_S = 1800`) that force-expires and re-keys long-lived flows; a
hard cap (`MAX_FLOWS = 200_000`) checked *before* insertion; and forced eviction
of least-recently-active flows down to a 90 % watermark when timeouts are not
enough. A packet-count sweep trigger (`SWEEP_EVERY_PACKETS = 10_000`) runs
alongside the capture-time one so bursts cannot outrun the sweeper. Both
triggers are deterministic functions of the capture, so replay stays
reproducible.

Verified: 600,000 unique spoofed 5-tuples pushed at 100k pps against a 5,000 cap
held peak residency at exactly 5,000, with 0 idle expiries and 595,000 overflow
evictions — confirming the overflow path is the only thing that works under this
attack.

*Note on the watermark.* Evicting to exactly the cap would make the next insert
retrigger a full sweep, giving an O(n log n) sort per packet. Measured at 20k
cap: 238 s versus 0.15 s for the watermark version — a livelock that recreates
the denial of service the fix exists to prevent. `heapq.nsmallest` is used
rather than `sorted` for the same reason.

### 2. The "learned" baseline was a permanent floor clamp *(Critical)*

**What.** `Metric.value` returned `max(self.mean, self.floor)` in both branches
of its warm-up `if`, so the floor was a permanent lower clamp.

**Why.** On a quiet link the EWMA mean converges far below the floor and never
escapes it. Measured on `normal.pcap` after 61 windows: `target_syn_rate` mean
0.0 vs floor 10.0, `host_fanout_ports` 1.95 vs 8.0, `bytes_out` 1,726 vs 50,000.

**Impact.** Every threshold any detector computed derived from a dictionary
literal. The system was a fixed-threshold detector wearing an adaptive-baseline
API, and the documentation claimed adaptation that measurably did not occur. The
demo line "1,500 SYN/s against a learned baseline of 10" was quoting
`DEFAULTS["target_syn_rate"][1]`.

**Fix (applied).** The floor is now a genuine warm-up fallback returned only for
the first `WARMUP = 12` windows; afterwards the learned mean is returned with a
1e-6 epsilon for divide-by-zero safety only. Floors retuned to observed
magnitudes (`host_fanout_ports` 8→2, `target_syn_rate` 10→0.5, `bytes_out`
5e4→2e3). Verified: all four baselines now report learned values, and
`normal.pcap` still produces zero alerts.

Absolute minimums (`MIN_SYN_RATE`, `MIN_PORTS`, `MIN_HOSTS`) now frequently bind
instead — see `docs/MODEL.md` §2. That is a different and defensible situation:
an explicit engineering judgement rather than a constant masquerading as an
observation.

### 3. `completion_ratio` returned 1.0 with no SYNs — dead model feature *(Critical)*

**What.** `HostFeatures.completion_ratio` returned `1.0` when `syn_sent == 0`,
indistinguishable from "every handshake succeeded".

**Why.** The `else` branch of a ratio expression was used as a default rather
than as a signal that no measurement exists.

**Impact.** 241 of 256 training rows have no SYNs, so *every* training vector
reported 1.0. The column had zero variance, `StandardScaler` clamped its scale
to 1.0, and the IsolationForest could never split on it — a documented
ten-feature model was really nine-dimensional, and the lost dimension is the
most discriminative one for scans. It also fabricated analyst-facing evidence:
`anomaly.py` prints "N standard deviations from the benign mean" for a feature
whose true standard deviation was zero.

**Fix (applied).** Returns a `NO_COMPLETION_DATA = -1.0` sentinel, with a
`has_completion_data` property so callers test intent rather than compare
against a magic number. Verified: `scale_` went 1.0 → 0.4697 and the
zero-variance column list went from `['completion_ratio']` to empty. Model
retrained; mean ROC-AUC 0.997.

*Consumer guard.* `portscan.py` gates on `completion > MAX_COMPLETION`. The old
`1.0` failed that test and rejected the host; `-1.0` would have **passed** it,
newly admitting every SYN-less high-fanout host. It now rejects explicitly on
`not hf.has_completion_data`.

### 4. Baseline medians polluted by pure-destination rows *(Medium)*

**What.** `engine.update_baselines()` took medians over every row in the host
index, including rows created solely to record inbound bytes.

**Why.** `extract()` materialises a `HostFeatures` keyed on `pkt.dst` so the
out:in ratio has somewhere to live. Those rows have `packets == 0` and
structurally zero fan-out. Unlike the model path, `update_baselines` had no
`MIN_PACKETS` filter.

**Impact.** 62 such rows per capture dragged every median toward zero,
describing addresses that never transmitted. Small on symmetric synthetic
traffic; severe on a server-heavy segment where such rows are the majority.

**Fix (applied).** `HostFeatures.observed_as_source` is set only in the
`pkt.src` branch; `update_baselines` filters on it. `by_src` renamed `by_host`
so the structure stops claiming to be something it is not.

*Correction to the original finding.* These rows never reached the
IsolationForest — `MIN_PACKETS >= 20` already excluded them, since `packets` is
incremented only for senders. The training-set contamination is a different
mechanism; see defect 7.

### 5. Dead warm-up branch in `Metric.value` *(Low)*
Both arms of the warm-up `if` returned the identical expression. No runtime
effect, but it advertised a cold/warm distinction the code did not implement,
which is why defect 2 survived review. Removed as part of that fix.

### 6. `_last_sweep = 0.0` made the sweep throttle epoch-sensitive *(Low)*
Pcap timestamps are ~1.7×10⁹, so `now - 0.0` always cleared the interval and the
first packet swept a one-element table. Harmless there — but on a capture with
timestamps starting near zero the same expression suppresses *every* sweep for
the first 30 s of stream time. Now initialised to `None` and anchored on the
first packet.

### 8. DNS was visible only on UDP/53 *(High)*

**What.** `reader.py` extracted DNS only inside the UDP branch, so DNS-over-TCP/53,
mDNS/5353 and LLMNR/5355 were invisible.

**Why.** Two independent gates, and fixing either alone does nothing. The parser
guarded DNS behind `isinstance(l4, dpkt.udp.UDP)`, *and* `features/extract.py`
collected `dns_queries` inside its own `elif pkt.proto == "UDP"` branch — so a
TCP DNS packet that parsed correctly would still have been counted as ordinary
TCP and dropped before reaching the detector.

**Impact.** The entire DNS tunnel detector was bypassable with one flag:
`dig +tcp`. That is a standard red-team move, and TCP is what any tunnel uses
once it outgrows a 512-byte datagram — so the more data an operator exfiltrated,
the more likely we were to miss it.

**Fix (applied).** Port sets for UDP (`53, 5353, 5355`) and TCP (`53`), with the
RFC 1035 §4.2.2 two-byte length prefix stripped on TCP. DNS collection in
`extract()` hoisted out of the UDP branch entirely. Answer *count* is now
recorded (`dns_answers`) as shape metadata — no rdata is decoded or retained, so
the no-payload guarantee holds. `_attach_dns`'s bare `except` narrowed to the
parse errors, so a bug in our own code no longer degrades into silence.

Verified against a synthetic `dig +tcp` tunnel — 90 high-entropy TXT queries
under one parent, carried over TCP/53. Same capture, both code versions:
**0 alerts before the fix, 1 `DNS_ANOMALY` after.**

*Not joined.* All questions are counted (`dns_qcount`) but `dns_qname` still
holds only the first. `detectors/dns.py` runs `split_domain()` over that string,
and a joined `"a.com;b.com"` parses to the nonsense parent `"com;b.com"` —
corrupting the detector to record a case (qdcount > 1) that most resolvers
reject outright.

---

## Open

### 7. Training population is 94% responders *(Critical — documented, not fixed)*

**What.** Of 256 benign training rows, only 15 (5.9 %) initiated a flow or sent a
SYN. The rest are remote CDN edges — Google, Microsoft, Akamai, Fastly — whose
reply traffic crosses the tap.

**Why.** `extract()` credits flows only to `rec.src`, the flow initiator, and
nothing filters responders out. They transmit, so `observed_as_source` does not
separate them; the discriminating predicate is `syn_sent > 0 or len(flows) > 0`.

**Impact.** The model's notion of "normal host behaviour" is dominated by what a
server looks like from the outside. `syn_rate_pps` and `flow_rate_fps` are
near-constant zero columns, so a genuine client's ordinary SYN activity is
already several sigma out.

**Why not fixed.** Filtering to initiators leaves 15 vectors. Fitting a 200-tree
forest with `contamination=0.01` on 15 samples gives 0.15 expected outliers — a
degenerate model, not a cleaner one. The root cause is that `normal.pcap`
contains few internal clients with sustained traffic.

**Fix.** Either generate more benign client traffic in `data/generate.py` and
then filter to initiators, or add an initiator/responder flag as an 11th feature
and let the forest separate the populations. The second is cheaper but widens
the vector and invalidates the feature table in `docs/MODEL.md`. Both require a
retrain and a refresh of `docs/model_report.json`.

### 9. DNS-based beaconing unreachable by construction *(High)*
`extract()` excludes `dport == 53` from `contacts`, the beacon detector's only
input, so `MIN_CONTACTS` can never be reached for a DNS pair however metronomic
the queries. Roughly half of all UDP traffic is excluded from periodicity
analysis. C2 over DNS is common precisely because it survives egress filtering,
and the DNS detector does not close the gap — it fires on QNAME *shape*, so a
beacon resolving one short plausible name every 60 s scores neither DGA nor
tunnel.
**Fix.** Include DNS in `contacts` but de-duplicate per (src, dst, dport) per
window, so a burst of resolutions contributes one timing point. Expect false
positives from chatty recursive resolvers; `MAX_CV` will need re-tuning against
`normal.pcap`.

### 10. Windower files packets into the wrong window after a gap *(High)*
The roll-forward loop advances one window per iteration and breaks on the first
non-empty closed window, then appends unconditionally — so after a multi-window
gap the packet lands outside `[start, end)` while `duration` is still nominal.
That window's pps/bps are computed against a span it never covered, and the
first packet of a post-gap burst is amputated from its burst.
**Fix.** Return a list of closed windows and run the loop to completion; best
done together with defect 15, and requires touching the engine's window loop.

### 11. No fragment reassembly, no tunnel decap, ICMPv6 misclassified *(High)*
Non-first fragments stay raw bytes in dpkt and fall through to `proto="OTHER"`
with ports zeroed; GRE and IP-in-IP likewise; `isinstance(l4, dpkt.icmp.ICMP)`
is False for ICMPv6, so all of it — including NDP — is `OTHER`. An attacker who
fragments UDP exfil keeps only the first fragment's ports visible.
**Fix.** One-line win: add `dpkt.icmp6.ICMP6` to the ICMP branch. Then tag
fragments explicitly rather than bucketing them, and unwrap one level of
GRE/IP-in-IP. A reassembly cache is itself unbounded state and needs the same
caps as defect 1.

### 12. `split_domain` over-merges unlisted public suffixes *(High)*
An 8-entry hand-rolled eTLD list means any domain under an unlisted multi-part
suffix collapses unrelated organisations into one detection key. `s3.amazonaws.com`,
`github.io`, `pages.dev`, `nic.in` all become "the parent". One host resolving 15
S3 buckets clears the tunnel gates on ordinary cloud traffic; conversely a real
tunnel under `evil.pp.ua` is attributed to the registry, and DGA lookups merged
with benign hostnames get their entropy averaged below threshold.
Concrete breaker: `ceo-mail.dept.nic.in` → parent `nic.in`, so every Indian
government department shares one bucket. (`nic` is already in the bigram corpus
but absent from the suffix list — the two disagree.)
**Fix.** Vendor a Public Suffix List snapshot and take the registrable domain.
Costs a dependency or a ~230 KB data file in an intentionally-inspectable MVP.

### 13. SYN flood detector cannot fire on non-TCP floods *(High)*
The `tf.syn_in < MIN_SYN_COUNT` gate runs before any rate test, and `syn_in` is
incremented only in the TCP branch, so UDP and ICMP floods are structurally
undetectable. No other detector backstops it. This is the PS class (a) gap.
**Fix.** Generalise the gate to a protocol-agnostic inbound-rate test and split
`UDP_FLOOD` into its own class, omitting completion ratio (meaningless for UDP).
Real amplification additionally needs defect 21.

### 14. `flush()` gives the trailing window a non-nominal duration *(Medium)*
`flush()` rewrites `w.end` to the last packet's timestamp, so the final window's
duration is an arbitrary fraction of nominal — exactly 0.0 if all its packets
share a timestamp. `extract()` clamps that to 1e-6, turning division into a rate
explosion: ≥40 SYNs in a 0.4 s tail reports 100 pps against a 50 pps floor, a
fabricated end-of-capture alert. Usually masked by the 20 s cooldown.
**Fix.** Keep `end` at the nominal boundary and expose `partial=True`, or drop
trailing windows covering less than ~20 % of nominal.

### 15. Empty windows are never emitted *(Medium)*
Windows with no packets are suppressed, so "traffic ceased" can never be
detected, baselines never decay during silence (a quiet period followed by
modest traffic is compared against a stale busy-hour baseline), and detector
pruning stalls.
**Fix.** Emit empty windows and let `extract()` produce a zero-count
`WindowFeatures`. Audit detectors for zero-guards first; costs throughput on
sparse captures.

### 16. `malformed` conflates "not IP" with "corrupt" *(Medium)*
ARP, STP, LLDP and genuine decode failures increment the same counter, and all
are excluded from `packets_read`/`bytes_read`. On any real capture the
"malformed" figure is dominated by perfectly well-formed L2 traffic — the tool
reports healthy background traffic as corruption on the dashboard.
**Fix.** Split into `non_ip` and `malformed`. Note `tools/selftest.py` asserts
`malformed == 0`; that assertion becomes strictly stronger and still passes.

### 17. ICMP and OTHER collapse to one flow per host pair *(Medium)*
Both carry `sport = dport = 0`, so the flow key degenerates to `(proto, src, dst)`.
Echo-request, destination-unreachable and time-exceeded merge into one record;
after defect 11, so do fragments, GRE and ESP. An ICMP tunnel cannot be
distinguished from a long-running ping.
**Fix.** Add `icmp_type`/`icmp_code` fields and include the echo identifier in
the key; include the IP protocol number for `OTHER`.

### 18. Blanket `except Exception` hides parser bugs *(Medium)*
The whole of `parse()` is wrapped in a catch-all reporting every failure as
"malformed", so `AttributeError`, `TypeError` and `KeyError` from our own code
degrade silently into a rising counter. If it hit a whole traffic class the tool
would quietly stop detecting on it. `_attach_dns` has the same pattern with an
even more silent `except: pass`. **This is the mechanism that would conceal
defects 11 and 17 in production.**
**Fix.** Narrow to `(dpkt.UnpackError, dpkt.NeedData, struct.error, IndexError,
ValueError)`, add a `parse_errors` counter, log the first N.

### 19. Flow expiry driven by capture time only *(Medium)*
`_maybe_sweep` is called only from `update()`, so eviction advances only when
packets arrive. A live tap that goes quiet holds its full flow table forever —
and the module docstring claims the idle timeout is "what makes the table usable
on a live stream that never ends", which is false. Backwards timestamps
(merged pcaps, NTP step) can also suppress sweeps or evict live flows.
**Fix.** Keep capture-time expiry as primary for replay determinism, add a
wall-clock floor, and guard against timestamp regression. Mixing clocks makes
eviction counts non-deterministic, so tests must assert bounds not equality.

### 20. Four baselines declared but never observed *(Medium)*
`src_entropy`, `out_in_ratio`, `dns_qname_entropy` and `dns_qname_len` are in
`DEFAULTS` but never `observe()`d and never read — all report `samples = 0`. They
still appear in `snapshot()`, which the dashboard renders as "learned baseline",
so dict literals are displayed to an operator as observations of the link.
**Fix.** Delete them, or wire them. `src_entropy` is the highest value: it would
let the SYN flood detector say "entropy 7.2 bits vs a learned 1.4" instead of an
unanchored number.

### 21. Amplification ratio is unrepresentable *(Medium — partially addressed)*
`TargetFeatures` counts UDP packets but has no `udp_bytes_in` and no
per-service-port byte breakdown. Defect 8's fix retains an answer *count*
(`dns_answers`) instead of discarding DNS responses outright, but that is a
packet count, not a byte total, and nothing reads it yet — there is still no
request/response *size* pairing anywhere in the feature layer.
**Fix.** Add `bytes_in_by_port` and `udp_bytes_in`, wire `dns_answers` into a
byte-aware equivalent, then a detector comparing per-port inbound volume against
outbound request volume. On a one-way tap you may only see the amplified half,
so scope the claim to "reflection observed at the victim".

### 22. DGA and tunnelling indistinguishable to a machine *(Medium)*
Both emit `threat_class = DNS_ANOMALY` with identical evidence field names and
severity; the distinction exists only as prose in an evidence note. Response
differs materially — DGA means sinkhole and hunt the host, tunnelling means block
the parent and open a data-loss investigation — but a SOAR rule can only tell
them apart by regex. The current output already shows the problem: the same
tunnelling episode is labelled "DGA-style" in one window and "DNS tunnelling" in
the next.
**Fix.** Add an optional `subtype` field to `Alert` (`DGA` / `TUNNEL` /
`DGA_TUNNEL`). The schema explicitly sanctions optional additions, so
`labels.json`, `bench/metrics.py` and the dashboard are unaffected.

### 23. `spoofed` is a label, not a gate *(Medium)*
`spoofed = unique_sources > 20 and spread > 0.85` selects evidence wording only;
it never affects firing, class or severity. Entropy contributes to confidence but
its full dynamic range is 0–0.693 of the summed log terms, and on `synflood.pcap`
the other two ratios are 25× and 60×, so confidence is already clipped at 0.99 —
recomputing with `spread = 0` changes nothing. A low-rate, highly-distributed
flood cannot be identified at all, because the rate gate rejects it first.
**Fix.** Emit `spoofed` as a field so consumers can route to anti-spoof
mitigation, give spread its own evidence entry with an explicit threshold, and
consider letting high spread lower the rate threshold. That last part is the most
likely way to break the zero-false-positive result and must be measured first.

---

## Also worth knowing

Three findings that are not defects but are easy to misread:

- **`Window.flows` holds live references** into the flow table, so records carry
  full history rather than window-local counters. Deliberate — but it means the
  model feature named `flow_rate_fps` is really an *active* flow rate, not a
  creation rate. Renaming it is a one-line honesty fix; adding true per-window
  deltas invalidates the model.
- **`payload_len` is inconsistent** — TCP/UDP report L4 payload, ICMP reports the
  whole message including header, `OTHER` reports 0. Currently read by nothing,
  so it is a loaded gun rather than a live bug. Fix it before anything starts
  using it.
- **The `Packet` docstring claims immutability** the dataclass does not enforce
  (`slots=True`, not `frozen=True`); `_attach_dns` mutates in place. No consumer
  ever observes a change, but the guarantee is enforced by comment only, and it
  is the project's headline isolation claim.

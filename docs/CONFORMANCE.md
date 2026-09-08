# Conformance to PS 26145 — Full Current Scope

What this project does today, mapped clause by clause onto the problem
statement. Written to be checkable: every verdict cites either a `file:line` or
a measured number from `docs/metrics.json`, `docs/throughput.json` or
`docs/model_report.json`.

**Summary:** all five architectural constraints are met, one of them
substantially exceeded. Of the six threat classes, **five are complete, one is
partial** — class (d) covers TLS but not QUIC.

---

## 1. Threat classes

### (a) Volumetric / protocol DDoS — **COMPLETE**

> *"SYN floods, UDP reflection/amplification, and spoofed-source floods
> identified from flow-level rate and source-IP entropy statistics."*

Three named shapes; all three implemented.

| Shape | Status | Detail |
|---|---|---|
| SYN floods | **Yes** | `detectors/synflood.py:43-56`. SYN rate against a learned target baseline (≥ 6×, floor 50/s), completion ratio ≤ 0.30. Measured on `synflood.pcap`: 1,500 SYN/s against a 50/s threshold, completion 0.0, 7,500 unique sources. |
| Spoofed-source floods | **Yes** | Source-IP Shannon entropy over the target's source distribution, normalised by `log2(unique_sources)` — `synflood.py:55-56`. Measured 12.87 bits across 7,500 sources. Feeds confidence at `:61`. |
| UDP reflection / amplification | **Yes** | `detectors/udpamp.py`. Aggregate inbound byte rate across a fixed 9-port reflector allowlist (DNS/NTP/SSDP/memcached/CharGen/QOTD/SNMP/Portmapper/CLDAP) against a learned target baseline (≥ 6×, floor 400,000 B/s), gated jointly on ≥ 3 distinct reflector IPs. Measured on `udp_amp.pcap`: 753,600 B/s against a 400,000 B/s floor, 4,000 distinct reflectors, 3,768,000 B total on NTP/123. |

**How amplification is detected, precisely.** Read at the victim
(`TargetFeatures`), not the reflector or the attacker — a one-way tap can only
ever see the reflector→victim leg, since the attacker→reflector leg is
external-to-external and (in a real attack) carries the victim's spoofed
address, so it never crosses this link. `features/extract.py`'s UDP branch
now accumulates `amp_bytes_by_port` and `amp_reflectors_by_port` whenever a
packet's *source* port matches the reflector allowlist — i.e. a response
landing on the victim, not a request to the victim's own service.
`detectors/udpamp.py` gates on the **aggregate** rate across all tracked
ports, not per-port, because a real campaign is routinely multi-vector
(DNS+NTP+SSDP at once, specifically to dodge single-protocol thresholds); a
corroborating (non-gating) amplification-ratio signal compares that volume
against the victim's own total outbound bytes that window, which is usually
zero — the victim never asked for any of this. See `docs/DEFECTS.md` #21
(fixed) for the full derivation, including the accepted gap: a 1-2-reflector
attack using very high-potency amplifiers can clear the byte-rate gate
without reaching the minimum-reflector-count gate.

**One honest qualification on spoofing.** The `spoofed` flag at `synflood.py:69`
is a *label*, not a gate: it selects the wording of one evidence note
(`:88-90`) and never decides whether the alert fires. Entropy does raise
confidence. The PS asks for spoofed floods to be "identified from flow-level
rate and source-IP entropy statistics", which this does — but the entropy
qualifies an alert that rate and completion ratio already triggered.

### (b) Botnet C2 beaconing — **COMPLETE**

> *"Periodicity and inter-arrival analysis on flows that repeat at regular
> intervals toward a small set of destinations."*

`detectors/beacon.py:87-110`. Per `(src, dst, dport)` triple across windows:
coefficient of variation of inter-arrival times ≤ 0.15, contact count ≥ 8,
packet-size CV, persistence, destination cardinality. CV is `std/mean`, so it is
scale-free — one threshold catches a 20-second and a 300-second beacon.

Measured on `beacon.pcap`: CV 0.046 against threshold 0.15, 14 contacts to one
destination over 257 s, packet-size CV 0. Detection latency 140 s — inherent,
since regularity cannot be established from two intervals.

### (c) DGA domains and DNS tunnelling — **COMPLETE (both)**

> *"Entropy/n-gram analysis of DNS query names, plus query-length and
> record-type anomalies."*

Detected over UDP/53, TCP/53, mDNS (5353) and LLMNR (5355) —
`ingest/reader.py` no longer gates DNS parsing to UDP only, which closed the
`dig +tcp` bypass (`docs/DEFECTS.md` #8). `detectors/dns.py:187-191`
implements both halves as separate tests:

- **DGA** (lexical): per-character Shannon entropy ≥ 3.4 bits **and** mean
  bigram log-probability ≤ −3.6 against an inline real-domain corpus
  (`dns.py:32-89`). Real labels score ≈ −2.5; random labels ≈ −4.5.
- **Tunnelling** (structural/volumetric): ≥ 15 distinct subdomains under one
  parent in a 60 s window, plus either a ≥ 30-character label **or** > 50 %
  TXT/NULL/CNAME.

All four PS-named signals are present: entropy ✓, n-gram ✓, query length ✓,
record type ✓. Measured on `dns_tunnel.pcap`: entropy 4.51 bits/char, bigram
−5.28, 70 unique subdomains, 52-char max label, 100 % TXT.

*Limitation:* both paths emit `threat_class = DNS_ANOMALY`; DGA vs tunnelling is
distinguishable only by reading an evidence note, not by machine. Recorded in
`docs/DEFECTS.md`.

### (d) Malware inside encrypted sessions — **PARTIAL**

> *"Detection from TLS/QUIC metadata alone (JA3/JA3S or JA4 fingerprints,
> packet-size and timing sequences), without decrypting payload."*

TLS is covered; QUIC is not. The clause names both, so this is partial rather
than complete, and the split is exactly along that line.

| Element | Status | Detail |
|---|---|---|
| TLS metadata extraction | **Yes** | `ingest/reader.py:_attach_tls`. Sniffs the 5-byte record header on **any** TCP payload — port-agnostic, so 8443 and an implant's arbitrary port are read the same as 443 — recording record type and the length from the header. |
| JA3 fingerprints | **Yes** | `ingest/reader.py:_attach_ja3`. Version, cipher list, extension list, curves and point formats from the ClientHello, GREASE stripped per RFC 8701, MD5 of the canonical JA3 string. SNI extracted alongside. |
| Packet-size sequences | **Yes** | `detectors/tlsmalware.py:_periodicity`. Dominant repeating period in the record-length sequence, scored against that sequence's own analytic null. |
| Timing sequences | **Yes** | Coefficient of variation of inter-arrival times of the same records, sub-second bursts excluded. |
| JA3S / JA4 | No | Client-side only. JA3S needs ServerHello parsing for little added signal; JA4 is a larger change. |
| QUIC | No | A QUIC Initial packet's headers are protected with a key derived from the connection ID. Recovering them is mechanical, but it is closer to decryption than to header parsing, and we would rather not blur constraint (b). |

**What actually gates, and what deliberately does not.** Both gates are
behavioural — properties of the *activity*, not of the client software:

1. the record-size sequence repeats at some period, explaining ≥ 60 % of the
   sequence and clearing a lift of 0.70 over what that sequence's own size
   distribution produces by chance; and
2. those records arrive on a beat, inter-arrival CV ≤ 0.25.

**The JA3 fingerprint is evidence and never gates.** This is the single most
important design decision in the detector, and it is a correction of the obvious
design rather than a shortcut. JA3 is order-sensitive by definition, and Chrome
≥ 110 permutes ClientHello extension order per connection — so on real traffic a
"rare fingerprint" gate fires on ordinary browsing, and because a cumulative
population never forgets, its false-positive rate would *grow with uptime*. We
measured this rather than assuming it: see the cross-validation below, where 3
of 6 real client hosts presented more than one fingerprint and one presented 8.
Rarity is reported so an analyst can pivot on it; it decides nothing.

Measured on `tls_malware.pcap`: period 3 explaining 86.4 % of a 25-record
sequence, lift 0.817 against the 0.70 gate, interval CV 0.044 over 7 intervals
at a mean 20.1 s, 5 distinct record sizes, no SNI offered. Precision / recall /
F1 = 1.000 in `docs/metrics.json`.

**Why this is not the beacon detector twice.** `detectors/beacon.py` keys on SYN
contacts — `features/extract.py` appends to `contacts` only when `pkt.is_syn` —
so one long-lived TLS session carrying periodic check-ins produces exactly *one*
contact and can never reach `MIN_CONTACTS`, however metronomic it is. This
detector reads the record sequence *inside* a single connection, which is the
case `beacon.py` is structurally blind to.

**Cross-validated against traffic we did not author.** An earlier version of
this document gave an honest reason for not building this class: *"a
rare-fingerprint score validated against fingerprints we invented would
demonstrate the parser rather than the detection."* Building the detector does
not by itself retire that objection, so `tools/tls_validate.py` exists to answer
it. Run against 11 public Wireshark test captures (real TLS from real stacks,
not written by us): **814 packets, 166 TLS handshake records, 51 ClientHellos
fingerprinted, 18 distinct JA3 fingerprints, 14 carrying SNI** — real values
including `localhost` and `reports.crashlytics.com` — and **0 alerts of any
class, 0 `TLS_MALWARE`.** That is a false-positive count on traffic nobody here
wrote.

The gap between 166 handshake records and 51 fingerprints is not a parser
failure, it is the reassembly limit being honest. Most of it comes from
`tls-fragmented-handshakes.pcap`, whose entire purpose is handshakes split
across records and segments; where the full ClientHello is not present in one
segment we record no fingerprint rather than hashing the fragment that happened
to arrive. That distinction matters — a fragment hashes to a plausible value
that exists in no corpus, so it would silently poison exactly the pivoting the
fingerprint is for.

Reproducible — the captures are Wireshark's own test corpus, not vendored here
(licensing, and they are not ours to redistribute):

```bash
BASE=https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures
curl -sSLO $BASE/tls13-rfc8446.pcap          # and the other 10, see below
python tools/tls_validate.py tls13-rfc8446.pcap
```

The eleven used: `retrans-tls.pcap`, `tls-renegotiation.pcap`,
`tls12-aes128ccm.pcap`, `tls12-aes256gcm.pcap`, `tls12-chacha20poly1305.pcap`,
`tls12-dsb.pcapng`, `tls13-20-chacha20poly1305.pcap`, `tls13-rfc8446.pcap`,
`tls-fragmented-handshakes.pcap.gz`, `tls-over-tls.pcapng.gz`,
`tls-fragmented-over-tcp-segmented.pcapng.gz`.

Two honest limits on that result. The captures are small protocol-test files,
not a busy production link, so 0 false positives over 814 packets is
encouraging, not conclusive. And the *rate* of periodic-looking benign sessions
on a real network is precisely what these files cannot tell us.

**The cross-validation found a real bug**, which is the best argument for having
done it. Three of the eleven captures use link type 228 (`DLT_IPV4`, a bare IP
packet with no Ethernet header, which `tcpdump` writes for tunnel and loopback
interfaces). `ingest/reader.py` handled 12 and 101 but not 228, so every packet
fell through to the Ethernet branch, produced no IP layer, and was dropped —
**an entire capture read as zero packets, silently.** Fixed, with 229
(`DLT_IPV6`) added alongside; recorded in `docs/DEFECTS.md`.

**Accepted gaps, stated rather than shipped quietly.** TLS 1.3 record padding
(RFC 8446 §5.4) blurs record lengths by design and defeats the size gate in one
line of implant code; the timing gate survives padding but both are required, so
a padding implant is missed. An implant that also jitters its check-in interval
defeats the timing gate, at the cost of the reliability that made a fixed beat
attractive. A ClientHello split across TCP segments is not reassembled, so its
fingerprint is not recovered — the size and timing analysis is unaffected, since
it reads record headers rather than the handshake. Detection latency is 145 s on
`tls_malware.pcap`: 24 records must accumulate before periodicity means
anything, so a slow beacon is caught late, in the same way `beacon.py` needs
140 s.

**`normal.pcap` contains no TLS at all**, so the project's headline
zero-false-positive result on that capture says nothing about this detector. The
false-positive evidence for class (d) is the real-capture run above and the
benign TLS carried inside `tls_malware.pcap` itself — a metrics agent posting a
fixed-size record on a perfect 15 s beat (it passes the timing gate outright and
is stopped only by the distinct-size and lift gates), six parallel connections
from one host to one server, and a long-lived reused connection with human-paced
bursts. None of them fire.

### (e) Reconnaissance and port scanning — **COMPLETE**

> *"Fan-out patterns from a single source across many destination ports or
> hosts."*

`detectors/portscan.py:50-96`. Port fan-out (≥ 5× baseline, floor 25) and host
fan-out (≥ 5× baseline, floor 12), completion ratio ≤ 0.45, sequential-port run
ratio, connection rate, plus vertical/horizontal/block scan-shape
classification. Measured: 83 ports across 18 hosts, completion 0.029, 102 RST.

### (f) Data exfiltration — **COMPLETE**

> *"Asymmetric flow-volume anomalies and unusual outbound-to-inbound byte
> ratios."*

`detectors/exfil.py:80-100`. Per `(src, dst)` over a 600 s history:
outbound:inbound ratio ≥ 8.0, total outbound ≥ 2 MB, sustained ≥ 20 s, plus
outbound rate and burstiness (peak/mean per window). Measured: ratio 107.4
(2,029,838 B out vs 18,900 B in) over 40 s, burstiness 1.03 — a steady drip
rather than a burst.

---

## 2. Architectural constraints

### (a) Read-only ingest — **MET, and the strongest part of the submission**

Proven four ways rather than asserted, via `tools/isolation_check.py`:

1. **Static** — every module in the detection path (`ingest/ features/
   detectors/ alerts/ engine.py`) is AST-parsed and rejected if it imports a
   networking or subprocess library or calls `connect`/`send`/`urlopen`/`popen`.
   AST rather than grep, so `import socket as s` and `from socket import *` are
   caught. Result: 19/19 files clean.
2. **Runtime** — a real capture replayed with `socket.socket` replaced by a
   subclass that raises on construction. 70,173 packets, 10 alerts, model loaded,
   no socket created.
3. **File access** — `builtins.open` wrapped for a full run; the only file
   opened is the capture, mode `rb`.
4. **Container** — `docker run --network none` with the capture mounted `:ro`
   produces byte-identical alerts to the host run: same classes, flows,
   timestamps, confidences, evidence values.

`server.py` and `config.py` are excluded from layers 1–3, and the exclusions are
named in the checker's source rather than quietly skipped — a dashboard has to
reach a browser. The socket lives downstream of detection and cannot reach
upstream of it.

### (b) No payload decryption — **MET**

Nothing decrypts. The parser handles Ethernet/SLL/raw, IPv4/IPv6, TCP/UDP/ICMP
headers, and DNS *query* names only — `ingest/reader.py:134` states explicitly
that answer payloads are never read or reconstructed. `ssl` is on the banned
import list (`tools/isolation_check.py:49`).

Note this constraint is currently satisfied partly *by not implementing class
(d)*. Building (d) correctly — ClientHello header parsing — would keep it
satisfied.

### (c) Streaming, not batch — **MET**

`engine.py:150-186` emits alerts when a window closes, not at end of capture, so
latency is bounded by window duration however long the stream runs. 61 windows
on `mixed.pcap`, not one batch — asserted by `tools/selftest.py`.

Measured first-alert latency after attack onset:

| Class | Latency | Bound by |
|---|---|---|
| `SYN_FLOOD`, `PORT_SCAN`, `DNS_ANOMALY` | 5 s | one window |
| `EXFIL` | 45 s | sustained-duration requirement |
| `C2_BEACON` | 140 s | intervals needed to establish regularity |

The two slow classes are limited by the signal, not the pipeline: a beacon is
not identifiable as periodic until enough intervals exist to measure.

### (d) Defined throughput target — **MET**

`docs/throughput.json`, median of 3 runs, full pipeline with the anomaly model
loaded:

| Capture | packets/s | Mbit/s | flows/s | vs real time |
|---|---|---|---|---|
| `mixed.pcap` | 9,318 | 33.8 | 5,890 | 40× |
| `synflood.pcap` | 16,140 | 32.4 | 10,796 | 102× |

Hardware stated: `Intel64 Family 6 Model 170` (Meteor Lake), 18 logical cores,
Windows 11, CPython 3.13, single process, no GPU. The PS asks for "flows/sec or
Mbps"; both are given.

*Measured on a dev machine with other applications running; repeated runs of
`bench/throughput.py` across this work produced real-time multiples from 33× to
102× on the same two captures. The spread is machine noise rather than a code
change — in the run behind this table `mixed.pcap` got slower while
`synflood.pcap` got faster, which no single-direction regression explains. Treat
it as "comfortably above real time" rather than a precise headline number until
re-measured on an idle machine. `TlsMalwareDetector`'s periodicity search is
O(n²) in record count, so it caps records per session (128) and sessions
examined per window (512) — a memory bound alone would not have bounded its
CPU.*

### (e) Standardised alert schema — **MET**

`alerts/schema.py`. Verified against a live emitted record:

| PS-required field | Present as |
|---|---|
| timestamp | `timestamp` (RFC3339, ms, UTC) |
| flow identifier | `flow_id` |
| threat class | `threat_class` |
| confidence score | `confidence` (0–1) |
| supporting evidence feature | `evidence[]` — structured `{feature, value, baseline, unit, note}` |

Plus `severity`, `detector`, `src`, `dst`, `window` (start/end/duration/epochs)
and optional `anomaly_score`. Evidence is structured rather than free text,
which is what lets the dashboard render value-vs-baseline bars.

Confidence is computed by `alerts.schema.confidence_from()` from
observed/threshold ratios — no detector contains a literal confidence value, and
`tools/selftest.py` fails if any evidence value is prose rather than a number.

---

## 3. Expected-solution deliverables

| Required | Status |
|---|---|
| Working prototype: ingest, feature extraction, model inference, alert output | Present — `ingest/`, `features/`, `detectors/`, `alerts/`, driven by `engine.py` |
| Documentation of models, features engineered, training/validation approach | `docs/MODEL.md` — 10 features itemised with rationale, IsolationForest hyperparameters, unsupervised regime, ROC-AUC validation, and a documented calibration bug |
| Simple dashboard of live or replayed detections with severity and confidence | `dashboard/index.html` — WebSocket-fed alert list with severity and confidence (`:182-183`), click-through evidence panel (`:211-212`), live counters |

## 4. Model summary

IsolationForest, 200 trees, `contamination=0.01`, `StandardScaler`, 10 features
per source host per window. Trained on `normal.pcap` only — **never sees an
attack during fit**, which mirrors what a passive monitor can actually collect.
Mean ROC-AUC 0.997 across held-out attack captures.

`docs/MODEL.md` documents where that number flatters the model: on exfiltration
it scores 0.727, ranked correctly but *inside* the benign tail, so it would not
alert on its own. Hosts under 20 packets/window are unscored, so the beacon and
DNS-tunnel hosts are invisible to it. The rules catch what the model misses and
vice versa; neither alone is sufficient.

## 5. Detection performance

Per-class precision / recall / F1 = 1.00 across all seven implemented classes,
macro-F1 1.00, and **0 false positives** on 16,701 packets of benign traffic.

**These numbers must be read with their caveat.** We authored the captures and
the ground truth, so labels are exact and the traffic lacks production
messiness. The PS does specify ingest "from a simulated IP data", so simulation
is the specified input rather than a shortcut — but authoring our own ground
truth still makes the metrics clean in a way real traffic never is. What they
demonstrate is that detectors fire on the behaviour they target and stay silent
otherwise, not field accuracy.

## 6. Scope boundaries

**Not built, deliberately:** QUIC metadata analysis (the unbuilt half of class
d — Initial-packet header protection is closer to decryption than to header
parsing); JA3S and JA4 fingerprints; payload
decryption (out of scope per constraint b); active probing (violates the
passive constraint, absence proven mechanically); automated blocking (needs a
return path that does not exist); supervised classification (no labelled
attack data obtainable in this deployment model); deep learning on raw bytes
(no labels, no explainability).

**Ingest breadth.** PCAP/PCAPNG files only. The PS *background* mentions
NetFlow/IPFIX/sFlow among what an enclave can observe, but this appears in
scene-setting rather than in the constraints or the expected-solution list — so
supporting them would be a differentiator, not a compliance requirement. Adding
them is genuinely non-trivial: `engine.run()` hardcodes `PcapReader`
(`engine.py:139`), and the feature layer depends on per-packet TCP flags that
flow records do not carry.

**Known defects.** Recorded with root cause and remedy in `docs/DEFECTS.md`,
including one that affects what a row in the model's training set represents.

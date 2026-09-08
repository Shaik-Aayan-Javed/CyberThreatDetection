# Passive Threat Detection for Unidirectional IP Traffic

**SIH Problem Statement 26145** — AI-based detection of cyber threats in traffic
copied one-way into a monitoring enclave.

A gateway link is mirrored into an enclave that can see every packet and has no
route back. This prototype turns that one-way stream into explained alerts:
seven behavioural detectors plus an unsupervised anomaly model, running as a
streaming pipeline, with the isolation constraint proven mechanically rather
than asserted on a slide.

```bash
py -3.13 -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt

python data/generate.py --seed 42      # 9 labelled captures, 258,529 packets
python train.py                        # fit + calibrate + validate the model
python engine.py data/pcaps/mixed.pcap --pretty
python server.py                       # then open http://127.0.0.1:8000
```

---

## What it detects

Measured against the PS threat list clause by clause: **five classes complete,
one partial.** The per-class breakdown and the evidence for each verdict are in
[docs/CONFORMANCE.md](docs/CONFORMANCE.md).

Each detector fires on a distinct behavioural signal. Thresholds are multiples
of a **learned** EWMA baseline — with the caveat that each baseline is floored
at a fixed minimum (`features/baseline.py:63-76`), and on a quiet metric that
floor is what is actually in effect.

| Class | Signal that fires it | Module |
|---|---|---|
| `SYN_FLOOD` | SYN rate vs baseline, completion ratio ≈ 0, **source-IP Shannon entropy** (separates one aggressive host from a spoofed flood) | `detectors/synflood.py` |
| `PORT_SCAN` | port + host fan-out from one source, RST ratio, sequential-port runs | `detectors/portscan.py` |
| `C2_BEACON` | coefficient of variation of inter-arrival times — scale-free, so one threshold catches a 20s and a 300s beacon | `detectors/beacon.py` |
| `DNS_ANOMALY` | QNAME character entropy + bigram plausibility against a real-domain corpus, label length, TXT/NULL ratio — over UDP/53, TCP/53, mDNS, and LLMNR | `detectors/dns.py` |
| `EXFIL` | outbound:inbound byte ratio to a single destination, sustained | `detectors/exfil.py` |
| `UDP_AMPLIFICATION` | aggregate inbound byte rate on known reflector ports (DNS/NTP/SSDP/memcached/...) vs baseline, plus distinct-reflector cardinality | `detectors/udpamp.py` |
| `TLS_MALWARE` | repeating period in the TLS record-size sequence plus a regular arrival beat, read *inside* one session; JA3 fingerprint reported as evidence, never as a gate | `detectors/tlsmalware.py` |
| `ANOMALOUS_FLOW` | IsolationForest on 10 per-host features, trained on benign traffic only | `detectors/anomaly.py` |

**One partial class, stated plainly:**

**PS class (a) is now complete.** It names three attack shapes — SYN floods,
spoofed floods, and UDP reflection/amplification — and all three are now
detected. Amplification is read at the victim (`TargetFeatures`), since on a
one-way tap the attacker→reflector leg is invisible by construction (both ends
are external and spoofed, so it never crosses this link) — only the
reflector→victim leg can be observed, which is exactly what
`detectors/udpamp.py` gates on: aggregate inbound bytes across a fixed
allowlist of reflector ports, plus a minimum distinct-reflector count so one
legitimate DNS resolver never looks like an attack. See `docs/DEFECTS.md` #21
(fixed) for the full writeup.

**PS class (d) — malware in encrypted sessions — is partial: TLS yes, QUIC no.**
The class asks for detection from TLS/QUIC *metadata alone* (JA3/JA3S/JA4,
packet-size and timing sequences), explicitly **without** decrypting payload —
so constraint (b) was never the reason to skip it. `ingest/reader.py` now parses
TLS record headers and computes JA3 from the cleartext ClientHello;
`detectors/tlsmalware.py` reads the record-size and timing sequences *inside* a
session. QUIC is not built: its Initial-packet headers are protected with a key
derived from the connection ID, and recovering them sits closer to decryption
than to header parsing.

**The fingerprint deliberately does not gate.** The obvious design — "rare JA3
equals malware" — fails on real traffic, because JA3 is order-sensitive and
Chrome ≥ 110 permutes ClientHello extension order per connection. We measured
it rather than assuming: across 11 public captures, 3 of 6 real client hosts
presented more than one fingerprint and one presented 8. Both gates are
therefore behavioural, and JA3 is reported as evidence for an analyst to pivot
on. That also answers the objection this README used to raise against building
the class at all — the detection logic does not depend on our having guessed
real-world fingerprints correctly.

**It is cross-validated on traffic we did not author.**
`python tools/tls_validate.py <capture.pcap>` runs the extractor and the full
engine over any third-party capture. On 11 public Wireshark test captures: 51
ClientHellos fingerprinted out of 166 handshake records, 18 distinct
fingerprints, real SNI values, **0 alerts of any class**. The shortfall is the
reassembly limit reported honestly — a ClientHello split across segments gets no
fingerprint rather than a fabricated one. It also surfaced a genuine ingest bug — link type 228 (raw IPv4,
which `tcpdump` writes for tunnel interfaces) was unhandled, so such captures
read as *zero packets*, silently. Every capture we generate is Ethernet, so no
test in this repository could have caught it. Fixed; `docs/DEFECTS.md` #24.

## Measured results

All numbers below come from `tools/selftest.py`, `bench/metrics.py` and
`bench/throughput.py` on this machine. Nothing here is illustrative.

**Detection** (`docs/metrics.json`) — per-class precision / recall / F1 = 1.00
across all seven *implemented* classes, macro-F1 **1.00**, and:

```
false positives on 16,701 packets of purely benign traffic:  0
```

**Read that number with the caveat attached**: we generated these captures, so
ground truth is exact and the traffic contains none of the messiness of a
production link. What the metrics show is that the detectors fire on the
behaviour they target and stay silent otherwise — not production accuracy. A
zero-FP claim against synthetic benign traffic is a sanity check, not evidence
of a low false-alarm rate in the field.

**Detection latency**, first alert after attack onset: 5 s for `SYN_FLOOD`,
`PORT_SCAN`, `DNS_ANOMALY`, `UDP_AMPLIFICATION` (one window), 45 s for `EXFIL`,
140 s for `C2_BEACON`, 145 s for `TLS_MALWARE`. The slow ones are inherent — a
beacon is not a beacon until enough intervals exist to measure regularity, and
a record sequence is not periodic until enough records exist to repeat. Calling
either earlier would mean calling it on two packets.

**Throughput** (`docs/throughput.json`), median of 3 runs, full pipeline with
the anomaly model loaded:

| Capture | packets/s | Mbit/s | flows/s | vs real time |
|---|---|---|---|---|
| `mixed.pcap` | 9,318 | 33.8 | 5,890 | **40×** |
| `synflood.pcap` | 16,140 | 32.4 | 10,796 | 102× |

Hardware: `Intel64 Family 6 Model 170` (Meteor Lake), 18 logical cores,
Windows 11, CPython 3.13 — single process, one core doing the work, no GPU.

**Caveat on these two figures specifically**: measured on a dev machine with
other applications running, and repeated runs of `bench/throughput.py` across
this work produced real-time multiples anywhere from **33× to 102×** for the
same two captures. The spread is machine noise, not a code change: in the run
that produced this table `mixed.pcap` got slower while `synflood.pcap` got
faster, which no single-direction regression explains. Treat the table as
"comfortably above real time", not as a precise headline number, and re-measure
on an idle machine before quoting a specific multiple.

The two newest detectors are the ones a reviewer would suspect, so their cost is
bounded by construction rather than by hope. `UdpAmplificationDetector` is a
single pass over `wf.by_dst`. `TlsMalwareDetector`'s periodicity search is
O(n²) in the record count, so it caps both the records per session (128) and the
sessions examined per window (512, least-recently-examined first) — without
that second cap, a bounded-memory table of 20,000 armed sessions still costs
more CPU than a 5-second window contains. That is a code-reading and
arithmetic argument, not a profiled one, and it is stated as such.

**Model** (`docs/model_report.json`): IsolationForest, 200 trees, 10 features,
trained on 256 benign windows, never on an attack. Mean ROC-AUC **0.997** across
held-out attack captures. `docs/MODEL.md` explains where that number flatters
the model and where the model genuinely fails.

## Architecture

```
   monitored link
        │  (mirror / data diode — one way, no return path)
        ▼
   ┌─────────────┐
   │ PCAP / SPAN │   ingest/reader.py    packets in capture-time order
   └──────┬──────┘                       --speed 0 = max, 1 = wall-clock
          ▼
   ┌─────────────┐   ingest/flows.py     5-tuple flow table, expiry
   │ flow table  │
   └──────┬──────┘
          ▼
   ┌─────────────┐   features/extract.py  per-window, per-host vectors
   │  5s window  │   features/baseline.py  EWMA baselines, winsorized
   └──────┬──────┘
          ▼
   ┌──────────────────────────────────────────────────────┐
   │ synflood udpamp portscan beacon dns exfil tlsmalware │  rules → evidence
   │ anomaly (IsolationForest)                            │  model → corroboration
   └──────┬───────────────────────────────────────────────┘
          ▼
   ┌─────────────┐   alerts/schema.py     confidence computed from evidence
   │   Alert     │───► stdout JSON
   └──────┬──────┘───► data/alerts.jsonl
          ▼
   ┌─────────────┐   server.py → WebSocket → dashboard/index.html
   │  dashboard  │   (loopback, enclave-internal, display only)
   └─────────────┘

   Every arrow points away from the monitored network. There is no return edge.
```

The single design decision that made three days work: detectors are **stateful
window consumers from the first line of code**, so "batch → streaming" was never
a rewrite. `engine.run()` drives the same loop whether output goes to stdout or
a WebSocket, and `--speed` changes pacing without changing the code path — so
the demo and the benchmark exercise the same pipeline.

**A streaming pipeline has to survive the traffic it's watching for.** A flow
table with no bound will run out of memory during exactly the flood it exists
to report — every spoofed source in a SYN flood mints a new flow, and idle
eviction alone can never catch up with a flood, because every record it holds
is recent. `ingest/flows.py` bounds this three ways: an active timeout so a
persistent connection can't accumulate state forever, a hard cap on resident
flows checked *before* insertion, and a packet-count sweep trigger so a burst
can't outrun a timer that only checks capture time. Verified: 600,000 unique
spoofed 5-tuples at 100k pps against a 5,000-flow cap held peak residency at
exactly 5,000. Full writeup in `docs/DEFECTS.md` #1.

## Alerts explain themselves

The PS asks for intelligence an analyst can act on without re-contacting the
network. So no alert is a label plus a score — every one carries the
measurements that produced it:

```
[CRITICAL] SYN_FLOOD      conf=0.99
           flow: *->10.0.1.10/TCP
           - syn_rate_pps: 1500 pkt/s  (baseline 50)  -- median target sees no SYN
                                                    traffic, so the 50/s absolute
                                                    floor set the threshold
           - completion_ratio: 0  (baseline 1)  -- 0 SYN/ACK observed for 7500 SYN
           - unique_source_ips: 7500 hosts
           - source_ip_entropy: 12.87 bits  -- near-uniform spread: consistent with spoofing
```

Confidence is computed by `alerts.schema.confidence_from()` from
observed/threshold ratios, compounded so that independent signals corroborate.
There is no literal confidence value anywhere in any detector, and
`tools/selftest.py` fails the build if an evidence value is ever prose instead of
a measured number.

## The isolation constraint, proven in four layers

```bash
python tools/isolation_check.py
```

1. **Static** — every module in `ingest/ features/ detectors/ alerts/ engine.py`
   is AST-parsed and rejected if it imports a networking or subprocess library
   or calls `connect`/`send`/`urlopen`/`popen`. AST, not grep: `import socket as
   s` and `from socket import *` are caught too.
2. **Runtime** — a real capture is replayed with `socket.socket` replaced by a
   subclass whose constructor raises. 70,173 packets, 10 alerts, no socket
   constructed.
3. **File access** — `builtins.open` is wrapped for a full run: the only file
   opened is the capture, mode `rb`.
4. **Container** — `docker run --network none` with the capture mounted `:ro`
   produces **byte-identical alerts** to the host run: same classes, flows,
   timestamps, confidences, evidence values. Verified, not asserted.

`server.py` is excluded from layers 1–3 and the exclusion is named in the
checker's source rather than quietly skipped — a dashboard has to reach a
browser. The point is that the socket lives downstream of detection and cannot
reach upstream of it. Full argument, including what none of this proves, in
[docs/ISOLATION.md](docs/ISOLATION.md).

## Repository

```
data/generate.py       scapy capture synthesis + ground-truth labels, seeded
ingest/                reader (packets in capture order), flow table
features/              per-window feature extraction, EWMA baselines
detectors/             7 behavioural detectors + the anomaly model
alerts/schema.py       Alert dataclass, computed confidence, JSON
engine.py              the streaming loop
server.py              FastAPI: WebSocket /stream, /api/alerts, /api/replay
dashboard/index.html   live alert list + click-through evidence, no build step
bench/                 throughput and precision/recall harnesses
tools/selftest.py      21-check acceptance list, executed not ticked
tools/isolation_check.py
docs/MODEL.md          models, features, training, validation, and limits
docs/ISOLATION.md      the unidirectional argument and its proofs
docs/DEMO.md           the rehearsed demo script
```

## Reproducing everything

```bash
python data/generate.py --seed 42      # captures + labels; deterministic
python train.py                        # -> docs/model_report.json
python bench/metrics.py                # -> docs/metrics.json
python bench/throughput.py             # -> docs/throughput.json
python tools/isolation_check.py        # 3 layers, exit code is the verdict
python tools/selftest.py               # 20 checks
docker build -t sih26145 .
docker run --rm --network none -v "${PWD}\data:/data:ro" sih26145 \
  /data/pcaps/mixed.pcap --pretty     # PowerShell; Git Bash mangles /data
```

Every stage is seeded. Two runs of `generate.py --seed 42` produce identical
captures, so every number in this README regenerates from scratch.

## Known limits

Stated here so a reviewer does not have to find them:

- **Synthetic traffic.** We wrote the captures and the ground truth. The metrics
  demonstrate detector behaviour, not field accuracy. (The PS does specify ingest
  "from a simulated IP data", so simulation is the specified input rather than a
  shortcut — but authoring our own ground truth still makes the numbers clean in
  a way production traffic never is.)
- **The anomaly model does not separate exfiltration by threshold.** It ranks it
  correctly (ROC-AUC 0.993) but scores 0.727 — inside the benign tail. The `EXFIL`
  rule catches it; the model corroborates. Measured, in `docs/MODEL.md`.
- **Low-and-slow traffic is below the model's volume floor** (20 packets/window)
  — the beacon and DNS-tunnel hosts are invisible to it and are caught by rules
  alone.
- **Encrypted-traffic analysis covers TLS but not QUIC (PS class d).** QUIC
  Initial-packet headers are protected with a key derived from the connection
  ID; recovering them sits closer to decryption than to header parsing, so it is
  left out rather than blurring constraint (b). Within TLS: record padding
  (RFC 8446 §5.4) defeats the size gate in one line of implant code
  (`docs/DEFECTS.md` #25), a ClientHello split across TCP segments is not
  reassembled, and no JA3S or JA4.
- **`normal.pcap` contains no TLS**, so this project's headline
  zero-false-positive result on that capture says nothing about `TLS_MALWARE`.
  Its false-positive evidence comes from 11 public captures we did not author
  (0 alerts) and from the benign TLS deliberately carried inside
  `tls_malware.pcap` — see `docs/CONFORMANCE.md` class (d).
- **UDP amplification detection is victim-side only.** A one-way tap can only
  ever observe the reflector→victim leg, never the (external, spoofed)
  attacker→reflector leg — see `docs/DEFECTS.md` #21. A 1-2-reflector attack
  using a small number of very high-potency amplifiers can clear the
  byte-rate gate without reaching the minimum-reflector-count gate; not
  defended against in this pass.
- **Six of six classes is not claimed.** Five complete, one partial.
- **Known defects.** Every defect found in an internal audit is recorded with
  cause and remedy in [docs/DEFECTS.md](docs/DEFECTS.md), including one that
  affects the anomaly model's training input.

## Extensions, in priority order

QUIC metadata analysis (the last unbuilt half of a PS class) → JA4 fingerprints,
whose sorted cipher and extension lists survive the ClientHello permutation that
makes raw JA3 unstable → NetFlow/IPFIX ingest alongside PCAP → live SPAN capture
(would require re-making the layer-1 isolation argument, deliberately) → alert
persistence and historical query.

A note on the second and third of those, because an earlier draft of this README
oversold them: NetFlow ingest is **not** a drop-in. `engine.run()` hardcodes
`PcapReader` (`engine.py:139`), any substitute must also duck-type
`packets_read` / `bytes_read` / `malformed` / `capture_duration`, and more
fundamentally the whole feature layer depends on per-packet TCP flags
(`is_syn` / `is_synack` / `is_rst`) that flow records do not carry — sampled
sFlow would additionally invalidate every rate. The iterator shape helps; it is
not the whole job.

Nothing in the current design needs to be undone to add any of them.

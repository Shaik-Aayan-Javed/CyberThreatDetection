# Conformance to PS 26145 — Full Current Scope

What this project does today, mapped clause by clause onto the problem
statement. Written to be checkable: every verdict cites either a `file:line` or
a measured number from `docs/metrics.json`, `docs/throughput.json` or
`docs/model_report.json`.

**Summary:** all five architectural constraints are met, one of them
substantially exceeded. Of the six threat classes, **four are complete, one is
partial, and one is absent.**

---

## 1. Threat classes

### (a) Volumetric / protocol DDoS — **PARTIAL**

> *"SYN floods, UDP reflection/amplification, and spoofed-source floods
> identified from flow-level rate and source-IP entropy statistics."*

Three named shapes; two implemented.

| Shape | Status | Detail |
|---|---|---|
| SYN floods | **Yes** | `detectors/synflood.py:43-56`. SYN rate against a learned target baseline (≥ 6×, floor 50/s), completion ratio ≤ 0.30. Measured on `synflood.pcap`: 1,500 SYN/s against a 50/s threshold, completion 0.0, 7,500 unique sources. |
| Spoofed-source floods | **Yes** | Source-IP Shannon entropy over the target's source distribution, normalised by `log2(unique_sources)` — `synflood.py:55-56`. Measured 12.87 bits across 7,500 sources. Feeds confidence at `:61`. |
| UDP reflection / amplification | **No** | Not implemented, and not currently measurable — see below. |

**Why amplification is absent, precisely.** Three layers would each need work:

1. `detectors/synflood.py:43` gates on `tf.syn_in`, which is incremented only
   inside the TCP branch of `features/extract.py:186-189`. A pure UDP flood has
   `syn_in == 0` and is skipped before any other test runs.
2. No detector reads `sport`. It is parsed (`ingest/reader.py:37,102,109`) but
   used only for flow keying (`ingest/flows.py:80,91-98`), so "responses from
   source port 53/123/11211 converging on a victim" is invisible.
3. The amplification factor is **unrepresentable**, not merely unused.
   `TargetFeatures` has `udp_in` as a packet count (`extract.py:105,203`) with
   no byte total and no per-service breakdown, and DNS answers are discarded
   outright (`reader.py:134`, `extract.py:205`) — so there is no
   request:response size pair anywhere in the feature set to threshold.

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

`detectors/dns.py:187-191` implements both halves as separate tests:

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

### (d) Malware inside encrypted sessions — **ABSENT**

> *"Detection from TLS/QUIC metadata alone (JA3/JA3S or JA4 fingerprints,
> packet-size and timing sequences), without decrypting payload."*

Not implemented at any layer. The gap is total: no TLS parsing in
`ingest/reader.py` (the parser stops at L4 with a DNS-only carve-out at `:112`),
no TLS features, no TLS traffic in the generator — every "HTTPS" session in
`data/generate.py` is plain TCP on port 443 carrying filler bytes — and no
detector.

**This class does not require decryption.** JA3 is computed from ClientHello
header fields (version, cipher list, extensions, curves), which is byte parsing.
An earlier version of our own documentation cited PS constraint (b) as the
reason this was skipped; that was a misreading and has been corrected. The real
reasons are time, and that a rare-fingerprint score validated against
fingerprints we invented would demonstrate the parser rather than the detection.

The closest existing capability is the beacon detector's packet-size CV
(`beacon.py:106-108`) — a scalar dispersion measure, not the *sequence* analysis
the PS describes.

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
   caught. Result: 17/17 files clean.
2. **Runtime** — a real capture replayed with `socket.socket` replaced by a
   subclass that raises on construction. 52,786 packets, 8 alerts, model loaded,
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
| `mixed.pcap` | 19,060 | 50.4 | 11,597 | 109× |
| `synflood.pcap` | 18,867 | 37.9 | 12,620 | 120× |

Hardware stated: `Intel64 Family 6 Model 170` (Meteor Lake), 18 logical cores,
Windows 11, CPython 3.13, single process, no GPU. The PS asks for "flows/sec or
Mbps"; both are given.

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
it scores 0.751, ranked correctly but *inside* the benign tail, so it would not
alert on its own. Hosts under 20 packets/window are unscored, so the beacon and
DNS-tunnel hosts are invisible to it. The rules catch what the model misses and
vice versa; neither alone is sufficient.

## 5. Detection performance

Per-class precision / recall / F1 = 1.00 across all five implemented classes,
macro-F1 1.00, and **0 false positives** on 16,701 packets of benign traffic.

**These numbers must be read with their caveat.** We authored the captures and
the ground truth, so labels are exact and the traffic lacks production
messiness. The PS does specify ingest "from a simulated IP data", so simulation
is the specified input rather than a shortcut — but authoring our own ground
truth still makes the metrics clean in a way real traffic never is. What they
demonstrate is that detectors fire on the behaviour they target and stay silent
otherwise, not field accuracy.

## 6. Scope boundaries

**Not built, deliberately:** TLS/QUIC metadata analysis (class d); UDP
reflection/amplification (part of class a); payload decryption (out of scope per
constraint b); active probing (violates the passive constraint, absence proven
mechanically); automated blocking (needs a return path that does not exist);
supervised classification (no labelled attack data obtainable in this deployment
model); deep learning on raw bytes (no labels, no explainability).

**Ingest breadth.** PCAP/PCAPNG files only. The PS *background* mentions
NetFlow/IPFIX/sFlow among what an enclave can observe, but this appears in
scene-setting rather than in the constraints or the expected-solution list — so
supporting them would be a differentiator, not a compliance requirement. Adding
them is genuinely non-trivial: `engine.run()` hardcodes `PcapReader`
(`engine.py:139`), and the feature layer depends on per-packet TCP flags that
flow records do not carry.

**Known defects.** Recorded with root cause and remedy in `docs/DEFECTS.md`,
including one that affects what a row in the model's training set represents.

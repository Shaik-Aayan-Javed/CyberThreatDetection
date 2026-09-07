# Passive Threat Detection for Unidirectional IP Traffic

**SIH Problem Statement 26145** — AI-based detection of cyber threats in traffic
copied one-way into a monitoring enclave.

A gateway link is mirrored into an enclave that can see every packet and has no
route back. This prototype turns that one-way stream into explained alerts:
six behavioural detectors plus an unsupervised anomaly model, running as a
streaming pipeline, with the isolation constraint proven mechanically rather
than asserted on a slide.

```bash
py -3.13 -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt

python data/generate.py --seed 42      # 8 labelled captures, 231,293 packets
python train.py                        # fit + calibrate + validate the model
python engine.py data/pcaps/mixed.pcap --pretty
python server.py                       # then open http://127.0.0.1:8000
```

---

## What it detects

Measured against the PS threat list clause by clause: **five classes complete,
one absent.** The per-class breakdown and the evidence for each verdict are in
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
| `ANOMALOUS_FLOW` | IsolationForest on 10 per-host features, trained on benign traffic only | `detectors/anomaly.py` |

**One gap, stated plainly:**

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

**PS class (d) — malware in encrypted sessions — is not built.** Note what it
actually asks for: detection from TLS/QUIC *metadata alone* (JA3/JA3S/JA4,
packet-size and timing sequences), explicitly **without** decrypting payload. So
constraint (b)'s no-decryption rule is not the reason we skipped it — the class
never required decryption, and citing that rule would be a misreading. The real
reason is time, plus the judgement that a JA3 rarity score computed against
fingerprints we invented ourselves would demonstrate plumbing rather than
detection. It is the first extension seam, not a claimed capability.

## Measured results

All numbers below come from `tools/selftest.py`, `bench/metrics.py` and
`bench/throughput.py` on this machine. Nothing here is illustrative.

**Detection** (`docs/metrics.json`) — per-class precision / recall / F1 = 1.00
across all six *implemented* classes, macro-F1 **1.00**, and:

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
140 s for `C2_BEACON`. The slow two are inherent — a beacon is not a beacon
until enough intervals exist to measure regularity, and calling it earlier
would mean calling it on two packets.

**Throughput** (`docs/throughput.json`), median of 3 runs, full pipeline with
the anomaly model loaded:

| Capture | packets/s | Mbit/s | flows/s | vs real time |
|---|---|---|---|---|
| `mixed.pcap` | 14,959 | 53.1 | 10,187 | **69×** |
| `synflood.pcap` | 12,737 | 25.6 | 8,520 | 81× |

Hardware: `Intel64 Family 6 Model 170` (Meteor Lake), 18 logical cores,
Windows 11, CPython 3.13 — single process, one core doing the work, no GPU.

**Caveat on these two figures specifically**: measured on a dev machine with
other applications running, and re-running `bench/throughput.py` three times
in a row during this pass produced real-time multiples ranging from 33× to
91× for the same two captures — too wide a spread to attribute confidently to
the sixth detector rather than run-to-run system load (`UdpAmplificationDetector.on_window`
is structurally a single pass over `wf.by_dst`, the same shape as
`SynFloodDetector`'s, but that is a code-reading argument, not a profiled
one). Treat this table as "still comfortably above real time," not as a
precise headline number — re-measure on an idle machine before quoting a
specific multiple with confidence.

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
   ┌────────────────────────────────────────────────┐
   │ synflood  udpamp  portscan  beacon  dns  exfil │  rules → evidence
   │ anomaly (IsolationForest)                      │  model → corroboration
   └──────┬─────────────────────────────────────────┘
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
   subclass whose constructor raises. 64,786 packets, 9 alerts, no socket
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
detectors/             6 behavioural detectors + the anomaly model
alerts/schema.py       Alert dataclass, computed confidence, JSON
engine.py              the streaming loop
server.py              FastAPI: WebSocket /stream, /api/alerts, /api/replay
dashboard/index.html   live alert list + click-through evidence, no build step
bench/                 throughput and precision/recall harnesses
tools/selftest.py      20-check acceptance list, executed not ticked
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
- **No encrypted-traffic classification (PS class d).** Unbuilt. This is *not*
  because decryption is out of scope — the class asks for metadata-only
  analysis. See the reasoning above.
- **UDP amplification detection is victim-side only.** A one-way tap can only
  ever observe the reflector→victim leg, never the (external, spoofed)
  attacker→reflector leg — see `docs/DEFECTS.md` #21. A 1-2-reflector attack
  using a small number of very high-potency amplifiers can clear the
  byte-rate gate without reaching the minimum-reflector-count gate; not
  defended against in this pass.
- **Six of six classes is not claimed.** Five complete, one absent.
- **Known defects.** Every defect found in an internal audit is recorded with
  cause and remedy in [docs/DEFECTS.md](docs/DEFECTS.md), including one that
  affects the anomaly model's training input.

## Extensions, in priority order

`TLS_MALWARE` via JA3/JA4 from ClientHello metadata (completes the class list) →
NetFlow/IPFIX ingest alongside PCAP → live SPAN capture (would require
re-making the layer-1 isolation argument, deliberately) → alert persistence
and historical query.

A note on the second and third of those, because an earlier draft of this README
oversold them: NetFlow ingest is **not** a drop-in. `engine.run()` hardcodes
`PcapReader` (`engine.py:139`), any substitute must also duck-type
`packets_read` / `bytes_read` / `malformed` / `capture_duration`, and more
fundamentally the whole feature layer depends on per-packet TCP flags
(`is_syn` / `is_synack` / `is_rst`) that flow records do not carry — sampled
sFlow would additionally invalidate every rate. The iterator shape helps; it is
not the whole job.

Nothing in the current design needs to be undone to add any of them.

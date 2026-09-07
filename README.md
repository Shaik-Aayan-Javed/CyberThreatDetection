# Passive Threat Detection for Unidirectional IP Traffic

**SIH Problem Statement 26145** — AI-based detection of cyber threats in traffic
copied one-way into a monitoring enclave.

A gateway link is mirrored into an enclave that can see every packet and has no
route back. This prototype turns that one-way stream into explained alerts:
five behavioural detectors plus an unsupervised anomaly model, running as a
streaming pipeline, with the isolation constraint proven mechanically rather
than asserted on a slide.

```bash
py -3.13 -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt

python data/generate.py --seed 42      # 7 labelled captures, 190,363 packets
python train.py                        # fit + calibrate + validate the model
python engine.py data/pcaps/mixed.pcap --pretty
python server.py                       # then open http://127.0.0.1:8000
```

---

## What it detects

Five of the six PS threat classes, each from a distinct behavioural signal.
Every threshold is a multiple of a **learned** baseline, not a fixed constant.

| Class | Signal that fires it | Module |
|---|---|---|
| `SYN_FLOOD` | SYN rate vs baseline, completion ratio ≈ 0, **source-IP Shannon entropy** (separates one aggressive host from a spoofed flood) | `detectors/synflood.py` |
| `PORT_SCAN` | port + host fan-out from one source, RST ratio, sequential-port runs | `detectors/portscan.py` |
| `C2_BEACON` | coefficient of variation of inter-arrival times — scale-free, so one threshold catches a 20s and a 300s beacon | `detectors/beacon.py` |
| `DNS_ANOMALY` | QNAME character entropy + bigram plausibility against a real-domain corpus, label length, TXT/NULL ratio | `detectors/dns.py` |
| `EXFIL` | outbound:inbound byte ratio to a single destination, sustained | `detectors/exfil.py` |
| `ANOMALOUS_FLOW` | IsolationForest on 10 per-host features, trained on benign traffic only | `detectors/anomaly.py` |

`TLS_MALWARE` (JA3 fingerprinting) is deliberately **not** built. Computing a
JA3 hash is easy; *validating* it on traffic we synthesised ourselves would prove
nothing. It is the first extension seam, not a claimed capability.

## Measured results

All numbers below come from `tools/selftest.py`, `bench/metrics.py` and
`bench/throughput.py` on this machine. Nothing here is illustrative.

**Detection** (`docs/metrics.json`) — per-class precision / recall / F1 = 1.00
across all five classes, macro-F1 **1.00**, and:

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
`PORT_SCAN`, `DNS_ANOMALY` (one window), 45 s for `EXFIL`, 140 s for
`C2_BEACON`. The slow two are inherent — a beacon is not a beacon until enough
intervals exist to measure regularity, and calling it earlier would mean calling
it on two packets.

**Throughput** (`docs/throughput.json`), median of 3 runs, full pipeline with
the anomaly model loaded:

| Capture | packets/s | Mbit/s | flows/s | vs real time |
|---|---|---|---|---|
| `mixed.pcap` | 18,357 | 48.5 | 11,170 | **105×** |
| `synflood.pcap` | 17,278 | 34.7 | 11,557 | 110× |

Hardware: `Intel64 Family 6 Model 170` (Meteor Lake), 18 logical cores,
Windows 11, CPython 3.13 — single process, one core doing the work, no GPU.
105× real time means one core keeps up with a link carrying this traffic mix
with two orders of magnitude of headroom.

**Model** (`docs/model_report.json`): IsolationForest, 200 trees, 10 features,
trained on 256 benign windows, never on an attack. Mean ROC-AUC **0.996** across
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
   ┌───────────────────────────────────────────────┐
   │ synflood  portscan  beacon  dns  exfil        │  rules → evidence
   │ anomaly (IsolationForest)                     │  model → corroboration
   └──────┬────────────────────────────────────────┘
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

## Alerts explain themselves

The PS asks for intelligence an analyst can act on without re-contacting the
network. So no alert is a label plus a score — every one carries the
measurements that produced it:

```
[CRITICAL] SYN_FLOOD      conf=0.99
           flow: *->10.0.1.10/TCP
           - syn_rate_pps: 1500 pkt/s  (baseline 10)  -- 6.0x baseline threshold
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
   subclass whose constructor raises. 52,786 packets, 8 alerts, no socket
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
detectors/             5 behavioural detectors + the anomaly model
alerts/schema.py       Alert dataclass, computed confidence, JSON
engine.py              the streaming loop
server.py              FastAPI: WebSocket /stream, /api/alerts, /api/replay
dashboard/index.html   live alert list + click-through evidence, no build step
bench/                 throughput and precision/recall harnesses
tools/selftest.py      19-check acceptance list, executed not ticked
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
python tools/selftest.py               # 19 checks
docker build -t sih26145 .
docker run --rm --network none -v "${PWD}\data:/data:ro" sih26145 \
  /data/pcaps/mixed.pcap --pretty     # PowerShell; Git Bash mangles /data
```

Every stage is seeded. Two runs of `generate.py --seed 42` produce identical
captures, so every number in this README regenerates from scratch.

## Known limits

Stated here so a reviewer does not have to find them:

- **Synthetic traffic.** We wrote the captures and the ground truth. The metrics
  demonstrate detector behaviour, not field accuracy.
- **The anomaly model does not separate exfiltration by threshold.** It ranks it
  correctly (ROC-AUC 0.993) but scores it inside the benign tail. The `EXFIL`
  rule catches it; the model corroborates. Measured, in `docs/MODEL.md`.
- **Low-and-slow traffic is below the model's volume floor** (20 packets/window)
  — the beacon and DNS-tunnel hosts are invisible to it and are caught by rules
  alone.
- **No encrypted-traffic classification.** TLS/QUIC decryption is out of scope
  per the PS; JA3 is unbuilt for the reason given above.
- **Six of six classes is not claimed.** Five are built and measured.

## Extensions, in priority order

`TLS_MALWARE` via JA3/JA4 from ClientHello metadata (completes the class list) →
NetFlow/IPFIX ingest alongside PCAP (`reader.py` is already an iterator
interface) → live SPAN capture (would require re-making the layer-1 isolation
argument, deliberately) → alert persistence and historical query.

Nothing in the current design needs to be undone to add any of them.

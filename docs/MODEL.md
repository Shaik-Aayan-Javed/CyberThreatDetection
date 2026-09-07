# Models, Features, and Training/Validation

PS 26145 asks for documentation of the models used, the features engineered, and
the training/validation approach. This is that document.

The short version: **five transparent behavioural detectors carry the detection
load, and one unsupervised model provides corroboration and open-ended anomaly
coverage.** We did not train a network to read packets, and we do not claim to
have. What follows is what the system actually does.

---

## 1. Why the detection layer is mostly rules

A passive monitor in a data-diode enclave cannot collect labelled attack data
from the link it watches. It can collect a great deal of *benign* traffic and
essentially no ground-truth attacks. That constraint drives the whole design:

- **Supervised classification is not available.** No labels, no classifier.
- **Unsupervised anomaly detection is available** — you can learn normal.
- **Behavioural rules are available and explainable**, and explainability is the
  product here. The output is intelligence for an analyst who cannot go and
  check, so "why" matters as much as "what".

An alert that says `SYN_FLOOD, 0.99` is worth much less than one that says
`3,684 SYN/s against a baseline of 12, completion ratio 0.003, source entropy
12.87 bits across 7,500 distinct sources`. The second can be acted on without
re-contacting the network. The first cannot.

---

## 2. The five behavioural detectors

Each is a small, readable function over per-window features. Thresholds are
expressed as multiples of a **learned** baseline, not as fixed constants,
because "3,000 SYN/s is abnormal" is only true on some links.

| Detector | Module | Primary signal | Secondary signals |
|---|---|---|---|
| SYN flood / DDoS | `detectors/synflood.py` | SYN rate at a target vs learned baseline | observed completion ratio, source-IP Shannon entropy, unique source count |
| Port scan / recon | `detectors/portscan.py` | port + host fan-out from one source | completion ratio, sequential-port run ratio, connection rate |
| C2 beaconing | `detectors/beacon.py` | coefficient of variation of inter-arrival times | contact count, packet-size stability, persistence |
| DGA / DNS tunnelling | `detectors/dns.py` | QNAME character entropy + bigram plausibility | unique subdomain count, label length, TXT/NULL ratio |
| Data exfiltration | `detectors/exfil.py` | outbound:inbound byte ratio to one destination | total volume, sustained duration, burstiness |

Three design decisions worth calling out:

**Source-IP entropy for spoofing.** A flood from one aggressive client and a
spoofed flood from 7,500 forged addresses look identical on a rate graph. Shannon
entropy over the source distribution separates them, and the PS names this signal
explicitly.

**Coefficient of variation for periodicity.** `std(IAT) / mean(IAT)` is
scale-free, so one threshold catches a 30-second beacon and a 300-second beacon.
Set to 0.15, which tolerates roughly ±15% jitter. Beyond that, timing stops being
distinguishable from human-driven traffic and we would rather miss it than drown
the analyst.

**A bigram model for DGA, not a classifier.** `detectors/dns.py` builds an
add-k-smoothed character bigram model from a corpus of real domain labels at
import time. A judge can read the corpus and the scoring function in one sitting.
Typical real label scores ≈ −2.5; a random DGA label ≈ −4.5. Being inspectable
matters more here than being 2% more accurate.

### Confidence is computed, never hardcoded

Every score comes from `alerts.schema.confidence_from()`, which takes
observed/threshold ratios and compounds them:

```
conf = 1 − exp(−1.6 · Σ log(1 + max(0, rᵢ − 1)) / √n)
```

Signals corroborate (√n, not n), so three independent weak signals outrank one
strong one. There is no literal confidence value anywhere in the detector
source — `tools/selftest.py` asserts every evidence value is a measured number.

### Baselines resist poisoning

`features/baseline.py` keeps EWMA baselines with two protections against an
ongoing attack teaching the system that the attack is normal:

1. **Winsorized updates** — a sample above 4× the current mean is clipped before
   being folded in, so a burst moves the baseline slowly.
2. **Median, not mean** — `engine.update_baselines()` feeds the *median* host or
   target per window. One host under attack cannot drag a median of fifty.

---

## 3. The machine-learning component

**Model:** `IsolationForest` (scikit-learn), 200 trees, `contamination=0.01`,
`StandardScaler` on the inputs. Module: `detectors/anomaly.py`.

### Features engineered (10 dimensions, per source host per window)

Defined in `features/extract.host_vector()`:

| # | Feature | Rationale |
|---|---|---|
| 1 | `packet_rate_pps` | volume normalised by window duration |
| 2 | `log_bytes_out` | outbound volume; log-scaled, traffic is heavy-tailed |
| 3 | `log_bytes_in` | inbound volume, same reason |
| 4 | `unique_dst_hosts` | horizontal fan-out |
| 5 | `unique_dst_ports` | vertical fan-out |
| 6 | `syn_rate_pps` | connection attempt rate |
| 7 | `completion_ratio` | observed handshake success |
| 8 | `out_in_byte_ratio` | directional asymmetry, clipped at 1000 |
| 9 | `mean_packet_size` | payload shape proxy |
| 10 | `flow_rate_fps` | flow creation rate |

Rates are normalised by window duration so the model does not depend on the
window size we happened to choose. Training and inference call the *same*
extractor on the *same* reader — computing training features a different way
from inference features is the classic route to a model that validates well and
then fails in the pipeline.

### Training

- **Data:** `data/pcaps/normal.pcap` only — 256 host-window vectors.
- **Regime:** unsupervised. **The model never sees an attack during fit.**
- **Why:** it mirrors what a passive monitor can actually collect. You can record
  a quiet week off a production link; you cannot record a labelled corpus of
  attacks against your own infrastructure on demand.

### Calibration — and a bug worth documenting

Raw `decision_function` values are mapped to a 0–1 score anchored on the training
distribution: **benign median → 0.0, most extreme benign window → 0.90.** A score
above 0.90 therefore means "stranger than anything in the training data", and
`ALERT_THRESHOLD = 0.92` sits just above it.

The first implementation anchored 1.0 at the benign **1st percentile**. That
guaranteed by construction that ~1% of benign windows would score at the ceiling
and alert — and it did: **5 false positives on purely benign traffic.** Moving
the anchor to the benign extreme reduced that to **0**. `tools/selftest.py` now
asserts `benign_max_score < alert_threshold` so the bug cannot come back
unnoticed.

### Validation

Attack captures are scored, never trained on. ROC-AUC over
(host, window) pairs labelled from `data/labels.json`:

| Capture | ROC-AUC | Attacker score | Benign score |
|---|---|---|---|
| `portscan.pcap` | 1.000 | 0.994 | 0.094 |
| `exfil.pcap` | 0.993 | 0.751 | 0.145 |
| `mixed.pcap` | 0.997 | 0.776 | 0.154 |

Mean ROC-AUC **0.996**. Live numbers in `docs/model_report.json`.

### What the model does *not* do — measured, not assumed

AUC ≈ 1.0 flatters this model, and the raw distributions show why it should not
be taken at face value:

- benign minimum raw score: **−0.1015**
- port-scan attacker: **−0.144 to −0.138** → cleanly below every benign window
- exfiltration attacker: **−0.050 to −0.041** → **inside the benign tail**

So exfiltration is *ranked* correctly but not *separable* by threshold. It
scores 0.751 — real corroboration, below the 0.92 alerting bar. The `EXFIL` rule
detector catches it at 0.98 confidence on directional evidence.

Three concrete limitations:

1. **Spoofed-source floods are out of scope for this model.** The vector is
   per-source; in a spoofed flood every source appears once and the anomaly lives
   at the target. Handled by `detectors/synflood.py`.
2. **Low-and-slow threats fall below the volume floor.** Hosts under 20
   packets/window are not scored, which excludes the beacon host (6 packets per
   20s) and the DNS-tunnel host (~10 per window). Both are caught by their rule
   detectors. Lowering the floor would add noise, not coverage.
3. **Feature-space ranking is not an explanation.** The alert reports the three
   features furthest from the training mean. That is a ranking, and it is
   labelled as one.

This is the honest shape of the result: **the model catches high-volume
anomalies, the behavioural detectors catch low-and-slow ones, and neither alone
is sufficient.** That is a better story than "our AI catches everything", and it
is the one the measurements support.

### Fusion

The anomaly score is attached to every rule alert as `anomaly_score`. It can
raise confidence; it never lowers it and never suppresses a rule hit.
Behavioural evidence stays primary — see `engine.run()`.

---

## 4. Deliberately not built

| Not built | Why |
|---|---|
| Deep learning on raw packet bytes | No labelled data, no explainability, no time. Would not survive the "why did it fire" question. |
| LLM-based packet analysis | Wrong tool. Adds latency and cost to a problem solved by counting. |
| TLS/QUIC decryption | Explicitly out of scope (PS constraint b). Not implemented at any layer. |
| Active probing / scanning | Violates the passive constraint. `tools/isolation_check.py` proves absence mechanically. |
| Automated blocking | Requires a return path that does not exist. |
| Supervised threat classifier | No labelled attack data is obtainable in this deployment model. |

## 5. Reproducing

```bash
python data/generate.py --seed 42     # captures + ground truth
python train.py                       # fit, calibrate, validate -> docs/model_report.json
python bench/metrics.py               # precision / recall / F1 -> docs/metrics.json
python tools/selftest.py              # assert every claim above
```

All of it is seeded and deterministic.

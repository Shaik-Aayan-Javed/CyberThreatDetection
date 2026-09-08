# Models, Features, and Training/Validation

PS 26145 asks for documentation of the models used, the features engineered, and
the training/validation approach. This is that document.

The short version: **six transparent behavioural detectors carry the detection
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

## 2. The seven behavioural detectors

Each is a small, readable function over per-window features. Thresholds are
expressed as multiples of a **learned** baseline, not as fixed constants,
because "3,000 SYN/s is abnormal" is only true on some links.

One deliberate exception: `tlsmalware.py` declares no baseline. Its two
thresholds are already scale-free (a fraction and a coefficient of variation)
and its null model is computed per session from that session's own size
distribution, so a declared-but-never-observed baseline would be the defect
`docs/DEFECTS.md` #20 records four times over.

| Detector | Module | Primary signal | Secondary signals |
|---|---|---|---|
| SYN flood / DDoS | `detectors/synflood.py` | SYN rate at a target vs learned baseline | observed completion ratio, source-IP Shannon entropy, unique source count |
| UDP reflection / amplification | `detectors/udpamp.py` | aggregate inbound byte rate on reflector ports vs learned baseline | distinct-reflector count, per-port breakdown, amplification ratio vs outbound |
| Port scan / recon | `detectors/portscan.py` | port + host fan-out from one source | completion ratio, sequential-port run ratio, connection rate |
| C2 beaconing | `detectors/beacon.py` | coefficient of variation of inter-arrival times | contact count, packet-size stability, persistence |
| DGA / DNS tunnelling | `detectors/dns.py` | QNAME character entropy + bigram plausibility | unique subdomain count, label length, TXT/NULL ratio |
| Malware in encrypted sessions | `detectors/tlsmalware.py` | repeating period in the TLS record-size sequence, scored against that sequence's own analytic null | record inter-arrival CV, distinct-size count, JA3 fingerprint and its host count (evidence only, never a gate), SNI presence |
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

### How a threshold is actually built

Every rule threshold comes from three layers, and it matters which one is doing
the work in any given alert.

**1. The learned EWMA baseline.** `features/baseline.py` tracks a per-metric
exponentially-weighted mean of the *median* host or target per window, fed by
`engine.update_baselines()`. This is the adaptive part: if the link quietens the
baseline falls, if background traffic grows it rises.

**2. The warm-up floor.** For the first `WARMUP = 12` windows — one minute at a
5-second window — a metric has not seen enough samples to be trusted, so
`Metric.value` returns a conservative floor from `DEFAULTS` instead. After that
the floor is gone and the learned mean is returned, clamped only by a 1e-6
epsilon that exists solely to stop downstream detectors dividing by zero.

This is a correction. An earlier version returned `max(mean, floor)` in *both*
branches, which made the floor a permanent lower clamp rather than a warm-up
fallback. On a quiet link the mean converged well below the floor and never
escaped it, so every threshold was derived from a dictionary literal — an
adaptive-baseline API wrapped around a fixed-threshold detector. Measured on
`normal.pcap`, all four baselines any detector reads were floor-dominated for
the entire capture. They now report learned values:

| baseline | learned mean | warm-up floor | in effect after warm-up |
|---|---|---|---|
| `host_fanout_ports` | 1.996 | 2.0 | learned |
| `host_fanout_hosts` | 1.997 | 4.0 | learned |
| `bytes_out` | 1919.45 | 2000.0 | learned |
| `target_syn_rate` | 0.000 | 0.5 | learned |

**3. Absolute engineering minimums.** A learned baseline can legitimately be
zero — the median target on a normal link receives no SYNs at all — and six
times zero is still zero. So each detector backstops its baseline multiple with
an absolute minimum: `MIN_SYN_RATE = 50/s`, `MIN_PORTS = 25`, `MIN_HOSTS = 12`.
The threshold is `max(baseline × multiplier, absolute_minimum)`.

These are engineering judgements, stated as such: *fewer than 50 SYN/s is not a
flood on any link we would deploy to.* On the demo captures they are frequently
the binding term, precisely because the traffic is quiet. That is the honest
position, and it is different in kind from the old floors, which were fixed
constants **masquerading as observations**. When the minimum binds, the alert
evidence says so rather than printing a meaningless near-zero baseline:

```
- syn_rate_pps: 1500pkt/s  (baseline 50)
  -- median target sees no SYN traffic, so the 50/s absolute floor set the threshold
```

### Baselines resist poisoning

Two protections stop an ongoing attack teaching the system that the attack is
normal:

1. **Winsorized updates** — a sample above 4× the current mean is clipped before
   being folded in, so a burst moves the baseline slowly.
2. **Median, not mean** — `engine.update_baselines()` feeds the *median* host or
   target per window. One host under attack cannot drag a median of fifty.

The median is taken over hosts we actually observed *transmitting*
(`observed_as_source`), not over every address in the window. Rows created only
because a host received packets have structurally zero fan-out and zero
outbound volume, and including them dragged every median toward zero —
describing addresses that never sent anything rather than traffic on the link.

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
| 7 | `completion_ratio` | observed handshake success; **−1.0 when the host sent no SYN**, meaning "no data" rather than a ratio |
| 8 | `out_in_byte_ratio` | directional asymmetry, clipped at 1000 |
| 9 | `mean_packet_size` | payload shape proxy |
| 10 | `flow_rate_fps` | flow creation rate |

**Feature 7 was dead until recently, and the fix is worth recording.** It
previously returned `1.0` when a host had sent no SYN — indistinguishable from
"every handshake succeeded". Since most rows in the benign set are hosts that
never initiate TCP, *every* training vector reported `1.0`: the column had zero
variance, `StandardScaler` clamped its scale to 1.0, and the IsolationForest
could never split on it. A documented ten-feature model was really
nine-dimensional, and the missing dimension is the most discriminative one for
scans. Returning a `−1.0` sentinel instead separates "no handshake attempted"
from "all handshakes completed" and revived the column (`scale_` 1.0 → 0.4697,
zero-variance columns 1 → 0).

It also silently fixed a reporting bug: `detectors/anomaly.py` prints
"N standard deviations from the benign mean" in analyst-facing evidence, and
with a true standard deviation of zero that number was produced by the
zero-variance fallback rather than measured.

Rates are normalised by window duration so the model does not depend on the
window size we happened to choose. Training and inference call the *same*
extractor on the *same* reader — computing training features a different way
from inference features is the classic route to a model that validates well and
then fails in the pipeline.

### Training

- **Data:** `data/pcaps/normal.pcap` only — 256 host-window vectors.
- **Population:** hosts observed *transmitting* (`observed_as_source`) with at
  least 20 packets in the window. `train.collect_vectors()` and
  `AnomalyDetector.on_window()` apply this filter identically — scoring a
  population the model was not fitted on is the same class of bug as computing
  training features differently from inference features.
- **Regime:** unsupervised. **The model never sees an attack during fit.**
- **Why:** it mirrors what a passive monitor can actually collect. You can record
  a quiet week off a production link; you cannot record a labelled corpus of
  attacks against your own infrastructure on demand.

**A limitation of this population, measured rather than assumed.** Of those 256
rows, only **15 (5.9%)** initiated a flow or sent a SYN. The other 241 are
*responders* — remote CDN edges (Google, Microsoft, Akamai, Fastly) whose reply
traffic crosses the tap. They transmit, so they are legitimately in scope, but
the model's idea of "normal host behaviour" is dominated by what a server looks
like from the outside rather than by monitored clients.

Filtering to initiators is not a fix on this data: it leaves 15 vectors, and
fitting a 200-tree forest with `contamination=0.01` on 15 samples gives 0.15
expected outliers — a degenerate model, not a cleaner one. The real constraint
is that `normal.pcap` contains few internal clients with sustained traffic. The
honest resolution is to generate more benign client traffic and then filter, or
to add an initiator/responder flag as a feature and let the forest separate the
two populations itself. Neither is done yet.

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
| `portscan.pcap` | 1.000 | 0.972 | 0.089 |
| `exfil.pcap` | 0.993 | 0.727 | 0.137 |
| `mixed.pcap` | 0.997 | 0.752 | 0.146 |

Mean ROC-AUC **0.997**. Live numbers in `docs/model_report.json`.

### What the model does *not* do — measured, not assumed

AUC ≈ 1.0 flatters this model, and the raw distributions show why it should not
be taken at face value:

- benign minimum raw score: **−0.0981**
- port-scan attacker: **−0.1314 to −0.1252** → cleanly below every benign window
- exfiltration attacker: **−0.0451 to −0.0260** → **inside the benign tail**

So exfiltration is *ranked* correctly but not *separable* by threshold. It
scores 0.727 — real corroboration, below the 0.92 alerting bar. The `EXFIL` rule
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
| QUIC metadata analysis (the unbuilt half of PS class d) | Initial-packet headers are protected with a key derived from the connection ID. Recovering them is mechanical but sits closer to decryption than to header parsing, and we would rather not blur constraint (b). |
| JA3S and JA4 fingerprints | Client-side JA3 only. JA3S needs ServerHello parsing for little added signal; JA4 is a larger change. Noted because JA4's sorted lists would survive the extension-order permutation described below. |
| Active probing / scanning | Violates the passive constraint. `tools/isolation_check.py` proves absence mechanically. |
| Automated blocking | Requires a return path that does not exist. |
| Supervised threat classifier | No labelled attack data is obtainable in this deployment model. |

### The distinction between constraint (b) and class (d)

An earlier version of this table used "TLS/QUIC decryption is out of scope" as
the reason class (d) was unbuilt. That was wrong, and worth correcting
explicitly rather than quietly:

- **Constraint (b)** forbids decrypting payload. We comply — the parser stops at
  L4 plus DNS QNAMEs and TLS *record headers*, and never reconstructs an answer
  section or a TLS record body.
- **Class (d)** asks for detection *"from TLS/QUIC metadata alone (JA3/JA3S or
  JA4 fingerprints, packet-size and timing sequences), without decrypting
  payload."* It never required decryption. JA3 is computed from ClientHello
  *header* fields — version, cipher list, extensions, curves — which is byte
  parsing, sent in the clear before any key exchange completes.

That correction is now acted on rather than merely stated: the TLS half of class
(d) is built (`detectors/tlsmalware.py`), and only QUIC remains unbuilt, for the
narrower reason in the table above.

The earlier note also said a rare-JA3 score validated against fingerprints we
invented would demonstrate the parser rather than the detection. That objection
was correct, and it shaped the design rather than being argued away:

- **The fingerprint never gates.** Both gates are behavioural — size-sequence
  periodicity and arrival regularity — so the detector does not depend on our
  having guessed real-world fingerprints correctly. JA3 is reported as evidence
  for an analyst to pivot on.
- **The reason is measured, not asserted.** JA3 is order-sensitive by
  definition, and Chrome ≥ 110 permutes ClientHello extension order per
  connection. On 11 public Wireshark test captures, 3 of 6 real client hosts
  presented more than one fingerprint and one presented 8 — so a rarity gate
  would fire on ordinary browsing.
- **Validation runs on traffic we did not author.** `tools/tls_validate.py`
  against those same captures: 51 ClientHellos fingerprinted, 18 distinct
  fingerprints, 0 alerts of any class. It also found a real ingest bug in the process
  (`docs/DEFECTS.md` #24), which is the strongest argument for having done it.

What remains honestly weaker than the other detectors: the *rate* of
periodic-looking benign TLS on a busy production link is unknown to us, and
small protocol-test captures cannot establish it.

## 5. Reproducing

```bash
python data/generate.py --seed 42     # captures + ground truth
python train.py                       # fit, calibrate, validate -> docs/model_report.json
python bench/metrics.py               # precision / recall / F1 -> docs/metrics.json
python tools/selftest.py              # assert every claim above
```

All of it is seeded and deterministic.

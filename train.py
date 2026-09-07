"""Train and validate the anomaly model.

    python train.py --normal data/pcaps/normal.pcap --out models/anomaly.joblib

Training set: benign traffic ONLY. The model never sees an attack during fit.
That is not a shortcut -- it reflects what a passive monitor can actually
collect. You can record a quiet week off a production link; you cannot record a
labelled corpus of attacks against your own infrastructure on demand.

Validation therefore cannot be "accuracy on a held-out labelled set" in the
supervised sense. Instead we score the labelled attack captures and ask whether
the attacking host's windows separate from the benign ones (ROC-AUC), which is
the honest question to ask of an unsupervised density model.

Scope note, stated plainly: the feature vector is per-SOURCE-host, so this model
addresses threats where one source behaves unusually -- scanning, beaconing,
tunnelling, exfiltration. It does NOT address spoofed-source SYN floods, where
every source appears exactly once and the anomaly lives at the target. That
class is covered by detectors/synflood.py on behavioural evidence, and no claim
is made here that the model contributes to it.
"""

from __future__ import annotations

import argparse
import json
import os

import numpy as np

from detectors.anomaly import AnomalyModel
from features.extract import VECTOR_FEATURE_NAMES, extract, host_vector
from ingest.flows import FlowTable, Windower
from ingest.reader import PcapReader

# Hosts quieter than this contribute noise rather than signal.
MIN_PACKETS = 20


def collect(pcap: str, window_s: float = 5.0):
    """Run a capture through ingest+features and return per-host vectors.

    Deliberately reuses the exact reader, flow table, windower and extractor the
    live engine uses. Computing training features a different way from inference
    features is the classic route to a model that validates well and then fails
    in the pipeline.
    """
    reader = PcapReader(pcap, speed=0.0)
    table = FlowTable()
    windower = Windower(duration=window_s)

    vectors: list[list[float]] = []
    meta: list[dict] = []

    def take(window) -> None:
        wf = extract(window)
        for src, hf in wf.by_src.items():
            if hf.packets < MIN_PACKETS:
                continue
            vectors.append(host_vector(hf, wf.duration))
            meta.append({"src": src, "start": window.start, "end": window.end})

    for pkt in reader.packets():
        rec, _ = table.update(pkt)
        closed = windower.add(pkt, rec)
        if closed is not None:
            take(closed)
    trailing = windower.flush()
    if trailing is not None:
        take(trailing)

    return np.asarray(vectors, dtype=float), meta


def label_from_truth(meta: list[dict], truths: list[dict]) -> np.ndarray:
    """1 if this (host, window) is the labelled attacker during its episode."""
    labels = np.zeros(len(meta), dtype=int)
    for i, m in enumerate(meta):
        for t in truths:
            if t["src"] == "*":
                continue  # spoofed-source episodes have no single source host
            if m["src"] != t["src"]:
                continue
            if m["end"] >= t["start_epoch"] and m["start"] <= t["end_epoch"]:
                labels[i] = 1
                break
    return labels


def main() -> int:
    ap = argparse.ArgumentParser(description="Train the benign-traffic anomaly model")
    ap.add_argument("--normal", default="data/pcaps/normal.pcap")
    ap.add_argument("--out", default="models/anomaly.joblib")
    ap.add_argument("--labels", default="data/labels.json")
    ap.add_argument("--window", type=float, default=5.0)
    ap.add_argument("--trees", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--report", default="docs/model_report.json")
    args = ap.parse_args()

    print(f"Training on benign capture: {args.normal}")
    X, meta = collect(args.normal, args.window)
    if len(X) < 50:
        print(f"ERROR: only {len(X)} training vectors; need a longer benign capture.")
        return 1

    model = AnomalyModel()
    info = model.fit(X, n_estimators=args.trees, seed=args.seed)
    model.save(args.out)

    print(f"  {info['samples']} host-window vectors x {info['features']} features")
    print(f"  IsolationForest, {info['n_estimators']} trees, contamination=0.01")
    print(f"  calibration: benign median raw={info['calibration_median_raw']:+.4f}"
          f"  benign extreme raw={info['calibration_extreme_raw']:+.4f}")
    print(f"  benign max calibrated score={info['benign_max_score']:.3f}"
          f"  (alert threshold {info['alert_threshold']})")
    if info["benign_max_score"] >= info["alert_threshold"]:
        print("  WARNING: the model would alert on its own training data.")
    print(f"  saved -> {args.out}")

    report = {
        "model": "IsolationForest",
        "library": "scikit-learn",
        "trained_on": args.normal,
        "training_regime": "unsupervised; benign traffic only, no attack samples seen during fit",
        "features": VECTOR_FEATURE_NAMES,
        "window_seconds": args.window,
        "hyperparameters": {
            "n_estimators": args.trees,
            "contamination": 0.01,
            "random_state": args.seed,
            "scaler": "StandardScaler",
        },
        "training": info,
        "feature_means": {
            n: round(float(v), 4) for n, v in zip(VECTOR_FEATURE_NAMES, model.scaler.mean_)
        },
        "validation": {},
        "scope_limitation": (
            "Per-source feature vector. Does not address spoofed-source floods, where "
            "each source appears once and the anomaly is at the target; that class is "
            "handled by the behavioural SYN flood detector."
        ),
    }

    benign_scores = model.score_many(X)
    report["validation"]["benign_score_mean"] = round(float(benign_scores.mean()), 4)
    report["validation"]["benign_score_p99"] = round(float(np.percentile(benign_scores, 99)), 4)

    if os.path.exists(args.labels):
        from sklearn.metrics import roc_auc_score

        with open(args.labels, encoding="utf-8") as fh:
            manifest = json.load(fh)

        print("\nValidation (these captures are scored, never trained on):")
        per_capture = {}

        for name, cap_info in manifest["captures"].items():
            truths = cap_info.get("ground_truth") or []
            if not any(t["src"] != "*" for t in truths):
                continue
            path = os.path.join("data", "pcaps", name)
            if not os.path.exists(path):
                continue

            Xa, meta_a = collect(path, args.window)
            if len(Xa) == 0:
                continue
            y = label_from_truth(meta_a, truths)
            if y.sum() == 0:
                continue

            scores = model.score_many(Xa)
            auc = float(roc_auc_score(y, scores))
            atk = float(scores[y == 1].mean())
            ben = float(scores[y == 0].mean())
            per_capture[name] = {
                "roc_auc": round(auc, 4),
                "attacker_window_score_mean": round(atk, 4),
                "benign_window_score_mean": round(ben, 4),
                "attacker_windows": int(y.sum()),
                "benign_windows": int((y == 0).sum()),
            }
            print(f"  {name:<18} AUC={auc:.3f}  attacker={atk:.3f}  benign={ben:.3f}"
                  f"  ({int(y.sum())} attacker windows)")

        report["validation"]["per_capture"] = per_capture
        if per_capture:
            aucs = [v["roc_auc"] for v in per_capture.values()]
            mean_auc = round(sum(aucs) / len(aucs), 4)
            report["validation"]["mean_roc_auc"] = mean_auc
            print(f"\n  mean ROC-AUC across captures: {mean_auc:.3f}")

    os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nreport -> {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

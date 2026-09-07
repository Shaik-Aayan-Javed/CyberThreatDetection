"""Detection metrics against the labelled captures.

    python bench/metrics.py

Reports, per threat class: precision, recall, F1, and detection latency. Plus
the number that matters most in review -- how many alerts fire on the purely
benign capture, where the correct answer is zero.

Read the numbers with their caveat attached. The captures are synthetic and we
authored the attacks, so this measures "do the detectors fire correctly on known
ground truth", not "how accurate is this in production". A perfect score here is
the floor for a working prototype, not evidence of a good detector.

Counting rules, stated so they can be argued with:
  - recall is per EPISODE. One labelled attack that produces three alerts is one
    detection, not three. Counting per-alert would let a chatty detector inflate
    its own recall.
  - precision is per ALERT. Every alert that matches no labelled episode is a
    false positive, including duplicates outside an episode's time range.
  - ANOMALOUS_FLOW has no labelled ground truth (it is an unsupervised channel),
    so it is excluded from the class table and reported separately rather than
    being quietly scored as either right or wrong.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

import engine  # noqa: E402
from alerts.schema import ANOMALOUS_FLOW  # noqa: E402

# Slow-accumulating detectors (beacon, exfil) legitimately confirm shortly after
# an episode's last packet. Alerts inside this grace period still count.
GRACE_S = 90.0


def entity_match(alert: dict, truth: dict) -> bool:
    blob = f"{alert.get('flow_id','')} {alert.get('src','')} {alert.get('dst','')}"
    if truth["src"] != "*" and truth["src"] not in blob:
        return False
    if truth["dst"] != "*" and truth["dst"] not in blob:
        return False
    return True


def time_match(alert: dict, truth: dict) -> bool:
    w = alert.get("window", {})
    start = w.get("start_epoch")
    end = w.get("end_epoch")
    if start is None or end is None:
        return False
    return end >= truth["start_epoch"] and start <= truth["end_epoch"] + GRACE_S


def matches(alert: dict, truth: dict) -> bool:
    return (
        alert["threat_class"] == truth["threat_class"]
        and time_match(alert, truth)
        and entity_match(alert, truth)
    )


def evaluate(manifest: dict, pcap_dir: str, window: float, use_model: bool) -> dict:
    per_class: dict[str, dict] = {}
    anomaly_alerts = 0
    anomaly_on_attacker = 0
    benign_false_positives = 0
    latencies: list[dict] = []
    captures: dict[str, dict] = {}

    for name, cap in manifest["captures"].items():
        path = os.path.join(pcap_dir, name)
        if not os.path.exists(path):
            continue

        collected: list[dict] = []
        stats = engine.run(
            path,
            speed=0.0,
            window_s=window,
            model_path=engine.DEFAULT_MODEL_PATH if use_model else None,
            enable_anomaly=use_model,
            on_alert=lambda a: collected.append(a.to_dict()),
        )

        truths = cap.get("ground_truth") or []
        rule_alerts = [a for a in collected if a["threat_class"] != ANOMALOUS_FLOW]
        anon = [a for a in collected if a["threat_class"] == ANOMALOUS_FLOW]
        anomaly_alerts += len(anon)
        for a in anon:
            if any(entity_match(a, t) and time_match(a, t) for t in truths):
                anomaly_on_attacker += 1

        # --- precision side: does each alert land on a labelled episode? ---
        tp_alerts = 0
        for a in rule_alerts:
            cls = a["threat_class"]
            slot = per_class.setdefault(cls, {"tp": 0, "fp": 0, "episodes": 0, "detected": 0})
            if any(matches(a, t) for t in truths):
                slot["tp"] += 1
                tp_alerts += 1
            else:
                slot["fp"] += 1
                if not truths:
                    benign_false_positives += 1

        # --- recall side: was each labelled episode detected at all? ---
        for t in truths:
            slot = per_class.setdefault(
                t["threat_class"], {"tp": 0, "fp": 0, "episodes": 0, "detected": 0}
            )
            slot["episodes"] += 1
            hits = [a for a in rule_alerts if matches(a, t)]
            if hits:
                slot["detected"] += 1
                first = min(h["window"]["end_epoch"] for h in hits)
                latencies.append({
                    "capture": name,
                    "threat_class": t["threat_class"],
                    "latency_s": round(first - t["start_epoch"], 2),
                })

        captures[name] = {
            "packets": stats.packets,
            "episodes": len(truths),
            "rule_alerts": len(rule_alerts),
            "anomaly_alerts": len(anon),
            "matched_alerts": tp_alerts,
        }
        flag = "" if truths else "   <- benign capture, expect 0"
        print(f"  {name:<18} {stats.packets:>6} pkts  "
              f"{len(rule_alerts):>2} rule alerts  {len(anon):>2} anomaly{flag}")

    for cls, s in per_class.items():
        tp, fp = s["tp"], s["fp"]
        s["precision"] = round(tp / (tp + fp), 4) if (tp + fp) else 1.0
        s["recall"] = round(s["detected"] / s["episodes"], 4) if s["episodes"] else 0.0
        p, r = s["precision"], s["recall"]
        s["f1"] = round(2 * p * r / (p + r), 4) if (p + r) else 0.0

    return {
        "per_class": per_class,
        "captures": captures,
        "benign_false_positives": benign_false_positives,
        "anomaly_channel": {
            "total_alerts": anomaly_alerts,
            "on_labelled_attacker": anomaly_on_attacker,
            "note": "unsupervised channel; excluded from the class table by design",
        },
        "latency": latencies,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure detection performance")
    ap.add_argument("--labels", default="data/labels.json")
    ap.add_argument("--pcaps", default="data/pcaps")
    ap.add_argument("--window", type=float, default=5.0)
    ap.add_argument("--no-model", action="store_true")
    ap.add_argument("--out", default="docs/metrics.json")
    args = ap.parse_args()

    with open(args.labels, encoding="utf-8") as fh:
        manifest = json.load(fh)

    print("Replaying labelled captures\n")
    result = evaluate(manifest, args.pcaps, args.window, not args.no_model)

    print("\n" + "=" * 74)
    print(f"{'THREAT CLASS':<16}{'PREC':>8}{'RECALL':>8}{'F1':>8}"
          f"{'EPISODES':>10}{'FOUND':>7}{'FP':>6}")
    print("-" * 74)
    for cls in sorted(result["per_class"]):
        s = result["per_class"][cls]
        print(f"{cls:<16}{s['precision']:>8.3f}{s['recall']:>8.3f}{s['f1']:>8.3f}"
              f"{s['episodes']:>10}{s['detected']:>7}{s['fp']:>6}")
    print("-" * 74)

    classes = result["per_class"]
    if classes:
        n = len(classes)
        macro_p = sum(s["precision"] for s in classes.values()) / n
        macro_r = sum(s["recall"] for s in classes.values()) / n
        macro_f = sum(s["f1"] for s in classes.values()) / n
        result["macro"] = {
            "precision": round(macro_p, 4),
            "recall": round(macro_r, 4),
            "f1": round(macro_f, 4),
        }
        print(f"{'MACRO AVG':<16}{macro_p:>8.3f}{macro_r:>8.3f}{macro_f:>8.3f}")

    lat = result["latency"]
    if lat:
        vals = sorted(x["latency_s"] for x in lat)
        result["latency_summary"] = {
            "min_s": vals[0],
            "median_s": vals[len(vals) // 2],
            "max_s": vals[-1],
        }
        print(f"\nDetection latency (capture time from episode start to first alert):")
        print(f"  min {vals[0]:.1f}s   median {vals[len(vals)//2]:.1f}s   max {vals[-1]:.1f}s")

    fp = result["benign_false_positives"]
    print(f"\nFalse positives on benign capture: {fp}"
          f"{'  <- clean' if fp == 0 else '  <- INVESTIGATE'}")
    a = result["anomaly_channel"]
    print(f"Anomaly channel: {a['total_alerts']} alerts, "
          f"{a['on_labelled_attacker']} on a labelled attacker")

    print("\nCaveat: synthetic captures with attacks we authored. These numbers show")
    print("the detectors fire correctly on known ground truth, not production accuracy.")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"\n-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

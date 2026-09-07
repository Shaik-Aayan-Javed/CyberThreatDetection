"""Sustained throughput measurement.

    python bench/throughput.py

PS 26145 constraint (d) requires stating and demonstrating the traffic rate the
solution was tested against. Every number this prints is measured on the machine
it runs on -- nothing here is a target, an estimate, or a projection.

What is being measured: the full pipeline end to end. Parse, flow table update,
windowing, feature extraction, all five rule detectors, and the anomaly model.
Not just the parser. Replay runs at --speed 0 (no pacing) so the measurement
reflects processing capacity rather than how fast the capture was recorded.

Reported as the MEDIAN of several runs, with min and max shown, because a single
timing on a laptop with background load is not a measurement.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

import engine  # noqa: E402


def hardware() -> dict:
    return {
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
    }


def measure(pcap: str, repeats: int, window: float, use_model: bool) -> dict:
    runs = []
    for i in range(repeats):
        t0 = time.perf_counter()
        stats = engine.run(
            pcap,
            speed=0.0,
            window_s=window,
            model_path=engine.DEFAULT_MODEL_PATH if use_model else None,
            enable_anomaly=use_model,
        )
        wall = time.perf_counter() - t0
        runs.append({
            "packets": stats.packets,
            "bytes": stats.bytes,
            "flows": stats.flows,
            "alerts": stats.alerts,
            "wall_s": wall,
            "pps": stats.packets / wall,
            "mbps": (stats.bytes * 8 / 1e6) / wall,
            "fps": stats.flows / wall,
            "capture_duration_s": stats.capture_duration,
        })
        print(f"    run {i+1}/{repeats}: {runs[-1]['pps']:>10,.0f} pkt/s"
              f"   {runs[-1]['mbps']:>7.1f} Mbit/s")

    pps = [r["pps"] for r in runs]
    mbps = [r["mbps"] for r in runs]
    fps = [r["fps"] for r in runs]
    first = runs[0]

    # How much faster than real time the pipeline consumes this capture. A
    # value of 60 means one second of processing absorbs a minute of traffic.
    realtime = (first["capture_duration_s"] / statistics.median([r["wall_s"] for r in runs])
                if first["capture_duration_s"] else 0.0)

    return {
        "packets": first["packets"],
        "bytes": first["bytes"],
        "flows": first["flows"],
        "alerts": first["alerts"],
        "capture_duration_s": round(first["capture_duration_s"], 2),
        "runs": repeats,
        "pps_median": round(statistics.median(pps), 1),
        "pps_min": round(min(pps), 1),
        "pps_max": round(max(pps), 1),
        "mbps_median": round(statistics.median(mbps), 3),
        "flows_per_s_median": round(statistics.median(fps), 1),
        "realtime_factor": round(realtime, 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure sustained pipeline throughput")
    ap.add_argument("pcaps", nargs="*", default=["data/pcaps/mixed.pcap",
                                                 "data/pcaps/synflood.pcap"])
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--window", type=float, default=5.0)
    ap.add_argument("--no-model", action="store_true", help="rules only")
    ap.add_argument("--out", default="docs/throughput.json")
    args = ap.parse_args()

    hw = hardware()
    print("Hardware")
    for k, v in hw.items():
        print(f"  {k:<12} {v}")
    print(f"\nPipeline: parse -> flows -> {args.window:g}s windows -> 5 rule detectors"
          f"{'' if args.no_model else ' + anomaly model'}\n")

    results = {}
    for pcap in args.pcaps:
        if not os.path.exists(pcap):
            print(f"  skip (missing): {pcap}")
            continue
        print(f"  {os.path.basename(pcap)}")
        results[os.path.basename(pcap)] = measure(
            pcap, args.repeats, args.window, not args.no_model
        )
        print()

    if not results:
        print("No captures measured. Run data/generate.py first.")
        return 1

    print("=" * 72)
    print(f"{'CAPTURE':<18}{'PKT/S':>12}{'MBIT/S':>10}{'FLOWS/S':>11}{'x REALTIME':>13}")
    print("-" * 72)
    for name, r in results.items():
        print(f"{name:<18}{r['pps_median']:>12,.0f}{r['mbps_median']:>10.1f}"
              f"{r['flows_per_s_median']:>11,.0f}{r['realtime_factor']:>12,.0f}x")
    print("-" * 72)

    best = max(results.values(), key=lambda r: r["pps_median"])
    print(f"\nSustained rate tested against: {best['pps_median']:,.0f} packets/sec "
          f"({best['mbps_median']:.1f} Mbit/s) on the hardware above.")
    print("Measured end to end including detection, single process, single core.")

    payload = {"hardware": hw, "window_s": args.window,
               "anomaly_model": not args.no_model, "captures": results}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\n-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

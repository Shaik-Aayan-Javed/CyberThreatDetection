"""Streaming detection engine.

    packets -> flow table -> tumbling window -> features -> detectors -> alerts

Alerts are emitted the moment a window closes, not at end of capture, so alert
latency is bounded by the window duration no matter how long the stream runs
(PS 26145 constraint c). Nothing in this file or anything it imports opens a
socket -- the only input is a file descriptor and the only output is a callback.

Run it directly for the Day 1 deliverable:

    python engine.py data/pcaps/mixed.pcap
    python engine.py data/pcaps/mixed.pcap --speed 10 --pretty
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from alerts.schema import Alert
from detectors.anomaly import DEFAULT_MODEL_PATH, AnomalyDetector
from detectors.base import Detector
from detectors.beacon import BeaconDetector
from detectors.dns import DnsAnomalyDetector
from detectors.exfil import ExfilDetector
from detectors.portscan import PortScanDetector
from detectors.synflood import SynFloodDetector
from features.baseline import BaselineTracker
from features.extract import WindowFeatures, extract
from ingest.flows import FlowTable, Windower
from ingest.reader import PcapReader

AlertSink = Callable[[Alert], None]
StatsSink = Callable[["EngineStats"], None]


@dataclass
class EngineStats:
    packets: int = 0
    bytes: int = 0
    flows: int = 0
    windows: int = 0
    alerts: int = 0
    malformed: int = 0
    by_class: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    elapsed: float = 0.0
    capture_duration: float = 0.0

    @property
    def pps(self) -> float:
        return self.packets / self.elapsed if self.elapsed > 0 else 0.0

    @property
    def mbps(self) -> float:
        return (self.bytes * 8 / 1e6) / self.elapsed if self.elapsed > 0 else 0.0

    @property
    def fps(self) -> float:
        return self.flows / self.elapsed if self.elapsed > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "flows": self.flows,
            "windows": self.windows,
            "alerts": self.alerts,
            "malformed": self.malformed,
            "by_class": self.by_class,
            "by_severity": self.by_severity,
            "elapsed_s": round(self.elapsed, 3),
            "capture_duration_s": round(self.capture_duration, 3),
            "throughput_pps": round(self.pps, 1),
            "throughput_mbps": round(self.mbps, 3),
            "flows_per_s": round(self.fps, 1),
        }


def build_detectors(model_path: str | None = DEFAULT_MODEL_PATH,
                    enable_anomaly: bool = True) -> list[Detector]:
    detectors: list[Detector] = [
        SynFloodDetector(),
        PortScanDetector(),
        BeaconDetector(),
        DnsAnomalyDetector(),
        ExfilDetector(),
    ]
    if enable_anomaly:
        detectors.append(AnomalyDetector(model_path=model_path or ""))
    return detectors


def update_baselines(wf: WindowFeatures, baselines: BaselineTracker) -> None:
    """Teach the baselines what this window looked like.

    Uses the MEDIAN host/target rather than the mean or max. One host under
    attack cannot drag a median of fifty; a mean it would. Combined with the
    winsorized EWMA in features/baseline.py, this is what stops an ongoing
    attack from normalising itself.
    """
    baselines.windows_seen += 1
    baselines.observe("pps", wf.pps)
    baselines.observe("bps", wf.bps)

    if wf.by_dst:
        syn_rates = [tf.syn_in / wf.duration for tf in wf.by_dst.values()]
        baselines.observe("target_syn_rate", statistics.median(syn_rates))

    if wf.by_src:
        hosts = list(wf.by_src.values())
        baselines.observe("syn_rate", statistics.median([h.syn_sent / wf.duration for h in hosts]))
        baselines.observe("host_fanout_ports", statistics.median([len(h.dst_ports) for h in hosts]))
        baselines.observe("host_fanout_hosts", statistics.median([len(h.dst_hosts) for h in hosts]))
        baselines.observe("bytes_out", statistics.median([h.bytes_out for h in hosts]))
        completions = [h.completion_ratio for h in hosts if h.syn_sent > 0]
        if completions:
            baselines.observe("completion_ratio", statistics.median(completions))


def run(
    pcap: str,
    *,
    speed: float = 0.0,
    window_s: float = 5.0,
    model_path: str | None = DEFAULT_MODEL_PATH,
    enable_anomaly: bool = True,
    limit: int | None = None,
    on_alert: AlertSink | None = None,
    on_window: StatsSink | None = None,
) -> EngineStats:
    """Drive one capture through the pipeline. Returns final stats."""
    reader = PcapReader(pcap, speed=speed, limit=limit)
    table = FlowTable()
    windower = Windower(duration=window_s)
    baselines = BaselineTracker()
    detectors = build_detectors(model_path, enable_anomaly)
    anomaly = next((d for d in detectors if isinstance(d, AnomalyDetector)), None)

    stats = EngineStats()
    started = time.perf_counter()

    def process(window) -> None:
        wf = extract(window)
        stats.windows += 1

        window_alerts: list[Alert] = []
        for det in detectors:
            try:
                window_alerts.extend(det.on_window(wf, baselines))
            except Exception as exc:  # one bad detector must not stop the stream
                print(f"[engine] {det.name} failed on window {window.index}: {exc}",
                      file=sys.stderr)

        # Attach the anomaly score to rule-based alerts as corroboration. The
        # model can raise confidence but never lowers it, and never suppresses a
        # rule hit -- behavioural evidence stays the primary signal.
        if anomaly is not None and anomaly.last_scores:
            for alert in window_alerts:
                if alert.detector == anomaly.name:
                    continue
                score = anomaly.last_scores.get(alert.src)
                if score is not None:
                    alert.anomaly_score = round(score, 3)

        for alert in window_alerts:
            stats.alerts += 1
            stats.by_class[alert.threat_class] = stats.by_class.get(alert.threat_class, 0) + 1
            stats.by_severity[alert.severity] = stats.by_severity.get(alert.severity, 0) + 1
            if on_alert:
                on_alert(alert)

        update_baselines(wf, baselines)

        stats.packets = reader.packets_read
        stats.bytes = reader.bytes_read
        stats.flows = table.total_flows
        stats.elapsed = time.perf_counter() - started
        if on_window:
            on_window(stats)

    for pkt in reader.packets():
        rec, _ = table.update(pkt)
        closed = windower.add(pkt, rec)
        if closed is not None:
            process(closed)

    trailing = windower.flush()
    if trailing is not None:
        process(trailing)

    stats.packets = reader.packets_read
    stats.bytes = reader.bytes_read
    stats.flows = table.total_flows
    stats.malformed = reader.malformed
    stats.elapsed = time.perf_counter() - started
    stats.capture_duration = reader.capture_duration
    return stats


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SIH26145 passive threat detection engine")
    ap.add_argument("pcap", help="path to a PCAP/PCAPNG file (read-only)")
    ap.add_argument("--speed", type=float, default=0.0,
                    help="0 = as fast as possible, 1 = real time, 10 = 10x real time")
    ap.add_argument("--window", type=float, default=5.0, help="window duration in seconds")
    ap.add_argument("--model", default=DEFAULT_MODEL_PATH, help="anomaly model path")
    ap.add_argument("--no-anomaly", action="store_true", help="rules only")
    ap.add_argument("--limit", type=int, default=None, help="stop after N packets")
    ap.add_argument("--pretty", action="store_true", help="human-readable alert lines")
    ap.add_argument("--out", default=None, help="also append alerts as JSONL to this file")
    ap.add_argument("--quiet", action="store_true", help="summary only")
    args = ap.parse_args(list(argv) if argv is not None else None)

    fh = open(args.out, "w", encoding="utf-8") if args.out else None

    def emit(alert: Alert) -> None:
        if fh:
            fh.write(alert.to_json() + "\n")
        if args.quiet:
            return
        if args.pretty:
            print(f"\n[{alert.severity:8}] {alert.threat_class:14} "
                  f"conf={alert.confidence:.2f}  {alert.timestamp}")
            print(f"           flow: {alert.flow_id}")
            for ev in alert.evidence:
                base = f"  (baseline {ev.baseline:g})" if ev.baseline is not None else ""
                note = f"  -- {ev.note}" if ev.note else ""
                print(f"           - {ev.feature}: {ev.value:g}{ev.unit}{base}{note}")
        else:
            print(alert.to_json())

    stats = run(
        args.pcap,
        speed=args.speed,
        window_s=args.window,
        model_path=None if args.no_anomaly else args.model,
        enable_anomaly=not args.no_anomaly,
        limit=args.limit,
        on_alert=emit,
    )

    if fh:
        fh.close()

    print(json.dumps({"summary": stats.to_dict()}, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

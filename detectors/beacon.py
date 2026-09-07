"""Detector #3 -- Botnet C2 beaconing.

The only detector here that fundamentally cannot work inside a single window: a
30-second beacon is invisible in a 5-second slice. It keeps a rolling per-pair
timing series across windows, which is the concrete reason the whole pipeline is
built around stateful detectors instead of per-window batch jobs.

Signal: a (source -> destination:port) pair contacted repeatedly with low
variance in inter-arrival time. Periodicity is measured as the coefficient of
variation of the IAT series (std / mean) -- scale-free, so it catches a 30s
beacon and a 300s beacon with the same threshold.

Real malware jitters deliberately, so the threshold tolerates roughly +/-15%.
Beyond that, timing stops being distinguishable from human-driven traffic and we
would rather miss it than flood the analyst with false positives.
"""

from __future__ import annotations

import statistics
from collections import defaultdict, deque

from alerts.schema import C2_BEACON, Alert, Evidence, confidence_from
from detectors.base import Detector
from features.baseline import BaselineTracker
from features.extract import WindowFeatures

# Contacts required before periodicity means anything. Three evenly spaced
# points happen by chance; eight do not.
MIN_CONTACTS = 8
# std/mean of inter-arrival times below this is "regular".
MAX_CV = 0.15
# Ignore intervals faster than this -- back-to-back packets inside one burst are
# not a beacon, they are a transfer.
MIN_INTERVAL_S = 1.0
# Forget contacts older than this so a pair that stopped beaconing ages out.
HISTORY_S = 1800.0
MAX_HISTORY = 400


class BeaconDetector(Detector):
    name = "beacon.v1"
    threat_class = C2_BEACON
    cooldown_s = 120.0

    def __init__(self) -> None:
        super().__init__()
        # (src, dst, dport) -> deque[(ts, frame_len)]
        self.history: dict[tuple[str, str, int], deque] = defaultdict(
            lambda: deque(maxlen=MAX_HISTORY)
        )

    def on_window(self, wf: WindowFeatures, baselines: BaselineTracker) -> list[Alert]:
        touched: set[tuple[str, str, int]] = set()

        for src, hf in wf.by_src.items():
            for dst, dport, ts, size in hf.contacts:
                key = (src, dst, dport)
                self.history[key].append((ts, size))
                touched.add(key)

        self._prune(wf.window.end)

        alerts: list[Alert] = []
        # Only re-evaluate pairs that saw activity this window; everything else
        # cannot have changed.
        for key in touched:
            alert = self._evaluate(key, wf)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def _prune(self, now: float) -> None:
        cutoff = now - HISTORY_S
        empty = []
        for key, series in self.history.items():
            while series and series[0][0] < cutoff:
                series.popleft()
            if not series:
                empty.append(key)
        for key in empty:
            del self.history[key]

    def _evaluate(self, key, wf: WindowFeatures) -> Alert | None:
        src, dst, dport = key
        series = self.history[key]
        if len(series) < MIN_CONTACTS:
            return None

        times = [t for t, _ in series]
        sizes = [s for _, s in series]

        intervals = [b - a for a, b in zip(times, times[1:]) if (b - a) >= MIN_INTERVAL_S]
        if len(intervals) < MIN_CONTACTS - 1:
            return None

        mean_iat = statistics.fmean(intervals)
        if mean_iat <= 0:
            return None
        stdev_iat = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev_iat / mean_iat

        if cv > MAX_CV:
            return None

        # Packet-size stability: implants send fixed-shape check-ins.
        mean_size = statistics.fmean(sizes)
        size_cv = (statistics.pstdev(sizes) / mean_size) if mean_size > 0 and len(sizes) > 1 else 0.0

        persistence = times[-1] - times[0]

        conf = confidence_from(
            MAX_CV / max(cv, 0.005),
            len(series) / MIN_CONTACTS,
            1.0 + max(0.0, 1.0 - size_cv * 5),
        )

        if not self.ready(f"{src}|{dst}|{dport}", wf.window.end):
            return None
        self.mark(f"{src}|{dst}|{dport}", wf.window.end)

        return Alert.build(
            threat_class=self.threat_class,
            detector=self.name,
            confidence=conf,
            flow_id=f"{src}->{dst}:{dport}",
            src=src,
            dst=f"{dst}:{dport}",
            window_start=wf.window.start,
            window_end=wf.window.end,
            evidence=[
                Evidence("repeated_connections", len(series), None, "contacts",
                         f"to a single destination over {persistence:.0f}s"),
                Evidence("mean_interval", mean_iat, None, "s",
                         f"jitter +/-{stdev_iat:.2f}s"),
                Evidence("interval_cv", cv, MAX_CV, "",
                         "std/mean of inter-arrival times; lower is more machine-like"),
                Evidence("packet_size_cv", size_cv, 0.0, "",
                         f"mean frame {mean_size:.0f} B"),
                Evidence("persistence", persistence, None, "s"),
                Evidence("destination_cardinality", 1, None, "hosts",
                         "traffic concentrated on one destination"),
            ],
        )

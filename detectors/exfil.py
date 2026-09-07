"""Detector #5 -- Data exfiltration.

Asymmetric flow volume: a host pushing far more out to one destination than it
pulls back, sustained long enough that it is not a one-off upload burst.

Normal client traffic is inbound-heavy -- you download pages, you upload a few
kilobytes of requests. Inverting that ratio against a single external
destination for minutes at a time is the signal. Volume alone is not: a backup
job moves gigabytes and is not exfiltration, which is why the ratio and the
sustained-duration test both have to pass.

Volume accumulates across windows, because a slow drip that never spikes inside
any single 5-second slice is precisely the case a batch detector misses.
"""

from __future__ import annotations

from collections import defaultdict, deque

from alerts.schema import EXFIL, Alert, Evidence, confidence_from
from detectors.base import Detector
from features.baseline import BaselineTracker
from features.extract import WindowFeatures

# Outbound must exceed inbound by this factor against one destination.
MIN_RATIO = 8.0
# ...and move at least this much in total, so a chatty heartbeat is not an alert.
MIN_BYTES_OUT = 2_000_000
# ...over at least this long, separating exfiltration from a normal file upload.
MIN_DURATION_S = 20.0
HISTORY_S = 600.0


class ExfilDetector(Detector):
    name = "exfil.v1"
    threat_class = EXFIL
    cooldown_s = 120.0

    def __init__(self) -> None:
        super().__init__()
        # (src, dst) -> deque[(ts, bytes_out, bytes_in)] of per-window deltas
        self.history: dict[tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=600))

    def on_window(self, wf: WindowFeatures, baselines: BaselineTracker) -> list[Alert]:
        touched: set[tuple[str, str]] = set()

        for src, hf in wf.by_host.items():
            for dst, out_bytes in hf.bytes_to.items():
                in_bytes = hf.bytes_from.get(dst, 0)
                key = (src, dst)
                self.history[key].append((wf.window.end, out_bytes, in_bytes))
                touched.add(key)

        self._prune(wf.window.end)

        alerts: list[Alert] = []
        for key in touched:
            alert = self._evaluate(key, wf, baselines)
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

    def _evaluate(self, key, wf: WindowFeatures, baselines: BaselineTracker) -> Alert | None:
        src, dst = key
        series = self.history[key]
        if len(series) < 2:
            return None

        total_out = sum(o for _, o, _ in series)
        total_in = sum(i for _, _, i in series)
        span = series[-1][0] - series[0][0]

        if total_out < MIN_BYTES_OUT or span < MIN_DURATION_S:
            return None

        ratio = total_out / total_in if total_in > 0 else float(total_out)
        if ratio < MIN_RATIO:
            return None

        rate_bps = (total_out * 8) / span if span > 0 else 0.0
        base_out = baselines.value("bytes_out")

        # Steadiness separates a deliberate transfer from a bursty one. Both can
        # be exfiltration, but a flat rate is the more suspicious shape.
        per_window = [o for _, o, _ in series if o > 0]
        mean_out = sum(per_window) / len(per_window) if per_window else 0.0
        spread = (
            max(per_window) / mean_out if per_window and mean_out > 0 else 0.0
        )

        conf = confidence_from(
            ratio / MIN_RATIO,
            total_out / MIN_BYTES_OUT,
            span / MIN_DURATION_S,
        )

        if not self.ready(f"{src}|{dst}", wf.window.end):
            return None
        self.mark(f"{src}|{dst}", wf.window.end)

        return Alert.build(
            threat_class=self.threat_class,
            detector=self.name,
            confidence=conf,
            flow_id=f"{src}->{dst}",
            src=src,
            dst=dst,
            window_start=wf.window.start,
            window_end=wf.window.end,
            evidence=[
                Evidence("out_in_byte_ratio", ratio, MIN_RATIO, "",
                         f"{total_out:,} B out vs {total_in:,} B in"),
                Evidence("bytes_out_total", total_out, base_out, "bytes",
                         f"accumulated over {span:.0f}s of observation"),
                Evidence("sustained_duration", span, MIN_DURATION_S, "s"),
                Evidence("outbound_rate", rate_bps, None, "bit/s"),
                Evidence("burstiness", spread, 1.0, "",
                         "peak/mean per-window outbound; near 1.0 means a steady drip"),
                Evidence("destination_cardinality", 1, None, "hosts",
                         "volume concentrated on a single external destination"),
            ],
        )

"""Adaptive baselines learned from the observed stream.

Detector thresholds are expressed as multiples of a learned baseline rather than
as absolute constants, because "3000 SYN/sec is abnormal" is only true for some
networks. A passive monitor cannot ask the network what normal looks like, so it
has to learn it from what crosses the link.

Two properties matter:

  Warm-up      until a metric has been seen enough times, we fall back to a
               conservative floor instead of alerting off one sample.
  Poisoning    an attack in progress must not teach the baseline that the attack
               is normal, so updates are winsorized to a bounded multiple of the
               current estimate.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Metric:
    alpha: float
    floor: float
    mean: float = 0.0
    samples: int = 0
    # Updates larger than this multiple of the current mean are clipped before
    # being folded in -- a burst moves the baseline slowly, never instantly.
    clamp: float = 4.0

    def update(self, value: float) -> float:
        value = max(0.0, float(value))
        if self.samples == 0:
            self.mean = value
        else:
            capped = min(value, self.mean * self.clamp) if self.mean > 0 else value
            self.mean = (1 - self.alpha) * self.mean + self.alpha * capped
        self.samples += 1
        return self.mean

    @property
    def value(self) -> float:
        """Current baseline, floored so early windows cannot divide by ~0."""
        if self.samples < BaselineTracker.WARMUP:
            return max(self.mean, self.floor)
        return max(self.mean, self.floor)

    @property
    def warm(self) -> bool:
        return self.samples >= BaselineTracker.WARMUP


class BaselineTracker:
    """Named EWMA baselines. One instance is shared by all detectors."""

    # Windows of traffic required before a baseline is trusted. At the default
    # 5s window that is one minute of observation.
    WARMUP = 12

    # floor values keep a quiet network from producing absurd ratios
    DEFAULTS: dict[str, tuple[float, float]] = {
        # name: (ewma alpha, floor)
        "syn_rate": (0.05, 20.0),
        "target_syn_rate": (0.05, 10.0),
        "pps": (0.05, 50.0),
        "bps": (0.05, 1e5),
        "host_fanout_ports": (0.05, 8.0),
        "host_fanout_hosts": (0.05, 4.0),
        "completion_ratio": (0.05, 0.30),
        "src_entropy": (0.05, 1.0),
        "out_in_ratio": (0.05, 2.0),
        "bytes_out": (0.05, 5e4),
        "dns_qname_entropy": (0.05, 3.0),
        "dns_qname_len": (0.05, 20.0),
    }

    def __init__(self):
        self.metrics: dict[str, Metric] = {
            name: Metric(alpha=a, floor=f) for name, (a, f) in self.DEFAULTS.items()
        }
        self.windows_seen = 0

    def get(self, name: str) -> Metric:
        m = self.metrics.get(name)
        if m is None:
            m = self.metrics[name] = Metric(alpha=0.05, floor=1.0)
        return m

    def value(self, name: str) -> float:
        return self.get(name).value

    def observe(self, name: str, value: float) -> None:
        self.get(name).update(value)

    def warm(self, name: str) -> bool:
        return self.get(name).warm

    def snapshot(self) -> dict[str, float]:
        return {k: round(m.value, 4) for k, m in self.metrics.items()}

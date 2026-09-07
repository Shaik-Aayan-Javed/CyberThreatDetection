"""Detector #1 -- Volumetric / protocol DDoS (SYN flood, spoofed-source flood).

The signature is read at the *target*, not the source: a victim absorbing SYNs
far above its learned baseline while almost none of those SYNs draw an observed
SYN/ACK. Source-IP entropy separates a spoofed flood (many one-shot sources,
near-maximum entropy) from a single aggressive client (low entropy).

Note the completion ratio is something we *observe*, never something we test.
Completing a handshake ourselves would need a return path we do not have.
"""

from __future__ import annotations

import math

from alerts.schema import SYN_FLOOD, Alert, Evidence, confidence_from
from detectors.base import Detector
from features.baseline import BaselineTracker
from features.extract import WindowFeatures

# A flood must exceed the learned baseline by this factor...
RATE_MULTIPLIER = 6.0
# ...and clear this absolute floor, so a quiet link cannot produce an alert from
# a handful of packets just because its baseline is near zero.
MIN_SYN_RATE = 50.0
# Below this fraction of observed handshake completions the traffic is not
# behaving like real clients.
MAX_COMPLETION = 0.30
MIN_SYN_COUNT = 40


class SynFloodDetector(Detector):
    name = "synflood.v1"
    threat_class = SYN_FLOOD
    cooldown_s = 20.0

    def on_window(self, wf: WindowFeatures, baselines: BaselineTracker) -> list[Alert]:
        alerts: list[Alert] = []
        base_rate = baselines.value("target_syn_rate")
        threshold = max(base_rate * RATE_MULTIPLIER, MIN_SYN_RATE)

        for dst, tf in wf.by_dst.items():
            if tf.syn_in < MIN_SYN_COUNT:
                continue

            syn_rate = tf.syn_in / wf.duration
            completion = tf.completion_ratio

            if syn_rate < threshold or completion > MAX_COMPLETION:
                continue

            entropy = tf.src_entropy
            # Maximum possible entropy for this many distinct sources; the ratio
            # tells us how evenly the load is spread, i.e. how spoofed it looks.
            max_entropy = math.log2(tf.unique_sources) if tf.unique_sources > 1 else 1.0
            spread = entropy / max_entropy if max_entropy > 0 else 0.0

            conf = confidence_from(
                syn_rate / threshold,
                MAX_COMPLETION / max(completion, 0.005),
                1.0 + spread,
            )

            if not self.ready(dst, wf.window.end):
                continue
            self.mark(dst, wf.window.end)

            top_src = tf.src_counts.most_common(1)[0][0] if tf.src_counts else "unknown"
            spoofed = tf.unique_sources > 20 and spread > 0.85

            alerts.append(
                Alert.build(
                    threat_class=self.threat_class,
                    detector=self.name,
                    confidence=conf,
                    flow_id=f"*->{dst}/TCP",
                    src=f"{tf.unique_sources} sources" if tf.unique_sources > 1 else top_src,
                    dst=dst,
                    window_start=wf.window.start,
                    window_end=wf.window.end,
                    evidence=[
                        Evidence("syn_rate_pps", syn_rate, base_rate, "pkt/s",
                                 f"{RATE_MULTIPLIER}x baseline threshold = {threshold:.1f}"),
                        Evidence("syn_packets_in_window", tf.syn_in, None, "packets"),
                        Evidence("completion_ratio", completion, 1.0, "",
                                 f"{tf.synack_out} SYN/ACK observed for {tf.syn_in} SYN"),
                        Evidence("unique_source_ips", tf.unique_sources, None, "hosts"),
                        Evidence("source_ip_entropy", entropy, None, "bits",
                                 "near-uniform source spread: consistent with spoofing"
                                 if spoofed else "concentrated source distribution"),
                        Evidence("inbound_rate_pps", tf.packets_in / wf.duration, None, "pkt/s"),
                    ],
                )
            )

        return alerts

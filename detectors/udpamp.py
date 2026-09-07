"""Detector #6 -- UDP reflection/amplification (PS class (a), third named shape).

Read at the victim (TargetFeatures), same vantage point as SynFloodDetector:
on a one-way tap at the monitored gateway, the attacker->reflector leg is
invisible by construction (both ends external, spoofed, never cross this
link) -- only the reflector->victim leg can ever be observed. Scoped to
"reflection observed at the victim" per docs/DEFECTS.md #21, not the full
attack chain.

Gated on the AGGREGATE inbound byte rate across all tracked amplification
ports, not per-port -- a real campaign is routinely multi-vector (DNS+NTP+
SSDP at once, specifically to evade single-protocol-rate detectors); a
per-port gate would let a distributed attack slip under every individual
threshold. Per-port volumes still appear in evidence.

Known gap, stated plainly (same honesty this codebase already applies to
`spoofed` in synflood.py -- see docs/DEFECTS.md #23): a 1-2-reflector attack
using a small number of very high-potency amplifiers (e.g. open memcached,
>10,000x) can clear the byte-rate gate while never reaching MIN_REFLECTORS.
Not defended against in this pass.
"""

from __future__ import annotations

from alerts.schema import UDP_AMPLIFICATION, Alert, Evidence, confidence_from
from detectors.base import Detector
from features.baseline import BaselineTracker
from features.extract import WindowFeatures

# Amplification must exceed the learned baseline by this factor...
RATE_MULTIPLIER = 6.0
# ...and clear this absolute floor, so a quiet link cannot produce an alert
# from a handful of packets just because its baseline is near zero.
MIN_AMP_BYTES_PER_S = 400_000.0
# Distinct reflector IPs required. Separates "many different open resolvers
# hitting me" (attack) from "my one configured DNS server sent a big
# response" (not an attack) -- load-bearing for zero false positives on
# normal.pcap, where every client has exactly one legitimate resolver.
MIN_REFLECTORS = 3
# Reference floor for the amplification-ratio confidence signal, well below
# even the weakest common amplifier (plain DNS, ~28-54x).
MIN_AMP_RATIO = 10.0

_PORT_NAMES = {
    53: "DNS", 123: "NTP", 1900: "SSDP", 11211: "memcached",
    19: "CharGen", 17: "QOTD", 161: "SNMP", 111: "Portmapper", 389: "CLDAP",
}


class UdpAmplificationDetector(Detector):
    name = "udpamp.v1"
    threat_class = UDP_AMPLIFICATION
    cooldown_s = 20.0

    def on_window(self, wf: WindowFeatures, baselines: BaselineTracker) -> list[Alert]:
        alerts: list[Alert] = []
        base_rate = baselines.value("udp_amp_bytes_in")
        threshold = max(base_rate * RATE_MULTIPLIER, MIN_AMP_BYTES_PER_S)

        for dst, tf in wf.by_dst.items():
            if not tf.amp_bytes_by_port:
                continue

            total_bytes = sum(tf.amp_bytes_by_port.values())
            rate = total_bytes / wf.duration

            reflectors: set[str] = set()
            for s in tf.amp_reflectors_by_port.values():
                reflectors |= s
            reflector_count = len(reflectors)

            if rate < threshold or reflector_count < MIN_REFLECTORS:
                continue

            # Outbound side is often simply absent -- the victim never asked
            # for any of this, the attacker spoofed the request. bytes_out is
            # this host's TOTAL outbound volume (any destination, any port),
            # not a per-port figure, so it is a deliberately coarse and
            # conservative proxy: real unrelated traffic only inflates the
            # denominator, pulling the ratio down, never up.
            hf = wf.by_host.get(dst)
            out_bytes = hf.bytes_out if hf else 0
            amp_ratio = total_bytes / max(out_bytes, 1)

            conf = confidence_from(
                rate / threshold,
                reflector_count / MIN_REFLECTORS,
                amp_ratio / MIN_AMP_RATIO,
            )

            if not self.ready(dst, wf.window.end):
                continue
            self.mark(dst, wf.window.end)

            # Same honest threshold-attribution pattern as synflood.py: say
            # plainly which layer actually gated, never print a near-zero
            # baseline or a divide-by-zero epsilon as if it meant something.
            if base_rate * RATE_MULTIPLIER < MIN_AMP_BYTES_PER_S:
                if base_rate < 1.0:
                    rate_note = (f"median target sees no amplification-port traffic, "
                                 f"so the {MIN_AMP_BYTES_PER_S:,.0f} B/s absolute floor "
                                 f"set the threshold")
                else:
                    rate_note = (f"learned baseline {base_rate:,.0f} B/s x {RATE_MULTIPLIER} "
                                 f"is under the {MIN_AMP_BYTES_PER_S:,.0f} B/s floor, which "
                                 f"set the threshold")
            else:
                rate_note = (f"{RATE_MULTIPLIER}x learned baseline "
                             f"{base_rate:,.0f} B/s = {threshold:,.0f} B/s")

            ports_desc = ", ".join(
                f"{_PORT_NAMES.get(p, p)}:{b:,}B" for p, b in
                sorted(tf.amp_bytes_by_port.items(), key=lambda kv: -kv[1])
            )

            alerts.append(
                Alert.build(
                    threat_class=self.threat_class,
                    detector=self.name,
                    confidence=conf,
                    flow_id=f"*->{dst}/UDP",
                    src=f"{reflector_count} reflectors",
                    dst=dst,
                    window_start=wf.window.start,
                    window_end=wf.window.end,
                    evidence=[
                        Evidence("amp_bytes_rate", rate, threshold, "B/s", rate_note),
                        Evidence("amp_bytes_total", total_bytes, None, "bytes", ports_desc),
                        Evidence("reflector_count", reflector_count, MIN_REFLECTORS, "hosts"),
                        Evidence("amplification_ratio", amp_ratio, MIN_AMP_RATIO, "",
                                 f"{total_bytes:,} B in on amplification ports vs "
                                 f"{out_bytes:,} B outbound total (this host, any "
                                 f"destination) -- a coarse proxy, not a per-port figure"),
                    ],
                )
            )

        return alerts

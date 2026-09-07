"""Detector #2 -- Reconnaissance / port scanning.

Fan-out from one source: many destination ports, many destination hosts, or
both, inside one window. Two extra signals separate a scanner from a busy but
legitimate client:

  completion   scans mostly hit closed ports, so few attempts complete
  sequencing   a scanner walks ports in runs; a browser does not

Sequential-run detection is what stops a busy proxy or a CDN-heavy page load
from being called reconnaissance.
"""

from __future__ import annotations

from alerts.schema import PORT_SCAN, Alert, Evidence, confidence_from
from detectors.base import Detector
from features.baseline import BaselineTracker
from features.extract import HostFeatures, WindowFeatures

FANOUT_MULTIPLIER = 5.0
MIN_PORTS = 25
MIN_HOSTS = 12
# Scans usually get RST or silence rather than SYN/ACK.
MAX_COMPLETION = 0.45


def sequential_run_ratio(ports: set[int]) -> float:
    """Fraction of ports that sit adjacent to another probed port.

    A sweep of 20-25,80,443 scores near 1.0. A browser's ephemeral spread of
    443, 8443, 80 scores near 0.0.
    """
    if len(ports) < 3:
        return 0.0
    ordered = sorted(ports)
    adjacent = sum(1 for a, b in zip(ordered, ordered[1:]) if b - a == 1)
    return adjacent / (len(ordered) - 1)


class PortScanDetector(Detector):
    name = "portscan.v1"
    threat_class = PORT_SCAN
    cooldown_s = 20.0

    def on_window(self, wf: WindowFeatures, baselines: BaselineTracker) -> list[Alert]:
        alerts: list[Alert] = []
        base_ports = baselines.value("host_fanout_ports")
        base_hosts = baselines.value("host_fanout_hosts")
        port_threshold = max(base_ports * FANOUT_MULTIPLIER, MIN_PORTS)
        host_threshold = max(base_hosts * FANOUT_MULTIPLIER, MIN_HOSTS)

        for src, hf in wf.by_host.items():
            n_ports = len(hf.dst_ports)
            n_hosts = len(hf.dst_hosts)

            port_sweep = n_ports >= port_threshold
            host_sweep = n_hosts >= host_threshold
            if not (port_sweep or host_sweep):
                continue

            # A host that sent no SYN has no handshake outcome to judge, and
            # completion_ratio now says so with a negative sentinel instead of
            # the old misleading 1.0. Treat "no data" as not-a-scan, which is
            # what the 1.0 accidentally achieved before. Deliberately keeps
            # ICMP/UDP-only sweeps out of scope rather than admitting them
            # through a comparison that a sentinel would silently pass.
            if not hf.has_completion_data:
                continue
            completion = hf.completion_ratio
            if completion > MAX_COMPLETION:
                continue

            alert = self._build(wf, hf, n_ports, n_hosts, completion,
                                port_threshold, host_threshold, base_ports, base_hosts)
            if alert is not None:
                alerts.append(alert)

        return alerts

    def _build(self, wf, hf: HostFeatures, n_ports, n_hosts, completion,
               port_threshold, host_threshold, base_ports, base_hosts) -> Alert | None:
        run_ratio = sequential_run_ratio(hf.dst_ports)
        conn_rate = (len(hf.contacts) or hf.packets) / wf.duration

        conf = confidence_from(
            max(n_ports / port_threshold, n_hosts / host_threshold),
            MAX_COMPLETION / max(completion, 0.01),
            1.0 + run_ratio,
        )

        if not self.ready(hf.src, wf.window.end):
            return None
        self.mark(hf.src, wf.window.end)

        if n_ports >= port_threshold and n_hosts >= host_threshold:
            shape = "block sweep (many hosts x many ports)"
        elif n_ports >= port_threshold:
            shape = "vertical scan (one host, many ports)"
        else:
            shape = "horizontal sweep (one port, many hosts)"

        ports = sorted(hf.dst_ports)
        span = f"{ports[0]}-{ports[-1]}" if ports else "n/a"

        return Alert.build(
            threat_class=self.threat_class,
            detector=self.name,
            confidence=conf,
            flow_id=f"{hf.src}->*/{n_hosts}h:{n_ports}p",
            src=hf.src,
            dst=f"{n_hosts} hosts" if n_hosts > 1 else next(iter(hf.dst_hosts), "unknown"),
            window_start=wf.window.start,
            window_end=wf.window.end,
            evidence=[
                Evidence("unique_dst_ports", n_ports, base_ports, "ports",
                         f"port range touched: {span}"),
                Evidence("unique_dst_hosts", n_hosts, base_hosts, "hosts"),
                Evidence("connection_rate", conn_rate, None, "conn/s"),
                Evidence("completion_ratio", completion, 1.0, "",
                         f"{hf.synack_recv} SYN/ACK observed, {hf.rst_recv} RST"),
                Evidence("sequential_port_ratio", run_ratio, 0.0, "",
                         "consecutive port walk" if run_ratio > 0.5 else "non-sequential"),
                Evidence("observation_window", wf.duration, None, "s", shape),
            ],
        )

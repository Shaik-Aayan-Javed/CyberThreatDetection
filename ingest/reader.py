"""Read-only packet ingest.

This module is the *only* place traffic enters the system, and it can only read.
It opens a file descriptor and yields immutable observations. There is no socket
here, no connect(), no send path -- see docs/ISOLATION.md. That property is the
whole point of PS 26145, so keep this file boring.

Parsing uses dpkt (pure Python, no libpcap/Npcap dependency), which means the
detector runs identically on a machine with no capture driver and no network.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Iterator

import dpkt

# TCP flag bits, named so detector code reads like the RFC.
TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PSH = 0x08
TH_ACK = 0x10


@dataclass(slots=True)
class Packet:
    """One passively observed packet. Never mutated after construction."""

    ts: float
    src: str
    dst: str
    proto: str  # TCP | UDP | ICMP | OTHER
    sport: int
    dport: int
    length: int  # frame length on the wire
    payload_len: int  # L4 payload bytes
    flags: int  # TCP flags, 0 for non-TCP
    dns_qname: str = ""
    dns_qtype: str = ""
    dns_is_response: bool = False

    @property
    def is_syn(self) -> bool:
        return self.proto == "TCP" and bool(self.flags & TH_SYN) and not (self.flags & TH_ACK)

    @property
    def is_synack(self) -> bool:
        return self.proto == "TCP" and bool(self.flags & TH_SYN) and bool(self.flags & TH_ACK)

    @property
    def is_rst(self) -> bool:
        return self.proto == "TCP" and bool(self.flags & TH_RST)


_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}


def _ip_str(raw: bytes) -> str:
    """Format a raw address.

    Written by hand rather than with socket.inet_ntoa so that the `socket`
    module is not imported anywhere in the detection path. That keeps
    tools/isolation_check.py's proof simple: no socket import exists to
    explain away.
    """
    if len(raw) == 4:
        return f"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}"
    try:
        return str(ipaddress.IPv6Address(bytes(raw)))
    except ValueError:  # pragma: no cover - malformed
        return raw.hex()


def parse(ts: float, buf: bytes, linktype: int = dpkt.pcap.DLT_EN10MB) -> Packet | None:
    """Decode one frame into a Packet, or None if it is not IP we care about."""
    try:
        if linktype == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
        elif linktype in (dpkt.pcap.DLT_RAW, 101, 12):
            ip = dpkt.ip.IP(buf)
        elif linktype == dpkt.pcap.DLT_LINUX_SLL:
            ip = dpkt.sll.SLL(buf).data
        else:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None

        src, dst = _ip_str(ip.src), _ip_str(ip.dst)
        l4 = ip.data
        frame_len = len(buf)

        if isinstance(l4, dpkt.tcp.TCP):
            return Packet(
                ts=ts, src=src, dst=dst, proto="TCP",
                sport=l4.sport, dport=l4.dport,
                length=frame_len, payload_len=len(l4.data), flags=l4.flags,
            )

        if isinstance(l4, dpkt.udp.UDP):
            pkt = Packet(
                ts=ts, src=src, dst=dst, proto="UDP",
                sport=l4.sport, dport=l4.dport,
                length=frame_len, payload_len=len(l4.data), flags=0,
            )
            if 53 in (l4.sport, l4.dport) and l4.data:
                _attach_dns(pkt, bytes(l4.data))
            return pkt

        if isinstance(l4, dpkt.icmp.ICMP):
            return Packet(
                ts=ts, src=src, dst=dst, proto="ICMP",
                sport=0, dport=0,
                length=frame_len, payload_len=len(bytes(l4)), flags=0,
            )

        return Packet(
            ts=ts, src=src, dst=dst, proto="OTHER",
            sport=0, dport=0, length=frame_len, payload_len=0, flags=0,
        )
    except Exception:
        # A malformed frame is an observation too: we drop it rather than crash.
        # Passive monitors see truncated and corrupt traffic as a matter of course.
        return None


def _attach_dns(pkt: Packet, payload: bytes) -> None:
    """Extract QNAME/QTYPE only. We never read or reconstruct answer payloads."""
    try:
        dns = dpkt.dns.DNS(payload)
        pkt.dns_is_response = bool(dns.qr)
        if dns.qd:
            q = dns.qd[0]
            name = q.name
            pkt.dns_qname = name.decode(errors="replace") if isinstance(name, bytes) else str(name)
            pkt.dns_qtype = _DNS_TYPES.get(q.type, str(q.type))
    except Exception:
        pass


class PcapReader:
    """Yields packets in capture-time order, optionally paced like the original.

    speed = 0    as fast as the CPU allows -- used by bench/throughput.py
    speed = 1    wall-clock faithful replay -- used for the live demo
    speed = 10   10x faster than real time -- used to keep the demo short

    Pacing lives here, not in the detectors, so the demo and the benchmark push
    bytes through exactly the same code path.
    """

    def __init__(self, path: str, speed: float = 0.0, limit: int | None = None):
        self.path = path
        self.speed = float(speed)
        self.limit = limit
        self.packets_read = 0
        self.bytes_read = 0
        self.malformed = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None

    def packets(self) -> Iterator[Packet]:
        with open(self.path, "rb") as fh:
            try:
                pcap = dpkt.pcap.Reader(fh)
            except ValueError:
                fh.seek(0)
                pcap = dpkt.pcapng.Reader(fh)

            linktype = pcap.datalink()
            wall_start = time.perf_counter()
            capture_start: float | None = None

            for ts, buf in pcap:
                if self.limit is not None and self.packets_read >= self.limit:
                    break

                if capture_start is None:
                    capture_start = ts
                    self.first_ts = ts
                self.last_ts = ts

                if self.speed > 0:
                    target = (ts - capture_start) / self.speed
                    drift = target - (time.perf_counter() - wall_start)
                    if drift > 0.0005:
                        time.sleep(drift)

                pkt = parse(ts, buf, linktype)
                if pkt is None:
                    self.malformed += 1
                    continue

                self.packets_read += 1
                self.bytes_read += pkt.length
                yield pkt

    @property
    def capture_duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

"""Read-only packet ingest.

This module is the *only* place traffic enters the system, and it can only read.
It opens a file descriptor and yields immutable observations. There is no socket
here, no connect(), no send path -- see docs/ISOLATION.md. That property is the
whole point of PS 26145, so keep this file boring.

Parsing uses dpkt (pure Python, no libpcap/Npcap dependency), which means the
detector runs identically on a machine with no capture driver and no network.
"""

from __future__ import annotations

import hashlib
import ipaddress
import time
from dataclasses import dataclass
from typing import Iterator

import struct

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
    # Number of questions and answers seen. Shape metadata only -- no rdata is
    # ever decoded or retained. dns_answers feeds amplification analysis.
    dns_qcount: int = 0
    dns_answers: int = 0
    # TLS record and handshake *header* shape. Cleartext fields only -- no
    # application data is decoded and no key material is touched, which is what
    # makes PS class (d) reachable without violating constraint (b).
    tls_record_type: int = 0  # 0x16 handshake, 0x17 application_data, 0 = not TLS
    tls_record_len: int = 0  # from the record header, NOT len(payload)
    tls_ja3: str = ""  # md5 of tls_ja3_string, ClientHello only
    tls_ja3_string: str = ""  # the pre-hash string, so a fingerprint is auditable
    tls_sni: str = ""

    @property
    def is_syn(self) -> bool:
        return self.proto == "TCP" and bool(self.flags & TH_SYN) and not (self.flags & TH_ACK)

    @property
    def is_synack(self) -> bool:
        return self.proto == "TCP" and bool(self.flags & TH_SYN) and bool(self.flags & TH_ACK)

    @property
    def is_rst(self) -> bool:
        return self.proto == "TCP" and bool(self.flags & TH_RST)


# DNS is not just UDP/53. mDNS and LLMNR are ordinary background traffic; TCP/53
# is what a tunnel uses once it outgrows a 512-byte datagram.
_DNS_UDP_PORTS = {53, 5353, 5355}
_DNS_TCP_PORTS = {53}

_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}

# TLS record content types worth recording. 0x16 carries the ClientHello we
# fingerprint; 0x17 is the steady state of a session, and its record lengths are
# the "packet-size sequence" PS class (d) asks to be analysed.
_TLS_HANDSHAKE = 0x16
_TLS_APPLICATION_DATA = 0x17
_TLS_CLIENT_HELLO = 0x01
# RFC 8446 5.1 caps a record at 2^14 plus expansion. Larger means these are
# bytes that merely happen to begin like a record header.
_TLS_MAX_RECORD = 16640

_EXT_SERVER_NAME = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_EC_POINT_FORMATS = 0x000B

# Link types carrying a bare IP packet with no link-layer header. DLT_RAW is 12
# and 101 is the same thing on several BSDs; 228/229 are DLT_IPV4/DLT_IPV6,
# which tcpdump writes for tunnel and loopback interfaces. Missing 228 meant
# every packet of such a capture fell through to the Ethernet branch, produced
# no IP layer and was dropped -- a whole file read as zero packets, silently.
# Found by running tools/tls_validate.py against real third-party captures.
_RAW_IP_LINKTYPES = (dpkt.pcap.DLT_RAW, 101, 12, 228)
_DLT_IPV6 = 229
# tcpdump -i any writes SLL2 (276), not SLL (113), on libpcap >= 1.10 --
# Ubuntu 22.04 and Debian 12 onwards. Same silent-whole-file-loss shape.
_DLT_LINUX_SLL2 = 276

# A real ClientHello offers tens of ciphers and extensions, not thousands. The
# cap keeps a hostile handshake from producing a ja3_string tens of kilobytes
# long, which would then be retained per session and interpolated into alert
# JSON -- bounding the number of tracked sessions is no use if one session can
# hold megabytes.
_MAX_JA3_FIELDS = 256


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
        elif linktype in _RAW_IP_LINKTYPES:
            # A bare IP packet is v4 or v6 and nothing but the version nibble
            # says which. Assuming v4 loses every IPv6 capture silently, which
            # is the same failure this branch was just fixed for.
            ip = dpkt.ip6.IP6(buf) if buf and (buf[0] >> 4) == 6 else dpkt.ip.IP(buf)
        elif linktype == _DLT_IPV6:
            ip = dpkt.ip6.IP6(buf)
        elif linktype == dpkt.pcap.DLT_LINUX_SLL:
            ip = dpkt.sll.SLL(buf).data
        elif linktype == _DLT_LINUX_SLL2:
            ip = dpkt.sll2.SLL2(buf).data
        else:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None

        src, dst = _ip_str(ip.src), _ip_str(ip.dst)
        l4 = ip.data
        frame_len = len(buf)

        if isinstance(l4, dpkt.tcp.TCP):
            pkt = Packet(
                ts=ts, src=src, dst=dst, proto="TCP",
                sport=l4.sport, dport=l4.dport,
                length=frame_len, payload_len=len(l4.data), flags=l4.flags,
            )
            # DNS over TCP. `dig +tcp` and every DNS tunnel that wants to move
            # more than 512 bytes lands here, so locking DNS parsing to UDP made
            # the whole tunnel detector bypassable with one flag.
            if (l4.sport in _DNS_TCP_PORTS or l4.dport in _DNS_TCP_PORTS) and len(l4.data) > 2:
                # RFC 1035 §4.2.2: TCP DNS messages carry a 2-byte big-endian
                # length prefix that UDP messages do not.
                _attach_dns(pkt, bytes(l4.data)[2:])
            elif l4.data:
                _attach_tls(pkt, bytes(l4.data))
            return pkt

        if isinstance(l4, dpkt.udp.UDP):
            pkt = Packet(
                ts=ts, src=src, dst=dst, proto="UDP",
                sport=l4.sport, dport=l4.dport,
                length=frame_len, payload_len=len(l4.data), flags=0,
            )
            if (l4.sport in _DNS_UDP_PORTS or l4.dport in _DNS_UDP_PORTS) and l4.data:
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
    """Extract QNAME/QTYPE and answer *count*. Never reads answer rdata.

    Recording how many answers a response carried is metadata about the shape of
    the exchange, not its content -- it is what a reflection/amplification
    detector needs, and it keeps the no-payload guarantee intact because no
    rdata is decoded or retained.
    """
    try:
        dns = dpkt.dns.DNS(payload)
        pkt.dns_is_response = bool(dns.qr)
        if dns.qd:
            pkt.dns_qcount = len(dns.qd)
            # Deliberately the FIRST question only, not a join of all of them.
            # detectors/dns.py runs split_domain() over this string, and a
            # joined "a.com;b.com" would parse to the nonsense parent
            # "com;b.com". Multi-question DNS is essentially unused in practice
            # (most resolvers reject qdcount > 1), so the count records that we
            # saw it without corrupting the field downstream consumers parse.
            q = dns.qd[0]
            name = q.name
            pkt.dns_qname = name.decode(errors="replace") if isinstance(name, bytes) else str(name)
            pkt.dns_qtype = _DNS_TYPES.get(q.type, str(q.type))
        if dns.an:
            pkt.dns_answers = len(dns.an)
    except (dpkt.UnpackError, dpkt.NeedData, struct.error,
            IndexError, ValueError, AttributeError):
        # Narrow rather than bare: a truncated or non-DNS payload on port 53 is
        # an ordinary observation, but a TypeError from our own code is a bug
        # and should not be laundered into silence.
        pass


def _is_grease(value: int) -> bool:
    """RFC 8701 GREASE values, which are deliberately random.

    They must be stripped before fingerprinting, or a client never matches even
    itself from one connection to the next.
    """
    return (value & 0x0F0F) == 0x0A0A


def _attach_tls(pkt: Packet, payload: bytes) -> None:
    """Record the TLS record header, and fingerprint a ClientHello.

    Deliberately port-agnostic. Gating on 443 would miss the 8443 sessions this
    project's own generator already produces, and any implant that picks another
    port -- the same mistake detectors/udpamp.py documents for per-port gates.
    Five byte comparisons is cheap enough to run on every TCP payload.
    """
    if len(payload) < 5:
        return
    ctype = payload[0]
    if ctype not in (_TLS_HANDSHAKE, _TLS_APPLICATION_DATA):
        return
    # The legacy record version is 0x03XX for TLS 1.0 through 1.3.
    if payload[1] != 0x03 or payload[2] > 0x04:
        return
    rec_len = (payload[3] << 8) | payload[4]
    if rec_len == 0 or rec_len > _TLS_MAX_RECORD:
        return

    pkt.tls_record_type = ctype
    # The header's length field, not len(payload). L4 payload size is a function
    # of MSS, segmentation and GRO offload, so it describes the network path;
    # the record length is the size the application actually chose, which is the
    # only one a size-sequence analysis can read anything into.
    pkt.tls_record_len = rec_len

    if ctype != _TLS_HANDSHAKE or len(payload) < 9 or payload[5] != _TLS_CLIENT_HELLO:
        return
    # Only fingerprint a handshake we have in full. A ClientHello larger than
    # one segment is routine on modern stacks (a post-quantum key_share alone
    # pushes it past a 1460-byte MSS), and parsing the fragment we happened to
    # receive yields a *plausible but wrong* JA3 -- one that appears in no
    # corpus, defeating the pivoting the fingerprint exists for, and minting a
    # fresh ja3_hosts key at every segmentation boundary. Recording no
    # fingerprint is the honest outcome; the size and timing analysis is
    # unaffected, since it reads record headers rather than the handshake.
    hs_len = (payload[6] << 16) | (payload[7] << 8) | payload[8]
    if 9 + hs_len > len(payload) or 5 + rec_len > len(payload):
        return
    _attach_ja3(pkt, payload, 9 + hs_len)


def _attach_ja3(pkt: Packet, payload: bytes, limit: int) -> None:
    """Build the JA3 fingerprint from a ClientHello's cleartext header fields.

    JA3 is md5 of "version,ciphers,extensions,curves,point_formats". Everything
    read here is sent in the clear before any key exchange completes, so this is
    byte parsing rather than decryption.

    The narrow except is load-bearing rather than defensive habit: letting a
    truncated handshake raise into parse()'s catch-all would discard the whole
    packet and count it malformed, which is the silent-traffic-loss mechanism
    docs/DEFECTS.md #18 describes.
    """
    try:
        pos = 9  # 5-byte record header + 4-byte handshake header
        if len(payload) < pos + 2:
            return
        version = (payload[pos] << 8) | payload[pos + 1]
        pos += 2 + 32  # client_version, then the 32-byte random

        if len(payload) < pos + 1:
            return
        pos += 1 + payload[pos]  # session_id

        if len(payload) < pos + 2:
            return
        cs_len = (payload[pos] << 8) | payload[pos + 1]
        pos += 2
        ciphers = [
            (payload[i] << 8) | payload[i + 1]
            for i in range(pos, min(pos + cs_len, limit - 1), 2)
        ][:_MAX_JA3_FIELDS]
        pos += cs_len

        if len(payload) < pos + 1:
            return
        pos += 1 + payload[pos]  # compression_methods

        exts: list[int] = []
        curves: list[int] = []
        formats: list[int] = []
        sni = ""

        if len(payload) >= pos + 2:
            ext_total = (payload[pos] << 8) | payload[pos + 1]
            pos += 2
            end = min(pos + ext_total, limit)
            while pos + 4 <= end and len(exts) < _MAX_JA3_FIELDS:
                etype = (payload[pos] << 8) | payload[pos + 1]
                elen = (payload[pos + 2] << 8) | payload[pos + 3]
                pos += 4
                body = payload[pos:pos + elen]
                pos += elen
                exts.append(etype)
                if etype == _EXT_SUPPORTED_GROUPS and len(body) >= 2:
                    n = (body[0] << 8) | body[1]
                    curves = [
                        (body[i] << 8) | body[i + 1]
                        for i in range(2, min(2 + n, len(body) - 1), 2)
                    ][:_MAX_JA3_FIELDS]
                elif etype == _EXT_EC_POINT_FORMATS and body:
                    formats = list(body[1:1 + body[0]])[:_MAX_JA3_FIELDS]
                elif etype == _EXT_SERVER_NAME and len(body) >= 5:
                    nlen = (body[3] << 8) | body[4]
                    sni = body[5:5 + nlen].decode("ascii", errors="replace")

        ja3 = ",".join([
            str(version),
            "-".join(str(c) for c in ciphers if not _is_grease(c)),
            "-".join(str(e) for e in exts if not _is_grease(e)),
            "-".join(str(c) for c in curves if not _is_grease(c)),
            # Point formats are single bytes and cannot collide with GREASE.
            "-".join(str(f) for f in formats),
        ])
        # usedforsecurity=False because this is a fingerprint, not a security
        # hash -- without it a FIPS-mode build raises ValueError on md5().
        pkt.tls_ja3 = hashlib.md5(ja3.encode(), usedforsecurity=False).hexdigest()
        pkt.tls_ja3_string = ja3
        pkt.tls_sni = sni
    except (IndexError, ValueError, struct.error):
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

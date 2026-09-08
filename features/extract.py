"""Per-window feature extraction.

Everything downstream -- every rule detector and the anomaly model -- reads
the structures built here. Features are computed once per window and shared, so
adding a detector costs nothing extra at ingest time.

All features are derived from packet headers and flow metadata only. Nothing in
this file inspects application payload, and nothing decrypts anything
(PS 26145 constraint b). DNS QNAMEs are read from the query section, which is
cleartext by protocol design -- that is metadata, not decryption. The same
applies to TLS: record headers and the ClientHello are sent before any key
exchange completes, so reading their lengths and offered ciphers is byte
parsing, not decryption.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ingest.flows import FlowRecord, Window
from ingest.reader import Packet

# Returned by HostFeatures.completion_ratio when the host sent no SYN at all,
# so there is no handshake outcome to report. Distinct from 0.0 ("every SYN
# went unanswered") and from 1.0 ("every SYN completed"), both of which are
# real measurements. Any consumer that thresholds on completion must treat a
# negative value as "no data" rather than comparing it as a ratio.
NO_COMPLETION_DATA = -1.0

# Well-known UDP services with a large amplification factor: DNS, NTP, SSDP,
# memcached, CharGen, QOTD, SNMP, Portmapper, CLDAP. Fixed and small on
# purpose -- any new per-target state has to stay bounded by construction,
# not by a runtime cap, after docs/DEFECTS.md #1's unbounded-flow-table OOM.
AMPLIFICATION_PORTS = {53, 123, 1900, 11211, 19, 17, 161, 111, 389}
# Per-port cap on distinct reflector IPs tracked in one window. A window's
# state is discarded on the next extract() call regardless, but a single
# pathological window (the attack this detector exists to catch) could still
# spike memory before that reset -- this bounds that spike.
MAX_REFLECTORS_TRACKED = 20_000

# Caps on the per-window TLS session index, same reasoning as above: a window's
# state is discarded on the next extract() call, but one pathological window
# must not be able to spike memory before that happens.
MAX_TLS_SESSIONS = 20_000
# Deliberately well under detectors/tlsmalware.py's MAX_STREAM_RECORDS (128),
# which is the cross-window deque these feed. If one window could contribute
# more records than that deque holds, a single chatty window would evict every
# earlier window's history -- and the detector's whole premise is that a
# session's shape is only visible across windows.
MAX_TLS_RECORDS_PER_SESSION = 64


def shannon_entropy(counts) -> float:
    """Shannon entropy in bits over a Counter or iterable of counts.

    Used for source-IP dispersion (spoofed floods produce near-maximum entropy)
    and for DNS QNAME character distribution (DGA/tunnelling produce high
    entropy relative to human-readable domains).
    """
    values = list(counts.values()) if hasattr(counts, "values") else list(counts)
    total = sum(values)
    if total <= 0:
        return 0.0
    h = 0.0
    for c in values:
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


@dataclass
class HostFeatures:
    """What one host did during one window.

    Despite the `src` field name this is a *peer* row, not strictly a source
    row: a host that only ever appears as a destination still gets one, because
    its inbound byte counts are what make the out:in ratio meaningful. Such a
    row is an observation of somebody else's traffic from the wrong side of the
    tap -- it has no fan-out, no SYNs and no flows credited to it.

    `observed_as_source` is what separates the two. Anything reasoning about
    host *behaviour* -- baselines, the anomaly model -- must filter on it.
    """

    src: str
    # True once this host has been seen actually sending a packet.
    observed_as_source: bool = False
    packets: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    syn_sent: int = 0
    synack_recv: int = 0
    rst_recv: int = 0
    dst_hosts: set[str] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    dns_queries: list[Packet] = field(default_factory=list)
    pkt_sizes: list[int] = field(default_factory=list)
    flows: set[str] = field(default_factory=set)
    # Per-peer byte counts. The exfiltration detector needs directional volume
    # against one destination, which the aggregate totals above cannot give it.
    bytes_to: Counter = field(default_factory=Counter)
    bytes_from: Counter = field(default_factory=Counter)
    # (dst, dport, ts, frame_len) tuples for every new outbound contact, feeding
    # the beacon detector's timing and packet-size-stability analysis.
    contacts: list[tuple[str, int, float, int]] = field(default_factory=list)

    @property
    def fanout(self) -> int:
        return len(self.dst_ports) + len(self.dst_hosts)

    @property
    def completion_ratio(self) -> float:
        """Fraction of this host's SYNs that drew an observed SYN/ACK.

        Returns NO_COMPLETION_DATA when the host sent no SYN. The previous
        behaviour returned 1.0 here, which was indistinguishable from "every
        handshake succeeded" -- so a UDP-only host, or a server observed from
        the wrong side, reported perfect TCP completion it had never attempted.
        Across the benign training set that made the column constant at 1.0,
        zero-variance, and therefore unusable by the model.
        """
        if not self.syn_sent:
            return NO_COMPLETION_DATA
        return self.synack_recv / self.syn_sent

    @property
    def has_completion_data(self) -> bool:
        """True when completion_ratio is a real measurement rather than a gap."""
        return self.syn_sent > 0

    @property
    def out_in_ratio(self) -> float:
        if self.bytes_in == 0:
            return float(self.bytes_out) if self.bytes_out else 0.0
        return self.bytes_out / self.bytes_in

    @property
    def mean_pkt_size(self) -> float:
        return sum(self.pkt_sizes) / len(self.pkt_sizes) if self.pkt_sizes else 0.0


@dataclass
class TargetFeatures:
    """What one destination address received during one window.

    SYN floods are visible here, not in HostFeatures: the attack signature is a
    victim absorbing SYNs from many (often spoofed) sources.
    """

    dst: str
    packets_in: int = 0
    bytes_in: int = 0
    syn_in: int = 0
    synack_out: int = 0
    rst_out: int = 0
    src_counts: Counter = field(default_factory=Counter)
    dports: Counter = field(default_factory=Counter)
    udp_in: int = 0
    udp_bytes_in: int = 0
    # Inbound bytes/reflector-IPs keyed by SOURCE port, only when that port is
    # in AMPLIFICATION_PORTS -- i.e. a response landing on this host from a
    # well-known reflector service, not a request to this host's own service.
    # Bounded to a 9-key outer space; see AMPLIFICATION_PORTS/MAX_REFLECTORS_TRACKED.
    amp_bytes_by_port: Counter = field(default_factory=Counter)
    amp_reflectors_by_port: dict[int, set[str]] = field(default_factory=dict)

    @property
    def unique_sources(self) -> int:
        return len(self.src_counts)

    @property
    def src_entropy(self) -> float:
        return shannon_entropy(self.src_counts)

    @property
    def completion_ratio(self) -> float:
        return self.synack_out / self.syn_in if self.syn_in else 1.0


@dataclass
class TlsSession:
    """TLS records seen in one direction of one connection, within one window.

    Keyed on the full directional 4-tuple rather than (src, dst, dport). A
    browser routinely opens six parallel connections to the same server; folding
    them into one series would interleave three independent conversations and
    manufacture a period that no single session actually has. The same key also
    keeps sequential unrelated sessions to one server from being concatenated.
    """

    src: str
    sport: int
    dst: str
    dport: int
    # (timestamp, record length from the TLS header). Never payload bytes.
    records: list[tuple[float, int]] = field(default_factory=list)
    ja3: str = ""
    ja3_string: str = ""
    sni: str = ""
    saw_client_hello: bool = False


@dataclass
class WindowFeatures:
    window: Window
    duration: float
    packets: int = 0
    bytes: int = 0
    # Keyed by host address, holding every peer seen in the window in either
    # direction. Filter on HostFeatures.observed_as_source for actual senders.
    by_host: dict[str, HostFeatures] = field(default_factory=dict)
    by_dst: dict[str, TargetFeatures] = field(default_factory=dict)
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    syn: int = 0
    synack: int = 0
    dns_queries: int = 0
    # Directional 4-tuple -> TlsSession. A session outlives a window, so the
    # detector stitches these together across windows; this is only the slice
    # observed here.
    tls_sessions: dict[tuple[str, int, str, int], TlsSession] = field(default_factory=dict)

    @property
    def pps(self) -> float:
        return self.packets / self.duration if self.duration > 0 else 0.0

    @property
    def bps(self) -> float:
        return (self.bytes * 8) / self.duration if self.duration > 0 else 0.0


def extract(window: Window) -> WindowFeatures:
    """Single pass over the window's packets, building every feature view."""
    duration = window.duration if window.duration > 0 else 1e-6
    wf = WindowFeatures(window=window, duration=duration)

    by_host: dict[str, HostFeatures] = {}
    by_dst: dict[str, TargetFeatures] = {}
    tls_sessions: dict[tuple[str, int, str, int], TlsSession] = {}

    for pkt in window.packets:
        wf.packets += 1
        wf.bytes += pkt.length

        src = by_host.get(pkt.src)
        if src is None:
            src = by_host[pkt.src] = HostFeatures(src=pkt.src)
        # This host has now been seen transmitting, whatever else it does.
        src.observed_as_source = True
        dst = by_dst.get(pkt.dst)
        if dst is None:
            dst = by_dst[pkt.dst] = TargetFeatures(dst=pkt.dst)

        src.packets += 1
        src.bytes_out += pkt.length
        src.pkt_sizes.append(pkt.length)
        src.dst_hosts.add(pkt.dst)
        src.bytes_to[pkt.dst] += pkt.length

        dst.packets_in += 1
        dst.bytes_in += pkt.length
        dst.src_counts[pkt.src] += 1

        # Bytes arriving at a host are that host's inbound volume. Tracking both
        # directions per host is what makes the out:in ratio meaningful.
        # Note this deliberately does NOT set observed_as_source: receiving
        # bytes is not behaviour, and a row created only by this branch is a
        # peer we see from the wrong side.
        peer = by_host.get(pkt.dst)
        if peer is None:
            peer = by_host[pkt.dst] = HostFeatures(src=pkt.dst)
        peer.bytes_in += pkt.length
        peer.bytes_from[pkt.src] += pkt.length

        # DNS collection is transport-agnostic. It used to live inside the UDP
        # branch, which meant a tunnel over TCP/53 parsed correctly at ingest
        # and then never reached the detector -- the query was counted as
        # ordinary TCP and dropped. Anything the reader identified as DNS
        # belongs here regardless of how it travelled.
        if pkt.dns_qname and not pkt.dns_is_response:
            wf.dns_queries += 1
            src.dns_queries.append(pkt)

        if pkt.proto == "TCP":
            wf.tcp += 1
            src.tcp += 1
            src.dst_ports.add(pkt.dport)
            dst.dports[pkt.dport] += 1
            if pkt.is_syn:
                wf.syn += 1
                src.syn_sent += 1
                dst.syn_in += 1
                src.contacts.append((pkt.dst, pkt.dport, pkt.ts, pkt.length))
            elif pkt.is_synack:
                wf.synack += 1
                dst.synack_out += 1
                # A SYN/ACK from B to A completes A's outbound attempt.
                peer.synack_recv += 1
            elif pkt.is_rst:
                dst.rst_out += 1
                peer.rst_recv += 1
            # TLS is collected by record type, not by port -- reader.py sniffs
            # the record header on any TCP payload, so a session on 8443 or an
            # implant's arbitrary port lands here the same as one on 443.
            if pkt.tls_record_type:
                tkey = (pkt.src, pkt.sport, pkt.dst, pkt.dport)
                sess = tls_sessions.get(tkey)
                if sess is None and len(tls_sessions) < MAX_TLS_SESSIONS:
                    sess = tls_sessions[tkey] = TlsSession(
                        src=pkt.src, sport=pkt.sport, dst=pkt.dst, dport=pkt.dport
                    )
                if sess is not None:
                    if len(sess.records) < MAX_TLS_RECORDS_PER_SESSION:
                        sess.records.append((pkt.ts, pkt.tls_record_len))
                    if pkt.tls_ja3 and not sess.saw_client_hello:
                        sess.saw_client_hello = True
                        sess.ja3 = pkt.tls_ja3
                        sess.ja3_string = pkt.tls_ja3_string
                        sess.sni = pkt.tls_sni
        elif pkt.proto == "UDP":
            wf.udp += 1
            src.udp += 1
            src.dst_ports.add(pkt.dport)
            dst.udp_in += 1
            dst.udp_bytes_in += pkt.length
            if pkt.sport in AMPLIFICATION_PORTS:
                dst.amp_bytes_by_port[pkt.sport] += pkt.length
                refl = dst.amp_reflectors_by_port.setdefault(pkt.sport, set())
                if len(refl) < MAX_REFLECTORS_TRACKED:
                    refl.add(pkt.src)
            dst.dports[pkt.dport] += 1
            if pkt.dport != 53:
                src.contacts.append((pkt.dst, pkt.dport, pkt.ts, pkt.length))
        elif pkt.proto == "ICMP":
            wf.icmp += 1
            src.icmp += 1

    for flow_id, rec in window.flows.items():
        hf = by_host.get(rec.src)
        if hf is not None:
            hf.flows.add(flow_id)

    wf.by_host = by_host
    wf.by_dst = by_dst
    wf.tls_sessions = tls_sessions
    return wf


def host_vector(hf: HostFeatures, duration: float) -> list[float]:
    """The ~10-dimension feature vector consumed by the anomaly model.

    Documented one-by-one in docs/MODEL.md. Rates are normalised by window
    duration so the model is not sensitive to the window size we happened to
    pick, and byte counts are log-scaled because traffic volume is heavy-tailed.
    """
    d = duration if duration > 0 else 1e-6
    return [
        hf.packets / d,                       # packet rate out
        math.log1p(hf.bytes_out),             # outbound volume (log)
        math.log1p(hf.bytes_in),              # inbound volume (log)
        len(hf.dst_hosts),                    # host fan-out
        len(hf.dst_ports),                    # port fan-out
        hf.syn_sent / d,                      # SYN rate
        hf.completion_ratio,                  # handshake completion
        min(hf.out_in_ratio, 1000.0),         # directional asymmetry (clipped)
        hf.mean_pkt_size,                     # mean frame size
        len(hf.flows) / d,                    # flow creation rate
    ]


VECTOR_FEATURE_NAMES = [
    "packet_rate_pps",
    "log_bytes_out",
    "log_bytes_in",
    "unique_dst_hosts",
    "unique_dst_ports",
    "syn_rate_pps",
    "completion_ratio",
    "out_in_byte_ratio",
    "mean_packet_size",
    "flow_rate_fps",
]

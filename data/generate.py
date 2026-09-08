"""Controlled demo traffic generator.

Produces the labelled captures the detectors are developed and measured against.
Every packet here is synthetic and every attack is one we placed ourselves,
which is the only reason precision/recall can be computed at all -- we know the
ground truth because we wrote it.

Read that as the caveat it is. These captures demonstrate that the detectors
fire correctly on known-good ground truth. They are NOT evidence of production
detection accuracy, and nothing built on them should be presented as such.

    python data/generate.py --seed 42 --out data/pcaps

Writes eight captures plus data/labels.json.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import string
from dataclasses import dataclass, field

from scapy.all import ICMP, IP, TCP, UDP, DNS, DNSQR, DNSRR, Ether, PcapWriter, Raw

# --- topology ---------------------------------------------------------------
CLIENT_NET = "10.0.0."
SERVER_NET = "10.0.1."
GATEWAY_MAC = "00:11:22:33:44:55"
HOST_MAC = "00:aa:bb:cc:dd:{:02x}"

EXTERNAL = [
    "142.250.183.14", "104.244.42.65", "13.107.42.14", "151.101.65.140",
    "52.94.236.248", "199.232.69.140", "23.62.99.16", "104.18.32.47",
]

REAL_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "github.com", "cloudflare.com",
    "microsoft.com", "stackoverflow.com", "amazon.in", "irctc.co.in", "sbi.co.in",
    "ndtv.com", "flipkart.com", "zomato.com", "linkedin.com", "mozilla.org",
    "python.org", "docker.com", "office.com", "paytm.com", "uidai.gov.in",
]

CAPTURE_DURATION = 300.0  # seconds of traffic per capture
BASE_TS = 1756200000.0    # fixed epoch so runs are byte-reproducible


@dataclass
class GroundTruth:
    threat_class: str
    src: str
    dst: str
    start_epoch: float
    end_epoch: float
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "threat_class": self.threat_class,
            "src": self.src,
            "dst": self.dst,
            "start_epoch": round(self.start_epoch, 3),
            "end_epoch": round(self.end_epoch, 3),
            "note": self.note,
        }


@dataclass
class Capture:
    """Accumulates (timestamp, packet) pairs, then writes them in time order."""

    name: str
    packets: list = field(default_factory=list)
    truth: list[GroundTruth] = field(default_factory=list)

    def add(self, ts: float, pkt) -> None:
        self.packets.append((ts, pkt))

    def extend(self, other: "Capture") -> None:
        self.packets.extend(other.packets)
        self.truth.extend(other.truth)

    def write(self, out_dir: str) -> dict:
        path = os.path.join(out_dir, self.name)
        self.packets.sort(key=lambda p: p[0])
        writer = PcapWriter(path, linktype=1, sync=False)
        try:
            for ts, pkt in self.packets:
                pkt.time = ts
                writer.write(pkt)
        finally:
            writer.close()

        first = self.packets[0][0] if self.packets else 0.0
        last = self.packets[-1][0] if self.packets else 0.0
        return {
            "packets": len(self.packets),
            "duration_s": round(last - first, 3),
            "bytes": sum(len(p) for _, p in self.packets),
            "first_epoch": round(first, 3),
            "last_epoch": round(last, 3),
            "ground_truth": [t.to_dict() for t in self.truth],
        }


def eth(host_id: int = 1):
    return Ether(src=HOST_MAC.format(host_id % 256), dst=GATEWAY_MAC)


def client_ip(rng: random.Random) -> str:
    return CLIENT_NET + str(rng.randint(10, 60))


# --- normal traffic ---------------------------------------------------------

def gen_normal(rng: random.Random, duration: float = CAPTURE_DURATION) -> Capture:
    """Ordinary background traffic: web sessions, DNS, ICMP, NTP.

    Deliberately varied. Every baseline and the anomaly model are learned from
    this, and a thin or repetitive normal set produces a detector that fires on
    everything -- the single most common way this kind of prototype fails.
    """
    cap = Capture("normal.pcap")
    clients = [CLIENT_NET + str(i) for i in range(10, 41)]
    resolver = SERVER_NET + "53"  # 10.0.1.53

    t = 0.0
    session_id = 0
    while t < duration:
        client = rng.choice(clients)
        host_id = int(client.split(".")[-1])
        session_id += 1

        # DNS lookup for a real domain, answered by the local resolver.
        domain = rng.choice(REAL_DOMAINS)
        sport = rng.randint(20000, 60000)
        txid = rng.randint(0, 65535)
        server_ip = rng.choice(EXTERNAL)

        cap.add(BASE_TS + t, eth(host_id) / IP(src=client, dst=resolver) /
                UDP(sport=sport, dport=53) /
                DNS(id=txid, rd=1, qd=DNSQR(qname=domain)))
        cap.add(BASE_TS + t + 0.012, eth(1) / IP(src=resolver, dst=client) /
                UDP(sport=53, dport=sport) /
                DNS(id=txid, qr=1, ra=1, qd=DNSQR(qname=domain),
                    an=DNSRR(rrname=domain, ttl=300, rdata=server_ip)))

        # A short HTTPS session to the resolved address.
        t += 0.05
        cport = rng.randint(20000, 60000)
        dport = rng.choice([443, 443, 443, 80, 8443])
        seq, ack = rng.randint(0, 2**31), rng.randint(0, 2**31)

        cap.add(BASE_TS + t, eth(host_id) / IP(src=client, dst=server_ip) /
                TCP(sport=cport, dport=dport, flags="S", seq=seq))
        cap.add(BASE_TS + t + 0.018, eth(1) / IP(src=server_ip, dst=client) /
                TCP(sport=dport, dport=cport, flags="SA", seq=ack, ack=seq + 1))
        cap.add(BASE_TS + t + 0.019, eth(host_id) / IP(src=client, dst=server_ip) /
                TCP(sport=cport, dport=dport, flags="A", seq=seq + 1, ack=ack + 1))

        # Inbound-heavy exchange, which is what ordinary browsing looks like.
        n_up = rng.randint(2, 5)
        n_down = rng.randint(6, 20)
        ts = t + 0.02
        for i in range(n_up):
            ts += rng.uniform(0.01, 0.12)
            cap.add(BASE_TS + ts, eth(host_id) / IP(src=client, dst=server_ip) /
                    TCP(sport=cport, dport=dport, flags="PA", seq=seq + 1 + i) /
                    Raw(load=b"x" * rng.randint(80, 500)))
        for i in range(n_down):
            ts += rng.uniform(0.005, 0.06)
            cap.add(BASE_TS + ts, eth(1) / IP(src=server_ip, dst=client) /
                    TCP(sport=dport, dport=cport, flags="PA", seq=ack + 1 + i) /
                    Raw(load=b"y" * rng.randint(400, 1400)))

        ts += 0.05
        cap.add(BASE_TS + ts, eth(host_id) / IP(src=client, dst=server_ip) /
                TCP(sport=cport, dport=dport, flags="FA"))
        cap.add(BASE_TS + ts + 0.01, eth(1) / IP(src=server_ip, dst=client) /
                TCP(sport=dport, dport=cport, flags="FA"))

        # Occasional ICMP and NTP so the model sees more than TCP and DNS.
        if session_id % 7 == 0:
            peer = rng.choice(clients)
            cap.add(BASE_TS + t + 0.3, eth(host_id) / IP(src=client, dst=peer) /
                    ICMP(type=8) / Raw(load=b"p" * 56))
            cap.add(BASE_TS + t + 0.31, eth(1) / IP(src=peer, dst=client) /
                    ICMP(type=0) / Raw(load=b"p" * 56))
        if session_id % 11 == 0:
            cap.add(BASE_TS + t + 0.4, eth(host_id) / IP(src=client, dst=SERVER_NET + "123") /
                    UDP(sport=rng.randint(20000, 60000), dport=123) / Raw(load=b"n" * 48))

        t += rng.uniform(0.15, 0.6)

    return cap


# --- attacks ----------------------------------------------------------------

def gen_synflood(rng: random.Random, start: float = 90.0, duration: float = 20.0,
                 rate: int = 1500) -> Capture:
    """Spoofed-source SYN flood: high rate, near-zero completion, high entropy."""
    cap = Capture("synflood.pcap")
    victim = SERVER_NET + "10"
    interval = 1.0 / rate

    t = start
    n = 0
    while t < start + duration:
        # Fresh random source every packet -- the spoofing signature the
        # detector picks up as near-maximum source-IP entropy.
        spoof = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        cap.add(BASE_TS + t, eth(2) / IP(src=spoof, dst=victim) /
                TCP(sport=rng.randint(1024, 65535), dport=80, flags="S",
                    seq=rng.randint(0, 2**31)))
        # A tiny fraction get a SYN/ACK back before the backlog fills, which is
        # realistic and keeps the completion ratio non-zero rather than exactly 0.
        if n % 400 == 0:
            cap.add(BASE_TS + t + 0.001, eth(1) / IP(src=victim, dst=spoof) /
                    TCP(sport=80, dport=1024, flags="SA"))
        t += interval
        n += 1

    cap.truth.append(GroundTruth(
        "SYN_FLOOD", "*", victim, BASE_TS + start, BASE_TS + start + duration,
        f"spoofed-source SYN flood, ~{rate} pkt/s for {duration:.0f}s"))
    return cap


def gen_udp_amplification(rng: random.Random, start: float = 250.0, duration: float = 15.0,
                          rate: int = 800) -> Capture:
    """UDP reflection/amplification: many distinct external "reflectors" send
    large UDP responses to one internal victim.

    Only the reflector->victim leg is synthesized. A one-way tap at the
    victim's gateway would never see the attacker->reflector leg either --
    both ends of that conversation are external and (per real amplification
    attacks) the attacker's request is spoofed to carry the victim's address,
    so it never crosses this link. Same reasoning gen_synflood() already
    applies to its own spoofed sources.

    Port 123 (NTP), not 53/DNS -- avoids needless coupling to _attach_dns()'s
    parse path for no benefit.
    """
    cap = Capture("udp_amp.pcap")
    victim = SERVER_NET + "40"
    interval = 1.0 / rate

    t = start
    while t < start + duration:
        # Fresh random reflector every packet, same spoofing-signature
        # rationale as gen_synflood's spoofed sources.
        reflector = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        cap.add(BASE_TS + t, eth(3) / IP(src=reflector, dst=victim) /
                UDP(sport=123, dport=rng.randint(1024, 65535)) /
                Raw(load=b"R" * 900))
        t += interval

    cap.truth.append(GroundTruth(
        "UDP_AMPLIFICATION", "*", victim, BASE_TS + start, BASE_TS + start + duration,
        f"NTP reflection/amplification, ~{rate} pkt/s x ~900B for {duration:.0f}s"))
    return cap


# --- TLS wire helpers -------------------------------------------------------
# Hand-rolled rather than via scapy.layers.tls, because the whole point is to
# control the exact ClientHello bytes that produce a given JA3. A library that
# chose cipher order for us would defeat the exercise.

# RFC 5737 TEST-NET-3, reserved for documentation. Deliberately not routable: a
# fictional C2 in a public repository should not be somebody's real host.
TLS_C2_IP = "203.0.113.47"


def tls_record(content_type: int, body_len: int) -> bytes:
    """A TLS record header plus filler. The header length is what we detect on."""
    return bytes([content_type, 0x03, 0x03]) + body_len.to_bytes(2, "big") + b"\x00" * body_len


def client_hello(ciphers, ext_order, curves, formats, sni: str = "",
                 version: int = 0x0303) -> bytes:
    """Assemble a ClientHello whose JA3 is fully determined by the arguments."""
    body = version.to_bytes(2, "big") + b"\xAB" * 32 + b"\x00"
    body += (len(ciphers) * 2).to_bytes(2, "big")
    body += b"".join(c.to_bytes(2, "big") for c in ciphers)
    body += b"\x01\x00"  # one compression method, null

    blob = b""
    for et in ext_order:
        if et == 0x0000 and sni:
            name = sni.encode()
            eb = (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name
        elif et == 0x000A:
            eb = (len(curves) * 2).to_bytes(2, "big") + b"".join(c.to_bytes(2, "big") for c in curves)
        elif et == 0x000B:
            eb = bytes([len(formats)]) + bytes(formats)
        else:
            eb = b""
        blob += et.to_bytes(2, "big") + len(eb).to_bytes(2, "big") + eb
    body += len(blob).to_bytes(2, "big") + blob

    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


# Three benign client profiles, so the capture carries a fingerprint population
# rather than one template. Illustrative of the general shape of mainstream TLS
# stacks -- NOT captured from real software, and the docs say so rather than
# implying we fingerprinted real browsers.
BENIGN_PROFILES = [
    ([0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0x009C],
     [0x0000, 0x0017, 0x000A, 0x000B, 0x0010, 0x0005, 0x000D, 0x0012, 0x002B, 0x0033],
     [0x001D, 0x0017, 0x0018], [0]),
    ([0x1301, 0x1303, 0x1302, 0xC02C, 0xC030, 0xC02B, 0xC02F, 0x009D, 0x009C],
     [0x0000, 0x000A, 0x000B, 0x000D, 0x0010, 0x002B, 0x0033, 0x001B],
     [0x001D, 0x0017], [0]),
    ([0xC02B, 0xC02F, 0xC02C, 0xC030, 0x009C, 0x009D, 0x002F, 0x0035],
     [0x0000, 0x000A, 0x000B, 0x000D, 0x0010, 0x0017],
     [0x0017, 0x0018, 0x0019], [0, 1, 2]),
]

# The implant: an old TLS version, a short idiosyncratic cipher list, almost no
# extensions, no SNI. Reported as evidence only -- none of this gates.
MALWARE_PROFILE = ([0xC014, 0xC013, 0x0035, 0x002F, 0x000A],
                   [0x000A, 0x000B, 0x0023],
                   [0x0017, 0x0018], [0])


def _tls_open(cap, rng, host_id, client, server, cport, dport, t, hello):
    """Three-way handshake followed by the ClientHello."""
    seq, ack = rng.randint(0, 2**31), rng.randint(0, 2**31)
    cap.add(BASE_TS + t, eth(host_id) / IP(src=client, dst=server) /
            TCP(sport=cport, dport=dport, flags="S", seq=seq))
    cap.add(BASE_TS + t + 0.014, eth(1) / IP(src=server, dst=client) /
            TCP(sport=dport, dport=cport, flags="SA", seq=ack, ack=seq + 1))
    cap.add(BASE_TS + t + 0.015, eth(host_id) / IP(src=client, dst=server) /
            TCP(sport=cport, dport=dport, flags="A", seq=seq + 1, ack=ack + 1))
    cap.add(BASE_TS + t + 0.016, eth(host_id) / IP(src=client, dst=server) /
            TCP(sport=cport, dport=dport, flags="PA", seq=seq + 1) / Raw(load=hello))


def gen_tls_malware(rng: random.Random, start: float = 40.0,
                    duration: float = 230.0, interval: float = 20.0) -> Capture:
    """Malware C2 inside a TLS session, plus the benign TLS it must not flag.

    The benign half is not decoration. Without it the zero-false-positive result
    would be an artefact of a capture containing nothing that could plausibly
    fire, so this deliberately includes the three shapes most likely to break a
    size/timing detector:

      * a metrics agent posting a FIXED-size record on a perfect 15s beat --
        it passes the timing gate outright, and is rejected only by the
        distinct-size and lift gates. The sharpest test in the file.
      * six parallel connections from one host to one server -- these would
        manufacture a period if sessions were keyed on (src, dst, dport)
        rather than the full 4-tuple.
      * a long-lived reused connection with human-paced, irregular bursts.

    The implant sends a repeating three-record check-in on a jittered beat,
    which is what the detector actually reads. Its ClientHello is distinctive
    and carries no SNI, but that is reported as evidence only.
    """
    cap = Capture("tls_malware.pcap")

    # -- benign population: ordinary short TLS sessions ----------------------
    benign_hosts = [CLIENT_NET + str(i) for i in range(12, 24)]
    t = 2.0
    while t < duration:
        client = rng.choice(benign_hosts)
        host_id = int(client.split(".")[-1])
        server = rng.choice(EXTERNAL)
        cport = rng.randint(20000, 60000)
        ciphers, exts, curves, formats = rng.choice(BENIGN_PROFILES)
        hello = client_hello(ciphers, exts, curves, formats, sni=rng.choice(REAL_DOMAINS))
        _tls_open(cap, rng, host_id, client, server, cport, 443, t, hello)

        ts = t + 0.05
        for _ in range(rng.randint(4, 14)):
            ts += rng.uniform(0.01, 0.4)
            cap.add(BASE_TS + ts, eth(host_id) / IP(src=client, dst=server) /
                    TCP(sport=cport, dport=443, flags="PA") /
                    Raw(load=tls_record(0x17, rng.randint(90, 700))))
            ts += rng.uniform(0.01, 0.2)
            cap.add(BASE_TS + ts, eth(1) / IP(src=server, dst=client) /
                    TCP(sport=443, dport=cport, flags="PA") /
                    Raw(load=tls_record(0x17, rng.randint(300, 1380))))
        t += rng.uniform(0.4, 1.6)

    # -- benign metrics agent: fixed size, perfect beat ----------------------
    # Passes the timing gate. Only the distinct-size and lift gates stop it,
    # which is exactly the false positive a naive size-CV detector would emit.
    agent = CLIENT_NET + "31"
    collector = SERVER_NET + "80"
    aport = 41112
    ciphers, exts, curves, formats = BENIGN_PROFILES[1]
    _tls_open(cap, rng, 31, agent, collector, aport, 443, 3.0,
              client_hello(ciphers, exts, curves, formats, sni="metrics.internal"))
    ts = 5.0
    while ts < duration:
        cap.add(BASE_TS + ts, eth(31) / IP(src=agent, dst=collector) /
                TCP(sport=aport, dport=443, flags="PA") / Raw(load=tls_record(0x17, 256)))
        cap.add(BASE_TS + ts + 0.03, eth(1) / IP(src=collector, dst=agent) /
                TCP(sport=443, dport=aport, flags="PA") / Raw(load=tls_record(0x17, 64)))
        ts += 15.0

    # -- benign parallel connections: one host, one server, six sockets ------
    par_host = CLIENT_NET + "33"
    par_server = EXTERNAL[0]
    ciphers, exts, curves, formats = BENIGN_PROFILES[0]
    for n in range(6):
        cport = 45000 + n
        _tls_open(cap, rng, 33, par_host, par_server, cport, 443, 8.0 + n * 0.05,
                  client_hello(ciphers, exts, curves, formats, sni="cdn.example.net"))
        ts = 8.4 + n * 0.05
        for _ in range(12):
            ts += rng.uniform(0.02, 0.5)
            cap.add(BASE_TS + ts, eth(33) / IP(src=par_host, dst=par_server) /
                    TCP(sport=cport, dport=443, flags="PA") /
                    Raw(load=tls_record(0x17, rng.randint(100, 900))))
            ts += rng.uniform(0.01, 0.3)
            cap.add(BASE_TS + ts, eth(1) / IP(src=par_server, dst=par_host) /
                    TCP(sport=443, dport=cport, flags="PA") /
                    Raw(load=tls_record(0x17, rng.randint(400, 1400))))

    # -- benign long-lived reused connection, human-paced ---------------------
    ws_host = CLIENT_NET + "35"
    ws_server = EXTERNAL[3]
    ws_port = 46001
    ciphers, exts, curves, formats = BENIGN_PROFILES[2]
    _tls_open(cap, rng, 35, ws_host, ws_server, ws_port, 8443, 6.0,
              client_hello(ciphers, exts, curves, formats, sni="chat.example.org"))
    ts = 7.0
    while ts < duration:
        for _ in range(rng.randint(1, 5)):
            ts += rng.uniform(0.2, 2.0)
            cap.add(BASE_TS + ts, eth(35) / IP(src=ws_host, dst=ws_server) /
                    TCP(sport=ws_port, dport=8443, flags="PA") /
                    Raw(load=tls_record(0x17, rng.randint(60, 1200))))
        ts += rng.uniform(3.0, 25.0)

    # -- the implant ----------------------------------------------------------
    victim = CLIENT_NET + "77"
    cport = 51877
    ciphers, exts, curves, formats = MALWARE_PROFILE
    # No SNI: the implant dials a hardcoded address and has no hostname to offer.
    _tls_open(cap, rng, 77, victim, TLS_C2_IP, cport, 443, start,
              client_hello(ciphers, exts, curves, formats, sni="", version=0x0301))

    # A fixed-shape check-in: three records up, two down, on a jittered beat.
    # The first two are the implant's fixed-format header and authenticator and
    # do not change size; only the third carries tasking or collected output, so
    # only that one varies, and only when there is something to carry. That
    # asymmetry is the realistic shape -- an implant whose every record changed
    # size on every beat would be a different and much noisier thing.
    up_pattern = [188, 76, 604]
    ts = start + 0.1
    checkins = 0
    while ts < start + duration:
        for i, size in enumerate(up_pattern):
            n = size
            if i == len(up_pattern) - 1 and checkins % 6 == 5:
                n = size + rng.choice([120, 240, 360])
            cap.add(BASE_TS + ts + i * 0.02, eth(77) / IP(src=victim, dst=TLS_C2_IP) /
                    TCP(sport=cport, dport=443, flags="PA") / Raw(load=tls_record(0x17, n)))
        cap.add(BASE_TS + ts + 0.09, eth(1) / IP(src=TLS_C2_IP, dst=victim) /
                TCP(sport=443, dport=cport, flags="PA") / Raw(load=tls_record(0x17, 1104)))
        cap.add(BASE_TS + ts + 0.11, eth(1) / IP(src=TLS_C2_IP, dst=victim) /
                TCP(sport=443, dport=cport, flags="PA") / Raw(load=tls_record(0x17, 60)))
        checkins += 1
        ts += interval + rng.uniform(-1.5, 1.5)

    cap.truth.append(GroundTruth(
        "TLS_MALWARE", victim, TLS_C2_IP, BASE_TS + start, BASE_TS + start + duration,
        f"TLS C2 check-in every ~{interval:.0f}s for {duration:.0f}s: repeating "
        f"{len(up_pattern)}-record size pattern inside one long-lived session, "
        f"distinctive ClientHello, no SNI"))
    return cap


def gen_portscan(rng: random.Random, start: float = 150.0, duration: float = 12.0) -> Capture:
    """One source sweeping many ports across many hosts."""
    cap = Capture("portscan.pcap")
    scanner = CLIENT_NET + "66"
    targets = [SERVER_NET + str(i) for i in range(10, 52)]
    ports = list(range(20, 200)) + [443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

    open_ports = {22, 80, 443, 3306}
    t = start
    step = duration / (len(targets) * 6)

    for target in targets:
        for dport in rng.sample(ports, 6):
            sport = rng.randint(40000, 60000)
            cap.add(BASE_TS + t, eth(66) / IP(src=scanner, dst=target) /
                    TCP(sport=sport, dport=dport, flags="S", seq=rng.randint(0, 2**31)))
            # Closed ports answer with RST; the few open ones complete.
            if dport in open_ports:
                cap.add(BASE_TS + t + 0.002, eth(1) / IP(src=target, dst=scanner) /
                        TCP(sport=dport, dport=sport, flags="SA"))
            else:
                cap.add(BASE_TS + t + 0.002, eth(1) / IP(src=target, dst=scanner) /
                        TCP(sport=dport, dport=sport, flags="RA"))
            t += step

    # A tight sequential sweep of one host, so the sequential-run evidence fires.
    focus = SERVER_NET + "10"
    for dport in range(1, 121):
        sport = rng.randint(40000, 60000)
        cap.add(BASE_TS + t, eth(66) / IP(src=scanner, dst=focus) /
                TCP(sport=sport, dport=dport, flags="S"))
        cap.add(BASE_TS + t + 0.001, eth(1) / IP(src=focus, dst=scanner) /
                TCP(sport=dport, dport=sport, flags="RA"))
        t += 0.01

    cap.truth.append(GroundTruth(
        "PORT_SCAN", scanner, "*", BASE_TS + start, BASE_TS + t,
        "vertical + horizontal sweep, ~300 ports across 42 hosts"))
    return cap


def gen_beacon(rng: random.Random, start: float = 20.0, duration: float = 260.0,
               interval: float = 20.0, jitter: float = 1.5) -> Capture:
    """Implant checking in to one C2 destination at near-fixed intervals."""
    cap = Capture("beacon.pcap")
    bot = CLIENT_NET + "77"
    c2 = "185.199.110.153"
    dport = 443

    t = start
    checkins = 0
    while t < start + duration:
        sport = rng.randint(30000, 60000)
        seq = rng.randint(0, 2**31)
        cap.add(BASE_TS + t, eth(77) / IP(src=bot, dst=c2) /
                TCP(sport=sport, dport=dport, flags="S", seq=seq))
        cap.add(BASE_TS + t + 0.03, eth(1) / IP(src=c2, dst=bot) /
                TCP(sport=dport, dport=sport, flags="SA"))
        cap.add(BASE_TS + t + 0.031, eth(77) / IP(src=bot, dst=c2) /
                TCP(sport=sport, dport=dport, flags="A"))
        # Fixed-size check-in and fixed-size task response: the packet-size
        # stability the detector reports alongside the timing regularity.
        cap.add(BASE_TS + t + 0.04, eth(77) / IP(src=bot, dst=c2) /
                TCP(sport=sport, dport=dport, flags="PA") / Raw(load=b"c" * 128))
        cap.add(BASE_TS + t + 0.08, eth(1) / IP(src=c2, dst=bot) /
                TCP(sport=dport, dport=sport, flags="PA") / Raw(load=b"r" * 96))
        cap.add(BASE_TS + t + 0.10, eth(77) / IP(src=bot, dst=c2) /
                TCP(sport=sport, dport=dport, flags="FA"))

        checkins += 1
        t += interval + rng.uniform(-jitter, jitter)

    cap.truth.append(GroundTruth(
        "C2_BEACON", bot, c2, BASE_TS + start, BASE_TS + t,
        f"{checkins} check-ins at {interval:.0f}s +/-{jitter:.1f}s"))
    return cap


def gen_dns_tunnel(rng: random.Random, start: float = 60.0, duration: float = 90.0) -> Capture:
    """Data smuggled in long, high-entropy subdomain labels under one parent."""
    cap = Capture("dns_tunnel.pcap")
    host = CLIENT_NET + "88"
    resolver = SERVER_NET + "53"
    parent = "x7k2q-tunnel.net"
    alphabet = string.ascii_lowercase + string.digits

    t = start
    queries = 0
    while t < start + duration:
        # 40-52 random characters: a chunk of base32-ish encoded payload.
        label = "".join(rng.choice(alphabet) for _ in range(rng.randint(40, 52)))
        qname = f"{label}.{parent}"
        sport = rng.randint(20000, 60000)
        txid = rng.randint(0, 65535)
        qtype = "TXT" if queries % 3 else "NULL"

        cap.add(BASE_TS + t, eth(88) / IP(src=host, dst=resolver) /
                UDP(sport=sport, dport=53) /
                DNS(id=txid, rd=1, qd=DNSQR(qname=qname, qtype=qtype if qtype == "TXT" else 10)))
        cap.add(BASE_TS + t + 0.02, eth(1) / IP(src=resolver, dst=host) /
                UDP(sport=53, dport=sport) /
                DNS(id=txid, qr=1, ra=1, qd=DNSQR(qname=qname, qtype=16),
                    an=DNSRR(rrname=qname, type=16, ttl=1,
                             rdata="".join(rng.choice(alphabet) for _ in range(80)))))
        queries += 1
        t += rng.uniform(0.5, 1.2)

    cap.truth.append(GroundTruth(
        "DNS_ANOMALY", host, parent, BASE_TS + start, BASE_TS + t,
        f"{queries} tunnelling queries, 40-52 char high-entropy labels"))
    return cap


def gen_exfil(rng: random.Random, start: float = 120.0, duration: float = 130.0) -> Capture:
    """Sustained outbound transfer to one external host; tiny return traffic."""
    cap = Capture("exfil.pcap")
    host = CLIENT_NET + "99"
    dest = "45.83.91.22"
    dport = 443
    sport = rng.randint(30000, 60000)

    cap.add(BASE_TS + start, eth(99) / IP(src=host, dst=dest) /
            TCP(sport=sport, dport=dport, flags="S"))
    cap.add(BASE_TS + start + 0.03, eth(1) / IP(src=dest, dst=host) /
            TCP(sport=dport, dport=sport, flags="SA"))

    t = start + 0.05
    seq = 1
    sent = 0
    # A steady drip rather than one burst: the shape a careful exfiltration
    # tool produces, and the one a single-window detector would miss.
    while t < start + duration:
        for _ in range(4):
            cap.add(BASE_TS + t, eth(99) / IP(src=host, dst=dest) /
                    TCP(sport=sport, dport=dport, flags="PA", seq=seq) /
                    Raw(load=b"D" * 1400))
            sent += 1400
            seq += 1400
            t += 0.008
        # A bare ACK back, which is what makes the ratio so lopsided.
        cap.add(BASE_TS + t, eth(1) / IP(src=dest, dst=host) /
                TCP(sport=dport, dport=sport, flags="A", ack=seq))
        t += rng.uniform(0.05, 0.14)

    cap.truth.append(GroundTruth(
        "EXFIL", host, dest, BASE_TS + start, BASE_TS + t,
        f"{sent / 1e6:.1f} MB outbound over {duration:.0f}s, minimal inbound"))
    return cap


# --- assembly ---------------------------------------------------------------

def build(seed: int, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    manifest: dict = {
        "seed": seed,
        "base_epoch": BASE_TS,
        "warning": (
            "Controlled synthetic demo traffic. Detection metrics computed against "
            "these captures show that the detectors fire correctly on known ground "
            "truth. They are NOT a measure of production detection accuracy."
        ),
        "captures": {},
    }

    def normal(tag: int) -> Capture:
        # Fresh RNG per capture so each file is reproducible on its own.
        return gen_normal(random.Random(seed + tag))

    attacks = [
        ("synflood.pcap", lambda r: gen_synflood(r), 101),
        ("portscan.pcap", lambda r: gen_portscan(r), 102),
        ("beacon.pcap", lambda r: gen_beacon(r), 103),
        ("dns_tunnel.pcap", lambda r: gen_dns_tunnel(r), 104),
        ("exfil.pcap", lambda r: gen_exfil(r), 105),
        ("udp_amp.pcap", lambda r: gen_udp_amplification(r), 106),
        ("tls_malware.pcap", lambda r: gen_tls_malware(r), 107),
    ]

    # Baseline capture: no attacks at all. The false-positive count measured on
    # this file is the number that matters most in review.
    base = normal(0)
    manifest["captures"]["normal.pcap"] = base.write(out_dir)
    print(f"  normal.pcap        {manifest['captures']['normal.pcap']['packets']:>7} packets")

    mixed = Capture("mixed.pcap")
    mixed.extend(normal(50))

    for name, make, tag in attacks:
        cap = Capture(name)
        cap.extend(normal(tag))
        attack = make(random.Random(seed + tag))
        cap.extend(attack)
        manifest["captures"][name] = cap.write(out_dir)
        print(f"  {name:<18} {manifest['captures'][name]['packets']:>7} packets")

        # The same attack, replayed into the combined demo capture.
        mixed.extend(make(random.Random(seed + tag)))

    manifest["captures"]["mixed.pcap"] = mixed.write(out_dir)
    print(f"  mixed.pcap         {manifest['captures']['mixed.pcap']['packets']:>7} packets")

    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate labelled demo captures")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=os.path.join("data", "pcaps"))
    ap.add_argument("--labels", default=os.path.join("data", "labels.json"))
    args = ap.parse_args()

    print(f"Generating captures (seed={args.seed}) -> {args.out}")
    manifest = build(args.seed, args.out)

    os.makedirs(os.path.dirname(args.labels) or ".", exist_ok=True)
    with open(args.labels, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    total = sum(c["packets"] for c in manifest["captures"].values())
    truths = sum(len(c["ground_truth"]) for c in manifest["captures"].values())
    print(f"\n{total:,} packets across {len(manifest['captures'])} captures")
    print(f"{truths} labelled attack episodes -> {args.labels}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

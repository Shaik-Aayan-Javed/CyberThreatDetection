"""Controlled demo traffic generator.

Produces the labelled captures the detectors are developed and measured against.
Every packet here is synthetic and every attack is one we placed ourselves,
which is the only reason precision/recall can be computed at all -- we know the
ground truth because we wrote it.

Read that as the caveat it is. These captures demonstrate that the detectors
fire correctly on known-good ground truth. They are NOT evidence of production
detection accuracy, and nothing built on them should be presented as such.

    python data/generate.py --seed 42 --out data/pcaps

Writes seven captures plus data/labels.json.
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

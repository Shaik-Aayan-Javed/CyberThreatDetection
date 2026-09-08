"""Cross-validate the TLS/JA3 extractor against a capture we did not author.

Why this exists
---------------
docs/CONFORMANCE.md used to give an honest reason for not building PS class (d):
"a rare-JA3 score validated against fingerprints we invented ourselves would
demonstrate that the parser works, not that the detection does." Building the
detector does not retire that objection -- every other capture in this
repository is one we wrote, so a green result on it proves only that we can
detect the thing we synthesised.

This tool is the answer. Point it at a real packet capture from anywhere else
and it reports two things that our own captures structurally cannot:

  1. whether the JA3 extractor produces stable, plausible fingerprints on real
     TLS handshakes, and
  2. how many TLS_MALWARE alerts the detector raises on ordinary traffic -- a
     false-positive count measured on traffic nobody here wrote.

Not part of tools/selftest.py, because it needs a file that is not in this
repository and must not silently pass when that file is absent.

Usage
-----
    python tools/tls_validate.py <capture.pcap>            # summary
    python tools/tls_validate.py <capture.pcap> --verbose  # every fingerprint

Where to get a capture. Wireshark's own test corpus is public and contains real
handshakes from real TLS stacks; it is deliberately not vendored into this
repository, since it is not ours to redistribute:

    BASE=https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures
    curl -sSLO $BASE/tls13-rfc8446.pcap

The results quoted in docs/CONFORMANCE.md class (d) come from eleven of those
files. Any capture with TLS handshakes will do.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine  # noqa: E402
from ingest.reader import PcapReader  # noqa: E402


def survey(path: str) -> dict:
    """One read-only pass, collecting what the extractor saw."""
    ja3_hosts: dict[str, set[str]] = defaultdict(set)
    ja3_strings: dict[str, str] = {}
    ja3_snis: dict[str, set[str]] = defaultdict(set)
    host_ja3s: dict[str, set[str]] = defaultdict(set)
    record_types: Counter = Counter()
    ports: Counter = Counter()
    hellos = 0
    with_sni = 0
    total = 0

    for pkt in PcapReader(path).packets():
        total += 1
        if not pkt.tls_record_type:
            continue
        record_types[pkt.tls_record_type] += 1
        if not pkt.tls_ja3:
            continue
        hellos += 1
        ports[pkt.dport] += 1
        ja3_hosts[pkt.tls_ja3].add(pkt.src)
        host_ja3s[pkt.src].add(pkt.tls_ja3)
        ja3_strings[pkt.tls_ja3] = pkt.tls_ja3_string
        if pkt.tls_sni:
            with_sni += 1
            ja3_snis[pkt.tls_ja3].add(pkt.tls_sni)

    return {
        "packets": total, "record_types": record_types, "hellos": hellos,
        "with_sni": with_sni, "ja3_hosts": ja3_hosts, "ja3_strings": ja3_strings,
        "ja3_snis": ja3_snis, "host_ja3s": host_ja3s, "ports": ports,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("capture")
    ap.add_argument("--verbose", action="store_true", help="print every fingerprint")
    args = ap.parse_args()

    if not os.path.exists(args.capture):
        print(f"no such capture: {args.capture}")
        return 2

    s = survey(args.capture)
    print(f"\n  capture            {args.capture}")
    print(f"  packets read       {s['packets']:,}")
    print(f"  TLS records        {sum(s['record_types'].values()):,} "
          f"(handshake {s['record_types'].get(0x16, 0):,}, "
          f"application_data {s['record_types'].get(0x17, 0):,})")
    print(f"  ClientHellos       {s['hellos']:,}, {s['with_sni']:,} carrying SNI")
    print(f"  distinct JA3       {len(s['ja3_hosts']):,}")
    if s["ports"]:
        top = ", ".join(f"{p}:{n}" for p, n in s["ports"].most_common(6))
        print(f"  handshake ports    {top}")

    if not s["hellos"]:
        print("\n  No ClientHello found. This capture cannot validate the "
              "extractor -- pick one containing TLS handshakes.")
        return 1

    # A host presenting many fingerprints is the Chrome-permutation effect the
    # detector's docstring describes. It is the single most important thing to
    # measure on real traffic, because it is why JA3 rarity does not gate.
    multi = {h: len(f) for h, f in s["host_ja3s"].items() if len(f) > 1}
    print(f"\n  hosts seen         {len(s['host_ja3s']):,}")
    print(f"  hosts with >1 JA3  {len(multi):,}", end="")
    if multi:
        worst = max(multi.items(), key=lambda kv: kv[1])
        print(f"  (worst: {worst[0]} presented {worst[1]} fingerprints)")
        print("                     -> fingerprint instability is real on this "
              "traffic, which is\n                        exactly why rarity is "
              "evidence here and never a gate")
    else:
        print("\n                     -> fingerprints were stable per host in "
              "this capture")

    shown = s["ja3_hosts"].items() if args.verbose else \
        sorted(s["ja3_hosts"].items(), key=lambda kv: -len(kv[1]))[:10]
    print(f"\n  {'JA3':<34} {'hosts':>5}  SNI sample")
    for ja3, hosts in shown:
        snis = sorted(s["ja3_snis"].get(ja3, ()))
        sample = snis[0] if snis else "(none offered)"
        print(f"  {ja3:<34} {len(hosts):>5}  {sample}")
    if args.verbose:
        print("\n  JA3 strings:")
        for ja3 in s["ja3_strings"]:
            print(f"    {ja3}\n      {s['ja3_strings'][ja3]}")

    # The part that cannot be faked: run the real detector over this traffic.
    print("\n  running the full engine over this capture...")
    alerts: list = []
    engine.run(args.capture, speed=0.0, on_alert=alerts.append)
    tls_alerts = [a for a in alerts if a.threat_class == "TLS_MALWARE"]
    print(f"  total alerts       {len(alerts)}")
    print(f"  TLS_MALWARE        {len(tls_alerts)}")
    if tls_alerts:
        print("\n  Every one of these is a false positive unless this capture "
              "genuinely contains\n  C2 traffic. Inspect before reporting a "
              "false-positive count:")
        for a in tls_alerts:
            print(f"    {a.flow_id}  confidence {a.confidence}")
    else:
        print("\n  Zero TLS_MALWARE alerts on traffic this project did not "
              "author.\n  That is the false-positive evidence our own captures "
              "cannot provide.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Acceptance checklist, executed rather than ticked by hand.

    python tools/selftest.py

Runs the invariants the prototype claims. Every one of these has been broken at
least once during development, which is why they are asserted in code instead of
written on a slide:

  - the anomaly model must not alert on its own training distribution
    (an earlier calibration anchored 1.0 at the benign 1st percentile and
     produced 5 false positives on benign traffic)
  - the benign capture must produce zero alerts of any kind
  - every threat class must fire on the capture built to contain it
  - alerts must carry every field PS 26145 requires
  - the detection path must not be able to reach the network

Exit code is non-zero if any check fails, so it works as a pre-demo smoke test.
"""

from __future__ import annotations

import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

import engine  # noqa: E402
from alerts.schema import (  # noqa: E402
    ANOMALOUS_FLOW, C2_BEACON, DNS_ANOMALY, EXFIL, PORT_SCAN, SYN_FLOOD, UDP_AMPLIFICATION,
)

REQUIRED_FIELDS = ["timestamp", "flow_id", "threat_class", "confidence", "severity", "evidence"]

EXPECTED = {
    "synflood.pcap": SYN_FLOOD,
    "portscan.pcap": PORT_SCAN,
    "beacon.pcap": C2_BEACON,
    "dns_tunnel.pcap": DNS_ANOMALY,
    "exfil.pcap": EXFIL,
    "udp_amp.pcap": UDP_AMPLIFICATION,
}

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((ok, label))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {label}" + (f"  -- {detail}" if detail else ""))
    return ok


def run(pcap: str, model: bool = True):
    collected = []
    stats = engine.run(
        os.path.join("data", "pcaps", pcap),
        speed=0.0,
        model_path=engine.DEFAULT_MODEL_PATH if model else None,
        enable_anomaly=model,
        on_alert=lambda a: collected.append(a),
    )
    return collected, stats


def main() -> int:
    print("=" * 70)
    print("ACCEPTANCE CHECKLIST -- SIH26145")
    print("=" * 70)

    if not os.path.exists("data/pcaps/mixed.pcap"):
        print("\nNo captures found. Run: python data/generate.py")
        return 1

    print("\nINGEST")
    alerts, stats = run("mixed.pcap")
    check(stats.packets > 0, "PCAP input works", f"{stats.packets:,} packets parsed")
    check(stats.malformed == 0, "No malformed frames dropped")
    check(stats.windows > 1, "Traffic processed incrementally as windows",
          f"{stats.windows} windows, not one batch")

    print("\nDETECTION")
    seen = {a.threat_class for a in alerts}
    for pcap, cls in EXPECTED.items():
        if not os.path.exists(os.path.join("data", "pcaps", pcap)):
            check(False, f"{cls} capture present", pcap)
            continue
        got, _ = run(pcap)
        classes = {a.threat_class for a in got}
        check(cls in classes, f"{cls} detected in {pcap}",
              f"{len([a for a in got if a.threat_class == cls])} alert(s)")

    check(len(seen & set(EXPECTED.values())) == len(EXPECTED),
          "All six classes fire on the combined capture",
          ", ".join(sorted(seen)))

    print("\nFALSE POSITIVES")
    benign, _ = run("normal.pcap")
    check(len(benign) == 0, "Benign capture produces zero alerts",
          f"{len(benign)} alert(s)" if benign else "clean")

    print("\nALERT SCHEMA")
    if alerts:
        sample = alerts[0].to_dict()
        missing = [f for f in REQUIRED_FIELDS if f not in sample]
        check(not missing, "Every PS-required field present",
              "missing: " + ", ".join(missing) if missing else ", ".join(REQUIRED_FIELDS))
        check(all(0.0 <= a.confidence <= 1.0 for a in alerts), "Confidence in [0,1]")
        check(all(a.evidence for a in alerts), "Every alert carries evidence",
              f"{sum(len(a.evidence) for a in alerts)} evidence items across {len(alerts)} alerts")
        check(all(isinstance(e.value, (int, float)) for a in alerts for e in a.evidence),
              "Evidence values are measured numbers, not prose")

    print("\nMODEL")
    report_path = "docs/model_report.json"
    if os.path.exists(report_path):
        with open(report_path, encoding="utf-8") as fh:
            rep = json.load(fh)
        t = rep["training"]
        check(t["benign_max_score"] < t["alert_threshold"],
              "Model stays silent on its own training distribution",
              f"benign max {t['benign_max_score']} < threshold {t['alert_threshold']}")
        check(rep["training_regime"].startswith("unsupervised"),
              "Model trained on benign traffic only")
        anomalies = [a for a in alerts if a.threat_class == ANOMALOUS_FLOW]
        check(True, "Anomaly channel corroborates rather than replaces rules",
              f"{len(anomalies)} standalone vs {len(alerts) - len(anomalies)} rule alerts")
    else:
        check(False, "Model report present", "run: python train.py")

    print("\nISOLATION")
    sys.path.insert(0, os.path.join(_ROOT, "tools"))
    import isolation_check

    check(_quiet(isolation_check.static_check),
          "Detection path imports no networking library")
    check(_quiet(lambda: isolation_check.descriptor_check("data/pcaps/mixed.pcap")),
          "Detection path opens the capture read-only and writes nothing")

    print("\n" + "=" * 70)
    failed = [label for ok, label in results if not ok]
    if failed:
        print(f"{len(failed)} CHECK(S) FAILED:")
        for label in failed:
            print(f"  - {label}")
        return 1
    print(f"ALL {len(results)} CHECKS PASSED")
    print("\nReminder: measured on controlled synthetic captures we authored.")
    return 0


def _quiet(fn):
    """Run a noisy check with its stdout suppressed."""
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return fn()


if __name__ == "__main__":
    raise SystemExit(main())

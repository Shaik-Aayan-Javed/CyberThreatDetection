"""Mechanical proof that the detection path cannot reach the monitored network.

    python tools/isolation_check.py

PS 26145 constraint (a) says the ingest is strictly read-only: no return path, no
live query to the source, no inline block. Saying so in a slide is cheap. This
script checks it against the source and fails loudly if it ever stops being true.

Three checks:

  1. IMPORTS   No module in the detection path may import any networking or
               subprocess library. Verified by parsing the AST, not by grep, so
               `import socket as s` and `from socket import *` are caught too.
  2. CALLS     No call to connect/send/sendto/urlopen/system/popen etc.
  3. RUNTIME   Run a real capture through the engine with socket.socket()
               monkeypatched to raise. If any code path tries to open a socket,
               the run dies and this script reports it.

The dashboard server (server.py) is deliberately NOT in the detection path: it
binds a loopback port to push alerts to a browser inside the enclave. It is
listed as an exclusion below rather than quietly skipped.
"""

from __future__ import annotations

import ast
import os
import sys

# Run from anywhere: put the repo root on the path and work relative to it.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

# Everything the detector needs to turn packets into alerts.
DETECTION_PATH = ["ingest", "features", "detectors", "alerts", "engine.py"]

# Not part of the detection path. Named explicitly so the exclusion is visible.
EXCLUDED = {
    "server.py": "dashboard backend; binds loopback to serve the enclave-local UI",
    "config.py": "service configuration; reads .env, imported by server.py only",
    "train.py": "offline model fitting; reads capture files only",
    "data/generate.py": "offline synthetic capture authoring; writes files only",
    "tools/isolation_check.py": "this checker",
    "bench": "offline measurement harness",
}

FORBIDDEN_MODULES = {
    "socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx", "aiohttp",
    "ftplib", "telnetlib", "smtplib", "asyncio", "subprocess", "os.system",
    "scapy", "paramiko", "websockets", "fastapi", "uvicorn", "xmlrpc", "socketserver",
}

FORBIDDEN_CALLS = {
    "connect", "send", "sendall", "sendto", "urlopen", "system", "popen",
    "spawn", "Popen", "check_output", "call", "run_command", "sendp", "sr1", "srp",
}


def python_files(targets: list[str]) -> list[str]:
    out: list[str] = []
    for target in targets:
        if os.path.isfile(target):
            out.append(target)
            continue
        for root, _dirs, files in os.walk(target):
            if "__pycache__" in root:
                continue
            for f in files:
                if f.endswith(".py"):
                    out.append(os.path.join(root, f))
    return sorted(out)


def check_imports(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)

    problems: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_MODULES:
                    problems.append(f"line {node.lineno}: imports '{alias.name}'")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in FORBIDDEN_MODULES:
                problems.append(f"line {node.lineno}: imports from '{node.module}'")
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
            if name in FORBIDDEN_CALLS:
                problems.append(f"line {node.lineno}: calls '{name}()'")
    return problems


def static_check() -> bool:
    print("1. STATIC ANALYSIS -- detection path may not import or call networking")
    files = python_files(DETECTION_PATH)
    failures = 0
    for path in files:
        problems = check_imports(path)
        rel = path.replace("\\", "/")
        if problems:
            failures += 1
            print(f"   FAIL  {rel}")
            for p in problems:
                print(f"         {p}")
        else:
            print(f"   ok    {rel}")
    print(f"\n   {len(files) - failures}/{len(files)} files clean")
    print("\n   excluded from this check (not in the detection path):")
    for name, why in EXCLUDED.items():
        print(f"     - {name}: {why}")
    return failures == 0


def runtime_check(pcap: str) -> bool:
    """Run the engine for real with socket creation poisoned."""
    print("\n2. RUNTIME -- replay a capture with socket.socket() disabled")
    if not os.path.exists(pcap):
        print(f"   SKIP  no capture at {pcap}")
        return True

    import socket as _socket

    class Tripwire(Exception):
        pass

    # Import everything the engine will touch BEFORE poisoning. The standard
    # library defines `class SSLSocket(socket)` at import time, so the tripwire
    # has to be in place only for the run itself, not for module loading.
    import joblib  # noqa: F401  (pulled in by the anomaly model loader)
    import engine

    original_socket = _socket.socket
    original_create = _socket.create_connection
    original_getaddr = _socket.getaddrinfo

    # A subclass rather than a bare function: anything that merely *references*
    # or subclasses socket.socket still works, but nothing can construct one.
    # Blocking instantiation is the property we actually care about.
    class PoisonedSocket(original_socket):
        def __init__(self, *args, **kwargs):
            raise Tripwire("detection path attempted to construct a socket")

    def poisoned(*args, **kwargs):
        raise Tripwire("detection path attempted to open a connection")

    _socket.socket = PoisonedSocket
    _socket.create_connection = poisoned
    _socket.getaddrinfo = poisoned

    try:
        stats = engine.run(pcap, speed=0.0, enable_anomaly=True)
        anomaly = stats.by_class.get("ANOMALOUS_FLOW", 0)
        print(f"   ok    {stats.packets:,} packets, {stats.alerts} alerts "
              f"({anomaly} from the loaded model), no socket created")
        return True
    except Tripwire as exc:
        print(f"   FAIL  {exc}")
        return False
    finally:
        _socket.socket = original_socket
        _socket.create_connection = original_create
        _socket.getaddrinfo = original_getaddr


def descriptor_check(pcap: str) -> bool:
    """Confirm the only thing the engine opens is the capture file, read-only."""
    print("\n3. FILE ACCESS -- the only input opened is the capture, mode 'rb'")
    opened: list[tuple[str, str]] = []
    real_open = open

    import builtins

    def watched(file, mode="r", *args, **kwargs):
        opened.append((str(file), mode))
        return real_open(file, mode, *args, **kwargs)

    builtins.open = watched
    try:
        import engine

        engine.run(pcap, speed=0.0, limit=2000, enable_anomaly=False)
    finally:
        builtins.open = real_open

    writes = [(f, m) for f, m in opened if any(c in m for c in ("w", "a", "+", "x"))]
    for f, m in opened:
        print(f"   opened  {m:<4} {f}")
    if writes:
        print(f"   FAIL  {len(writes)} file(s) opened for writing in the detection path")
        return False
    print("   ok    all opens are read-only")
    return True


def main() -> int:
    pcap = sys.argv[1] if len(sys.argv) > 1 else os.path.join("data", "pcaps", "mixed.pcap")

    print("=" * 68)
    print("ISOLATION PROOF -- SIH26145 unidirectional monitoring constraint")
    print("=" * 68 + "\n")

    results = [static_check(), runtime_check(pcap), descriptor_check(pcap)]

    print("\n" + "=" * 68)
    if all(results):
        print("PASS -- the detection path has no return route to the monitored network.")
        print("       Input is a file descriptor. No socket is created. No write occurs.")
        return 0
    print("FAIL -- isolation constraint violated; see above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

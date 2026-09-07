# The Unidirectional Constraint, and How It Is Proven

PS 26145 constraint (a): the monitoring enclave sees everything crossing the
link and has **no physical or protocol-level path back** into the production
network. The ingest is strictly read-only — no return path, no live query to the
source, no inline block.

Every project in this problem statement will *claim* this. The claim is free.
This document is about making it checkable, and the checks are executable:

```bash
python tools/isolation_check.py        # three layers, exits non-zero on violation
```

---

## Why this constraint shapes the whole design

A data diode is a physical guarantee, but it moves the risk rather than removing
it. The monitoring system is now the thing an attacker wants: it sees all the
traffic, and if it can be made to talk back — a DNS lookup, an HTTP callback, an
error report to a vendor endpoint — the diode has been defeated in software.

So the design rule is not "don't send anything on purpose". It is **the
detection path should not contain the machinery to send anything at all.** Then
the property survives a bug, a bad dependency, and a careless afternoon.

Three consequences run through the codebase:

| Constraint | Consequence in the code |
|---|---|
| No return path | Input is a file descriptor. `ingest/reader.py` takes a path and yields packets. There is no capture-from-interface mode to accidentally enable. |
| No live query | No enrichment, no reverse DNS, no threat-intel lookup, no reputation API. Every field in an alert is computed from bytes already on disk. |
| No inline block | The output is an alert. There is no action interface — nothing to call, nothing to configure, no code path that mutates the monitored network. |

The cost is real and worth stating plainly: we cannot resolve a domain, look up
an IP's reputation, or confirm a host is still live. The detectors have to
extract everything from traffic shape alone. That is why the evidence in an
alert is entirely measurements — rates, ratios, entropies — and never external
context.

---

## Layer 1 — Static: the detection path cannot import networking

`tools/isolation_check.py` parses every module in the detection path with
Python's `ast` module and rejects any import of a networking, transport, or
subprocess library, and any call to `connect` / `send` / `sendto` / `urlopen` /
`system` / `popen` / `Popen` / scapy's `sendp` / `sr1` / `srp`.

AST parsing, not `grep`. A text search for `import socket` misses
`import socket as s`, `from socket import *`, and `__import__("socket")`.
Parsing the syntax tree catches all three.

The detection path is:

```
ingest/   features/   detectors/   alerts/   engine.py
```

Everything else is named as an explicit exclusion in the checker source — not
quietly skipped:

| Excluded | Why it is not in the detection path |
|---|---|
| `server.py` | Dashboard backend. Binds **loopback** to serve the enclave-local UI. Pushes alerts outward to a browser; never toward the monitored link. |
| `config.py` | Service configuration. Reads `.env` for the dashboard's bind address and paths; imported by `server.py` only, never by the detection path. |
| `train.py` | Offline model fitting. Reads capture files. |
| `data/generate.py` | Offline capture authoring. Uses scapy to **write files** — `wrpcap`, never `sendp`. |
| `bench/` | Offline measurement harness. |
| `tools/isolation_check.py` | The checker itself. |

That table is the honest version of the claim. The system as a whole does open a
socket — a dashboard has to reach a browser. The point is that the socket lives
in a component architecturally downstream of detection, and cannot reach
upstream of it.

**Current result: every detection-path file clean.**

---

## Layer 2 — Runtime: replay with sockets poisoned

Static analysis proves the source does not ask for a socket. It does not prove a
dependency will not open one at runtime. So the second check replaces
`socket.socket` with a subclass whose constructor raises, along with
`create_connection` and `getaddrinfo`, and then runs a **real capture through
the real engine**, anomaly model loaded.

```
2. RUNTIME -- replay a capture with socket.socket() disabled
   ok    52,786 packets, 8 alerts (1 from the loaded model), no socket created
```

Two details that matter:

- It is a **subclass**, not a bare stub. The standard library executes
  `class SSLSocket(socket)` at import time, so anything that merely *references*
  or subclasses `socket.socket` still works — only *constructing* one fails.
  Blocking instantiation is the property we actually care about; stubbing the
  whole class would have made the test fail for the wrong reason.
- Imports happen **before** poisoning. Otherwise the test measures import
  behaviour rather than detection behaviour.

Full detection runs, including scikit-learn inference, with no socket
constructible anywhere in the process.

## Layer 3 — File access: read-only, and only the capture

The third check wraps `builtins.open`, runs the engine, and records every file
it touches with the mode it was opened in:

```
3. FILE ACCESS -- the only input opened is the capture, mode 'rb'
   opened  rb   data/pcaps/mixed.pcap
   ok    all opens are read-only
```

No write, no append, no `r+`. The engine does not modify its own input — which
also means a capture can be mounted read-only, and is, in the container below.

---

## Layer 4 — Container: no network interface at all

```powershell
docker build -t sih26145 .
docker run --rm --network none -v "${PWD}\data:/data:ro" sih26145 /data/pcaps/mixed.pcap --pretty
```

Run from PowerShell, not Git Bash — Git Bash rewrites `/data/...` into a Windows
path and the container will not find the capture.

`--network none` gives the container loopback and nothing else — no interface,
no DNS, no route. The capture is mounted `:ro`. The image installs
`requirements-detect.txt` only: numpy, scikit-learn, joblib. No web framework,
no scapy, no HTTP client is present *to* be called.

The run produces the same alerts as the host run. Identical output with the
network physically absent is the demonstration: the detection path never had a
network to lose.

This is the layer for anyone unmoved by source-code arguments — it requires
trusting nothing about our code, only about Docker's network namespaces.

---

## What this does *not* prove

Worth saying before someone asks:

- **It is a software argument about a hardware property.** A real deployment's
  guarantee comes from the diode. These checks prove our software does not
  *assume* a return path and will not quietly grow one; they cannot substitute
  for the physical link.
- **The dashboard is a socket, and it is on this machine.** In a real enclave
  the server binds an enclave-internal interface and the browser is an
  enclave-internal workstation. `--host` defaults to `127.0.0.1` so the lazy
  default is the safe one, but placement is a deployment decision, not a code
  guarantee.
- **A live-capture ingest would need this argument re-made.** Reading from an
  interface via a SPAN port is still passive, but it introduces a capture
  library into the detection path, and the layer-1 exclusion list would have to
  change. That is a deliberate future decision, not an oversight.
- **Model files are trusted input.** `models/anomaly.joblib` is loaded with
  joblib, which unpickles. It is built by our own `train.py` from our own
  captures. In a real deployment it should be signed and verified, and that is
  not implemented.

---

## Reproducing

```powershell
python tools/isolation_check.py                  # layers 1-3, exit code is the verdict
python tools/selftest.py                         # includes both isolation invariants
docker build -t sih26145 .                       # layer 4 -- rebuild after any code change
docker run --rm --network none -v "${PWD}\data:/data:ro" sih26145 /data/pcaps/mixed.pcap --pretty
```

`tools/selftest.py` runs the isolation invariants alongside the detection ones,
so an accidental `import requests` in a detector fails the acceptance checklist,
not just a document.

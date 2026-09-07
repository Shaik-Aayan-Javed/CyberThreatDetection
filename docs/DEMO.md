# Demo Script

Twelve steps, roughly 8 minutes, rehearsed in this order. Every command here has
been run end-to-end on the demo machine; nothing is typed for the first time in
front of a judge.

**Before the room:** `python tools/selftest.py` — if it does not print
`ALL 20 CHECKS PASSED`, fix that before anything else. Have two terminals open at
the repo root with `.venv` active, and a browser at `http://127.0.0.1:8000`
already loaded but not started.

---

## 0. The setup line (30 s, no slides)

> "A critical-infrastructure operator mirrors their gateway link into a
> monitoring enclave. The enclave sees every packet and has no route back — not
> a firewall rule, a physical diode. Everything we built has to work with that:
> we can watch, and we can never ask."

That framing earns you the isolation demo later. Say it before any code.

## 1. Show the captures exist and are reproducible (30 s)

```bash
python data/generate.py --seed 42
```

Do not run this live unless you have the time — it takes a while. Instead show
`data/labels.json` and say:

> "Seven captures, 190,363 packets, synthesised with scapy. We wrote the ground
> truth in the same pass, which is the only reason we can report recall at all.
> Seeded — same seed, same bytes."

**Say the caveat here, unprompted, before a judge says it for you:**

> "We generated this traffic. So our precision and recall show that the
> detectors fire on the behaviour they target and stay quiet otherwise. They are
> not production accuracy numbers and we are not presenting them as such."

That sentence is worth more than the F1 table. Do not skip it.

## 2. One command, five threat classes (60 s)

```bash
python engine.py data/pcaps/mixed.pcap --pretty
```

Scroll to the `SYN_FLOOD` alert and read the evidence lines out loud:

> "1,500 SYN/s against a 50/s threshold. Zero SYN/ACK for 7,500 SYN.
> 7,500 distinct sources, source entropy 12.87 bits — near-uniform, which is
> what spoofing looks like and what one aggressive host does not."

The point being made: **the alert is actionable without re-contacting the
network**, which is the whole constraint.

## 3. Nothing fires on benign traffic (20 s)

```bash
python engine.py data/pcaps/normal.pcap --quiet
```

`"alerts": 0` on 16,701 packets. This is the number an experienced judge asks
for, so volunteer it rather than waiting.

## 4. Start the dashboard (15 s)

```bash
python server.py
```

Browser is already open. Pick `mixed.pcap`, speed `20x`, **Start replay**.

## 5. Watch it stream (90 s)

Let it run. Alerts appear as the windows close, in capture-time order:
`DNS_ANOMALY`, `SYN_FLOOD`, `PORT_SCAN`, `ANOMALOUS_FLOW`, `C2_BEACON`, `EXFIL`.
Counters climb. While it runs:

> "This is the same `engine.run()` as the CLI. The `--speed` flag changes pacing,
> not the code path — the demo and the benchmark exercise the same pipeline.
> Detectors were written as stateful window consumers from the first commit, so
> there was never a batch-to-streaming rewrite."

## 6. Click an alert (60 s)

Click the `C2_BEACON`. The evidence panel shows value-vs-baseline bars:

> "Coefficient of variation of inter-arrival times: 0.046 against a threshold of
> 0.15. That is std over mean, so it is scale-free — the same threshold catches a
> 20-second beacon and a 300-second one. Packet-size variation zero. Fourteen
> contacts to a single destination over 257 seconds."

Then click the `SYN_FLOOD` to show a completely different evidence set. The
message: every detector explains itself in its own terms.

## 7. Where the model actually is (60 s)

Click `ANOMALOUS_FLOW`.

> "IsolationForest, 200 trees, ten features per host per window, trained on
> benign traffic only — it never saw an attack during fit, which mirrors what a
> passive monitor can actually collect. Mean ROC-AUC 0.997 on held-out attack
> captures."

Then, before anyone asks, the honest half:

> "AUC near 1.0 flatters it. On exfiltration the model scores 0.73 — ranked
> correctly, but inside the benign tail, so it would not alert on its own. The
> rule detector catches that one at 0.98 on directional evidence. The model
> catches high-volume anomalies, the rules catch low-and-slow, and neither alone
> is enough. That is measured, and it is in `docs/MODEL.md`."

## 8. Confidence is not a magic number (30 s)

Open `alerts/schema.py` at `confidence_from()`.

> "Confidence compounds observed-over-threshold ratios, with a square-root term
> so independent signals corroborate rather than multiply. There is no literal
> confidence value anywhere in any detector, and the self-test fails the build if
> an evidence value is ever prose instead of a number."

## 9. The isolation proof (90 s — the closer)

```bash
python tools/isolation_check.py
```

Three layers scroll past. Narrate:

> "One: every module in the detection path is AST-parsed and rejected if it
> imports a networking library. AST, not grep, so `import socket as s` is caught
> too. Two: we replay a real capture with `socket.socket` replaced by a class
> that raises on construction — 64,786 packets, 9 alerts, no socket created.
> Three: we wrap `open` for a whole run and the only file touched is the capture,
> mode `rb`."

Then the layer that requires trusting nothing about our code:

```powershell
docker run --rm --network none -v "${PWD}\data:/data:ro" sih26145 /data/pcaps/mixed.pcap
```

Run this one from **PowerShell**, not Git Bash — Git Bash rewrites `/data/...`
into a Windows path and the container will not find the capture. That failure
looks alarming and is not.

> "No network interface but loopback. Capture mounted read-only. Byte-identical
> alerts to the host run — same classes, flows, timestamps, confidences,
> evidence. The detection path never had a network to lose."

**Have the image pre-built.** `docker build` in front of judges is how you lose
two minutes.

## 10. Throughput (30 s)

Show `docs/throughput.json` rather than running the benchmark live:

> "Tens of thousands of packets per second, tens of megabits, median of three
> runs, full pipeline with the model loaded — comfortably above real time on
> one core of a laptop. The PS asks for measured throughput on stated
> hardware — that is the hardware, and that is our number. If asked for the
> exact multiple: check `docs/throughput.json` on the machine you're running,
> since it moves with what else is running on the box that day — re-run it
> live if a judge wants a number measured in front of them, not read off a
> file."

## 11. What we did not build, and why (45 s)

Do not let this be dragged out of you:

> "Five of the six threat classes complete, one absent — and I want to be
> precise about which. Class (a) names three shapes: SYN floods, spoofed
> floods, and UDP reflection/amplification. All three now fire — amplification
> is read at the victim, since a one-way tap only ever sees the
> reflector-to-victim leg, never the spoofed attacker-to-reflector leg, which
> never crosses this link anyway. Class (d), malware in encrypted sessions, is
> the one gap, and it's not built at all.
>
> One thing I want to correct before you ask it: (d) does *not* require
> decryption. It asks for JA3 fingerprints and packet-size sequences from
> metadata. So 'no decryption' is not our excuse — the honest reason is time,
> and that a JA3 rarity score measured against fingerprints we invented
> ourselves would prove our parser works, not that the detection works.
>
> No automated blocking, because blocking needs a return path and there isn't
> one. And no payload decryption anywhere, which is constraint (b) — that part
> we do comply with."

Volunteering the gaps is what makes the rest of the numbers credible.

## 12. The one-line close (15 s)

> "Streaming pipeline, six detectors and an unsupervised model, alerts that
> explain themselves, and an isolation constraint we prove four ways instead of
> asserting. Three days, and every number on these slides came from a run you
> can reproduce with a seed."

---

## Questions you will get, and the honest answers

**"Your F1 is 1.0. Isn't that suspicious?"**
Yes — and we said so before you asked. We wrote the traffic and the labels.
It shows the detectors fire correctly on known ground truth. Production traffic
would produce false positives and we have no data to estimate how many.

**"Would this work on real traffic?"**
The detectors would need baseline re-tuning on the target link, which is why
every threshold is a multiple of a learned EWMA baseline rather than a constant.
One caveat we should give rather than have found: each baseline is floored at a
fixed minimum, and on a quiet metric that floor is what is actually in effect —
so on our captures some "learned" thresholds are the constant. The parts most
likely to survive contact are SYN flood and port scan; the parts most likely to
need work are the DNS bigram corpus and the beacon jitter tolerance.

**"You claim six threat classes — do you?"**
No, and the README says so. Five complete, one absent. Class (a) now covers
all three of its named shapes — SYN floods, spoofed floods, and UDP
reflection/amplification; class (d), malware in encrypted sessions, is not
built. We would rather be counted at five honestly than six on a claim that
does not survive someone opening `detectors/`.

**"Are there known bugs?"**
Yes, and they are written down in `docs/DEFECTS.md` with cause and fix rather
than left for you to find. The one that matters most: the feature extractor
materialises every destination host as a synthetic "source" row with zero
packets, and those rows reach the anomaly model's training set. It does not
change the alerts we show you, but it means a training row is not always what
the word implies.

**"What if an attacker knows your thresholds?"**
Beaconing below CV 0.15 detection means adding jitter, which costs the attacker
reliability. Exfil below the ratio means going slower. Both are real evasions and
both raise the attacker's cost, which is the honest claim. The anomaly model
covers behaviour we did not write a rule for, but its floor is 20 packets per
window, so a truly low-and-slow actor is out of reach of both channels.

**"Why not deep learning?"**
No labelled attack data is obtainable in this deployment model — that is the
constraint, not a preference. Unsupervised is what the data supports, and we
built that. A packet-bytes network would also fail the question you would ask
next, which is "why did it fire".

**"Can it block?"**
No, and it must not be able to. Blocking requires a path back into the monitored
network, which is the exact thing the diode exists to remove.

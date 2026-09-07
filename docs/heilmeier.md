# The Heilmeier questions

Answers sized for the proposal and the two presentations. Numbers are from
`results/metrics.json`; regenerate with `python scripts/run_eval.py --stealth-sweep`.

---

### 1. What are you trying to do? Articulate your objectives using absolutely no jargon.

Factories, water plants and power utilities run on old industrial controllers
that were built decades ago with no security in them. They usually cannot be
patched or replaced — they are expensive, certified, and swapping one out means
shutting down production.

If an attacker takes over the operator's computer, they can tell the controller
to open a valve or run a pump, and it will do it, because doing what it is told
is the only thing it knows how to do.

I am building a small device that sits on the cable between the operator's
computer and the controller. It knows the basic physics of the process — how
fast a tank can fill, how fast it can drain — and it checks every command
against that. If a command would do something the physical process should not do,
it refuses it or shuts the process down safely.

### 2. How is it done today, and what are the limits of current practice?

Today's defences try to recognise the *attacker*: antivirus on the workstation,
network monitoring that learns what normal traffic looks like, and process-aware
intrusion detection that learns what normal plant behaviour looks like.
Commercial ICS security products work this way.

Two limits:

- **Any such detector is only as complete as its model of badness.** It has to
  have seen something like the attack before. An attacker who looks normal is
  invisible, and the detector needs continual updating.
- **They observe; they do not intervene.** They raise an alert. In a control room
  already saturated with alarms, an alert that arrives thirty seconds before a
  tank overflows is not a save.

There is also a deployment limit that matters more than either: the obvious place
to put a safety check is inside the controller, and that is the one place a real
plant cannot touch without recertification and downtime.

### 3. What is new in your approach, and why do you think it will be successful?

**What is new:** stop trying to identify the attack. Ask instead whether the
command is *physically sensible given where the process actually is*.

A tank cannot go from empty to full in a second. A pump running against a closed
outlet has to put the water somewhere. These are not policies an attacker can
argue with — they are the plant.

This is the same move the course's BFT++ example makes: rather than detect
malicious software, which is hard and never complete, lean on physics, inertia
and time scales, which hold regardless of what the attack turns out to be. This
project applies that reasoning one layer up, to the command stream.

**Why it should work:** the check does not depend on training data, does not
degrade as the attacker learns, and does not need updating when a new technique
appears. And because it sits inline, it can *refuse* a command rather than
merely note it.

**Where it should not work, stated up front:** physics only constrains outcomes.
An attack whose physical outcome is ordinary is invisible to this approach.
Question 8 quantifies exactly where that line falls.

### 4. Who cares? If you succeed, what difference will it make?

Utilities and manufacturers running legacy controllers they cannot patch. The
guard is a bolt-on: no controller firmware change, no HMI change, no vendor
approval. For a water utility running twenty-year-old equipment, that is often
the only class of security control they can realistically deploy.

The difference, measured: across seven attack scenarios, six caused physical
damage with the guard removed, and five of those six did no damage with it in
place — including one where the operator's level display was frozen by the
attacker throughout. The sixth is the stealthy-bias case in question 8.

The secondary contribution is the negative result. Quantifying the band where a
patient attacker still wins tells an asset owner what this class of defence does
and does not buy them, which is more useful than a detection percentage.

### 5. What are the risks?

| Risk | Status |
| --- | --- |
| **False alarms make it unusable.** A guard that blocks a legitimate emergency drain gets ripped out in a week. | **Addressed and measured.** 0 alarms across 5 benign transients; 0 of 181 benign writes blocked. The benign suite deliberately includes the cases most likely to trip a naive rule: startup at maximum fill rate, a drain toward the low limit, and a manual valve slam from 25% to 100%. |
| **Added latency breaks the control loop.** | **Addressed and measured.** p99 decision cost 125 µs, ~0.2% of a 100 ms scan; 170–280 µs added round-trip over real Modbus TCP. |
| **A stealthy attacker stays under the detector.** | **Real, quantified, not solved.** See question 8. |
| **The guard's model of the plant is wrong.** | **Partly addressed.** The guard runs on a model deliberately 4% off the simulated plant and all results hold. How much mismatch is tolerable is not yet characterised. |
| **Simulation flatters the design.** | **Open.** Evaluation is simulation-only; physical validation is future work. Stated as a limitation rather than hedged. |
| **Scope creep into "detect everything".** | **Controlled** by a threat model fixed up front (attacker owns the HMI, not the PLC firmware) and a rule set that stayed at five. |

### 6. How much will it cost? / How long will it take?

Roughly 120–150 hours across the term, alongside three other courses. Structured
so it degrades gracefully — a bad week costs a feature, not the project:

| Phase | Hours | Deliverable |
| --- | --- | --- |
| Testbed + plant simulation | 20 | tank model, verified against its closed-form equilibrium |
| Modbus interception | 20 | working proxy, commands flowing end to end |
| Rules + state estimator | 35 | R1–R5, Kalman filter, supervision |
| Attack + benign scenarios | 20 | 7 attacks, 5 benign transients, labelled |
| Evaluation + tuning | 25 | the three numbers, plus the stealth sweep |
| Writing (proposal, 5 progress reports, final, 2 talks) | 40–50 | — |

The guaranteed baseline — proxy plus range and rate checks — was reachable
early; the state estimator, R4/R5 and the stealth sweep were layered on top.

### 7. What are the midterm and final "exams" to check for success?

**Midterm:** commands flowing end to end through the proxy, with range and
rate-of-change rules working and a first detection/false-alarm number on a
handful of scenarios. Achieved.

**Final:** the three numbers, each with its counterfactual:

1. **Detection rate** — 85.7% (6/7 attack scenarios); **damage avoidance** 83.3%
   (5/6 attacks that caused damage unguarded).
2. **False-alarm rate** — 0% of benign scenarios; 0 of 181 benign writes blocked.
3. **Added latency** — p50 49 µs, p99 125 µs decision cost; 170–280 µs added
   round-trip on the wire.

Plus a characterised failure mode (question 8) and a reproducible harness: one
command regenerates every number and figure, and 178 tests pin the behaviour —
including two that guard the *evaluation* itself, so a benign scenario cannot
quietly drift into genuinely unsafe territory and score a correct trip as a false
alarm.

### 8. What is the honest limitation?

An attacker who biases the level reading *slowly enough* stays under the
detector's threshold and wins. Sweeping the ramp rate:

| Ramp rate | Detected | Outcome |
| --- | --- | --- |
| 0.2–1.0 mm/s | never | too slow to cause damage |
| **2.0 mm/s** | **never** | **attack succeeds** |
| 3.0–5.0 mm/s | after 147–246 s | detected, but too late |
| 10–50 mm/s | after 1–16 s | prevented |

There is a band — about 2–5 mm/s in this configuration — where the attack both
evades detection and does real damage.

This is not a tuning error and no threshold setting removes it. It is the
standard stealthy-attack result for residual-based detectors: lowering the
threshold to catch 2 mm/s trades directly against the 0% false-alarm rate, which
is the number that decides whether the guard stays installed. A residual detector
bounds an attacker's *rate*, not their eventual displacement.

Closing the band requires information this design does not have: a second,
physically independent measurement — a flow totaliser cross-checked against the
level, or a redundant transmitter on a separate path. That is the clearest
direction for future work, and it is a design change rather than a parameter
change.

Reporting a suite where every attack was caught would have meant the suite was
chosen to flatter the defence.

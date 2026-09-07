# Design notes

Companion to the README. This is the "why it is shaped this way" document: the
threat model it is built against, the assumption it relaxes, and the reasoning
behind each rule — including the two places where the obvious design is the
dangerous one.

---

## 1. The assumption being relaxed

The course material makes the point that good practicum problems come from
finding an assumption everyone accepts and relaxing it. The relevant one here:

> **Assumed:** to stop an attack on a control system, you must first identify
> the attack — the malware, the traffic anomaly, the operator who should not be
> logged in.

Every process-aware IDS in the CPS literature since roughly 2013 accepts some
form of this. So do the commercial products (Nozomi, Claroty): they learn a
baseline of normal traffic or normal process behaviour and alert on deviation.
The residual risk is the same in all of them — the detector is only as complete
as its model of *badness*, and an attacker who looks normal is invisible.

**Relaxed:** don't identify the attack at all. Enforce the physics of the
process as a policy, and let anything physically impossible be refused
regardless of who sent it or what it looks like.

The difference is not cosmetic. A traffic-anomaly detector asks "have I seen
this before?" A physics guard asks "can the plant do this?" The second question
has an answer that does not depend on training data, does not degrade as the
attacker learns, and does not need updating when a new technique appears.

The honest counterpart: physics only constrains *outcomes*. An attack whose
outcome is physically ordinary is invisible to this approach, and §6 is explicit
about where that bites.

## 2. Threat model

**The attacker has:**

- full control of the HMI or engineering workstation;
- the ability to send any Modbus write, at any rate, at any time;
- the ability to alter what the operator's screen displays, including replaying
  or biasing the level reading.

**The attacker does not have:**

- code execution on the PLC (no firmware modification);
- the ability to modify or bypass the guard;
- physical access to the instrumentation, actuators, or the wiring between the
  guard and the controller.

This is the standard "compromised operator station" position, and it is the one
where a bump-in-the-wire has authority: every command still has to cross the
guard to reach the controller. It is also the position most real ICS incidents
have started from.

**What is explicitly out of scope:** an attacker inside the PLC, an attacker who
can move the guard, and physical sabotage. If any of those hold, none of this
helps, and saying otherwise would overstate the result.

## 3. The process

A single water tank — the simplest process that still has the property the whole
design rests on: **inertia**. The level cannot jump. Whatever an attacker writes,
the tank still fills and drains at a rate set by geometry and gravity.

```
        pump (0-100%)
             |
             v
      +-------------+   <- overflow limit 1.80 m
      |             |
      |    level    |   tank: 1.0 m^2, 2.0 m tall
      |             |
      +-------------+   <- dry-out limit 0.20 m
             |
             v
        valve (0-100%)
```

Mass balance, with a linear pump and an orifice outlet:

```
A · dh/dt = Q_in − Q_out
Q_in  = pump_max_flow · (pump_position / 100)
Q_out = valve_coeff · (valve_position / 100) · √h
```

`pump_position` and `valve_position` are *actual* actuator positions, which chase
the commanded values at a finite slew rate. That distinction matters: a command
is a request, and the physical actuator takes seconds to honour it. Several
rules depend on it.

Two properties make this tractable to reason about and to test:

- The equilibrium has a closed form, `h_eq = (Q_in / (valve_coeff · valve_frac))²`,
  which the tests assert against rather than against recorded numbers.
- The dominant time constant (~40 s) is far longer than the 0.1 s scan period, so
  explicit Euler integration is accurate and the guard has real time to react.

**The guard's model is deliberately wrong.** It carries a +4% error on pump flow
and −4% on the valve coefficient, because a real engineer's datasheet model is
always a little off. A guard that only works against a perfect model would prove
nothing. Everything reported holds under that mismatch.

## 4. Architecture

```
                     +----------------------------+
   Modbus writes --> |  PhysicsGuard.check()      | --> allow / alarm / block
                     |    R1 R2 R3 R4 R5          |
                     +----------------------------+
                                 ^
                                 | state
                     +----------------------------+
   Modbus reads ---> |  TankEstimator             |
                     |    Kalman + CUSUM          |
                     |    lookahead, equilibrium  |
                     +----------------------------+
                                 |
                     +----------------------------+
   every scan -----> |  supervision -> trip       | --> protective write
                     +----------------------------+
```

`PhysicsGuard` is protocol-agnostic on purpose. The same object serves the
deterministic evaluation harness and the live Modbus proxy; nothing inside it
knows what a function code is. That split is what lets the evaluation be
reproducible to the sample — scheduler jitter on a loopback socket would
otherwise show up in the detection numbers — while the network cost is measured
separately, end to end.

Two entry points:

- `observe(Observation)` — every process read. Advances the filter, runs
  supervision. Once per scan.
- `check(Command) -> Verdict` — every write. Runs the rules. On the real-time
  path.

## 5. The rules, and why they are shaped that way

### R1 — range

Static equipment envelope. The cheapest rule and the one easiest to dismiss as
trivial, but it is the only thing between an attacker and `valve = 250%` on a
controller that accepts it because nobody ever told it not to.

One subtlety: the wire carries unsigned 16-bit words. `pump = −20%` arrives as
`0xFF38`. Read unsigned that is 65336 — rejected, but for the wrong reason, and
on a controller that interprets the word as signed it would be *obeyed*. The
register layer sign-extends before the rule sees it.

The legal setpoint ceiling (1.60 m) sits well below the overflow limit
(1.80 m) — by more than one reaction horizon of fill. Otherwise a perfectly
legitimate setpoint could itself provoke a supervision trip.

### R2 — actuation dynamics

Catches sequences that are individually legal and collectively impossible.
Cycling a valve open/closed at 5 Hz is a textbook water-hammer attack: every
command is in range, the level barely moves, and the damage is mechanical. The
signature is in the *sequence*, so R2 counts large direction reversals in a
sliding window, plus a write-rate check (a human clicks; a script hammers).

Deliberately **not** a simple rate-of-change limit on the command. An operator
slamming a valve from 25% to 100% in one write during an emergency drain is
legitimate and must not be blocked — see `emergency_drain` in the benign suite.
Only *repeated reversals* are implausible.

### R3 — inertia lookahead

The intellectual core. Integrates the model forward over the reaction horizon
under the candidate command and checks the safety envelope.

**The design trap.** The obvious formulation — "does the predicted trajectory
violate the envelope?" — is dangerous. When a tank is already heading for an
overflow, *every* trajectory violates the envelope, including the one where the
operator opens the outlet. That guard blocks the corrective action in precisely
the moment it matters most, and is worse than having no guard at all.

R3 instead compares the candidate against the counterfactual of holding the
current command, and objects only when the candidate is **strictly worse** in
the direction of the violation. A command that improves the trajectory is always
allowed, however dire the situation.
(`test_r3_never_blocks_a_corrective_command` pins this.)

### R4 — sensor/model consistency

A Kalman residual with a two-sided CUSUM. Catches false data injection and
replay: the reported level has stopped obeying physics, so the *sensor* — not
the command — is what can no longer be trusted.

Three decisions that took measurement to get right:

**Low gain.** The filter is tuned as a *detector*, not a tracker
(`process_noise_std` 0.001 against `sensor_noise_std` 0.005, giving a steady-state
gain of ~0.18). Tuned the other way — the natural instinct — it absorbs an
injected bias within two samples and the residual vanishes before the CUSUM can
accumulate. The first version of this rule was silent against a 0.30 m offset for
exactly that reason.

**Latching.** The alarm stays up until acknowledged. Without the latch it clears
itself the moment the filter finishes absorbing the offset — which is precisely
when the operator is most thoroughly deceived.

**Open-loop on alarm.** Once the transmitter is caught lying, the estimator
stops taking corrections from it and dead reckons on the model. This is what
keeps R3 and supervision usable *during* a spoofing attack instead of blinding
them. In `replay_overflow` the screen is frozen at 0.95 m while the tank is at
1.13 m; the guard's estimate tracks the truth and trips.

### R5 — post-trip lockout

Closes the gap that makes a trip worthless. When the guard shuts the pump to stop
an overflow, the compromised HMI is still there and still writing — one second
later it re-sends `pump = 100` and the trip is undone. Cycling that way, the
guard alarms forever while the tank fills anyway. This was observed, not
predicted: the stealthy-bias runs kept overflowing despite the guard tripping.

So while a trip is latched, a pump or valve command is refused if the resulting
pair would come to rest **past the limit that tripped**. The test uses only the
commands — never the level reading — via the closed-form equilibrium, which is
what lets it hold up when the transmitter is the thing under attack.

**The second design trap.** The tidier-looking rule is "equilibrium must be
inside the envelope, full stop". That version forbids draining the tank after an
overflow trip: pump shut against an open outlet settles at empty, so every
recovery action an operator could take is refused and the process is stranded at
the level that caused the trip. Only the aggravating direction is locked out.
(`test_lockout_still_allows_draining_after_an_overflow_trip` pins this.)

### Continuous supervision

Not a rule but a loop, and necessary because vetting commands as they arrive is
not enough: an attacker sends one legal command and waits. Supervision re-checks
the *standing order* against the envelope every scan, with a longer horizon (5 s
vs 3 s) because a standing order has to be caught while it is still correctable.

Edge-triggered **per direction**. Shutting the pump to stop an overflow leaves an
open outlet, which is itself a dry-out configuration; a single boolean latch
would suppress that second alarm and the guard would empty the tank it had just
saved. This was a real bug, caught by the sweep.

## 6. Evaluation design

Every scenario runs twice — enforcing, and watching but powerless. Without that
counterfactual, "no overflow occurred" is unfalsifiable.

Detection is scored at two levels because either alone misleads:

- **Command level** gives precision/recall and the false-positive rate, but
  flatters a guard facing an attack made of many writes (a 200-write flood
  scores 200 true positives for one idea) and punishes one that catches a
  two-write attack via its consequence.
- **Scenario level** asks what an asset owner cares about: was it caught, and
  was it caught early enough to prevent damage.

The headline number is **damage avoidance** — of the attacks that actually broke
something with the guard removed, how many did the guard stop. Plain
"prevention rate" gives free credit for stopping attacks that were never going
to do harm.

The false-positive rate is computed on **benign episodes only**. A benign-labelled
write inside an attack scenario is usually the compromised controller being
refused by the lockout, which is the guard working. Both numbers are reported.

Two guardrails on the suite itself, as tests:

- benign scenarios must stay inside the safety envelope *with the guard
  disabled* — otherwise a badly parameterised "normal" case genuinely overflows,
  the guard correctly trips, and the correct trip is scored as a false alarm
  (this happened, with `pump_trip_restart`);
- enough attacks must still cause damage unguarded, so "prevented" keeps meaning
  something.

## 7. Latency

The course material is blunt that security must not break a control loop's
real-time properties, so this is a first-class result.

| | mean | p50 | p99 |
| --- | --- | --- | --- |
| R1 range | 0.6 µs | 0.5 | 1.1 |
| R2 dynamics | 1.8 µs | 1.6 | 3.2 |
| **R3 prediction** | **38.7 µs** | **36.3** | **71.9** |
| R4 consistency | 0.2 µs | 0.2 | 0.2 |
| R5 lockout | 3.1 µs | 3.0 | 7.4 |
| `check()` (all rules) | 65.5 µs | 59.4 | 134.1 |
| `observe()` (per scan) | 35.5 µs | 32.0 | 68.3 |

Worst case per scan is ~202 µs, **0.20% of the 100 ms scan period**. R3
dominates, and its cost is linear in the horizon (3 s → 19 µs, 30 s → 171 µs),
which makes the detection-vs-latency trade explicit and tunable.

The binding cost in a real deployment is not the rules but the network hop: the
end-to-end demo measures 170–280 µs median added round-trip over Modbus TCP.

## 8. Known limitations

Beyond the stealthy-bias band documented in the README:

1. **Simulation only.** No physical hardware validation.
2. **One process.** Rule *shapes* generalise; parameters do not. Deriving them
   for a new process is engineering work.
3. **Bounded model mismatch.** 4% is tolerated; a grossly wrong model would
   produce both false alarms and misses. How much mismatch is tolerable is not
   yet characterised — a sweep over model error would be a natural next result.
4. **Single sensor.** R4's detection floor is set by the noise on one
   transmitter. Redundant or physically independent measurement is the principled
   fix and the clearest direction for future work.
5. **No authentication.** The guard is orthogonal to identity: it does not care
   who sent a command. That is the point, but it means it complements rather than
   replaces access control.
6. **Modbus TCP only.** The guard core is protocol-agnostic; only the adapter is
   Modbus-specific, so DNP3 or EtherNet/IP would need a new adapter and no rule
   changes.

## 9. Related work

The process-aware IDS line in CPS security (Cárdenas et al. on residual-based
detection and its stealthy-attack limits; Urbina et al. on bounding attacker
impact under such detectors) is the closest prior work, and the stealthy-bias
result here reproduces their central finding in miniature: a residual detector
bounds an attacker's *rate*, not their eventual displacement.

The distinction this project draws is between *detecting anomalies in the
process* and *enforcing physics as an admission policy on commands*. The first
observes and alerts; the second sits inline and refuses. R3's counterfactual
comparison and R5's sensor-free equilibrium test are both artefacts of being
inline — they exist because the guard has to decide whether to *pass* a command,
not merely whether to flag it after the fact.

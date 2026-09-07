# OTGuard — a physics-plausibility guard for OT/ICS command streams

> Legacy industrial controllers can't be patched, so instead of detecting
> attackers, enforce the laws of physics on the commands they send — a
> bump-in-the-wire that refuses anything the real world couldn't do.

CS 6727 Cybersecurity Practicum · Georgia Tech

---

## The problem

Water plants, factories and utilities run on PLCs designed decades ago with no
security in them. You usually cannot patch or replace them: they are expensive,
certified, and taking them offline means stopping production. If an attacker
reaches the operator's workstation, they can tell the controller *"open the valve
fully"* or *"raise the setpoint to maximum"*, and the controller will obey,
because obeying is the only thing it knows how to do.

Most defences try to recognise the attacker — signatures, traffic anomalies,
malware. Attackers keep going around them, and any such detector is only ever as
complete as its last update.

## The idea

Ask a different question. Not *"is this command from a bad actor?"* but **"is
this command physically sensible right now?"**

A tank cannot go from empty to full in a second. A pump cannot fill against a
closed outlet without the level going somewhere. These constraints are not
policy — they are the plant, and an attacker on the HMI cannot renegotiate them.

So OTGuard sits on the wire between the operator station and the controller.
Every command passes through it. It keeps a running estimate of the physical
state, and asks whether the command in front of it is consistent with that
state. If not, it refuses the command or trips the process to a safe
configuration.

This is the same move as the BFT++ work the course uses as its example: rather
than detect malice — which is hard and never complete — lean on physics, inertia
and time scales, which hold regardless of what the attack turns out to be.

## Results

Seven attack scenarios and five benign operating transients. Every scenario is
run **twice** — once with the guard enforcing, once with it watching but
powerless — because "no overflow occurred" means nothing without the
counterfactual.

| Metric | Result |
| --- | --- |
| Attack detection rate | **85.7%** (6/7 scenarios) |
| Damage avoidance | **83.3%** (5/6 attacks that caused damage unguarded) |
| False-alarm rate | **0%** (0/5 benign scenarios raised any alarm) |
| Benign writes blocked | **0** of 181 |
| Added decision latency | **p50 49 µs, p99 125 µs** — 0.2% of a 100 ms scan |
| Added network round-trip | **170–280 µs** median, measured over real Modbus TCP |

| Scenario | Kind | Detected | Damage | Without guard | Rules |
| --- | --- | --- | --- | --- | --- |
| `out_of_envelope` | attack | yes | no | damaged | R1 |
| `overflow` | attack | yes | no | damaged | R3 |
| `dryout` | attack | yes | no | damaged | R3 |
| `water_hammer` | attack | yes | no | damaged | R2 |
| `command_flood` | attack | yes | no | safe | R2 |
| `replay_overflow` | attack | yes | no | damaged | R3, R4, R5 |
| `stealthy_bias` | attack | **no** | **yes** | damaged | — |
| `startup` | normal | no | no | safe | — |
| `shutdown` | normal | no | no | safe | — |
| `emergency_drain` | normal | no | no | safe | — |
| `setpoint_change` | normal | no | no | safe | — |
| `pump_trip_restart` | normal | no | no | safe | — |

**The one miss is deliberate, and it is the most interesting result.** See
[What doesn't work](#what-doesnt-work).

## Quickstart

```bash
pip install -r requirements.txt

python scripts/run_eval.py --stealth-sweep   # full evaluation + figures
python scripts/run_demo.py --attack overflow # live attack over real Modbus TCP
python scripts/bench_latency.py              # where the time goes
python -m pytest                             # 93 tests
```

`run_eval.py` writes `results/metrics.json` and a trace figure per scenario to
`results/plots/`.

The demo output is the short version of the whole project:

```
                              no guard     through guard
----------------------------------------------------------------------
final true level (m)             2.000             1.660
overflowed                        True             False
protective trips                     -                 1

Added round-trip through the guard: median 282 us over ... transactions
Result: damage prevented
```

## How it works

```
 HMI / engineering workstation          <-- assumed compromised
              |
              v   Modbus TCP
    +---------------------+
    |      OTGuard        |  R1..R5 + state estimator + supervision
    +---------------------+
              |
              v   Modbus TCP
        legacy PLC             <-- unmodified, uncertified-for-security, obeys anything
              |
         water tank            <-- inlet pump, outlet valve, level transmitter
```

Nothing changes on either side. The controller keeps its firmware and its
certification; the HMI keeps its screens. For an asset owner running
twenty-year-old equipment, that is often the only class of control they can
actually deploy.

### The rules

| Rule | Enforces | Catches |
| --- | --- | --- |
| **R1** range | the equipment's static rating | raw out-of-range writes (`valve = 250%`) |
| **R2** dynamics | plausible actuation *sequences* | water hammer, write floods |
| **R3** prediction | inertia lookahead against the safety envelope | legal commands with illegal consequences |
| **R4** consistency | the level reading must obey physics | false data injection, replay |
| **R5** lockout | no re-establishing a tripped condition | a compromised HMI undoing the trip |

Three design decisions carry most of the weight:

**R3 compares against a counterfactual, not against the envelope.** The naive
version — "does the predicted trajectory violate the limit?" — rejects the
*corrective* command too, because when a tank is already heading for an overflow
every trajectory looks bad. That guard would be worse than no guard in exactly
the moment it matters. R3 instead compares the candidate command against holding
the current one, and objects only when the candidate is strictly worse. Opening
the outlet on a filling tank is always allowed.

**Supervision runs every scan, not just on commands.** A guard that only vets
commands as they arrive is bypassed by sending one legal command and waiting.
So the guard re-checks the *standing order* on every scan cycle and can trip the
actuators itself.

**Trips latch, and R4 stops trusting the sensor.** A trip the HMI can undo is
not a protection — the compromised station simply re-sends the command a second
later. And once the transmitter is caught disagreeing with physics, the estimator
stops taking corrections from it and dead reckons on the model instead. In the
replay scenario the operator's screen is frozen at 0.95 m while the tank is
really at 1.13 m and climbing; the guard tracks the truth and trips anyway.

## What doesn't work

The `stealthy_bias` attack ramps a false offset onto the level reading slowly
enough to stay under R4's detection threshold. It is in the suite on purpose. A
result where every attack is caught usually means the attacks were chosen to
flatter the defence.

`--stealth-sweep` maps the whole rate axis, and the shape is the finding:

| Ramp rate | Detected after | Peak level, guarded | Outcome |
| --- | --- | --- | --- |
| 0.2–1.0 mm/s | never | 1.38–1.67 m | too slow to do damage |
| **2.0 mm/s** | **never** | **2.00 m** | **attack succeeds** |
| 3.0–5.0 mm/s | 147–246 s | 2.00 m | detected, but too late |
| 10–50 mm/s | 1–16 s | 1.31–1.43 m | prevented |

There is a band — roughly 2–5 mm/s here — where the attack both evades the
detector and does real damage. This is not a tuning error, and no threshold
fixes it: it is the standard stealthy-attack result for any residual-based
detector. Tightening the threshold to catch 2 mm/s trades directly against the
0% false-alarm rate, which is the number that decides whether operators leave
the guard installed.

Closing that band needs information the current design does not have — a second,
physically independent measurement (a flow totaliser cross-checking the level, a
redundant transmitter on a separate path). That is the clearest direction for
future work.

### Other limitations, stated plainly

- **Simulation only.** Evaluation is against a simulated tank, not a real plant.
  Validation on physical hardware is future work.
- **One process, one model.** The guard's rules are specific to a single-tank
  process. The rule *shapes* generalise; the parameters do not, and deriving
  them for a new process is engineering work, not configuration.
- **Model mismatch is bounded, not absent.** The guard's model is deliberately
  4% off the simulated plant, which it tolerates. A grossly wrong model would
  produce both false alarms and misses.
- **The attacker cannot reach the guard.** If they can modify the guard or the
  wiring, none of this holds.

## Repository layout

```
src/otguard/
  config.py            typed configuration, strict about unknown keys
  sim/water_tank.py    the plant: mass balance, actuator slew, sensor noise
  guard/
    types.py           Command / Observation / Verdict
    estimator.py       Kalman filter, CUSUM, lookahead, equilibrium
    rules.py           R1..R5
    guard.py           decision engine, supervision, trips, lockout
  scenarios/           labelled attacks and benign transients (ground truth)
  eval/                harness, metrics, figures, CLI
  modbus/
    protocol.py        MBAP/PDU framing
    plc_server.py      simulated PLC (obeys anything, by design)
    proxy.py           the bump-in-the-wire
config/default.yaml    every tunable number, with the reasoning
scripts/               run_eval.py, run_demo.py, bench_latency.py
tests/                 93 tests
docs/                  design.md, heilmeier.md, threat model
```

## Documentation

- [`docs/design.md`](docs/design.md) — threat model, architecture, and why each
  rule is shaped the way it is
- [`docs/heilmeier.md`](docs/heilmeier.md) — the Heilmeier questions
- [`config/default.yaml`](config/default.yaml) — the parameters, each with the
  reasoning for its value

## License

MIT — see [LICENSE](LICENSE).

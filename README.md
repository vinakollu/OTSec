# OTGuard

A program that sits on the cable between the computer an operator uses and the
machine that runs a factory. It reads every command going past and asks one
question: could the real world actually do this right now? If the answer is no,
the command doesn't get through.

CS 6727 Cybersecurity Practicum, Georgia Tech.

## Start with a bathtub

Picture a bathtub with a tap at the top and a plug at the bottom. You don't turn
the tap yourself. You type instructions to a small computer, and that computer
moves the tap and the plug for you. In a factory this small computer is called a
controller, and the screen you type into is called the operator station.

Now someone sneaks onto your operator station and types their own instruction:
tap fully on, plug shut.

Look at what they typed. The tap can go to 100 percent, so that part is fine.
The plug can close all the way, so that part is fine too. Nothing is broken.
Nothing looks odd. There's no virus, no strange file, no weird network traffic.
A few minutes later the water is on the floor.

That's the problem in one picture. The dangerous thing wasn't a strange command.
It was an ordinary command sent at the wrong moment.

Swap the bathtub for a water treatment plant, a chemical reactor, or a power
station, and the floor is a town.

## Why you can't just fix the controller

The obvious answer is to teach the controller to refuse silly instructions. In a
real plant you usually can't.

Controllers in service today were designed decades ago, and many have no
security built in at all. They're expensive. They're certified, meaning a safety
authority signed a piece of paper saying this exact version of this exact device
is approved, and changing the software voids that. Turning one off to upgrade it
means stopping production, which costs money every minute.

So the one place you'd most like to put a safety check is the one place a real
plant can't touch.

## Why catching the attacker doesn't work either

Most security products try to spot the attacker. Antivirus looks for known bad
software. Network monitors learn what normal traffic looks like and flag traffic
that looks different. Process monitors learn what a normal plant looks like and
flag a plant that behaves differently.

Two things go wrong with all of them.

The first is that they need to have seen something like the attack before, or at
least seen enough normal behaviour to call this abnormal. An attacker who looks
normal is invisible. Our bathtub attacker looks completely normal, because
everything they typed was a legal instruction.

The second is that these tools watch and then tell someone. They raise an alarm.
In a control room that already has hundreds of alarms going, an alarm that
arrives thirty seconds before the tank overflows is not a rescue.

## The idea

Stop asking whether the command came from a bad person. Ask whether the command
makes physical sense given where the plant actually is at this second.

A tank can't go from empty to full in one second. A pump running against a
closed outlet has to put the water somewhere. Water has weight, valves take
seconds to move, and none of that changes because an attacker wants it to. These
aren't rules anybody wrote down and can therefore argue with. They're the plant.

So OTGuard sits on the wire, watches every command, keeps its own running guess
of the water level, and checks each command against that guess. If a command
would push the plant somewhere it shouldn't go, the guard refuses it or shuts
the process down safely.

Nothing changes on either side. The controller keeps its software and its
certificate. The operator station keeps its screens. For a water utility running
twenty-year-old equipment, that's often the only kind of security they can
actually install.

```
 operator station               assumed to be under the attacker's control
        |
        v   Modbus TCP
   +----------+
   | OTGuard  |               five rules, a state estimator, supervision
   +----------+
        |
        v   Modbus TCP
   controller                  unchanged, obeys anything it is told
        |
    water tank                 pump, outlet valve, level sensor
```

Modbus TCP is just the language controllers speak over a network cable. It's
about as simple as it sounds: write this number into slot 3, read the number in
slot 7. There's no password in it and no signature, which is part of why this
project exists.

## The tank we test against

Everything is measured against a simulated tank, written in Python, with numbers
chosen to behave like real equipment.

The tank is 1 square metre across and 2 metres tall. The pump can push in 0.05
cubic metres of water per second at full speed, and takes 5 seconds to go from
stopped to full speed, because a real motor drive ramps rather than jumping. The
outlet valve takes about 4 seconds to travel from shut to open. The level sensor
is accurate to about 5 millimetres, and its reading wobbles, because real sensors
wobble.

Damage means one of two things. Above 1.80 metres the tank overflows. Below 0.20
metres the pump runs dry and wrecks itself.

The controller updates ten times a second. That 100 millisecond gap matters
later: it's the budget the guard has to make a decision without slowing the plant
down.

One detail is there on purpose. The guard's idea of the tank is deliberately
wrong by 4 percent. It thinks the pump is slightly stronger than it is and the
valve slightly weaker. A real engineer works from a datasheet, and a datasheet is
never exactly the machine in front of you. A guard that only worked with a
perfect model would fall over on its first day in a real plant.

## The five rules

R1, range, checks the command against what the equipment is physically rated
for. A valve cannot be 250 percent open. This catches the clumsiest attacks and
almost nothing else.

R2, dynamics, looks at sequences rather than single commands. Slamming a valve
shut and open four times in three seconds isn't a person operating a plant. It's
a pressure surge, called water hammer, that can split a pipe. R2 also notices
someone writing ten or more commands a second, which no operator station does.

R3, prediction, is the one that catches the bathtub attack. The guard takes the
command, runs its model of the tank forward three seconds, and looks at where the
water ends up. Tap on and plug shut are both fine as instructions. Together, from
1.4 metres, they end at the ceiling.

R4, consistency, checks the sensor against physics. If the reading says the level
is holding steady while the pump has been running full for a minute with the
outlet shut, one of those two things is a lie. Since water doesn't negotiate, the
reading is the lie.

R5, lockout, stops an attacker from undoing a shutdown. Once the guard has
tripped the process to safety, commands that would recreate the same dangerous
condition stay refused until a human clears it.

## Three decisions that do most of the work

R3 compares against doing nothing, not against the limit. The obvious version of
R3 asks whether the predicted path crosses the danger line. That version is worse
than having no guard at all, and here's why. When a tank is already heading for an
overflow, every possible future crosses the line, including the one where the
operator opens the outlet to save it. The obvious guard blocks the rescue. So R3
compares the proposed command against simply holding whatever command is already
in force, and objects only when the proposal is strictly worse. Opening the drain
on a filling tank is always allowed.

The guard rechecks the standing order ten times a second, not just when a command
arrives. A guard that only inspects commands as they arrive has an easy bypass:
send one legal command and wait. The tank fills on its own, no further traffic
required. So the guard re-evaluates the currently held command on every cycle and
can drive the pump and valve to safety by itself.

Once the sensor is caught lying, the guard stops believing it. After R4 catches a
reading that contradicts physics, the estimator stops taking corrections from the
sensor and runs on its model alone. In the replay attack the operator's screen is
frozen at 0.95 metres while the water is really at 1.13 metres and rising. The
guard tracks the real number and trips.

## What happened when we tested it

Seven attacks and five ordinary operating situations. Every one runs twice: once
with the guard enforcing, and once with the guard watching but unable to act. The
second run is the control. Without it, "the tank didn't overflow" proves nothing,
because maybe it was never going to.

| Metric | Result |
| --- | --- |
| Attacks detected | 6 of 7 |
| Attacks that damaged the tank without the guard, and didn't with it | 5 of 6 |
| Ordinary situations that raised a false alarm | 0 of 5 |
| Ordinary commands wrongly blocked | 0 of 181 |

| Scenario | Kind | Detected | Damage | Without the guard | Rules |
| --- | --- | --- | --- | --- | --- |
| `out_of_envelope` | attack | yes | no | damaged | R1 |
| `overflow` | attack | yes | no | damaged | R3 |
| `dryout` | attack | yes | no | damaged | R3 |
| `water_hammer` | attack | yes | no | damaged | R2 |
| `command_flood` | attack | yes | no | safe | R2 |
| `replay_overflow` | attack | yes | no | damaged | R3, R4, R5 |
| `stealthy_bias` | attack | no | yes | damaged | none |
| `startup` | normal | no | no | safe | none |
| `shutdown` | normal | no | no | safe | none |
| `emergency_drain` | normal | no | no | safe | none |
| `setpoint_change` | normal | no | no | safe | none |
| `pump_trip_restart` | normal | no | no | safe | none |

The false alarm number deserves a note about arithmetic. Zero of 181 counts only
the commands inside the five ordinary scenarios. Counted across the whole test
suite the number is 2 of 320, and those two are lockout refusals that happen
inside attack scenarios after the guard has already tripped. Both numbers are
published, because either one on its own tells half the story.

Speed: the guard takes roughly 50 microseconds to decide on a command, and under
130 microseconds in the slowest 1 percent of cases. That's a fraction of one
percent of the 100 millisecond control cycle. Measured end to end over a real
network socket, the proxy adds a few hundred microseconds to a round trip. Timing
numbers move by 10 or 20 percent between machines and between runs, so treat
these as the scale rather than as constants, and re-measure on your own hardware
with `scripts/bench_latency.py`.

## The attack that gets through

`stealthy_bias` is in the suite on purpose. It does not attack the tank. It
attacks the guard's belief about the tank, by adding a slowly growing lie to the
level reading, slowly enough that R4 never sees a contradiction big enough to
report.

A test suite where every attack is caught usually means the attacks were picked
to make the defence look good. So instead of one attack, the sweep runs the same
attack at many different speeds and reports where the guard stops winning.

| Lie added per second | Caught after | Highest level reached | What happened |
| --- | --- | --- | --- |
| 0.2 to 1.0 mm | never | 1.38 to 1.67 m | too slow to do damage |
| 2.0 mm | never | 2.00 m | the attack wins |
| 3.0 to 5.0 mm | 147 to 246 s | 2.00 m | caught, too late |
| 10 to 50 mm | 1 to 16 s | 1.31 to 1.43 m | stopped |

There's a band, roughly 2 to 5 millimetres per second, where the attacker is both
invisible and effective. This isn't a tuning mistake and no threshold setting
fixes it. Making R4 twitchier to catch 2 millimetres per second trades directly
against the zero false alarms, and the false alarm rate is what decides whether
operators leave the guard switched on or rip it out.

Closing that band needs information this design doesn't have: a second
measurement of the same physical thing, arriving by a different physical path.
That sentence is why the rest of this project exists.

## What the numbers don't prove

The tank is simulated. No physical controller has been in the loop, so the
proxy's behaviour against real vendor hardware is untested.

The attacks and the rules were written by the same person, and some thresholds
were set after looking at the attacks. That makes 6 of 7 a description of this
suite, not a prediction about attacks nobody has thought of yet. The sweeps carry
more weight than the counts, because a boundary says something a sample can't.

The rules are shaped for one tank. The shapes generalise. The numbers don't, and
working them out for a new process is engineering, not configuration.

If an attacker can reach the guard itself, or rewire around it, none of this
holds.

## The battery site

The tank work ended on a limitation it couldn't fix from inside: a slow enough
lie on one sensor is undetectable when that sensor is the only thing measuring
the quantity. Fixing it needs a second, physically independent measurement, which
is a design change and not a setting.

A grid battery site has three of them. The power leaving the site is measured by
the revenue meter the utility bills against, by adding up what each battery unit
reports about itself, and by the current transformers the protection relay uses.
Different hardware, different cables, different vendors, different protocols, all
measuring the same power. The site already pays for that redundancy for billing
and for protection. Using it to catch a liar costs nothing extra.

So the guard also runs against a site modelled on a utility-scale battery
installation: sixteen units of 1.927 MW each (30.8 MW and 62 MWh in total) behind
a 20 MW export limit and a 25 MVA transformer, with a site controller, protection
relays, a revenue meter, redundant switching, SCADA, a jump server and a
firewall, speaking Modbus TCP, DNP3, GOOSE, PRP and REST.

Eight rules, numbered B1 to B8, cover capability, energy balance, power balance,
ramp rate, temperature, cross-source agreement, interlocks, and where a command
came from.

| Metric | Result |
| --- | --- |
| Attacks detected | 13 of 13 |
| Attacks that damaged the site without the guard, and didn't with it | 5 of 5 |
| Ordinary situations clean | 7 of 7 |
| Ordinary commands wrongly blocked | 0 of 3783 |
| Lying measurement named correctly | 1 of 1 |

Across the whole suite, 1200 of 7831 commands labelled ordinary are flagged.
Almost all of them are the site controller's own commands inside attack
scenarios, refused after the guard had established that a unit was lying about
its own state. Both denominators are published for the same reason as before.

### Why three meters beat one

The interesting experiment biases the revenue meter at different speeds and asks
not how long detection takes, but how far the reading has moved by the time it's
caught.

| Bias growth (mW/s) | Caught after | Lie accumulated by then | Source named |
| --- | --- | --- | --- |
| 0.20 | 1309 s | 262 kW | revenue meter |
| 1.00 | 298 s | 298 kW | revenue meter |
| 10.0 | 46 s | 455 kW | revenue meter |
| 50.0 | 14 s | 725 kW | revenue meter |
| 1.00, voting switched off | never | | |

The third column is the result. It stays between 262 and 725 kW while the attack
speed changes by a factor of 250, and the slowest attacker is caught having moved
the reading the least. Comparing three independent measurements bounds how far an
attacker can shift a number, where the tank's detector could only bound how fast.
The last row repeats the attack with voting disabled and reproduces the tank's
blind spot exactly, which is what makes the comparison mean anything. Biasing the
protection relay instead makes the guard name the relay, so the vote identifies
which instrument is lying rather than only noticing a disagreement.

### Where the site guard fails

`stealth_dispatch_creep` is in the suite because it defeats the design. B3
objects only when a command makes an existing excursion worse, which is exactly
what stops it blocking an operator's recovery, and is also a way in.

| Increase per unit per 20 s | Caught after | Peak MW over the export limit |
| --- | --- | --- |
| 0.002 MW | never | 0.00 |
| 0.005 MW | never | 2.77 |
| 0.010 MW | 1300 s | 4.76 |
| 0.200 MW | 160 s | 0.04 |

At 0.005 MW per unit the attack is never caught and leaves the site exporting
2.77 MW more than its connection agreement allows. Even in the band that is
caught, the site gets 4.8 MW over the limit first. Same character as the tank's
2 millimetre band.

13 of 13 is not a claim about attacks in general. It's thirteen scenarios written
by the same person who wrote the rules, several thresholds set after looking at
them, and one deliberate failure.

The threat model matters more here than anywhere else in the project. An attacker
who controls the field devices themselves can make all three measurements agree
on the same lie, and B6 fails completely. The DNP3 and GOOSE frames are byte
exact and tested against known values, but they run over an in-process network
segment rather than real layer 2, because raw Ethernet needs root. Full detail is
in [`docs/bess-design.md`](docs/bess-design.md).

## Running it yourself

```bash
pip install -r requirements.txt
```

Nothing else needs installing. The scripts add `src/` to the path themselves, and
figures are drawn without a display.

```bash
python scripts/run_demo.py --attack overflow --duration 25
python scripts/run_eval.py --stealth-sweep
python scripts/run_site_eval.py --sweeps
python scripts/bench_latency.py
python -m pytest
```

`run_demo.py` is the short version of the whole project. It stands up the
simulated controller, the guard and an attacker driving a stock `pymodbus`
client, then runs one attack twice, once through the guard and once straight at
the controller:

```
                              no guard     through guard
----------------------------------------------------------------------
final true level (m)             2.000             1.660
overflowed                        True             False
protective trips                     -                 1

Result: damage prevented
```

Two things to know before you run it. The attack needs at least 20 seconds to
reach the overflow limit, so a shorter `--duration` prints "no damage in either
run" and proves nothing. And a single-scenario site run overwrites
`results/site_metrics.json` with partial data, so pass `--out` somewhere else
when you only want one scenario.

Approximate times on a laptop: the demo takes twice whatever `--duration` you
give it, `run_eval.py` takes 6 seconds, `run_site_eval.py` takes 95 seconds and
about 4 minutes with `--sweeps`, and the test suite takes a minute for 177 tests
and one expected failure. Everything under `results/` is regenerated by these
commands and is not tracked by git.

## How the code is laid out

```
src/otguard/
  config.py            typed configuration, strict about unknown keys
  sim/water_tank.py    the tank: mass balance, actuator travel, sensor noise
  guard/
    types.py           Command, Observation, Verdict
    estimator.py       Kalman filter, CUSUM, lookahead, equilibrium
    rules.py           R1 to R5
    guard.py           decisions, supervision, trips, lockout
    site_estimator.py  per-unit charge and temperature estimates, voting
    site_rules.py      B1 to B8
    site_guard.py      site decisions, supervision, curtailment
  bess/                battery model, fleet, connection point, three meters
  site/topology.py     IEC 62443 zones and conduits over the Purdue levels
  protocols/
    dnp3.py            framing with the 0x3D65 CRC, CROB, select-before-operate
    goose.py           IEC 61850 frames, stNum and sqNum handling, subscriber
    prp.py             redundancy control trailer, dual-LAN mismatch
    rest.py            site controller API, roles and tokens
  scenarios/           labelled attacks and ordinary situations
  eval/                harness, metrics, sweeps, figures, command line
  modbus/
    protocol.py        MBAP and PDU framing
    plc_server.py      simulated controller, obeys anything by design
    proxy.py           the guard on the wire
config/default.yaml    every tunable number, with the reasoning next to it
scripts/               run_eval.py, run_site_eval.py, run_demo.py, bench_latency.py
tests/                 177 tests and one expected failure
docs/                  design.md, bess-design.md, heilmeier.md
```

## More detail

[`docs/design.md`](docs/design.md) covers the threat model, the architecture, and
why each rule is shaped the way it is.

[`docs/bess-design.md`](docs/bess-design.md) covers the battery site: physics,
rules B1 to B8, the protocols, the results, and where it fails.

[`docs/heilmeier.md`](docs/heilmeier.md) answers the Heilmeier questions.

[`config/default.yaml`](config/default.yaml) holds the parameters, each with the
reasoning for its value written beside it.

## License

MIT. See [LICENSE](LICENSE).

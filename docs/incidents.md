# Attacks that actually happened

Every scenario in the original suite was written from the design outward. Each
one exists to exercise a rule, which is the right way to build a test suite and
a weak way to argue that the design matters: the attacks and the rules were
written by the same person on the same afternoon, and sixty of sixty is what
you would expect from that arrangement whether the idea was any good or not.

This part of the project works in the other direction. It starts from twelve
publicly reported incidents and campaigns, and asks of each one whether this
guard would have been in a position to do anything about it.

The answer is no for four of the twelve, and the reasons are more useful than
the hit rate.

## Three reasons an incident is outside what this guard can do

The first is where the commands came from. A bump-in-the-wire watches one
conduit. Stuxnet executed on the controllers themselves, so its rotor commands
never crossed a network link that a guard could have been installed on. That is
not a gap in the rules. The rules recognise the pattern perfectly well — the
scenario derived from it is detected and its damage is prevented — and the
incident is still something this device would have been blind to, because of
where the device sits. A coverage table that scored Stuxnet as a hit on the
strength of that scenario would be making a claim about geometry it has not
earned.

The second is whether there was a command at all. Night Dragon and Havex are
both in every ICS security syllabus and neither manipulated a process. Night
Dragon took documents. Havex inventoried OPC servers and reported what it
found. A plausibility guard judges commands against physics; when nothing is
commanded there is nothing to judge, and the correct behaviour is to forward
the traffic and contribute nothing. The Havex row is worth having precisely
because of that: the OPC UA experiment includes a reconnaissance episode that
browses and reads the entire address space, and it is scored as traffic the
guard must not refuse rather than as an attack it caught.

The third is whether the public account says enough to model. Germany's federal
information security office reported in 2014 that a steel mill was reached
through its office network and that a blast furnace could not be brought into a
controlled shutdown. It does not say what was written, to which device, or
whether the furnace failed to shut down because of a command that was issued, a
command that was suppressed, or an interlock that was disabled. Those are three
different scenarios with three different results. Building one and putting this
incident's name on it would be presenting an invention as evidence, so the row
stays empty and says why.

## How the catalogue is wired up

Each incident points at evidence that already exists somewhere in the project
rather than carrying a copy of its own. A row names a tank scenario, a
storage-site scenario, a sender and receiver pair from the device matrix, or a
cell of the OPC UA experiment, and `scripts/run_incidents.py` runs whichever of
those it names.

That is deliberate. The alternative is a parallel attack library with
incident names on it, which drifts from the original within a week and then
reports two different numbers for the same attack. The cost of the mapping
approach is that a renamed scenario silently breaks a row, so the tests check
every reference resolves.

Two scenarios had to be added, because nothing in the suite had their shape.

`stuxnet_overspeed_replay` runs the overdrive in bursts with quiet periods
between them, behind a transmitter replaying its own earlier recording rather
than holding a constant. Both details matter to the defence. A CUSUM relaxes
during the quiet periods, a latched alarm may have been acknowledged, and no
single burst is long enough to do the damage on its own. A replayed recording
has the right noise and the right small movements, where a frozen reading is a
conspicuous thing to show an operator.

`setpoint_overdose` is one write, to one address, that moves no actuator. It
raises the level set-point above the top of the tank, and the plant's own
control loop does everything harmful that follows, correctly, against a target
it was handed. It is the cheapest harmful write there is, and nothing reasoning
about rate, sequence, volume or credentials can see anything wrong with it.
What catches it is that the number is above the top of the tank.

## Results

| | |
| --- | --- |
| Incidents in the catalogue | 12 |
| A plausibility guard is the right control for | 8 |
| Of those, an attack of that shape was objected to | 8 of 8 |
| By a physics rule | 7 |
| By the access policy alone | 1 |
| Of those, damage occurred without the guard | 8 |
| Of those, the guard prevented it | 8 of 8 |
| Pieces of evidence run | 21 |

The last two rows of the detection block are kept apart for the reason
`docs/devices.md` already gives. An access check that stops an attack is worth
having and is not evidence for the claim this project makes, and reporting the
two together inflates the number that matters. The one incident carried by the
access policy alone is the Unitronics intrusion, where the attack is a write
from a device the guard has never heard of and there is nothing physical to
reason about until it lands.

| Incident | Mechanism | Where it sat | What this project found |
| --- | --- | --- | --- |
| Maroochy Water Services, 2000 | process command | crosses the guard | prevented, 5.3 s of warning |
| Stuxnet, 2010 | process command | below the guard | pattern recognised, out of reach |
| Night Dragon, 2011 | enterprise intrusion | beside the guard | not modelled |
| Havex / Dragonfly, 2014 | reconnaissance | crosses the guard | forwarded, nothing claimed |
| German steel mill, 2014 | not publicly disclosed | not established | not modelled |
| Ukraine distribution outage, 2015 | process command | crosses the guard | prevented, 5.3 s of warning |
| Industroyer, 2016 | process command | crosses the guard | prevented |
| Triton / Trisis, 2017 | process command | crosses the guard | prevented |
| Oldsmar water treatment, 2021 | process command | crosses the guard | prevented, 33.1 s of warning |
| Industroyer2, 2022 | process command | crosses the guard | prevented, 60.0 s of warning |
| Pipedream, 2022 | process command | crosses the guard | prevented |
| Unitronics in water utilities, 2023 | process command | crosses the guard | prevented, by the access policy |

The warning times are seconds between the guard's first objection and the
moment the process left its envelope in the counterfactual run. Where a row has
none, the evidence for it came from the device matrix or the OPC UA
experiment, neither of which records that quantity.

Stuxnet is the row to look at twice. The scenario derived from it is detected
and its damage is prevented, and the incident is still out of scope, because
the commands that did the damage ran on the controllers and never crossed a
link a bump-in-the-wire could have been on. Reading that row as a hit is the
mistake this whole table exists to make harder.

## Where the facts in this file came from

Every account here is public reporting as the author understood it, and none of
it has been checked against primary sources. The dates and the mechanisms are
the parts to trust least. Where reporting is disputed the catalogue says so:
the Oldsmar row records that later reporting raised the possibility that the
set-point change was a plant employee's own action rather than an intrusion,
and the attribution is not settled.

Every number in every scenario is this project's own. The tank is 1.8 m tall
because this project made it 1.8 m tall. None of these are an incident's
measured parameters, and a detection here means that an attack of that shape
was objected to on a conduit the guard sits on. It is not a claim that the
incident would have been stopped.

## Reproducing

```bash
python scripts/run_incidents.py              # tank and storage-site evidence
python scripts/run_incidents.py --matrix     # and the device-matrix pairs
python scripts/run_incidents.py --only oldsmar triton
python -m pytest tests/test_incidents.py
```

The OPC UA rows are read from `results/opcua/opcua_metrics.json` when
`scripts/run_opcua.py` has been run, and say so when it has not. Those episodes
cost a secure-channel handshake each and re-running them for every row that
points at one would make this the slowest thing in the project.

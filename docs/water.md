# The water treatment works

A conventional surface-water treatment works, from a river intake to the
mains, with the whole OT environment around it: twenty-two devices in six
zones, five controllers, nine analysers, and one conduit with the guard on it.
It runs live in a browser, it narrates itself in ordinary English, and nine
attacks taken from real incidents can be launched at it while it runs.

```bash
python scripts/run_water.py
```

The page opens on `http://127.0.0.1:8701/`. Nothing else needs installing and
nothing is fetched from the network.

## Why a works rather than another tank

The storage tank in this project has one level, one pump and one valve, and its
rules can be checked against a single number. That makes it a good first
example and a poor second one. A treatment works has properties a tank does not:

**The dangerous quantity is a chemical dose, not a position.** A pump is open or
shut. A dose is a number, and the number that protects the public is stored in
the same controller an attacker is already writing to. The attack at Oldsmar in
2021 was a dosing set-point raised about a hundredfold; nothing moved, no alarm
was configured to care, and an operator happened to be watching the screen.

**The measurement arrives minutes after the command.** Chlorine injected now
reaches the residual analyser two and a half minutes later, and coagulant takes
four. For that long, a works that has stopped disinfecting reads exactly like a
works that has not. An instrument-watching defence has nothing to say during
the interval in which the decision was made.

**The quantity that decides whether the water is safe is not measured at all.**
CT — residual chlorine multiplied by the time the water spent in the contact
tank — is the figure that says whether the bacteria are dead. No instrument on
the site reads it. It has to be computed from a chlorine analyser, a level
gauge and a flow meter, which means an attacker who moves any one of the three
moves it, and an attacker who opens the high-lift pumps collapses it while
every instrument on the plant still reads normal.

That last one is the clearest case in the project for a guard that models the
process rather than inspecting traffic. There is no packet to flag and no
reading to disbelieve. There is only arithmetic that nobody on the site is
doing.

## The process

Eight stages, in order: raw water intake, coagulation, flocculation,
sedimentation, filtration, disinfection, the clearwell, and distribution.

The model is a first-order one and the figures are the ones a works this size
runs at — about 1,100 m³/h of production, raw water near 3.5 NTU, a settled
turbidity around 0.5 NTU, filtered water under 0.05 NTU, a chlorine residual of
about 0.5 mg/L leaving the works, and three quarters of an hour of contact. It
is a simulation for a guard to reason about, not a design tool.

Three parts of it earn their place, and each was wrong at first in a way that
flattered the guard:

A **filter fed water a clarifier should have cleaned** stops removing before it
stops passing. The first version let filter efficiency hold near its design
figure however dirty the arriving water was, so cutting the coagulant produced
0.26 NTU — untidy, legal and survivable. Sand beds are sized for what a working
clarifier hands them; several times that and particles go through. With the
overload term, cutting the coagulant breaches the turbidity limit and, because
all that mud consumes chlorine, breaks disinfection as well.

**Pumps cannot send water the clearwell does not have.** Taking the outflow from
pump speed alone meant an empty tank went on reporting a steady flow to the
town, which hid the one consequence that matters.

**High-lift pumps lose suction.** Below about 1.3 m the column breaks and the
pumps pass air, so the mains do not hold at two thirds of normal while the tank
empties. Without that, draining the clearwell looked survivable.

## The OT environment

Six zones, numbered on the Purdue model and quoted the way IEC 62443 talks
about zones and conduits.

| Zone | Level | What is in it |
|---|---|---|
| enterprise | 4 | billing, email, the vendor's remote support |
| dmz | 3.5 | the jump server everything from outside must pass through |
| operations | 3 | the historian and the engineering workstation |
| supervisory | 2 | the SCADA servers and the operator stations |
| control | 1 | five PLCs and an RTU |
| field | 0 | analysers, meters, dose pumps and drives |

Six conduits join them and exactly one is guarded: supervisory to control, over
Modbus/TCP. That is the bump in the wire. Everything above it is out of the
guard's sight and everything below it is out of its reach, which is the
honest position for a device of this kind and the reason the vendor's jump
server is drawn on the page at all.

## The rules

Eight, evaluated in the order `W1 W8 W6 W2 W7 W5 W4 W3`. Every one of them
blocks: a works has no rule whose honest answer is "let it through but mention
it".

| | Asks |
|---|---|
| W1 | is this value even in range for this piece of equipment? |
| W2 | is this dose sensible for the amount and quality of water? |
| W3 | where does the water end up if this command sticks? |
| W4 | do the instruments that measure this agree with each other? |
| W5 | does what goes in match what comes out and what is stored? |
| W6 | has the plant been put into a hold that only a person can clear? |
| W7 | is the plant in a state where this command is allowed at all? |
| W8 | should this device, in this part of the network, be writing this? |

W2 is the Oldsmar rule, and the part worth noticing is that it checks the
*ceiling* as well as the dose. The maximum dose is a writable register, so an
attacker raises it and then doses through the gap. A guard that reads the
ceiling as a constraint is checking the attacker's own work. W2 judges a
proposed ceiling against what the chemical does to a person, which is not
stored in the plant.

W3 carries two horizons, and the reason is the two speeds in the process. A
dose reaches the analyser in under three minutes; a clearwell this size takes
over an hour to empty. A single ten-minute prediction cannot see the second
one, and opening the high-lift pumps right up read as harmless until the rule
grew a water-balance clause that asks about the rate rather than the level at
some horizon.

## What the page shows

Six headline figures, then the process schematic with live values at every
stage, then all fourteen measurements as a meter list — one row each, with the
bar drawn against that measurement's own limits and the limit marks on the
track. Four charts carry recent history with the allowed range shaded. The
network panel lists the zones, their devices and the conduits.

Commands are drawn. Each one leaves the device that sent it, travels down to
the guard, and either crosses it and reaches its stage or stops on the line
with a cross through it. A refused command never gets past the guard on the
screen, which is the whole point of drawing it that way.

The narration column is the part written for somebody who has never seen a
treatment works. It names the device in words rather than by tag, says what was
asked for, says what happened, and gives the reason in the same sentence:

> The operator's screen in the control room asked to set the chlorine dose to
> 9.5 mg/L.
> OTGuard refused it. A chlorine dose of 9.5 mg/L into water needing 0.59 mg/L
> would leave 8.91 mg/L in the mains, above the 4 mg/L limit.

Every status on the page carries a glyph and a word as well as a colour, both
colour sets were run through a palette validator against their own surface, and
there is a light theme that is chosen rather than flipped.

## The attacks

Nine, each the shape of something that has happened.

| | What it does |
|---|---|
| Chemical overdose | raises the chlorine ceiling, then doses through it — Oldsmar's shape |
| Caustic overdose | the same with caustic soda, which is what Oldsmar's attacker touched |
| Quietly stop disinfecting | turns the dose down; every instrument reads normal for minutes |
| Steal the contact time | opens the high-lift pumps so water rushes through the contact tank |
| Let the mud through | cuts the coagulant; the filters cannot cover for a failed clarifier |
| Empty the treated water tank | stops the intake, leaves the town pumps running |
| Blind the alarms first | moves the turbidity alarm point so nothing will ever trigger |
| Freeze the chlorine reading | holds the analyser at its last good value while the dose is cut |
| A command from outside | a write from the vendor's remote support connection |

Each one is tested twice, and both halves have to hold. With the guard watching
only, the attack must actually damage the water — an attack that does nothing
unguarded proves nothing about the guard that blocked it. With the guard
enforcing, no harm may occur and at least one command must have been refused,
so that the saving cannot be the plant quietly recovering on its own.

The plant's own control stands down while an attack runs. Leaving it going
meant the legitimate loop overwrote the attacker's set-point within seconds and
the guard took credit for a save its victim had already made.

## The one number that matters most

Nine hundred simulated seconds of the works running itself — dosing paced to
flow and turbidity, pumps trimmed to hold the clearwell — produce fifty-five
commands across the guard and **none refused**. That is the figure to read
first. A guard that objects to a plant operating normally has not made the
works safer, it has taken it off line, and every attack it then catches is
beside the point.

Getting there took two fixes worth recording, because both made the guard look
better than it was. The cross-instrument rule compared the dose with the
residual as though water went straight from the injector to the analyser; at a
forty-minute contact time about four tenths of the free chlorine is gone by
then, so a compliant works read as a tampered one. And the rule fired on
whatever command happened to be passing, so an instrument disagreement about
chlorine refused a turbidity alarm setting. It now speaks only to the commands
whose safety is decided on the reading it is doubting.

## What is modelled and what is not

The twenty-two devices, six zones and six conduits are a model of the network,
not twenty-two listening servers. The tank demonstration
(`scripts/run_live_demo.py`) is the one that runs real Modbus over real
sockets, and it is the right place to look for wire-level behaviour.

What is not modelled is the guard. Every verdict on the page is the rule set
reaching a decision about the water the simulation is actually moving, over the
same forward model the rules use, and the clock runs at ×30 so that a contact
tank that takes forty minutes to fill can be watched in a few seconds.

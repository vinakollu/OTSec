# OTGuard

A program that sits on the cable between the computer an operator uses and the
machine that runs a plant. It reads every command going past and asks one
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
of the plant's state, and checks each command against that guess. If a command
would push the plant somewhere it shouldn't go, the guard refuses it or drives
the process to safety itself.

Nothing changes on either side. The controller keeps its software and its
certificate. The operator station keeps its screens. For a water utility running
twenty-year-old equipment, that's often the only kind of security they can
actually install.

```
 operator station               assumed to be under the attacker's control
        |
        v   Modbus TCP
   +----------+
   | OTGuard  |               rules, a state estimator, supervision
   +----------+
        |
        v   Modbus TCP
   controller                  unchanged, obeys anything it is told
        |
      plant                    pumps, valves, dose injectors, sensors
```

Modbus TCP is just the language controllers speak over a network cable. It's
about as simple as it sounds: write this number into slot 3, read the number in
slot 7. There's no password in it and no signature, which is part of why this
project exists.

## What's in here

Four plants. Three of them form a chain, where each is in the project because
the one before it ran out of road.

| Plant | What it is | Why it's here |
| --- | --- | --- |
| [Storage tank](#the-storage-tank) | one tank, a pump, an outlet valve | the base case, and the blind spot that motivates the two after it |
| [Battery site](#the-battery-site) | sixteen units, 30.8 MW, three independent meters | what a second measurement of the same quantity buys, and what takes it away again |
| [Treatment works](#the-water-treatment-works) | eight stages, twenty-two devices, six zones | what to do when the quantity that decides public safety has no instrument on it |
| [Device matrix](#other-senders-other-receivers) | five kinds of sender against three kinds of receiver | a separate question: one station writing to one PLC is not what a plant looks like |

And two experiments that test the idea rather than the implementation. One
takes [twelve reported incidents](#attacks-that-actually-happened) and asks
which of them this device could have spoken to, including the four where the
answer is no. The other runs the same attacks over OPC UA at three security
modes and measures [what encryption costs the guard](#what-encryption-costs-the-guard).

Every section ends with where that piece fails, because a defence with no
stated failure mode has not been tested, only demonstrated. The counts, with
the caveats left in their own sections:

| | Objected to | Damage prevented | Ordinary commands refused |
| --- | --- | --- | --- |
| Storage tank | 6 of 7 | 5 of 6 | 0 of 181 |
| Battery site | 13 of 13 | 5 of 5 | 0 of 3783 |
| Treatment works | 9 of 9 | 9 of 9 | 0 of 57 |
| Device matrix | 60 of 60 | 38 of 38 | 0 of 336 |
| Incident-derived | 8 of 8 | 8 of 8 | — |

Those denominators are not comparable with each other and the counts are not
predictions. Each section says what its own numbers mean and what they leave
out.

## The storage tank

Everything started against a simulated tank, written in Python, with numbers
chosen to behave like real equipment.

The tank is 1 square metre across and 2 metres tall. The pump can push in 0.05
cubic metres of water per second at full speed, and takes 5 seconds to go from
stopped to full speed, because a real motor drive ramps rather than jumping. The
outlet valve takes about 4 seconds to travel from shut to open. The level sensor
is accurate to about 5 millimetres, and its reading wobbles, because real sensors
wobble. Above 1.80 metres the tank overflows; below 0.20 metres the pump runs dry
and wrecks itself.

The controller updates ten times a second. That 100 millisecond gap matters
later: it's the budget the guard has to make a decision without slowing the plant
down.

One detail is there on purpose. The guard's idea of the tank is deliberately
wrong by 4 percent. It thinks the pump is slightly stronger than it is and the
valve slightly weaker. A real engineer works from a datasheet, and a datasheet is
never exactly the machine in front of you. A guard that only worked with a
perfect model would fall over on its first day in a real plant.

### The five rules

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

### Three decisions that do most of the work

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

### What happened

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

| Scenario | Kind | Detected | Damage | Without the guard | Rules fired |
| --- | --- | --- | --- | --- | --- |
| `out_of_envelope` | attack | yes | no | damaged | R1 |
| `overflow` | attack | yes | no | damaged | R3 |
| `dryout` | attack | yes | no | damaged | R3 |
| `water_hammer` | attack | yes | no | damaged | R2 |
| `command_flood` | attack | yes | no | safe | R2 |
| `replay_overflow` | attack | yes | no | damaged | R3, R4, R5 |
| `stealthy_bias` | attack | no | yes | damaged | R3, R4, R5 |
| `startup` | normal | no | no | safe | — |
| `shutdown` | normal | no | no | safe | — |
| `emergency_drain` | normal | no | no | safe | — |
| `setpoint_change` | normal | no | no | safe | — |
| `pump_trip_restart` | normal | no | no | safe | — |

The last attack row needs reading carefully, and the two columns that look
contradictory are the point. `stealthy_bias` fires three rules and is still
scored as not detected, because detection counts only objections raised inside
the attack window. By the time those rules fire the tank is at 2.00 m. A guard
that eventually notices is not a guard.

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

### The attack that gets through

`stealthy_bias` is in the suite on purpose. It does not attack the tank. It
attacks the guard's belief about the tank, by adding a slowly growing lie to the
level reading, slowly enough that R4 never sees a contradiction big enough to
report in time.

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

### What the tank numbers don't prove

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

### The site is not an old system, and that is the point

It would be easy to read this project as being about old equipment. The tank
half is: Modbus TCP has no authentication and no encryption, the controller
obeys any word written to it, and the whole argument for putting the check
outside is that you cannot patch the thing inside.

The storage site is the opposite case and it is in the project deliberately. It
is a modern system. The site controller has an HTTP API over TLS, with bearer
tokens, expiry and roles. There is a jump server, a firewall, zones and
conduits laid out the way IEC 62443 asks for. Nothing about it is a
twenty-year-old installation nobody can touch.

Now look at what happened in the `rest_limit_tamper` scenario. The attacker
raises the site's export limit from 20 MW to 40 MW over the REST API, and then
dispatches the fleet against the new limit. Every security control on that site
worked exactly as designed. The token was valid and unexpired. The role was
`engineer`, which is the role that is supposed to change limits. The request
arrived through the jump server, over TLS, at the documented endpoint, in the
right shape. Every check the API makes, it passed. There is nothing anomalous
about the request at any layer that was looking.

What stopped it was that 40 MW through a 25 MVA transformer is not something
anybody can authorise. That is a fact about the iron in the yard, and no token
can change it.

So the storage site is not evidence that modern OT systems are fine and legacy
ones are the problem. It is evidence that these are two different questions.
Authentication answers who sent this. Plausibility answers whether this is a
sane thing to do to the plant. A modern stack closes the first question well
and leaves the second one completely open, and the second one is the one that
spills sewage and melts transformers.

The OPC UA work below is the uncomfortable other half of that. Modernising the
protocol improves the answer to the first question and can remove your ability
to ask the second at all.

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

### A majority of stale readings outvotes the truth

Three measurements beat one because an attacker has to corrupt two of them to
move the consensus. That argument assumes all three are still arriving, and
nothing in the guard was checking.

A measurement whose communications link drops does not disappear. SCADA keeps
serving the last value it received, and a frozen number looks exactly like a
number that agrees. Cut two of the three links and the two stale readings agree
with each other, because they are stuck at the same old figure. The majority is
now wrong, and B6 does what it was built to do: it names the one instrument
still telling the truth.

The run that shows it ramps the fleet to 19 MW, cuts the revenue meter's link,
then the protection relay's, then ramps the site down to idle.

| Two links cut, site ramped down | Scanner informs the guard | Scanner does not |
| --- | --- | --- |
| Error in the guard's belief | −0.04 MW | +18.23 MW |
| Measurements counted | 1 of 3 | 3 of 3 |
| Source named as lying | none | Megapack telemetry sum |

The right-hand column is the one to read. The guard believes the site is
exporting 18.8 MW while it is exporting 0.6 MW, and it has formally accused the
only honest instrument of lying. This is the threat model's "an attacker who
controls the field devices can make all three measurements agree" reached far
more cheaply: an attacker who can drop two links never has to touch a meter.

The fix is a device scanner that asks every device whether it is still
answering and tells the guard which measurements are still being refreshed. A
stale source stops counting as a vote. What that costs is honest and worth
stating: with one measurement gone the vote can still see a disagreement but
can no longer say which source is wrong, and with two gone there is no
cross-check left at all. The guard reports that it has lost quorum rather than
carrying on as though three sources were still arriving, because the useful
thing here is not detection but knowing what can no longer be established.

A stale source is also never accused. Integrating a frozen reading's drift
against consensus would eventually name it a liar for the crime of not being
there, and send an engineer to recalibrate a meter whose only fault is a dead
switch.

Two caveats. The scanner's debounce means the guard hears about a lost
measurement three sweeps late, three seconds at the default interval, and that
delay is deliberate: a scanner that condemned a device on one missed poll would
drop measurements in and out of the vote several times a second. And a probe
that comes back clean proves only that something answered. On a network the
attacker is assumed to hold, anyone who can keep a socket open and echo a
canned response keeps a dead device looking alive. This is monitoring, not
authentication.

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

## The water treatment works

The tank and the battery site both argue about a quantity somebody is
measuring. The tank has one instrument and can be lied to slowly. The site has
three and can be lied to only within a bound. Both arguments assume the number
that matters is on an instrument somewhere.

A treatment works is where that assumption runs out, so the project has one:
eight stages from a river intake to the mains, twenty-two devices across six
zones, five controllers, nine analysers, and exactly one guarded conduit.

```bash
python scripts/run_water.py
```

### Three things a tank cannot show

The dangerous quantity is a chemical dose rather than a position. A pump is
open or shut, and the worst an attacker does with it is move it. A dose is a
number, and the number that protects the public is a limit held in the same
controller the attacker is already writing to. At a Florida water plant in
2021 a dosing set-point was raised about a hundredfold, from roughly 100 ppm
to roughly 11,100 ppm. Nothing moved, no alarm was configured to care, and an
operator happened to be looking at the screen. Later reporting raised the
possibility that it was a plant employee's own action rather than an
intrusion, and the attribution is not settled; what the shape of the write
demonstrates does not depend on who sent it.

The measurement arrives minutes after the command. Chlorine injected now
reaches the residual analyser two and a half minutes later; coagulant takes
four. For that long, a works that has stopped disinfecting reads exactly like a
works that has not. Anything that waits for an instrument to disagree has
nothing to say during the interval in which the damage was decided.

The quantity that decides whether the water is safe is not measured at all.
Disinfection is judged by CT, the residual chlorine multiplied by the time the
water spent in the contact tank. No instrument on the site reads it. It is
computed from a chlorine analyser, a level gauge and a flow meter, which means
an attacker who moves any one of the three moves it, and an attacker who simply
opens the pumps feeding the town collapses it while every reading on the plant
stays healthy.

That last one is the clearest case in the project for modelling the process
rather than inspecting the traffic. There is no packet to flag and no reading
to disbelieve. There is only arithmetic that nobody on the site is doing.

### What the rules ask

Eight, evaluated in the order `W1 W8 W6 W2 W7 W5 W4 W3`.

| | Asks |
| --- | --- |
| W1 | is this value even in range for this piece of equipment? |
| W2 | is this dose sensible for the amount and quality of water? |
| W3 | where does the water end up if this command sticks? |
| W4 | do the instruments that measure this agree with each other? |
| W5 | does what goes in match what comes out and what is stored? |
| W6 | has the plant been put into a hold that only a person can clear? |
| W7 | is the plant in a state where this command is allowed at all? |
| W8 | should this device, in this part of the network, be writing this? |

W2 is the Oldsmar rule, and the part worth noticing is that it judges the
ceiling as well as the dose. The maximum dose is a writable register, so an
attacker raises it first and then doses through the gap. A guard that reads
that register as a constraint is checking the attacker's own work, so W2 judges
a proposed ceiling against what the chemical does to a person, which is not
stored anywhere in the plant.

W3 carries two horizons, because the process has two speeds. A dose reaches the
analyser in under three minutes; a clearwell this size takes over an hour to
empty. A single ten-minute prediction cannot see the second, and opening the
high-lift pumps right up read as harmless until the rule grew a second clause
that asks about the water balance as a rate rather than the level at some
horizon.

### What happened

Nine attacks, each the shape of something that has happened, launchable from
the page while the plant runs.

| | What it does |
| --- | --- |
| Chemical overdose | raises the chlorine ceiling, then doses through it |
| Caustic overdose | the same with caustic soda, the chemical the Florida incident actually involved |
| Quietly stop disinfecting | turns the dose down; every instrument reads normal for minutes |
| Steal the contact time | opens the pumps to the town so water rushes through the contact tank |
| Let the mud through | cuts the coagulant; the filters cannot cover for a failed clarifier |
| Empty the treated water tank | stops the intake, leaves the town pumps running |
| Blind the alarms first | moves the turbidity alarm point so nothing will ever trigger |
| Freeze the chlorine reading | holds the analyser at its last good value while the dose is cut |
| A command from outside | a write from the vendor's remote support connection |

| Metric | Result |
| --- | --- |
| Attacks the guard objected to | 9 of 9 |
| Attacks that harmed the water without the guard | 9 of 9 |
| Of those, harm prevented | 9 of 9 |
| Ordinary commands refused | 0 of 57 |

Each attack is tested twice and both halves have to hold. With the guard
watching only, the attack must actually damage the water, because an attack
that does nothing unguarded proves nothing about the guard that blocked it.
With the guard enforcing, no harm may occur and at least one command must have
been refused, so that the saving cannot be the plant quietly recovering on its
own.

The last row is the one to read first. Nine hundred simulated seconds of the
works running itself, dosing paced to flow and turbidity and pumps trimmed to
hold the clearwell, put fifty-seven commands across the guard and none were
refused. A guard that objects to a plant operating normally has not made the
works safer, it has taken it off line, and every attack it then catches is
beside the point.

### The model had to be made harsher three times

Each of these flattered the guard, and each was found by an attack that should
have worked and didn't.

A filter kept its design efficiency however dirty the water arriving was, so
cutting the coagulant produced 0.26 NTU: untidy, legal and survivable. Sand
beds are sized for what a working clarifier hands them, and several times that
goes through rather than being caught. With the overload term, cutting the
coagulant breaches the turbidity limit and, because all that mud consumes
chlorine, breaks disinfection as well.

Outflow was taken from pump speed alone, so an empty clearwell went on
reporting a steady flow to the town, which hid the one consequence that
matters.

Pressure sagged gently towards a legal value as the clearwell drained. High-lift
pumps draw from that tank, and below their suction the column breaks and they
pass air, so the mains do not hold at two thirds of normal while it empties.

There were four more on the guard's side, including a rule that compared a dose
against a residual with no decay in the contact tank and so refused every
command a compliant works issued. All seven have a regression test that says
what the bug was. Full detail in [`docs/water.md`](docs/water.md).

### Watching it

The works runs live in a browser rather than printing a table afterwards.

The schematic carries the process left to right with the live value at every
stage, and the command traffic comes down from the top: each command leaves the
device that sent it, travels to the guard, and either crosses it and reaches its
stage or stops on the line with a cross through it. Six headline figures sit
above it. All fourteen measurements are drawn below as a meter list, each
against its own limits with the limit marks on the track, so no number is shown
without the thing it has to stay inside.

Beside the schematic is a column that says what just happened, written for
somebody who has never seen a treatment works:

> The operator's screen in the control room asked to set the chlorine dose to
> 9.5 mg/L.
> OTGuard refused it. A chlorine dose of 9.5 mg/L into water needing 0.59 mg/L
> would leave 8.91 mg/L in the mains, above the 4 mg/L limit.

The guard can be switched between enforcing and watching while an attack runs,
which puts the method into one gesture: the same plant, the same attack, a
minute apart, and the chlorine climbing past the line it stopped at the first
time.

Both colour sets were run through a palette validator against their own surface
and pass the lightness band, the chroma floor, adjacent-pair separation under
simulated colour blindness, the normal-vision floor and contrast. Nothing states
a condition by colour alone. There is no network dependency of any kind.

### What the works does not show

The twenty-two devices, six zones and six conduits are a model of the network,
not twenty-two listening servers. The tank demonstration is the one that runs
real Modbus over real sockets, and it is the right place to look for wire-level
behaviour. The page says so itself rather than letting a visitor assume
otherwise.

Nine of nine is nine scenarios written by the same person who wrote the rules.
What carries weight here is not the count but the shape of the thing being
defended: a works has a safety-critical quantity with no instrument on it, and
that is true of real works whoever writes the test suite.

## Other senders, other receivers

An operator station writing to a PLC is the textbook picture and it is not what
a plant looks like. Commands also come from supervisory masters, peer
controllers, engineering laptops and historians, and they land on drives and
remote terminal units as well as on PLCs. So the guard now runs against three
kinds of receiver and five kinds of sender, over real TCP sockets.

The physics is the same everywhere. What differs is everything between a
command on the wire and the pump. A PLC takes a pump command as tenths of a
percent in a register. A variable-frequency drive takes it as a fraction of
full scale, where full scale means whatever its maximum-frequency parameter
currently says. An RTU takes it as one bit closing a contactor, which means
full speed at once with no ramp. Read an RTU contactor as if it were a PLC
speed word and you get 0.01 % instead of 100 %.

Senders differ in how they talk. An operator clicks a few times a minute, a
peer controller writes every scan for as long as it runs. One write-rate
threshold cannot serve both: set it for the operator and the peer controller
is a permanent flood, set it for the peer controller and a script hammering the
valve is ordinary traffic. So R2 counts writes per sending device against a
budget for that device's class. Its other half, the water-hammer check, counts
across every sender, because two compromised devices taking turns on a valve
hammer the pipe as hard as one does.

Sixty sender and receiver pairs, eleven attacks, each run with the guard
enforcing and again with it powerless.

| Metric | Result |
| --- | --- |
| Attacks the guard objected to | 60 of 60 |
| Pairs that damaged the plant unguarded | 38 |
| Of those, damage prevented | 38 of 38 |
| Ordinary writes refused | 0 of 336 |
| Added round trip | p50 105 us, p99 353 us |

Some writes cannot be judged by a physics rule at all: a write to an address
the guard has no description for, a write to a drive's ramp or maximum
frequency, a mask write whose result depends on what the register already
holds, a diagnostics function code. None of those are physics questions, so a
wire policy answers them before the rules run, and it refuses by default.

Turning that policy off is the interesting measurement, because it runs first
and so takes credit for everything it stops. With it off, the physics rules
alone still catch all sixty pairs and prevent all thirty-eight. The policy is
load-bearing for four of them, the mask writes, and those are not a physics
failure: the value a mask write produces is not in the frame, so there is
nothing to judge. That reads against the policy more than for it.

### What this part does not show

Sixty of sixty is not a claim about attacks in general. The attacks and the
rules were written by the same person.

Water hammer is detected on all twelve of its pairs and damages the plant on
none, because this tank models level and not pressure. Those pairs say
something about detection and nothing about damage.

Twelve pairs are stopped by source scoping before any physics runs, because the
peer controller is configured to write the valve and those attacks write the
pump. Eight more do no damage unguarded whatever the guard does, because the
RTU opens its own pump contactor at 1.70 m. They are reported as having no
damage to prevent rather than counted as saves.

The guard learns who is talking from the source address of the connection and
nothing else. An attacker who has taken over the operator station inherits its
identity, and a spoofed address defeats the check outright.

Full detail is in [`docs/devices.md`](docs/devices.md).

## Attacks that actually happened

Everything above was written from the design outward. Each scenario exists to
exercise a rule, which is the right way to build a test suite and a weak way to
argue that the design matters: the attacks and the rules were written by the
same person on the same afternoon, and sixty of sixty is what you would expect
from that whether the idea was any good or not.

So the project also works in the other direction. It takes twelve publicly
reported incidents and campaigns, from Maroochy Shire in 2000 to the Unitronics
controllers in water utilities in 2023, and asks of each one whether this guard
would have been in a position to do anything about it. Each row points at
evidence that already exists elsewhere in the project rather than carrying a
copy of its own attack, so a renamed scenario breaks a row loudly instead of
quietly.

For four of the twelve the answer is no, and those four are the useful part.

Stuxnet ran on the controllers. Its rotor commands never crossed a network link
a bump-in-the-wire could have been installed on. The rules recognise the
pattern fine, and the scenario derived from it is detected and its damage
prevented, and the incident is still something this device would have been
blind to because of where the device sits. Counting it as a hit would be
claiming a geometry the project has not earned.

Night Dragon took documents. Havex inventoried OPC servers. Neither
manipulated a process, so there is no command for a plausibility rule to judge,
and the correct behaviour is to forward the traffic and contribute nothing. The
Havex row is worth having for exactly that reason: the OPC UA work below
includes a reconnaissance episode that browses and reads the whole address
space, and it is scored as traffic the guard must not refuse rather than as an
attack it caught.

The 2014 German steel mill report says a blast furnace could not be brought to
a controlled shutdown. It does not say what was written, to what, or whether a
command was issued, suppressed, or an interlock disabled. Those are three
different scenarios with three different results, and building one with this
incident's name on it would be presenting an invention as evidence. The row
stays empty and says so.

Two scenarios had to be added because nothing in the suite had their shape. One
runs the overdrive in bursts behind a transmitter replaying its own earlier
recording, which is harder on a decaying detector than one continuous push
behind a frozen reading. The other is a single set-point write, above the top of
the tank, that moves no actuator: the plant's own control loop does everything
harmful that follows, correctly, against a target it was handed. That is the
cheapest harmful write there is, and no amount of reasoning about credentials,
rate or volume can see anything wrong with it.

| Metric | Result |
| --- | --- |
| Incidents in the catalogue | 12 |
| A plausibility guard is the right control for | 8 |
| Of those, an attack of that shape was objected to | 8 of 8 |
| By a physics rule | 7 |
| By the access policy alone | 1 |
| Of those, damage occurred without the guard | 8 |
| Of those, the guard prevented it | 8 of 8 |

The last two rows of that detection block are split for the same reason the
device matrix splits them. An access check that stops an attack is worth having
and is not evidence for the claim this project makes. The one incident carried
by the access policy alone is the Unitronics intrusion, where the attack is a
write from a device the guard has never heard of and there is nothing physical
to reason about until it lands.

Every account in the catalogue is public reporting as I understood it, checked
against no primary sources, and every number in every scenario is this
project's own rather than an incident's measured parameter. Where the reporting
is disputed the catalogue says so. Full detail is in
[`docs/incidents.md`](docs/incidents.md).

## What encryption costs the guard

Modbus has no security, so the guard's access to the traffic has been assumed
throughout. OPC UA is the protocol a plant replaces Modbus with, and it changes
that: a client and a server negotiate a security mode, and the negotiation
decides how much of their conversation anybody else can read.

Same guard, same attacks, same tank, three times, changing only that setting.

Under `None` everything is cleartext. The guard decodes the write, runs the
same five rules, and refuses by withholding the request and answering the
client with a `BadUserAccessDenied` in the device's voice. Withholding a
request leaves the two ends disagreeing about how many messages have passed, so
it renumbers the rest of the conversation in both directions. The write never
lands and the session carries on.

Under `Sign` the guard still reads every write and can alter none of them,
because each message is signed and the guard has none of the keys. It can still
refuse, by withholding the frame and cutting the channel, and it can still
write a protective command on its own session.

Under `SignAndEncrypt` sixteen bytes of each message stay legible: the type,
the length, the channel and the key. Nothing in them says which node is being
written, or to what.

The interesting result is not that the guard goes blind. It is what happened to
the half that was supposed to survive. The supervisor polls the level itself,
so it never needed to read anyone else's traffic, and the expectation was that
it would come through intact. It did not. Its lookahead integrates a model
forward under the commands the guard has forwarded, and on an encrypted channel
it has forwarded commands it never read, so the model says both actuators are
shut. When the level rose, the consistency check reached the only conclusion
its premise allows: the transmitter must be lying. It went open loop, froze its
estimate at 0.99 m, and watched the tank fill to 2.00 m while holding a CUSUM
above 20,000.

That is a design fault rather than a tuning problem, so the guard now carries a
second supervisor that runs only when it knows it is command-blind. It reads
the level and the level's slope, predicts forward with no model at all, and
trips on the measurement. It is the weakest protection in the project, it has
no idea which command caused anything, and it is the only thing left on an
encrypted channel.

Two attacks show what that is worth. The overflow is prevented in all three
modes, because its commands are individually legal, nothing refuses them at the
wire in any mode, and the supervisor that saves the tank works blind. The
set-point write separates them: refused on its range under `None` before the
tank moves; refused under `Sign` by cutting the channel, after which the
operator cannot get back in and every recovery write fails; and under
`SignAndEncrypt` it lands, the control loop starts filling toward a target
above the top of the tank, the blind supervisor trips the pump repeatedly, the
control loop overrides each trip because the guard cannot see or stop its
commands, and the tank overflows.

| What the guard could read | None | Sign | SignAndEncrypt |
| --- | --- | --- | --- |
| Request and response bytes legible | 100.0% | 100.0% | 9.5% |
| Request bodies decoded | 1361 | 1032 | 0 |
| Ordinary writes refused | 0 of 34 | 0 of 28 | 0 of 31 |

Two things in the results need reading carefully. The `Sign` column looks as
good as `None` and is not: four of its five refusals were carried out by
cutting the channel, and in every one the operator's writes after the attack
window all failed. The plant was saved and the operator was locked out of it.
And the encrypted column has a false alarm in it. The only detector left there
counts message arrivals and cannot tell a read from a write, so a
reconnaissance sweep that writes nothing looks like a flood, and the guard cuts
the operator's session over it.

The rules did not get worse. The traffic they run on disappeared. Full detail,
including the deployment option this does not model, is in
[`docs/opcua.md`](docs/opcua.md).

## Running it

```bash
pip install -r requirements.txt
```

Nothing else needs installing. The scripts add `src/` to the path themselves,
and figures are drawn without a display.

Three of these open something you can watch. The rest print results.

```bash
python scripts/run_water.py                    # the treatment works, live
python scripts/run_live_demo.py                # the tank, live, interactive
python scripts/run_live.py tank                # one scripted site, narrated
python scripts/run_live.py battery

python scripts/run_demo.py --attack overflow --duration 25
python scripts/run_eval.py --stealth-sweep
python scripts/run_site_eval.py --sweeps
python scripts/run_matrix.py --ablation
python scripts/run_incidents.py --matrix
python scripts/run_opcua.py
python scripts/bench_latency.py
python -m pytest
```

Each site has its own command and none of them runs two. The sites keep
different time — the tank moves in seconds, the works in tens of minutes, the
battery site in whatever the ramp takes — and one invocation that played them in
sequence left nobody able to say afterwards which numbers belonged to which
plant.

`run_water.py` is the one to run first, and the section above describes what it
puts on screen. It opens on `http://127.0.0.1:8701/`.

`run_live_demo.py` is the tank with the script taken out. The stack stands up
with ordinary traffic flowing and then waits for you. The page draws the whole
topology: five masters with their source addresses, the guard with a lamp per
rule, the field device with its tank drawn to scale. Every frame the guard
judges crosses the wire as a dot in the colour of the verdict it got, three
charts fill as the plant moves, and the scanner's device table says what is
still answering. Three buttons do the demonstrating: launch any attack the
matrix defines for that device, turn enforcement off and run the same attack
again, or cut the link to the device and watch the scanner work out within
three sweeps that nothing is answering while the plant carries on behind it.

`run_live.py` narrates one scripted site while it happens, to a terminal that
redraws in place and to a browser at `http://127.0.0.1:8765/`. Both read one
event stream, so neither can show a number the other does not have. It takes
the site as an argument and will not start without one. `--no-web` skips the
browser, and outside a terminal it falls back to one line per event so a
transcript stays readable.

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
about 4 minutes with `--sweeps`, and the test suite takes about 110 seconds. The
device matrix takes about twenty minutes with `--ablation` and about half that
without. `run_incidents.py` takes a couple of seconds, or a few minutes with
`--matrix`, and reads the OPC UA rows out of `results/opcua/` if that has been
run. `run_opcua.py` takes several minutes: forty-two episodes, each paying for
its own secure-channel handshake.

Two of these are not reproducible to the sample, and say so in their own
output. The device matrix and the OPC UA experiment run over real sockets on a
scaled clock, so the number of writes an episode produces moves by a few either
way between runs. Their outcomes are stable; their counts are not. Everything
under `results/` is regenerated by these commands and is not tracked by git.

## How the code is laid out

```
src/otguard/
  config.py              typed configuration, strict about unknown keys
  clock.py               one timeline, faster than the wall

  sim/water_tank.py      the tank: mass balance, actuator travel, sensor noise
  bess/                  battery model, fleet, connection point, three meters
  water/
    types.py             stages, command points, what each harm means
    plant.py             the works: eight stages, transport delay, harm scoring
    topology.py          six zones, six conduits, twenty-two devices
    metrics.py           the fourteen measurements and the limits on each
  site/topology.py       IEC 62443 zones and conduits over the Purdue levels

  guard/
    types.py             Command, Observation, Verdict
    estimator.py         Kalman filter, CUSUM, lookahead, equilibrium
    rules.py             R1 to R5
    guard.py             decisions, supervision, trips, lockout
    site_estimator.py    per-unit charge and temperature estimates, voting
    site_rules.py        B1 to B8
    site_guard.py        site decisions, supervision, curtailment
    water_estimator.py   belief over the works, and the forward model
    water_rules.py       W1 to W8
    water_guard.py       water decisions, supervision, protective actions

  modbus/
    protocol.py          MBAP and PDU framing, every write function code
    plc_server.py        simulated controller, obeys anything by design
    device.py            protocol and scan loop shared by every receiver
    field_devices.py     drive gateway and remote terminal unit
    devicemap.py         what each point on each device means
    registers.py         the register map the tank controller exposes
    inventory.py         who may talk, and what to do with unjudgeable frames
    masters.py           the senders: HMI, SCADA, peer controller, historian
    proxy.py             the guard on the wire
    deviceproxy.py       the guard on the wire, for any sender and receiver
  protocols/
    dnp3.py              framing with the 0x3D65 CRC, CROB, select-before-operate
    goose.py             IEC 61850 frames, stNum and sqNum handling, subscriber
    prp.py               redundancy control trailer, dual-LAN mismatch
    rest.py              site controller API, roles and tokens
  opcua/
    framing.py           the OPC UA binary transport, and what each mode hides
    nodes.py             the device's address space, and the guard's map of it
    device.py            a field device that speaks OPC UA, security modes and all
    proxy.py             the guard on the wire, with powers that depend on the mode
    masters.py           the clients: one honest, five not
    certs.py             self-signed test certificates

  scan/
    probe.py             liveness probes, and what each one's answer proves
    scanner.py           up/down per device, debounced both ways
    targets.py           the device lists, and which rows are model reads
  live/
    events.py            what a watcher is told, in one JSON-safe shape
    bus.py               fan-out that never blocks the plant
    terminal.py          the screen, redrawn in place
    web.py               server-sent events over a hand-rolled HTTP server
    page.py              the scripted view
    demo.py              the interactive tank: attacks, enforcement, link cuts
    demo_page.py         the tank's browser view
    water_demo.py        the works: plant, guard, its own control, nine attacks
    water_page.py        the works' browser view
    plain.py             every event rendered into English a visitor can read

  scenarios/             labelled attacks and ordinary situations
  scenarios/incidents.py twelve reported incidents, and what speaks to each
  eval/                  harness, metrics, sweeps, figures, command line
  eval/matrix.py         every sender against every receiver, over sockets

config/default.yaml      every tunable number, with the reasoning next to it
scripts/                 run_water.py, run_live.py, run_live_demo.py,
                         run_demo.py, run_eval.py, run_site_eval.py,
                         run_matrix.py, run_incidents.py, run_opcua.py,
                         bench_latency.py
tests/                   361 tests and one expected failure
docs/                    design.md, bess-design.md, water.md, devices.md,
                         incidents.md, opcua.md, live.md, heilmeier.md
```

## More detail

[`docs/design.md`](docs/design.md) covers the threat model, the architecture, and
why each rule is shaped the way it is.

[`docs/water.md`](docs/water.md) covers the treatment works: the eight stages
and the three places the model had to be made harsher before an attack on it
meant anything, the six zones and the one guarded conduit, rules W1 to W8, the
nine attacks, and the ordinary commands that have to get through.

[`docs/bess-design.md`](docs/bess-design.md) covers the battery site: physics,
rules B1 to B8, the protocols, the results, and where it fails.

[`docs/devices.md`](docs/devices.md) covers the senders and receivers: what
changes between device classes, what the wire policy is for, and where those
numbers are weaker than they look.

[`docs/incidents.md`](docs/incidents.md) covers the twelve reported incidents:
which of them this guard could speak to, which it could not, and why the second
list is the interesting one.

[`docs/opcua.md`](docs/opcua.md) covers the security-mode experiment: what each
mode leaves a bump-in-the-wire, how the supervisor failed when it could not see
the commands, and the deployment option the experiment does not model.

[`docs/live.md`](docs/live.md) covers the device scanner and the live views: why
a frozen measurement outvotes an honest one, what dropping it costs the guard,
which rows of the device table are measured and which are modelled, and how to
run the thing.

[`docs/heilmeier.md`](docs/heilmeier.md) answers the Heilmeier questions.

[`config/default.yaml`](config/default.yaml) holds the parameters, each with the
reasoning for its value written beside it.

## License

MIT. See [LICENSE](LICENSE).

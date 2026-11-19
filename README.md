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

Swap the bathtub for a water treatment plant or a grid battery site — the two
plants this project guards — and the floor is a town.

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
      plant                    dose injectors, pumps, inverters, breakers
```

Modbus TCP is just the language controllers speak over a network cable. It's
about as simple as it sounds: write this number into slot 3, read the number in
slot 7. There's no password in it and no signature, which is part of why this
project exists.

## What's in here

Two plants, and the second exists because the first ran out of road.

| Plant | What it is | Why it's here |
| --- | --- | --- |
| [Storage site](#the-storage-site) | sixteen battery units, 30.8 MW, three independent meters | what a second measurement of the same quantity buys, and what takes it away again |
| [Treatment works](#the-water-treatment-works) | eight stages, twenty-two devices, six zones | what to do when the quantity that decides public safety has no instrument on it |

Each one runs live in a browser, with its own command:

```bash
python scripts/run_site.py     # the storage site
python scripts/run_water.py    # the treatment works
```

And two experiments that test the idea rather than the implementation. One
takes [twelve reported incidents](#attacks-that-actually-happened) and asks
which of them this device could have spoken to, including the five where the
answer is no. The other runs the same attacks over OPC UA at three security
modes and measures [what encryption costs the guard](#what-encryption-costs-the-guard).

Every section ends with where that piece fails, because a defence with no
stated failure mode has not been tested, only demonstrated. The counts, with
the caveats left in their own sections:

| | Objected to | Damage prevented | Ordinary commands refused |
| --- | --- | --- | --- |
| Storage site, scripted | 13 of 13 | 5 of 5 | 0 of 3783 |
| Storage site, live | 8 of 10 | 8 of 8 | 0 of 150 |
| Treatment works | 9 of 9 | 9 of 9 | 0 of 57 |
| Incident-derived | 7 of 7 | 7 of 7 | — |

The storage site's live row is the honest one: two of its ten attacks defeat
the guard and are on the page saying so, and two more harm what the guard
knows rather than the equipment, so they are scored on whether it works out
which instrument to disbelieve rather than on damage.

## The storage site

A guard with one instrument can be lied to slowly. Bias a single sensor gently
enough and nothing it reports ever contradicts physics by more than noise, so
the only detector available is one that compares a model against that same
sensor, and the attacker is dragging both. Closing that needs a second,
physically independent measurement, which is a design change and not a
setting.

A grid battery site has three of them. The power leaving the site is measured by
the revenue meter the utility bills against, by adding up what each battery unit
reports about itself, and by the current transformers the protection relay uses.
Different hardware, different cables, different vendors, different protocols, all
measuring the same power. The site already pays for that redundancy for billing
and for protection. Using it to catch a liar costs nothing extra.

So the first plant is a site modelled on a utility-scale battery
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

### Watching it

```bash
python scripts/run_site.py
```

The page draws the yard: sixteen units each with their own charge and
temperature, the collection bus, the transformer, the breaker, the grid
connection, and the three instruments drawn where they actually sit in the
circuit. Seeing all three side by side is the point, because on a real site
nobody can, which is how two frozen readings come to outvote a live one.

Ten attacks run from the page and two of them defeat the guard, which their
own cards say. Two more are marked as harming what the guard knows rather
than the equipment: biasing a meter moves no power, so scoring it on damage
would mark a success as a failure. Its win is naming which instrument to
disbelieve, and it does that with under half a megawatt of lie accumulated.

Nothing starts from fixed numbers. Each run gives every unit its own charge
and temperature and dispatches the site to whatever it happens to be doing,
then reports the seed so an interesting run can be reproduced. Doing that
found a real fault: every pack estimator had been anchored to the fleet
average, so a unit ten per cent below the mean looked from the first scan
like one whose reported charge had drifted, B2 said so, and the guard tripped
protectively on a site nobody had touched. A guard put in front of a running
yard reads each unit first.

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

The storage site's argument is about a quantity three instruments measure:
with three of them an attacker can shift the number only so far before the
vote catches it. That argument assumes the number that matters is on an
instrument somewhere.

A treatment works is where that assumption runs out, so the project has one:
eight stages from a river intake to the mains, twenty-two devices across six
zones, five controllers, nine analysers, and exactly one guarded conduit.

```bash
python scripts/run_water.py
```

### Three things the battery site cannot show

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
incident catalogue splits them. An access check that stops an attack is worth having
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

Same guard, same attacks, same storage site, three times, changing only
that setting.

Under `None` everything is cleartext. The guard decodes the write, runs the
same B1 to B8, and refuses by withholding the request and answering the client
with a `BadUserAccessDenied` in the device's voice. Withholding a request
leaves the two ends disagreeing about how many messages have passed, so it
renumbers the rest of the conversation in both directions. The write never
lands and the session carries on.

Under `Sign` the guard still reads every write and can alter none of them,
because each message is signed and the guard has none of the keys. It can
still refuse, by withholding the frame and cutting the channel, and it can
still write a protective command on its own session.

Under `SignAndEncrypt` sixteen bytes of each message stay legible: the type,
the length, the channel and the key. Nothing in them says which node is being
written, or to what.

Two things about this vantage point are worth stating before the numbers. A
bump-in-the-wire on one OPC UA session reads what that server publishes and
nothing else, so the site's three independent measurements are not three
nodes on this endpoint — they are three instruments on three conduits, and
this device sees one figure. The guard is told it has one source rather than
being handed the same number three times, because three copies of one reading
would look like three instruments agreeing and would be a lie about what the
guard knows. And a guard spliced into a running site has not seen the command
that put the site where it is: left at zero, its idea of what has been
ordered says the fleet is idle, and the first ordinary dispatch then looks
like the whole site starting from a standstill. It refused seventy of
seventy-four honest writes that way before it was made to read the standing
order first.

The interesting result is not that the guard goes blind. It is what happened
to the half that was supposed to survive. The guard's reasoning works forward
from the commands it has accepted, and on an encrypted channel it accepts
commands it never read, so its picture of the fleet says every unit is where
it last saw it. When the power at the connection climbs, the cross-source
check reaches the only conclusion its premise allows: an instrument must be
lying. It accuses a healthy meter and goes on believing a site that is not
there.

That is a design fault rather than a tuning problem, so the guard carries a
second supervisor that runs only when it knows it is command-blind. It reads
the export and the export's slope, predicts forward with no model at all, and
trips against the transformer rather than against the export limit — the
limit is a number on the wire an attacker may already have moved, and the
transformer rating is iron. It is the weakest protection in the project and
the only one that survives an encrypted channel.

What that is worth is less than the tank's version was, and the result is
sharper for it. Under `SignAndEncrypt` the over-export attack still damages
the site: the blind supervisor fires, but by the time measured export has
crossed its threshold the transformer is already overloaded. A supervisor
that can only react to a quantity after it has moved cannot prevent damage
that happens as it moves.

The headline table for this experiment is not reproduced here. The figures
that used to sit in it were measured against the storage tank, and the
experiment now runs against the storage site, so quoting them would be
quoting a different plant. Regenerate them with `scripts/run_opcua.py`, which
writes the whole matrix to `results/opcua/`. What has been checked by hand on
the new plant, and is safe to state: under `None` the guard decodes every
write and refuses the over-export attack without the site leaving its normal
operating point; with the guard watching instead, the same attack reaches
29.5 MW through a 25 MVA transformer and damages it; and under
`SignAndEncrypt` nothing is decoded at all, the blind supervisor fires, and
the site is damaged anyway.

Two things in the results need reading carefully whenever they are
regenerated. A `Sign` column that looks as good as `None` is not: refusals
there are carried out by cutting the channel, and the operator's writes after
the attack window fail too, so the plant is saved and the operator is locked
out of it. And the encrypted column will carry a false alarm, because the
only detector left there counts message arrivals and cannot tell a read from
a write, so a reconnaissance sweep that writes nothing looks like a flood.

The rules did not get worse. The traffic they run on disappeared. Full detail,
including the deployment option this does not model, is in
[`docs/opcua.md`](docs/opcua.md).

## Running it

```bash
pip install -r requirements.txt
```

Nothing else needs installing. The scripts add `src/` to the path themselves,
and figures are drawn without a display.

```bash
python scripts/run_site.py                 # the storage site, live
python scripts/run_water.py                # the treatment works, live
python scripts/run_live.py battery         # the scripted site run, narrated

python scripts/run_site_eval.py --sweeps
python scripts/run_incidents.py --matrix
python scripts/run_opcua.py
python -m pytest
```

Each plant has its own command and none of them runs two. They keep different
time — a battery warms up over tens of minutes and a contact tank fills over
forty — and one invocation that played them in sequence left nobody able to
say afterwards which numbers belonged to which plant.

Neither live page starts from the same numbers twice. The works meets a
different river each run, with the flow it draws tied to how dirty that water
is, because a plant takes less when the filters are the bottleneck. The yard
starts with every unit on its own charge and temperature and the site
dispatched to whatever it happens to be doing: charging overnight, idling, or
into the evening peak. A run with no seed picks one and reports it, so an
interesting one can be reproduced.

`run_site.py` opens on `http://127.0.0.1:8702/` and `run_water.py` on
`http://127.0.0.1:8701/`. Both draw the plant, every measurement against the
limit that applies to it, and a column saying in ordinary English what just
happened and why. The guard can be switched between enforcing and watching
while an attack runs, which puts the whole method into one gesture: the same
plant, the same attack, a minute apart.

`run_opcua.py` takes several minutes: forty-two episodes, each paying for its
own secure-channel handshake. Its counts move by a few either way between
runs because it runs over real sockets on a scaled clock; its outcomes are
stable. Everything under `results/` is regenerated by these commands and is
not tracked by git.

## How the code is laid out

```
src/otguard/
  bess/__init__.py
  bess/megapack.py
  bess/metrics.py
  bess/site.py
  bess/types.py
  clock.py
  config.py
  eval/__init__.py
  eval/figstyle.py
  eval/incident_report.py
  eval/incidents.py
  eval/opcua_experiment.py
  eval/opcua_report.py
  eval/site_harness.py
  eval/site_metrics.py
  eval/site_report.py
  eval/site_sweeps.py
  guard/__init__.py
  guard/site_estimator.py
  guard/site_guard.py
  guard/site_rules.py
  guard/types.py
  guard/water_estimator.py
  guard/water_guard.py
  guard/water_rules.py
  guard/wire.py
  live/__init__.py
  live/bus.py
  live/events.py
  live/plain.py
  live/site_demo.py
  live/site_page.py
  live/terminal.py
  live/ui.py
  live/water_demo.py
  live/water_page.py
  live/web.py
  modbus/__init__.py
  modbus/protocol.py
  opcua/__init__.py
  opcua/certs.py
  opcua/device.py
  opcua/framing.py
  opcua/masters.py
  opcua/nodes.py
  opcua/proxy.py
  protocols/__init__.py
  protocols/dnp3.py
  protocols/goose.py
  protocols/prp.py
  protocols/rest.py
  scan/__init__.py
  scan/probe.py
  scan/scanner.py
  scan/targets.py
  scenarios/__init__.py
  scenarios/base.py
  scenarios/bess_attacks.py
  scenarios/bess_normal.py
  scenarios/incidents.py
  scenarios/site_base.py
  site/__init__.py
  site/topology.py
  water/__init__.py
  water/metrics.py
  water/plant.py
  water/topology.py
  water/types.py

config/default.yaml      every tunable number, with the reasoning next to it
scripts/                 run_site.py, run_water.py, run_live.py,
                         run_site_eval.py, run_incidents.py, run_opcua.py
tests/                   216 tests
docs/                    design.md, bess-design.md, water.md,
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

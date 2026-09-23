# Senders and receivers

The first version of this project had one sender and one receiver: an operator
station writing to a PLC. That is the textbook picture, and it is not what a
plant looks like. Commands come from supervisory masters, peer controllers,
engineering laptops and historians as well as from operator screens, and they
land on drives, remote terminal units and protection devices as well as on
PLCs.

This part of the project asks whether the guard still works when both ends
vary, and it is run over real TCP sockets rather than in process, because most
of what distinguishes one device class from another only exists on the wire.

## What changes when the receiver changes

The physics does not change. A tank fills at a rate set by geometry and
gravity whatever is driving the pump. What changes is everything between a
command on the wire and that pump.

A PLC takes a pump command as tenths of a percent in a holding register. A
variable-frequency drive takes it as a fraction of full scale, where full scale
means whatever its maximum-frequency parameter currently says. An RTU takes it
as a single bit driving a contactor: on or off, and on means full speed with no
ramp at all.

Three consequences follow, and each is something a guard validated only against
a PLC gets wrong.

The first is scaling. A coil and a holding register at the same address are
unrelated points. Reading an RTU's pump contactor as if it were a PLC's 0.1 %
speed word gives 0.01 % instead of 100 %. A 4-20 mA analog output has a live
zero, so 0 % is 6400 counts and not 0; a guard that forgets the offset reads
every valve position 25 % low.

The second is unit addressing. A gateway fronting an RS-485 segment carries
several devices on one TCP endpoint, distinguished only by the unit id in the
frame header. A PLC typically ignores that byte entirely and answers whatever
it is addressed as. Both behaviours are in the simulated devices here, because
a guard that assumes either one is wrong half the time.

The third is that some receivers protect themselves. The RTU opens its pump
contactor whenever the level it reads reaches 1.70 m, whatever it was told to
do. That matters for the evaluation, not just for the plant: an attack against
the RTU can do no damage without the guard present, and counting that as a save
would credit the guard for the device's own interlock. Those pairs are reported
as having no damage to prevent.

## What changes when the sender changes

An operator clicks a few times a minute. A SCADA master polls and adjusts a
setpoint every few seconds. A peer controller closing a cascade loop writes
every scan, for as long as it is running. A historian polls constantly and
never writes. An engineering workstation is silent for weeks and then rewrites
a drive's configuration.

A single write-rate threshold cannot serve all of those. Set it where an
operator station sits and the peer controller is a permanent flood; set it
where the peer controller sits and a script hammering the valve from the
operator station is ordinary traffic. So R2's flood check now counts writes per
sending device against a budget for that device's class.

R2's other half does not work that way, deliberately. Water hammer is counted
across every sender, because two compromised devices taking turns on a valve
hammer the pipe exactly as hard as one does. The split is the useful thing to
notice: the half of R2 that is about traffic needs to know who is talking, and
the half that is about physics does not.

## How the guard learns who is talking

From the source address of the TCP connection, and nothing else.

That is weak evidence and the code says so. An attacker who has taken over the
operator station inherits the operator station's identity, which is the threat
model this project has assumed throughout. A spoofed source address defeats it
outright. It is a configured fact, the way a plant's documentation records that
the historian lives at one address and the engineering laptop at another, and
it is worth exactly as much as that documentation.

This is why the results separate what the physics rules caught from what the
source check caught. An access rule that stops an attack is a useful thing to
have, but it is not evidence for the claim this project makes, and reporting
the two together would inflate the number that matters.

## Frames the rules cannot judge

Some writes cannot be evaluated by a physics rule at all, and they are not
rare.

A write to an address the device map does not describe carries an unknown
meaning. A write to a drive's maximum-frequency or acceleration parameter
changes how the actuator responds, which silently invalidates the model every
other rule reasons about. A mask write (function 22) sets bits according to
what the register already holds, so the resulting value is not in the frame.
A diagnostics or vendor-specific function code is a channel straight to the
device's firmware.

None of these are physics questions, so none of them belong in R1 to R5. They
are handled by a wire policy that runs before the rules and answers a different
question: can this frame be judged at all? Everything it covers defaults to
refusing, because a guard that forwards what it does not understand has a
coverage list equal to the attacks its author happened to think of.

Two of them are refused whatever the policy says. A malformed write and a mask
write are not forwarded even with every other check disabled, because
forwarding either means vouching for a value the guard has not seen.

The policy has an honest cost, and the evaluation shows it. Rewriting a drive's
acceleration ramp is a legitimate thing for a commissioning engineer to do, and
the guard refuses it. A deployment would need a documented way to put the guard
in a maintenance mode, which is its own risk and is not modelled here.

## The devices

| Receiver | What it is | Pump command | Valve command | Level |
| --- | --- | --- | --- | --- |
| `plc` | a controller with the tank behind it | holding register, 0.1 % | holding register, 0.1 % | input register, mm |
| `drives` | gateway to a VFD, a positioner and a transmitter | unit 2, fraction of full scale | unit 3, 0.01 % | unit 4, mm |
| `rtu` | remote terminal unit with 4-20 mA I/O | coil 0, a contactor | holding register, 4-20 mA raw | input register, 4-20 mA raw |

The drive gateway has four parameter points: maximum frequency, acceleration,
deceleration and valve stroke time. The RTU has one: the enable bit for its own
high-level interlock. The PLC has none, which is part of why a guard tested
only against it looks better than it is.

| Sender | What it is | Writes | Rate |
| --- | --- | --- | --- |
| `hmi` | operator station | any actuator | a few a minute |
| `scada` | supervisory master closing a level loop | pump, valve, setpoint | every 3 s |
| `peer_controller` | another controller, cascade loop | valve only | every 0.5 s |
| `engineering` | commissioning laptop | any, including parameters | rare |
| `historian` | process historian | nothing | reads every 0.5 s |

## The attacks

Three run everywhere. `overflow` shuts the outlet and runs the inlet flat out,
which is the original attack and is individually legal at every write.
`valve_hammer` slams the outlet open and shut, a pressure transient rather than
a level excursion, so no lookahead rule sees it coming. `write_flood` hammers
the command path, and what counts as a flood depends on which device is
sending.

The rest exist because a particular device class allows them.
`parameter_overspeed` raises the drive's maximum frequency and then commands
100 %: the speed reference never leaves its legal range, and the meaning of
that range is what changed. `ramp_tamper` shortens the drive's acceleration so
the pump steps instead of ramping, outrunning the guard's model of the
actuator. `interlock_disable` switches off the RTU's own high-level interlock,
a single coil write that moves no actuator at all. `coil_sweep` starts the pump
and clears the interlock in one multiple-coil frame. `mask_write` and
`readwrite_sneak` carry an ordinary pump command inside function codes 22 and
23, which a parser written against functions 6 and 16 never examines.

Two test the sender rather than the receiver. `historian_write` has a read-only
device start issuing commands. `unknown_source` has a device that is not in the
inventory write to the controller.

## Results

Sixty sender and receiver pairs, each run with the guard enforcing and again
with it watching but powerless.

| Metric | Result |
| --- | --- |
| Pairs run | 60 |
| Attacks the guard objected to | 60 of 60 |
| Pairs that damaged the plant unguarded | 38 |
| Of those, damage prevented | 38 of 38 |
| Ordinary writes refused | 0 of 336 |
| Added round trip | p50 105 us, p95 222 us, p99 353 us over 14723 frames |

The ordinary-traffic run is the one to read first. Every benign sender runs at
once against each receiver, including the peer controller writing twice a
second for the whole episode, and nothing is refused. That is what the
per-source write budget bought: before it, a single pooled threshold either
called the peer controller a permanent flood or let a script through.

### What the physics rules do on their own

The wire policy runs before the rules, so it takes credit for everything it
stops first. Turning it off says how much of that the rules would have caught
anyway.

| | Pairs |
| --- | --- |
| Stopped at the wire with the policy on | 18 |
| Of those, a physics rule catches anyway | 14 |
| Of those, the policy is load-bearing | 4 |
| Undetected with the policy off | 0 |
| Damaged with the policy off | 0 |

The rules alone catch all sixty pairs and prevent all thirty-eight that did
damage. The four the policy genuinely carries are the mask writes, and they are
not a physics failure: the value a mask write produces is not in the frame, so
there is nothing for a rule to judge. Refusing them is the only honest answer,
and it is the one case where the guard stops an attack without understanding
its physics.

That result cuts against the wire policy rather than for it. An access check
that stops an attack is worth having, but on this suite it is nearly always
stopping something the physics would have stopped a moment later.

### An ablation that was not one

The first version of this table reported eleven pairs undetected and eight
damaged with the policy off, which made the policy look essential. It was a bug
in the proxy, not a result. A defect the policy permitted returned early from
the inspection loop instead of continuing, so with the policy disabled the
physics rules never ran either. "Policy off" was measuring a guard with no
rules at all.

It is recorded here because it is the second time in this project an ablation
has silently measured the wrong thing, after the storage site's cross-source
voting flag gated only its reporting rule. Both had the same shape: a switch
meant to disable one mechanism disabled the thing it was being compared
against. Two regression tests pin this one.

### Where the numbers are weaker than they look

Sixty of sixty is not a generalisation claim. The attacks and the rules were
written by the same person, and the suite is built from what this design was
expected to handle.

Three specific caveats matter more than the headline.

Water hammer is detected on all twelve of its pairs and damages the plant on
none of them, because this tank models level and not pressure. Those pairs are
evidence about detection and no evidence at all about damage.

The twelve pairs where the peer controller is the attacker are stopped by
source scoping before any physics runs, because the peer controller is
configured to write the valve and the attacks write the pump. With the policy
off the rules catch them, so the physics is doing the work, but the default
configuration never exercises it.

The RTU's own interlock means eight pairs do no damage unguarded whatever the
guard does. They are reported as having no damage to prevent rather than
counted as saves.

## Reproducing

```bash
python scripts/run_matrix.py              # every applicable pair
python scripts/run_matrix.py --ablation   # and again with the wire policy off
python -m pytest tests/test_devices.py
```

Episodes run on a clock faster than the wall so that a 45 second scenario takes
about two seconds. Decision latency is still measured in wall-clock
microseconds, because that is the number a plant cares about and it does not
scale with the simulation.

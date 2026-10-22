# What encryption costs the guard

Everything else in this project guards a protocol with no security at all.
Modbus TCP has no authentication, no integrity and no confidentiality, so a
device sitting on the wire can read every frame, and the guard's access to the
traffic is simply assumed. The storage site adds TLS and tokens at the REST
API, but the register writes that actually move the batteries are still
cleartext Modbus.

OPC UA is the protocol a plant replaces Modbus with. It is the one in the 2022
Pipedream advisory, it is in most new equipment, and it changes the assumption
this project has been resting on: a client and a server negotiate a security
mode, and that negotiation decides how much of their conversation anybody else
can read.

So this is the same guard, the same attacks and the same tank, run three times,
changing only that setting.

## The three modes, and what each one leaves the guard

An OPC UA message starts with eight bytes of header, then four bytes of secure
channel identifier, then four bytes naming the key. After that come the
sequence number, the request identifier and the body.

Under `None` all of it is cleartext. The guard reads the body, decodes the
`WriteRequest`, extracts the node identifier and the value, and runs the same
five rules it runs on Modbus. It can also refuse. Withholding one request
leaves the two ends disagreeing about how many messages have passed, so the
guard answers the client with a `BadUserAccessDenied` in the device's voice and
renumbers the rest of the conversation in both directions. The attacker's write
never reaches the device, the client gets a proper OPC UA status code, and the
session carries on.

Under `Sign` nothing is encrypted, so the guard reads every write exactly as
before. What it cannot do is alter one. Each message carries a signature over
its whole length, and the guard has none of the channel's keys, so anything it
fabricates or renumbers fails verification at the far end. It has two levers
left: it can refuse a write by withholding the frame and cutting the channel,
and it can issue a protective command on its own session. Both work. The first
is blunt in a way that matters, below.

Under `SignAndEncrypt` the sequence number, the request identifier and the body
are all ciphertext. Sixteen bytes of each message stay legible: the type, the
length, the channel and the key. None of them say which node is being written,
or to what. The guard cannot pair a response with a request, let alone judge
one. It does not try — a guard that pattern matches inside ciphertext and acts
on what it finds is worse than one that reports it cannot see, because the
first kind is wrong without knowing it.

## What survived, and what the measurement changed

The part of this project that does not read anyone else's traffic is the
supervisor. The guard polls the level on a session of its own, keeps a state
estimate, looks a few seconds ahead and trips the plant when the standing order
is heading out of the envelope. None of that needs visibility into the operator
station's conversation, so the expectation going in was that command-level
authority would be lost and process-level supervision would survive intact.

That expectation was wrong, and finding out how was the most useful thing this
experiment did.

The lookahead integrates a model forward under the commands the guard has
forwarded. On an encrypted channel it has forwarded commands it never read, so
its model says both actuators are shut. When the level then rose, the
consistency check reached the only conclusion its premise allows: the
transmitter must be lying. It went open loop, froze its estimate at 0.99 m, and
watched the tank fill to 2.00 m while holding a CUSUM above 20,000 and
reporting a sensor-integrity alarm.

That is not a tuning problem. "If the model and the sensor disagree, suspect the
sensor" is sound only for a guard that sees every command, and an encrypted
channel is exactly the case where it does not.

So the proxy now carries a second supervisor that runs only when the guard knows
it is command-blind. It reads the level and the level's own slope, predicts
forward with no model and no commands at all, and trips when the measurement is
heading out of the envelope. It is reported as `R3b` and it is the weakest
protection in the project: it has no attribution, no idea which command caused
anything, and it has to wait for the process to physically start moving. It is
also the only thing left on an encrypted channel.

## Reading the results table

Four outcomes, and they are not points on a scale.

`refused` means the command never reached the device. `recovered` means it
reached the device and the guard pulled the plant back afterwards, which
requires the process to have moved far enough to notice. `damaged` means the
consequence stood. `alarmed` means the guard objected to something this model
has no way to damage.

The two attacks worth following are the overflow and the set-point write,
because they fail differently.

The overflow is prevented in all three modes. Its commands are individually
legal, so no mode refuses them at the wire; what saves the tank is the
supervisor, and the supervisor works blind. An encrypted channel costs this
attack almost nothing, which is worth saying because it is the opposite of what
the headline suggests.

The set-point write is the one that separates the modes. Under `None` it is
refused on its range before it lands and the tank never moves. Under `Sign` it
is refused too, by cutting the channel, and then the operator cannot get back
in: every recovery write after that point fails. Under `SignAndEncrypt` it
lands, the plant's own control loop starts filling toward a target above the
top of the tank, the blind supervisor trips the pump repeatedly, the control
loop overrides each trip because the guard cannot see or stop its commands, and
the tank overflows anyway.

That is the encryption problem with a number on it rather than an argument. The
rules did not get worse. The traffic they run on disappeared.

## The numbers

What the guard could read, counting request and response chunks only:

| security mode | messages | bytes | legible | legible | bodies read | opaque |
| --- | --- | --- | --- | --- | --- | --- |
| None | 1375 | 146742 | 146742 | 100.0 % | 1361 | 0 |
| Sign | 1046 | 154011 | 154011 | 100.0 % | 1032 | 0 |
| SignAndEncrypt | 884 | 146528 | 13920 | 9.5 % | 0 | 870 |

The 9.5 % is the sixteen-byte prefix of every message and nothing else. Not one
request body was decoded, so not one write was judged.

What the guard did about each attack:

| scenario | None | Sign | SignAndEncrypt |
| --- | --- | --- | --- |
| overflow | recovered | recovered | recovered |
| parameter_tamper | refused | refused | recovered |
| setpoint_jump | refused | refused | damaged |
| valve_hammer | refused | refused | recovered |
| write_flood | refused | refused | alarmed |
| recon_browse | ignored | ignored | false alarm |

Ordinary traffic was never refused: 34, 28 and 31 writes across the three
no-attack episodes, none of them blocked, no rule fired and no trip issued.

Deciding a write costs p50 119 us, p95 198 us and p99 264 us over 341
decisions, on the two modes where there is anything to decide.

Two things in that table need reading carefully.

The denominators move between modes. The counterfactual run is a separate
episode over real sockets, so an attack that damages the plant unguarded in one
mode occasionally does not in another, and "damage prevented 4 of 4" and "3 of
3" in the summary are not the same denominator. The outcomes are stable across
runs; the counts are not, and anything quoted from here should carry that.

The `Sign` column looks as good as `None` and is not. Four of its five
refusals were carried out by cutting the channel, and in every one of those
four the operator's recovery writes after the attack window all failed. The
plant was saved and the operator was locked out of it.

## The cost of the only lever left

Two cells are worth more attention than the headline, because both are the
guard doing harm.

The reconnaissance episode browses the address space and reads every node. It
writes nothing, so there is nothing for a plausibility rule to judge and the
correct behaviour is to forward all of it and claim nothing. Under `None` and
`Sign` that is exactly what happens. Under `SignAndEncrypt` the only detector
left is the one counting message arrivals, and it cannot tell a read from a
write, so an enumeration sweep looks like a flood and the guard cuts the
channel. That is a false alarm with teeth: the session it cut is the operator's
own.

The same mechanism shows up wherever the guard refuses on a signed channel. It
cannot withhold one write and keep the session, so refusing means cutting, and
under this project's threat model the channel it cuts belongs to the operator
station the attacker is sitting on. Every refusal on a `Sign` channel in these
results costs the operator every write they would have made afterwards, and the
table counts them: the recovery writes after the attack window all fail.

A guard that can refuse a single frame is not a marginal improvement over one
that can only cut a connection. It is a different kind of device.

## What this does not show

The guard's own session is a short cut. It polls the device directly with its
own certificate, which means it needs credentials of its own on the control
network. A real deployment would have to issue them, and a device holding a
key that can write actuators is a device whose compromise hands over the
conduit.

There is a fourth option no cell here models, because it is a deployment
decision rather than a measurement: give the guard the device's private key, or
terminate the secure channel at the guard and open a second one onward. Either
turns the guard into an endpoint of the session instead of a witness to it.
That probably works. It also moves the plant's keys into the guard and makes
the guard the single thing worth attacking, and this project has not evaluated
that trade.

The blind rate detector counts message arrivals, which no mode hides, and that
is all it counts. It cannot tell a read from a write, so its budget has to cover
both, which makes it several times looser than the per-source write budget R2
uses when the traffic is readable. A polling historian would trip it.

A write frame is judged as a unit and refused as a unit, so a legitimate value
bundled into the same request as a bad one is refused with it. The same is true
of the Modbus write-multiple case, and for the same reason: the guard cannot
half-forward a request.

The security modes here are correctly configured. Certificates on both ends,
Basic256Sha256, and no anonymous endpoint left open beside the secure one. The
problem being demonstrated is not a misconfiguration.

Unlike the in-process evaluation, this runs over real sockets on a scaled
clock, so it is not reproducible to the sample. The number of writes an episode
produces moves by a few either way between runs, exactly as the device matrix
does. The outcomes are stable; the counts are not.

## Reproducing

```bash
python scripts/run_opcua.py
python scripts/run_opcua.py --scenarios none overflow setpoint_jump
python scripts/run_opcua.py --modes None SignAndEncrypt
python -m pytest tests/test_opcua.py
```

Certificates are self-signed test fixtures, generated on first use into
`results/opcua/certs` and reused after that; nothing validates a chain. The
full set is forty-two episodes, each with its own secure-channel handshake, and
takes several minutes.

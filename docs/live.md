# The device scanner and the live view

Two things live here. A scanner that asks every device whether it is still
answering, and a live view that narrates a run while it happens instead of
printing a table once it is over. They are in one document because the scanner
is the more interesting of the two and the view is how you see it work.

## Why a scanner changes anything

The site guard compares three independent measurements of the same power and
takes the median. That is a good design and it rests on an assumption nobody
was checking: that all three are still arriving.

A measurement whose communications link drops does not go away. SCADA holds the
last value it received and keeps serving it. Nothing in the observation says
the number is old. A frozen reading and a reading that agrees are the same
reading as far as a median is concerned.

So cut two of the three links. The two stale values are both stuck at whatever
the site was doing when their links died, which means they agree with each
other. The majority is now a majority of corpses, and the vote reaches the
conclusion its arithmetic demands: the one measurement still tracking reality
is the outlier, and B6 names it.

| Two links cut, site ramped down | Scanner informs the guard | Scanner does not |
| --- | --- | --- |
| Error in the guard's belief | −0.04 MW | +18.23 MW |
| Measurements counted | 1 of 3 | 3 of 3 |
| Source named as lying | none | Megapack telemetry sum |

`scripts/run_live.py --only site` runs both columns, the second as the control.
`tests/test_scan.py::test_two_stale_measurements_invert_the_majority_vote` is
the same thing as an assertion.

This is the threat model's stated failure — "an attacker who controls the field
devices themselves can make all three measurements agree on the same lie" —
reached without controlling any field device. Dropping two links is cheaper
than compromising two meters, and it produces the same inversion.

## What the fix does and what it costs

`SiteGuard.set_live_sources` tells the voter which measurements are still being
refreshed. Anything else stops counting.

The cost is quorum. Three sources can name a liar, because two agree and the
third does not. Two can notice a disagreement and have no grounds to attribute
it; preferring either reading would be a coin flip reported as a diagnosis.
One is no cross-check at all, which is the tank's predicament again. The guard
says which of those three situations it is in rather than carrying on as though
nothing had changed, and `VoteResult.can_name_outlier` is the flag that carries
it.

Three decisions inside that are worth knowing about.

**A stale source is never accused.** Nothing is integrated and nothing is named
while quorum is lost. Accumulating anyway would leave the CUSUMs primed, so
that the moment a third source returned one of them would cross immediately and
name a source on evidence gathered while there was no majority to measure
against. It would also, in the ordinary case, name a meter a liar for the crime
of not being there.

**Two sources take their mean, not the upper one.** The original index
arithmetic picked `ordered[len // 2]`, which for two values is the larger. With
no grounds to prefer either, silently taking the larger biases every downstream
limit check in one direction.

**An unprobed device counts as reachable.** Answering "down" for a device
nobody has looked at yet would drop every measurement out of the vote for the
first few sweeps of every run — a blind spot the scanner would have created by
itself, in the window where a plant is starting up.

## The scanner

`ScanTarget` names a device, how to probe it, and what losing it means.
`measurement_source` is the load-bearing field: set it, and losing this device
removes a vote. `critical` marks a device whose loss is a process-safety
condition rather than a monitoring nuisance; the scanner only records the flag.

Three probes, and the difference between them matters:

| Probe | What a clean result proves |
| --- | --- |
| `TcpProbe` | Something is listening on that port |
| `ModbusProbe` | Something spoke Modbus and answered the register we asked for |
| `CallbackProbe` | A model says so; never evidence about real hardware |

A probe records which of those it got, as `Evidence`, and a target can insist
on a minimum. The default is `ANSWERED` rather than a bare socket, because the
failure worth catching is a controller whose port still accepts while its scan
loop has stopped — the case a connect-only check calls healthy. There is a test
for exactly that: a listener that accepts and never replies satisfies
`TcpProbe` and fails `ModbusProbe`.

The state machine debounces in both directions and asymmetrically: three
consecutive failures to go down, two consecutive answers to come back. Slow to
condemn, slower to forgive. Sweeps run concurrently, because twenty-seven
devices at a one-second timeout is twenty-seven seconds of serial sweep, by
which time the first answer is older than the interval.

Timestamps come from the simulation clock so a device going quiet lines up with
the commands around it. Timeouts do not: a socket that waits one second waits
one real second whatever speed the scenario runs at, because that is a property
of the network rather than of the experiment.

### What is measured and what is modelled

The tank's controller and guard are listening processes and are probed for
real, by reading the level input register off each. The battery site is
twenty-seven objects in one process; probing the addresses in its topology
would report every one of them down. So the site is sensed through
`ModelledNetwork`, and every such row is stamped `Evidence.MODEL` and carries
`networked=False` through the event stream to both displays, which label it.

A device table that mixes measurements with model reads and does not say which
is worse than no table. Nothing here measures whether any of this works against
real hardware.

## The live view

One event stream, two renderers, neither of which may read the plant. Every
number on either display arrived as an event, so a disagreement between the
terminal and the browser is a rendering bug and never two opinions about the
same tank.

`EventBus.publish` never awaits. Each watcher has a bounded queue and a full
queue drops its oldest event rather than making the producer wait. A browser on
a bad connection therefore loses detail and the simulation keeps its timing;
back-pressure from a display into a control loop, in a project about control
timing, would be an unforced error. Drops are counted. The oldest goes rather
than the newest, because a watcher left looking at a frozen plant is the one
failure a live view must not have.

A watcher arriving late is briefed before it is streamed: the current scenario,
the device table, the latest state per plant, and a bounded tail of the feed.
A page opened halfway through a run draws a full screen immediately.

The terminal renderer redraws in place by homing the cursor and clearing each
line, rather than clearing the screen first, which shows a blank frame every
refresh and flickers. Outside a terminal it prints one line per event instead,
which is the mode a transcript or a CI log sees.

The browser renderer is one self-contained page: no CDN, no external fonts, no
framework. A control display that goes blank because a network is unavailable
would be a poor advertisement for a project about operational technology, and
the machines this would sit near often have no route to the internet. It is
served by a hand-rolled HTTP server over `asyncio.start_server`, bound to
loopback by default, because the page shows the state of a control system and
authenticates nobody.

## Running it

```bash
python scripts/run_live.py                 # tank, then the site twice
python scripts/run_live.py --only site     # just the measurement story
python scripts/run_live.py --no-web        # terminal only
python scripts/run_live.py --speed 25      # how fast the site scenario plays
python scripts/run_live.py --hold 120      # keep the page up after the run
```

The tank half runs at real speed and cannot be accelerated: the guard's
supervision loop sleeps on the wall clock, so running the plant faster would
have the guard sampling it proportionally less often and would measure the
wrong thing. The site half has no socket layer and is paced by the display.

## What this does not show

The scanner has never been pointed at real hardware. Twenty-five of the
twenty-seven site rows are model reads, and the two that are not are a
simulated controller and a proxy on loopback.

A probe that comes back clean proves that something answered. It does not prove
the device is healthy, that it is the device we think it is, or that the answer
came from the device rather than from somebody in the path. Anyone who can hold
a socket open and echo a canned response keeps a dead device looking alive, and
on a network the rest of this project assumes the attacker holds, that is not a
remote possibility. This is monitoring, not authentication, and nothing
downstream should read a green light as more than "we were answered".

The debounce means the guard hears about a lost measurement three sweeps late.
At the default one-second interval that is three seconds, which is inside the
site's own supervision cycle; at a longer interval it would not be.

The inversion result is one scenario, written by the same person who wrote the
fix for it.

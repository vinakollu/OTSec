# The storage-site add-on

Extends OTGuard from a single water tank to a utility-scale battery site of the
kind built around Megapack-class units. This document covers what was added, why
each rule has the shape it does, and where the design fails.

## Why a battery site, specifically

The tank version ended with a stated limitation. Its `stealthy_bias` attack —
slowly biasing the level transmitter — was undetectable, and the reason was
structural rather than a matter of tuning:

> Residual detectors bound an attacker's rate, not their eventual displacement.
> Closing it needs a physically independent second measurement, which is a
> design change rather than a parameter change.

A storage site has that second measurement, and a third. Site power is measured
by the POI revenue meter, by the sum of what the Megapacks report, and by the
protection relay's current transformers — three chains with different hardware,
different cabling, different vendors and different protocols. That redundancy is
already paid for on revenue and protection grounds. Using it for detection is
free, and it is what this add-on is built around.

## The site

Sixteen 1.927 MW / 3.916 MWh units — about 30.8 MW of inverter and 62 MWh —
behind a 20 MW contractual export limit and a 25 MVA transformer.

```
Megapacks (16) ──► LV bus ──► main transformer ──► POI breaker ──► grid
                      │                               │
              protection relay                  revenue meter
```

The fleet deliberately out-produces the interconnection, because that is how
these sites are built. It is also what makes the export limit a thing an
attacker can violate rather than a physical impossibility.

### Equipment and zones

Modelled as IEC 62443 zones and conduits over the Purdue levels:

| Level | Zone | Equipment |
| --- | --- | --- |
| 4 | enterprise | historian, market systems |
| 3.5 | dmz | firewall, jump server |
| 3 | supervisory / engineering | SCADA front end, HMI, engineering workstation |
| 2 | control | site controller |
| 1 | field | Megapack controllers, protection relay, revenue meter, switches |

A conduit is a permitted path carrying named protocols in a named direction; the
engineering path additionally requires traversal `via` the jump server. Rule B8
adjudicates against this.

**This models the segmentation, it does not implement it.** In a real deployment
the provenance of a write comes from the firewall's rule set and the bastion's
session records. Here it is a field on the command. B8's results show the rule
works given trustworthy provenance metadata; they do not show the metadata is
unforgeable.

## Physics

Three couplings, each of which becomes a rule.

**Energy is conserved.** State of charge is the integral of DC power over
capacity, with asymmetric charge and discharge efficiency. A reported SoC that
does not match the power a unit was commanded to deliver is a lie that no
protocol compromise can make true.

**Capability is state-dependent.** Discharge tapers below 10% SoC, charge tapers
above 90% and again in the cold (charging a cold lithium cell plates lithium
metal, so the curve is not a mirror image). Both taper with temperature. The
inverter is bounded by its apparent-power circle, and vars give way to watts —
so reactive power cannot be used to smuggle extra real power past a limit.

**Heat follows current and cooling is slow.** Losses go as the square of
apparent power; the thermal system removes heat proportionally to temperature
rise.

A command is clamped to capability *before* the energy and thermal states
integrate it. Modelling it the other way round would let a command the guard
blocked still do damage in the unguarded run, and the guard would collect credit
for preventing something that could not have happened.

### Where damage comes from

Normal full-power operation does not overheat a unit — SoC drains, power falls,
and the pack settles at 44 °C. The reachable thermal vector is **thermal
management shutdown**: the same duty with cooling commanded off passes the trip
in about thirty minutes. That is also the realistic one; BESS thermal events come
from cooling failure, not from dispatch.

### Deliberate simplifications

- **Thermal mass is compressed** to give a time constant of about twenty minutes
  rather than hours. The direction of that error is safe: a slower real plant
  gives the lookahead *more* warning, so the compressed model is the pessimistic
  case for detection.
- Lumped single-cell-equivalent per unit. No cell imbalance, no degradation over
  cycles, no inverter switching model.
- Grid frequency and fault current are exogenous. A 20 MW site does not move a
  synchronous grid, so treating frequency as an input is honest — and it is what
  gives rule B4 its context.
- The guard's model of the plant is wrong on purpose, by a few percent in every
  constant. A guard tested against a model identical to the plant measures
  nothing but its own arithmetic.

## The rules

| Rule | Name | Enforcement | What it rests on |
| --- | --- | --- | --- |
| B1 | capability | block | SoC- and temperature-derated limits, apparent-power circle |
| B2 | energy | alarm | SoC as the integral of accepted commands |
| B3 | balance | block | fleet conservation; transformer nameplate |
| B4 | ramp | block | grid-code ramp, conditioned on frequency |
| B5 | thermal | block | thermal lookahead and equilibrium |
| B6 | cross-source | alarm | three independent measurements, majority vote |
| B7 | interlock | block | synchronism check, latched lockout, fault corroboration |
| B8 | provenance | block | 62443 zones and conduits (**not physics**) |

### Three lessons carried forward from the tank

**The counterfactual test (B3, B5).** R3's lesson was that "does this command's
predicted trajectory violate the limit?" rejects the *corrective* command too,
because once a process is heading out of bounds every trajectory looks bad —
including the one that saves it. B3 and B5 object only when a candidate is
strictly worse than continuing what is already held. This is what lets
`curtailment_recovery` pass: every command in it is issued while over the limit,
and every one improves it.

**Directional lockout (B7).** R5's lesson: a lockout phrased as "the resulting
state must be inside the envelope" refuses every recovery action and strands the
plant. B7 latches against the direction that tripped.

**Detector, not tracker (B2).** R4's lesson: a filter with enough gain to follow
a transmitter absorbs an injected offset within two samples and goes quiet
exactly when it should be shouting. Low gain, CUSUM on the normalised residual,
latched alarm, open-loop dead reckoning once a unit is caught lying.

### What is new here

**B3 reasons about the aggregate.** The `aggregate_stealth` attack asks each of
sixteen units for 1.45 MW — comfortably inside a 1.927 MW capability, and exactly
the sort of value a per-device rule waves through. The sum is 23.2 MW against a
20 MW limit. Only a conservation law across the fleet can see it.

**B3 checks limits against iron.** The absolute test uses `poi_rating_mw`, the
transformer nameplate, not the writable `poi_limit_mw`. An attacker who raises
the export limit to 40 MW over REST with a valid engineer token gains nothing:
no authorisation makes 40 MW deliverable through a 25 MVA transformer.

**B4 uses physics as context, not as a threshold.** A slam from full charge to
full discharge is an attack with the grid at nominal and is the contracted
service during a frequency excursion. B4 opens its allowance by 6× outside the
normal frequency band. The `ramp_slam` attack and the `frequency_response`
benign scenario are the same command shape; only the grid separates them. An
attacker who wants the fast ramp must also fake a frequency excursion across the
relay and the meter.

**B5 checks equilibrium, not just the horizon.** With cooling off the thermal
time constant runs to hours, so 300 s of lookahead sees two degrees and stays
quiet while a unit is on its way to well past its trip. The equilibrium
temperature needs no horizon: if the commanded configuration settles beyond the
trip, the unit gets there eventually however slowly.

**B6 names the liar.** With one sensor, a model-versus-measurement disagreement
is ambiguous — either the sensor is spoofed or the model is wrong. With three
independent measurements a majority vote identifies the outlier, which is the
difference between "something is wrong" and "the revenue meter is lying, trust
the relay". Everything downstream then reads site power through
`trusted_power_mw`, so the guard keeps running on the remaining two rather than
going blind or believing the liar.

Comparing the three requires referring them to the same electrical point first.
The telemetry sum is measured at the LV bus and the other two at the POI, so the
voter converts through the guard's own model of the house load and transformer.
Getting this wrong makes the telemetry sum a permanent outlier and the vote
meaningless.

## Results

13 attacks, 7 benign scenarios, each run twice — enforcing, and watching but
powerless.

| Metric | Result |
| --- | --- |
| Detection rate | 13/13 |
| Damage avoidance | 5/5 attacks that damaged the site unguarded |
| Benign scenarios clean | 7/7 |
| Benign writes flagged | 0 of 3783 |
| Lying source named correctly | 1/1 |
| Decision latency | p50 144 µs, p95 206 µs, p99 250 µs |

Latency is 0.14% of a 100 ms dispatch cycle, over sixteen estimators and eight
rules.

**Two denominators, as in the tank version.** Suite-wide, 1200 of 7831
benign-labelled writes are flagged — but nearly all are the site controller's own
writes *inside attack scenarios*, refused after B2 or B6 has established that a
unit is lying about its state. Declining to honour set-points for a unit whose
telemetry is known false is the guard working. Quote the 0/3783 figure for
benign operation and the 1200/7831 alongside it; neither alone is honest.

### The headline experiment

`--sweeps` runs the meter bias at rates spanning 250×:

| ramp (mW/s) | detected | bias accumulated by then | named |
| --- | --- | --- | --- |
| 0.20 | 1309 s | 262 kW | POI meter |
| 0.50 | 556 s | 278 kW | POI meter |
| 1.00 | 298 s | 298 kW | POI meter |
| 2.00 | 166 s | 333 kW | POI meter |
| 5.00 | 78 s | 390 kW | POI meter |
| 10.0 | 46 s | 455 kW | POI meter |
| 50.0 | 14 s | 725 kW | POI meter |
| **1.0, voting disabled** | **never** | — | — |

The column that matters is the third. It stays between 262 and 725 kW while the
ramp rate changes by two and a half orders of magnitude, and the *slowest*
attacker is caught at the *smallest* displacement. Voting bounds how far an
attacker can move a measurement, not how fast — which is precisely the bound the
tank version could not achieve, and the control row shows the tank's blind spot
reproduced when voting is switched off.

## Where this fails

**A creeping aggregate.** B3's incremental test fires only when a command makes
an existing excursion worse. That is what stops it blocking a recovery, and it is
also an escape hatch:

| step (MW per unit per 20 s) | detected | peak MW over export limit |
| --- | --- | --- |
| 0.002 | never | 0.00 (too slow to matter) |
| **0.005** | **never** | **2.77** |
| 0.010 | 1300 s | 4.76 |
| 0.050 | 360 s | 4.89 |
| 0.200 | 160 s | 0.04 |

At 0.005 MW per unit per 20 s the attack is never detected and puts the site
2.77 MW over its export limit. Worse, in the band that *is* detected, the site
still reaches 4.8 MW over the limit first — detection is real but late. Only the
absolute transformer-rating test has no escape hatch, and by construction it does
not engage until the excursion is large. This is the direct analogue of the tank
project's 2 mm/s band and it has the same character: no threshold fixes it,
because tightening trades against the false-alarm rate that decides whether
operators leave the guard installed.

**B2 cannot separate a large re-anchor from a spoof.** Battery management systems
re-anchor their SoC estimate at known points, and the correction lands in one
sample. A spoof is the same shape — a step followed by an offset. What separates
them is persistence: the CUSUM only accumulates while the disagreement continues,
so a held offset is caught down to 2% within four seconds, while a one-sample
correction passes up to 6%. A single-sample correction larger than that raises a
false alarm. Real re-anchors are a few percent, so the boundary sits in a usable
place — but it is a boundary, not a proof.

**The threat model is load-bearing.** The attacker owns SCADA or the engineering
workstation. They cannot execute code on the Megapack controllers, alter the
cells, or reach the CTs. An attacker who *does* own the field devices can make
all three measurements agree on a lie and B6 fails completely. What the design
buys is that compromising three independent measurement chains simultaneously is
a much larger operation than writing a set-point — not that it is impossible.

**B8 trusts its inputs.** See the zones section above.

**13/13 is not a generalisation claim.** It is thirteen scenarios written by the
same person who wrote the rules, and several thresholds were set after looking at
them. The sweeps exist because they measure a boundary rather than a sample, and
the boundaries are where the honest limits are.

**Simulation only.** No real Megapack, no real relay, no real meter. Frames are
byte-exact where the protocol matters (DNP3 CRC is verified against the canonical
reset-link frame; GOOSE round-trips byte-identically) but GOOSE and PRP run over
an in-process virtual segment rather than a NIC, because raw layer-2 needs root.

## Protocols

| Protocol | What is real | What is modelled |
| --- | --- | --- |
| Modbus TCP | full framing, real sockets (from the tank version) | — |
| DNP3 | link/transport/application framing, 0x3D65 CRC, CROB and analog output, select-before-operate | no SAv5, no event classes, no file transfer |
| GOOSE | Ethernet/VLAN header, BER-encoded goosePdu, stNum/sqNum semantics, TTL | transport is an in-process segment |
| PRP | 6-octet redundancy control trailer, duplicate discard, A/B discrepancy | dual LAN is in-process |
| REST | roles, bearer tokens, endpoint authorisation | not a hardened HTTP stack |

Two of these carry security properties worth having independent of the physics:

**DNP3 select-before-operate** is a protocol-level plausibility constraint of the
same shape as a physics rule — the outstation does not need to know whether
opening a breaker is wise, only that nobody armed it. Comparing the OPERATE's
payload against the armed SELECT defeats an attacker who watches a legitimate
SELECT and substitutes their own OPERATE, with no key material involved.

**PRP is rule B6 one layer down.** A node sends every frame on two independent
LANs. An attacker on one LAN produces a frame with no matching copy, or two
copies that disagree. Both checks are free, because the frames are already being
compared by sequence number for duplicate discard. Same argument, same limit: an
attacker positioned on both paths defeats it.

## Running it

```bash
python -m pytest                              # full suite
python scripts/run_site_eval.py               # the 20 scenarios
python scripts/run_site_eval.py --sweeps      # + the boundary experiments
python scripts/run_site_eval.py --scenario soc_spoof --verbose
```

Figures and `site_metrics.json` land in `results/`.

"""A bump-in-the-wire guard for OPC UA, and an honest account of its limits.

The structure is the Modbus proxy's: listen, accept, relay to the device,
inspect every write on the way past, and run a second session of the guard's own
to poll the process and issue protective writes. What is new is that how much
of that works now depends on a setting neither the guard nor the attacker
controls — the security mode the device and its client negotiated.

Three modes, three different guards:

``None``
    Full inspection and inline refusal. A refused write never reaches the
    device, and the client gets ``BadUserAccessDenied`` for it and carries on.
    This costs some bookkeeping: dropping one request leaves the two ends
    disagreeing about how many messages have gone by, so the proxy renumbers
    the rest of the conversation in both directions.

``Sign``
    Full inspection, no inline refusal. Every write is readable and judgeable,
    and the guard cannot alter a single byte of the stream, because it cannot
    produce a signature over what it would have changed. It has two levers
    left: cut the channel, and write a protective command on its own session.

``SignAndEncrypt``
    No inspection. Sixteen bytes per message are legible and none of them say
    which node is being written or to what. The command-level guard is gone
    entirely. What survives is the part that never depended on reading anyone
    else's traffic: the guard polls the level itself, so it still sees the
    process leave its envelope and can still trip. An attack that does not move
    the process is invisible.

That last paragraph is the result worth taking away, and it is more specific
than "encryption breaks the guard". Encryption costs a bump-in-the-wire its
command-level authority and leaves its process-level supervision intact. Which
attacks that matters for is measured rather than argued: see ``docs/opcua.md``.

A deployment has a fourth option this proxy does not model, because it is a
deployment decision rather than a measurement: give the guard the device's
private key, or terminate the secure channel at the guard and open a second one
to the device. Either turns the guard into an endpoint, which means it is now
the thing holding the plant's keys and a single device whose compromise hands
over the whole conduit. The project has not evaluated that trade and should not
pretend to have.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import logging
import struct
import time
from collections import deque
from dataclasses import dataclass, field

from asyncua import Client, ua
from asyncua.common.utils import Buffer
from asyncua.ua import ua_binary

from ..clock import SimClock
from ..config import Config
from ..guard import Command, Observation, PhysicsGuard, Verdict
from ..guard.types import RuleFinding
from ..guard.guard import ProtectiveAction, SupervisionEvent
from ..modbus.devicemap import PointRole
from ..modbus.inventory import WireDecision, WirePolicy
from .certs import CertSet
from .framing import BODY_OFFSET, Message, SecurityMode, Visibility, frame
from .nodes import LEVEL_POINT, NodeMap

log = logging.getLogger(__name__)


@dataclass
class WriteRecord:
    """One write message the guard saw, and what it did about it.

    ``objected`` and ``forwarded`` are separate on purpose. Running the proxy
    with ``enforce=False`` is how the evaluation gets its "what would have
    happened anyway" column, and it must change only what the guard *does*,
    never what it evaluates. Collapsing the two into one flag is how this
    project has twice produced an ablation that measured the wrong thing.
    """

    t: float
    readable: bool
    node: str = ""
    value: float | None = None
    objected: bool = False
    blocked: bool = False
    forwarded: bool = True
    wire_reason: WireDecision | None = None
    verdicts: list[Verdict] = field(default_factory=list)
    detail: str = ""

    @property
    def rule_ids(self) -> list[str]:
        return [r for v in self.verdicts for r in v.rule_ids]

    @property
    def blocked_by_rules(self) -> bool:
        return self.blocked and self.wire_reason is None


@dataclass
class ProxyStats:
    messages_relayed: int = 0
    writes_decoded: int = 0
    writes_blocked: int = 0
    writes_alarmed: int = 0
    wire_blocked: int = 0
    trips_issued: int = 0
    blind_trips: int = 0
    polls: int = 0
    integrity_alarm_t: float | None = None
    severed_at: float | None = None
    sever_reason: str = ""
    decision_latency_us: list[float] = field(default_factory=list)
    wire_reasons: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        return (
            f"relayed={self.messages_relayed} writes_read={self.writes_decoded} "
            f"blocked={self.writes_blocked} wire_blocked={self.wire_blocked} "
            f"alarmed={self.writes_alarmed} trips={self.trips_issued} "
            f"severed={'yes' if self.severed_at is not None else 'no'}"
        )


@dataclass
class Channel:
    """One client connection's relay state.

    Per-connection rather than per-proxy because the experiment runs an
    operator station and an attacker at the same time, which is what a plant
    looks like. Sequence numbering, the count of withheld requests and the
    blind arrival-rate window all belong to one secure channel and mean nothing
    across two.
    """

    name: str
    client_writer: asyncio.StreamWriter
    server_writer: asyncio.StreamWriter
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    dropped: int = 0          # requests withheld from the device
    injected: int = 0         # responses fabricated for the client
    last_down_seq: int = 0
    arrivals: deque[float] = field(default_factory=deque)
    severed: bool = False


class OpcUaGuardProxy:
    """Transparent OPC UA TCP proxy whose powers depend on the security mode."""

    def __init__(
        self,
        config: Config,
        mode: SecurityMode,
        target_host: str = "127.0.0.1",
        target_port: int = 4842,
        listen_host: str = "127.0.0.1",
        listen_port: int = 4840,
        certs: CertSet | None = None,
        guard: PhysicsGuard | None = None,
        policy: WirePolicy | None = None,
        clock: SimClock | None = None,
        enforce: bool = True,
        initial_level_m: float | None = None,
        poll_period_s: float = 0.5,
        blind_rate_window_s: float = 2.0,
        blind_rate_budget: int = 24,
    ) -> None:
        self.config = config
        self.mode = mode
        self.target_host = target_host
        self.target_port = target_port
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.certs = certs
        self.policy = policy or WirePolicy()
        self.clock = clock or SimClock()
        self.enforce = enforce
        self.poll_period_s = poll_period_s
        self.map = NodeMap()

        # What a guard on an encrypted channel has left: message arrivals. The
        # budget has to cover reads as well as writes, because it cannot tell
        # them apart, which is why it is several times looser than R2's
        # per-source write budget. That looseness is the measurement, not a
        # tuning choice to be improved away.
        self.blind_rate_window_s = blind_rate_window_s
        self.blind_rate_budget = blind_rate_budget

        self.guard = guard or PhysicsGuard(config, initial_level_m=initial_level_m)
        self.stats = ProxyStats()
        self.writes: list[WriteRecord] = []
        self.events: list[SupervisionEvent] = []
        self.visibility = Visibility()

        self._server: asyncio.AbstractServer | None = None
        self._supervisor: asyncio.Task | None = None
        self._poll_client: Client | None = None
        self._nodes: dict[str, object] = {}
        self._level_m: float | None = None

        self.channels: list[Channel] = []
        self.first_detection_t: float | None = None
        self._readings: deque[tuple[float, float]] = deque(maxlen=16)
        # Rearm is tracked per direction, for the reason PhysicsGuard already
        # had to learn: shutting the pump to stop an overflow leaves the outlet
        # open, which is itself a dry-out configuration, and a single timer
        # swallows the trip that would catch it. This started out as one
        # timestamp and the tank ran dry at 0.00 m in the write-flood episode.
        self._blind_trip_t: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------
    def _now(self) -> float:
        return self.clock.now()

    def _decode_write(self, message: Message):
        """Return the decoded ``WriteRequest``, or a reason it is not available.

        When the channel is encrypted this does not try. A guard that pattern
        matches inside ciphertext and acts on what it finds is worse than one
        that reports it cannot see: the first kind is wrong without knowing it.
        """
        if not self.mode.body_is_readable:
            return None, "encrypted"
        if not message.is_final:
            # A multi-chunk request cannot be judged from one chunk, and
            # reassembling it would mean holding part of a write while the rest
            # arrives. Treated as unjudgeable, which defaults to refusing.
            return None, "chunked"
        payload = message.body
        try:
            node_id = ua_binary.nodeid_from_binary(Buffer(payload))
        except Exception:
            return None, "unparseable"
        if getattr(node_id, "Identifier", None) != ua.ObjectIds.WriteRequest_Encoding_DefaultBinary:
            return None, "not_a_write"
        try:
            request = ua_binary.struct_from_binary(ua.WriteRequest, Buffer(payload))
        except Exception:
            return None, "undecodable"
        return request, ""

    def _judge(self, request) -> WriteRecord:
        """Run the wire policy and then the physics rules over one write frame.

        A frame is judged as a unit and refused as a unit. That has an honest
        cost: a legitimate value bundled into the same frame as a bad one is
        refused with it. The same is true of the Modbus write-multiple case and
        for the same reason — the guard cannot half-forward a request.
        """
        now = self._now()
        record = WriteRecord(t=now, readable=True, forwarded=True)
        started = time.perf_counter()

        values = list(request.Parameters.NodesToWrite)
        described: list[tuple[object, float]] = []
        for item in values:
            point = self.map.lookup(item.NodeId)
            name = getattr(item.NodeId, "Identifier", "?")
            record.node = str(name) if not record.node else f"{record.node},{name}"
            if point is None:
                return self._refuse(record, WireDecision.UNMAPPED_POINT,
                                    f"write to {name}, which the node map does not describe",
                                    started)
            if point.role is PointRole.PARAMETER:
                return self._refuse(record, WireDecision.PARAMETER_WRITE,
                                    f"write to {name}: a commissioning parameter, "
                                    "which changes what every later command means",
                                    started)
            if point.kind is None:
                return self._refuse(record, WireDecision.UNJUDGEABLE_WRITE,
                                    f"write to {name} carries no physical meaning the rules know",
                                    started)
            try:
                value = float(item.Value.Value.Value)
            except (TypeError, ValueError, AttributeError):
                return self._refuse(record, WireDecision.UNPARSEABLE,
                                    f"write to {name} is not a number", started)
            described.append((point, value))

        if not described:
            return self._refuse(record, WireDecision.UNPARSEABLE,
                                "write frame carries no values", started)

        record.value = described[-1][1]
        for point, value in described:
            verdict = self.guard.check(Command(t=now, kind=point.kind, value=value, source="opcua"))
            record.verdicts.append(verdict)

        record.blocked = any(not v.allowed for v in record.verdicts)
        record.objected = record.blocked or any(v.flagged for v in record.verdicts)
        if record.objected:
            record.detail = "; ".join(str(f) for v in record.verdicts for f in v.findings)
        if record.objected and not record.blocked:
            self.stats.writes_alarmed += 1
        record.forwarded = not (record.blocked and self.enforce)
        if record.blocked and self.enforce:
            self.stats.writes_blocked += 1
        self.stats.decision_latency_us.append((time.perf_counter() - started) * 1e6)
        return record

    def _refuse(self, record: WriteRecord, reason: WireDecision, detail: str,
                started: float) -> WriteRecord:
        self.stats.decision_latency_us.append((time.perf_counter() - started) * 1e6)
        record.detail = detail
        if self.policy.permits(reason):
            # The policy lets this defect through. The write still has to reach
            # the physics rules, which is the whole content of the ablation:
            # a permitted defect that returns early here would disable the
            # comparison baseline rather than the policy.
            record.forwarded = True
            return record
        record.objected = True
        record.blocked = True
        record.wire_reason = reason
        record.forwarded = not self.enforce
        self.stats.wire_blocked += 1
        self.stats.wire_reasons[reason.value] = self.stats.wire_reasons.get(reason.value, 0) + 1
        return record

    # ------------------------------------------------------------------
    # Relay
    # ------------------------------------------------------------------
    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        try:
            up_reader, up_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )
        except OSError:
            writer.close()
            return
        peer = writer.get_extra_info("peername") or ("?", 0)
        channel = Channel(
            name=f"{peer[0]}:{peer[1]}", client_writer=writer, server_writer=up_writer
        )
        self.channels.append(channel)
        try:
            await asyncio.gather(
                self._upstream(reader, channel),
                self._downstream(up_reader, channel),
                return_exceptions=True,
            )
        finally:
            for w in (writer, up_writer):
                with contextlib.suppress(Exception):
                    w.close()

    async def _messages(self, reader: asyncio.StreamReader):
        buffer = b""
        while True:
            try:
                chunk = await reader.read(65536)
            except (ConnectionResetError, asyncio.IncompleteReadError, OSError):
                return
            if not chunk:
                return
            buffer += chunk
            messages, buffer = frame(buffer)
            for message in messages:
                yield message

    async def _upstream(self, reader: asyncio.StreamReader, channel: Channel) -> None:
        """Client to device: the direction every command travels."""
        async for message in self._messages(reader):
            if channel.severed:
                return
            if message.is_message_chunk:
                forward = await self._inspect(message, channel)
            else:
                # The handshake and the channel-opening request. OPN carries the
                # client's certificate in the secure modes, which is real
                # identity evidence this guard does not act on: it has none of
                # the channel's keys, so a certificate it reads off the wire is
                # a certificate it cannot tell from a replay.
                self.visibility.record(message, body_readable=True)
                forward = True
            if not forward:
                continue
            raw = message.raw
            if message.uses_symmetric_header and channel.dropped:
                # The device counts the messages it has seen on this channel.
                # Having withheld some, the guard has to close the gap or the
                # device drops the connection on the next one it reads.
                raw = message.renumbered(message.sequence_number - channel.dropped)
            try:
                channel.server_writer.write(raw)
                await channel.server_writer.drain()
            except (ConnectionResetError, OSError):
                return
            self.stats.messages_relayed += 1

    async def _inspect(self, message: Message, channel: Channel) -> bool:
        """Decide one client-to-device message. True to forward it."""
        self._note_arrival(message, channel)
        if channel.severed:
            return False
        request, why = self._decode_write(message)

        if request is None:
            readable = self.mode.body_is_readable
            self.visibility.record(
                message,
                body_readable=readable,
                decoded=readable and why == "not_a_write",
            )
            if why in ("encrypted", "not_a_write"):
                return True
            # Readable but not judgeable: the wire policy decides, and it
            # defaults to refusing for the same reason it does on Modbus.
            reason = {
                "chunked": WireDecision.UNJUDGEABLE_WRITE,
                "unparseable": WireDecision.UNPARSEABLE,
                "undecodable": WireDecision.UNPARSEABLE,
            }[why]
            record = self._refuse(
                WriteRecord(t=self._now(), readable=readable),
                reason, f"message not judgeable: {why}", time.perf_counter(),
            )
            self.writes.append(record)
            if record.objected:
                self._note_detection(record.t)
            if record.forwarded:
                return True
            return await self._deny(message, None, record, channel)

        self.stats.writes_decoded += 1
        self.visibility.record(message, body_readable=True, decoded=True, is_write=True)
        record = self._judge(request)
        self.writes.append(record)
        if record.objected:
            self._note_detection(record.t)
        if record.forwarded:
            return True
        return await self._deny(message, request, record, channel)

    def _note_arrival(self, message: Message, channel: Channel) -> None:
        """The blind detector: message arrivals, which no mode hides.

        Only consulted when the channel is encrypted, because when the guard can
        read the traffic R2 does this job properly — per source, over writes
        only, and able to say which actuator was being hammered.
        """
        now = self._now()
        channel.arrivals.append(now)
        while channel.arrivals and now - channel.arrivals[0] > self.blind_rate_window_s:
            channel.arrivals.popleft()
        if self.mode.body_is_readable:
            return
        if len(channel.arrivals) <= self.blind_rate_budget:
            return
        self._note_detection(now)
        if not self.enforce or channel.severed:
            return
        channel.severed = True
        self.stats.severed_at = now
        self.stats.sever_reason = (
            f"{len(channel.arrivals)} messages in {self.blind_rate_window_s:g}s from "
            f"{channel.name} on an encrypted channel, above the budget; contents unknown"
        )

    async def _deny(self, message: Message, request, record: WriteRecord,
                    channel: Channel) -> bool:
        """Carry out a refusal with whatever the security mode leaves available."""
        if self.mode.can_rewrite and request is not None:
            await self._inject_refusal(message, request, channel)
            channel.dropped += 1
            return False
        # Everything else: withholding a message without answering it hangs the
        # client, and on a signed channel the guard cannot answer in the
        # device's voice or renumber what follows. The channel is the only
        # thing left to take away.
        channel.severed = True
        self.stats.severed_at = self._now()
        detail = record.detail or "refused write"
        self.stats.sever_reason = (
            detail if self.mode.can_rewrite
            else f"{detail} — signed channel, so the only refusal left is to cut it"
        )
        with contextlib.suppress(Exception):
            channel.client_writer.close()
        return False

    async def _inject_refusal(self, message: Message, request, channel: Channel) -> None:
        """Answer a withheld write with ``BadUserAccessDenied``, in the device's voice.

        Only possible on an unsecured channel, and that is the point. The
        response is framed by hand because the guard is not a party to the
        session: it has no session key, no sequence state of its own and no
        standing to open one.
        """
        response = ua.WriteResponse()
        response.ResponseHeader.RequestHandle = request.RequestHeader.RequestHandle
        response.ResponseHeader.Timestamp = datetime.datetime.now(datetime.timezone.utc)
        response.Results = [
            ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
            for _ in request.Parameters.NodesToWrite
        ]
        body = ua_binary.struct_to_binary(response)
        async with channel.lock:
            channel.injected += 1
            sequence = channel.last_down_seq + 1
            channel.last_down_seq = sequence
            out = (
                b"MSG" + b"F"
                + struct.pack("<I", BODY_OFFSET + len(body))
                + struct.pack(
                    "<IIII", message.channel_id, message.token_id,
                    sequence, message.request_id,
                )
                + body
            )
            with contextlib.suppress(ConnectionResetError, OSError):
                channel.client_writer.write(out)
                await channel.client_writer.drain()

    async def _downstream(self, reader: asyncio.StreamReader, channel: Channel) -> None:
        """Device to client: responses, and the sequence numbers that must add up."""
        async for message in self._messages(reader):
            raw = message.raw
            try:
                async with channel.lock:
                    if message.uses_symmetric_header:
                        sequence = message.sequence_number + channel.injected
                        channel.last_down_seq = sequence
                        if channel.injected:
                            raw = message.renumbered(sequence)
                    channel.client_writer.write(raw)
                    await channel.client_writer.drain()
            except (ConnectionResetError, OSError):
                return
            if channel.severed:
                return

    # ------------------------------------------------------------------
    # The guard's own session
    # ------------------------------------------------------------------
    async def _open_poll_session(self) -> None:
        from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256

        from .certs import GUARD_URI

        url = f"opc.tcp://{self.target_host}:{self.target_port}/otguard/tank/"
        client = Client(url, timeout=10)
        client.application_uri = GUARD_URI
        if self.mode is not SecurityMode.NONE:
            if self.certs is None:
                raise ValueError("a secure mode needs certificates for the guard too")
            await client.set_security(
                SecurityPolicyBasic256Sha256,
                certificate=self.certs.guard.cert_str,
                private_key=self.certs.guard.key_str,
                server_certificate=self.certs.device.cert_str,
                mode=(
                    ua.MessageSecurityMode.Sign
                    if self.mode is SecurityMode.SIGN
                    else ua.MessageSecurityMode.SignAndEncrypt
                ),
            )
        await client.connect()
        self._poll_client = client
        for point in self.map:
            self._nodes[point.identifier] = client.get_node(
                ua.NodeId(point.identifier, self.map.namespace_index)
            )

    async def _supervise_loop(self) -> None:
        """Poll the level on the guard's own session, estimate, trip if needed.

        This is the part of the guard that does not care what the security mode
        is. It reads the process, not the conversation, so an encrypted channel
        costs it nothing. It is also the only part left under SignAndEncrypt,
        and the experiment is largely a measurement of how much that is worth.
        """
        try:
            while True:
                try:
                    level = float(await self._nodes[LEVEL_POINT].read_value())
                except Exception:
                    await self.clock.sleep(self.poll_period_s)
                    continue
                now = self._now()
                self._level_m = level
                self.stats.polls += 1
                self._readings.append((now, level))

                event = self.guard.observe(Observation(now, level))
                if (self.guard.estimator.integrity_alarm
                        and self.stats.integrity_alarm_t is None):
                    self.stats.integrity_alarm_t = now
                if event is not None:
                    self.events.append(event)
                    # The model-based lookahead is only trustworthy when the
                    # guard has seen the commands that produced the movement.
                    # On an encrypted channel it has seen none, so its verdict
                    # is recorded and not acted on; see _blind_supervise.
                    if self.mode.body_is_readable:
                        self._note_detection(event.t)
                        if self.enforce and event.action is not None:
                            await self._apply_trip(event)
                if not self.mode.body_is_readable:
                    await self._blind_supervise(now, level)
                await self.clock.sleep(self.poll_period_s)
        except asyncio.CancelledError:
            raise

    async def _blind_supervise(self, t: float, level: float) -> None:
        """An envelope check from the reading alone, for traffic it cannot read.

        This exists because of what the experiment measured. The guard's normal
        lookahead integrates a model forward under the commands it has
        forwarded. On an encrypted channel it forwards commands it never read,
        so that model says both actuators are shut. When the level then rises,
        the consistency check reaches the only conclusion its premise allows:
        the transmitter is lying. It goes open loop, freezes its estimate at the
        last value it believed, and watches the tank overflow while holding a
        CUSUM in the thousands and a level estimate of 0.99 m.

        That is not a tuning problem. The premise "if the model and the sensor
        disagree, suspect the sensor" is sound only for a guard that sees every
        command, and an encrypted channel is exactly the case where it does not.

        So when the guard knows it is command-blind it stops reasoning from the
        model and falls back to the reading and the reading's own slope. No
        model, no commands, no attribution: a trip when the measured level is
        heading out of the envelope. It is the weakest protection in the project
        and the only one that survives an encrypted channel, and the lead time
        it gets is worth measuring against what the readable modes get, because
        it has to wait for the process to actually start moving.
        """
        cfg = self.config.guard.supervision
        if not cfg.enabled:
            return
        high = self.config.safety.level_max_m - self.config.guard.prediction.margin_m
        low = self.config.safety.level_min_m + self.config.guard.prediction.margin_m

        slope = 0.0
        if len(self._readings) >= 2:
            t0, l0 = self._readings[0]
            if t - t0 > 1e-6:
                slope = (level - l0) / (t - t0)
        reach = level + slope * cfg.horizon_s

        breach_high = level > high or reach > high
        breach_low = level < low or reach < low
        if not (breach_high or breach_low):
            return

        direction = "high" if breach_high else "low"
        previous = self._blind_trip_t.get(direction)
        if previous is not None and (t - previous) < cfg.rearm_after_s:
            return
        self._blind_trip_t[direction] = t
        self._note_detection(t)
        detail = (
            f"measured level {level:.3f} m moving at {slope * 1000:+.0f} mm/s reaches "
            f"{reach:.3f} m within {cfg.horizon_s:g}s (limit "
            f"{high if breach_high else low:.2f} m); the channel is encrypted, so "
            "there is no command to attribute this to and none to refuse"
        )
        finding = RuleFinding("R3b", "blind supervision", detail)
        action = ProtectiveAction(
            t=t,
            pump_cmd_pct=0.0 if breach_high else None,
            valve_cmd_pct=0.0 if breach_low else None,
            reason=detail,
        )
        event = SupervisionEvent(t=t, findings=[finding], action=action)
        self.events.append(event)
        if self.enforce:
            await self._apply_trip(event)
            self.stats.blind_trips += 1

    async def _apply_trip(self, event: SupervisionEvent) -> None:
        action = event.action
        if action is None:
            return
        for identifier, value in (
            ("Tank.PumpCommand", action.pump_cmd_pct),
            ("Tank.ValveCommand", action.valve_cmd_pct),
        ):
            if value is None:
                continue
            with contextlib.suppress(Exception):
                await self._nodes[identifier].write_value(
                    ua.DataValue(ua.Variant(float(value), ua.VariantType.Double))
                )
        self.stats.trips_issued += 1

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------
    def _note_detection(self, t: float) -> None:
        if self.first_detection_t is None:
            self.first_detection_t = t

    @property
    def detected(self) -> bool:
        return self.first_detection_t is not None

    @property
    def legible_fraction(self) -> float:
        return self.visibility.legible_fraction

    def reset_scoring(self) -> None:
        """Forget everything scored so far, keeping the guard's state estimate.

        The episode is scored from the end of warm-up, and warm-up happens
        after the session is up, so everything the handshake and the settling
        period produced has to be cleared before counting starts.
        """
        self.guard.acknowledge()
        self.guard.reset_log()
        self.writes.clear()
        self.events.clear()
        self.first_detection_t = None
        self.stats.severed_at = None
        self.stats.sever_reason = ""
        self.stats.integrity_alarm_t = None
        self.stats.blind_trips = 0
        self._blind_trip_t.clear()
        self._readings.clear()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        self.first_detection_t = None
        await self._open_poll_session()
        self._server = await asyncio.start_server(
            self._handle_client, self.listen_host, self.listen_port
        )
        self._supervisor = asyncio.create_task(self._supervise_loop())

    async def stop(self) -> None:
        if self._supervisor is not None:
            self._supervisor.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._supervisor
            self._supervisor = None
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        if self._poll_client is not None:
            with contextlib.suppress(Exception):
                await self._poll_client.disconnect()
            self._poll_client = None

    async def __aenter__(self) -> "OpcUaGuardProxy":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()

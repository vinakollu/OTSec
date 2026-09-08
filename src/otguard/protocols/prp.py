"""PRP (IEC 62439-3) — parallel redundancy, and what it gives security for free.

PRP is an availability mechanism. A sending node puts *the same frame on two
independent LANs* at the same instant; the receiver takes whichever copy arrives
first and discards the duplicate. There is no failover delay because there was
never a failure to detect — both paths were always carrying the traffic.

Each copy carries a 6-octet Redundancy Control Trailer appended after the
payload:

    ┌────────────────┬──────────────┬─────────────────┐
    │ sequence (16b) │ LanId (4b)   │ LSDU size (12b) │  + PRP suffix 0x88FB
    └────────────────┴──────────────┴─────────────────┘

The sequence number is per-source and shared between the two copies, which is
what lets the receiver pair them up.

The security consequence is the reason this module exists. An attacker is
almost always on *one* LAN — they compromised a switch, or patched into one
ring, or spoofed from a host with a single connection. When they inject a frame,
it appears on LAN A with no matching copy on LAN B; when they modify a frame in
transit, the two copies disagree at the same sequence number. Neither is subtle,
and neither requires knowing anything about what the frame means.

This is the same argument as rule B6, one layer down. B6 catches a lying
*measurement* by comparing three sensors; PRP catches a lying *frame* by
comparing two network paths. Both work because the attacker has to compromise
every independent copy simultaneously to stay consistent, and independence is
expensive to defeat.

The honest limit: an attacker positioned to inject on both LANs — a compromised
end node, or a doubly-attached device — produces two consistent copies and
defeats this entirely. PRP raises the bar to "compromise both paths", it does
not authenticate anything.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum

PRP_SUFFIX = 0x88FB
RCT_SIZE = 6


class LanId(IntEnum):
    A = 0xA
    B = 0xB


@dataclass(frozen=True)
class RedundancyControlTrailer:
    """The 6 octets PRP appends to every frame."""

    sequence: int
    lan: LanId
    lsdu_size: int

    def encode(self) -> bytes:
        if not 0 <= self.lsdu_size < 0x1000:
            raise ValueError("LSDU size does not fit in 12 bits")
        lan_and_size = ((int(self.lan) & 0xF) << 12) | (self.lsdu_size & 0x0FFF)
        return struct.pack(">HHH", self.sequence & 0xFFFF, lan_and_size, PRP_SUFFIX)

    @classmethod
    def decode(cls, raw: bytes) -> "RedundancyControlTrailer":
        if len(raw) < RCT_SIZE:
            raise ValueError("truncated PRP trailer")
        sequence, lan_and_size, suffix = struct.unpack(">HHH", raw[-RCT_SIZE:])
        if suffix != PRP_SUFFIX:
            raise ValueError(f"not a PRP trailer: suffix 0x{suffix:04X}")
        return cls(
            sequence=sequence,
            lan=LanId((lan_and_size >> 12) & 0xF),
            lsdu_size=lan_and_size & 0x0FFF,
        )


def append_rct(payload: bytes, sequence: int, lan: LanId) -> bytes:
    """Wrap a payload as one PRP copy.

    ``lsdu_size`` counts the payload plus the trailer, which is the definition
    in the standard and is easy to get wrong by six.
    """
    trailer = RedundancyControlTrailer(
        sequence=sequence, lan=lan, lsdu_size=len(payload) + RCT_SIZE
    )
    return payload + trailer.encode()


def strip_rct(frame: bytes) -> tuple[bytes, RedundancyControlTrailer]:
    trailer = RedundancyControlTrailer.decode(frame)
    return frame[:-RCT_SIZE], trailer


@dataclass
class PrpAnomaly:
    """A discrepancy between the two LANs."""

    kind: str          # "single_lan" | "content_mismatch" | "sequence_gap"
    detail: str
    sequence: int
    lan: LanId | None = None

    def __str__(self) -> str:
        return f"[PRP {self.kind}] {self.detail}"


@dataclass
class _PendingFrame:
    payload: bytes
    lan: LanId
    t: float


class PrpNode:
    """A doubly-attached node: duplicate discard plus discrepancy reporting.

    A stock PRP implementation only needs to answer "have I seen this sequence
    number before?". This one also keeps the first copy's *payload* so it can
    answer "did the second copy say the same thing?", and reports a frame that
    arrived on only one LAN once the pairing window closes.

    Both of those are free — the frames are already being received and already
    being compared by sequence number. That is what makes PRP attractive as a
    detection surface: the redundancy is being paid for on availability grounds
    whether or not anyone uses it for security.
    """

    def __init__(self, pair_window_s: float = 0.05, drop_window: int = 512) -> None:
        self.pair_window_s = pair_window_s
        self.drop_window = drop_window
        self._pending: dict[int, _PendingFrame] = {}
        self._delivered: dict[int, float] = {}
        self.anomalies: list[PrpAnomaly] = []
        self.delivered_count = 0
        self.discarded_duplicates = 0

    def receive(self, frame: bytes, lan: LanId, t: float) -> bytes | None:
        """Accept one copy. Returns the payload on first delivery, else ``None``."""
        payload, trailer = strip_rct(frame)
        seq = trailer.sequence

        if trailer.lan is not lan:
            self.anomalies.append(
                PrpAnomaly(
                    "content_mismatch",
                    f"frame arrived on LAN {lan.name} but its trailer claims "
                    f"LAN {trailer.lan.name}",
                    seq,
                    lan,
                )
            )

        pending = self._pending.get(seq)
        if pending is None:
            self._pending[seq] = _PendingFrame(payload=payload, lan=lan, t=t)
            self._delivered[seq] = t
            self.delivered_count += 1
            self._evict(t)
            return payload

        # The pair has arrived. This is the check a plain PRP node does not make.
        if pending.lan is lan:
            self.anomalies.append(
                PrpAnomaly(
                    "content_mismatch",
                    f"two copies of sequence {seq} on the same LAN {lan.name}; "
                    f"a doubly-attached node sends one copy per LAN",
                    seq,
                    lan,
                )
            )
        elif pending.payload != payload:
            self.anomalies.append(
                PrpAnomaly(
                    "content_mismatch",
                    f"LAN A and LAN B disagree at sequence {seq}: "
                    f"{len(pending.payload)}B vs {len(payload)}B, "
                    f"differing from octet {_first_difference(pending.payload, payload)} — "
                    f"one path has been modified in transit",
                    seq,
                    lan,
                )
            )
        self.discarded_duplicates += 1
        self._pending.pop(seq, None)
        self._evict(t)
        return None

    def _evict(self, t: float) -> None:
        """Close the pairing window on frames whose partner never arrived."""
        expired = [
            seq
            for seq, pending in self._pending.items()
            if t - pending.t > self.pair_window_s
        ]
        for seq in expired:
            pending = self._pending.pop(seq)
            self.anomalies.append(
                PrpAnomaly(
                    "single_lan",
                    f"sequence {seq} arrived only on LAN {pending.lan.name}; "
                    f"no matching copy within {self.pair_window_s * 1000:.0f} ms — "
                    f"injected on one path, or that path has failed",
                    seq,
                    pending.lan,
                )
            )
        if len(self._delivered) > self.drop_window:
            oldest = sorted(self._delivered.items(), key=lambda kv: kv[1])
            for seq, _ in oldest[: len(oldest) - self.drop_window]:
                self._delivered.pop(seq, None)

    def flush(self, t: float) -> list[PrpAnomaly]:
        """Force the pairing window closed. Call at end of run."""
        before = len(self.anomalies)
        self._evict(t + self.pair_window_s + 1.0)
        return self.anomalies[before:]


class PrpLink:
    """A sender that puts every frame on both LANs, and a fault injector."""

    def __init__(self) -> None:
        self.sequence = 0
        self.lan_a: list[tuple[float, bytes]] = []
        self.lan_b: list[tuple[float, bytes]] = []

    def send(self, payload: bytes, t: float) -> tuple[bytes, bytes]:
        self.sequence = (self.sequence + 1) & 0xFFFF
        a = append_rct(payload, self.sequence, LanId.A)
        b = append_rct(payload, self.sequence, LanId.B)
        self.lan_a.append((t, a))
        self.lan_b.append((t, b))
        return a, b

    def inject(self, payload: bytes, t: float, lan: LanId, sequence: int | None = None) -> bytes:
        """Put a frame on one LAN only — what an attacker on a single path does."""
        seq = self.sequence + 1 if sequence is None else sequence
        frame = append_rct(payload, seq, lan)
        (self.lan_a if lan is LanId.A else self.lan_b).append((t, frame))
        return frame


def _first_difference(a: bytes, b: bytes) -> int:
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b))

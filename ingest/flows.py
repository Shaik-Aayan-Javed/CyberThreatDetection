"""Packet -> flow aggregation and tumbling windows.

Two objects live here:

  FlowTable   long-lived, bidirectional 5-tuple table with idle expiry
  Windower    slices the packet stream into fixed tumbling windows

The Windower is what makes the pipeline streaming rather than batch (PS 26145
constraint c). It emits a Window the moment capture time crosses a boundary --
it never waits for end of file, so alert latency is bounded by the window
duration regardless of how long the capture runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from ingest.reader import Packet, TH_ACK, TH_FIN, TH_RST, TH_SYN

# A flow with no packets for this long is considered finished and evicted.
# Bounds memory on long captures; also what makes the table usable on a live
# stream that never ends.
IDLE_TIMEOUT_S = 120.0


@dataclass(slots=True)
class FlowRecord:
    flow_id: str
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    first_ts: float
    last_ts: float
    fwd_pkts: int = 0
    fwd_bytes: int = 0
    rev_pkts: int = 0
    rev_bytes: int = 0
    syn: int = 0
    synack: int = 0
    fin: int = 0
    rst: int = 0

    @property
    def completed(self) -> bool:
        """Did we observe the server half of the handshake?

        Note we can only ever *observe* this. We never complete a handshake
        ourselves -- that would require a return path we do not have.
        """
        return self.synack > 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def out_in_ratio(self) -> float:
        """Outbound:inbound byte ratio, the core exfiltration signal."""
        if self.rev_bytes == 0:
            return float(self.fwd_bytes) if self.fwd_bytes else 0.0
        return self.fwd_bytes / self.rev_bytes


class FlowTable:
    """Bidirectional flow table. The first packet seen defines the direction."""

    def __init__(self, idle_timeout: float = IDLE_TIMEOUT_S):
        self.flows: dict[tuple, FlowRecord] = {}
        self.idle_timeout = idle_timeout
        self.total_flows = 0
        self.expired_flows = 0
        self._last_sweep = 0.0

    @staticmethod
    def _key(pkt: Packet) -> tuple:
        """Canonical bidirectional key: same tuple for both directions."""
        a = (pkt.src, pkt.sport)
        b = (pkt.dst, pkt.dport)
        return (pkt.proto, a, b) if a <= b else (pkt.proto, b, a)

    def update(self, pkt: Packet) -> tuple[FlowRecord, bool]:
        """Fold a packet into its flow. Returns (record, is_forward)."""
        key = self._key(pkt)
        rec = self.flows.get(key)

        if rec is None:
            rec = FlowRecord(
                flow_id=f"{pkt.src}:{pkt.sport}->{pkt.dst}:{pkt.dport}/{pkt.proto}",
                src=pkt.src, dst=pkt.dst, sport=pkt.sport, dport=pkt.dport,
                proto=pkt.proto, first_ts=pkt.ts, last_ts=pkt.ts,
            )
            self.flows[key] = rec
            self.total_flows += 1

        forward = pkt.src == rec.src and pkt.sport == rec.sport
        if forward:
            rec.fwd_pkts += 1
            rec.fwd_bytes += pkt.length
        else:
            rec.rev_pkts += 1
            rec.rev_bytes += pkt.length

        if pkt.proto == "TCP":
            if pkt.flags & TH_SYN:
                if pkt.flags & TH_ACK:
                    rec.synack += 1
                else:
                    rec.syn += 1
            if pkt.flags & TH_FIN:
                rec.fin += 1
            if pkt.flags & TH_RST:
                rec.rst += 1

        rec.last_ts = pkt.ts
        self._maybe_sweep(pkt.ts)
        return rec, forward

    def _maybe_sweep(self, now: float) -> None:
        # Sweeping every packet would dominate the profile; once per timeout
        # period keeps the table bounded without hurting throughput.
        if now - self._last_sweep < self.idle_timeout / 4:
            return
        self._last_sweep = now
        cutoff = now - self.idle_timeout
        stale = [k for k, r in self.flows.items() if r.last_ts < cutoff]
        for k in stale:
            del self.flows[k]
        self.expired_flows += len(stale)

    def active(self) -> Iterator[FlowRecord]:
        return iter(self.flows.values())


@dataclass
class Window:
    """One tumbling slice of the stream, handed to every detector in turn."""

    start: float
    end: float
    packets: list[Packet] = field(default_factory=list)
    # Flow records touched during this window, keyed by flow_id. These are live
    # references into the FlowTable, so they carry full history, not just this
    # window's counters -- detectors that need "so far" totals read them here.
    flows: dict[str, FlowRecord] = field(default_factory=dict)
    index: int = 0

    @property
    def duration(self) -> float:
        return self.end - self.start

    def __len__(self) -> int:
        return len(self.packets)


class Windower:
    """Tumbling windows aligned to the first packet's capture timestamp."""

    def __init__(self, duration: float = 5.0):
        self.duration = float(duration)
        self.current: Window | None = None
        self.emitted = 0

    def add(self, pkt: Packet, flow: FlowRecord) -> Window | None:
        """Add a packet. Returns the completed Window if this one closed it."""
        if self.current is None:
            self.current = Window(start=pkt.ts, end=pkt.ts + self.duration)

        closed: Window | None = None
        # A gap larger than one window (common in sparse captures) can skip
        # several boundaries at once; roll forward until the packet fits.
        while pkt.ts >= self.current.end:
            closed = self.current
            self.emitted += 1
            nxt = Window(
                start=self.current.end,
                end=self.current.end + self.duration,
                index=self.current.index + 1,
            )
            self.current = nxt
            if closed.packets:
                break
            # Empty window: nothing to hand a detector, keep rolling.
            closed = None

        self.current.packets.append(pkt)
        self.current.flows[flow.flow_id] = flow
        return closed

    def flush(self) -> Window | None:
        """Emit the trailing partial window at end of capture."""
        w = self.current
        self.current = None
        if w and w.packets:
            w.end = max(w.packets[-1].ts, w.start)
            self.emitted += 1
            return w
        return None

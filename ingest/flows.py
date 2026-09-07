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

import heapq
from dataclasses import dataclass, field
from typing import Iterator

from ingest.reader import Packet, TH_ACK, TH_FIN, TH_RST, TH_SYN

# A flow with no packets for this long is considered finished and evicted.
IDLE_TIMEOUT_S = 120.0

# Absolute lifetime cap, NetFlow's "active timeout". A flow that keeps
# receiving packets is never idle, so idle expiry alone cannot bound it: a bulk
# transfer or a persistent C2 channel would accumulate counters forever and its
# duration would stop meaning anything. At this age the record is force-expired
# and the next packet starts a fresh one.
MAX_DURATION_S = 1800.0

# Hard ceiling on resident flow records. Idle expiry bounds memory only if the
# arrival rate is bounded, and an attacker chooses the arrival rate: a spoofed
# SYN flood mints one record per forged source, so ~100k unique sources/sec
# fills gigabytes long before a 120s idle timeout makes anything eligible for
# eviction. A monitor that dies when it sees an attack is worse than no monitor.
MAX_FLOWS = 200_000

# Once the cap is hit, evict down to this fraction of it rather than to exactly
# the cap, so the next insert does not immediately trigger another full sweep.
CAP_WATERMARK = 0.9

# Sweep at least this often in packets, independent of capture time. The
# capture-time trigger fires every idle_timeout/4 of *stream* time, which a
# burst can outrun: 100k pps means 3 million records arrive inside one 30s
# capture-time window with no sweep in between. Both triggers are deterministic
# functions of the capture, so replay stays byte-reproducible.
SWEEP_EVERY_PACKETS = 10_000


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

    def __init__(
        self,
        idle_timeout: float = IDLE_TIMEOUT_S,
        max_duration: float = MAX_DURATION_S,
        max_flows: int = MAX_FLOWS,
        sweep_every_packets: int = SWEEP_EVERY_PACKETS,
    ):
        self.flows: dict[tuple, FlowRecord] = {}
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        self.max_flows = max_flows
        self.sweep_every_packets = sweep_every_packets
        self._watermark = max(1, int(max_flows * CAP_WATERMARK))

        self.total_flows = 0
        self.expired_flows = 0
        # Broken out so the reason a record left the table is visible rather
        # than inferred. Overflow evictions in particular are lossy -- they
        # discard live flows -- and that must be observable, not silent.
        self.expired_idle = 0
        self.expired_duration = 0
        self.evicted_overflow = 0

        # None until the first packet anchors it. Initialising to 0.0 would
        # make the throttle epoch-sensitive: pcap timestamps are ~1.7e9, so
        # `now - 0.0` always clears the interval and the first packet swept a
        # one-element table. Harmless there, but on a capture with relative
        # timestamps starting near zero the same expression suppresses every
        # sweep for the first 30s of stream time instead.
        self._last_sweep: float | None = None
        self._packets_since_sweep = 0

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

        # Active timeout: a flow that has been open too long is force-expired
        # even though it is not idle, and this packet re-keys it into a fresh
        # record. Without this a long-lived connection is never evicted at all.
        if rec is not None and pkt.ts - rec.first_ts > self.max_duration:
            del self.flows[key]
            self.expired_flows += 1
            self.expired_duration += 1
            rec = None

        if rec is None:
            # Guard the cap BEFORE inserting, so the table can never exceed it.
            if len(self.flows) >= self.max_flows:
                self._sweep(pkt.ts, enforce_cap=True)
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
        self._packets_since_sweep += 1
        self._maybe_sweep(pkt.ts)
        return rec, forward

    def _maybe_sweep(self, now: float) -> None:
        """Sweep on either capture time or packet count, whichever comes first.

        Sweeping every packet would dominate the profile. Sweeping on capture
        time alone lets a burst outrun the sweeper, because stream time barely
        advances while millions of packets arrive -- which is precisely the
        condition a flood creates.
        """
        if self._last_sweep is None:
            # First packet: anchor the clock. There is nothing to evict yet.
            self._last_sweep = now
            return
        due_by_time = now - self._last_sweep >= self.idle_timeout / 4
        due_by_packets = self._packets_since_sweep >= self.sweep_every_packets
        if not (due_by_time or due_by_packets):
            return
        self._sweep(now)

    def _sweep(self, now: float, enforce_cap: bool = False) -> None:
        """Evict finished, over-age and (if still over the cap) oldest flows."""
        self._last_sweep = now
        self._packets_since_sweep = 0

        idle_cutoff = now - self.idle_timeout
        idle_keys: list[tuple] = []
        aged_keys: list[tuple] = []
        for k, r in self.flows.items():
            if r.last_ts < idle_cutoff:
                idle_keys.append(k)
            elif now - r.first_ts > self.max_duration:
                aged_keys.append(k)

        for k in idle_keys:
            del self.flows[k]
        for k in aged_keys:
            del self.flows[k]
        self.expired_idle += len(idle_keys)
        self.expired_duration += len(aged_keys)
        self.expired_flows += len(idle_keys) + len(aged_keys)

        # Timeouts are not a defence against cardinality: under a spoofed flood
        # every record is both recent and short-lived, so nothing above is
        # eligible and the table would keep growing. Past the cap we drop the
        # least-recently-active flows outright. This is lossy by construction --
        # we would rather lose the oldest state than the process.
        if (enforce_cap or len(self.flows) >= self.max_flows) and len(self.flows) > self._watermark:
            excess = len(self.flows) - self._watermark
            victims = heapq.nsmallest(excess, self.flows.items(), key=lambda kv: kv[1].last_ts)
            for k, _ in victims:
                del self.flows[k]
            self.evicted_overflow += len(victims)

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

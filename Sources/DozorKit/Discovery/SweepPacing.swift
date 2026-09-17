import Foundation

/// How fast probes leave the machine.
///
/// A schedule rather than a live token bucket, because a schedule is a pure
/// function of an index and a bucket is a clock-dependent object. The sweeper
/// sleeps until `start + departure(index:)` rather than pausing a fixed amount
/// between packets, so a slow `send` cannot let the real rate drift upward
/// afterwards to catch up.
public struct SweepPacing: Hashable, Sendable {

    /// Packets per second. Never zero: a sweep that repeats forever always has
    /// a ceiling, unlike a one-shot scan the user started deliberately.
    public let packetsPerSecond: Int
    /// Probes released back to back before the next wait.
    public let burst: Int
    /// The rate backing off can never fall below.
    public let minimumRate: Int

    public init(packetsPerSecond: Int, burst: Int = 8, minimumRate: Int = 20) {
        self.packetsPerSecond = max(minimumRate, packetsPerSecond)
        self.burst = max(1, burst)
        self.minimumRate = max(1, minimumRate)
    }

    /// Seconds after the start of the sweep at which probe `index` departs.
    public func departure(index: Int) -> TimeInterval {
        guard index > 0 else { return 0 }
        let slot = index / burst
        return Double(slot * burst) / Double(packetsPerSecond)
    }

    /// The wall-clock floor for a whole sweep.
    public func duration(forProbes count: Int) -> TimeInterval {
        guard count > 1 else { return 0 }
        return departure(index: count - 1)
    }

    /// After the kernel refuses more work (`ENOBUFS`), halve the rate.
    public func backedOff() -> SweepPacing {
        SweepPacing(packetsPerSecond: max(minimumRate, packetsPerSecond / 2),
                    burst: burst, minimumRate: minimumRate)
    }
}

import Foundation

/// Why we believe an address has something behind it.
public enum HostEvidence: String, Codable, Hashable, Sendable, CaseIterable {
    /// An ARP entry appeared during this sweep, or its MAC changed.
    case arpFresh
    /// An ARP entry was already there before we probed.
    case arpPrior
    case icmpReply
    case icmpUnreachable
    case tcpOpen
    case tcpRefused
    case ownAddress
}

public struct HostPresence: Hashable, Sendable, Codable {
    public enum Level: Int, Codable, Comparable, Sendable {
        case absent = 0
        case stale = 1
        case present = 2

        public static func < (lhs: Level, rhs: Level) -> Bool { lhs.rawValue < rhs.rawValue }
    }

    public let level: Level
    public let evidence: Set<HostEvidence>

    public init(level: Level, evidence: Set<HostEvidence>) {
        self.level = level
        self.evidence = evidence
    }
}

/// Turns a set of observations into a verdict.
///
/// The rule that matters: an ARP entry that was already in the table is **not**
/// proof the host is up. Measured on macOS, `net.link.ether.inet.max_age` is
/// 1200 — the kernel keeps a completed entry for twenty minutes and reuses it
/// without ever putting a request on the wire, so probing such an address
/// produces no new information about it. Reporting that as "up" would be the
/// most common lie this mode could tell, so it reports "seen recently" instead.
public enum PresenceRules {

    /// Evidence that means something answered during this sweep.
    static let live: Set<HostEvidence> = [
        .arpFresh, .icmpReply, .icmpUnreachable, .tcpOpen, .tcpRefused, .ownAddress,
    ]

    public static func presence(from evidence: Set<HostEvidence>) -> HostPresence {
        if !evidence.isDisjoint(with: live) {
            return HostPresence(level: .present, evidence: evidence)
        }
        if evidence.contains(.arpPrior) {
            return HostPresence(level: .stale, evidence: evidence)
        }
        return HostPresence(level: .absent, evidence: evidence)
    }
}

import Foundation

/// How a row reads in the table.
public enum RowStatus: String, Codable, Hashable, Sendable {
    case up            // answered the latest sweep
    case recentlyUp    // missed a sweep or three
    case gone          // silent for a while, kept so it can be recognised
}

public struct NetworkHostRow: Codable, Hashable, Sendable, Identifiable {
    public var id: String { host.address }

    /// The existing model, reused so `HostCopyMenu`, `bestName`, `macSummary`,
    /// `tabSeparatedSummary` and the tag editor all work unchanged — and so the
    /// hand-off to a full Nmap scan is a single line.
    public var host: HostResult
    public var firstSeen: Date
    public var lastSeen: Date
    public var lastProbed: Date
    public var presence: HostPresence
    public var missedSweeps: Int
    public var isGateway: Bool
    public var isSelf: Bool
    public var capabilities: HostCapabilities
    /// Set when a different MAC started answering for this address.
    public var macChangedAt: Date?

    public init(host: HostResult, firstSeen: Date, lastSeen: Date, lastProbed: Date,
                presence: HostPresence, missedSweeps: Int, isGateway: Bool, isSelf: Bool,
                capabilities: HostCapabilities, macChangedAt: Date? = nil) {
        self.host = host
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.lastProbed = lastProbed
        self.presence = presence
        self.missedSweeps = missedSweeps
        self.isGateway = isGateway
        self.isSelf = isSelf
        self.capabilities = capabilities
        self.macChangedAt = macChangedAt
    }

    public func status(missThreshold: Int = 3) -> RowStatus {
        if missedSweeps == 0 { return .up }
        return missedSweeps <= missThreshold ? .recentlyUp : .gone
    }
}

/// The rolling view of a subnet: what is here now, and what was here.
///
/// A snapshot would make a host blink out of the table the moment it sleeps.
/// Rows persist and age instead, which is the behaviour that makes a LAN list
/// worth leaving open.
public struct NetworkInventory: Codable, Hashable, Sendable {

    public let scopeCIDR: String
    public private(set) var rows: [String: NetworkHostRow]

    public init(scopeCIDR: String, rows: [String: NetworkHostRow] = [:]) {
        self.scopeCIDR = scopeCIDR
        self.rows = rows
    }

    public mutating func merge(_ observations: [SweepObservation],
                               probed: [String],
                               capabilities: [String: HostCapabilities] = [:],
                               at now: Date) {
        // A sweep that probed nothing — cancelled, or the scope went away — must
        // not mark the whole subnet as gone.
        guard !probed.isEmpty else { return }

        let seen = Dictionary(observations.map { ($0.address, $0) }, uniquingKeysWith: { first, _ in first })

        for observation in observations {
            let address = observation.address
            var row = rows[address] ?? NetworkHostRow(
                host: HostResult(address: address, addressType: "ipv4", state: "up"),
                firstSeen: now, lastSeen: now, lastProbed: now,
                presence: observation.presence, missedSweeps: 0,
                isGateway: observation.isGateway, isSelf: false,
                capabilities: .none, macChangedAt: nil
            )

            // A different MAC on a known address is a different device, not an
            // update: a DHCP lease was handed to someone else. Identity resets,
            // and the tags do not follow the address to a new machine.
            if let previous = row.host.mac, let current = observation.mac, previous != current {
                row.firstSeen = now
                row.host.tags = []
                row.macChangedAt = now
            }

            row.host.mac = observation.mac ?? row.host.mac
            row.host.macSource = observation.mac != nil ? .arpCache : row.host.macSource
            row.host.vendor = observation.vendor ?? row.host.vendor
            if let name = observation.name { row.host.reverseName = name }
            row.host.state = observation.presence.level == .present ? "up" : "down"
            row.presence = observation.presence
            row.isGateway = observation.isGateway
            row.lastProbed = now
            if let found = capabilities[address] { row.capabilities = found }

            if observation.presence.level == .present {
                row.lastSeen = now
                row.missedSweeps = 0
            } else {
                // Cached-only evidence is not a sighting; it does not refresh
                // lastSeen, but neither does it count as a miss.
                row.missedSweeps = max(row.missedSweeps, 0)
            }
            rows[address] = row
        }

        // Anything probed that produced nothing ages by one sweep but keeps its row.
        for address in probed where seen[address] == nil {
            guard var row = rows[address] else { continue }
            row.missedSweeps += 1
            row.lastProbed = now
            row.presence = HostPresence(level: .absent, evidence: [])
            row.host.state = "down"
            rows[address] = row
        }
    }

    /// Forgetting needs both a long silence and a lot of missed sweeps, so a
    /// laptop that was away for the weekend is still recognised on Monday.
    public func pruned(missThreshold: Int = 12,
                       maxAge: TimeInterval = 86_400,
                       now: Date) -> NetworkInventory {
        var kept = rows
        for (address, row) in rows
        where row.missedSweeps >= missThreshold && now.timeIntervalSince(row.lastSeen) > maxAge {
            kept.removeValue(forKey: address)
        }
        return NetworkInventory(scopeCIDR: scopeCIDR, rows: kept)
    }

    public func sorted() -> [NetworkHostRow] {
        rows.values.sorted { lhs, rhs in
            (LocalNetworks.hostValue(lhs.host.address) ?? 0)
                < (LocalNetworks.hostValue(rhs.host.address) ?? 0)
        }
    }

    public var presentCount: Int { rows.values.filter { $0.status() == .up }.count }
    public var knownCount: Int { rows.count }
}

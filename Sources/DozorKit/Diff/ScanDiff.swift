import Foundation

public struct PortChange: Hashable, Sendable, Identifiable {
    public var id: String { "\(host)-\(port.id)-\(kind)" }
    public enum Kind: String, Sendable {
        case opened, closed, serviceChanged
    }
    public let host: String
    public let port: PortInfo
    public let kind: Kind
    /// Previous service description, for `serviceChanged`.
    public let previous: String?
    public let current: String?
}

public struct ScanDiff: Sendable {
    public let baselineDate: Date?
    public let currentDate: Date?
    public let newHosts: [HostResult]
    public let missingHosts: [HostResult]
    public let changes: [PortChange]

    public var isEmpty: Bool {
        newHosts.isEmpty && missingHosts.isEmpty && changes.isEmpty
    }

    public var openedCount: Int { changes.filter { $0.kind == .opened }.count }
    public var closedCount: Int { changes.filter { $0.kind == .closed }.count }
    public var serviceChangedCount: Int { changes.filter { $0.kind == .serviceChanged }.count }

    /// Compares two results by address. Only open ports are compared: a port
    /// that moves between "closed" and "filtered" is noise, not a change.
    public static func compare(baseline: ScanResult, current: ScanResult) -> ScanDiff {
        let baseHosts = Dictionary(baseline.hosts.map { ($0.address, $0) }, uniquingKeysWith: { a, _ in a })
        let currentHosts = Dictionary(current.hosts.map { ($0.address, $0) }, uniquingKeysWith: { a, _ in a })

        let newHosts = current.hosts.filter { baseHosts[$0.address] == nil && $0.state == "up" }
        let missingHosts = baseline.hosts.filter { host in
            host.state == "up" && (currentHosts[host.address]?.state ?? "down") != "up"
        }

        var changes: [PortChange] = []
        for (address, currentHost) in currentHosts {
            guard let baseHost = baseHosts[address] else { continue }
            let basePorts = Dictionary(baseHost.openPorts.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
            let currentPorts = Dictionary(currentHost.openPorts.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })

            for (key, port) in currentPorts {
                guard let previous = basePorts[key] else {
                    changes.append(.init(host: address, port: port, kind: .opened,
                                         previous: nil, current: port.serviceSummary))
                    continue
                }
                if previous.serviceSummary != port.serviceSummary {
                    changes.append(.init(host: address, port: port, kind: .serviceChanged,
                                         previous: previous.serviceSummary,
                                         current: port.serviceSummary))
                }
            }
            for (key, port) in basePorts where currentPorts[key] == nil {
                changes.append(.init(host: address, port: port, kind: .closed,
                                     previous: port.serviceSummary, current: nil))
            }
        }
        changes.sort { ($0.host, $0.port.port) < ($1.host, $1.port.port) }

        return ScanDiff(baselineDate: baseline.startedAt, currentDate: current.startedAt,
                        newHosts: newHosts.sorted { $0.address < $1.address },
                        missingHosts: missingHosts.sorted { $0.address < $1.address },
                        changes: changes)
    }
}

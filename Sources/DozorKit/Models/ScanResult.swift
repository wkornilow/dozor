import Foundation

public struct PortInfo: Codable, Hashable, Sendable, Identifiable {
    public var id: String { "\(proto)/\(port)" }
    public var port: Int
    public var proto: String          // tcp, udp
    public var state: String          // open, closed, filtered
    public var reason: String?
    public var serviceName: String?
    public var product: String?
    public var version: String?
    public var extraInfo: String?
    public var scripts: [String: String]

    public init(port: Int, proto: String, state: String, reason: String? = nil,
                serviceName: String? = nil, product: String? = nil, version: String? = nil,
                extraInfo: String? = nil, scripts: [String: String] = [:]) {
        self.port = port
        self.proto = proto
        self.state = state
        self.reason = reason
        self.serviceName = serviceName
        self.product = product
        self.version = version
        self.extraInfo = extraInfo
        self.scripts = scripts
    }

    /// "OpenSSH 9.6p1 (protocol 2.0)" style summary, or nil when unknown.
    public var serviceSummary: String? {
        let parts = [product, version, extraInfo.map { "(\($0))" }].compactMap { $0 }
        if parts.isEmpty { return serviceName }
        return parts.joined(separator: " ")
    }
}

/// Where a piece of host information came from. An unprivileged scan cannot see
/// a MAC address, so anything the app fills in afterwards is labelled rather
/// than presented as a scan finding.
public enum AddressSource: String, Codable, Hashable, Sendable {
    case scan        // Nmap reported it directly
    case arpCache    // read from this Mac's own ARP cache after the scan
}

public struct HostResult: Codable, Hashable, Sendable, Identifiable {
    public var id: String { address }
    public var address: String
    public var addressType: String      // ipv4, ipv6
    public var mac: String?
    public var vendor: String?
    public var hostnames: [String]
    public var state: String            // up, down
    public var osGuess: String?
    public var ports: [PortInfo]
    /// User labels, persisted with the run.
    public var tags: [String]
    /// How the MAC address was obtained. Optional so runs recorded before this
    /// existed still decode.
    public var macSource: AddressSource?
    /// Name from the system resolver, which sees mDNS ".local" names that
    /// Nmap's own resolver does not.
    public var reverseName: String?

    public init(address: String, addressType: String, mac: String? = nil, vendor: String? = nil,
                hostnames: [String] = [], state: String, osGuess: String? = nil,
                ports: [PortInfo] = [], tags: [String] = [],
                macSource: AddressSource? = nil, reverseName: String? = nil) {
        self.address = address
        self.addressType = addressType
        self.mac = mac
        self.vendor = vendor
        self.hostnames = hostnames
        self.state = state
        self.osGuess = osGuess
        self.ports = ports
        self.tags = tags
        self.macSource = macSource
        self.reverseName = reverseName
    }

    public var openPorts: [PortInfo] { ports.filter { $0.state == "open" } }
    /// Nmap's own name wins; the system resolver fills the gap it leaves.
    public var displayName: String { hostnames.first ?? reverseName ?? address }
    /// The best name available, or nil when the host has none at all.
    public var bestName: String? { hostnames.first ?? reverseName }
    /// Tab-separated line for the clipboard: pastes as one row into a
    /// spreadsheet and still reads as a sentence in a message.
    public var tabSeparatedSummary: String {
        var fields = [address]
        if let bestName { fields.append(bestName) }
        if let mac { fields.append(mac) }
        if let vendor { fields.append(vendor) }
        let ports = openPorts.map { port in
            port.serviceName.map { "\(port.port)/\(port.proto) (\($0))" } ?? "\(port.port)/\(port.proto)"
        }
        if !ports.isEmpty { fields.append(ports.joined(separator: ", ")) }
        return fields.joined(separator: "\t")
    }

    /// "d0:65:78:00:00:d9 — Intel Corporate", or just the address when the
    /// vendor is unknown.
    public var macSummary: String? {
        guard let mac else { return nil }
        guard let vendor, !vendor.isEmpty else { return mac }
        return "\(mac) — \(vendor)"
    }
}

public struct ScanResult: Codable, Hashable, Sendable {
    public var nmapVersion: String?
    public var commandLine: String?
    public var startedAt: Date?
    public var finishedAt: Date?
    public var hosts: [HostResult]
    public var hostsUp: Int
    public var hostsDown: Int
    /// Non-fatal messages Nmap emitted (e.g. "Warning: ...").
    public var warnings: [String]

    public init(nmapVersion: String? = nil, commandLine: String? = nil,
                startedAt: Date? = nil, finishedAt: Date? = nil,
                hosts: [HostResult] = [], hostsUp: Int = 0, hostsDown: Int = 0,
                warnings: [String] = []) {
        self.nmapVersion = nmapVersion
        self.commandLine = commandLine
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.hosts = hosts
        self.hostsUp = hostsUp
        self.hostsDown = hostsDown
        self.warnings = warnings
    }
}

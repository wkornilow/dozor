import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// One IPv4 address as the operating system reports it for a network interface.
public struct InterfaceAddress: Hashable, Sendable {
    public let name: String          // BSD name, e.g. "en0"
    public let address: String       // "192.168.30.9"
    public let netmask: String       // "255.255.255.0"
    public let isUp: Bool
    public let isRunning: Bool
    public let isLoopback: Bool
    public let isPointToPoint: Bool

    public init(name: String, address: String, netmask: String,
                isUp: Bool, isRunning: Bool, isLoopback: Bool, isPointToPoint: Bool) {
        self.name = name
        self.address = address
        self.netmask = netmask
        self.isUp = isUp
        self.isRunning = isRunning
        self.isLoopback = isLoopback
        self.isPointToPoint = isPointToPoint
    }
}

/// A range the app offers as a one-click starting point. It is a convenience
/// only: the target still goes through validation, policy and the scope
/// confirmation exactly like text the user typed.
public struct NetworkSuggestion: Hashable, Sendable, Identifiable {
    public enum Kind: String, Sendable {
        case network
        case gateway
    }

    public var id: String { "\(kind.rawValue):\(target.raw)" }
    public let kind: Kind
    /// Always produced by `TargetValidator`, never constructed directly.
    public let target: ScanTarget
    public let interfaceName: String
    /// Friendly name when the platform can supply one ("Wi-Fi"); nil otherwise.
    public let displayName: String?
    /// True when the interface sits on a wider network and this is the /24 slice
    /// around the host's own address.
    public let isNarrowed: Bool
    /// The interface's real prefix length, when the suggestion was narrowed.
    public let originalPrefix: Int?

    public init(kind: Kind, target: ScanTarget, interfaceName: String,
                displayName: String? = nil, isNarrowed: Bool = false,
                originalPrefix: Int? = nil) {
        self.kind = kind
        self.target = target
        self.interfaceName = interfaceName
        self.displayName = displayName
        self.isNarrowed = isNarrowed
        self.originalPrefix = originalPrefix
    }

    public var label: String { displayName ?? interfaceName }
}

/// Turns the machine's own interface list into scan suggestions.
///
/// The enumeration is a read-only local system call: it sends no traffic and
/// spawns no process. The interesting logic — masks, narrowing, filtering — is
/// kept pure so it can be tested without a network.
public enum LocalNetworks {

    /// Widest network offered as a single suggestion. An interface on anything
    /// wider is narrowed to the /24 around its own address: a /16 is 65 536
    /// addresses, well past what one run is allowed to cover.
    public static let narrowToPrefix = 24

    /// Prefixes outside this range describe something that is not a scannable
    /// LAN: /31 and /32 are a point-to-point link or a single host, and nothing
    /// shorter than /8 is a real interface mask.
    static let acceptedPrefixes = 8...30

    // MARK: - Suggestions

    public static func suggestions(
        from interfaces: [InterfaceAddress],
        gateway: String? = nil,
        primaryInterface: String? = nil,
        displayNames: [String: String] = [:]
    ) -> [NetworkSuggestion] {

        // Primary interface first, then stable by BSD name.
        let ordered = interfaces.sorted { lhs, rhs in
            let lhsPrimary = lhs.name == primaryInterface
            let rhsPrimary = rhs.name == primaryInterface
            if lhsPrimary != rhsPrimary { return lhsPrimary }
            return lhs.name < rhs.name
        }

        var result: [NetworkSuggestion] = []
        var seen = Set<String>()
        var acceptedNetworks: [(cidr: String, interface: InterfaceAddress)] = []

        for interface in ordered {
            guard let network = network(for: interface) else { continue }
            guard seen.insert(network.cidr).inserted else { continue }
            guard case .success(let target) = TargetValidator.validate(network.cidr) else { continue }

            result.append(NetworkSuggestion(
                kind: .network,
                target: target,
                interfaceName: interface.name,
                displayName: displayNames[interface.name],
                isNarrowed: network.isNarrowed,
                originalPrefix: network.isNarrowed ? network.actualPrefix : nil
            ))
            acceptedNetworks.append((network.cidr, interface))
        }

        // A gateway is only offered when it really belongs to one of the
        // networks above; a stale value from the system store is dropped rather
        // than presented as something worth scanning.
        if let gateway, case .success(let target) = TargetValidator.validate(gateway),
           target.kind == .ipv4,
           let owner = acceptedNetworks.first(where: { contains(cidr: $0.cidr, address: gateway) }),
           seen.insert(gateway).inserted {
            let suggestion = NetworkSuggestion(
                kind: .gateway,
                target: target,
                interfaceName: owner.interface.name,
                displayName: displayNames[owner.interface.name]
            )
            // Place it directly after its own network.
            if let index = result.firstIndex(where: { $0.kind == .network && $0.interfaceName == owner.interface.name }) {
                result.insert(suggestion, at: result.index(after: index))
            } else {
                result.append(suggestion)
            }
        }

        return result
    }

    /// The CIDR an interface contributes, or nil when it is not worth offering.
    static func network(for interface: InterfaceAddress) -> (cidr: String, actualPrefix: Int, isNarrowed: Bool)? {
        guard interface.isUp, interface.isRunning else { return nil }
        guard !interface.isLoopback, !interface.isPointToPoint else { return nil }
        guard TargetValidator.parseIPv4(interface.address) != nil else { return nil }
        // An IPv4 link-local address means the interface never got a real
        // configuration; there is no network behind it to scan.
        guard !interface.address.hasPrefix("169.254.") else { return nil }
        guard let prefix = prefixLength(ofMask: interface.netmask),
              acceptedPrefixes.contains(prefix) else { return nil }

        let effective = max(prefix, narrowToPrefix)
        guard let base = networkAddress(interface.address, prefix: effective) else { return nil }
        return ("\(base)/\(effective)", prefix, effective != prefix)
    }

    // MARK: - Address arithmetic

    /// "255.255.255.0" → 24. Non-contiguous masks are refused: they are not
    /// expressible as a CIDR prefix, so there is nothing honest to suggest.
    public static func prefixLength(ofMask mask: String) -> Int? {
        guard let parsed = TargetValidator.parseIPv4(mask) else { return nil }
        let host = UInt32(bigEndian: parsed.s_addr)
        let prefix = (0...32).first { candidate in
            maskValue(prefix: candidate) == host
        }
        return prefix
    }

    /// The base address of the network containing `address` at `prefix`.
    public static func networkAddress(_ address: String, prefix: Int) -> String? {
        guard (0...32).contains(prefix), let parsed = TargetValidator.parseIPv4(address) else { return nil }
        let host = UInt32(bigEndian: parsed.s_addr) & maskValue(prefix: prefix)
        return dotted(host)
    }

    /// Whether a plain IPv4 address falls inside a CIDR network.
    static func contains(cidr: String, address: String) -> Bool {
        let parts = cidr.components(separatedBy: "/")
        guard parts.count == 2, let prefix = Int(parts[1]),
              let base = networkAddress(parts[0], prefix: prefix),
              let candidate = networkAddress(address, prefix: prefix)
        else { return false }
        return base == candidate
    }

    static func maskValue(prefix: Int) -> UInt32 {
        prefix == 0 ? 0 : ~UInt32(0) << (32 - prefix)
    }

    static func dotted(_ host: UInt32) -> String {
        "\((host >> 24) & 0xff).\((host >> 16) & 0xff).\((host >> 8) & 0xff).\(host & 0xff)"
    }

    // MARK: - Live enumeration

    #if canImport(Darwin)
    /// Reads the machine's interface list through `getifaddrs(3)`.
    public static func currentInterfaces() -> [InterfaceAddress] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var result: [InterfaceAddress] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }

            guard let addr = entry.pointee.ifa_addr,
                  addr.pointee.sa_family == UInt8(AF_INET),
                  let mask = entry.pointee.ifa_netmask,
                  let address = numericHost(addr),
                  let netmask = numericHost(mask)
            else { continue }

            let flags = entry.pointee.ifa_flags
            result.append(InterfaceAddress(
                name: String(cString: entry.pointee.ifa_name),
                address: address,
                netmask: netmask,
                isUp: flags & UInt32(IFF_UP) != 0,
                isRunning: flags & UInt32(IFF_RUNNING) != 0,
                isLoopback: flags & UInt32(IFF_LOOPBACK) != 0,
                isPointToPoint: flags & UInt32(IFF_POINTOPOINT) != 0
            ))
        }
        return result
    }

    private static func numericHost(_ addr: UnsafeMutablePointer<sockaddr>) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status = getnameinfo(addr, socklen_t(addr.pointee.sa_len),
                                 &buffer, socklen_t(buffer.count),
                                 nil, 0, NI_NUMERICHOST)
        guard status == 0 else { return nil }
        let text = String(cString: buffer)
        return text.isEmpty ? nil : text
    }
    #else
    /// Interface enumeration is platform-specific; the pure logic above still
    /// builds and is still tested elsewhere.
    public static func currentInterfaces() -> [InterfaceAddress] { [] }
    #endif
}

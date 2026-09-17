import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// A subnet this Mac is itself attached to.
///
/// There is deliberately no initialiser that takes free text. The only way to
/// obtain a scope is to match a live interface, so the network mode cannot be
/// pointed at anything the machine is not already on — the authorised-asset rule
/// is satisfied by construction rather than by a check someone can forget.
///
/// A scope is resolved again immediately before every sweep. The stored choice is
/// a preference, not a capability: during the planning of this feature the
/// machine moved from one subnet to another between two commands, which is
/// exactly the case a stored scope would get wrong.
public struct SweepScope: Hashable, Sendable, Identifiable {

    public var id: String { "\(interfaceName):\(target.raw)" }

    /// Validator-produced, always `.cidr`.
    public let target: ScanTarget
    public let interfaceName: String
    /// For `IP_BOUND_IF`: without it a VPN default route swallows the probes and
    /// the subnet reads as empty with no error.
    public let interfaceIndex: UInt32
    public let localAddress: String
    public let broadcastAddress: String
    public let prefix: Int
    /// True when the interface sits on something wider and this is the /24
    /// around the local address.
    public let isNarrowed: Bool

    public init(target: ScanTarget, interfaceName: String, interfaceIndex: UInt32,
                localAddress: String, broadcastAddress: String, prefix: Int,
                isNarrowed: Bool) {
        self.target = target
        self.interfaceName = interfaceName
        self.interfaceIndex = interfaceIndex
        self.localAddress = localAddress
        self.broadcastAddress = broadcastAddress
        self.prefix = prefix
        self.isNarrowed = isNarrowed
    }

    // MARK: - Resolution

    /// Every scope the machine currently offers, primary interface first.
    public static func available(
        interfaces: [InterfaceAddress] = LocalNetworks.currentInterfaces(),
        primaryInterface: String? = nil
    ) -> [SweepScope] {
        var seen = Set<String>()
        var scopes: [SweepScope] = []
        let ordered = interfaces.sorted { lhs, rhs in
            let lhsPrimary = lhs.name == primaryInterface
            let rhsPrimary = rhs.name == primaryInterface
            if lhsPrimary != rhsPrimary { return lhsPrimary }
            return lhs.name < rhs.name
        }
        for interface in ordered {
            guard let scope = scope(for: interface) else { continue }
            guard seen.insert(scope.target.raw).inserted else { continue }
            scopes.append(scope)
        }
        return scopes
    }

    /// Nil unless `cidr` is exactly the network of a live interface right now.
    public static func resolve(
        cidr: String,
        interfaces: [InterfaceAddress] = LocalNetworks.currentInterfaces()
    ) -> SweepScope? {
        available(interfaces: interfaces).first { $0.target.raw == cidr }
    }

    /// Builds the scope for one interface, reusing `LocalNetworks.network(for:)`
    /// so the filtering and the /24 narrowing rule live in exactly one place.
    static func scope(for interface: InterfaceAddress) -> SweepScope? {
        guard let network = LocalNetworks.network(for: interface) else { return nil }
        guard case .success(let target) = TargetValidator.validate(network.cidr) else { return nil }

        let effective = max(network.actualPrefix, LocalNetworks.narrowToPrefix)
        guard let base = LocalNetworks.networkAddress(interface.address, prefix: effective),
              let baseValue = LocalNetworks.hostValue(base)
        else { return nil }

        let broadcast = LocalNetworks.dotted(baseValue | ~LocalNetworks.maskValue(prefix: effective))

        return SweepScope(
            target: target,
            interfaceName: interface.name,
            interfaceIndex: interfaceIndex(named: interface.name),
            localAddress: interface.address,
            broadcastAddress: broadcast,
            prefix: effective,
            isNarrowed: network.isNarrowed
        )
    }

    static func interfaceIndex(named name: String) -> UInt32 {
        #if canImport(Darwin)
        return if_nametoindex(name)
        #else
        return 0
        #endif
    }

    // MARK: - Addresses

    /// The addresses a sweep probes: the subnet minus its network address, its
    /// broadcast address and this Mac. Ascending numeric order — the order the
    /// table shows them in.
    public func hostAddresses() -> [String] {
        let parts = target.raw.components(separatedBy: "/")
        guard let base = parts.first, let baseValue = LocalNetworks.hostValue(base) else { return [] }
        let mask = LocalNetworks.maskValue(prefix: prefix)
        let broadcastValue = baseValue | ~mask
        guard broadcastValue > baseValue + 1 else { return [] }   // /31 and /32 hold no hosts

        let localValue = LocalNetworks.hostValue(localAddress)
        return ((baseValue + 1)..<broadcastValue).compactMap { value in
            value == localValue ? nil : LocalNetworks.dotted(value)
        }
    }

    /// The same addresses, each put back through the validator.
    ///
    /// The project's rule is that only validator-produced targets exist; running
    /// the enumerator's own output through it means the sweep cannot hand a
    /// socket a string the validator would have refused.
    public func hostTargets() -> [ScanTarget] {
        hostAddresses().compactMap { address in
            guard case .success(let target) = TargetValidator.validate(address),
                  target.kind == .ipv4 else { return nil }
            return target
        }
    }

    public var addressCount: Int { hostAddresses().count }
}

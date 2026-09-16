import Foundation

/// A validated scan target. Only values produced by `TargetValidator` exist,
/// so nothing that reaches the Nmap argument vector is unchecked user text.
public struct ScanTarget: Codable, Hashable, Sendable, Identifiable {
    public enum Kind: String, Codable, Sendable {
        case ipv4
        case ipv6
        case cidr
        case ipv4Range
        case hostname
    }

    public var id: String { raw }
    /// The canonical text handed to Nmap.
    public let raw: String
    public let kind: Kind
    /// Number of addresses the target expands to, when it can be computed.
    public let addressCount: Int?
    /// True when every address is inside RFC1918 / loopback / link-local space.
    public let isPrivate: Bool

    public init(raw: String, kind: Kind, addressCount: Int?, isPrivate: Bool) {
        self.raw = raw
        self.kind = kind
        self.addressCount = addressCount
        self.isPrivate = isPrivate
    }
}

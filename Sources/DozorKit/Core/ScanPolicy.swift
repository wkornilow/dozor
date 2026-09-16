import Foundation

/// Local policy governing what may be scanned and how hard.
/// Stored in Application Support and edited in Settings.
public struct ScanPolicy: Codable, Hashable, Sendable {
    /// Targets that the operator has declared they are authorised to scan.
    /// Anything outside private address space must match an entry here.
    public var authorisedAssets: [String]
    /// Refuse instead of warn when a target is not authorised.
    public var blockUnauthorisedTargets: Bool
    /// Highest intensity allowed without an extra confirmation step.
    public var maxIntensityWithoutConfirmation: ScanIntensity
    /// Intensity that is refused outright.
    public var blockedIntensity: ScanIntensity?
    /// Packets per second ceiling handed to Nmap as --max-rate. 0 means no cap.
    ///
    /// This is by far the most expensive limit: on a 10000-port loopback scan,
    /// 500 pps turns 0.15 s into 20 s. The default is high enough that it never
    /// binds on a normal LAN — where the wire, not the cap, is the bottleneck —
    /// while still preventing a scan from flooding a fragile network.
    public var maxPacketRate: Int
    /// Concurrent probes per host group, handed to Nmap as --max-parallelism.
    /// 0 means no cap. Cheap: capping parallelism barely affects run time.
    public var maxParallelism: Int
    /// Hosts probed at once, handed to Nmap as --max-hostgroup. 0 means no cap.
    public var maxHostGroup: Int
    /// Hard ceiling on addresses in one run.
    public var maxAddressesPerRun: Int
    /// Only one scan may run at a time, regardless of anything else.
    public var serialiseScans: Bool
    /// Bumped when the shipped defaults change in a way that must override a
    /// stored policy; see `migratedIfNeeded()`.
    public var schemaVersion: Int

    public static let currentSchemaVersion = 2

    public static let `default` = ScanPolicy(
        authorisedAssets: [],
        blockUnauthorisedTargets: true,
        maxIntensityWithoutConfirmation: .moderate,
        blockedIntensity: nil,
        maxPacketRate: 20_000,
        maxParallelism: 128,
        maxHostGroup: 64,
        maxAddressesPerRun: 4096,
        serialiseScans: true,
        schemaVersion: currentSchemaVersion
    )

    /// Replaces throttling values written by an older build, which were low
    /// enough to make every scan look like it had hung. User choices that are
    /// not about throughput — authorised assets, blocking rules — are kept.
    public func migratedIfNeeded() -> ScanPolicy {
        guard schemaVersion < Self.currentSchemaVersion else { return self }
        var migrated = self
        migrated.maxPacketRate = ScanPolicy.default.maxPacketRate
        migrated.maxParallelism = ScanPolicy.default.maxParallelism
        migrated.maxHostGroup = ScanPolicy.default.maxHostGroup
        migrated.schemaVersion = Self.currentSchemaVersion
        return migrated
    }

    public init(authorisedAssets: [String], blockUnauthorisedTargets: Bool,
                maxIntensityWithoutConfirmation: ScanIntensity, blockedIntensity: ScanIntensity?,
                maxPacketRate: Int, maxParallelism: Int, maxHostGroup: Int,
                maxAddressesPerRun: Int, serialiseScans: Bool,
                schemaVersion: Int = 1) {
        self.authorisedAssets = authorisedAssets
        self.blockUnauthorisedTargets = blockUnauthorisedTargets
        self.maxIntensityWithoutConfirmation = maxIntensityWithoutConfirmation
        self.blockedIntensity = blockedIntensity
        self.maxPacketRate = maxPacketRate
        self.maxParallelism = maxParallelism
        self.maxHostGroup = maxHostGroup
        self.maxAddressesPerRun = maxAddressesPerRun
        self.serialiseScans = serialiseScans
        self.schemaVersion = schemaVersion
    }

    // A policy written by version 1 has no schemaVersion field; default it to 1
    // so `migratedIfNeeded()` can recognise and update it.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        authorisedAssets = try container.decodeIfPresent([String].self, forKey: .authorisedAssets) ?? []
        blockUnauthorisedTargets = try container.decodeIfPresent(Bool.self, forKey: .blockUnauthorisedTargets) ?? true
        maxIntensityWithoutConfirmation = try container.decodeIfPresent(
            ScanIntensity.self, forKey: .maxIntensityWithoutConfirmation) ?? .moderate
        blockedIntensity = try container.decodeIfPresent(ScanIntensity.self, forKey: .blockedIntensity)
        maxPacketRate = try container.decodeIfPresent(Int.self, forKey: .maxPacketRate)
            ?? ScanPolicy.default.maxPacketRate
        maxParallelism = try container.decodeIfPresent(Int.self, forKey: .maxParallelism)
            ?? ScanPolicy.default.maxParallelism
        maxHostGroup = try container.decodeIfPresent(Int.self, forKey: .maxHostGroup)
            ?? ScanPolicy.default.maxHostGroup
        maxAddressesPerRun = try container.decodeIfPresent(Int.self, forKey: .maxAddressesPerRun) ?? 4096
        serialiseScans = try container.decodeIfPresent(Bool.self, forKey: .serialiseScans) ?? true
        schemaVersion = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
    }
}

public enum PolicyVerdict: Hashable, Sendable {
    case allowed
    case needsConfirmation([PolicyFinding])
    case blocked([PolicyFinding])
}

public struct PolicyFinding: Hashable, Sendable, Identifiable {
    public enum Kind: String, Sendable {
        case unauthorisedTarget     // outside private space and not in the allow-list
        case publicTarget           // routable address
        case largeScope             // many addresses
        case highIntensity
        case rootRequired
        case scopeOverLimit
    }
    public var id: String { "\(kind.rawValue):\(detail)" }
    public let kind: Kind
    public let detail: String
    public let isBlocking: Bool

    public init(kind: Kind, detail: String, isBlocking: Bool) {
        self.kind = kind
        self.detail = detail
        self.isBlocking = isBlocking
    }
}

public enum PolicyEngine {

    public static func evaluate(
        targets: [ScanTarget],
        profile: ScanProfile,
        policy: ScanPolicy,
        isRoot: Bool
    ) -> PolicyVerdict {
        var findings: [PolicyFinding] = []

        let total = targets.reduce(0) { $0 + ($1.addressCount ?? 1) }
        if total > policy.maxAddressesPerRun {
            findings.append(.init(kind: .scopeOverLimit,
                                  detail: "\(total) > \(policy.maxAddressesPerRun)",
                                  isBlocking: true))
        } else if total > 256 {
            findings.append(.init(kind: .largeScope, detail: "\(total)", isBlocking: false))
        }

        for target in targets where !target.isPrivate {
            if isAuthorised(target, policy: policy) {
                findings.append(.init(kind: .publicTarget, detail: target.raw, isBlocking: false))
            } else {
                findings.append(.init(kind: .unauthorisedTarget, detail: target.raw,
                                      isBlocking: policy.blockUnauthorisedTargets))
            }
        }

        if let blocked = policy.blockedIntensity, profile.intensity.order >= blocked.order {
            findings.append(.init(kind: .highIntensity, detail: profile.intensity.rawValue,
                                  isBlocking: true))
        } else if profile.intensity.order > policy.maxIntensityWithoutConfirmation.order {
            findings.append(.init(kind: .highIntensity, detail: profile.intensity.rawValue,
                                  isBlocking: false))
        }

        if profile.requiresRoot && !isRoot {
            findings.append(.init(kind: .rootRequired, detail: profile.name, isBlocking: true))
        }

        if findings.contains(where: \.isBlocking) {
            return .blocked(findings)
        }
        return findings.isEmpty ? .allowed : .needsConfirmation(findings)
    }

    /// An asset entry authorises a target when it matches exactly, or when the
    /// entry is a CIDR that contains the target's base address.
    static func isAuthorised(_ target: ScanTarget, policy: ScanPolicy) -> Bool {
        for asset in policy.authorisedAssets {
            let entry = asset.trimmingCharacters(in: .whitespaces)
            if entry.isEmpty { continue }
            if entry.caseInsensitiveCompare(target.raw) == .orderedSame { return true }
            if entry.contains("/"), cidrContains(entry, target: target.raw) { return true }
            // Wildcard suffix for hostnames: "*.example.com"
            if entry.hasPrefix("*."), target.raw.lowercased().hasSuffix(entry.dropFirst().lowercased()) {
                return true
            }
        }
        return false
    }

    static func cidrContains(_ cidr: String, target: String) -> Bool {
        let parts = cidr.components(separatedBy: "/")
        guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix),
              let network = TargetValidator.parseIPv4(parts[0])
        else { return false }
        // Compare against the target's first address (works for plain IPs and CIDRs).
        let base = target.components(separatedBy: "/")[0].components(separatedBy: "-")[0]
        guard let addr = TargetValidator.parseIPv4(base) else { return false }
        let mask: UInt32 = prefix == 0 ? 0 : ~0 << (32 - prefix)
        let networkHost = UInt32(bigEndian: network.s_addr)
        let addrHost = UInt32(bigEndian: addr.s_addr)
        return (networkHost & mask) == (addrHost & mask)
    }
}

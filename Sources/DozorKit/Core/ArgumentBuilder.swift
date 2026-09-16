import Foundation

/// Assembles the final argv for one run: profile flags, policy-derived rate
/// limits, targets, and app-owned output flags — in that order.
public enum ArgumentBuilder {

    public struct Plan: Hashable, Sendable {
        public let arguments: [String]
        public let xmlURL: URL
        /// Estimated wall-clock seconds, for the pre-run explanation.
        public let estimatedSeconds: Double
        public let addressCount: Int
        /// True when the packet-rate cap, not the network, sets the run time.
        /// The UI warns about this: a low cap is the difference between a scan
        /// that takes seconds and one that looks like it has frozen.
        public let isRateLimited: Bool
    }

    public enum BuildError: Error, Equatable, Sendable {
        case noTargets
        case policy([ArgumentPolicyError])
    }

    public static func build(
        profile: ScanProfile,
        targets: [ScanTarget],
        policy: ScanPolicy,
        xmlURL: URL,
        statsInterval: String = "2s"
    ) throws -> Plan {
        guard !targets.isEmpty else { throw BuildError.noTargets }

        let policyErrors = ArgumentPolicy.validate(profile.arguments)
        guard policyErrors.isEmpty else { throw BuildError.policy(policyErrors) }

        var arguments = profile.arguments

        // Timing template: profile value unless it already sets one explicitly.
        if !arguments.contains(where: { $0.hasPrefix("-T") }) {
            arguments.append(profile.timing.flag)
        }

        // Rate limiting is app-owned so a profile cannot opt out of it.
        // A limit of 0 means "no cap": the flag is omitted entirely rather than
        // passed as 0, which Nmap would reject.
        if policy.maxPacketRate > 0 {
            arguments += ["--max-rate", String(policy.maxPacketRate)]
        }
        if policy.maxParallelism > 0 {
            arguments += ["--max-parallelism", String(policy.maxParallelism)]
        }
        if policy.maxHostGroup > 0 {
            arguments += ["--max-hostgroup", String(policy.maxHostGroup)]
        }

        // Progress reporting and machine-readable output.
        arguments += ["-v", "--stats-every", statsInterval]
        arguments += ["-oX", xmlURL.path]

        // Targets last, each already validated. `--` stops option parsing so a
        // target can never be read as a flag.
        arguments.append("--")
        arguments += targets.map(\.raw)

        let addresses = targets.reduce(0) { $0 + ($1.addressCount ?? 1) }
        let estimate = estimateSeconds(profile: profile, addresses: addresses, policy: policy)

        return Plan(arguments: arguments, xmlURL: xmlURL,
                    estimatedSeconds: estimate, addressCount: addresses,
                    isRateLimited: rateLimitSeconds(profile: profile, addresses: addresses,
                                                    policy: policy)
                        > networkSeconds(profile: profile, addresses: addresses, policy: policy))
    }

    /// The longer of two lower bounds: how long the network takes, and how long
    /// the packet-rate cap allows. The cap dominates far more often than it
    /// looks — at 500 pps a single 10000-port scan cannot finish under 20 s.
    public static func estimateSeconds(profile: ScanProfile, addresses: Int, policy: ScanPolicy) -> Double {
        max(2.0,
            networkSeconds(profile: profile, addresses: addresses, policy: policy),
            rateLimitSeconds(profile: profile, addresses: addresses, policy: policy))
    }

    /// Per-host cost times hosts, divided by how many hosts Nmap works on at once.
    public static func networkSeconds(profile: ScanProfile, addresses: Int, policy: ScanPolicy) -> Double {
        let hostGroup = policy.maxHostGroup > 0 ? policy.maxHostGroup : 64
        let concurrency = Double(max(1, min(hostGroup, addresses)))
        let discoveryCost = profile.intensity == .passive ? 0.0 : Double(addresses) * 0.2
        return (Double(addresses) * profile.secondsPerHost) / concurrency + discoveryCost
    }

    /// Probes the run must send, divided by the packets-per-second ceiling.
    public static func rateLimitSeconds(profile: ScanProfile, addresses: Int, policy: ScanPolicy) -> Double {
        guard policy.maxPacketRate > 0 else { return 0 }
        let probes = Double(addresses) * Double(probesPerHost(profile))
        return probes / Double(policy.maxPacketRate)
    }

    /// True when the packet-rate cap, rather than the network, decides how long
    /// the run takes.
    public static func isRateLimitBinding(profile: ScanProfile, addresses: Int,
                                          policy: ScanPolicy) -> Bool {
        rateLimitSeconds(profile: profile, addresses: addresses, policy: policy)
            > networkSeconds(profile: profile, addresses: addresses, policy: policy)
    }

    /// How many ports the profile probes on each host, read back out of its own
    /// arguments so a custom profile is estimated as accurately as a built-in one.
    public static func probesPerHost(_ profile: ScanProfile) -> Int {
        if profile.intensity == .passive { return 2 }
        var index = 0
        while index < profile.arguments.count {
            let token = profile.arguments[index]
            if token == "--top-ports", index + 1 < profile.arguments.count,
               let count = Int(profile.arguments[index + 1]) {
                return count
            }
            if token == "-p", index + 1 < profile.arguments.count {
                return portCount(profile.arguments[index + 1])
            }
            index += 1
        }
        return 1000   // Nmap's own default
    }

    static func portCount(_ spec: String) -> Int {
        var total = 0
        for item in spec.components(separatedBy: ",") {
            var body = item
            if let colon = body.firstIndex(of: ":") { body = String(body[body.index(after: colon)...]) }
            if body == "-" { total += 65_535; continue }
            let bounds = body.components(separatedBy: "-")
            if bounds.count == 2 {
                let low = Int(bounds[0]) ?? 1
                let high = Int(bounds[1]) ?? 65_535
                total += max(0, high - low + 1)
            } else {
                total += 1
            }
        }
        return max(1, total)
    }
}

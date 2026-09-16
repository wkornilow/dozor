import Foundation
import Darwin

public enum TargetValidationError: Error, Equatable, Sendable {
    case empty
    case illegalCharacters(String)
    case unrecognised(String)
    case badCIDR(String)
    case badRange(String)
    case tooManyAddresses(String, Int)

    public var targetText: String? {
        switch self {
        case .empty: return nil
        case .illegalCharacters(let s), .unrecognised(let s), .badCIDR(let s), .badRange(let s):
            return s
        case .tooManyAddresses(let s, _): return s
        }
    }
}

/// Turns free text into `ScanTarget` values, rejecting anything that is not a
/// well-formed address, network, range or hostname. This is the only entry point
/// through which user text can become an Nmap argument.
public enum TargetValidator {

    /// Hard ceiling so a typo like /8 cannot start a 16-million-address scan.
    public static let maxAddressesPerTarget = 65_536

    /// What separates one target from the next in the input field. Shared with
    /// `TargetTextEditor` so the two never drift apart: text the editor writes
    /// must tokenise here exactly the way it did there.
    public static let separators = CharacterSet(charactersIn: " \t\n\r,;")

    /// Everything outside this set is refused outright — it also removes every
    /// shell metacharacter, even though arguments never reach a shell.
    private static let allowed = CharacterSet(charactersIn:
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-/_")

    public static func parse(_ text: String) -> (targets: [ScanTarget], errors: [TargetValidationError]) {
        let tokens = text
            .components(separatedBy: separators)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        guard !tokens.isEmpty else { return ([], [.empty]) }

        var targets: [ScanTarget] = []
        var errors: [TargetValidationError] = []
        var seen = Set<String>()

        for token in tokens {
            switch validate(token) {
            case .success(let target):
                if seen.insert(target.raw).inserted { targets.append(target) }
            case .failure(let error):
                errors.append(error)
            }
        }
        return (targets, errors)
    }

    public static func validate(_ token: String) -> Result<ScanTarget, TargetValidationError> {
        guard !token.isEmpty else { return .failure(.empty) }
        guard token.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            return .failure(.illegalCharacters(token))
        }
        // Nmap treats a leading dash as an option; never let one through.
        guard !token.hasPrefix("-") else { return .failure(.illegalCharacters(token)) }

        if token.contains("/") { return validateCIDR(token) }
        if let ipv4 = parseIPv4(token) {
            return .success(ScanTarget(raw: token, kind: .ipv4, addressCount: 1,
                                       isPrivate: isPrivateIPv4(ipv4)))
        }
        if token.contains(":"), parseIPv6(token) != nil {
            return .success(ScanTarget(raw: token, kind: .ipv6, addressCount: 1,
                                       isPrivate: isPrivateIPv6(token)))
        }
        if token.contains("-") , token.contains(".") { return validateIPv4Range(token) }
        if isHostname(token) {
            return .success(ScanTarget(raw: token, kind: .hostname, addressCount: 1, isPrivate: false))
        }
        return .failure(.unrecognised(token))
    }

    // MARK: - CIDR

    private static func validateCIDR(_ token: String) -> Result<ScanTarget, TargetValidationError> {
        let parts = token.components(separatedBy: "/")
        guard parts.count == 2, let prefix = Int(parts[1]) else { return .failure(.badCIDR(token)) }

        if let ipv4 = parseIPv4(parts[0]) {
            guard (0...32).contains(prefix) else { return .failure(.badCIDR(token)) }
            let count = 1 << (32 - prefix)
            guard count <= maxAddressesPerTarget else {
                return .failure(.tooManyAddresses(token, count))
            }
            return .success(ScanTarget(raw: token, kind: .cidr, addressCount: count,
                                       isPrivate: isPrivateIPv4(ipv4)))
        }
        if parts[0].contains(":"), parseIPv6(parts[0]) != nil {
            guard (0...128).contains(prefix) else { return .failure(.badCIDR(token)) }
            let hostBits = 128 - prefix
            let count = hostBits >= 63 ? Int.max : 1 << hostBits
            guard count <= maxAddressesPerTarget else {
                return .failure(.tooManyAddresses(token, count))
            }
            return .success(ScanTarget(raw: token, kind: .cidr, addressCount: count,
                                       isPrivate: isPrivateIPv6(parts[0])))
        }
        return .failure(.badCIDR(token))
    }

    // MARK: - Octet ranges, e.g. 192.168.1.1-20 or 10.0.1-3.1-254

    private static func validateIPv4Range(_ token: String) -> Result<ScanTarget, TargetValidationError> {
        let octets = token.components(separatedBy: ".")
        guard octets.count == 4 else { return .failure(.badRange(token)) }

        var count = 1
        var firstOctet: Int?
        for (index, octet) in octets.enumerated() {
            let bounds = octet.components(separatedBy: "-")
            switch bounds.count {
            case 1:
                guard let value = Int(octet), (0...255).contains(value) else {
                    return .failure(.badRange(token))
                }
                if index == 0 { firstOctet = value }
            case 2:
                guard let low = Int(bounds[0]), let high = Int(bounds[1]),
                      (0...255).contains(low), (0...255).contains(high), low <= high else {
                    return .failure(.badRange(token))
                }
                if index == 0 { firstOctet = low }
                count *= (high - low + 1)
            default:
                return .failure(.badRange(token))
            }
        }
        guard count <= maxAddressesPerTarget else { return .failure(.tooManyAddresses(token, count)) }
        // Privacy judged on the low end of the first two octets — conservative:
        // a range that starts public is treated as public.
        let isPrivate = firstOctet.map { first -> Bool in
            let secondLow = Int(octets[1].components(separatedBy: "-")[0]) ?? 0
            return isPrivateOctets(first, secondLow)
        } ?? false
        return .success(ScanTarget(raw: token, kind: .ipv4Range, addressCount: count, isPrivate: isPrivate))
    }

    // MARK: - Primitives

    public static func parseIPv4(_ text: String) -> in_addr? {
        var addr = in_addr()
        guard text.components(separatedBy: ".").count == 4 else { return nil }
        guard inet_pton(AF_INET, text, &addr) == 1 else { return nil }
        return addr
    }

    public static func parseIPv6(_ text: String) -> in6_addr? {
        var addr = in6_addr()
        guard inet_pton(AF_INET6, text, &addr) == 1 else { return nil }
        return addr
    }

    private static func isHostname(_ text: String) -> Bool {
        guard text.count <= 253, !text.hasPrefix("."), !text.hasSuffix("-") else { return false }
        let labels = text.components(separatedBy: ".")
        guard labels.allSatisfy({ label in
            !label.isEmpty && label.count <= 63
                && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
        }) else { return false }
        // Require at least one letter so "1.2.3" cannot pass as a hostname.
        return text.contains(where: { $0.isLetter })
    }

    public static func isPrivateIPv4(_ addr: in_addr) -> Bool {
        let host = UInt32(bigEndian: addr.s_addr)
        let a = Int((host >> 24) & 0xff), b = Int((host >> 16) & 0xff)
        return isPrivateOctets(a, b)
    }

    private static func isPrivateOctets(_ a: Int, _ b: Int) -> Bool {
        if a == 10 { return true }                        // 10.0.0.0/8
        if a == 127 { return true }                       // loopback
        if a == 172, (16...31).contains(b) { return true } // 172.16.0.0/12
        if a == 192, b == 168 { return true }             // 192.168.0.0/16
        if a == 169, b == 254 { return true }             // link-local
        if a == 100, (64...127).contains(b) { return true } // CGNAT 100.64.0.0/10
        return false
    }

    public static func isPrivateIPv6(_ text: String) -> Bool {
        let lower = text.lowercased()
        if lower == "::1" { return true }
        if lower.hasPrefix("fe80") { return true }             // link-local
        if let first = lower.first, first == "f" {
            let second = lower.dropFirst().first
            if second == "c" || second == "d" { return true }  // fc00::/7 ULA
        }
        return false
    }
}

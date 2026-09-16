import Foundation

public enum ArgumentPolicyError: Error, Equatable, Sendable {
    case notAllowed(String)
    case malformedValue(String)
    case outputFlagNotAllowed(String)
    case scriptNotAllowed(String)
}

/// Allow-list for Nmap flags that may appear in a profile or custom template.
///
/// Custom templates are the only place a user can type option text, so every
/// token is checked here before it is handed to `Process`. Anything not listed
/// is refused rather than escaped: there is no shell, and no "clever" quoting.
public enum ArgumentPolicy {

    /// Flags taking no value.
    public static let booleanFlags: Set<String> = [
        "-sn", "-sT", "-sV", "-sC", "-Pn", "-PE", "-PP", "-PM", "-n", "-R",
        "-6", "-A", "-O", "-F", "-r", "-v", "-vv", "-d", "--open", "--reason",
        "--traceroute", "--system-dns", "--disable-arp-ping", "--defeat-rst-ratelimit",
        "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
        // Raw-socket scan types: allowed syntactically, gated separately by
        // `requiresRoot` and by organisation policy.
        "-sS", "-sU", "-sA", "-sW", "-sN", "-sF", "-sX",
    ]

    /// Flags taking exactly one value, with a validator for that value.
    public static let valueFlags: [String: (String) -> Bool] = [
        "-p": isPortSpec,
        "--top-ports": isPositiveInt,
        "--exclude-ports": isPortSpec,
        "--version-intensity": { isInt($0, range: 0...9) },
        "--max-retries": { isInt($0, range: 0...10) },
        "--host-timeout": isDuration,
        "--max-rtt-timeout": isDuration,
        "--min-rtt-timeout": isDuration,
        "--initial-rtt-timeout": isDuration,
        "--scan-delay": isDuration,
        "--max-scan-delay": isDuration,
        "--min-rate": isPositiveInt,
        "--max-rate": isPositiveInt,
        "--min-parallelism": isPositiveInt,
        "--max-parallelism": isPositiveInt,
        "--min-hostgroup": isPositiveInt,
        "--max-hostgroup": isPositiveInt,
        "--stats-every": isDuration,
        "--script": isScriptSpec,
        "--dns-servers": isCommaSeparatedAddresses,
        "-PS": isPortSpec,
        "-PA": isPortSpec,
        "-PU": isPortSpec,
    ]

    /// Output flags are owned by the app; a template may not set them.
    private static let outputFlags: Set<String> = [
        "-oX", "-oN", "-oG", "-oA", "-oS", "--stylesheet", "--webxml", "--resume",
        "--script-args", "--script-args-file", "--datadir", "--servicedb",
        "--versiondb", "-iL", "-iR", "--excludefile", "--append-output",
    ]

    /// NSE categories considered safe to run without extra confirmation.
    private static let allowedScriptCategories: Set<String> = [
        "default", "safe", "discovery", "version", "banner",
    ]

    /// Validates a whole argument vector fragment (flags + their values).
    public static func validate(_ arguments: [String]) -> [ArgumentPolicyError] {
        var errors: [ArgumentPolicyError] = []
        var index = 0
        while index < arguments.count {
            let token = arguments[index]
            if outputFlags.contains(token) || outputFlags.contains(where: { token.hasPrefix($0 + "=") }) {
                errors.append(.outputFlagNotAllowed(token))
                index += 1
                continue
            }
            if booleanFlags.contains(token) {
                index += 1
                continue
            }
            // Accept both "--top-ports 100" and "--top-ports=100".
            if let equals = token.firstIndex(of: "="), token.hasPrefix("-") {
                let flag = String(token[token.startIndex..<equals])
                let value = String(token[token.index(after: equals)...])
                if let check = valueFlags[flag] {
                    if !check(value) { errors.append(.malformedValue(token)) }
                } else {
                    errors.append(.notAllowed(flag))
                }
                index += 1
                continue
            }
            if let check = valueFlags[token] {
                guard index + 1 < arguments.count else {
                    errors.append(.malformedValue(token))
                    index += 1
                    continue
                }
                let value = arguments[index + 1]
                if !check(value) { errors.append(.malformedValue("\(token) \(value)")) }
                index += 2
                continue
            }
            errors.append(.notAllowed(token))
            index += 1
        }
        return errors
    }

    /// Splits a template string the user typed into argv tokens. Quotes are not
    /// interpreted — values containing spaces are not valid for any allowed flag.
    public static func tokenize(_ text: String) -> [String] {
        text.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
    }

    // MARK: - Value validators

    static func isInt(_ value: String, range: ClosedRange<Int>) -> Bool {
        guard let number = Int(value) else { return false }
        return range.contains(number)
    }

    static func isPositiveInt(_ value: String) -> Bool {
        guard let number = Int(value) else { return false }
        return number > 0 && number <= 1_000_000
    }

    /// "22", "1-1024", "U:53,T:80", "http*" is *not* accepted.
    static func isPortSpec(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 400 else { return false }
        for item in value.components(separatedBy: ",") {
            var body = item
            if let colon = body.firstIndex(of: ":") {
                let proto = body[body.startIndex..<colon]
                guard ["T", "U", "S", "P"].contains(String(proto)) else { return false }
                body = String(body[body.index(after: colon)...])
            }
            if body == "-" { continue }
            let bounds = body.components(separatedBy: "-")
            guard bounds.count <= 2 else { return false }
            for bound in bounds where !bound.isEmpty {
                guard let port = Int(bound), (0...65535).contains(port) else { return false }
            }
            if bounds.allSatisfy({ $0.isEmpty }) { return false }
        }
        return true
    }

    /// "500ms", "30s", "5m", "1h" or a bare number of seconds.
    static func isDuration(_ value: String) -> Bool {
        guard !value.isEmpty else { return false }
        let suffixes = ["ms", "s", "m", "h"]
        for suffix in suffixes where value.hasSuffix(suffix) {
            let number = String(value.dropLast(suffix.count))
            return !number.isEmpty && Double(number) != nil
        }
        return Double(value) != nil
    }

    /// Only named categories and plain script names; no paths, globs or args.
    static func isScriptSpec(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 200 else { return false }
        for item in value.components(separatedBy: ",") {
            guard !item.isEmpty,
                  item.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
            else { return false }
            if allowedScriptCategories.contains(item) { continue }
            // A concrete script name is fine; wildcards and paths are not.
            guard !item.contains("*"), !item.contains("/") else { return false }
        }
        return true
    }

    static func isCommaSeparatedAddresses(_ value: String) -> Bool {
        let items = value.components(separatedBy: ",")
        guard !items.isEmpty, items.count <= 8 else { return false }
        return items.allSatisfy {
            TargetValidator.parseIPv4($0) != nil || TargetValidator.parseIPv6($0) != nil
        }
    }
}

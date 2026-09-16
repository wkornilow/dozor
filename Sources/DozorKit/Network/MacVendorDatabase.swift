import Foundation

/// Maps the first three bytes of a MAC address to the organisation that
/// registered them, using the prefix table that ships with Nmap.
///
/// Nmap itself only annotates a vendor when it discovered the MAC during a
/// privileged scan. Reading the same table directly means an unprivileged scan
/// can name the hardware too, from the address the system already holds.
public final class MacVendorDatabase: @unchecked Sendable {

    private var prefixes: [String: String] = [:]
    public var isEmpty: Bool { prefixes.isEmpty }
    public let sourcePath: String?

    /// Standard locations, relative to the Nmap binary and then the usual
    /// install prefixes. Only absolute, known paths are read.
    public static func candidatePaths(nmapPath: String?) -> [String] {
        var paths: [String] = []
        if let nmapPath {
            let prefix = URL(fileURLWithPath: nmapPath)
                .deletingLastPathComponent()      // .../bin
                .deletingLastPathComponent()      // .../
            paths.append(prefix.appendingPathComponent("share/nmap/nmap-mac-prefixes").path)
        }
        paths += [
            "/opt/homebrew/share/nmap/nmap-mac-prefixes",
            "/usr/local/share/nmap/nmap-mac-prefixes",
            "/opt/local/share/nmap/nmap-mac-prefixes",
            "/usr/share/nmap/nmap-mac-prefixes",
        ]
        return paths
    }

    public init(nmapPath: String? = nil) {
        let path = Self.candidatePaths(nmapPath: nmapPath)
            .first { FileManager.default.isReadableFile(atPath: $0) }
        sourcePath = path
        guard let path, let text = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        prefixes = Self.parse(text)
    }

    /// Lines look like `001C7F Check Point Software Technologies`; anything
    /// starting with `#` is a comment.
    public static func parse(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            guard !line.hasPrefix("#") else { continue }
            guard let separator = line.firstIndex(of: " ") else { continue }
            let prefix = line[line.startIndex..<separator].uppercased()
            guard prefix.count == 6, prefix.allSatisfy(\.isHexDigit) else { continue }
            let vendor = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            guard !vendor.isEmpty else { continue }
            result[prefix] = vendor
        }
        return result
    }

    /// Accepts "00:1c:7f:00:00:2e" or "001C7F00002E".
    public func vendor(for mac: String) -> String? {
        // A locally administered address was not assigned by a vendor, so any
        // OUI match would be a coincidence, not an identification.
        guard !ArpTable.isLocallyAdministered(mac: mac) else { return nil }
        let digits = mac.filter(\.isHexDigit).uppercased()
        guard digits.count >= 6 else { return nil }
        return prefixes[String(digits.prefix(6))]
    }
}

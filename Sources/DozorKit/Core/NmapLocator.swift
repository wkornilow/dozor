import Foundation

public struct NmapInstallation: Hashable, Sendable {
    public let path: String
    public let version: String
}

public enum NmapLocatorError: Error, Equatable, Sendable {
    case notFound([String])
    case notExecutable(String)
    case versionUnreadable(String)
}

/// Finds the Nmap binary without consulting $PATH from a shell. Only absolute,
/// known-good locations are probed, plus an explicit user-configured override.
public enum NmapLocator {

    public static let searchPaths = [
        "/opt/homebrew/bin/nmap",   // Apple silicon Homebrew
        "/usr/local/bin/nmap",      // Intel Homebrew / manual install
        "/opt/local/bin/nmap",      // MacPorts
        "/usr/bin/nmap",
        "/sw/bin/nmap",
    ]

    public static func locate(override: String? = nil) throws -> NmapInstallation {
        var candidates = searchPaths
        if let override, !override.isEmpty { candidates.insert(override, at: 0) }

        for path in candidates {
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
                  !isDirectory.boolValue else { continue }
            guard FileManager.default.isExecutableFile(atPath: path) else {
                throw NmapLocatorError.notExecutable(path)
            }
            let version = try readVersion(at: path)
            return NmapInstallation(path: path, version: version)
        }
        throw NmapLocatorError.notFound(candidates)
    }

    static func readVersion(at path: String) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["--version"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            throw NmapLocatorError.notExecutable(path)
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard let text = String(data: data, encoding: .utf8),
              let line = text.split(separator: "\n").first
        else { throw NmapLocatorError.versionUnreadable(path) }
        // "Nmap version 7.95 ( https://nmap.org )"
        let scanner = Scanner(string: String(line))
        _ = scanner.scanUpToString("version")
        _ = scanner.scanString("version")
        let version = scanner.scanUpToString(" ")?.trimmingCharacters(in: .whitespaces)
        guard let version, !version.isEmpty else {
            throw NmapLocatorError.versionUnreadable(path)
        }
        return version
    }
}

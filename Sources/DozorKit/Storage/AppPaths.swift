import Foundation

/// Locations for on-disk state. The container directory is created 0700 and
/// every file inside is written 0600, so results are readable only by the
/// account that produced them.
public enum AppPaths {

    public static let bundleIdentifier = "dev.dozor.app"

    public static var container: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Dozor", isDirectory: true)
    }

    public static var runsDirectory: URL { container.appendingPathComponent("runs", isDirectory: true) }
    public static var profilesFile: URL { container.appendingPathComponent("profiles.json") }
    public static var policyFile: URL { container.appendingPathComponent("policy.json") }
    public static var settingsFile: URL { container.appendingPathComponent("settings.json") }
    public static var scheduleFile: URL { container.appendingPathComponent("schedules.json") }
    public static var auditLog: URL { container.appendingPathComponent("audit.jsonl") }
    public static var networkDirectory: URL { container.appendingPathComponent("network", isDirectory: true) }

    /// One file per subnet, so the overview's "was here" survives a relaunch
    /// without polluting the scan history.
    public static func networkInventoryFile(scopeCIDR: String) -> URL {
        let safe = scopeCIDR.replacingOccurrences(of: "/", with: "_")
        return networkDirectory.appendingPathComponent("\(safe).json")
    }
    public static var scratchDirectory: URL { container.appendingPathComponent("scratch", isDirectory: true) }

    /// Everything lived under "NmapMac" before the app was named. Move it once,
    /// so an existing scan history, profile set and audit trail survive the
    /// rename instead of being silently orphaned next to the new directory.
    static func migrateLegacyContainerIfNeeded() {
        let manager = FileManager.default
        let legacy = manager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("NmapMac", isDirectory: true)
        guard manager.fileExists(atPath: legacy.path),
              !manager.fileExists(atPath: container.path)
        else { return }
        try? manager.moveItem(at: legacy, to: container)
    }

    @discardableResult
    public static func ensureContainers() throws -> URL {
        migrateLegacyContainerIfNeeded()
        for directory in [container, runsDirectory, scratchDirectory, networkDirectory] {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            // createDirectory ignores permissions on an existing directory.
            try? FileManager.default.setAttributes([.posixPermissions: 0o700],
                                                   ofItemAtPath: directory.path)
        }
        return container
    }

    /// Atomic, owner-only write.
    public static func writeProtected(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

import Foundation

public enum ScanRunStatus: String, Codable, Sendable {
    case running, completed, failed, cancelled
}

/// One entry in the run history: what was asked for, who asked, and what came back.
public struct ScanRun: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var profileName: String
    public var profileID: UUID?
    public var targets: [ScanTarget]
    /// Exact argument vector passed to Nmap (argv, never a shell string).
    public var arguments: [String]
    public var startedAt: Date
    public var finishedAt: Date?
    public var status: ScanRunStatus
    public var author: String
    public var exitCode: Int32?
    public var errorMessage: String?
    public var result: ScanResult?
    /// Raw Nmap XML, kept so reports can be re-exported without a re-scan.
    public var rawXML: String?
    public var log: [String]
    public var notes: String

    public init(id: UUID = UUID(), profileName: String, profileID: UUID? = nil,
                targets: [ScanTarget], arguments: [String], startedAt: Date = Date(),
                finishedAt: Date? = nil, status: ScanRunStatus = .running,
                author: String = NSUserName(), exitCode: Int32? = nil,
                errorMessage: String? = nil, result: ScanResult? = nil,
                rawXML: String? = nil, log: [String] = [], notes: String = "") {
        self.id = id
        self.profileName = profileName
        self.profileID = profileID
        self.targets = targets
        self.arguments = arguments
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.status = status
        self.author = author
        self.exitCode = exitCode
        self.errorMessage = errorMessage
        self.result = result
        self.rawXML = rawXML
        self.log = log
        self.notes = notes
    }

    public var duration: TimeInterval? {
        finishedAt.map { $0.timeIntervalSince(startedAt) }
    }

    /// Human-readable preview of the command, for display only — never executed.
    public func commandPreview(nmapPath: String = "nmap") -> String {
        ([nmapPath] + arguments).map { arg in
            arg.contains(where: { $0 == " " }) ? "'\(arg)'" : arg
        }.joined(separator: " ")
    }

    /// A light-weight row for the history list, without the heavy payload.
    public var summaryLine: String {
        let up = result?.hostsUp ?? 0
        let open = result?.hosts.reduce(0) { $0 + $1.openPorts.count } ?? 0
        return "\(up) / \(open)"
    }
}

import Foundation

public struct AuditEntry: Codable, Hashable, Sendable, Identifiable {
    public enum Action: String, Codable, Sendable {
        case appStarted
        case scanRequested
        case scanBlocked
        case scanConfirmed
        case scanStarted
        case scanFinished
        case scanFailed
        case scanCancelled
        case runDeleted
        case runExported
        case profileCreated
        case profileEdited
        case profileDeleted
        case policyChanged
        case scheduleChanged
    }

    public var id: UUID
    public var timestamp: Date
    public var actor: String
    public var action: Action
    public var detail: String
    public var runID: UUID?

    public init(id: UUID = UUID(), timestamp: Date = Date(), actor: String = NSUserName(),
                action: Action, detail: String, runID: UUID? = nil) {
        self.id = id
        self.timestamp = timestamp
        self.actor = actor
        self.action = action
        self.detail = detail
        self.runID = runID
    }
}

/// Append-only JSON Lines audit trail. Appends are serialised and the file is
/// never rewritten in place, so an entry cannot be silently edited by the app.
public final class AuditLog: @unchecked Sendable {

    public static let shared = AuditLog()

    private let queue = DispatchQueue(label: "dev.dozor.audit")
    private let url: URL
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    public init(url: URL = AppPaths.auditLog) {
        self.url = url
    }

    public func record(_ action: AuditEntry.Action, _ detail: String, runID: UUID? = nil) {
        let entry = AuditEntry(action: action, detail: detail, runID: runID)
        queue.async { [url, encoder] in
            guard var data = try? encoder.encode(entry) else { return }
            data.append(0x0A)
            try? AppPaths.ensureContainers()
            if let handle = try? FileHandle(forWritingTo: url) {
                defer { try? handle.close() }
                _ = try? handle.seekToEnd()
                try? handle.write(contentsOf: data)
            } else {
                try? AppPaths.writeProtected(data, to: url)
            }
        }
    }

    public func readAll(limit: Int = 500) -> [AuditEntry] {
        queue.sync {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return text.split(separator: "\n")
                .suffix(limit)
                .compactMap { line in
                    guard let data = line.data(using: .utf8) else { return nil }
                    return try? decoder.decode(AuditEntry.self, from: data)
                }
                .reversed()
        }
    }
}

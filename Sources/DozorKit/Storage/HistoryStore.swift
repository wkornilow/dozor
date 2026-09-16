import Foundation

/// One run per file, so a large history never has to be loaded or rewritten
/// wholesale. The index is rebuilt by reading only the header of each file.
public final class HistoryStore: @unchecked Sendable {

    private let directory: URL
    private let queue = DispatchQueue(label: "dev.dozor.history")
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return encoder
    }()
    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    public init(directory: URL = AppPaths.runsDirectory) {
        self.directory = directory
    }

    public func save(_ run: ScanRun) throws {
        try AppPaths.ensureContainers()
        let data = try encoder.encode(run)
        try queue.sync {
            try AppPaths.writeProtected(data, to: fileURL(for: run.id))
        }
    }

    public func load(_ id: UUID) throws -> ScanRun {
        let data = try Data(contentsOf: fileURL(for: id))
        return try decoder.decode(ScanRun.self, from: data)
    }

    public func loadAll() -> [ScanRun] {
        queue.sync {
            guard let files = try? FileManager.default.contentsOfDirectory(
                at: directory, includingPropertiesForKeys: [.contentModificationDateKey]
            ) else { return [] }
            return files
                .filter { $0.pathExtension == "json" }
                .compactMap { url -> ScanRun? in
                    guard let data = try? Data(contentsOf: url) else { return nil }
                    return try? decoder.decode(ScanRun.self, from: data)
                }
                .sorted { $0.startedAt > $1.startedAt }
        }
    }

    public func delete(_ id: UUID) throws {
        try queue.sync {
            try FileManager.default.removeItem(at: fileURL(for: id))
        }
    }

    private func fileURL(for id: UUID) -> URL {
        directory.appendingPathComponent("\(id.uuidString).json")
    }
}

/// Small JSON-file store for profiles, policy, settings and schedules.
public final class CodableFileStore<Value: Codable & Sendable>: @unchecked Sendable {

    private let url: URL
    private let fallback: Value
    private let queue = DispatchQueue(label: "dev.dozor.filestore")

    public init(url: URL, fallback: Value) {
        self.url = url
        self.fallback = fallback
    }

    public func load() -> Value {
        queue.sync {
            guard let data = try? Data(contentsOf: url) else { return fallback }
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return (try? decoder.decode(Value.self, from: data)) ?? fallback
        }
    }

    public func save(_ value: Value) throws {
        try AppPaths.ensureContainers()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        try queue.sync { try AppPaths.writeProtected(data, to: url) }
    }
}

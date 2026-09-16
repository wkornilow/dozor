import Foundation

public enum ScanEvent: Sendable {
    case started(command: String)
    case log(String)
    case progress(fraction: Double, etaSeconds: Double?)
    case finished(ScanResult, rawXML: String, exitCode: Int32)
    case failed(NmapRunnerError)
}

public enum NmapRunnerError: Error, Sendable, Equatable {
    case launchFailed(String)
    case permissionDenied
    case networkUnreachable
    case noXMLOutput
    case parseFailed(String)
    case nonZeroExit(Int32, stderr: String)
    case cancelled
}

/// Runs Nmap as a child process with an explicit argument vector.
///
/// There is no shell anywhere in this path: `Process` calls `posix_spawn`
/// directly, so no argument is ever word-split, globbed or interpreted.
public final class NmapRunner: @unchecked Sendable {

    private let executablePath: String
    private let queue = DispatchQueue(label: "dev.dozor.runner")
    private var process: Process?

    public init(executablePath: String) {
        self.executablePath = executablePath
    }

    public var isRunning: Bool { queue.sync { process?.isRunning ?? false } }

    public func cancel() {
        queue.sync {
            guard let process, process.isRunning else { return }
            // SIGINT lets Nmap flush the XML it has so far.
            process.interrupt()
        }
    }

    /// Streams progress and log lines, then one terminal event.
    public func run(plan: ArgumentBuilder.Plan) -> AsyncStream<ScanEvent> {
        AsyncStream(bufferingPolicy: .bufferingNewest(512)) { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executablePath)
            process.arguments = plan.arguments
            // Minimal, fixed environment: nothing inherited that could alter
            // how the child resolves libraries or data files.
            process.environment = [
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "HOME": NSHomeDirectory(),
            ]
            process.currentDirectoryURL = plan.xmlURL.deletingLastPathComponent()

            let outPipe = Pipe(), errPipe = Pipe()
            process.standardOutput = outPipe
            process.standardError = errPipe
            process.standardInput = FileHandle.nullDevice

            let stderrBuffer = LineBuffer()
            let stdoutBuffer = LineBuffer()

            outPipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                // Empty data means EOF. The handler must be removed here or the
                // dispatch source keeps firing in a tight loop, burning a core.
                guard !data.isEmpty else {
                    handle.readabilityHandler = nil
                    return
                }
                for line in stdoutBuffer.append(data) {
                    if let progress = Self.parseProgress(line) {
                        continuation.yield(.progress(fraction: progress.0, etaSeconds: progress.1))
                    } else {
                        continuation.yield(.log(line))
                    }
                }
            }
            errPipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                guard !data.isEmpty else {
                    handle.readabilityHandler = nil
                    return
                }
                for line in stderrBuffer.append(data) {
                    continuation.yield(.log(line))
                }
            }

            process.terminationHandler = { [weak self] finished in
                outPipe.fileHandleForReading.readabilityHandler = nil
                errPipe.fileHandleForReading.readabilityHandler = nil
                for line in stdoutBuffer.flush() { continuation.yield(.log(line)) }
                let trailingErr = stderrBuffer.flush()
                for line in trailingErr { continuation.yield(.log(line)) }

                self?.queue.sync { self?.process = nil }

                let stderrText = stderrBuffer.allText
                let code = finished.terminationStatus

                if finished.terminationReason == .uncaughtSignal && code != 0 {
                    continuation.yield(.failed(.cancelled))
                    continuation.finish()
                    return
                }

                // Nmap writes the XML even on interrupt, so try to parse first.
                guard let xmlData = try? Data(contentsOf: plan.xmlURL),
                      !xmlData.isEmpty else {
                    continuation.yield(.failed(Self.classify(exitCode: code, stderr: stderrText)))
                    continuation.finish()
                    return
                }
                do {
                    let result = try NmapXMLParser().parse(data: xmlData)
                    let rawXML = String(data: xmlData, encoding: .utf8) ?? ""
                    continuation.yield(.finished(result, rawXML: rawXML, exitCode: code))
                } catch {
                    continuation.yield(.failed(.parseFailed(String(describing: error))))
                }
                continuation.finish()
            }

            continuation.onTermination = { @Sendable reason in
                if case .cancelled = reason { self.cancel() }
            }

            do {
                try process.run()
                queue.sync { self.process = process }
                continuation.yield(.started(command: ([executablePath] + plan.arguments).joined(separator: " ")))
            } catch {
                continuation.yield(.failed(.launchFailed(error.localizedDescription)))
                continuation.finish()
            }
        }
    }

    // MARK: - Output interpretation

    /// "Stats: 0:00:12 elapsed; ... About 34.56% done; ETC: 12:01 (0:00:23 remaining)"
    public static func parseProgress(_ line: String) -> (Double, Double?)? {
        guard let range = line.range(of: "About ") else { return nil }
        let rest = line[range.upperBound...]
        guard let percentEnd = rest.range(of: "% done") else { return nil }
        guard let percent = Double(rest[rest.startIndex..<percentEnd.lowerBound]) else { return nil }

        var eta: Double?
        if let remainingRange = line.range(of: " remaining)"),
           let openParen = line[line.startIndex..<remainingRange.lowerBound].lastIndex(of: "(") {
            let clock = line[line.index(after: openParen)..<remainingRange.lowerBound]
            eta = parseClock(String(clock))
        }
        return (percent / 100.0, eta)
    }

    /// "0:01:23" → 83
    public static func parseClock(_ text: String) -> Double? {
        let parts = text.split(separator: ":").compactMap { Double($0) }
        guard !parts.isEmpty, parts.count <= 3 else { return nil }
        return parts.reduce(0) { $0 * 60 + $1 }
    }

    static func classify(exitCode: Int32, stderr: String) -> NmapRunnerError {
        let lower = stderr.lowercased()
        if lower.contains("requires root") || lower.contains("operation not permitted")
            || lower.contains("you requested a scan type which requires root") {
            return .permissionDenied
        }
        if lower.contains("network is unreachable") || lower.contains("no route to host")
            || lower.contains("failed to resolve") {
            return .networkUnreachable
        }
        if stderr.isEmpty { return .noXMLOutput }
        return .nonZeroExit(exitCode, stderr: stderr)
    }
}

/// Splits streamed bytes into complete lines; keeps the full text for diagnosis.
final class LineBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var partial = ""
    private var everything = ""

    var allText: String { lock.withLock { everything } }

    func append(_ data: Data) -> [String] {
        guard let text = String(data: data, encoding: .utf8) else { return [] }
        return lock.withLock {
            everything += text
            partial += text
            var lines = partial.components(separatedBy: "\n")
            partial = lines.removeLast()
            return lines.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
    }

    func flush() -> [String] {
        lock.withLock {
            let remainder = partial.trimmingCharacters(in: .whitespacesAndNewlines)
            partial = ""
            return remainder.isEmpty ? [] : [remainder]
        }
    }
}

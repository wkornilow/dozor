import Foundation
import DozorKit

/// End-to-end check against the loopback interface. Runs a real Nmap process,
/// so it is opt-in: `DOZOR_LIVE=1 swift run DozorKitTests`.
func runLiveScanTests() {
    guard ProcessInfo.processInfo.environment["DOZOR_LIVE"] == "1" else { return }

    suite("Live scan (loopback)") {
        test("locates nmap") {
            let installation = try NmapLocator.locate()
            expect(!installation.version.isEmpty, "version read")
            expect(FileManager.default.isExecutableFile(atPath: installation.path), "executable")
        }

        test("scans 127.0.0.1 and parses the result") {
            let installation = try NmapLocator.locate()
            let target = try TargetValidator.validate("127.0.0.1").get()
            let xmlURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("dozor-live-\(UUID().uuidString).xml")
            defer { try? FileManager.default.removeItem(at: xmlURL) }

            var profile = BuiltInProfiles.quick
            profile.arguments = ["-sT", "--top-ports", "20", "--reason"]

            let plan = try ArgumentBuilder.build(profile: profile, targets: [target],
                                                 policy: .default, xmlURL: xmlURL)
            let runner = NmapRunner(executablePath: installation.path)

            let semaphore = DispatchSemaphore(value: 0)
            nonisolated(unsafe) var outcome: ScanResult?
            nonisolated(unsafe) var failure: NmapRunnerError?

            Task {
                for await event in runner.run(plan: plan) {
                    switch event {
                    case .finished(let result, _, _): outcome = result
                    case .failed(let error): failure = error
                    default: break
                    }
                }
                semaphore.signal()
            }
            let waited = semaphore.wait(timeout: .now() + 120)
            expect(waited == .success, "scan finished within the timeout")
            expect(failure == nil, "no failure, got \(String(describing: failure))")

            let result = try require(outcome, "no result produced")
            expectEqual(result.hostsUp, 1, "loopback is up")
            expectEqual(result.hosts.first?.address, "127.0.0.1", "address parsed")
        }
    }
}

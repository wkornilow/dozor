import Foundation

/// Minimal test harness: the Command Line Tools ship neither XCTest nor
/// swift-testing, so the suite runs as an ordinary executable.
/// Replace with swift-testing once the project is built with Xcode.
final class TestRunner {
    static let shared = TestRunner()

    private var failures: [String] = []
    private var checks = 0
    private var currentSuite = ""

    func suite(_ name: String, _ body: () throws -> Void) {
        currentSuite = name
        print("\n\u{1B}[1m\(name)\u{1B}[0m")
        do {
            try body()
        } catch {
            record(failure: "threw \(error)", label: "suite body")
        }
    }

    func test(_ name: String, _ body: () throws -> Void) {
        let before = failures.count
        do {
            try body()
        } catch {
            record(failure: "threw \(error)", label: name)
        }
        let symbol = failures.count == before ? "\u{1B}[32m✓\u{1B}[0m" : "\u{1B}[31m✗\u{1B}[0m"
        print("  \(symbol) \(name)")
    }

    func expect(_ condition: Bool, _ label: String,
                file: StaticString = #file, line: UInt = #line) {
        checks += 1
        if !condition {
            record(failure: "\(label)", label: label, file: file, line: line)
        }
    }

    func expectEqual<T: Equatable>(_ lhs: T, _ rhs: T, _ label: String,
                                   file: StaticString = #file, line: UInt = #line) {
        checks += 1
        if lhs != rhs {
            record(failure: "\(label): \(lhs) != \(rhs)", label: label, file: file, line: line)
        }
    }

    private func record(failure: String, label: String,
                        file: StaticString = #file, line: UInt = #line) {
        let location = "\(URL(fileURLWithPath: "\(file)").lastPathComponent):\(line)"
        failures.append("[\(currentSuite)] \(failure)  (\(location))")
    }

    func finish() -> Never {
        print("\n\(checks) checks, \(failures.count) failures")
        for failure in failures { print("  \u{1B}[31m\(failure)\u{1B}[0m") }
        exit(failures.isEmpty ? 0 : 1)
    }
}

func suite(_ name: String, _ body: () throws -> Void) { TestRunner.shared.suite(name, body) }
func test(_ name: String, _ body: () throws -> Void) { TestRunner.shared.test(name, body) }
func expect(_ condition: Bool, _ label: String = "", file: StaticString = #file, line: UInt = #line) {
    TestRunner.shared.expect(condition, label.isEmpty ? "expectation failed" : label, file: file, line: line)
}
func expectEqual<T: Equatable>(_ lhs: T, _ rhs: T, _ label: String = "",
                               file: StaticString = #file, line: UInt = #line) {
    TestRunner.shared.expectEqual(lhs, rhs, label.isEmpty ? "values differ" : label, file: file, line: line)
}

struct TestFailure: Error { let message: String }

func require<T>(_ value: T?, _ label: String = "required value was nil") throws -> T {
    guard let value else { throw TestFailure(message: label) }
    return value
}

extension Result {
    var isFailure: Bool { if case .failure = self { return true } else { return false } }
}

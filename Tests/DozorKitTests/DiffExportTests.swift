import Foundation
import DozorKit

func runDiffTests() {
    suite("Diff") {
        func result(hosts: [HostResult]) -> ScanResult {
            ScanResult(hosts: hosts, hostsUp: hosts.filter { $0.state == "up" }.count)
        }

        test("detects opened, closed, changed and missing") {
            let baseline = result(hosts: [
                HostResult(address: "10.0.0.1", addressType: "ipv4", state: "up", ports: [
                    PortInfo(port: 22, proto: "tcp", state: "open", serviceName: "ssh",
                             product: "OpenSSH", version: "9.5"),
                    PortInfo(port: 80, proto: "tcp", state: "open", serviceName: "http"),
                ]),
                HostResult(address: "10.0.0.2", addressType: "ipv4", state: "up"),
            ])
            let current = result(hosts: [
                HostResult(address: "10.0.0.1", addressType: "ipv4", state: "up", ports: [
                    PortInfo(port: 22, proto: "tcp", state: "open", serviceName: "ssh",
                             product: "OpenSSH", version: "9.6"),
                    PortInfo(port: 443, proto: "tcp", state: "open", serviceName: "https"),
                ]),
                HostResult(address: "10.0.0.3", addressType: "ipv4", state: "up"),
            ])

            let diff = ScanDiff.compare(baseline: baseline, current: current)
            expectEqual(diff.newHosts.map(\.address), ["10.0.0.3"], "new hosts")
            expectEqual(diff.missingHosts.map(\.address), ["10.0.0.2"], "missing hosts")
            expectEqual(diff.openedCount, 1, "opened ports")
            expectEqual(diff.closedCount, 1, "closed ports")
            expectEqual(diff.serviceChangedCount, 1, "service changes")
        }

        test("identical results produce no diff") {
            let hosts = [HostResult(address: "10.0.0.1", addressType: "ipv4", state: "up",
                                    ports: [PortInfo(port: 22, proto: "tcp", state: "open")])]
            let diff = ScanDiff.compare(baseline: result(hosts: hosts), current: result(hosts: hosts))
            expect(diff.isEmpty, "no differences expected")
        }
    }
}

func runExportTests() {
    suite("Export") {
        func sampleRun() -> ScanRun {
            var run = ScanRun(profileName: "Test", targets: [], arguments: ["-sT"])
            run.rawXML = "<nmaprun/>"
            run.result = ScanResult(hosts: [
                HostResult(address: "10.0.0.1", addressType: "ipv4", hostnames: ["a,b"], state: "up",
                           ports: [PortInfo(port: 80, proto: "tcp", state: "open",
                                            serviceName: "http",
                                            product: "<script>alert(1)</script>")]),
            ], hostsUp: 1)
            return run
        }

        test("HTML escapes attacker-controlled banner text") {
            let data = try Exporter.data(for: sampleRun(), format: .html)
            let html = try require(String(data: data, encoding: .utf8))
            expect(!html.contains("<script>alert(1)</script>"), "raw script tag must not appear")
            expect(html.contains("&lt;script&gt;"), "banner is escaped")
        }

        test("CSV quotes fields containing separators") {
            let data = try Exporter.data(for: sampleRun(), format: .csv)
            let csv = try require(String(data: data, encoding: .utf8))
            expect(csv.contains("\"a,b\""), "comma-containing field quoted")
            expect(csv.contains("10.0.0.1"), "address present")
        }

        test("JSON round-trips a run") {
            let data = try Exporter.data(for: sampleRun(), format: .json)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let decoded = try decoder.decode(ScanRun.self, from: data)
            expectEqual(decoded.result?.hosts.first?.address, "10.0.0.1", "address survives round trip")
            expect(decoded.rawXML == nil, "raw XML is not duplicated into JSON")
        }

        test("XML export returns the original Nmap document") {
            let data = try Exporter.data(for: sampleRun(), format: .xml)
            expectEqual(String(data: data, encoding: .utf8), "<nmaprun/>", "raw XML preserved")
        }
    }
}

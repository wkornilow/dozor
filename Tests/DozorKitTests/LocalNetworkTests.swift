import Foundation
import DozorKit

private func iface(_ name: String, _ address: String, _ netmask: String,
                   up: Bool = true, running: Bool = true,
                   loopback: Bool = false, pointToPoint: Bool = false) -> InterfaceAddress {
    InterfaceAddress(name: name, address: address, netmask: netmask,
                     isUp: up, isRunning: running,
                     isLoopback: loopback, isPointToPoint: pointToPoint)
}

func runLocalNetworkTests() {
    suite("Netmask arithmetic") {
        test("contiguous masks convert to a prefix length") {
            expectEqual(LocalNetworks.prefixLength(ofMask: "255.255.255.0"), 24, "/24")
            expectEqual(LocalNetworks.prefixLength(ofMask: "255.255.0.0"), 16, "/16")
            expectEqual(LocalNetworks.prefixLength(ofMask: "255.255.255.252"), 30, "/30")
            expectEqual(LocalNetworks.prefixLength(ofMask: "255.255.255.255"), 32, "/32")
            expectEqual(LocalNetworks.prefixLength(ofMask: "0.0.0.0"), 0, "/0")
        }

        test("non-contiguous and malformed masks are refused") {
            expect(LocalNetworks.prefixLength(ofMask: "255.0.255.0") == nil, "holes in the mask")
            expect(LocalNetworks.prefixLength(ofMask: "255.255.255.1") == nil, "trailing one bit")
            expect(LocalNetworks.prefixLength(ofMask: "not-a-mask") == nil, "garbage")
        }

        test("network base address is masked correctly") {
            expectEqual(LocalNetworks.networkAddress("192.168.30.9", prefix: 24), "192.168.30.0", "/24 base")
            expectEqual(LocalNetworks.networkAddress("10.1.2.3", prefix: 16), "10.1.0.0", "/16 base")
            expectEqual(LocalNetworks.networkAddress("172.16.5.9", prefix: 12), "172.16.0.0", "/12 base")
            expectEqual(LocalNetworks.networkAddress("8.8.8.8", prefix: 0), "0.0.0.0", "/0 base")
        }
    }

    suite("Network suggestions") {
        test("a typical Mac on Wi-Fi yields its own /24") {
            // Exactly what getifaddrs reports for en0 on the development machine.
            let suggestions = LocalNetworks.suggestions(
                from: [iface("en0", "192.168.30.9", "255.255.255.0")],
                primaryInterface: "en0",
                displayNames: ["en0": "Wi-Fi"]
            )
            expectEqual(suggestions.count, 1, "one suggestion")
            let first = try require(suggestions.first)
            expectEqual(first.kind, .network, "kind")
            expectEqual(first.target.raw, "192.168.30.0/24", "cidr")
            expectEqual(first.target.addressCount, 256, "address count")
            expect(first.target.isPrivate, "private range")
            expect(!first.isNarrowed, "a /24 needs no narrowing")
            expectEqual(first.displayName, "Wi-Fi", "friendly name")
        }

        test("interfaces with nothing scannable behind them are dropped") {
            // Every one of these is present on the development machine.
            let suggestions = LocalNetworks.suggestions(from: [
                iface("lo0", "127.0.0.1", "255.0.0.0", loopback: true),
                iface("utun3", "10.8.0.2", "255.255.255.255", pointToPoint: true),
                iface("awdl0", "169.254.11.4", "255.255.0.0"),
                iface("en4", "192.168.50.3", "255.255.255.0", up: false),
                iface("en5", "192.168.60.3", "255.255.255.0", running: false),
            ])
            expect(suggestions.isEmpty, "expected nothing, got \(suggestions.map(\.target.raw))")
        }

        test("a wider network is narrowed to the /24 around this Mac") {
            let suggestions = LocalNetworks.suggestions(
                from: [iface("en0", "172.16.5.9", "255.255.0.0")]
            )
            let first = try require(suggestions.first)
            expectEqual(first.target.raw, "172.16.5.0/24", "narrowed cidr")
            expectEqual(first.target.addressCount, 256, "address count")
            expect(first.isNarrowed, "flagged as narrowed")
            expectEqual(first.originalPrefix, 16, "real prefix kept")
        }

        test("two interfaces on one subnet produce one suggestion") {
            let suggestions = LocalNetworks.suggestions(from: [
                iface("en0", "192.168.30.9", "255.255.255.0"),
                iface("en7", "192.168.30.40", "255.255.255.0"),
            ])
            expectEqual(suggestions.count, 1, "de-duplicated")
        }

        test("the primary interface sorts first") {
            let suggestions = LocalNetworks.suggestions(from: [
                iface("en7", "10.0.7.5", "255.255.255.0"),
                iface("en0", "192.168.30.9", "255.255.255.0"),
            ], primaryInterface: "en0")
            expectEqual(suggestions.first?.target.raw, "192.168.30.0/24", "primary first")
        }

        test("the gateway is offered next to the network it belongs to") {
            let suggestions = LocalNetworks.suggestions(
                from: [iface("en0", "192.168.30.9", "255.255.255.0")],
                gateway: "192.168.30.1",
                primaryInterface: "en0",
                displayNames: ["en0": "Wi-Fi"]
            )
            expectEqual(suggestions.count, 2, "network plus gateway")
            expectEqual(suggestions[0].kind, .network, "network first")
            expectEqual(suggestions[1].kind, .gateway, "gateway second")
            expectEqual(suggestions[1].target.raw, "192.168.30.1", "gateway address")
            expectEqual(suggestions[1].target.addressCount, 1, "single host")
            expectEqual(suggestions[1].displayName, "Wi-Fi", "gateway inherits the interface name")
        }

        test("a gateway outside every known network is dropped") {
            // A stale value from the system store must not become a scan target.
            let suggestions = LocalNetworks.suggestions(
                from: [iface("en0", "192.168.30.9", "255.255.255.0")],
                gateway: "10.99.99.1"
            )
            expectEqual(suggestions.count, 1, "gateway rejected")
            expect(!suggestions.contains { $0.kind == .gateway }, "no gateway suggestion")
        }

        test("hostile text in a gateway value cannot become a target") {
            let suggestions = LocalNetworks.suggestions(
                from: [iface("en0", "192.168.30.9", "255.255.255.0")],
                gateway: "192.168.30.1; rm -rf /"
            )
            expect(!suggestions.contains { $0.kind == .gateway }, "rejected by the validator")
        }

        test("every suggestion round-trips through the target validator") {
            let suggestions = LocalNetworks.suggestions(from: [
                iface("en0", "192.168.30.9", "255.255.255.0"),
                iface("en7", "10.4.0.17", "255.255.240.0"),
            ], gateway: "192.168.30.1")
            expect(!suggestions.isEmpty, "expected suggestions to check")
            for suggestion in suggestions {
                let revalidated = TargetValidator.validate(suggestion.target.raw)
                expect(!revalidated.isFailure, "\(suggestion.target.raw) must revalidate")
                expectEqual(try? revalidated.get(), suggestion.target,
                            "\(suggestion.target.raw) must match the validator's own value")
            }
        }

        test("point-to-point and single-host masks never appear") {
            let suggestions = LocalNetworks.suggestions(from: [
                iface("en0", "192.168.30.9", "255.255.255.255"),
                iface("en1", "192.168.31.9", "255.255.255.254"),
            ])
            expect(suggestions.isEmpty, "a /31 or /32 has no network to scan")
        }
    }

    suite("Target text toggling") {
        let cidr = "192.168.30.0/24"

        test("adding a target to an empty field") {
            expectEqual(TargetTextEditor.toggling(cidr, in: ""), cidr, "from empty")
        }

        test("the user's separator style survives") {
            expectEqual(TargetTextEditor.toggling(cidr, in: "10.0.0.1"),
                        "10.0.0.1 \(cidr)", "spaces")
            expectEqual(TargetTextEditor.toggling(cidr, in: "10.0.0.1, 8.8.8.8"),
                        "10.0.0.1, 8.8.8.8, \(cidr)", "commas")
            expectEqual(TargetTextEditor.toggling(cidr, in: "10.0.0.1\n8.8.8.8"),
                        "10.0.0.1\n8.8.8.8\n\(cidr)", "one per line")
        }

        test("toggling a present target removes every occurrence") {
            expectEqual(TargetTextEditor.toggling(cidr, in: "10.0.0.1 \(cidr)"), "10.0.0.1", "one copy")
            expectEqual(TargetTextEditor.toggling(cidr, in: cidr), "", "last one")
            expectEqual(TargetTextEditor.toggling(cidr, in: "\(cidr) 10.0.0.1 \(cidr)"),
                        "10.0.0.1", "duplicates")
        }

        test("a click tidies stray separators") {
            expectEqual(TargetTextEditor.toggling(cidr, in: "  10.0.0.1 ,, "),
                        "10.0.0.1, \(cidr)", "normalised")
        }

        test("containment is textual, not semantic") {
            expect(!TargetTextEditor.contains(cidr, in: "192.168.30.5"),
                   "an address inside the range is not the range")
            expect(TargetTextEditor.contains("Host.local", in: "host.local"),
                   "hostnames compare case-insensitively")
        }

        test("what a toggle writes is what the parser reads back") {
            let text = TargetTextEditor.toggling(cidr, in: "10.0.0.1, 8.8.8.8")
            let parsed = TargetValidator.parse(text)
            expect(parsed.errors.isEmpty, "no new parse errors: \(parsed.errors)")
            expectEqual(parsed.targets.map(\.raw), ["10.0.0.1", "8.8.8.8", cidr], "same tokens")
        }

        test("toggling twice restores the original set of targets") {
            let once = TargetTextEditor.toggling(cidr, in: "10.0.0.1 8.8.8.8")
            let twice = TargetTextEditor.toggling(cidr, in: once)
            expectEqual(TargetValidator.parse(twice).targets.map(\.raw),
                        ["10.0.0.1", "8.8.8.8"], "round trip")
        }
    }

    suite("Live interface enumeration") {
        test("reading the real interface list produces usable records") {
            // Read-only local system call: no traffic, no subprocess.
            let interfaces = LocalNetworks.currentInterfaces()
            for interface in interfaces {
                expect(TargetValidator.parseIPv4(interface.address) != nil,
                       "\(interface.name) address \(interface.address) must parse")
                expect(TargetValidator.parseIPv4(interface.netmask) != nil,
                       "\(interface.name) netmask \(interface.netmask) must parse")
                expect(!interface.name.isEmpty, "interface name present")
            }
            // Every machine has a loopback, so an empty list means the walk broke.
            expect(!interfaces.isEmpty, "expected at least the loopback interface")
        }

        test("suggestions built from the real list are all valid targets") {
            for suggestion in LocalNetworks.suggestions(from: LocalNetworks.currentInterfaces()) {
                expect(!TargetValidator.validate(suggestion.target.raw).isFailure,
                       "\(suggestion.target.raw) must be a valid target")
            }
        }
    }
}

/// Prints what this machine would actually be offered. Opt-in, because the
/// output depends on whatever network the developer happens to be on:
/// `DOZOR_DUMP_NETWORKS=1 swift run DozorKitTests`
func dumpLocalNetworks() {
    guard ProcessInfo.processInfo.environment["DOZOR_DUMP_NETWORKS"] == "1" else { return }
    let info = SystemNetworkInfo.current()
    print("\nSystem info: router=\(info.router ?? "-") primary=\(info.primaryInterface ?? "-")")
    print("Display names: \(info.displayNames.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " "))")
    let arp = ArpTable.current()
    print("ARP entries: \(arp.count)")
    for (address, mac) in arp.sorted(by: { $0.key < $1.key }) {
        print("  \(address) -> \(mac)\(ArpTable.isLocallyAdministered(mac: mac) ? "  (locally administered)" : "")")
    }
    let vendors = MacVendorDatabase()
    print("Vendor table: \(vendors.sourcePath ?? "not found")")
    var probe = ScanResult(hosts: arp.keys.sorted().map {
        HostResult(address: $0, addressType: "ipv4", state: "up")
    }, hostsUp: arp.count)
    probe = HostEnricher.applyLinkLayer(to: probe, arp: arp, vendors: vendors)
    let semaphore = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var named: ScanResult?
    let snapshot = probe
    Task { named = await HostEnricher.applyNames(to: snapshot); semaphore.signal() }
    semaphore.wait()
    print("Enriched hosts (no packets sent — ARP cache plus system resolver):")
    for host in (named ?? probe).hosts {
        print("  \(host.address)  \(host.macSummary ?? "-")  name=\(host.bestName ?? "-")")
    }
    for suggestion in LocalNetworks.currentSuggestions(info: info) {
        print("  [\(suggestion.kind.rawValue)] \(suggestion.label) · \(suggestion.target.raw)"
              + (suggestion.isNarrowed ? "  (narrowed from /\(suggestion.originalPrefix ?? 0))" : ""))
    }
}

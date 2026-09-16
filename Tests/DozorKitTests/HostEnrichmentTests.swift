import Foundation
import DozorKit

func runHostEnrichmentTests() {
    suite("MAC vendor table") {
        test("parses the Nmap prefix format") {
            let table = MacVendorDatabase.parse("""
            # $Id: $ generated with make-mac-prefixes.pl
            # comment line
            001C7F Check Point Software Technologies
            D06578 Intel Corporate
            6C71D9 AzureWave Technology
            NOTHEX Some Vendor
            001C7
            """)
            expectEqual(table.count, 3, "three usable rows")
            expectEqual(table["001C7F"], "Check Point Software Technologies", "vendor with spaces")
            expectEqual(table["D06578"], "Intel Corporate", "second row")
            expect(table["NOTHEX"] == nil, "non-hex prefix rejected")
        }

        test("locally administered addresses are recognised") {
            // Bit 0x02 of the first octet: the address was not assigned by a vendor.
            expect(ArpTable.isLocallyAdministered(mac: "fa:62:f7:00:00:e6"), "fa: randomised")
            expect(ArpTable.isLocallyAdministered(mac: "96:bc:9b:00:00:5b"), "96: randomised")
            expect(!ArpTable.isLocallyAdministered(mac: "00:1c:7f:00:00:2e"), "00:1c:7f is burned in")
            expect(!ArpTable.isLocallyAdministered(mac: "d0:65:78:00:00:d9"), "d0:65:78 is burned in")
        }

        test("broadcast and multicast rows are not hosts") {
            expect(ArpTable.isReserved(mac: "ff:ff:ff:ff:ff:ff"), "broadcast")
            expect(ArpTable.isReserved(mac: "01:00:5e:00:00:fb"), "ipv4 multicast")
            expect(!ArpTable.isReserved(mac: "00:1c:7f:00:00:2e"), "an ordinary address")
        }

        test("the real table shipped with Nmap resolves known prefixes") {
            let database = MacVendorDatabase()
            guard !database.isEmpty else {
                // Nmap not installed here; the parser is covered above.
                return
            }
            expectEqual(database.vendor(for: "00:1c:7f:00:00:2e"),
                        "Check Point Software Technologies", "colon form")
            expectEqual(database.vendor(for: "D06578AABBCC"), "Intel Corporate", "bare hex form")
            expect(database.vendor(for: "fa:62:f7:00:00:e6") == nil,
                   "a randomised address must not be attributed to a vendor")
        }
    }

    suite("Host enrichment") {
        func host(_ address: String, mac: String? = nil, vendor: String? = nil,
                  hostnames: [String] = [], state: String = "up") -> HostResult {
            HostResult(address: address, addressType: "ipv4", mac: mac, vendor: vendor,
                       hostnames: hostnames, state: state)
        }

        let vendors = MacVendorDatabase()

        test("a MAC the scan could not see is filled in from the ARP cache") {
            let result = ScanResult(hosts: [host("192.168.30.1")], hostsUp: 1)
            let enriched = HostEnricher.applyLinkLayer(
                to: result,
                arp: ["192.168.30.1": "00:1c:7f:00:00:2e"],
                vendors: vendors
            )
            let first = try require(enriched.hosts.first)
            expectEqual(first.mac, "00:1c:7f:00:00:2e", "mac filled in")
            expectEqual(first.macSource, .arpCache, "source recorded")
            if !vendors.isEmpty {
                expectEqual(first.vendor, "Check Point Software Technologies", "vendor looked up")
            }
        }

        test("a MAC the scan did report is kept and labelled as a scan finding") {
            let result = ScanResult(hosts: [host("192.168.30.1", mac: "aa:bb:cc:dd:ee:ff")], hostsUp: 1)
            let enriched = HostEnricher.applyLinkLayer(
                to: result,
                arp: ["192.168.30.1": "00:1c:7f:00:00:2e"],
                vendors: vendors
            )
            let first = try require(enriched.hosts.first)
            expectEqual(first.mac, "aa:bb:cc:dd:ee:ff", "scan's own value wins")
            expectEqual(first.macSource, .scan, "labelled as coming from the scan")
        }

        test("a vendor Nmap already supplied is not overwritten") {
            let result = ScanResult(hosts: [host("192.168.30.1", mac: "00:1c:7f:00:00:2e",
                                                 vendor: "Something Nmap Said")], hostsUp: 1)
            let enriched = HostEnricher.applyLinkLayer(to: result, arp: [:], vendors: vendors)
            expectEqual(enriched.hosts.first?.vendor, "Something Nmap Said", "kept")
        }

        test("hosts with no cache entry are left untouched") {
            let result = ScanResult(hosts: [host("10.99.99.99")], hostsUp: 1)
            let enriched = HostEnricher.applyLinkLayer(to: result, arp: [:], vendors: vendors)
            let first = try require(enriched.hosts.first)
            expect(first.mac == nil, "no invented address")
            expect(first.macSource == nil, "no invented source")
        }

        test("the best available name is used, in the right order") {
            var named = host("10.0.0.1", hostnames: ["from-nmap"])
            named.reverseName = "from-resolver"
            expectEqual(named.bestName, "from-nmap", "nmap wins when it has a name")
            expectEqual(named.displayName, "from-nmap", "display follows")

            var resolved = host("10.0.0.2")
            resolved.reverseName = "from-resolver"
            expectEqual(resolved.bestName, "from-resolver", "resolver fills the gap")

            let anonymous = host("10.0.0.3")
            expect(anonymous.bestName == nil, "no name at all")
            expectEqual(anonymous.displayName, "10.0.0.3", "falls back to the address")
        }

        test("the MAC summary reads as address and vendor") {
            let known = host("10.0.0.1", mac: "d0:65:78:00:00:d9", vendor: "Intel Corporate")
            expectEqual(known.macSummary, "d0:65:78:00:00:d9 — Intel Corporate", "with vendor")
            expectEqual(host("10.0.0.2", mac: "d0:65:78:00:00:d9").macSummary,
                        "d0:65:78:00:00:d9", "without vendor")
            expect(host("10.0.0.3").macSummary == nil, "no address, no summary")
        }

        test("the clipboard line carries what is known, in a fixed order") {
            var full = host("192.168.30.1", mac: "00:1c:7f:00:00:2e",
                            vendor: "Check Point Software Technologies")
            full.reverseName = "fw.example"
            full.ports = [
                PortInfo(port: 443, proto: "tcp", state: "open", serviceName: "https"),
                PortInfo(port: 22, proto: "tcp", state: "closed", serviceName: "ssh"),
            ]
            expectEqual(full.tabSeparatedSummary,
                        "192.168.30.1\tfw.example\t00:1c:7f:00:00:2e\tCheck Point Software Technologies\t443/tcp (https)",
                        "closed ports are left out")

            expectEqual(host("10.0.0.5").tabSeparatedSummary, "10.0.0.5",
                        "an address with nothing else known is the whole line")

            expectEqual(host("10.0.0.6", mac: "d0:65:78:00:00:d9").tabSeparatedSummary,
                        "10.0.0.6\td0:65:78:00:00:d9",
                        "missing fields are skipped, not left as empty columns")
        }

        test("only live, unnamed hosts are sent to the resolver") {
            // A down host and an already-named host must not queue a lookup;
            // on a sparse /24 that is the difference between 3 lookups and 254.
            let probe = ScanResult(hosts: [
                host("127.0.0.1"),
                host("10.99.99.98", hostnames: ["already-named"]),
                host("10.99.99.99", state: "down"),
            ], hostsUp: 2)
            let result = runBlocking { await HostEnricher.applyNames(to: probe, concurrency: 4) }

            expectEqual(result.hosts[0].reverseName, "localhost", "loopback resolves locally")
            expect(result.hosts[1].reverseName == nil, "a named host is skipped")
            expect(result.hosts[2].reverseName == nil, "a down host is skipped")
        }
    }

    suite("Reverse name lookup") {
        test("the system resolver names the loopback address") {
            // Answered from /etc/hosts, so this needs no network.
            expectEqual(ReverseDNS.hostname(for: "127.0.0.1"), "localhost", "loopback")
        }

        test("an address with no name returns nil rather than itself") {
            expect(ReverseDNS.hostname(for: "192.0.2.1") == nil,
                   "TEST-NET-1 has no PTR record")
            expect(ReverseDNS.hostname(for: "not-an-address") == nil, "garbage input")
        }
    }
}

/// The harness is synchronous; this runs one async call to completion.
private func runBlocking<T: Sendable>(_ body: @escaping @Sendable () async -> T) -> T {
    let semaphore = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var outcome: T?
    Task {
        outcome = await body()
        semaphore.signal()
    }
    semaphore.wait()
    return outcome!
}

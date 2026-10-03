import Foundation
import DozorKit

private func iface(_ name: String, _ address: String, _ netmask: String,
                   up: Bool = true, running: Bool = true,
                   loopback: Bool = false, pointToPoint: Bool = false) -> InterfaceAddress {
    InterfaceAddress(name: name, address: address, netmask: netmask,
                     isUp: up, isRunning: running,
                     isLoopback: loopback, isPointToPoint: pointToPoint)
}

func runSweepTests() {
    suite("Sweep scope") {
        // The machine's real configuration at the time this was written. It had
        // already moved once mid-session, which is why nothing stores a scope.
        let wifi = iface("en0", "192.168.40.156", "255.255.255.0")

        test("a live interface resolves to its own subnet") {
            let scope = try require(SweepScope.resolve(cidr: "192.168.40.0/24", interfaces: [wifi]))
            expectEqual(scope.target.raw, "192.168.40.0/24", "cidr")
            expectEqual(scope.target.kind, .cidr, "kind")
            expect(scope.target.isPrivate, "private range")
            expectEqual(scope.localAddress, "192.168.40.156", "local address")
            expectEqual(scope.broadcastAddress, "192.168.40.255", "broadcast")
            expectEqual(scope.prefix, 24, "prefix")
            expect(!scope.isNarrowed, "a /24 needs no narrowing")
        }

        test("a subnet the Mac is not on cannot become a scope") {
            expect(SweepScope.resolve(cidr: "10.99.0.0/24", interfaces: [wifi]) == nil,
                   "foreign subnet refused")
            expect(SweepScope.resolve(cidr: "192.168.40.0/24", interfaces: []) == nil,
                   "no interfaces, no scope")
            expect(SweepScope.resolve(cidr: "8.8.8.0/24", interfaces: [wifi]) == nil,
                   "public subnet refused")
        }

        test("hostile text cannot become a scope") {
            for hostile in ["192.168.40.0/24; rm -rf /", "$(whoami)", "--script=evil",
                            "192.168.40.0/24 && curl evil.test"] {
                expect(SweepScope.resolve(cidr: hostile, interfaces: [wifi]) == nil,
                       "refused: \(hostile)")
            }
        }

        test("interfaces with nothing scannable behind them offer no scope") {
            let scopes = SweepScope.available(interfaces: [
                iface("lo0", "127.0.0.1", "255.0.0.0", loopback: true),
                iface("utun3", "10.8.0.2", "255.255.255.255", pointToPoint: true),
                iface("awdl0", "169.254.11.4", "255.255.0.0"),
                iface("en4", "192.168.50.3", "255.255.255.0", up: false),
                iface("en5", "192.168.60.3", "255.255.255.0", running: false),
            ])
            expect(scopes.isEmpty, "expected none, got \(scopes.map(\.target.raw))")
        }

        test("a wider network is narrowed to the /24 around this Mac") {
            let scope = try require(SweepScope.available(
                interfaces: [iface("en0", "172.16.5.9", "255.255.0.0")]).first)
            expectEqual(scope.target.raw, "172.16.5.0/24", "narrowed")
            expect(scope.isNarrowed, "flagged")
            expectEqual(scope.broadcastAddress, "172.16.5.255", "broadcast of the /24")
            expectEqual(scope.addressCount, 253, "253 probeable addresses")
        }

        test("the primary interface is offered first") {
            let scopes = SweepScope.available(interfaces: [
                iface("en7", "10.0.7.5", "255.255.255.0"),
                iface("en0", "192.168.40.156", "255.255.255.0"),
            ], primaryInterface: "en0")
            expectEqual(scopes.first?.target.raw, "192.168.40.0/24", "primary first")
            expectEqual(scopes.count, 2, "both offered")
        }
    }

    suite("Sweep address enumeration") {
        let wifi = iface("en0", "192.168.40.156", "255.255.255.0")

        test("network, broadcast and this Mac are never probed") {
            let scope = try require(SweepScope.resolve(cidr: "192.168.40.0/24", interfaces: [wifi]))
            let addresses = scope.hostAddresses()
            expectEqual(addresses.count, 253, "254 hosts minus ourselves")
            expect(!addresses.contains("192.168.40.0"), "network address excluded")
            expect(!addresses.contains("192.168.40.255"), "broadcast excluded")
            expect(!addresses.contains("192.168.40.156"), "this Mac excluded")
            expect(addresses.contains("192.168.40.1"), "the gateway is probed")
        }

        test("addresses come out in numeric order, not lexical") {
            let scope = try require(SweepScope.resolve(cidr: "192.168.40.0/24", interfaces: [wifi]))
            let addresses = scope.hostAddresses()
            expectEqual(addresses.first, "192.168.40.1", "starts at .1")
            expectEqual(addresses.last, "192.168.40.254", "ends at .254")
            let ninth = try require(addresses.firstIndex(of: "192.168.40.9"))
            let tenth = try require(addresses.firstIndex(of: "192.168.40.10"))
            expect(ninth < tenth, ".9 sorts before .10")
        }

        test("small subnets hold the right number of hosts") {
            let thirty = try require(SweepScope.available(
                interfaces: [iface("en0", "10.0.0.1", "255.255.255.252")]).first)
            // .0 network, .3 broadcast, .1 is us — only .2 is left.
            expectEqual(thirty.hostAddresses(), ["10.0.0.2"], "/30 leaves one host")

            let twentyNine = try require(SweepScope.available(
                interfaces: [iface("en0", "10.0.0.1", "255.255.255.248")]).first)
            expectEqual(twentyNine.addressCount, 5, "/29 leaves five")
        }

        test("every address the sweeper would probe survives the validator") {
            let scope = try require(SweepScope.resolve(cidr: "192.168.40.0/24", interfaces: [wifi]))
            let targets = scope.hostTargets()
            expectEqual(targets.count, scope.hostAddresses().count,
                        "the enumerator cannot emit a string the validator refuses")
            expect(targets.allSatisfy { $0.kind == .ipv4 }, "all plain addresses")
            expect(targets.allSatisfy { $0.isPrivate }, "all inside private space")
        }
    }

    suite("Presence rules") {
        test("a fresh answer means present, a cached entry does not") {
            expectEqual(PresenceRules.presence(from: [.arpFresh]).level, .present, "fresh ARP")
            expectEqual(PresenceRules.presence(from: [.arpPrior]).level, .stale,
                        "a 20-minute-old cache entry is not proof of life")
            expectEqual(PresenceRules.presence(from: []).level, .absent, "no evidence")
        }

        test("any direct answer counts, even a refusal") {
            expectEqual(PresenceRules.presence(from: [.tcpRefused]).level, .present,
                        "a closed port still proves a host")
            expectEqual(PresenceRules.presence(from: [.icmpUnreachable]).level, .present,
                        "the host's own stack answered")
            expectEqual(PresenceRules.presence(from: [.arpPrior, .tcpOpen]).level, .present,
                        "stale ARP plus a live port is present")
        }

        test("the verdict never drops when evidence is added") {
            // Total and monotonic over every possible combination.
            let all = HostEvidence.allCases
            for mask in 0..<(1 << all.count) {
                var evidence = Set<HostEvidence>()
                for (bit, item) in all.enumerated() where mask & (1 << bit) != 0 {
                    evidence.insert(item)
                }
                let base = PresenceRules.presence(from: evidence).level
                for extra in all where !evidence.contains(extra) {
                    let richer = PresenceRules.presence(from: evidence.union([extra])).level
                    expect(richer >= base, "adding \(extra) lowered the verdict")
                }
            }
        }
    }

    suite("ARP delta") {
        test("a new entry is a fresh answer, an unchanged one is not") {
            let delta = ArpDelta.between(
                before: ["192.168.40.1": "aa:aa:aa:aa:aa:aa"],
                after: ["192.168.40.1": "aa:aa:aa:aa:aa:aa", "192.168.40.5": "bb:bb:bb:bb:bb:bb"]
            )
            expectEqual(delta.appeared, ["192.168.40.5": "bb:bb:bb:bb:bb:bb"], "appeared")
            expectEqual(delta.persisted, ["192.168.40.1": "aa:aa:aa:aa:aa:aa"], "persisted")
            expect(delta.changed.isEmpty && delta.vanished.isEmpty, "nothing else")
            expectEqual(delta.evidence(for: "192.168.40.5"), [.arpFresh], "new entry is fresh")
            expectEqual(delta.evidence(for: "192.168.40.1"), [.arpPrior], "old entry is prior")
            expectEqual(delta.evidence(for: "192.168.40.9"), [], "unknown address")
        }

        test("a MAC change is a different device, not an update") {
            let delta = ArpDelta.between(
                before: ["10.0.0.5": "aa:aa:aa:aa:aa:aa"],
                after: ["10.0.0.5": "cc:cc:cc:cc:cc:cc"]
            )
            let change = try require(delta.changed["10.0.0.5"])
            expectEqual(change.old, "aa:aa:aa:aa:aa:aa", "old MAC kept")
            expectEqual(change.new, "cc:cc:cc:cc:cc:cc", "new MAC")
            expect(delta.appeared.isEmpty && delta.persisted.isEmpty,
                   "a change is neither an appearance nor a persistence")
            expectEqual(delta.evidence(for: "10.0.0.5"), [.arpFresh], "counts as a fresh answer")
            expectEqual(delta.mac(for: "10.0.0.5"), "cc:cc:cc:cc:cc:cc", "the new MAC wins")
        }

        test("an entry expiring mid-sweep says nothing") {
            let delta = ArpDelta.between(before: ["10.0.0.7": "dd:dd:dd:dd:dd:dd"], after: [:])
            expectEqual(delta.vanished, ["10.0.0.7": "dd:dd:dd:dd:dd:dd"], "recorded")
            expectEqual(delta.evidence(for: "10.0.0.7"), [], "but contributes no evidence")
        }

        test("empty tables produce an empty delta") {
            let delta = ArpDelta.between(before: [:], after: [:])
            expect(delta.appeared.isEmpty && delta.changed.isEmpty
                   && delta.persisted.isEmpty && delta.vanished.isEmpty, "all empty")
        }
    }

    suite("Sweep pacing") {
        test("the first probe leaves immediately and the schedule never goes backwards") {
            let pacing = SweepPacing(packetsPerSecond: 200)
            expectEqual(pacing.departure(index: 0), 0, "first probe")
            var previous = -1.0
            for index in 0..<253 {
                let departure = pacing.departure(index: index)
                expect(departure >= previous, "schedule went backwards at \(index)")
                previous = departure
            }
        }

        test("a /24 at 200 packets per second takes about a second and a quarter") {
            let pacing = SweepPacing(packetsPerSecond: 200)
            let duration = pacing.duration(forProbes: 253)
            expect(duration > 1.1 && duration < 1.4, "expected ~1.26 s, got \(duration)")
        }

        test("a low cap cannot be outrun") {
            let pacing = SweepPacing(packetsPerSecond: 20, burst: 1)
            expect(pacing.departure(index: 99) >= 4.9, "100 probes at 20 pps take 5 s")
        }

        test("backing off halves the rate and then holds at the floor") {
            let pacing = SweepPacing(packetsPerSecond: 200, burst: 8, minimumRate: 25)
            expectEqual(pacing.backedOff().packetsPerSecond, 100, "halved")
            expectEqual(pacing.backedOff().backedOff().packetsPerSecond, 50, "halved again")
            let floored = pacing.backedOff().backedOff().backedOff().backedOff()
            expectEqual(floored.packetsPerSecond, 25, "stops at the floor")
            expectEqual(floored.backedOff().packetsPerSecond, 25, "and stays there")
        }

        test("a rate below the floor is raised to it, never accepted as zero") {
            expectEqual(SweepPacing(packetsPerSecond: 0).packetsPerSecond, 20,
                        "a repeating sweep always has a ceiling")
        }
    }

    suite("Sweeper, without sending a packet") {
        let wifi = iface("en0", "192.168.40.156", "255.255.255.0")

        test("only fresh answers become rows, and the arithmetic adds up") {
            let scope = try require(SweepScope.resolve(cidr: "192.168.40.0/24", interfaces: [wifi]))
            let transport = RecordingTransport(
                before: ["192.168.40.1": "aa:aa:aa:aa:aa:aa"],          // already cached
                after: ["192.168.40.1": "aa:aa:aa:aa:aa:aa",            // unchanged → stale
                        "192.168.40.20": "d0:65:78:00:00:d9",           // appeared → present
                        "192.168.40.21": "6c:71:d9:00:00:89"]           // appeared → present
            )
            let outcome = runBlocking {
                await collect(SubnetSweeper(transport: transport, vendors: nil,
                                            options: quietOptions())
                    .run(scope: scope, gateway: "192.168.40.1"))
            }

            let summary = try require(outcome.summary)
            expectEqual(summary.probed, 253, "every host address probed")
            expectEqual(summary.present, 2, "two fresh answers")
            expectEqual(summary.stale, 1, "the cached entry is not counted as up")
            expectEqual(transport.probedAddresses.count, 253, "one probe each")
            expect(!transport.probedAddresses.contains("192.168.40.0"), "network never probed")
            expect(!transport.probedAddresses.contains("192.168.40.255"), "broadcast never probed")
            expect(!transport.probedAddresses.contains("192.168.40.156"), "ourselves never probed")

            let gateway = try require(outcome.observations.first { $0.address == "192.168.40.1" })
            expectEqual(gateway.presence.level, .stale, "cached entry is 'seen recently'")
            expect(gateway.isGateway, "labelled as the gateway")
        }

        test("a host that answers the echo is up even when its ARP entry is old") {
            // The case that broke the first design: on a Mac that has been on the
            // network a while every host is already cached, so the ARP table looks
            // identical before and after. A direct reply is what proves life.
            let scope = try require(SweepScope.resolve(cidr: "192.168.40.0/24", interfaces: [wifi]))
            let cached = ["192.168.40.1": "aa:aa:aa:aa:aa:aa", "192.168.40.50": "bb:bb:bb:bb:bb:bb"]
            let transport = RecordingTransport(before: cached, after: cached)
            transport.replies = ["192.168.40.50"]
            let outcome = runBlocking {
                await collect(SubnetSweeper(transport: transport, vendors: nil,
                                            options: quietOptions()).run(scope: scope))
            }
            let summary = try require(outcome.summary)
            expectEqual(summary.present, 1, "the host that replied is up")
            expectEqual(summary.stale, 1, "the one that only sat in the cache is not")

            let replied = try require(outcome.observations.first { $0.address == "192.168.40.50" })
            expect(replied.presence.evidence.contains(.icmpReply), "evidence recorded")
            expectEqual(replied.mac, "bb:bb:bb:bb:bb:bb", "the cached MAC is still used")
        }

        test("addresses that never answer do not become rows at all") {
            let scope = try require(SweepScope.resolve(cidr: "192.168.40.0/24", interfaces: [wifi]))
            let transport = RecordingTransport(before: [:], after: [:])
            let outcome = runBlocking {
                await collect(SubnetSweeper(transport: transport, vendors: nil,
                                            options: quietOptions()).run(scope: scope))
            }
            expect(outcome.observations.isEmpty, "no evidence, no rows")
            expectEqual(outcome.summary?.probed, 253, "but the probing still happened")
        }

        test("the kernel refusing work halves the rate instead of failing") {
            let scope = try require(SweepScope.resolve(cidr: "10.0.0.1/30",
                                                       interfaces: [iface("en0", "10.0.0.1", "255.255.255.252")])
                                    ?? SweepScope.available(interfaces: [iface("en0", "10.0.0.1", "255.255.255.252")]).first)
            let transport = RecordingTransport(before: [:], after: ["10.0.0.2": "aa:bb:cc:dd:ee:ff"])
            transport.failEveryProbeWith = .outOfBuffers
            let outcome = runBlocking {
                await collect(SubnetSweeper(transport: transport, vendors: nil,
                                            options: quietOptions()).run(scope: scope))
            }
            let summary = try require(outcome.summary)
            expect(summary.backedOff, "back-off recorded")
            expect(summary.warnings.contains(.rateBackedOff), "and surfaced as a warning")
            expectEqual(summary.packetsSent, 0, "nothing actually left the machine")
        }

        test("every probe refused with EPERM reads as denied access, not a quiet subnet") {
            // The bug this guards: before this, a permission denial looked
            // identical to "nobody answered" — a sweep that silently returns
            // zero hosts forever, with nothing telling the person why.
            let scope = try require(SweepScope.resolve(cidr: "192.168.40.0/24", interfaces: [wifi]))
            let transport = RecordingTransport(before: [:], after: [:])
            transport.failEveryProbeWith = .permissionDenied
            let outcome = runBlocking {
                await collect(SubnetSweeper(transport: transport, vendors: nil,
                                            options: quietOptions()).run(scope: scope))
            }
            let summary = try require(outcome.summary)
            expectEqual(summary.warnings, [.localNetworkAccessDenied],
                       "reported instead of an empty table with no explanation")
        }

        test("EPERM and EACCES both classify as a permission denial") {
            expectEqual(DarwinDiscoveryTransport.classify(EPERM), .permissionDenied)
            expectEqual(DarwinDiscoveryTransport.classify(EACCES), .permissionDenied)
        }

        test("one MAC answering for the whole subnet is called out as proxy ARP") {
            let observations = (1...12).map { index in
                SweepObservation(address: "10.0.0.\(index)", mac: "aa:aa:aa:aa:aa:aa",
                                 vendor: nil, presence: HostPresence(level: .present, evidence: [.arpFresh]),
                                 name: nil, isGateway: false, observedAt: Date())
            }
            let warnings = SubnetSweeper.warnings(observations: observations, probed: 253,
                                                  gateway: nil, backedOff: false,
                                                  proxyArpThreshold: 8)
            expect(warnings.contains(.proxyArpSuspected),
                   "253 addresses behind one MAC is a router, not a busy subnet")
        }

        test("a subnet where only the gateway answers looks like client isolation") {
            let gateway = SweepObservation(address: "192.168.40.1", mac: "aa:aa:aa:aa:aa:aa",
                                           vendor: nil,
                                           presence: HostPresence(level: .present, evidence: [.arpFresh]),
                                           name: nil, isGateway: true, observedAt: Date())
            let warnings = SubnetSweeper.warnings(observations: [gateway], probed: 253,
                                                  gateway: "192.168.40.1", backedOff: false,
                                                  proxyArpThreshold: 8)
            expect(warnings.contains(.clientIsolationSuspected),
                   "better than showing an empty table with no explanation")
        }
    }

    suite("Live sweep scope") {
        test("this machine offers a scope it is actually attached to") {
            // Read-only: enumerates interfaces, sends nothing.
            for scope in SweepScope.available() {
                expect(!SweepScope.resolve(cidr: scope.target.raw).isNil,
                       "\(scope.target.raw) re-resolves")
                expect(LocalNetworks.contains(cidr: scope.target.raw, address: scope.localAddress),
                       "the local address lies inside its own scope")
                expect(!scope.hostAddresses().contains(scope.localAddress),
                       "and is never probed")
                expect(scope.interfaceIndex > 0, "\(scope.interfaceName) has an index for IP_BOUND_IF")
            }
        }
    }
}

private extension Optional {
    var isNil: Bool { self == nil }
}


// MARK: - Test doubles and helpers

/// Scripted ARP snapshots, so the whole sweep pipeline runs with no packets.
final class RecordingTransport: DiscoveryTransport, @unchecked Sendable {
    private let lock = NSLock()
    private let before: [String: String]
    private let after: [String: String]
    private var snapshotsTaken = 0
    private var probed: [String] = []
    var failEveryProbeWith: DiscoveryTransportError?
    /// Addresses that "answer" the echo request.
    var replies: Set<String> = []
    private var repliesDelivered = false

    var probedAddresses: [String] { lock.withLock { probed } }

    init(before: [String: String], after: [String: String]) {
        self.before = before
        self.after = after
    }

    func probe(address: String, interfaceIndex: UInt32) throws {
        lock.withLock { probed.append(address) }
        if let failure = failEveryProbeWith { throw failure }
    }

    func drainReplies() -> Set<String> {
        lock.withLock {
            guard !repliesDelivered else { return [] }
            repliesDelivered = true
            return replies
        }
    }

    func arpSnapshot() -> [String: String] {
        lock.withLock {
            snapshotsTaken += 1
            return snapshotsTaken == 1 ? before : after
        }
    }
}

struct SweepOutcome {
    var observations: [SweepObservation] = []
    var summary: SweepSummary?
    var failure: SweepError?
}

/// Pacing and settle delay wound down so the suite does not sit waiting.
func quietOptions() -> SweepOptions {
    SweepOptions(pacing: SweepPacing(packetsPerSecond: 100_000, burst: 256),
                 settleDelay: .milliseconds(1),
                 resolveNames: false)
}

func collect(_ stream: AsyncStream<SweepEvent>) async -> SweepOutcome {
    var outcome = SweepOutcome()
    for await event in stream {
        switch event {
        case .observed(let observations): outcome.observations = observations
        case .finished(let summary): outcome.summary = summary
        case .failed(let error): outcome.failure = error
        case .started, .progress: break
        }
    }
    return outcome
}

/// Sweeps the subnet this Mac is actually on and prints what it found.
/// Opt-in, because it puts real packets on a real network:
/// `DOZOR_SWEEP_LIVE=1 swift run DozorKitTests`
func dumpLiveSweep() {
    guard ProcessInfo.processInfo.environment["DOZOR_SWEEP_LIVE"] == "1" else { return }
    #if canImport(Darwin)
    let info = SystemNetworkInfo.current()
    guard let scope = SweepScope.available(primaryInterface: info.primaryInterface).first else {
        print("\nno sweepable scope on this machine")
        return
    }
    print("\nLive sweep of \(scope.target.raw) on \(scope.interfaceName)"
          + " — \(scope.addressCount) addresses, gateway \(info.router ?? "unknown")")

    let vendors = MacVendorDatabase()
    let sweeper = SubnetSweeper(transport: DarwinDiscoveryTransport(), vendors: vendors)
    let started = Date()
    let outcome = runBlocking {
        await collect(sweeper.run(scope: scope, gateway: info.router))
    }
    let elapsed = Date().timeIntervalSince(started)

    guard let summary = outcome.summary else {
        print("  sweep failed: \(String(describing: outcome.failure))")
        return
    }
    print(String(format: "  %.2f s wall clock, %d probes sent, %d present, %d seen recently",
                 elapsed, summary.packetsSent, summary.present, summary.stale))
    if !summary.warnings.isEmpty { print("  warnings: \(summary.warnings.map(\.rawValue))") }
    for observation in outcome.observations.sorted(by: { $0.address.compare($1.address, options: .numeric) == .orderedAscending }) {
        let level = observation.presence.level == .present ? "up  " : "seen"
        print("  \(level) \(observation.address.padding(toLength: 16, withPad: " ", startingAt: 0))"
              + " \(observation.mac ?? "-")  \(observation.name ?? "")"
              + "  \(observation.vendor ?? "")\(observation.isGateway ? "  [gateway]" : "")")
    }
    #endif
}

func runEchoTests() {
    suite("ICMP echo request") {
        #if canImport(Darwin)
        test("the packet is a well-formed echo request") {
            let packet = DarwinDiscoveryTransport.echoRequest(identifier: 0x1234, sequence: 1)
            expectEqual(packet.count, 16, "header plus payload")
            expectEqual(packet[0], 8, "type 8 — echo request")
            expectEqual(packet[1], 0, "code 0")
            expectEqual(packet[4], 0x12, "identifier high byte")
            expectEqual(packet[5], 0x34, "identifier low byte")
            expectEqual(packet[7], 1, "sequence")
        }

        test("the checksum is the one's-complement sum the RFC asks for") {
            let packet = DarwinDiscoveryTransport.echoRequest(identifier: 0xABCD, sequence: 7)
            // A correct checksum makes the sum over the whole message zero.
            expectEqual(DarwinDiscoveryTransport.internetChecksum(packet), 0,
                        "a packet including its own checksum sums to zero")
            expectEqual(DarwinDiscoveryTransport.internetChecksum([0x00, 0x00]), 0xFFFF, "all zeroes")
        }

        test("an unprivileged echo socket is available on this machine") {
            // The whole design rests on this: no root, yet direct proof of life.
            let transport = DarwinDiscoveryTransport()
            var threw = false
            do {
                try transport.probe(address: "127.0.0.1", interfaceIndex: 0)
            } catch {
                threw = true
            }
            expect(!threw, "sending an echo request must not need privileges")
        }
        #endif
    }
}

func runActionTests() {
    suite("Wake on LAN") {
        test("the magic packet has the shape the standard requires") {
            let packet = try require(WakeOnLan.magicPacket(for: "d0:65:78:00:00:d9"))
            expectEqual(packet.count, 102, "6 sync bytes plus the MAC sixteen times")
            expectEqual(Array(packet.prefix(6)), [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], "sync stream")

            let mac: [UInt8] = [0xd0, 0x65, 0x78, 0x00, 0x00, 0xd9]
            for repetition in 0..<16 {
                let start = 6 + repetition * 6
                expectEqual(Array(packet[start..<(start + 6)]), mac,
                            "repetition \(repetition)")
            }
        }

        test("the separators people actually type are accepted") {
            expect(WakeOnLan.magicPacket(for: "d0-65-78-00-00-d9") != nil, "dashes")
            expect(WakeOnLan.magicPacket(for: "d065780000d9") != nil, "bare hex")
            expect(WakeOnLan.magicPacket(for: "D0:65:78:00:00:D9") != nil, "upper case")
        }

        test("addresses that cannot belong to a wakeable NIC produce nothing") {
            expect(WakeOnLan.magicPacket(for: "") == nil, "empty")
            expect(WakeOnLan.magicPacket(for: "zz:65:78:00:00:d9") == nil, "not hex")
            expect(WakeOnLan.magicPacket(for: "d0:65:78:00:00") == nil, "five octets")
            expect(WakeOnLan.magicPacket(for: "d0:65:78:00:00:d9:ff") == nil, "seven octets")
            expect(WakeOnLan.magicPacket(for: "ff:ff:ff:ff:ff:ff") == nil, "broadcast")
            expect(WakeOnLan.magicPacket(for: "01:00:5e:00:00:fb") == nil, "multicast")
            expect(WakeOnLan.magicPacket(for: "fa:62:f7:00:00:e6") == nil,
                   "a randomised address is not a NIC that wakes on LAN")
        }
    }

    suite("Host capabilities") {
        test("only an accepted connection counts as a capability") {
            let capabilities = HostCapabilities.from(
                ports: [22: .open, 445: .refused, 443: .timedOut],
                mac: "d0:65:78:00:00:d9")
            expect(capabilities.ssh, "22 accepted")
            expect(!capabilities.fileSharing, "a refusal is not an offer")
            expect(!capabilities.secureWeb, "nor is a timeout")
            expect(capabilities.wakeable, "a real MAC can be woken")
        }

        test("the first plain web port that answers is the one offered") {
            expectEqual(HostCapabilities.from(ports: [80: .open, 8080: .open], mac: nil).web, 80,
                        "80 wins over 8080")
            expectEqual(HostCapabilities.from(ports: [8080: .open], mac: nil).web, 8080,
                        "8080 when it is the only one")
            expect(HostCapabilities.from(ports: [:], mac: nil).web == nil, "nothing open")
        }

        test("remote desktop is recorded but never offered as an action") {
            let capabilities = HostCapabilities.from(ports: [3389: .open], mac: nil)
            expect(capabilities.remoteDesktop, "identifies a Windows host")
            expectEqual(capabilities.openPorts, [3389], "listed among the open ports")
            // No rdp action exists: nothing on this Mac registers the scheme, and
            // a button that opens nothing is worse than no button.
        }

        test("a host with no MAC cannot be woken") {
            expect(!HostCapabilities.from(ports: [22: .open], mac: nil).wakeable, "no address")
            expect(!HostCapabilities.from(ports: [:], mac: "fa:62:f7:00:00:e6").wakeable,
                   "randomised address")
        }
    }
}

private func observation(_ address: String, mac: String? = nil, name: String? = nil,
                         level: HostPresence.Level = .present,
                         gateway: Bool = false, at now: Date = Date()) -> SweepObservation {
    SweepObservation(address: address, mac: mac, vendor: nil,
                     presence: HostPresence(level: level,
                                            evidence: level == .present ? [.icmpReply] : [.arpPrior]),
                     name: name, isGateway: gateway, observedAt: now)
}

func runInventoryTests() {
    suite("Network inventory") {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let probed = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

        test("a host seen for the first time becomes a row") {
            var inventory = NetworkInventory(scopeCIDR: "10.0.0.0/24")
            inventory.merge([observation("10.0.0.2", mac: "aa:bb:cc:dd:ee:ff", name: "nas.local")],
                            probed: probed, at: start)

            let row = try require(inventory.rows["10.0.0.2"])
            expectEqual(row.firstSeen, start, "first seen")
            expectEqual(row.lastSeen, start, "last seen")
            expectEqual(row.missedSweeps, 0, "no misses")
            expectEqual(row.status(), .up, "up")
            expectEqual(row.host.mac, "aa:bb:cc:dd:ee:ff", "mac carried over")
            expectEqual(row.host.bestName, "nas.local", "name carried over")
        }

        test("a host that goes quiet keeps its row instead of vanishing") {
            var inventory = NetworkInventory(scopeCIDR: "10.0.0.0/24")
            inventory.merge([observation("10.0.0.2", mac: "aa:bb:cc:dd:ee:ff")],
                            probed: probed, at: start)
            inventory.merge([], probed: probed, at: start.addingTimeInterval(60))

            let row = try require(inventory.rows["10.0.0.2"])
            expectEqual(row.missedSweeps, 1, "one miss")
            expectEqual(row.lastSeen, start, "last sighting is not rewritten")
            expectEqual(row.status(), .recentlyUp, "shown as recently up")
            expectEqual(row.host.mac, "aa:bb:cc:dd:ee:ff", "what we learned is kept")
        }

        test("a long silence reads as gone, but the row survives") {
            var inventory = NetworkInventory(scopeCIDR: "10.0.0.0/24")
            inventory.merge([observation("10.0.0.2")], probed: probed, at: start)
            for step in 1...5 {
                inventory.merge([], probed: probed, at: start.addingTimeInterval(Double(step) * 60))
            }
            let row = try require(inventory.rows["10.0.0.2"])
            expectEqual(row.status(), .gone, "gone")
            expectEqual(inventory.knownCount, 1, "still known")
            expectEqual(inventory.presentCount, 0, "but not counted as up")
        }

        test("coming back clears the misses without losing the history") {
            var inventory = NetworkInventory(scopeCIDR: "10.0.0.0/24")
            inventory.merge([observation("10.0.0.2")], probed: probed, at: start)
            inventory.merge([], probed: probed, at: start.addingTimeInterval(60))
            inventory.merge([], probed: probed, at: start.addingTimeInterval(120))
            let later = start.addingTimeInterval(180)
            inventory.merge([observation("10.0.0.2", at: later)], probed: probed, at: later)

            let row = try require(inventory.rows["10.0.0.2"])
            expectEqual(row.missedSweeps, 0, "misses cleared")
            expectEqual(row.firstSeen, start, "first sighting preserved")
            expectEqual(row.lastSeen, later, "last sighting updated")
        }

        test("a cancelled sweep must not mark the subnet dead") {
            var inventory = NetworkInventory(scopeCIDR: "10.0.0.0/24")
            inventory.merge([observation("10.0.0.2")], probed: probed, at: start)
            inventory.merge([], probed: [], at: start.addingTimeInterval(60))

            let row = try require(inventory.rows["10.0.0.2"])
            expectEqual(row.missedSweeps, 0, "a sweep that probed nothing proves nothing")
            expectEqual(row.status(), .up, "still up")
        }

        test("a new MAC on a known address is a different device") {
            var inventory = NetworkInventory(scopeCIDR: "10.0.0.0/24")
            inventory.merge([observation("10.0.0.2", mac: "aa:aa:aa:aa:aa:aa")],
                            probed: probed, at: start)
            inventory.rows["10.0.0.2"].map { _ in }
            var tagged = try require(inventory.rows["10.0.0.2"])
            tagged.host.tags = ["printer"]
            inventory = NetworkInventory(scopeCIDR: "10.0.0.0/24", rows: ["10.0.0.2": tagged])

            let later = start.addingTimeInterval(3600)
            inventory.merge([observation("10.0.0.2", mac: "bb:bb:bb:bb:bb:bb", at: later)],
                            probed: probed, at: later)

            let row = try require(inventory.rows["10.0.0.2"])
            expectEqual(row.host.mac, "bb:bb:bb:bb:bb:bb", "new MAC")
            expectEqual(row.firstSeen, later, "identity reset")
            expectEqual(row.macChangedAt, later, "and flagged")
            expect(row.host.tags.isEmpty,
                   "tags must not follow a lease to a different machine")
        }

        test("a cached-only sighting is not counted as a sighting") {
            var inventory = NetworkInventory(scopeCIDR: "10.0.0.0/24")
            inventory.merge([observation("10.0.0.2", level: .stale)], probed: probed, at: start)
            let row = try require(inventory.rows["10.0.0.2"])
            expectEqual(row.presence.level, .stale, "stale")
            expectEqual(row.host.state, "down", "not reported as up")
        }

        test("forgetting needs both a long silence and many misses") {
            var inventory = NetworkInventory(scopeCIDR: "10.0.0.0/24")
            inventory.merge([observation("10.0.0.2")], probed: probed, at: start)
            for step in 1...15 {
                inventory.merge([], probed: probed, at: start.addingTimeInterval(Double(step) * 60))
            }
            let soon = start.addingTimeInterval(3600)
            expectEqual(inventory.pruned(now: soon).knownCount, 1,
                        "many misses but only an hour — a laptop at lunch")
            let muchLater = start.addingTimeInterval(200_000)
            expectEqual(inventory.pruned(now: muchLater).knownCount, 0, "days later, forgotten")
        }

        test("rows sort numerically and survive a round trip") {
            var inventory = NetworkInventory(scopeCIDR: "10.0.0.0/24")
            inventory.merge([observation("10.0.0.10"), observation("10.0.0.9"),
                             observation("10.0.0.100")],
                            probed: ["10.0.0.9", "10.0.0.10", "10.0.0.100"], at: start)
            expectEqual(inventory.sorted().map(\.host.address),
                        ["10.0.0.9", "10.0.0.10", "10.0.0.100"], "numeric order")

            let data = try JSONEncoder().encode(inventory)
            let decoded = try JSONDecoder().decode(NetworkInventory.self, from: data)
            expectEqual(decoded.knownCount, 3, "survives being written to disk")
        }
    }
}

private func summary(_ cidr: String = "10.0.0.0/24", present: Int = 5,
                     packets: Int = 253, warnings: [SweepWarning] = []) -> SweepSummary {
    SweepSummary(scopeCIDR: cidr, interfaceName: "en0", startedAt: Date(), finishedAt: Date(),
                 probed: 253, present: present, stale: 0, packetsSent: packets,
                 backedOff: false, warnings: warnings)
}

func runSweepPolicyTests() {
    suite("Policy for a sweep") {
        func target(_ text: String) throws -> ScanTarget {
            try TargetValidator.validate(text).get()
        }

        test("a passive sweep of our own /24 is allowed") {
            let verdict = PolicyEngine.evaluate(
                targets: [try target("192.168.40.0/24")], intensity: .passive,
                requiresRoot: false, subject: "network overview",
                policy: .default, isRoot: false, addressCountOverride: 253)
            expectEqual(verdict, .allowed, "the everyday case must not nag")
        }

        test("the sweep is judged on what it probes, not on the CIDR's size") {
            // A /24 is 256 addresses and trips the large-scope advisory; the 253
            // it actually touches do not.
            let honest = PolicyEngine.evaluate(
                targets: [try target("10.0.0.0/24")], intensity: .passive,
                requiresRoot: false, subject: "sweep", policy: .default,
                isRoot: false, addressCountOverride: 253)
            expectEqual(honest, .allowed, "253 probed")
        }

        test("a sweep gets no private door through the policy") {
            var policy = ScanPolicy.default
            policy.maxAddressesPerRun = 100
            let verdict = PolicyEngine.evaluate(
                targets: [try target("10.0.0.0/24")], intensity: .passive,
                requiresRoot: false, subject: "sweep", policy: policy,
                isRoot: false, addressCountOverride: 253)
            guard case .blocked = verdict else {
                expect(false, "a tightened limit must still bite, got \(verdict)")
                return
            }
        }

        test("a public interface is refused exactly as a typed target would be") {
            let verdict = PolicyEngine.evaluate(
                targets: [try target("8.8.8.0/24")], intensity: .passive,
                requiresRoot: false, subject: "sweep", policy: .default, isRoot: false)
            guard case .blocked(let findings) = verdict else {
                expect(false, "expected blocked, got \(verdict)")
                return
            }
            expect(findings.contains { $0.kind == .unauthorisedTarget }, "unauthorised")
        }

        test("the profile-shaped call still agrees with the core") {
            let targets = [try target("10.0.0.0/24")]
            expectEqual(
                PolicyEngine.evaluate(targets: targets, profile: BuiltInProfiles.quick,
                                      policy: .default, isRoot: false),
                PolicyEngine.evaluate(targets: targets, intensity: BuiltInProfiles.quick.intensity,
                                      requiresRoot: BuiltInProfiles.quick.requiresRoot,
                                      subject: BuiltInProfiles.quick.name,
                                      policy: .default, isRoot: false),
                "the refactor must not change any existing verdict")
        }
    }

    suite("Sweep policy decoding") {
        test("adding sweep limits does not undo a rate cap the user lowered") {
            // The trap: migratedIfNeeded resets the throughput caps whenever the
            // stored schema is older. Adding fields must not ride on a bump.
            let stored = """
            {"authorisedAssets":[],"blockUnauthorisedTargets":true,
             "maxIntensityWithoutConfirmation":"moderate","maxPacketRate":500,
             "maxParallelism":32,"maxHostGroup":32,"maxAddressesPerRun":4096,
             "serialiseScans":true,"schemaVersion":2}
            """
            let decoded = try JSONDecoder().decode(ScanPolicy.self, from: Data(stored.utf8))
            expectEqual(decoded.maxPacketRate, 500, "the user's cap is read back")
            expectEqual(decoded.sweepPacketRate, 200, "sweep defaults filled in")
            expectEqual(decoded.sweepMinimumInterval, 15, "interval default")

            let migrated = decoded.migratedIfNeeded()
            expectEqual(migrated.maxPacketRate, 500,
                        "and survives migration — this is the regression guard")
        }
    }

    suite("Sweep audit") {
        let start = Date(timeIntervalSince1970: 1_700_000_000)

        test("an hour of automatic sweeping writes a handful of lines, not hundreds") {
            var coalescer = SweepAuditCoalescer(summaryInterval: 900)
            var entries = [coalescer.sessionBegan(scopeCIDR: "10.0.0.0/24",
                                                  interval: 30, at: start)]
            let addresses: Set<String> = ["10.0.0.1", "10.0.0.2"]
            // Prime the known set so the first sweep is not treated as novelty.
            _ = coalescer.note(summary(), addresses: addresses, manual: false, at: start)

            for step in 1...120 {
                let now = start.addingTimeInterval(Double(step) * 30)
                if let draft = coalescer.note(summary(), addresses: addresses,
                                              manual: false, at: now) {
                    entries.append(draft)
                }
            }
            if let ended = coalescer.sessionEnded(scopeCIDR: "10.0.0.0/24",
                                                  at: start.addingTimeInterval(3600)) {
                entries.append(ended)
            }
            expect(entries.count <= 8, "expected a handful, got \(entries.count)")
            expect(entries.count >= 3, "but not silence: \(entries.count)")
        }

        test("a person pressing refresh is always recorded") {
            var coalescer = SweepAuditCoalescer()
            let draft = try require(coalescer.note(summary(), addresses: [],
                                                   manual: true, at: start))
            expectEqual(draft.action, .sweepFinished, "recorded")
            expect(draft.detail.contains("manual"), "and marked as deliberate")
        }

        test("trouble and novelty are never coalesced away") {
            var coalescer = SweepAuditCoalescer(summaryInterval: 900)
            _ = coalescer.sessionBegan(scopeCIDR: "10.0.0.0/24", interval: 30, at: start)
            _ = coalescer.note(summary(), addresses: ["10.0.0.1"], manual: false, at: start)

            let warned = coalescer.note(summary(warnings: [.proxyArpSuspected]),
                                        addresses: ["10.0.0.1"], manual: false,
                                        at: start.addingTimeInterval(30))
            expect(warned != nil, "a warning breaks the silence immediately")

            let newHost = coalescer.note(summary(), addresses: ["10.0.0.1", "10.0.0.99"],
                                         manual: false, at: start.addingTimeInterval(60))
            let draft = try require(newHost)
            expect(draft.detail.contains("10.0.0.99"), "a host never seen before is reported")
        }
    }
}

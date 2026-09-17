import Foundation

public struct SweepObservation: Hashable, Sendable {
    public let address: String
    public let mac: String?
    public let vendor: String?
    public let presence: HostPresence
    public let name: String?
    public let isGateway: Bool
    public let observedAt: Date

    public init(address: String, mac: String?, vendor: String?, presence: HostPresence,
                name: String?, isGateway: Bool, observedAt: Date) {
        self.address = address
        self.mac = mac
        self.vendor = vendor
        self.presence = presence
        self.name = name
        self.isGateway = isGateway
        self.observedAt = observedAt
    }
}

public struct SweepSummary: Hashable, Sendable {
    public let scopeCIDR: String
    public let interfaceName: String
    public let startedAt: Date
    public let finishedAt: Date
    public let probed: Int
    public let present: Int
    public let stale: Int
    public let packetsSent: Int
    public let backedOff: Bool
    public let warnings: [SweepWarning]

    public init(scopeCIDR: String, interfaceName: String, startedAt: Date, finishedAt: Date,
                probed: Int, present: Int, stale: Int, packetsSent: Int,
                backedOff: Bool, warnings: [SweepWarning]) {
        self.scopeCIDR = scopeCIDR
        self.interfaceName = interfaceName
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.probed = probed
        self.present = present
        self.stale = stale
        self.packetsSent = packetsSent
        self.backedOff = backedOff
        self.warnings = warnings
    }

    public var duration: TimeInterval { finishedAt.timeIntervalSince(startedAt) }
}

public enum SweepWarning: String, Hashable, Sendable, Codable {
    /// Only the gateway answered out of a whole subnet — the access point is
    /// almost certainly isolating clients from each other.
    case clientIsolationSuspected
    /// One MAC answers for many addresses: a router doing proxy ARP, not a
    /// subnet full of devices.
    case proxyArpSuspected
    /// The kernel refused work and the rate was halved.
    case rateBackedOff
}

public enum SweepError: Error, Equatable, Sendable {
    case cancelled
    case scopeUnavailable
}

public enum SweepEvent: Sendable {
    case started(scopeCIDR: String, addressCount: Int, estimatedSeconds: Double)
    case progress(probed: Int, total: Int)
    case observed([SweepObservation])
    case finished(SweepSummary)
    case failed(SweepError)
}

public struct SweepOptions: Hashable, Sendable {
    public var pacing: SweepPacing
    /// How long to wait after the last probe before reading the table again.
    /// A present host answers ARP in single-digit milliseconds; this is slack
    /// for a slow switch.
    public var settleDelay: Duration
    public var resolveNames: Bool
    public var nameConcurrency: Int
    /// One MAC claiming more addresses than this looks like proxy ARP.
    public var proxyArpThreshold: Int

    public init(pacing: SweepPacing = SweepPacing(packetsPerSecond: 200),
                settleDelay: Duration = .milliseconds(900),
                resolveNames: Bool = true,
                nameConcurrency: Int = 8,
                proxyArpThreshold: Int = 8) {
        self.pacing = pacing
        self.settleDelay = settleDelay
        self.resolveNames = resolveNames
        self.nameConcurrency = nameConcurrency
        self.proxyArpThreshold = proxyArpThreshold
    }
}

/// Runs one sweep of one scope.
///
/// Shaped like `NmapRunner.run(plan:)` — an `AsyncStream` of events ending in one
/// terminal event — so the app layer consumes it the way it already consumes a
/// scan.
public actor SubnetSweeper {

    private let transport: any DiscoveryTransport
    private let vendors: MacVendorDatabase?
    private let options: SweepOptions
    private var cancelled = false

    public init(transport: any DiscoveryTransport,
                vendors: MacVendorDatabase?,
                options: SweepOptions = SweepOptions()) {
        self.transport = transport
        self.vendors = vendors
        self.options = options
    }

    public func cancel() { cancelled = true }

    public func run(scope: SweepScope, gateway: String? = nil) -> AsyncStream<SweepEvent> {
        AsyncStream(bufferingPolicy: .bufferingNewest(64)) { continuation in
            Task {
                await self.perform(scope: scope, gateway: gateway, continuation: continuation)
                continuation.finish()
            }
        }
    }

    private func perform(scope: SweepScope, gateway: String?,
                         continuation: AsyncStream<SweepEvent>.Continuation) async {
        cancelled = false
        let startedAt = Date()
        let addresses = scope.hostAddresses()
        guard !addresses.isEmpty else {
            continuation.yield(.failed(.scopeUnavailable))
            return
        }

        var pacing = options.pacing
        continuation.yield(.started(scopeCIDR: scope.target.raw,
                                    addressCount: addresses.count,
                                    estimatedSeconds: pacing.duration(forProbes: addresses.count)))

        let before = transport.arpSnapshot()

        var packetsSent = 0
        var backedOff = false
        var answered = Set<String>()
        let clockStart = ContinuousClock.now

        for (index, address) in addresses.enumerated() {
            if cancelled {
                continuation.yield(.failed(.cancelled))
                return
            }
            // Sleep until this probe's scheduled departure rather than pausing a
            // fixed amount, so a slow send cannot let the rate drift upward.
            let due = clockStart.advanced(by: .seconds(pacing.departure(index: index)))
            if due > ContinuousClock.now {
                try? await Task.sleep(until: due, clock: ContinuousClock())
            }
            do {
                try transport.probe(address: address, interfaceIndex: scope.interfaceIndex)
                packetsSent += 1
            } catch DiscoveryTransportError.outOfBuffers {
                pacing = pacing.backedOff()
                backedOff = true
            } catch {
                // Per-address failures are negative evidence, not sweep failures.
            }
            if index % 32 == 0 {
                // Drain as we go: a nearby host answers in milliseconds, long
                // before the last probe leaves.
                answered.formUnion(transport.drainReplies())
                continuation.yield(.progress(probed: index + 1, total: addresses.count))
            }
        }
        continuation.yield(.progress(probed: addresses.count, total: addresses.count))

        try? await Task.sleep(for: options.settleDelay)
        if cancelled {
            continuation.yield(.failed(.cancelled))
            return
        }
        answered.formUnion(transport.drainReplies())

        let after = transport.arpSnapshot()
        let delta = ArpDelta.between(before: before, after: after)

        var observations: [SweepObservation] = []
        let now = Date()
        for address in addresses {
            var evidence = delta.evidence(for: address)
            if answered.contains(address) { evidence.insert(.icmpReply) }
            if address == scope.localAddress { evidence.insert(.ownAddress) }
            let presence = PresenceRules.presence(from: evidence)
            guard presence.level > .absent else { continue }
            let mac = delta.mac(for: address)
            observations.append(SweepObservation(
                address: address,
                mac: mac,
                vendor: mac.flatMap { vendors?.vendor(for: $0) },
                presence: presence,
                name: nil,
                isGateway: address == gateway,
                observedAt: now
            ))
        }

        if options.resolveNames, !observations.isEmpty {
            let names = await ReverseDNS.hostnames(
                for: observations.filter { $0.presence.level == .present }.map(\.address),
                concurrency: options.nameConcurrency)
            observations = observations.map { observation in
                guard let name = names[observation.address] else { return observation }
                return SweepObservation(address: observation.address, mac: observation.mac,
                                        vendor: observation.vendor, presence: observation.presence,
                                        name: name, isGateway: observation.isGateway,
                                        observedAt: observation.observedAt)
            }
        }

        continuation.yield(.observed(observations))
        continuation.yield(.finished(SweepSummary(
            scopeCIDR: scope.target.raw,
            interfaceName: scope.interfaceName,
            startedAt: startedAt,
            finishedAt: Date(),
            probed: addresses.count,
            present: observations.filter { $0.presence.level == .present }.count,
            stale: observations.filter { $0.presence.level == .stale }.count,
            packetsSent: packetsSent,
            backedOff: backedOff,
            warnings: Self.warnings(observations: observations, probed: addresses.count,
                                    gateway: gateway, backedOff: backedOff,
                                    proxyArpThreshold: options.proxyArpThreshold)
        )))
    }

    /// Conditions worth telling the user about rather than presenting an odd
    /// table as if it were the truth.
    public static func warnings(observations: [SweepObservation], probed: Int,
                         gateway: String?, backedOff: Bool,
                         proxyArpThreshold: Int) -> [SweepWarning] {
        var warnings: [SweepWarning] = []
        if backedOff { warnings.append(.rateBackedOff) }

        let present = observations.filter { $0.presence.level == .present }
        if probed > 64, present.count == 1, let gateway, present[0].address == gateway {
            warnings.append(.clientIsolationSuspected)
        }
        var perMac: [String: Int] = [:]
        for observation in observations {
            guard let mac = observation.mac else { continue }
            perMac[mac, default: 0] += 1
        }
        if perMac.values.contains(where: { $0 > proxyArpThreshold }) {
            warnings.append(.proxyArpSuspected)
        }
        return warnings
    }
}

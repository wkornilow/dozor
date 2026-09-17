import Foundation
import Network
import Observation
import AppKit
import DozorKit

/// Drives the network overview: which subnet, when to sweep, and what the table
/// shows.
///
/// Deliberately not routed through `AppModel.start`. That path owns the live-run
/// state, forces the sidebar to the scan route, writes a history file and two
/// audit lines per run — all correct for a scan a person started, all wrong for
/// something that repeats on a timer.
@MainActor
@Observable
final class NetworkModeModel {

    enum Phase: Equatable {
        case idle
        case sweeping(probed: Int, total: Int)
        case cooling(until: Date)
    }

    private(set) var scopes: [SweepScope] = []
    var selectedScopeID: String?
    private(set) var rows: [NetworkHostRow] = []
    private(set) var phase: Phase = .idle
    private(set) var lastSummary: SweepSummary?
    private(set) var blockedReason: String?
    private(set) var advisories: [PolicyFinding] = []

    var autoRefresh = false {
        didSet { autoRefresh ? beginAutoRefresh() : endAutoRefresh() }
    }
    var interval: TimeInterval = 60
    var probePorts = true

    var selectedScope: SweepScope? {
        scopes.first { $0.id == selectedScopeID } ?? scopes.first
    }

    var isSweeping: Bool { if case .sweeping = phase { return true } else { return false } }

    @ObservationIgnored private weak var app: AppModel?
    @ObservationIgnored private var inventory: NetworkInventory?
    @ObservationIgnored private var sweepTask: Task<Void, Never>?
    @ObservationIgnored private var autoTask: Task<Void, Never>?
    @ObservationIgnored private var monitor: NWPathMonitor?
    @ObservationIgnored private var coalescer = SweepAuditCoalescer()
    @ObservationIgnored private var lastSweepEnded: Date?
    @ObservationIgnored private let queue = DispatchQueue(label: "dev.dozor.networkmode")
    @ObservationIgnored private lazy var vendors = MacVendorDatabase(nmapPath: app?.installation?.path)

    func attach(to app: AppModel) {
        self.app = app
    }

    // MARK: - Lifecycle

    func start() {
        refreshScopes()
        guard monitor == nil else { return }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] _ in
            Task { @MainActor in self?.networkChanged() }
        }
        monitor.start(queue: queue)
        self.monitor = monitor
    }

    func stop() {
        autoRefresh = false
        sweepTask?.cancel()
        sweepTask = nil
        monitor?.cancel()
        monitor = nil
    }

    /// The scope is re-resolved, never remembered as a capability: this Mac
    /// moved between subnets mid-development, and a stored scope would have kept
    /// sweeping a network it had left.
    private func refreshScopes() {
        let info = SystemNetworkInfo.current()
        scopes = SweepScope.available(primaryInterface: info.primaryInterface)
        if let selectedScopeID, !scopes.contains(where: { $0.id == selectedScopeID }) {
            self.selectedScopeID = nil
            rows = []
            inventory = nil
        }
        if selectedScopeID == nil { selectedScopeID = scopes.first?.id }
        loadInventory()
    }

    private func networkChanged() {
        autoRefresh = false
        refreshScopes()
    }

    // MARK: - Sweeping

    func refresh(manual: Bool = true) {
        guard sweepTask == nil else { return }
        guard let app, let scope = selectedScope else { return }

        if app.policy.serialiseScans, app.isScanning {
            blockedReason = L10n.t("network.blocked.scanRunning")
            return
        }
        if let last = lastSweepEnded {
            let floor = Double(app.policy.sweepMinimumInterval)
            let ready = last.addingTimeInterval(floor)
            if ready > Date() {
                phase = .cooling(until: ready)
                return
            }
        }

        // The same gate a typed target passes, judged on what is actually probed.
        let verdict = PolicyEngine.evaluate(
            targets: [scope.target], intensity: .passive, requiresRoot: false,
            subject: L10n.t("nav.network"), policy: app.policy, isRoot: app.isRoot,
            addressCountOverride: scope.addressCount)

        switch verdict {
        case .blocked(let findings):
            blockedReason = findings.map { L10n.t("policy.finding.\($0.kind.rawValue)", $0.detail) }
                .joined(separator: "\n")
            advisories = []
            AuditLog.shared.record(.sweepBlocked, scope.target.raw)
            return
        case .needsConfirmation(let findings):
            advisories = findings
            blockedReason = nil
        case .allowed:
            advisories = []
            blockedReason = nil
        }

        let rate = min(app.policy.sweepPacketRate, app.policy.maxPacketRate)
        let options = SweepOptions(pacing: SweepPacing(packetsPerSecond: rate))
        let gateway = SystemNetworkInfo.current().router

        sweepTask = Task { [weak self] in
            await self?.runSweep(scope: scope, gateway: gateway,
                                 options: options, manual: manual)
            self?.sweepTask = nil
        }
    }

    private func runSweep(scope: SweepScope, gateway: String?,
                          options: SweepOptions, manual: Bool) async {
        let sweeper = SubnetSweeper(transport: DarwinDiscoveryTransport(),
                                    vendors: vendors, options: options)
        var observations: [SweepObservation] = []

        for await event in await sweeper.run(scope: scope, gateway: gateway) {
            switch event {
            case .started(_, let count, _):
                phase = .sweeping(probed: 0, total: count)
            case .progress(let probed, let total):
                phase = .sweeping(probed: probed, total: total)
            case .observed(let found):
                observations = found
            case .finished(let summary):
                lastSummary = summary
                await apply(observations: observations, scope: scope,
                            summary: summary, manual: manual)
            case .failed:
                break
            }
        }
        phase = .idle
        lastSweepEnded = Date()
    }

    private func apply(observations: [SweepObservation], scope: SweepScope,
                       summary: SweepSummary, manual: Bool) async {
        var capabilities: [String: HostCapabilities] = [:]
        if probePorts {
            // Across hosts as well as across ports: probing forty hosts one after
            // another took longer than the sweep itself.
            let prober = DarwinPortProber()
            let live = observations.filter { $0.presence.level == .present }
            let index = scope.interfaceIndex
            capabilities = await withTaskGroup(of: (String, HostCapabilities).self) { group in
                var found: [String: HostCapabilities] = [:]
                var next = 0
                func addNext() {
                    guard next < live.count else { return }
                    let observation = live[next]
                    next += 1
                    group.addTask {
                        let outcome = await prober.probe(address: observation.address,
                                                         ports: HostCapabilities.probedPorts,
                                                         timeout: .milliseconds(500),
                                                         interfaceIndex: index)
                        return (observation.address,
                                HostCapabilities.from(ports: outcome, mac: observation.mac))
                    }
                }
                for _ in 0..<min(8, live.count) { addNext() }
                while let (address, capability) = await group.next() {
                    found[address] = capability
                    addNext()
                }
                return found
            }
        }

        var current = inventory ?? NetworkInventory(scopeCIDR: scope.target.raw)
        current.merge(observations, probed: scope.hostAddresses(),
                      capabilities: capabilities, at: Date())
        inventory = current
        rows = current.sorted()
        saveInventory()

        if let draft = coalescer.note(summary, addresses: Set(observations.map(\.address)),
                                      manual: manual, at: Date()) {
            AuditLog.shared.record(draft.action, draft.detail)
        }
    }

    // MARK: - Automatic refreshing

    private func beginAutoRefresh() {
        guard autoTask == nil, let app, let scope = selectedScope else { return }
        AuditLog.shared.record(
            coalescer.sessionBegan(scopeCIDR: scope.target.raw, interval: interval,
                                   at: Date()).action,
            "auto-refresh every \(Int(interval)) s on \(scope.target.raw)")

        let deadline = app.policy.sweepAutoRefreshMaxMinutes > 0
            ? Date().addingTimeInterval(Double(app.policy.sweepAutoRefreshMaxMinutes) * 60)
            : Date.distantFuture

        autoTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, self.autoRefresh else { return }
                // A scanner that keeps sweeping while nobody is looking is the
                // thing this app argues against, so it stops itself.
                if Date() >= deadline {
                    self.autoRefresh = false
                    return
                }
                self.refresh(manual: false)
                // Measured between completions, so a slow sweep cannot overlap
                // the next one.
                while self.sweepTask != nil {
                    try? await Task.sleep(for: .milliseconds(200))
                }
                try? await Task.sleep(for: .seconds(self.interval))
            }
        }
    }

    private func endAutoRefresh() {
        autoTask?.cancel()
        autoTask = nil
        guard let scope = selectedScope,
              let draft = coalescer.sessionEnded(scopeCIDR: scope.target.raw, at: Date())
        else { return }
        AuditLog.shared.record(draft.action, draft.detail)
    }

    // MARK: - Persistence

    private func loadInventory() {
        guard let scope = selectedScope else { return }
        let store = CodableFileStore<NetworkInventory>(
            url: AppPaths.networkInventoryFile(scopeCIDR: scope.target.raw),
            fallback: NetworkInventory(scopeCIDR: scope.target.raw))
        let loaded = store.load().pruned(now: Date())
        inventory = loaded
        rows = loaded.sorted()
    }

    private func saveInventory() {
        guard let inventory, let scope = selectedScope else { return }
        let store = CodableFileStore<NetworkInventory>(
            url: AppPaths.networkInventoryFile(scopeCIDR: scope.target.raw),
            fallback: inventory)
        try? store.save(inventory)
    }

    // MARK: - Actions

    func open(_ url: URL) {
        NSWorkspace.shared.open(url)
    }

    /// Built with `URLComponents` rather than interpolation: the address is a
    /// dotted quad by construction, and this keeps that a property of the type
    /// rather than an argument about where the string came from.
    func actionURL(scheme: String, address: String, port: Int? = nil) -> URL? {
        var components = URLComponents()
        components.scheme = scheme
        components.host = address
        if let port, port != 80, port != 443 { components.port = port }
        return components.url
    }

    func wake(_ row: NetworkHostRow) {
        guard let mac = row.host.mac, let scope = selectedScope else { return }
        let sent = WakeOnLan.send(to: mac, broadcast: scope.broadcastAddress,
                                  interfaceIndex: scope.interfaceIndex)
        AuditLog.shared.record(.wakeOnLanSent,
                               "\(row.host.address) \(mac)\(sent ? "" : " (failed)")")
    }
}

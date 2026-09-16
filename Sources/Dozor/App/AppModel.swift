import Foundation
import Observation
import SwiftUI
import DozorKit

struct AppSettings: Codable, Sendable {
    var language: AppLanguage = .system
    var nmapPathOverride: String = ""
    var advancedMode: Bool = false
    /// Index into `TextScale.steps`. Optional on decode so settings written
    /// before this existed still load.
    var textSizeIndex: Int?
}

enum SidebarRoute: Hashable {
    case scan
    case history
    case profiles
    case audit
    case settings
}

/// Everything the UI observes. Scans are driven from here so that history,
/// audit and policy are always updated together with the run itself.
@MainActor
@Observable
final class AppModel {

    // Persisted state
    var settings: AppSettings {
        didSet {
            L10n.language = settings.language
            try? settingsStore.save(settings)
        }
    }
    var policy: ScanPolicy {
        didSet {
            try? policyStore.save(policy)
            AuditLog.shared.record(.policyChanged, "limits and authorised assets updated")
        }
    }
    private(set) var customProfiles: [ScanProfile] = []
    private(set) var history: [ScanRun] = []

    // Environment
    private(set) var installation: NmapInstallation?
    private(set) var installationError: String?

    // Live scan state
    private(set) var activeRun: ScanRun?
    private(set) var progress: Double = 0
    private(set) var etaSeconds: Double?
    private(set) var logLines: [String] = []
    var isScanning: Bool { activeRun?.status == .running }

    /// Networks this Mac is attached to, offered as one-click scan ranges.
    /// Owned here rather than by the view so switching sidebar routes does not
    /// tear down and restart the path monitor.
    let networks = NetworkSuggestionsModel()

    // UI state
    var route: SidebarRoute = .scan
    var selectedRunID: UUID?
    var alertMessage: String?

    private let settingsStore = CodableFileStore(url: AppPaths.settingsFile, fallback: AppSettings())
    private let policyStore = CodableFileStore(url: AppPaths.policyFile, fallback: ScanPolicy.default)
    private let profileStore = CodableFileStore<[ScanProfile]>(url: AppPaths.profilesFile, fallback: [])
    private let historyStore = HistoryStore()
    private var runner: NmapRunner?
    private var scanTask: Task<Void, Never>?
    /// Vendor table shipped with Nmap. Loaded once, on first use, so start-up
    /// does not pay for a 1.4 MB file the user may never need.
    @ObservationIgnored private lazy var macVendors = MacVendorDatabase(nmapPath: installation?.path)

    var allProfiles: [ScanProfile] { BuiltInProfiles.all + customProfiles }

    init() {
        try? AppPaths.ensureContainers()
        let loadedSettings = settingsStore.load()
        settings = loadedSettings
        let storedPolicy = policyStore.load()
        policy = storedPolicy.migratedIfNeeded()
        L10n.language = loadedSettings.language
        if policy != storedPolicy { try? policyStore.save(policy) }
        customProfiles = profileStore.load()
        history = historyStore.loadAll()
        locateNmap()
        AuditLog.shared.record(.appStarted, "version \(installation?.version ?? "nmap not found")")
        ZoomShortcut.install { [weak self] in self?.zoomTextIn() }
    }

    // MARK: - Text size

    var textSizeIndex: Int { TextScale.clamp(settings.textSizeIndex ?? TextScale.defaultIndex) }
    var textScale: Double { TextScale.scale(at: textSizeIndex) }
    var canZoomTextIn: Bool { textSizeIndex < TextScale.steps.count - 1 }
    var canZoomTextOut: Bool { textSizeIndex > 0 }

    func zoomTextIn() { setTextSize(textSizeIndex + 1) }
    func zoomTextOut() { setTextSize(textSizeIndex - 1) }
    func resetTextSize() { setTextSize(TextScale.defaultIndex) }

    private func setTextSize(_ index: Int) {
        let clamped = TextScale.clamp(index)
        guard clamped != textSizeIndex else { return }
        settings.textSizeIndex = clamped
    }

    // MARK: - Environment

    func locateNmap() {
        do {
            let override = settings.nmapPathOverride.trimmingCharacters(in: .whitespaces)
            installation = try NmapLocator.locate(override: override.isEmpty ? nil : override)
            installationError = nil
        } catch let error as NmapLocatorError {
            installation = nil
            switch error {
            case .notFound: installationError = L10n.t("error.nmapMissing")
            case .notExecutable(let path): installationError = L10n.t("error.nmapNotExecutable", path)
            case .versionUnreadable(let path): installationError = L10n.t("error.nmapNotExecutable", path)
            }
        } catch {
            installation = nil
            installationError = L10n.t("error.nmapMissing")
        }
    }

    var isRoot: Bool { getuid() == 0 }

    // MARK: - Profiles

    func saveProfile(_ profile: ScanProfile) {
        if let index = customProfiles.firstIndex(where: { $0.id == profile.id }) {
            customProfiles[index] = profile
            AuditLog.shared.record(.profileEdited, profile.name)
        } else {
            customProfiles.append(profile)
            AuditLog.shared.record(.profileCreated, profile.name)
        }
        try? profileStore.save(customProfiles)
    }

    func deleteProfile(_ profile: ScanProfile) {
        customProfiles.removeAll { $0.id == profile.id }
        try? profileStore.save(customProfiles)
        AuditLog.shared.record(.profileDeleted, profile.name)
    }

    // MARK: - Planning

    struct PrepareFailure: Error {
        let message: String
    }

    struct PreparedScan: Identifiable {
        let id = UUID()
        let profile: ScanProfile
        let targets: [ScanTarget]
        let plan: ArgumentBuilder.Plan
        let verdict: PolicyVerdict
    }

    /// Builds the plan and runs it past policy, without starting anything.
    func prepare(profile: ScanProfile, targets: [ScanTarget], portsOverride: String,
                 timing: TimingTemplate?) -> Result<PreparedScan, PrepareFailure> {
        guard !targets.isEmpty else { return .failure(PrepareFailure(message: L10n.t("scan.noTargets"))) }

        var effective = profile
        if let timing { effective.timing = timing }
        let ports = portsOverride.trimmingCharacters(in: .whitespaces)
        if !ports.isEmpty {
            guard ArgumentPolicy.validate(["-p", ports]).isEmpty else {
                return .failure(PrepareFailure(message: L10n.t("profiles.invalid.value", "-p \(ports)")))
            }
            // Replace any port selection the profile already carries.
            var arguments: [String] = []
            var index = 0
            while index < effective.arguments.count {
                let token = effective.arguments[index]
                if token == "-p" || token == "--top-ports" {
                    index += 2
                    continue
                }
                arguments.append(token)
                index += 1
            }
            effective.arguments = arguments + ["-p", ports]
        }

        let xmlURL = AppPaths.scratchDirectory
            .appendingPathComponent("scan-\(UUID().uuidString).xml")
        do {
            let plan = try ArgumentBuilder.build(profile: effective, targets: targets,
                                                 policy: policy, xmlURL: xmlURL)
            let verdict = PolicyEngine.evaluate(targets: targets, profile: effective,
                                                policy: policy, isRoot: isRoot)
            return .success(PreparedScan(profile: effective, targets: targets,
                                         plan: plan, verdict: verdict))
        } catch let error as ArgumentBuilder.BuildError {
            switch error {
            case .noTargets: return .failure(PrepareFailure(message: L10n.t("scan.noTargets")))
            case .policy(let errors):
                return .failure(PrepareFailure(message: errors.map(Self.describe).joined(separator: "\n")))
            }
        } catch {
            return .failure(PrepareFailure(message: String(describing: error)))
        }
    }

    static func describe(_ error: ArgumentPolicyError) -> String {
        switch error {
        case .notAllowed(let flag): return L10n.t("profiles.invalid.notAllowed", flag)
        case .malformedValue(let token): return L10n.t("profiles.invalid.value", token)
        case .outputFlagNotAllowed(let flag): return L10n.t("profiles.invalid.output", flag)
        case .scriptNotAllowed(let name): return L10n.t("profiles.invalid.notAllowed", name)
        }
    }

    // MARK: - Running

    func start(_ prepared: PreparedScan) {
        guard let installation else {
            alertMessage = installationError ?? L10n.t("error.nmapMissing")
            return
        }
        if policy.serialiseScans && isScanning {
            alertMessage = L10n.t("error.busy")
            return
        }
        if case .blocked = prepared.verdict {
            AuditLog.shared.record(.scanBlocked, prepared.targets.map(\.raw).joined(separator: " "))
            alertMessage = L10n.t("policy.blocked.title")
            return
        }

        var run = ScanRun(
            profileName: L10n.profileName(prepared.profile),
            profileID: prepared.profile.id,
            targets: prepared.targets,
            arguments: prepared.plan.arguments
        )
        activeRun = run
        selectedRunID = run.id
        progress = 0
        etaSeconds = nil
        logLines = []
        route = .scan

        AuditLog.shared.record(.scanStarted,
                               "\(run.profileName) → \(prepared.targets.map(\.raw).joined(separator: " "))",
                               runID: run.id)

        let runner = NmapRunner(executablePath: installation.path)
        self.runner = runner

        scanTask = Task { [weak self] in
            for await event in runner.run(plan: prepared.plan) {
                guard let self else { return }
                switch event {
                case .started(let command):
                    self.append(log: "$ \(command)")
                case .log(let line):
                    self.append(log: line)
                case .progress(let fraction, let eta):
                    self.progress = fraction
                    self.etaSeconds = eta
                case .finished(let result, let rawXML, let exitCode):
                    // The scan just talked to every host that answered, so the
                    // system's ARP cache is warm: this is the moment to read the
                    // MAC addresses an unprivileged scan could not see.
                    run.result = HostEnricher.applyLinkLayer(to: result,
                                                             arp: ArpTable.current(),
                                                             vendors: self.macVendors)
                    run.rawXML = rawXML
                    run.exitCode = exitCode
                    run.finishedAt = Date()
                    run.status = .completed
                    run.log = self.logLines
                    self.progress = 1
                    self.finish(run)
                    self.resolveNames(forRun: run.id)
                    AuditLog.shared.record(.scanFinished,
                                           "\(result.hostsUp) hosts up, " +
                                           "\(result.hosts.reduce(0) { $0 + $1.openPorts.count }) open ports",
                                           runID: run.id)
                case .failed(let error):
                    run.finishedAt = Date()
                    run.status = error == .cancelled ? .cancelled : .failed
                    run.errorMessage = Self.describe(error)
                    run.log = self.logLines
                    self.finish(run)
                    AuditLog.shared.record(error == .cancelled ? .scanCancelled : .scanFailed,
                                           run.errorMessage ?? "", runID: run.id)
                    if error != .cancelled { self.alertMessage = run.errorMessage }
                }
            }
            // Clean up the scratch XML; the parsed result and raw text are in
            // the run record now.
            try? FileManager.default.removeItem(at: prepared.plan.xmlURL)
        }
    }

    func cancelScan() {
        runner?.cancel()
    }

    /// Names the hosts Nmap could not, using the system resolver so mDNS
    /// ".local" names are found too. Runs after the result is already on screen
    /// and fills the names in when they arrive; a slow resolver delays nothing.
    private func resolveNames(forRun id: UUID) {
        guard let result = run(withID: id)?.result else { return }
        Task { [weak self] in
            let named = await HostEnricher.applyNames(to: result)
            guard let self, named != result else { return }
            self.apply(result: named, toRun: id)
        }
    }

    private func apply(result: ScanResult, toRun id: UUID) {
        if activeRun?.id == id { activeRun?.result = result }
        guard let index = history.firstIndex(where: { $0.id == id }) else { return }
        history[index].result = result
        try? historyStore.save(history[index])
    }

    private func append(log line: String) {
        logLines.append(line)
        if logLines.count > 5000 { logLines.removeFirst(1000) }
        // The run record picks the log up once, when the scan ends. Copying the
        // whole array on every line made a long scan quadratic on the main actor.
    }

    private func finish(_ run: ScanRun) {
        activeRun = run
        try? historyStore.save(run)
        if let index = history.firstIndex(where: { $0.id == run.id }) {
            history[index] = run
        } else {
            history.insert(run, at: 0)
        }
    }

    static func describe(_ error: NmapRunnerError) -> String {
        switch error {
        case .launchFailed(let message): return L10n.t("error.launchFailed", message)
        case .permissionDenied: return L10n.t("error.permissionDenied")
        case .networkUnreachable: return L10n.t("error.networkUnreachable")
        case .noXMLOutput: return L10n.t("error.noXML")
        case .parseFailed(let message): return L10n.t("error.parseFailed", message)
        case .nonZeroExit(let code, let stderr):
            let base = L10n.t("error.exit", Int(code))
            return stderr.isEmpty ? base : base + "\n" + stderr
        case .cancelled: return L10n.t("error.cancelled")
        }
    }

    // MARK: - History

    func delete(run: ScanRun) {
        try? historyStore.delete(run.id)
        history.removeAll { $0.id == run.id }
        if activeRun?.id == run.id { activeRun = nil }
        AuditLog.shared.record(.runDeleted, run.id.uuidString, runID: run.id)
    }

    func updateTags(runID: UUID, host address: String, tags: [String]) {
        guard let index = history.firstIndex(where: { $0.id == runID }),
              var result = history[index].result,
              let hostIndex = result.hosts.firstIndex(where: { $0.address == address })
        else { return }
        result.hosts[hostIndex].tags = tags
        history[index].result = result
        if activeRun?.id == runID { activeRun?.result = result }
        try? historyStore.save(history[index])
    }

    func run(withID id: UUID?) -> ScanRun? {
        guard let id else { return nil }
        if activeRun?.id == id { return activeRun }
        return history.first { $0.id == id }
    }

    // MARK: - Export

    @discardableResult
    func export(run: ScanRun, format: ExportFormat, to url: URL) -> Bool {
        do {
            let data = try Exporter.data(for: run, format: format, strings: L10n.reportStrings)
            try data.write(to: url, options: [.atomic])
            AuditLog.shared.record(.runExported, "\(format.rawValue) → \(url.lastPathComponent)",
                                   runID: run.id)
            return true
        } catch {
            alertMessage = String(describing: error)
            return false
        }
    }
}

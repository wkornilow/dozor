import SwiftUI
import DozorKit

struct ScanView: View {
    @Environment(AppModel.self) private var model

    @State private var targetText = ""
    @State private var profileID: UUID = BuiltInProfiles.quick.id
    @State private var portsOverride = ""
    @State private var timingOverride: TimingTemplate?
    @State private var prepared: AppModel.PreparedScan?
    @State private var showingSetup = true

    private var parsed: (targets: [ScanTarget], errors: [TargetValidationError]) {
        TargetValidator.parse(targetText)
    }

    private var profile: ScanProfile {
        model.allProfiles.first { $0.id == profileID } ?? BuiltInProfiles.quick
    }

    var body: some View {
        Group {
            if let run = model.activeRun, !showingSetup {
                RunDetailView(run: run, isLive: model.isScanning,
                              progress: model.progress, eta: model.etaSeconds)
                    .toolbar {
                        ToolbarItem(placement: .navigation) {
                            Button {
                                showingSetup = true
                            } label: {
                                Label(L10n.t("nav.scan"), systemImage: "chevron.left")
                            }
                            .disabled(model.isScanning)
                        }
                        ToolbarItem(placement: .primaryAction) {
                            if model.isScanning {
                                Button(role: .destructive) {
                                    model.cancelScan()
                                } label: {
                                    Label(L10n.t("scan.cancel"), systemImage: "stop.fill")
                                }
                            }
                        }
                    }
            } else {
                setupForm
            }
        }
        .onChange(of: model.activeRun?.id) { _, newValue in
            if newValue != nil { showingSetup = false }
        }
        // Driven by the value, not by a separate flag: with `isPresented` the
        // content closure could run before `prepared` was set, which presented
        // an empty sheet with no way to dismiss it and no way to start the scan.
        .sheet(item: $prepared) { plan in
            ScanConfirmationSheet(prepared: plan, rateCap: model.policy.maxPacketRate) {
                model.start(plan)
                prepared = nil
                showingSetup = false
            } cancel: {
                prepared = nil
            }
        }
    }

    // MARK: - Setup

    private var setupForm: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                targetsSection
                profileSection
                impactSection
                if model.settings.advancedMode { advancedSection }
                previewSection
            }
            .padding(24)
            .frame(maxWidth: 820, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task { model.networks.startMonitoring() }
        .onChange(of: model.pendingNetworkTargets) { _, handed in
            guard let handed else { return }
            targetText = handed
            model.pendingNetworkTargets = nil
        }
        .onDisappear { model.networks.stopMonitoring() }
        .safeAreaInset(edge: .bottom) { startBar }
        .navigationTitle(L10n.t("nav.scan"))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Toggle(isOn: Binding(get: { model.settings.advancedMode },
                                     set: { model.settings.advancedMode = $0 })) {
                    Label(L10n.t("scan.advanced.show"), systemImage: "wrench.and.screwdriver")
                }
                .toggleStyle(.button)
                .help(L10n.t("scan.advanced.show"))
            }
        }
    }

    private var targetsSection: some View {
        SectionCard(title: L10n.t("scan.targets"), systemImage: "target") {
            TextEditor(text: $targetText)
                .appFont(.body, design: .monospaced)
                .frame(minHeight: 64, maxHeight: 120)
                .scrollContentBackground(.hidden)
                .padding(6)
                .background(Color(nsColor: .textBackgroundColor), in: .rect(cornerRadius: 6))
                .overlay(alignment: .topLeading) {
                    if targetText.isEmpty {
                        Text(L10n.t("scan.targets.placeholder"))
                            .appFont(.body, design: .monospaced)
                            .foregroundStyle(.tertiary)
                            .padding(.horizontal, 11)
                            .padding(.vertical, 12)
                            .allowsHitTesting(false)
                    }
                }
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))

            Text(L10n.t("scan.targets.help"))
                .appFont(.caption)
                .foregroundStyle(.secondary)

            suggestionsRow

            let result = parsed
            if !result.targets.isEmpty {
                FlowRow(spacing: 6) {
                    ForEach(result.targets) { target in
                        TargetChip(target: target)
                    }
                }
            }
            ForEach(Array(result.errors.enumerated()), id: \.offset) { _, error in
                Label(describe(error), systemImage: "exclamationmark.triangle.fill")
                    .appFont(.caption)
                    .foregroundStyle(.orange)
            }
        }
    }

    /// Networks this Mac is attached to, as one-click ranges. Nothing here
    /// bypasses anything: a chip writes text into the same field the user types
    /// into, and that text is re-parsed by `TargetValidator` like any other.
    @ViewBuilder
    private var suggestionsRow: some View {
        if model.networks.hasProbed {
            VStack(alignment: .leading, spacing: 6) {
                Text(L10n.t("suggestions.title"))
                    .appFont(.caption)
                    .foregroundStyle(.secondary)

                if model.networks.suggestions.isEmpty {
                    Text(L10n.t("suggestions.none"))
                        .appFont(.caption)
                        .foregroundStyle(.tertiary)
                } else {
                    FlowRow(spacing: 6) {
                        ForEach(model.networks.suggestions) { suggestion in
                            SuggestionChip(
                                suggestion: suggestion,
                                displayName: displayName(for: suggestion),
                                isSelected: TargetTextEditor.contains(suggestion.target.raw, in: targetText)
                            ) {
                                targetText = TargetTextEditor.toggling(suggestion.target.raw, in: targetText)
                            }
                        }
                    }
                }
            }
            .padding(.top, 2)
        }
    }

    private func displayName(for suggestion: NetworkSuggestion) -> String {
        switch suggestion.kind {
        case .gateway: return L10n.t("suggestions.gateway")
        case .network: return suggestion.label
        }
    }

    private var profileSection: some View {
        SectionCard(title: L10n.t("scan.profile"), systemImage: "slider.horizontal.3") {
            ForEach(model.allProfiles) { item in
                ProfileRow(profile: item, isSelected: item.id == profileID)
                    .contentShape(Rectangle())
                    .onTapGesture { profileID = item.id }
            }
        }
    }

    private var impactSection: some View {
        SectionCard(title: L10n.t("scan.impact"), systemImage: "waveform.path.ecg") {
            HStack(alignment: .top, spacing: 12) {
                IntensityBadge(intensity: profile.intensity)
                VStack(alignment: .leading, spacing: 4) {
                    Text(L10n.intensityExplanation(profile.intensity))
                        .appFont(.callout)
                    HStack(spacing: 16) {
                        MetricLabel(title: L10n.t("scan.scope"),
                                    value: L10n.t("scan.addresses", addressCount))
                        MetricLabel(title: L10n.t("scan.estimate"),
                                    value: estimateText)
                        MetricLabel(title: L10n.t("settings.maxRate"),
                                    value: model.policy.maxPacketRate > 0
                                        ? "\(model.policy.maxPacketRate) pps"
                                        : L10n.t("settings.unlimited"))
                    }
                    if isRateLimited {
                        Label(L10n.t("scan.rateWarning", model.policy.maxPacketRate),
                              systemImage: "tortoise.fill")
                            .appFont(.caption)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }

    /// True when the configured packet-rate cap, not the network, will decide
    /// how long the run takes — the difference between a scan that finishes in
    /// seconds and one the user reads as frozen.
    private var isRateLimited: Bool {
        guard addressCount > 0 else { return false }
        var effective = profile
        if let timingOverride { effective.timing = timingOverride }
        return ArgumentBuilder.isRateLimitBinding(profile: effective,
                                                  addresses: addressCount,
                                                  policy: model.policy)
    }

    private var advancedSection: some View {
        SectionCard(title: L10n.t("scan.advanced"), systemImage: "wrench.and.screwdriver") {
            Picker(L10n.t("scan.timing"), selection: Binding(
                get: { timingOverride ?? profile.timing },
                set: { timingOverride = $0 }
            )) {
                ForEach(TimingTemplate.allCases, id: \.self) { timing in
                    Text(L10n.timingName(timing)).tag(timing)
                }
            }
            .pickerStyle(.menu)

            LabeledContent(L10n.t("scan.ports")) {
                TextField(L10n.t("scan.ports.placeholder"), text: $portsOverride)
                    .textFieldStyle(.roundedBorder)
                    .appFont(.body, design: .monospaced)
            }
        }
    }

    private var previewSection: some View {
        SectionCard(title: L10n.t("scan.preview"), systemImage: "terminal") {
            Text(previewCommand)
                .appFont(.caption, design: .monospaced)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(Color(nsColor: .textBackgroundColor), in: .rect(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))
        }
    }

    private var startBar: some View {
        HStack {
            if !parsed.targets.isEmpty {
                Text(L10n.t("scan.valid", parsed.targets.count))
                    .appFont(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                switch model.prepare(profile: profile, targets: parsed.targets,
                                     portsOverride: portsOverride, timing: timingOverride) {
                case .success(let plan):
                    AuditLog.shared.record(.scanRequested,
                                           parsed.targets.map(\.raw).joined(separator: " "))
                    prepared = plan
                case .failure(let failure):
                    model.alertMessage = failure.message
                }
            } label: {
                Label(L10n.t("scan.start"), systemImage: "play.fill")
                    .frame(minWidth: 120)
            }
            .keyboardShortcut(.return, modifiers: .command)
            .buttonStyle(.borderedProminent)
            .disabled(parsed.targets.isEmpty || model.installation == nil
                      || (model.policy.serialiseScans && model.isScanning))
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 12)
        .background(.bar)
    }

    // MARK: - Derived

    private var addressCount: Int {
        parsed.targets.reduce(0) { $0 + ($1.addressCount ?? 1) }
    }

    private var estimateText: String {
        guard addressCount > 0 else { return L10n.t("common.none") }
        var effective = profile
        if let timingOverride { effective.timing = timingOverride }
        let seconds = ArgumentBuilder.estimateSeconds(profile: effective,
                                                      addresses: addressCount,
                                                      policy: model.policy)
        return "≈ " + L10n.duration(seconds)
    }

    private var previewCommand: String {
        let path = model.installation?.path ?? "nmap"
        var effective = profile
        if let timingOverride { effective.timing = timingOverride }
        let targets = parsed.targets.isEmpty
            ? [ScanTarget(raw: "<target>", kind: .hostname, addressCount: 1, isPrivate: true)]
            : parsed.targets
        let placeholderURL = URL(fileURLWithPath: "/tmp/scan.xml")
        guard let plan = try? ArgumentBuilder.build(profile: effective, targets: targets,
                                                    policy: model.policy, xmlURL: placeholderURL)
        else { return path }
        return ([path] + plan.arguments).joined(separator: " ")
    }

    private func describe(_ error: TargetValidationError) -> String {
        switch error {
        case .empty: return L10n.t("validation.empty")
        case .illegalCharacters(let text): return L10n.t("validation.illegal", text)
        case .unrecognised(let text): return L10n.t("validation.unrecognised", text)
        case .badCIDR(let text): return L10n.t("validation.badCIDR", text)
        case .badRange(let text): return L10n.t("validation.badRange", text)
        case .tooManyAddresses(let text, let count): return L10n.t("validation.tooMany", text, count)
        }
    }
}

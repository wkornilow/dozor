import SwiftUI
import DozorKit

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var assetsText = ""

    var body: some View {
        @Bindable var model = model
        TabView {
            general.tabItem { Label(L10n.t("settings.general"), systemImage: "gearshape") }
            security.tabItem { Label(L10n.t("settings.security"), systemImage: "lock.shield") }
            limits.tabItem { Label(L10n.t("settings.limits"), systemImage: "speedometer") }
        }
        .padding(20)
        .onAppear { assetsText = model.policy.authorisedAssets.joined(separator: "\n") }
        .navigationTitle(L10n.t("nav.settings"))
    }

    private var general: some View {
        @Bindable var model = model
        return Form {
            Picker(L10n.t("settings.language"), selection: $model.settings.language) {
                ForEach(AppLanguage.allCases, id: \.self) { language in
                    Text(language.displayName).tag(language)
                }
            }

            Toggle(L10n.t("scan.advanced.show"), isOn: $model.settings.advancedMode)

            Section {
                TextField(L10n.t("settings.nmapPath"), text: $model.settings.nmapPathOverride,
                          prompt: Text("/opt/homebrew/bin/nmap"))
                    .appFont(.body, design: .monospaced)
                    .onSubmit { model.locateNmap() }
                if let installation = model.installation {
                    Label("\(installation.path) — \(installation.version)",
                          systemImage: "checkmark.seal.fill")
                        .appFont(.caption)
                        .foregroundStyle(.green)
                } else if let error = model.installationError {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .appFont(.caption)
                        .foregroundStyle(.orange)
                }
                Button(L10n.t("settings.nmapPath.auto")) { model.locateNmap() }
            }
        }
        .formStyle(.grouped)
    }

    private var security: some View {
        @Bindable var model = model
        return Form {
            Section(L10n.t("settings.assets")) {
                TextEditor(text: $assetsText)
                    .appFont(.body, design: .monospaced)
                    .frame(minHeight: 140)
                    .onChange(of: assetsText) { _, text in
                        model.policy.authorisedAssets = text
                            .components(separatedBy: .newlines)
                            .map { $0.trimmingCharacters(in: .whitespaces) }
                            .filter { !$0.isEmpty }
                    }
                Text(L10n.t("settings.assets.help"))
                    .appFont(.caption)
                    .foregroundStyle(.secondary)
            }

            Toggle(L10n.t("settings.blockUnauthorised"), isOn: $model.policy.blockUnauthorisedTargets)

            Picker(L10n.t("settings.maxIntensity"), selection: $model.policy.maxIntensityWithoutConfirmation) {
                ForEach(ScanIntensity.allCases, id: \.self) { intensity in
                    Text(L10n.intensityName(intensity)).tag(intensity)
                }
            }

            Picker(L10n.t("settings.blockedIntensity"), selection: Binding(
                get: { model.policy.blockedIntensity },
                set: { model.policy.blockedIntensity = $0 }
            )) {
                Text(L10n.t("settings.blockedIntensity.none")).tag(ScanIntensity?.none)
                ForEach(ScanIntensity.allCases, id: \.self) { intensity in
                    Text(L10n.intensityName(intensity)).tag(ScanIntensity?.some(intensity))
                }
            }
        }
        .formStyle(.grouped)
    }

    private func limitText(_ value: Int) -> String {
        value > 0 ? "\(value)" : L10n.t("settings.unlimited")
    }

    private var limits: some View {
        @Bindable var model = model
        return Form {
            Section {
                Stepper(value: $model.policy.maxPacketRate, in: 0...200_000, step: 1_000) {
                    LabeledContent(L10n.t("settings.maxRate"), value: limitText(model.policy.maxPacketRate))
                }
                Text(L10n.t("settings.maxRate.help"))
                    .appFont(.caption)
                    .foregroundStyle(.secondary)
            }
            Stepper(value: $model.policy.maxParallelism, in: 0...1024, step: 16) {
                LabeledContent(L10n.t("settings.maxParallelism"), value: limitText(model.policy.maxParallelism))
            }
            Stepper(value: $model.policy.maxHostGroup, in: 0...1024, step: 16) {
                LabeledContent(L10n.t("settings.maxHostGroup"), value: limitText(model.policy.maxHostGroup))
            }
            Stepper(value: $model.policy.maxAddressesPerRun, in: 1...65_536, step: 256) {
                LabeledContent(L10n.t("settings.maxAddresses"), value: "\(model.policy.maxAddressesPerRun)")
            }
            Toggle(L10n.t("settings.serialise"), isOn: $model.policy.serialiseScans)
        }
        .formStyle(.grouped)
    }
}

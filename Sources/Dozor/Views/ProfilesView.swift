import SwiftUI
import DozorKit

struct ProfilesView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: UUID?
    @State private var draft: ScanProfile?

    var body: some View {
        // HStack rather than HSplitView: inside NavigationSplitView's detail
        // column an HSplitView sizes itself to its children instead of to the
        // space offered. Measured on a 960 pt window it took 922 x 139 pt of a
        // 741 x 672 column, which squashed the list into a band and shoved the
        // sidebar off the left edge.
        HStack(spacing: 0) {
            List(selection: $selection) {
                Section(L10n.t("profiles.builtIn")) {
                    ForEach(BuiltInProfiles.all) { profile in
                        profileLabel(profile).tag(profile.id)
                    }
                }
                Section(L10n.t("profiles.custom")) {
                    ForEach(model.customProfiles) { profile in
                        profileLabel(profile).tag(profile.id)
                            .contextMenu {
                                Button(L10n.t("profiles.duplicate")) { duplicate(profile) }
                                Button(L10n.t("profiles.delete"), role: .destructive) {
                                    model.deleteProfile(profile)
                                }
                            }
                    }
                }
            }
            .frame(width: 260)
            .safeAreaInset(edge: .bottom) {
                HStack {
                    Button {
                        let new = ScanProfile(name: L10n.t("profiles.new"), detail: "",
                                              arguments: ["-sT", "--top-ports", "100"],
                                              intensity: .light)
                        draft = new
                        selection = new.id
                    } label: {
                        Label(L10n.t("profiles.new"), systemImage: "plus")
                    }
                    .buttonStyle(.borderless)
                    Spacer()
                }
                .padding(8)
                .background(.bar)
            }

            Divider()

            Group {
                if let profile = editingProfile {
                    ProfileEditor(profile: profile, isEditable: !profile.isBuiltIn) { saved in
                        model.saveProfile(saved)
                        draft = nil
                        selection = saved.id
                    }
                    .id(profile.id)
                } else {
                    ContentUnavailableView(L10n.t("profiles.custom"), systemImage: "slider.horizontal.3")
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle(L10n.t("nav.profiles"))
    }

    private var editingProfile: ScanProfile? {
        if let draft, draft.id == selection { return draft }
        return model.allProfiles.first { $0.id == selection }
    }

    private func profileLabel(_ profile: ScanProfile) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(L10n.profileName(profile))
            Text(L10n.intensityName(profile.intensity))
                .appFont(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func duplicate(_ profile: ScanProfile) {
        var copy = profile
        copy.id = UUID()
        copy.name = L10n.profileName(profile) + " copy"
        copy.detail = L10n.profileDetail(profile)
        copy.isBuiltIn = false
        model.saveProfile(copy)
        selection = copy.id
    }
}

struct ProfileEditor: View {
    @State private var profile: ScanProfile
    @State private var argumentText: String
    let isEditable: Bool
    let save: (ScanProfile) -> Void

    init(profile: ScanProfile, isEditable: Bool, save: @escaping (ScanProfile) -> Void) {
        _profile = State(initialValue: profile)
        _argumentText = State(initialValue: profile.arguments.joined(separator: " "))
        self.isEditable = isEditable
        self.save = save
    }

    private var tokens: [String] { ArgumentPolicy.tokenize(argumentText) }
    private var errors: [ArgumentPolicyError] { ArgumentPolicy.validate(tokens) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                SectionCard(title: L10n.t("profiles.name"), systemImage: "tag") {
                    TextField(L10n.t("profiles.name"), text: Binding(
                        get: { isEditable ? profile.name : L10n.profileName(profile) },
                        set: { profile.name = $0 }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .disabled(!isEditable)

                    TextField(L10n.t("profiles.detail"), text: Binding(
                        get: { isEditable ? profile.detail : L10n.profileDetail(profile) },
                        set: { profile.detail = $0 }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .disabled(!isEditable)
                }

                SectionCard(title: L10n.t("profiles.arguments"), systemImage: "terminal") {
                    TextEditor(text: $argumentText)
                        .appFont(.body, design: .monospaced)
                        .frame(minHeight: 60, maxHeight: 110)
                        .scrollContentBackground(.hidden)
                        .padding(6)
                        .background(Color(nsColor: .textBackgroundColor), in: .rect(cornerRadius: 6))
                        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))
                        .disabled(!isEditable)

                    Text(L10n.t("profiles.arguments.help"))
                        .appFont(.caption)
                        .foregroundStyle(.secondary)

                    if errors.isEmpty {
                        Label(L10n.t("profiles.valid"), systemImage: "checkmark.circle.fill")
                            .appFont(.caption)
                            .foregroundStyle(.green)
                    } else {
                        ForEach(Array(errors.enumerated()), id: \.offset) { _, error in
                            Label(AppModel.describe(error), systemImage: "exclamationmark.triangle.fill")
                                .appFont(.caption)
                                .foregroundStyle(.orange)
                        }
                    }
                }

                SectionCard(title: L10n.t("scan.impact"), systemImage: "waveform.path.ecg") {
                    Picker(L10n.t("scan.impact"), selection: $profile.intensity) {
                        ForEach(ScanIntensity.allCases, id: \.self) { intensity in
                            Text(L10n.intensityName(intensity)).tag(intensity)
                        }
                    }
                    .disabled(!isEditable)

                    Picker(L10n.t("scan.timing"), selection: $profile.timing) {
                        ForEach(TimingTemplate.allCases, id: \.self) { timing in
                            Text(L10n.timingName(timing)).tag(timing)
                        }
                    }
                    .disabled(!isEditable)

                    Toggle("root", isOn: $profile.requiresRoot)
                        .disabled(!isEditable)
                }

                SectionCard(title: L10n.t("scan.preview"), systemImage: "eye") {
                    Text("nmap " + tokens.joined(separator: " ") + " … -oX <file> -- <targets>")
                        .appFont(.caption, design: .monospaced)
                        .textSelection(.enabled)
                }

                if isEditable {
                    Button(L10n.t("profiles.save")) {
                        profile.arguments = tokens
                        save(profile)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!errors.isEmpty || profile.name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .padding(20)
            .frame(maxWidth: 640, alignment: .leading)
        }
    }
}

import SwiftUI
import DozorKit

struct ProfilesView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: UUID?
    /// A new profile that has not been saved yet. It shows in the list so the
    /// user can see where it will land, and disappears if they move away.
    @State private var draft: ScanProfile?
    @State private var pendingDelete: ScanProfile?

    var body: some View {
        // HStack rather than HSplitView: inside NavigationSplitView's detail
        // column an HSplitView sizes itself to its children instead of to the
        // space offered. Measured on a 960 pt window it took 922 x 139 pt of a
        // 741 x 672 column, which squashed the list into a band and shoved the
        // sidebar off the left edge.
        HStack(spacing: 0) {
            profileList
                .frame(width: 270)

            Divider()

            Group {
                if let profile = selectedProfile {
                    ProfileDetail(
                        profile: profile,
                        isDraft: profile.id == draft?.id,
                        save: { saved in
                            model.saveProfile(saved)
                            draft = nil
                            selection = saved.id
                        },
                        duplicate: { duplicate(profile) },
                        delete: { requestDelete(profile) }
                    )
                    .id(profile.id)
                } else {
                    ContentUnavailableView {
                        Label(L10n.t("profiles.empty.title"), systemImage: "slider.horizontal.3")
                    } description: {
                        Text(L10n.t("profiles.empty.detail"))
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle(L10n.t("nav.profiles"))
        .onChange(of: selection) { _, newValue in
            if let draft, newValue != draft.id { self.draft = nil }
        }
        .onAppear {
            if selection == nil { selection = BuiltInProfiles.all.first?.id }
        }
        .confirmationDialog(
            L10n.t("profiles.delete.confirm", pendingDelete.map(L10n.profileName) ?? ""),
            isPresented: Binding(get: { pendingDelete != nil },
                                 set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button(L10n.t("profiles.delete"), role: .destructive) {
                if let pendingDelete { delete(pendingDelete) }
            }
            Button(L10n.t("common.cancel"), role: .cancel) { pendingDelete = nil }
        } message: {
            Text(L10n.t("profiles.delete.message"))
        }
    }

    // MARK: - List

    private var profileList: some View {
        List(selection: $selection) {
            Section(L10n.t("profiles.builtIn")) {
                ForEach(BuiltInProfiles.all) { profile in
                    ProfileListRow(profile: profile)
                        .tag(profile.id)
                        .contextMenu {
                            Button(L10n.t("profiles.duplicate")) { duplicate(profile) }
                        }
                }
            }
            Section {
                ForEach(customRows) { profile in
                    ProfileListRow(profile: profile, isDraft: profile.id == draft?.id)
                        .tag(profile.id)
                        .contextMenu {
                            if profile.id != draft?.id {
                                Button(L10n.t("profiles.duplicate")) { duplicate(profile) }
                                Divider()
                                Button(L10n.t("profiles.delete"), role: .destructive) {
                                    requestDelete(profile)
                                }
                            }
                        }
                }
            } header: {
                Text(L10n.t("profiles.custom"))
            } footer: {
                if customRows.isEmpty {
                    Text(L10n.t("profiles.custom.empty"))
                        .appFont(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .listStyle(.inset)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: 0) {
                Divider()
                HStack(spacing: 2) {
                    Button(action: createProfile) {
                        Image(systemName: "plus")
                            .frame(width: 22, height: 20)
                    }
                    .help(L10n.t("profiles.new"))

                    Button {
                        if let profile = selectedProfile { requestDelete(profile) }
                    } label: {
                        Image(systemName: "minus")
                            .frame(width: 22, height: 20)
                    }
                    .help(L10n.t("profiles.delete"))
                    .disabled(selectedProfile.map { $0.isBuiltIn } ?? true)

                    Spacer()
                }
                .buttonStyle(.borderless)
                .padding(.horizontal, 8)
                .padding(.vertical, 6)
            }
            .background(.bar)
        }
    }

    private var customRows: [ScanProfile] {
        var rows = model.customProfiles
        if let draft, !rows.contains(where: { $0.id == draft.id }) { rows.append(draft) }
        return rows
    }

    private var selectedProfile: ScanProfile? {
        if let draft, draft.id == selection { return draft }
        return model.allProfiles.first { $0.id == selection }
    }

    // MARK: - Actions

    private func createProfile() {
        let new = ScanProfile(name: L10n.t("profiles.new"), detail: "",
                              arguments: ["-sT", "--top-ports", "100"],
                              intensity: .light)
        draft = new
        selection = new.id
    }

    private func duplicate(_ profile: ScanProfile) {
        var copy = profile
        copy.id = UUID()
        copy.name = L10n.t("profiles.copyName", L10n.profileName(profile))
        copy.detail = L10n.profileDetail(profile)
        copy.isBuiltIn = false
        model.saveProfile(copy)
        selection = copy.id
    }

    private func requestDelete(_ profile: ScanProfile) {
        guard !profile.isBuiltIn else { return }
        if profile.id == draft?.id {
            // Never saved, nothing to lose: no need to ask.
            draft = nil
            selection = nil
        } else {
            pendingDelete = profile
        }
    }

    private func delete(_ profile: ScanProfile) {
        model.deleteProfile(profile)
        if selection == profile.id { selection = nil }
        pendingDelete = nil
    }
}

// MARK: - List row

private struct ProfileListRow: View {
    let profile: ScanProfile
    var isDraft = false

    var body: some View {
        HStack(spacing: 10) {
            IntensityTile(intensity: profile.intensity, size: 28)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(L10n.profileName(profile))
                        .appFont(.body, weight: .medium)
                        .lineLimit(1)
                    if profile.requiresRoot {
                        Image(systemName: "lock.fill")
                            .appFont(.caption2)
                            .foregroundStyle(.orange)
                            .help(L10n.t("profiles.root"))
                    }
                }
                Text(subtitle)
                    .appFont(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 3)
    }

    private var subtitle: String {
        if isDraft { return L10n.t("profiles.unsaved") }
        let detail = L10n.profileDetail(profile)
        return detail.isEmpty ? L10n.intensityName(profile.intensity) : detail
    }
}

/// Coloured square carrying the intensity symbol — the profile's "icon".
private struct IntensityTile: View {
    let intensity: ScanIntensity
    let size: CGFloat

    var body: some View {
        Image(systemName: intensity.symbol)
            .font(.system(size: size * 0.5, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(intensity.tint.gradient, in: .rect(cornerRadius: size * 0.24))
    }
}

// MARK: - Detail

private struct ProfileDetail: View {
    let original: ScanProfile
    let isDraft: Bool
    let save: (ScanProfile) -> Void
    let duplicate: () -> Void
    let delete: () -> Void

    @State private var profile: ScanProfile
    @State private var argumentText: String

    init(profile: ScanProfile, isDraft: Bool,
         save: @escaping (ScanProfile) -> Void,
         duplicate: @escaping () -> Void,
         delete: @escaping () -> Void) {
        self.original = profile
        self.isDraft = isDraft
        self.save = save
        self.duplicate = duplicate
        self.delete = delete
        _profile = State(initialValue: profile)
        _argumentText = State(initialValue: profile.arguments.joined(separator: " "))
    }

    private var isEditable: Bool { !original.isBuiltIn }
    private var tokens: [String] { ArgumentPolicy.tokenize(argumentText) }
    private var errors: [ArgumentPolicyError] { ArgumentPolicy.validate(tokens) }
    private var trimmedName: String { profile.name.trimmingCharacters(in: .whitespaces) }

    private var edited: ScanProfile {
        var result = profile
        result.arguments = tokens
        return result
    }

    private var hasChanges: Bool { isDraft || edited != original }
    private var canSave: Bool { hasChanges && errors.isEmpty && !trimmedName.isEmpty }

    var body: some View {
        VStack(spacing: 0) {
            header
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
            Divider()
            Form {
                if isEditable { editableSections } else { readOnlySections }
                commandSection
            }
            .formStyle(.grouped)
            if isEditable {
                Divider()
                footer
            }
        }
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            IntensityTile(intensity: profile.intensity, size: 44)
            VStack(alignment: .leading, spacing: 4) {
                Text(displayName)
                    .appFont(.title2, weight: .semibold)
                    .lineLimit(1)
                if !displayDetail.isEmpty {
                    Text(displayDetail)
                        .appFont(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                HStack(spacing: 6) {
                    Chip(text: L10n.intensityName(profile.intensity), tint: profile.intensity.tint)
                    Chip(text: L10n.timingName(profile.timing), tint: .secondary)
                    if profile.requiresRoot {
                        Chip(text: "root", systemImage: "lock.fill", tint: .orange)
                    }
                    if original.isBuiltIn {
                        Chip(text: L10n.t("profiles.builtIn.one"), systemImage: "shippingbox", tint: .secondary)
                    }
                }
                .padding(.top, 2)
            }
            Spacer(minLength: 12)
            HStack(spacing: 8) {
                if !isDraft {
                    Button(action: duplicate) {
                        Label(L10n.t("profiles.duplicate"), systemImage: "plus.square.on.square")
                    }
                    .help(L10n.t("profiles.duplicate"))
                }
                if isEditable {
                    Button(role: .destructive, action: delete) {
                        Label(L10n.t("profiles.delete"), systemImage: "trash")
                    }
                    .help(L10n.t("profiles.delete"))
                }
            }
            .labelStyle(.iconOnly)
            .buttonStyle(.bordered)
        }
    }

    private var displayName: String {
        if isEditable { return trimmedName.isEmpty ? L10n.t("profiles.new") : profile.name }
        return L10n.profileName(profile)
    }

    private var displayDetail: String {
        isEditable ? profile.detail : L10n.profileDetail(profile)
    }

    // MARK: Read-only (built-in)

    @ViewBuilder
    private var readOnlySections: some View {
        Section {
            Label {
                HStack {
                    Text(L10n.t("profiles.readOnly"))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button(L10n.t("profiles.duplicateToEdit"), action: duplicate)
                }
            } icon: {
                Image(systemName: "lock")
                    .foregroundStyle(.secondary)
            }
        }

        Section(L10n.t("profiles.behavior")) {
            LabeledContent(L10n.t("scan.impact")) {
                Text(L10n.intensityName(profile.intensity))
            }
            Text(L10n.intensityExplanation(profile.intensity))
                .appFont(.caption)
                .foregroundStyle(.secondary)
            LabeledContent(L10n.t("scan.timing"), value: L10n.timingName(profile.timing))
            LabeledContent(L10n.t("profiles.root"),
                           value: L10n.t(profile.requiresRoot ? "profiles.root.yes" : "profiles.root.no"))
            LabeledContent(L10n.t("profiles.perHost"), value: perHostEstimate)
        }
    }

    private var perHostEstimate: String {
        profile.secondsPerHost < 1 ? L10n.t("profiles.perHost.instant")
                                   : "≈ " + L10n.duration(profile.secondsPerHost)
    }

    // MARK: Editable (custom)

    @ViewBuilder
    private var editableSections: some View {
        Section(L10n.t("profiles.general")) {
            TextField(L10n.t("profiles.name"), text: $profile.name)
            TextField(L10n.t("profiles.detail"), text: $profile.detail,
                      prompt: Text(L10n.t("profiles.detail.prompt")))
        }

        Section {
            TextEditor(text: $argumentText)
                .appFont(.body, design: .monospaced)
                .scrollContentBackground(.hidden)
                .frame(minHeight: 54, maxHeight: 96)
                .autocorrectionDisabled()
            validation
        } header: {
            Text(L10n.t("profiles.arguments"))
        } footer: {
            Text(L10n.t("profiles.arguments.help"))
                .appFont(.caption)
                .foregroundStyle(.secondary)
        }

        Section(L10n.t("profiles.behavior")) {
            Picker(L10n.t("scan.impact"), selection: $profile.intensity) {
                ForEach(ScanIntensity.allCases, id: \.self) { intensity in
                    Text(L10n.intensityName(intensity)).tag(intensity)
                }
            }
            Text(L10n.intensityExplanation(profile.intensity))
                .appFont(.caption)
                .foregroundStyle(.secondary)
            Picker(L10n.t("scan.timing"), selection: $profile.timing) {
                ForEach(TimingTemplate.allCases, id: \.self) { timing in
                    Text(L10n.timingName(timing)).tag(timing)
                }
            }
            Toggle(isOn: $profile.requiresRoot) {
                Text(L10n.t("profiles.root"))
                Text(L10n.t("profiles.root.help"))
            }
        }
    }

    @ViewBuilder
    private var validation: some View {
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

    // MARK: Shared

    private var commandSection: some View {
        Section(L10n.t("scan.preview")) {
            HStack(alignment: .top) {
                Text(previewCommand)
                    .appFont(.callout, design: .monospaced)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    Pasteboard.copy(previewCommand)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help(L10n.t("common.copy"))
            }
        }
    }

    /// Mirrors ArgumentBuilder: the timing template is appended unless the
    /// arguments already carry one.
    private var previewCommand: String {
        var parts = ["nmap"] + tokens
        if !tokens.contains(where: { $0.hasPrefix("-T") }) { parts.append(profile.timing.flag) }
        parts.append("… -oX <file> -- <targets>")
        return parts.joined(separator: " ")
    }

    private var footer: some View {
        HStack {
            if hasChanges && !isDraft {
                Text(L10n.t("profiles.unsavedChanges"))
                    .appFont(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !isDraft {
                Button(L10n.t("profiles.revert")) {
                    profile = original
                    argumentText = original.arguments.joined(separator: " ")
                }
                .disabled(!hasChanges)
            }
            Button(L10n.t("profiles.save")) {
                var result = edited
                result.name = trimmedName
                save(result)
            }
            .buttonStyle(.borderedProminent)
            .keyboardShortcut("s", modifiers: .command)
            .disabled(!canSave)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
        .background(.bar)
    }
}

private struct Chip: View {
    let text: String
    var systemImage: String?
    let tint: Color

    var body: some View {
        HStack(spacing: 3) {
            if let systemImage { Image(systemName: systemImage) }
            Text(text)
        }
        .appFont(.caption2, weight: .medium)
        .padding(.horizontal, 7)
        .padding(.vertical, 2)
        .foregroundStyle(tint)
        .background(tint.opacity(0.15), in: .capsule)
    }
}

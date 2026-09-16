import SwiftUI
import DozorKit

@main
struct DozorApp: App {

    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(model)
                .environment(\.textScale, model.textScale)
                .frame(minWidth: 960, minHeight: 620)
        }
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button(L10n.t("nav.scan")) { model.route = .scan }
                    .keyboardShortcut("n", modifiers: .command)
            }
            CommandGroup(after: .toolbar) {
                Toggle(L10n.t("scan.advanced.show"), isOn: Binding(
                    get: { model.settings.advancedMode },
                    set: { model.settings.advancedMode = $0 }
                ))
                .keyboardShortcut("e", modifiers: [.command, .shift])

                Divider()

                Button(L10n.t("view.zoomIn")) { model.zoomTextIn() }
                    .keyboardShortcut("+", modifiers: .command)
                    .disabled(!model.canZoomTextIn)
                Button(L10n.t("view.zoomOut")) { model.zoomTextOut() }
                    .keyboardShortcut("-", modifiers: .command)
                    .disabled(!model.canZoomTextOut)
                Button(L10n.t("view.zoomReset", TextScale.percentLabel(at: model.textSizeIndex))) {
                    model.resetTextSize()
                }
                .keyboardShortcut("0", modifiers: .command)
            }
        }

        Settings {
            SettingsView()
                .environment(model)
                .environment(\.textScale, model.textScale)
                .frame(width: 560, height: 520)
        }
    }
}

struct ContentView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            List(selection: $model.route) {
                Section(L10n.t("nav.section.work")) {
                    Label(L10n.t("nav.scan"), systemImage: "dot.radiowaves.left.and.right")
                        .tag(SidebarRoute.scan)
                    Label(L10n.t("nav.history"), systemImage: "clock.arrow.circlepath")
                        .tag(SidebarRoute.history)
                }
                Section(L10n.t("nav.section.manage")) {
                    Label(L10n.t("nav.profiles"), systemImage: "slider.horizontal.3")
                        .tag(SidebarRoute.profiles)
                    Label(L10n.t("nav.audit"), systemImage: "list.bullet.rectangle")
                        .tag(SidebarRoute.audit)
                    Label(L10n.t("nav.settings"), systemImage: "gearshape")
                        .tag(SidebarRoute.settings)
                }
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 210, max: 280)
            .safeAreaInset(edge: .bottom) { NmapStatusBar() }
        } detail: {
            switch model.route {
            case .scan: ScanView()
            case .history: HistoryView()
            case .profiles: ProfilesView()
            case .audit: AuditView()
            case .settings: SettingsView()
            }
        }
        .alert(L10n.t("error.title"),
               isPresented: Binding(get: { model.alertMessage != nil },
                                    set: { if !$0 { model.alertMessage = nil } })) {
            Button(L10n.t("common.ok"), role: .cancel) { model.alertMessage = nil }
        } message: {
            Text(model.alertMessage ?? "")
        }
    }
}

/// Persistent footer showing whether Nmap is usable at all — the single most
/// common failure for this kind of app.
struct NmapStatusBar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: model.installation == nil ? "exclamationmark.triangle.fill" : "checkmark.seal.fill")
                .foregroundStyle(model.installation == nil ? .orange : .green)
            if let installation = model.installation {
                Text("Nmap \(installation.version)")
                    .foregroundStyle(.secondary)
            } else {
                Text(L10n.t("error.nmapMissing"))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer()
        }
        .appFont(.caption)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
        .help(model.installation?.path ?? "")
    }
}

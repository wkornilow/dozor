import SwiftUI
import DozorKit

struct HistoryView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: UUID?
    @State private var search = ""

    private var runs: [ScanRun] {
        let needle = search.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return model.history }
        return model.history.filter { run in
            run.profileName.lowercased().contains(needle)
                || run.author.lowercased().contains(needle)
                || run.targets.contains { $0.raw.lowercased().contains(needle) }
        }
    }

    private var selectedRun: ScanRun? {
        model.history.first { $0.id == selection }
    }

    /// Full width now, so the author column earns its place again.
    private var runTable: some View {
        Table(runs, selection: $selection) {
            TableColumn(L10n.t("history.started")) { run in
                Text(DateFormatter.runStamp.string(from: run.startedAt))
                    .appFont(.callout, monospacedDigit: true)
            }
            .width(150)
            TableColumn(L10n.t("history.profile")) { run in
                Text(run.profileName)
            }
            .width(min: 120, ideal: 180)
            TableColumn(L10n.t("history.targets")) { run in
                Text(run.targets.map(\.raw).joined(separator: ", "))
                    .appFont(.callout, design: .monospaced)
                    .lineLimit(1)
            }
            .width(min: 140, ideal: 240)
            TableColumn(L10n.t("history.status")) { run in
                StatusPill(status: run.status)
            }
            .width(90)
            TableColumn(L10n.t("history.author")) { run in
                Text(run.author).foregroundStyle(.secondary)
            }
            .width(min: 90, ideal: 120)
        }
        .contextMenu(forSelectionType: UUID.self) { ids in
            Button(L10n.t("history.delete"), role: .destructive) {
                for id in ids {
                    if let run = model.history.first(where: { $0.id == id }) {
                        model.delete(run: run)
                    }
                }
            }
        }
    }

    var body: some View {
        Group {
            if model.history.isEmpty {
                ContentUnavailableView(L10n.t("history.empty"), systemImage: "clock.arrow.circlepath")
            } else {
                // Table across the full width, the selected run underneath it.
                // With nothing selected the table takes the whole pane rather
                // than leaving an empty placeholder beside it.
                GeometryReader { proxy in
                    VStack(spacing: 0) {
                        runTable
                            .frame(height: selectedRun == nil
                                   ? proxy.size.height
                                   : max(200, proxy.size.height * 0.42))

                        if let run = selectedRun {
                            Divider()
                            RunDetailView(run: run)
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                        }
                    }
                    .frame(width: proxy.size.width, height: proxy.size.height)
                }
            }
        }
        .searchable(text: $search)
        .navigationTitle(L10n.t("nav.history"))
    }
}

struct AuditView: View {
    @State private var entries: [AuditEntry] = []

    var body: some View {
        Group {
            if entries.isEmpty {
                ContentUnavailableView(L10n.t("audit.empty"), systemImage: "list.bullet.rectangle")
            } else {
                Table(entries) {
                    TableColumn(L10n.t("audit.time")) { entry in
                        Text(DateFormatter.runStamp.string(from: entry.timestamp))
                            .appFont(.callout, monospacedDigit: true)
                    }
                    .width(150)
                    TableColumn(L10n.t("audit.actor")) { entry in
                        Text(entry.actor)
                    }
                    .width(110)
                    TableColumn(L10n.t("audit.action")) { entry in
                        Text(entry.action.rawValue)
                    }
                    .width(140)
                    TableColumn(L10n.t("audit.detail")) { entry in
                        Text(entry.detail).lineLimit(2)
                    }
                }
            }
        }
        .navigationTitle(L10n.t("nav.audit"))
        .task { entries = AuditLog.shared.readAll() }
        .refreshable { entries = AuditLog.shared.readAll() }
    }
}

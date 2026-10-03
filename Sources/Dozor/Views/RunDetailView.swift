import SwiftUI
import AppKit
import DozorKit

struct RunDetailView: View {
    let run: ScanRun
    var isLive: Bool = false
    var progress: Double = 0
    var eta: Double?

    @Environment(AppModel.self) private var model
    @State private var tab: Tab = .results
    @State private var compareWith: UUID?

    enum Tab: String, CaseIterable { case results, log }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            Picker("", selection: $tab) {
                Text(L10n.t("results.hosts")).tag(Tab.results)
                Text(L10n.t("results.log")).tag(Tab.log)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 260)
            .padding(.vertical, 8)

            Divider()

            switch tab {
            case .results:
                if let baseline = model.run(withID: compareWith)?.result,
                   let current = run.result {
                    DiffView(diff: ScanDiff.compare(baseline: baseline, current: current),
                             baselineRun: model.run(withID: compareWith))
                } else {
                    ResultsView(run: run)
                }
            case .log:
                LogView(lines: run.log.isEmpty ? model.logLines : run.log)
            }
        }
        .navigationTitle(run.profileName)
        .toolbar { toolbarContent }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                StatusPill(status: run.status)
                Text(run.targets.map(\.raw).joined(separator: ", "))
                    .appFont(.callout)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Text(DateFormatter.runStamp.string(from: run.startedAt))
                    .appFont(.caption)
                    .foregroundStyle(.secondary)
            }

            if isLive {
                VStack(alignment: .leading, spacing: 4) {
                    ProgressView(value: progress)
                    HStack {
                        Text(L10n.t("scan.running"))
                        Spacer()
                        Text("\(Int(progress * 100))%")
                        if let eta {
                            Text("· " + L10n.duration(eta))
                        }
                    }
                    .appFont(.caption, monospacedDigit: true)
                    .foregroundStyle(.secondary)
                }
            } else if let result = run.result {
                HStack(spacing: 20) {
                    MetricLabel(title: L10n.t("results.hostsUp"), value: "\(result.hostsUp)")
                    MetricLabel(title: L10n.t("results.openPorts"),
                                value: "\(result.hosts.reduce(0) { $0 + $1.openPorts.count })")
                    if let duration = run.duration {
                        MetricLabel(title: L10n.t("history.duration"), value: L10n.duration(duration))
                    }
                    MetricLabel(title: L10n.t("history.author"), value: run.author)
                }
            }

            if let message = run.errorMessage, run.status != .cancelled {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .appFont(.caption)
                    .foregroundStyle(.red)
                    .lineLimit(4)
                    .help(message)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem {
            Menu {
                Button(L10n.t("diff.none")) { compareWith = nil }
                Divider()
                ForEach(comparableRuns) { other in
                    Button {
                        compareWith = other.id
                    } label: {
                        Text("\(DateFormatter.runStamp.string(from: other.startedAt)) — \(other.profileName)")
                    }
                }
            } label: {
                Label(L10n.t("history.compare"), systemImage: "arrow.left.arrow.right")
            }
            .disabled(run.result == nil || comparableRuns.isEmpty)
        }
        ToolbarItem {
            Menu {
                ForEach(ExportFormat.allCases, id: \.self) { format in
                    Button(L10n.t("export.\(format.rawValue)")) { export(format) }
                }
            } label: {
                Label(L10n.t("export.title"), systemImage: "square.and.arrow.up")
            }
            .disabled(run.result == nil)
        }
    }

    private var comparableRuns: [ScanRun] {
        model.history.filter { $0.id != run.id && $0.result != nil }
    }

    private func export(_ format: ExportFormat) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = Exporter.suggestedFilename(for: run, format: format)
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        model.export(run: run, format: format, to: url)
    }
}

struct LogView: View {
    let lines: [String]

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { index, line in
                        Text(line)
                            .appFont(.caption, design: .monospaced)
                            .foregroundStyle(colour(for: line))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .id(index)
                    }
                }
                .padding(12)
            }
            .background(Color(nsColor: .textBackgroundColor))
            .onChange(of: lines.count) { _, count in
                // No animation: a busy scan emits lines faster than an animated
                // scroll can settle, which stalls the main thread.
                proxy.scrollTo(count - 1, anchor: .bottom)
            }
        }
    }

    private func colour(for line: String) -> Color {
        let lower = line.lowercased()
        if lower.hasPrefix("$ ") { return .accentColor }
        if lower.contains("warning") { return .orange }
        if lower.contains("error") || lower.contains("failed") { return .red }
        return .primary
    }
}

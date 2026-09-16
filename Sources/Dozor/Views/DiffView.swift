import SwiftUI
import DozorKit

struct DiffView: View {
    let diff: ScanDiff
    let baselineRun: ScanRun?

    var body: some View {
        if diff.isEmpty {
            ContentUnavailableView(L10n.t("diff.none"), systemImage: "equal.circle")
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if let baselineRun {
                        Text("\(L10n.t("diff.pick")): \(DateFormatter.runStamp.string(from: baselineRun.startedAt))")
                            .appFont(.caption)
                            .foregroundStyle(.secondary)
                    }

                    if !diff.newHosts.isEmpty {
                        group(L10n.t("diff.newHosts"), "plus.circle.fill", .green) {
                            ForEach(diff.newHosts) { host in
                                Text("\(host.address)  \(host.hostnames.first ?? "")")
                                    .appFont(.callout, design: .monospaced)
                            }
                        }
                    }
                    if !diff.missingHosts.isEmpty {
                        group(L10n.t("diff.missingHosts"), "minus.circle.fill", .red) {
                            ForEach(diff.missingHosts) { host in
                                Text("\(host.address)  \(host.hostnames.first ?? "")")
                                    .appFont(.callout, design: .monospaced)
                            }
                        }
                    }
                    changeGroup(.opened, L10n.t("diff.opened"), "arrow.up.circle.fill", .orange)
                    changeGroup(.closed, L10n.t("diff.closed"), "arrow.down.circle.fill", .green)
                    changeGroup(.serviceChanged, L10n.t("diff.serviceChanged"), "arrow.triangle.2.circlepath", .blue)
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    @ViewBuilder
    private func changeGroup(_ kind: PortChange.Kind, _ title: String,
                             _ icon: String, _ colour: Color) -> some View {
        let items = diff.changes.filter { $0.kind == kind }
        if !items.isEmpty {
            group(title, icon, colour) {
                ForEach(items) { change in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(change.host)
                            .appFont(.callout, design: .monospaced)
                            .frame(width: 140, alignment: .leading)
                        Text("\(change.port.port)/\(change.port.proto)")
                            .appFont(.callout, design: .monospaced)
                            .frame(width: 80, alignment: .leading)
                        if kind == .serviceChanged {
                            Text("\(change.previous ?? "—") → \(change.current ?? "—")")
                                .appFont(.callout)
                                .foregroundStyle(.secondary)
                        } else {
                            Text(change.port.serviceSummary ?? change.port.serviceName ?? "—")
                                .appFont(.callout)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func group<Content: View>(_ title: String, _ icon: String, _ colour: Color,
                                      @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon)
                .appFont(.headline)
                .foregroundStyle(colour)
            VStack(alignment: .leading, spacing: 4) { content() }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(nsColor: .controlBackgroundColor), in: .rect(cornerRadius: 8))
        }
    }
}

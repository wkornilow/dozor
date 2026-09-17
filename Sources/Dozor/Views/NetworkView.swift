import SwiftUI
import DozorKit

/// The LAN overview: one flat table of everything on this Mac's own subnet.
///
/// Deliberately has no target field. The subnet comes from a picker fed by the
/// machine's live interfaces, so the mode cannot be pointed anywhere the Mac is
/// not already attached — the authorised-asset rule holds by construction rather
/// than by a check that could be forgotten.
struct NetworkView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: Set<String> = []
    @State private var search = ""
    @State private var sortOrder = [KeyPathComparator(\NetworkHostRow.host.address)]

    private var network: NetworkModeModel { model.network }

    private var visibleRows: [NetworkHostRow] {
        let needle = search.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return network.rows }
        return network.rows.filter { row in
            row.host.address.contains(needle)
                || (row.host.bestName?.lowercased().contains(needle) ?? false)
                || (row.host.mac?.lowercased().contains(needle) ?? false)
                || (row.host.vendor?.lowercased().contains(needle) ?? false)
        }
    }

    private var selectedRow: NetworkHostRow? {
        guard selection.count == 1, let address = selection.first else { return nil }
        return network.rows.first { $0.host.address == address }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if network.scopes.isEmpty {
                ContentUnavailableView(L10n.t("network.noScope"),
                                       systemImage: "network.slash")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HStack(spacing: 0) {
                    table
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    if let row = selectedRow {
                        Divider()
                        NetworkHostDetail(row: row)
                            .frame(minWidth: 280, idealWidth: 320, maxWidth: 380)
                            .frame(maxHeight: .infinity)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(L10n.t("nav.network"))
        .task { network.start() }
        .onDisappear { network.stop() }
    }

    // MARK: - Header

    private var header: some View {
        @Bindable var network = model.network
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Picker("", selection: $network.selectedScopeID) {
                    ForEach(network.scopes) { scope in
                        Text("\(scope.interfaceName) · \(scope.target.raw)")
                            .tag(Optional(scope.id))
                    }
                }
                .labelsHidden()
                .frame(maxWidth: 260)

                Button {
                    network.refresh()
                } label: {
                    Label(L10n.t("network.refresh"), systemImage: "arrow.clockwise")
                }
                .disabled(network.isSweeping)

                Toggle(isOn: $network.autoRefresh) {
                    Label(L10n.t("network.auto"), systemImage: "repeat")
                }
                .toggleStyle(.button)

                Picker("", selection: $network.interval) {
                    Text("30 s").tag(TimeInterval(30))
                    Text("1 min").tag(TimeInterval(60))
                    Text("5 min").tag(TimeInterval(300))
                }
                .labelsHidden()
                .frame(width: 90)
                .disabled(!network.autoRefresh)

                Toggle(L10n.t("network.probePorts"), isOn: $network.probePorts)
                    .toggleStyle(.checkbox)

                Spacer()

                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField(L10n.t("results.search"), text: $search)
                        .textFieldStyle(.plain)
                        .frame(width: 180)
                }
            }

            HStack(spacing: 14) {
                if case .sweeping(let probed, let total) = network.phase {
                    ProgressView(value: Double(probed), total: Double(max(total, 1)))
                        .frame(width: 120)
                    Text(L10n.t("network.sweeping", probed, total))
                        .appFont(.caption)
                        .foregroundStyle(.secondary)
                } else if let summary = network.lastSummary {
                    Text(L10n.t("network.counts", summary.present,
                                network.rows.count, summary.probed))
                        .appFont(.caption)
                        .foregroundStyle(.secondary)
                    Text(String(format: "%.1f s", summary.duration))
                        .appFont(.caption, monospacedDigit: true)
                        .foregroundStyle(.tertiary)
                }
                Spacer()
            }

            if let reason = network.blockedReason {
                Label(reason, systemImage: "hand.raised.fill")
                    .appFont(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(network.advisories) { finding in
                Label(L10n.t("policy.finding.\(finding.kind.rawValue)", finding.detail),
                      systemImage: "exclamationmark.triangle.fill")
                    .appFont(.caption)
                    .foregroundStyle(.orange)
            }
            ForEach(network.lastSummary?.warnings ?? [], id: \.self) { warning in
                Label(L10n.t("network.warning.\(warning.rawValue)"), systemImage: "info.circle")
                    .appFont(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    // MARK: - Table

    private var table: some View {
        Table(visibleRows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("") { row in
                Circle()
                    .fill(colour(for: row.status()))
                    .frame(width: 8, height: 8)
                    .help(L10n.t("network.status.\(row.status().rawValue)"))
            }
            .width(24)

            TableColumn("IP", value: \.host.address) { row in
                HStack(spacing: 5) {
                    if row.isGateway {
                        Image(systemName: "wifi.router").appFont(.caption2)
                    }
                    Text(row.host.address).appFont(.callout, design: .monospaced)
                }
            }
            .width(min: 150, ideal: 170)

            TableColumn(L10n.t("results.name.column")) { row in
                Text(row.host.bestName ?? "—")
                    .foregroundStyle(row.host.bestName == nil ? .tertiary : .primary)
            }
            .width(min: 120, ideal: 180)

            TableColumn("MAC") { row in
                HStack(spacing: 4) {
                    Text(row.host.mac ?? "—").appFont(.caption, design: .monospaced)
                    if row.macChangedAt != nil {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .appFont(.caption2)
                            .foregroundStyle(.orange)
                            .help(L10n.t("network.macChanged"))
                    }
                }
            }
            .width(150)

            TableColumn(L10n.t("network.vendor")) { row in
                Text(vendorText(row)).foregroundStyle(.secondary)
            }
            .width(min: 120, ideal: 170)

            TableColumn(L10n.t("network.ports")) { row in
                Text(row.capabilities.openPorts.map(String.init).joined(separator: " "))
                    .appFont(.caption, design: .monospaced)
                    .foregroundStyle(.secondary)
            }
            .width(min: 90, ideal: 120)

            TableColumn(L10n.t("network.lastSeen")) { row in
                Text(row.status() == .up ? "—"
                     : DateFormatter.runStamp.string(from: row.lastSeen))
                    .appFont(.caption, monospacedDigit: true)
                    .foregroundStyle(.secondary)
            }
            .width(120)
        }
        .contextMenu(forSelectionType: String.self) { addresses in
            if let address = addresses.first,
               let row = network.rows.first(where: { $0.host.address == address }) {
                NetworkRowActions(row: row)
                Divider()
                HostCopyMenu(host: row.host)
            }
            if addresses.count > 1 {
                Button(L10n.t("network.scanSelected")) { scanWithNmap(addresses) }
            }
        }
        .copyable(selection.compactMap { address in
            network.rows.first { $0.host.address == address }?.host.tabSeparatedSummary
        })
    }

    private func vendorText(_ row: NetworkHostRow) -> String {
        if let vendor = row.host.vendor { return vendor }
        guard let mac = row.host.mac else { return "—" }
        return ArpTable.isLocallyAdministered(mac: mac)
            ? L10n.t("results.mac.random") : "—"
    }

    private func colour(for status: RowStatus) -> Color {
        switch status {
        case .up: return .green
        case .recentlyUp: return .orange
        case .gone: return .secondary
        }
    }

    /// Hands off to the existing engine: same validator, same policy, same
    /// confirmation sheet, same run record. The overview is a targeting aid for
    /// the scanner, not a second scanner.
    private func scanWithNmap(_ addresses: Set<String>) {
        let targets = addresses.compactMap { address -> ScanTarget? in
            guard case .success(let target) = TargetValidator.validate(address) else { return nil }
            return target
        }
        guard !targets.isEmpty else { return }
        model.pendingNetworkTargets = targets.map(\.raw).joined(separator: " ")
        model.route = .scan
    }
}

/// The per-host actions. Anything that depends on a port appears only when that
/// port answered, so a button never opens something that is not there.
struct NetworkRowActions: View {
    @Environment(AppModel.self) private var model
    let row: NetworkHostRow

    var body: some View {
        if let port = row.capabilities.web,
           let url = model.network.actionURL(scheme: "http", address: row.host.address, port: port) {
            Button(L10n.t("network.action.web")) { model.network.open(url) }
        }
        if row.capabilities.secureWeb,
           let url = model.network.actionURL(scheme: "https", address: row.host.address) {
            Button(L10n.t("network.action.secureWeb")) { model.network.open(url) }
        }
        if row.capabilities.ssh,
           let url = model.network.actionURL(scheme: "ssh", address: row.host.address) {
            Button(L10n.t("network.action.ssh")) { model.network.open(url) }
        }
        if row.capabilities.fileSharing,
           let url = model.network.actionURL(scheme: "smb", address: row.host.address) {
            Button(L10n.t("network.action.smb")) { model.network.open(url) }
        }
        if row.capabilities.screenSharing,
           let url = model.network.actionURL(scheme: "vnc", address: row.host.address) {
            Button(L10n.t("network.action.screen")) { model.network.open(url) }
        }
        if row.capabilities.wakeable {
            Button(L10n.t("network.action.wake")) { model.network.wake(row) }
        }
    }
}

struct NetworkHostDetail: View {
    @Environment(AppModel.self) private var model
    let row: NetworkHostRow

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 6) {
                    Text(row.host.address)
                        .appFont(.title2, design: .monospaced, weight: .semibold)
                        .textSelection(.enabled)
                    Button {
                        Pasteboard.copy(row.host.address)
                    } label: {
                        Image(systemName: "document.on.document").appFont(.caption)
                    }
                    .buttonStyle(.borderless)
                }

                if let name = row.host.bestName {
                    Text(name).foregroundStyle(.secondary)
                }

                HStack(alignment: .top, spacing: 18) {
                    MetricLabel(title: L10n.t("network.status"),
                                value: L10n.t("network.status.\(row.status().rawValue)"))
                    MetricLabel(title: L10n.t("network.firstSeen"),
                                value: DateFormatter.runStamp.string(from: row.firstSeen))
                }

                if let mac = row.host.mac {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("MAC").appFont(.caption2).foregroundStyle(.tertiary)
                        Text(mac).appFont(.callout, design: .monospaced).textSelection(.enabled)
                        Text(row.host.vendor
                             ?? L10n.t(ArpTable.isLocallyAdministered(mac: mac)
                                       ? "results.mac.random" : "results.mac.unknownVendor"))
                            .appFont(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if !row.capabilities.openPorts.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(L10n.t("network.ports")).appFont(.caption2).foregroundStyle(.tertiary)
                        FlowRow(spacing: 6) {
                            ForEach(row.capabilities.openPorts, id: \.self) { port in
                                Text("\(port)")
                                    .appFont(.caption, design: .monospaced)
                                    .padding(.horizontal, 7).padding(.vertical, 2)
                                    .background(.quaternary, in: .capsule)
                            }
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 6) {
                    NetworkRowActions(row: row)
                        .buttonStyle(.bordered)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                if row.macChangedAt != nil {
                    Label(L10n.t("network.macChanged"), systemImage: "exclamationmark.triangle.fill")
                        .appFont(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

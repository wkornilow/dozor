import SwiftUI
import DozorKit

struct ResultsView: View {
    let run: ScanRun

    @Environment(AppModel.self) private var model
    @State private var search = ""
    @State private var openOnly = true
    @State private var upOnly = true
    @State private var selectedHost: String?
    @State private var newTag = ""
    @FocusState private var searchFocused: Bool

    private var hosts: [HostResult] {
        guard let result = run.result else { return [] }
        let needle = search.trimmingCharacters(in: .whitespaces).lowercased()
        return result.hosts.filter { host in
            if upOnly && host.state != "up" { return false }
            if openOnly && host.openPorts.isEmpty && host.state == "up"
                && !(run.result?.hosts.allSatisfy { $0.ports.isEmpty } ?? false) {
                // Keep discovery-only runs visible; hide port-scanned hosts with
                // nothing open when the filter is on.
                if !host.ports.isEmpty { return false }
            }
            guard !needle.isEmpty else { return true }
            if host.address.lowercased().contains(needle) { return true }
            if host.hostnames.contains(where: { $0.lowercased().contains(needle) }) { return true }
            if host.reverseName?.lowercased().contains(needle) == true { return true }
            if host.mac?.lowercased().contains(needle) == true { return true }
            if host.vendor?.lowercased().contains(needle) == true { return true }
            if host.tags.contains(where: { $0.lowercased().contains(needle) }) { return true }
            return host.ports.contains { port in
                String(port.port).contains(needle)
                    || (port.serviceName ?? "").lowercased().contains(needle)
                    || (port.serviceSummary ?? "").lowercased().contains(needle)
            }
        }
        .sorted { $0.address.compare($1.address, options: .numeric) == .orderedAscending }
    }

    private var selected: HostResult? {
        hosts.first { $0.address == selectedHost } ?? hosts.first
    }

    var body: some View {
        if run.result == nil {
            ContentUnavailableView(L10n.t("results.empty"), systemImage: "list.bullet.rectangle")
        } else {
            // The filter bar sits outside every branch below it. When it lived
            // inside them, typing a query that matched nothing swapped the
            // branch, destroyed the text field and took the caret with it.
            VStack(spacing: 0) {
                filters
                Divider()

                if hosts.isEmpty {
                    ContentUnavailableView(L10n.t("results.noHosts"),
                                           systemImage: "antenna.radiowaves.left.and.right.slash")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    HSplitView {
                        List(hosts, selection: $selectedHost) { host in
                            HostRow(host: host)
                                .tag(host.address)
                                .contextMenu { HostCopyMenu(host: host) }
                        }
                        .listStyle(.inset)
                        .copyable(selected.map { [$0.address] } ?? [])
                        .frame(minWidth: 260, idealWidth: 320, maxWidth: 420)

                        if let host = selected {
                            HostDetailView(host: host, runID: run.id, newTag: $newTag)
                        } else {
                            ContentUnavailableView(L10n.t("results.empty"), systemImage: "sidebar.right")
                        }
                    }
                }
            }
        }
    }

    private var filters: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField(L10n.t("results.search"), text: $search)
                .textFieldStyle(.plain)
                .focused($searchFocused)
            Menu {
                Toggle(L10n.t("results.filter.openOnly"), isOn: $openOnly)
                Toggle(L10n.t("results.filter.upOnly"), isOn: $upOnly)
            } label: {
                Image(systemName: "line.3.horizontal.decrease.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

struct HostRow: View {
    let host: HostResult

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(host.state == "up" ? Color.green : Color.secondary)
                .frame(width: 7, height: 7)
            VStack(alignment: .leading, spacing: 1) {
                Text(host.address)
                    .appFont(.body, design: .monospaced)
                if let name = host.bestName {
                    Text(name).appFont(.caption).foregroundStyle(.secondary)
                }
                if let mac = host.mac {
                    HStack(spacing: 4) {
                        Text(mac)
                            .appFont(.caption2, design: .monospaced)
                        if let vendor = host.vendor {
                            Text(vendor).appFont(.caption2)
                        }
                    }
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                } else if let vendor = host.vendor {
                    Text(vendor)
                        .appFont(.caption2)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
            }
            Spacer()
            if !host.openPorts.isEmpty {
                Text("\(host.openPorts.count)")
                    .appFont(.caption, monospacedDigit: true)
                    .padding(.horizontal, 6).padding(.vertical, 1)
                    .background(.quaternary, in: .capsule)
            }
        }
        .padding(.vertical, 2)
    }
}

struct HostDetailView: View {
    let host: HostResult
    let runID: UUID
    @Binding var newTag: String

    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        Text(host.address)
                            .appFont(.title2, design: .monospaced, weight: .semibold)
                            .textSelection(.enabled)
                        Button {
                            Pasteboard.copy(host.address)
                        } label: {
                            Image(systemName: "document.on.document")
                                .appFont(.caption)
                        }
                        .buttonStyle(.borderless)
                        .help(L10n.t("results.copy.ip"))
                    }
                    if let name = host.bestName {
                        HStack(spacing: 6) {
                            Text(name).foregroundStyle(.secondary)
                            if host.hostnames.isEmpty, host.reverseName != nil {
                                Text(L10n.t("results.name.resolver"))
                                    .appFont(.caption2)
                                    .padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(.quaternary, in: .capsule)
                            }
                        }
                    }
                    HStack(alignment: .top, spacing: 18) {
                        if let mac = host.mac {
                            VStack(alignment: .leading, spacing: 1) {
                                HStack(spacing: 5) {
                                    Text("MAC")
                                        .appFont(.caption2)
                                        .foregroundStyle(.tertiary)
                                    if host.macSource == .arpCache {
                                        Image(systemName: "info.circle")
                                            .appFont(.caption2)
                                            .foregroundStyle(.tertiary)
                                            .help(L10n.t("results.mac.arp"))
                                    }
                                }
                                Text(mac)
                                    .appFont(.callout, design: .monospaced)
                                    .textSelection(.enabled)
                                    .contextMenu { HostCopyMenu(host: host) }
                                Text(host.vendor ?? L10n.t(ArpTable.isLocallyAdministered(mac: mac)
                                                           ? "results.mac.random" : "results.mac.unknownVendor"))
                                    .appFont(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        if let os = host.osGuess {
                            MetricLabel(title: L10n.t("results.os"), value: os)
                        }
                    }
                    .padding(.top, 4)
                }

                tagEditor

                if host.ports.isEmpty {
                    Text(L10n.t("results.empty")).foregroundStyle(.secondary)
                } else {
                    portTable
                }

                let scripts = host.ports.flatMap { port in
                    port.scripts.map { (port.port, $0.key, $0.value) }
                }
                if !scripts.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(Array(scripts.enumerated()), id: \.offset) { _, item in
                            VStack(alignment: .leading, spacing: 2) {
                                Text("\(item.0) · \(item.1)")
                                    .appFont(.caption, weight: .semibold)
                                Text(item.2)
                                    .appFont(.caption, design: .monospaced)
                                    .textSelection(.enabled)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.quaternary.opacity(0.3), in: .rect(cornerRadius: 8))
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var tagEditor: some View {
        HStack(spacing: 6) {
            ForEach(host.tags, id: \.self) { tag in
                HStack(spacing: 3) {
                    Text(tag).appFont(.caption)
                    Button {
                        model.updateTags(runID: runID, host: host.address,
                                         tags: host.tags.filter { $0 != tag })
                    } label: {
                        Image(systemName: "xmark.circle.fill").appFont(.caption2)
                    }
                    .buttonStyle(.plain)
                }
                .padding(.horizontal, 7).padding(.vertical, 2)
                .background(.tint.opacity(0.15), in: .capsule)
            }
            TextField(L10n.t("results.addTag"), text: $newTag)
                .textFieldStyle(.roundedBorder)
                .frame(width: 140)
                .onSubmit {
                    let tag = newTag.trimmingCharacters(in: .whitespaces)
                    guard !tag.isEmpty, !host.tags.contains(tag) else { return }
                    model.updateTags(runID: runID, host: host.address, tags: host.tags + [tag])
                    newTag = ""
                }
        }
    }

    private var portTable: some View {
        Table(host.ports) {
            TableColumn(L10n.t("results.port")) { port in
                Text("\(port.port)/\(port.proto)")
                    .appFont(.body, design: .monospaced)
            }
            .width(90)
            TableColumn(L10n.t("results.state")) { port in
                Text(port.state)
                    .foregroundStyle(port.state == "open" ? Color.green : .secondary)
            }
            .width(80)
            TableColumn(L10n.t("results.service")) { port in
                Text(port.serviceName ?? "—")
            }
            .width(120)
            TableColumn(L10n.t("results.version")) { port in
                Text(port.serviceSummary ?? "—").textSelection(.enabled)
            }
            TableColumn(L10n.t("results.reason")) { port in
                Text(port.reason ?? "—").foregroundStyle(.secondary)
            }
            .width(100)
        }
        .frame(minHeight: 220, maxHeight: 460)
    }
}

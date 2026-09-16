import SwiftUI
import DozorKit

/// Last gate before any packet leaves the machine: the exact scope, the network
/// impact, the command itself, and an explicit authorisation acknowledgement.
struct ScanConfirmationSheet: View {
    let prepared: AppModel.PreparedScan
    let rateCap: Int
    let confirm: () -> Void
    let cancel: () -> Void

    @State private var acknowledged = false

    private var findings: [PolicyFinding] {
        switch prepared.verdict {
        case .allowed: return []
        case .needsConfirmation(let items), .blocked(let items): return items
        }
    }

    private var isBlocked: Bool {
        if case .blocked = prepared.verdict { return true }
        return false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: isBlocked ? "hand.raised.fill" : "shield.lefthalf.filled")
                    .appFont(.title)
                    .foregroundStyle(isBlocked ? .red : .accentColor)
                Text(isBlocked ? L10n.t("policy.blocked.title") : L10n.t("policy.title"))
                    .appFont(.title2, weight: .semibold)
            }
            .padding(20)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    scopeGrid
                    if !findings.isEmpty { findingsList }
                    commandBox
                }
                .padding(20)
            }
            .frame(maxHeight: 360)

            Divider()

            VStack(alignment: .leading, spacing: 12) {
                if !isBlocked {
                    Toggle(isOn: $acknowledged) {
                        Text(L10n.t("policy.confirm"))
                            .appFont(.callout)
                    }
                }
                HStack {
                    Spacer()
                    Button(L10n.t("common.cancel"), role: .cancel, action: cancel)
                        .keyboardShortcut(.escape)
                    if !isBlocked {
                        Button(L10n.t("policy.run"), action: confirm)
                            .buttonStyle(.borderedProminent)
                            .disabled(!acknowledged)
                            .keyboardShortcut(.return)
                    }
                }
            }
            .padding(20)
        }
        .frame(width: 620)
    }

    private var scopeGrid: some View {
        Grid(alignment: .leading, horizontalSpacing: 20, verticalSpacing: 8) {
            GridRow {
                Text(L10n.t("scan.profile")).foregroundStyle(.secondary)
                Text(L10n.profileName(prepared.profile))
            }
            GridRow {
                Text(L10n.t("scan.scope")).foregroundStyle(.secondary)
                Text(L10n.t("scan.addresses", prepared.plan.addressCount))
            }
            GridRow {
                Text(L10n.t("scan.estimate")).foregroundStyle(.secondary)
                Text("≈ " + L10n.duration(prepared.plan.estimatedSeconds))
            }
            if prepared.plan.isRateLimited {
                GridRow {
                    Text("").frame(width: 0)
                    Label(L10n.t("scan.rateWarning", rateCap), systemImage: "tortoise.fill")
                        .appFont(.callout)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            GridRow {
                Text(L10n.t("scan.impact")).foregroundStyle(.secondary)
                Text(L10n.intensityExplanation(prepared.profile.intensity))
                    .fixedSize(horizontal: false, vertical: true)
            }
            GridRow {
                Text(L10n.t("scan.targets")).foregroundStyle(.secondary)
                FlowRow(spacing: 6) {
                    ForEach(prepared.targets) { TargetChip(target: $0) }
                }
            }
        }
        .appFont(.callout)
    }

    private var findingsList: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(findings) { finding in
                Label {
                    Text(describe(finding))
                        .appFont(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: finding.isBlocking ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(finding.isBlocking ? .red : .orange)
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: .rect(cornerRadius: 8))
    }

    private var commandBox: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(L10n.t("scan.preview"))
                .appFont(.caption)
                .foregroundStyle(.secondary)
            Text(prepared.plan.arguments.joined(separator: " "))
                .appFont(.caption, design: .monospaced)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(Color(nsColor: .textBackgroundColor), in: .rect(cornerRadius: 6))
        }
    }

    private func describe(_ finding: PolicyFinding) -> String {
        L10n.t("policy.finding.\(finding.kind.rawValue)", finding.detail)
    }
}

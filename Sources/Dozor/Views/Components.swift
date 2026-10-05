import SwiftUI
import DozorKit

/// Grouped card matching the look of System Settings panes.
struct SectionCard<Content: View>: View {
    let title: String
    let systemImage: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: systemImage)
                .appFont(.headline)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 10) { content }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(14)
                .background(Color(nsColor: .controlBackgroundColor), in: .rect(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.separator.opacity(0.6)))
        }
    }
}

struct MetricLabel: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title)
                .appFont(.caption2)
                .foregroundStyle(.tertiary)
            Text(value)
                .appFont(.callout, monospacedDigit: true)
        }
    }
}

extension ScanIntensity {
    /// Shared by every place that shows a profile's weight, so a colour means
    /// the same thing on the Scan and Profiles screens.
    var tint: Color {
        switch self {
        case .passive: return .green
        case .light: return .mint
        case .moderate: return .blue
        case .heavy: return .orange
        case .aggressive: return .red
        }
    }

    var symbol: String {
        switch self {
        case .passive: return "leaf"
        case .light: return "wind"
        case .moderate: return "gauge.medium"
        case .heavy: return "gauge.high"
        case .aggressive: return "exclamationmark.triangle"
        }
    }
}

struct IntensityBadge: View {
    let intensity: ScanIntensity

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: intensity.symbol)
                .appFont(.title2)
            Text(L10n.intensityName(intensity))
                .appFont(.caption, weight: .medium)
        }
        .foregroundStyle(intensity.tint)
        .frame(width: 84)
        .padding(.vertical, 8)
        .background(intensity.tint.opacity(0.12), in: .rect(cornerRadius: 8))
    }
}

struct TargetChip: View {
    let target: ScanTarget

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: target.isPrivate ? "house" : "globe")
                .appFont(.caption2)
            Text(target.raw)
                .appFont(.caption, design: .monospaced)
            if let count = target.addressCount, count > 1 {
                Text("×\(count)")
                    .appFont(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background((target.isPrivate ? Color.secondary : Color.orange).opacity(0.15),
                    in: .capsule)
    }
}

/// A network the Mac is attached to, offered as a starting point. Kept separate
/// from `TargetChip` on purpose: that one states what will be scanned, this one
/// is a control. The two rows sit next to each other and must not converge.
struct SuggestionChip: View {
    let suggestion: NetworkSuggestion
    let displayName: String
    let isSelected: Bool
    let action: () -> Void

    private var tint: Color {
        if isSelected { return .accentColor }
        // Same colour language as TargetChip: a routable address reads as a
        // warning even before the policy engine refuses it.
        return suggestion.target.isPrivate ? .secondary : .orange
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Image(systemName: isSelected ? "checkmark" : icon)
                    .appFont(.caption2)
                Text(displayName)
                    .appFont(.caption)
                Text(suggestion.target.raw)
                    .appFont(.caption, design: .monospaced)
                if let count = suggestion.target.addressCount, count > 1 {
                    Text("×\(count)")
                        .appFont(.caption2)
                        .foregroundStyle(.secondary)
                }
                if suggestion.isNarrowed {
                    Image(systemName: "arrow.down.right.and.arrow.up.left")
                        .appFont(.caption2)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(tint.opacity(isSelected ? 0.22 : 0.15), in: .capsule)
            .foregroundStyle(isSelected ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.primary))
        }
        .buttonStyle(.plain)
        .contentShape(.capsule)
        .help(tooltip)
        .accessibilityLabel(L10n.t(isSelected ? "suggestions.remove" : "suggestions.add",
                                   suggestion.target.raw))
    }

    private var icon: String {
        switch suggestion.kind {
        case .gateway: return "wifi.router"
        case .network: return displayName.localizedCaseInsensitiveContains("wi-fi") ? "wifi" : "network"
        }
    }

    private var tooltip: String {
        if suggestion.isNarrowed, let prefix = suggestion.originalPrefix {
            return L10n.t("suggestions.narrowed.help", prefix)
        }
        if !suggestion.target.isPrivate {
            return L10n.t("suggestions.public")
        }
        return L10n.t(isSelected ? "suggestions.remove" : "suggestions.add", suggestion.target.raw)
    }
}

struct ProfileRow: View {
    let profile: ScanProfile
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
                .foregroundStyle(isSelected ? Color.accentColor : Color.secondary)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(L10n.profileName(profile))
                        .appFont(.body, weight: isSelected ? .semibold : .regular)
                    if profile.requiresRoot {
                        Label("root", systemImage: "lock.fill")
                            .appFont(.caption2)
                            .labelStyle(.titleAndIcon)
                            .foregroundStyle(.orange)
                    }
                    if !profile.isBuiltIn {
                        Text(L10n.t("profiles.custom"))
                            .appFont(.caption2)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(.quaternary, in: .capsule)
                    }
                }
                Text(L10n.profileDetail(profile))
                    .appFont(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(L10n.intensityName(profile.intensity))
                .appFont(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 3)
    }
}

/// Wraps its children onto as many lines as needed — used for target chips.
struct FlowRow: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x + size.width > maxWidth, x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: maxWidth == .infinity ? x : maxWidth, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize,
                       subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX, x > bounds.minX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            view.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}

struct StatusPill: View {
    let status: ScanRunStatus

    var body: some View {
        Text(L10n.t("status.\(status.rawValue)"))
            .appFont(.caption2, weight: .medium)
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(color.opacity(0.18), in: .capsule)
            .foregroundStyle(color)
    }

    private var color: Color {
        switch status {
        case .running: return .blue
        case .completed: return .green
        case .failed: return .red
        case .cancelled: return .orange
        }
    }
}

extension DateFormatter {
    static let runStamp: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        // Short time, not medium: seconds pushed the history column past its
        // width and left every row ending in an ellipsis.
        formatter.timeStyle = .short
        return formatter
    }()
}

/// Fills exactly the space it is offered and never lets its content's own size
/// leak back up to the split view.
///
/// NavigationSplitView sizes the window from what each column reports, and it
/// asks with extreme proposals — near-zero widths, unbounded heights. One view
/// that answers those literally (wrapping text pinned with `fixedSize`, an
/// HSplitView, a row of fixed-width controls) used to grow the whole split past
/// the window, which then centred it: both columns slid off the top and bottom,
/// taking the toolbar-adjacent controls with them. Every detail route is
/// wrapped in this, so a route can misbehave only inside its own pane.
struct PaneFrame: Layout {
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        // Unspecified dimensions get a neutral answer instead of the child's
        // ideal, which is exactly the number that must not reach the window.
        proposal.replacingUnspecifiedDimensions(by: .zero)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize,
                       subviews: Subviews, cache: inout ()) {
        for view in subviews {
            view.place(at: bounds.origin, anchor: .topLeading, proposal: ProposedViewSize(bounds.size))
        }
    }
}

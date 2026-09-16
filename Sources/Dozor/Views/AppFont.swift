import SwiftUI
import AppKit
import os

/// Text scaling for the whole window.
///
/// macOS has no Dynamic Type: measuring the same view at every `DynamicTypeSize`
/// step produced an identical 171×31 image, so that modifier scales nothing here.
/// Instead each text style is resolved to the size the system actually uses and
/// multiplied by the current step, which keeps the app's typographic hierarchy
/// intact and lets layout reflow rather than blur the way a zoom transform does.
private struct TextScaleKey: EnvironmentKey {
    static let defaultValue: Double = 1.0
}

extension EnvironmentValues {
    var textScale: Double {
        get { self[TextScaleKey.self] }
        set { self[TextScaleKey.self] = newValue }
    }
}

extension View {
    /// Use instead of `.font(...)` so the text takes part in scaling.
    func appFont(_ style: Font.TextStyle,
                 design: Font.Design = .default,
                 weight: Font.Weight? = nil,
                 monospacedDigit: Bool = false) -> some View {
        modifier(AppFontModifier(style: style, design: design,
                                 weight: weight, monospacedDigit: monospacedDigit))
    }
}

struct AppFontModifier: ViewModifier {
    @Environment(\.textScale) private var scale

    let style: Font.TextStyle
    let design: Font.Design
    let weight: Font.Weight?
    let monospacedDigit: Bool

    func body(content: Content) -> some View {
        content.font(resolved)
    }

    private var resolved: Font {
        // At 100 % use the semantic style itself: it carries line spacing that a
        // plain point size does not, so the default appearance stays exactly as
        // designed rather than a pixel or two tighter per line.
        var font: Font
        if scale == 1.0 {
            font = .system(style, design: design)
            if let weight { font = font.weight(weight) }
        } else {
            font = .system(size: AppFontMetrics.baseSize(for: style) * scale,
                           weight: weight ?? AppFontMetrics.defaultWeight(for: style),
                           design: design)
        }
        if monospacedDigit { font = font.monospacedDigit() }
        return font
    }
}

enum AppFontMetrics {
    /// Asks AppKit for the size the system uses for each style, so the scale of
    /// 1.0 is indistinguishable from plain `.font(.caption)` and friends.
    static func baseSize(for style: Font.TextStyle) -> Double {
        if let cached = cache.withLock({ $0[style] }) { return cached }
        let size = NSFont.preferredFont(forTextStyle: nsStyle(for: style)).pointSize
        cache.withLock { $0[style] = size }
        return size
    }

    /// `.headline` is semibold in the system's own definition; the rest are
    /// regular unless a call site says otherwise.
    static func defaultWeight(for style: Font.TextStyle) -> Font.Weight {
        style == .headline ? .semibold : .regular
    }

    private static let cache = OSAllocatedUnfairLock(initialState: [Font.TextStyle: Double]())

    private static func nsStyle(for style: Font.TextStyle) -> NSFont.TextStyle {
        switch style {
        case .largeTitle: return .largeTitle
        case .title: return .title1
        case .title2: return .title2
        case .title3: return .title3
        case .headline: return .headline
        case .subheadline: return .subheadline
        case .body: return .body
        case .callout: return .callout
        case .footnote: return .footnote
        case .caption: return .caption1
        case .caption2: return .caption2
        @unknown default: return .body
        }
    }
}


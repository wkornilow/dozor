import SwiftUI
import AppKit

/// ⌘+ requires Shift on most layouts, so the menu item alone leaves the bare
/// ⌘= key — what people actually press — doing nothing. A local event monitor
/// covers it without putting a hidden button in the view tree: an empty-label
/// Button inside `.background` was tried first and broke the subtree it was in.
@MainActor
enum ZoomShortcut {
    private static var monitor: Any?

    static func install(zoomIn: @escaping @MainActor () -> Void) {
        guard monitor == nil else { return }
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            guard event.modifierFlags.intersection(.deviceIndependentFlagsMask) == .command,
                  event.charactersIgnoringModifiers == "="
            else { return event }
            zoomIn()
            return nil   // swallow it, so the key does not also beep
        }
    }
}

/// The steps the View menu walks through. Multipliers rather than
/// `DynamicTypeSize` values: macOS ignores Dynamic Type, so the app resolves
/// each text style to the system's own size and scales it itself (`appFont`).
enum TextScale {

    static let steps: [Double] = [0.8, 0.9, 1.0, 1.15, 1.3, 1.5, 1.75, 2.0]

    /// 1.0 — a fresh install looks exactly like every other Mac app.
    static let defaultIndex = 2

    static func clamp(_ index: Int) -> Int {
        min(max(index, 0), steps.count - 1)
    }

    static func scale(at index: Int) -> Double {
        steps[clamp(index)]
    }

    /// "100 %", "130 %" … shown on the reset item so the current step is
    /// readable without measuring anything on screen.
    static func percentLabel(at index: Int) -> String {
        "\(Int((scale(at: index) * 100).rounded())) %"
    }
}

import SwiftUI
import AppKit
import DozorKit

enum Pasteboard {
    /// Replaces the clipboard with plain text. Declaring the type first is
    /// required: without `clearContents` the old contents can survive.
    static func copy(_ text: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
    }
}

/// Copy actions shared by the host list and the host detail pane, so both
/// offer the same items in the same order.
struct HostCopyMenu: View {
    let host: HostResult

    var body: some View {
        Button(L10n.t("results.copy.ip")) { Pasteboard.copy(host.address) }
        if let mac = host.mac {
            Button(L10n.t("results.copy.mac")) { Pasteboard.copy(mac) }
        }
        if let name = host.bestName {
            Button(L10n.t("results.copy.name")) { Pasteboard.copy(name) }
        }
        Divider()
        Button(L10n.t("results.copy.summary")) { Pasteboard.copy(host.tabSeparatedSummary) }
    }
}

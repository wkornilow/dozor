import Foundation
import Network
import Observation
import DozorKit

/// Keeps the scan screen's suggested ranges in step with whatever the Mac is
/// attached to. Reading the interface list is a cheap, read-only local call, so
/// the model simply re-reads it when the network path changes: switching Wi-Fi
/// networks or plugging in Ethernet updates the chips without reopening the
/// window.
///
/// It only ever replaces `suggestions`. It never touches what the user has typed
/// into the targets field — a range that disappears from the network stays in
/// the field, it just stops being offered.
@MainActor
@Observable
final class NetworkSuggestionsModel {

    private(set) var suggestions: [NetworkSuggestion] = []
    /// False until the first read completes, so the UI can tell "nothing found"
    /// apart from "not looked yet" and avoid flashing an empty-state caption.
    private(set) var hasProbed = false

    @ObservationIgnored private var monitor: NWPathMonitor?
    @ObservationIgnored private var pendingRefresh: Task<Void, Never>?
    @ObservationIgnored private let queue = DispatchQueue(label: "dev.dozor.networkmonitor")

    func startMonitoring() {
        refresh()
        guard monitor == nil else { return }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] _ in
            Task { @MainActor in self?.scheduleRefresh() }
        }
        monitor.start(queue: queue)
        self.monitor = monitor
    }

    func stopMonitoring() {
        pendingRefresh?.cancel()
        pendingRefresh = nil
        monitor?.cancel()
        monitor = nil
    }

    /// A path change arrives before the new lease is fully applied, and it
    /// arrives several times while an interface settles. Wait for the flapping
    /// to stop, then read again a little later to catch the finished DHCP.
    private func scheduleRefresh() {
        pendingRefresh?.cancel()
        pendingRefresh = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(400))
            guard !Task.isCancelled else { return }
            self?.refresh()
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { return }
            self?.refresh()
        }
    }

    func refresh() {
        let updated = LocalNetworks.currentSuggestions()
        hasProbed = true
        // Assign only on a real change: a burst of path callbacks would
        // otherwise rebuild the chip row several times over.
        guard updated != suggestions else { return }
        suggestions = updated
    }
}

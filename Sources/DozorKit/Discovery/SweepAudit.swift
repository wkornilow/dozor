import Foundation

public struct AuditDraft: Hashable, Sendable {
    public let action: AuditEntry.Action
    public let detail: String

    public init(action: AuditEntry.Action, detail: String) {
        self.action = action
        self.detail = detail
    }
}

/// Keeps automatic sweeping out of the audit log without hiding it.
///
/// The log is append-only and never truncated, and `readAll` shows the last few
/// hundred lines. A thirty-second refresh would write nearly three thousand
/// entries a day and bury every record the log exists to keep. So a person
/// pressing Refresh is always logged, an automatic session is logged once at
/// each end plus a rolling summary, and anything unusual breaks the silence
/// immediately — novelty is exactly what a reader of the log is looking for.
public struct SweepAuditCoalescer: Sendable {

    public let summaryInterval: TimeInterval

    private var sessionStarted: Date?
    private var lastSummary: Date?
    private var sweepsSinceSummary = 0
    private var packetsSinceSummary = 0
    private var knownAddresses: Set<String> = []

    public init(summaryInterval: TimeInterval = 900) {
        self.summaryInterval = summaryInterval
    }

    /// Call when automatic refreshing begins.
    public mutating func sessionBegan(scopeCIDR: String, interval: TimeInterval,
                                      at now: Date) -> AuditDraft {
        sessionStarted = now
        lastSummary = now
        sweepsSinceSummary = 0
        packetsSinceSummary = 0
        return AuditDraft(action: .sweepStarted,
                          detail: "auto-refresh every \(Int(interval)) s on \(scopeCIDR)")
    }

    /// Call after each sweep. Returns an entry only when one is warranted.
    public mutating func note(_ summary: SweepSummary,
                              addresses: Set<String>,
                              manual: Bool,
                              at now: Date) -> AuditDraft? {
        let newcomers = addresses.subtracting(knownAddresses)
        knownAddresses.formUnion(addresses)

        // A person pressed a button: that is what an audit log is for.
        if manual {
            return AuditDraft(action: .sweepFinished,
                              detail: "manual sweep of \(summary.scopeCIDR): "
                                    + "\(summary.present) up of \(summary.probed) probed")
        }

        sweepsSinceSummary += 1
        packetsSinceSummary += summary.packetsSent

        // Novelty and trouble are never coalesced away.
        if !summary.warnings.isEmpty {
            return AuditDraft(action: .sweepFinished,
                              detail: "\(summary.scopeCIDR): "
                                    + summary.warnings.map(\.rawValue).joined(separator: ", "))
        }
        if !newcomers.isEmpty, sessionStarted != nil {
            return AuditDraft(action: .sweepFinished,
                              detail: "\(summary.scopeCIDR): new host(s) "
                                    + newcomers.sorted().prefix(5).joined(separator: ", "))
        }

        guard let last = lastSummary, now.timeIntervalSince(last) >= summaryInterval else {
            return nil
        }
        let draft = AuditDraft(action: .sweepFinished,
                               detail: "\(summary.scopeCIDR): \(sweepsSinceSummary) sweeps, "
                                     + "\(packetsSinceSummary) packets, \(summary.present) up")
        lastSummary = now
        sweepsSinceSummary = 0
        packetsSinceSummary = 0
        return draft
    }

    /// Call when automatic refreshing stops. Always emits.
    public mutating func sessionEnded(scopeCIDR: String, at now: Date) -> AuditDraft? {
        guard let started = sessionStarted else { return nil }
        let minutes = Int(now.timeIntervalSince(started) / 60)
        sessionStarted = nil
        return AuditDraft(action: .sweepFinished,
                          detail: "auto-refresh stopped after \(minutes) min on \(scopeCIDR)")
    }
}

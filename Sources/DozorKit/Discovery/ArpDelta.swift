import Foundation

/// What changed in the kernel's ARP table across one sweep.
///
/// The evidence a sweep produces is the *difference* between a snapshot taken
/// before the first probe and one taken after the last, not the final table:
/// entries linger for twenty minutes, so the final table alone cannot tell a
/// host that just answered from one that answered a quarter of an hour ago.
public struct ArpDelta: Hashable, Sendable {

    /// Absent before, present after — something answered our probe.
    public let appeared: [String: String]
    /// A different MAC now answers for the same address: a different device.
    public let changed: [String: MacChange]
    /// Same MAC before and after. Weak evidence: the entry may predate us.
    public let persisted: [String: String]
    /// Present before, gone after. Says nothing useful; kept for diagnosis.
    public let vanished: [String: String]

    public struct MacChange: Hashable, Sendable {
        public let old: String
        public let new: String
        public init(old: String, new: String) {
            self.old = old
            self.new = new
        }
    }

    public init(appeared: [String: String], changed: [String: MacChange],
                persisted: [String: String], vanished: [String: String]) {
        self.appeared = appeared
        self.changed = changed
        self.persisted = persisted
        self.vanished = vanished
    }

    public static func between(before: [String: String],
                               after: [String: String]) -> ArpDelta {
        var appeared: [String: String] = [:]
        var changed: [String: MacChange] = [:]
        var persisted: [String: String] = [:]
        var vanished: [String: String] = [:]

        for (address, mac) in after {
            guard let previous = before[address] else {
                appeared[address] = mac
                continue
            }
            if previous == mac {
                persisted[address] = mac
            } else {
                changed[address] = MacChange(old: previous, new: mac)
            }
        }
        for (address, mac) in before where after[address] == nil {
            vanished[address] = mac
        }
        return ArpDelta(appeared: appeared, changed: changed,
                        persisted: persisted, vanished: vanished)
    }

    /// The evidence this delta contributes for one address.
    public func evidence(for address: String) -> Set<HostEvidence> {
        if appeared[address] != nil || changed[address] != nil { return [.arpFresh] }
        if persisted[address] != nil { return [.arpPrior] }
        return []
    }

    /// The MAC now answering for an address, whatever the reason.
    public func mac(for address: String) -> String? {
        appeared[address] ?? changed[address]?.new ?? persisted[address]
    }
}

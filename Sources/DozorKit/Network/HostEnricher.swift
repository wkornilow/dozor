import Foundation

/// Fills in what an unprivileged scan cannot see: the MAC address behind each
/// IP, the organisation that registered it, and a name for hosts Nmap could not
/// resolve.
///
/// Nothing here sends a packet of its own. The MAC comes from the ARP cache the
/// scan itself warmed up, and the name comes from the resolver the machine is
/// already configured to use.
public enum HostEnricher {

    /// Instant, offline pass: MAC address and vendor.
    ///
    /// A MAC that Nmap reported itself is left alone — it saw the wire; this is
    /// only for the gaps.
    public static func applyLinkLayer(
        to result: ScanResult,
        arp: [String: String],
        vendors: MacVendorDatabase?
    ) -> ScanResult {
        guard !arp.isEmpty || vendors != nil else { return result }
        var updated = result

        for index in updated.hosts.indices {
            let host = updated.hosts[index]
            if host.mac == nil, let mac = arp[host.address] {
                updated.hosts[index].mac = mac
                updated.hosts[index].macSource = .arpCache
            } else if host.mac != nil, host.macSource == nil {
                updated.hosts[index].macSource = .scan
            }
            if let mac = updated.hosts[index].mac,
               updated.hosts[index].vendor == nil || updated.hosts[index].vendor?.isEmpty == true {
                updated.hosts[index].vendor = vendors?.vendor(for: mac)
            }
        }
        return updated
    }

    /// Names the hosts Nmap left unnamed, through the system resolver.
    /// Only live hosts are looked up, so a sparse subnet does not queue hundreds
    /// of doomed lookups.
    public static func applyNames(to result: ScanResult, concurrency: Int = 8) async -> ScanResult {
        let pending = result.hosts
            .filter { $0.state == "up" && $0.hostnames.isEmpty && $0.reverseName == nil }
            .map(\.address)
        guard !pending.isEmpty else { return result }

        let names = await ReverseDNS.hostnames(for: pending, concurrency: concurrency)
        guard !names.isEmpty else { return result }

        var updated = result
        for index in updated.hosts.indices {
            if let name = names[updated.hosts[index].address] {
                updated.hosts[index].reverseName = name
            }
        }
        return updated
    }

    /// Both passes: the instant one first so the UI can show MAC addresses
    /// immediately, then the resolver.
    public static func enrich(
        _ result: ScanResult,
        arp: [String: String] = ArpTable.current(),
        vendors: MacVendorDatabase?,
        resolveNames: Bool = true,
        concurrency: Int = 8
    ) async -> ScanResult {
        let linkLayer = applyLinkLayer(to: result, arp: arp, vendors: vendors)
        guard resolveNames else { return linkLayer }
        return await applyNames(to: linkLayer, concurrency: concurrency)
    }
}

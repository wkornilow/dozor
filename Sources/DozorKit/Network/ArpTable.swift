import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// The kernel's ARP cache: which MAC address answers for which IPv4 address on
/// the local segment.
///
/// This matters because an unprivileged Nmap scan never reports a MAC address —
/// ARP needs raw sockets, so `-sT` cannot see one. The operating system already
/// knows, though, and a connect scan talks to every live host on the segment, so
/// by the time a scan finishes the cache holds an entry for each host that
/// answered. Reading it costs one `sysctl` call: no traffic, no privileges, no
/// subprocess.
///
/// The cache only covers the local link. A host behind a router has the router's
/// MAC or none at all, which is why results label the source rather than
/// presenting it as something the scan discovered.
public enum ArpTable {

    #if canImport(Darwin)
    /// IPv4 address → lower-case colon-separated MAC.
    public static func current() -> [String: String] {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO]
        var size = 0
        guard sysctl(&mib, u_int(mib.count), nil, &size, nil, 0) == 0, size > 0 else { return [:] }

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, u_int(mib.count), &buffer, &size, nil, 0) == 0 else { return [:] }

        return buffer.withUnsafeBytes { raw -> [String: String] in
            guard let base = raw.baseAddress else { return [:] }
            var entries: [String: String] = [:]
            var offset = 0

            while offset + MemoryLayout<rt_msghdr>.stride <= size {
                let message = base.advanced(by: offset).assumingMemoryBound(to: rt_msghdr.self)
                let length = Int(message.pointee.rtm_msglen)
                guard length >= MemoryLayout<rt_msghdr>.stride, offset + length <= size else { break }
                defer { offset += length }

                // The route message is followed by the destination address and
                // then the link-layer address, each padded to a 4-byte boundary.
                let destination = UnsafeRawPointer(message).advanced(by: MemoryLayout<rt_msghdr>.stride)
                let socketAddress = destination.assumingMemoryBound(to: sockaddr_in.self)
                guard socketAddress.pointee.sin_family == UInt8(AF_INET) else { continue }

                let linkOffset = padded(Int(destination.assumingMemoryBound(to: sockaddr.self).pointee.sa_len))
                guard MemoryLayout<rt_msghdr>.stride + linkOffset + MemoryLayout<sockaddr_dl>.stride <= length
                else { continue }

                let link = destination.advanced(by: linkOffset).assumingMemoryBound(to: sockaddr_dl.self)
                guard link.pointee.sdl_family == UInt8(AF_LINK), link.pointee.sdl_alen == 6 else { continue }

                // LLADDR: sdl_data starts at a fixed offset, after the interface
                // name of sdl_nlen bytes.
                let macStart = sdlDataOffset + Int(link.pointee.sdl_nlen)
                let macBytes = UnsafeRawPointer(link).advanced(by: macStart)
                    .assumingMemoryBound(to: UInt8.self)
                let mac = (0..<6).map { String(format: "%02x", macBytes[$0]) }.joined(separator: ":")

                var address = socketAddress.pointee.sin_addr
                guard let text = dotted(&address) else { continue }
                // Broadcast and multicast rows are routing artefacts, not hosts.
                guard !isReserved(mac: mac) else { continue }
                entries[text] = mac
            }
            return entries
        }
    }

    /// Route messages pad each address to a four-byte boundary; a zero length
    /// still advances by one slot.
    private static func padded(_ length: Int) -> Int {
        length == 0 ? MemoryLayout<UInt32>.size : (length + MemoryLayout<UInt32>.size - 1)
            & ~(MemoryLayout<UInt32>.size - 1)
    }

    /// Byte offset of `sdl_data` inside `sockaddr_dl`: len, family, index (2),
    /// type, nlen, alen, slen.
    private static let sdlDataOffset = 8

    private static func dotted(_ address: inout in_addr) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
        return String(cString: buffer)
    }
    #else
    public static func current() -> [String: String] { [:] }
    #endif

    /// Broadcast and IPv4-multicast link addresses describe no real host.
    public static func isReserved(mac: String) -> Bool {
        if mac == "ff:ff:ff:ff:ff:ff" { return true }
        return mac.hasPrefix("01:00:5e")
    }

    /// A MAC with the locally-administered bit set is not burned in by a vendor:
    /// it is a randomised or virtual address, so an OUI lookup would be
    /// misleading rather than merely empty.
    public static func isLocallyAdministered(mac: String) -> Bool {
        guard let first = mac.split(separator: ":").first,
              let value = UInt8(first, radix: 16) else { return false }
        return value & 0x02 != 0
    }
}

import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// The magic packet, and the one place that decides whether a host can be woken.
public enum WakeOnLan {

    /// Six `0xFF` bytes followed by the six MAC bytes repeated sixteen times.
    ///
    /// Returns nil — rather than a packet nobody will answer — when the address
    /// cannot belong to a wakeable NIC: malformed, broadcast, multicast, or
    /// locally administered. A phone's randomised address is not a NIC that
    /// wakes on LAN, so the button must not appear for it at all.
    public static func magicPacket(for mac: String) -> Data? {
        guard let bytes = macBytes(mac) else { return nil }
        guard !ArpTable.isReserved(mac: normalised(mac)) else { return nil }
        guard !ArpTable.isLocallyAdministered(mac: normalised(mac)) else { return nil }

        var packet = Data(repeating: 0xFF, count: 6)
        for _ in 0..<16 { packet.append(contentsOf: bytes) }
        return packet
    }

    /// Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` and `aabbccddeeff`.
    static func macBytes(_ mac: String) -> [UInt8]? {
        // Only hex digits and the two conventional separators may appear, so a
        // string like "zz:..." or "1.2.3.4" cannot slip through by having its
        // punctuation filtered away.
        guard mac.allSatisfy({ $0.isHexDigit || $0 == ":" || $0 == "-" }) else { return nil }
        let digits = mac.filter(\.isHexDigit)
        guard digits.count == 12 else { return nil }
        var bytes: [UInt8] = []
        var index = digits.startIndex
        while index < digits.endIndex {
            let next = digits.index(index, offsetBy: 2)
            guard let byte = UInt8(digits[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }

    static func normalised(_ mac: String) -> String {
        guard let bytes = macBytes(mac) else { return mac }
        return bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    #if canImport(Darwin)
    /// Sent to the subnet's own broadcast address rather than 255.255.255.255,
    /// so a multi-homed Mac cannot spray the packet out of the wrong interface.
    /// Three times, because a sleeping NIC's pattern matcher can miss one.
    public static func send(to mac: String, broadcast: String,
                            interfaceIndex: UInt32, port: UInt16 = 9) -> Bool {
        guard let packet = magicPacket(for: mac) else { return false }
        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }

        var enabled: Int32 = 1
        setsockopt(descriptor, SOL_SOCKET, SO_BROADCAST, &enabled, socklen_t(MemoryLayout<Int32>.size))
        if interfaceIndex > 0 {
            var index = interfaceIndex
            setsockopt(descriptor, IPPROTO_IP, IP_BOUND_IF, &index,
                       socklen_t(MemoryLayout<UInt32>.size))
        }

        var destination = sockaddr_in()
        destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destination.sin_family = sa_family_t(AF_INET)
        destination.sin_port = port.bigEndian
        guard inet_pton(AF_INET, broadcast, &destination.sin_addr) == 1 else { return false }

        var sentAny = false
        for attempt in 0..<3 {
            let sent = packet.withUnsafeBytes { bytes in
                withUnsafePointer(to: &destination) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { target in
                        sendto(descriptor, bytes.baseAddress, bytes.count, 0,
                               target, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            if sent > 0 { sentAny = true }
            if attempt < 2 { usleep(100_000) }
        }
        return sentAny
    }
    #endif
}

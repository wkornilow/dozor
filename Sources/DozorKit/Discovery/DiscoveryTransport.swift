import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum DiscoveryTransportError: Error, Equatable, Sendable {
    /// The kernel refused more work: we are probing faster than the wire drains.
    case outOfBuffers
    /// Per-address, not fatal.
    case unreachable
    /// The OS refused the socket the local-network access sweep needs — either
    /// the person denied the "Local Network" prompt, or `Info.plist` is missing
    /// `NSLocalNetworkUsageDescription` so the prompt never had a chance to ask.
    /// Every subsequent probe in the sweep fails the same way, so this is worth
    /// telling apart from an ordinary unreachable host.
    case permissionDenied
    case other(Int32)
}

/// The only part of the sweep that touches a socket.
///
/// Keeping it behind three methods means every decision the sweeper makes can be
/// tested against scripted input with no packets at all.
public protocol DiscoveryTransport: Sendable {
    /// Fire and forget. Two jobs at once: the kernel must resolve the
    /// destination's link layer before it can put a frame on the wire, and the
    /// host itself may answer.
    func probe(address: String, interfaceIndex: UInt32) throws

    /// Addresses that have answered since the last call. Non-blocking.
    func drainReplies() -> Set<String>

    /// The kernel's ARP table right now.
    func arpSnapshot() -> [String: String]
}

#if canImport(Darwin)
/// Sends an ICMP echo request per address, over an unprivileged datagram socket.
///
/// Why echo rather than a UDP datagram: measuring a real sweep showed the flaw in
/// relying on the ARP table alone. On a Mac that has been on the network a while
/// every host is already cached, and `net.link.ether.inet.max_age` is 1200 — the
/// kernel reuses a completed entry for twenty minutes without ever putting a
/// request on the wire. The table therefore looked identical before and after
/// probing, and not one of 41 real hosts could be called "up". An echo reply is
/// direct evidence from the host itself, independent of the cache, and the echo
/// request still forces ARP for hosts that are not cached. One packet, both jobs.
///
/// Hosts that ignore ICMP are not lost: if they were uncached, the ARP entry
/// their reply created is still picked up by the before/after comparison.
public final class DarwinDiscoveryTransport: DiscoveryTransport, @unchecked Sendable {

    private let lock = NSLock()
    private var descriptor: Int32 = -1
    private var sequence: UInt16 = 0
    private let identifier: UInt16

    public init(identifier: UInt16 = UInt16.random(in: 1...UInt16.max)) {
        self.identifier = identifier
    }

    deinit {
        if descriptor >= 0 { close(descriptor) }
    }

    /// Opened on first use and kept for the sweep, so replies that arrive while
    /// later probes are still going out are not lost.
    private func socketDescriptor(interfaceIndex: UInt32) throws -> Int32 {
        if descriptor >= 0 { return descriptor }
        let created = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard created >= 0 else { throw Self.classify(errno) }

        // FIONBIO is not importable from Swift; set the flag on the descriptor.
        let flags = fcntl(created, F_GETFL, 0)
        _ = fcntl(created, F_SETFL, flags | O_NONBLOCK)
        if interfaceIndex > 0 {
            var index = interfaceIndex
            setsockopt(created, IPPROTO_IP, IP_BOUND_IF, &index,
                       socklen_t(MemoryLayout<UInt32>.size))
        }
        descriptor = created
        return created
    }

    public func probe(address: String, interfaceIndex: UInt32) throws {
        try lock.withLock {
            let fd = try socketDescriptor(interfaceIndex: interfaceIndex)
            sequence &+= 1
            let packet = Self.echoRequest(identifier: identifier, sequence: sequence)

            var destination = sockaddr_in()
            destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            destination.sin_family = sa_family_t(AF_INET)
            guard inet_pton(AF_INET, address, &destination.sin_addr) == 1 else {
                throw DiscoveryTransportError.other(EINVAL)
            }

            let sent = packet.withUnsafeBytes { bytes in
                withUnsafePointer(to: &destination) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { target in
                        sendto(fd, bytes.baseAddress, bytes.count, Int32(MSG_DONTWAIT),
                               target, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            guard sent >= 0 else { throw Self.classify(errno) }
        }
    }

    /// Replies are matched on **source address**, not on the identifier: Darwin
    /// rewrites the id field of an unprivileged echo request to the socket's own
    /// port, so the value we put in is not the value that comes back.
    public func drainReplies() -> Set<String> {
        lock.withLock {
            guard descriptor >= 0 else { return [] }
            var answered = Set<String>()
            var buffer = [UInt8](repeating: 0, count: 256)

            while true {
                var source = sockaddr_in()
                var length = socklen_t(MemoryLayout<sockaddr_in>.size)
                let received = withUnsafeMutablePointer(to: &source) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { target in
                        recvfrom(descriptor, &buffer, buffer.count, 0, target, &length)
                    }
                }
                guard received > 0 else { break }

                var address = source.sin_addr
                var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &address, &text, socklen_t(INET_ADDRSTRLEN)) != nil {
                    answered.insert(String(cString: text))
                }
            }
            return answered
        }
    }

    public func arpSnapshot() -> [String: String] { ArpTable.current() }

    /// Type 8, code 0, checksum over the whole message.
    public static func echoRequest(identifier: UInt16, sequence: UInt16) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 16)
        packet[0] = 8
        packet[4] = UInt8(identifier >> 8)
        packet[5] = UInt8(identifier & 0xFF)
        packet[6] = UInt8(sequence >> 8)
        packet[7] = UInt8(sequence & 0xFF)
        let checksum = internetChecksum(packet)
        packet[2] = UInt8(checksum >> 8)
        packet[3] = UInt8(checksum & 0xFF)
        return packet
    }

    /// One's-complement sum of 16-bit words, as RFC 1071 defines it.
    public static func internetChecksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < bytes.count {
            sum &+= (UInt32(bytes[index]) << 8) | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count { sum &+= UInt32(bytes[index]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) &+ (sum >> 16) }
        return ~UInt16(sum & 0xFFFF)
    }

    public static func classify(_ code: Int32) -> DiscoveryTransportError {
        switch code {
        case ENOBUFS: return .outOfBuffers
        case EHOSTDOWN, EHOSTUNREACH, ENETDOWN, ENETUNREACH: return .unreachable
        case EPERM, EACCES: return .permissionDenied
        default: return .other(code)
        }
    }
}
#endif

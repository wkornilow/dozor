import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum TCPProbeOutcome: String, Codable, Hashable, Sendable {
    case open        // the connection was accepted
    case refused     // RST: the host is alive, nothing is listening
    case timedOut    // no answer within the budget
    case unreachable
    case error
}

/// Behind a protocol for the same reason as the discovery transport: everything
/// that decides anything stays testable without a network.
public protocol PortProbing: Sendable {
    func probe(address: String, ports: [Int], timeout: Duration,
               interfaceIndex: UInt32) async -> [Int: TCPProbeOutcome]
}

/// What a host offers, as far as a handful of connects can tell.
///
/// This is not a port scan and must never be presented as one — the app already
/// has a port scanner with a confirmation sheet in front of it. The set is fixed
/// and small because its only job is to decide which buttons a row shows.
public struct HostCapabilities: Codable, Hashable, Sendable {
    public static let probedPorts = [22, 80, 443, 445, 3389, 5900, 8080]

    public let web: Int?          // the first plain-HTTP port that answered
    public let secureWeb: Bool
    public let ssh: Bool
    public let fileSharing: Bool
    public let screenSharing: Bool
    /// Recorded because it identifies a Windows machine, but no action hangs off
    /// it: no RDP client is guaranteed to be installed, and a button that opens
    /// nothing is worse than no button.
    public let remoteDesktop: Bool
    public let wakeable: Bool

    public static let none = HostCapabilities(web: nil, secureWeb: false, ssh: false,
                                              fileSharing: false, screenSharing: false,
                                              remoteDesktop: false, wakeable: false)

    public init(web: Int?, secureWeb: Bool, ssh: Bool, fileSharing: Bool,
                screenSharing: Bool, remoteDesktop: Bool, wakeable: Bool) {
        self.web = web
        self.secureWeb = secureWeb
        self.ssh = ssh
        self.fileSharing = fileSharing
        self.screenSharing = screenSharing
        self.remoteDesktop = remoteDesktop
        self.wakeable = wakeable
    }

    public static func from(ports: [Int: TCPProbeOutcome], mac: String?) -> HostCapabilities {
        func isOpen(_ port: Int) -> Bool { ports[port] == .open }
        return HostCapabilities(
            web: [80, 8080].first(where: isOpen),
            secureWeb: isOpen(443),
            ssh: isOpen(22),
            fileSharing: isOpen(445),
            screenSharing: isOpen(5900),
            remoteDesktop: isOpen(3389),
            // A randomised address is not a wakeable NIC.
            wakeable: mac.map { WakeOnLan.magicPacket(for: $0) != nil } ?? false
        )
    }

    public var openPorts: [Int] {
        var ports: [Int] = []
        if ssh { ports.append(22) }
        if let web { ports.append(web) }
        if secureWeb { ports.append(443) }
        if fileSharing { ports.append(445) }
        if remoteDesktop { ports.append(3389) }
        if screenSharing { ports.append(5900) }
        return ports.sorted()
    }
}

#if canImport(Darwin)
public struct DarwinPortProber: PortProbing {

    public let concurrency: Int

    public init(concurrency: Int = 16) {
        // An app launched from Finder can get a much lower descriptor limit than
        // a shell. Running out mid-sweep produces a baffling failure, so clamp.
        var limits = rlimit()
        let soft = getrlimit(RLIMIT_NOFILE, &limits) == 0 ? Int(limits.rlim_cur) : 256
        self.concurrency = max(1, min(concurrency, (soft - 64) / 2))
    }

    public func probe(address: String, ports: [Int], timeout: Duration,
                      interfaceIndex: UInt32) async -> [Int: TCPProbeOutcome] {
        await withTaskGroup(of: (Int, TCPProbeOutcome).self) { group in
            var results: [Int: TCPProbeOutcome] = [:]
            var index = 0

            func addNext() {
                guard index < ports.count else { return }
                let port = ports[index]
                index += 1
                group.addTask {
                    (port, await Task.detached(priority: .utility) {
                        Self.connect(address: address, port: port, timeout: timeout,
                                     interfaceIndex: interfaceIndex)
                    }.value)
                }
            }

            for _ in 0..<min(concurrency, ports.count) { addNext() }
            while let (port, outcome) = await group.next() {
                results[port] = outcome
                addNext()
            }
            return results
        }
    }

    /// Non-blocking connect, then poll. Never writes a byte and never reads one:
    /// the answer is in whether the handshake completed.
    static func connect(address: String, port: Int, timeout: Duration,
                        interfaceIndex: UInt32) -> TCPProbeOutcome {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return .error }
        defer { close(descriptor) }

        let flags = fcntl(descriptor, F_GETFL, 0)
        _ = fcntl(descriptor, F_SETFL, flags | O_NONBLOCK)
        if interfaceIndex > 0 {
            var index = interfaceIndex
            setsockopt(descriptor, IPPROTO_IP, IP_BOUND_IF, &index,
                       socklen_t(MemoryLayout<UInt32>.size))
        }

        var destination = sockaddr_in()
        destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destination.sin_family = sa_family_t(AF_INET)
        destination.sin_port = UInt16(port).bigEndian
        guard inet_pton(AF_INET, address, &destination.sin_addr) == 1 else { return .error }

        let started = withUnsafePointer(to: &destination) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { target in
                Darwin.connect(descriptor, target, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if started == 0 { return .open }
        guard errno == EINPROGRESS else { return classify(errno) }

        var descriptorSet = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
        let milliseconds = Int32(timeout.components.seconds * 1000
                                 + timeout.components.attoseconds / 1_000_000_000_000_000)
        let ready = poll(&descriptorSet, 1, milliseconds)
        guard ready > 0 else { return ready == 0 ? .timedOut : .error }

        var failure: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &failure, &length)
        return failure == 0 ? .open : classify(failure)
    }

    static func classify(_ code: Int32) -> TCPProbeOutcome {
        switch code {
        case 0: return .open
        case ECONNREFUSED: return .refused
        case ETIMEDOUT: return .timedOut
        case EHOSTUNREACH, ENETUNREACH, EHOSTDOWN: return .unreachable
        default: return .error
        }
    }
}
#endif

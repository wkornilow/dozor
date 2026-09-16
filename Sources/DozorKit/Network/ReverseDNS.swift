import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Reverse name lookup through the system resolver.
///
/// Nmap runs its own parallel resolver, which never sees the multicast-DNS
/// names that most devices on a home or office LAN answer to. Asking the system
/// instead picks up `.local` names alongside ordinary PTR records.
public enum ReverseDNS {

    #if canImport(Darwin)
    /// Blocking: call this off the main thread. Returns nil when the address has
    /// no name, rather than echoing the address back.
    public static func hostname(for address: String) -> String? {
        var socketAddress = sockaddr_in()
        socketAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        socketAddress.sin_family = sa_family_t(AF_INET)
        guard inet_pton(AF_INET, address, &socketAddress.sin_addr) == 1 else { return nil }

        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status = withUnsafePointer(to: &socketAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                // NI_NAMEREQD: fail rather than hand back the numeric address.
                getnameinfo(sa, socklen_t(MemoryLayout<sockaddr_in>.size),
                            &buffer, socklen_t(buffer.count), nil, 0, NI_NAMEREQD)
            }
        }
        guard status == 0 else { return nil }
        let name = String(cString: buffer)
        return name.isEmpty || name == address ? nil : name
    }
    #else
    public static func hostname(for address: String) -> String? { nil }
    #endif

    /// Resolves many addresses with a bounded number of lookups in flight. Each
    /// lookup can sit on a slow resolver for seconds, so this is deliberately
    /// capped rather than fanned out over a whole subnet at once.
    public static func hostnames(for addresses: [String], concurrency: Int = 8) async -> [String: String] {
        guard !addresses.isEmpty else { return [:] }
        let limit = max(1, concurrency)

        return await withTaskGroup(of: (String, String?).self) { group in
            var results: [String: String] = [:]
            var index = 0

            func addNext() {
                guard index < addresses.count else { return }
                let address = addresses[index]
                index += 1
                group.addTask {
                    (address, await Task.detached(priority: .utility) {
                        hostname(for: address)
                    }.value)
                }
            }

            for _ in 0..<min(limit, addresses.count) { addNext() }
            while let (address, name) = await group.next() {
                if let name { results[address] = name }
                addNext()
            }
            return results
        }
    }
}

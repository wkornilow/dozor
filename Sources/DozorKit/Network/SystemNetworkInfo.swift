import Foundation
#if canImport(SystemConfiguration)
import SystemConfiguration
#endif

/// What the operating system knows about the current network beyond the raw
/// interface list: which interface carries the default route, where that route
/// points, and what the interfaces are called in the user's own language.
///
/// Guarded by `canImport` so `DozorKit` still builds where SystemConfiguration
/// does not exist; the caller then simply gets empty values and the UI falls
/// back to BSD interface names with no gateway suggestion.
public struct SystemNetworkInfo: Hashable, Sendable {
    public let router: String?
    public let primaryInterface: String?
    /// BSD name → localised name, e.g. "en0" → "Wi-Fi".
    public let displayNames: [String: String]

    public init(router: String? = nil, primaryInterface: String? = nil,
                displayNames: [String: String] = [:]) {
        self.router = router
        self.primaryInterface = primaryInterface
        self.displayNames = displayNames
    }

    public static let empty = SystemNetworkInfo()

    #if canImport(SystemConfiguration)
    /// Reads the live values. Every lookup degrades on its own: a missing
    /// router still leaves the interface names usable, and vice versa.
    public static func current() -> SystemNetworkInfo {
        SystemNetworkInfo(router: globalIPv4()?.router,
                          primaryInterface: globalIPv4()?.primaryInterface,
                          displayNames: localisedInterfaceNames())
    }

    private static func globalIPv4() -> (router: String?, primaryInterface: String?)? {
        guard let store = SCDynamicStoreCreate(nil, "dev.dozor.app" as CFString, nil, nil),
              let value = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString),
              let dictionary = value as? [String: Any]
        else { return nil }
        return (dictionary["Router"] as? String, dictionary["PrimaryInterface"] as? String)
    }

    private static func localisedInterfaceNames() -> [String: String] {
        guard let interfaces = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return [:] }
        var names: [String: String] = [:]
        for interface in interfaces {
            guard let bsdName = SCNetworkInterfaceGetBSDName(interface) as String?,
                  let displayName = SCNetworkInterfaceGetLocalizedDisplayName(interface) as String?
            else { continue }
            names[bsdName] = displayName
        }
        return names
    }
    #else
    public static func current() -> SystemNetworkInfo { .empty }
    #endif
}

extension LocalNetworks {
    /// Everything the scan screen needs, in one call: the live interface list
    /// enriched with the router and the interfaces' localised names.
    public static func currentSuggestions(info: SystemNetworkInfo = .current()) -> [NetworkSuggestion] {
        suggestions(from: currentInterfaces(),
                    gateway: info.router,
                    primaryInterface: info.primaryInterface,
                    displayNames: info.displayNames)
    }
}

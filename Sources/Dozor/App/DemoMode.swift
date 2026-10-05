import SwiftUI
import AppKit
import DozorKit

/// `DOZOR_DEMO=1` runs the app against an invented home network and scan
/// history, for screenshots and for trying the interface without Nmap traffic.
///
/// The demo is a closed box: data lives in a temporary directory
/// (`AppPaths.isDemo`), the network overview never sweeps, and suggested ranges
/// are fixed. Every address below sits in 192.168.50.0/24 and every name is made
/// up. A scan started by hand from the Scan screen still runs Nmap for real.
enum DemoMode {
    static var isActive: Bool { AppPaths.isDemo }

    private static let now = Date()

    // MARK: - Network overview

    static let scope = SweepScope(
        target: ScanTarget(raw: "192.168.50.0/24", kind: .cidr, addressCount: 256, isPrivate: true),
        interfaceName: "en0", interfaceIndex: 0,
        localAddress: "192.168.50.23", broadcastAddress: "192.168.50.255",
        prefix: 24, isNarrowed: false)

    static var summary: SweepSummary {
        SweepSummary(scopeCIDR: scope.target.raw, interfaceName: scope.interfaceName,
                     startedAt: now.addingTimeInterval(-34), finishedAt: now.addingTimeInterval(-31),
                     probed: 254, present: 11, stale: 1, packetsSent: 508,
                     backedOff: false, warnings: [])
    }

    static var rows: [NetworkHostRow] {
        func row(_ last: Int, _ name: String?, mac: String?, vendor: String?,
                 ports: [Int] = [], web: Int? = nil, https: Bool = false, ssh: Bool = false,
                 smb: Bool = false, vnc: Bool = false, rdp: Bool = false, wake: Bool = false,
                 missed: Int = 0, firstSeenDays: Double = 20,
                 gateway: Bool = false, isSelf: Bool = false) -> NetworkHostRow {
            let address = "192.168.50.\(last)"
            let seen = now.addingTimeInterval(missed == 0 ? -31 : -Double(missed) * 300)
            let open = ports.map { PortInfo(port: $0, proto: "tcp", state: "open") }
            return NetworkHostRow(
                host: HostResult(address: address, addressType: "ipv4", mac: mac, vendor: vendor,
                                 hostnames: name.map { [$0] } ?? [], state: missed == 0 ? "up" : "down",
                                 ports: open, macSource: mac == nil ? nil : .arpCache),
                firstSeen: now.addingTimeInterval(-firstSeenDays * 86_400),
                lastSeen: seen, lastProbed: seen,
                presence: HostPresence(level: missed == 0 ? .present : .stale,
                                       evidence: isSelf ? [.ownAddress] : [.arpFresh, .icmpReply]),
                missedSweeps: missed, isGateway: gateway, isSelf: isSelf,
                capabilities: HostCapabilities(web: web, secureWeb: https, ssh: ssh, fileSharing: smb,
                                               screenSharing: vnc, remoteDesktop: rdp, wakeable: wake))
        }
        return [
            row(1, "router.lan", mac: "D8:07:B6:4A:10:01", vendor: "TP-Link",
                ports: [80, 443], web: 80, https: true, gateway: true),
            row(4, "nas.local", mac: "00:11:32:9C:2E:51", vendor: "Synology",
                ports: [22, 80, 443, 445], web: 80, https: true, ssh: true, smb: true, wake: true),
            row(7, "printer.local", mac: "30:05:5C:71:A8:0E", vendor: "Brother",
                ports: [80, 443], web: 80, https: true),
            row(12, "homeassistant.local", mac: "DC:A6:32:5B:7F:20", vendor: "Raspberry Pi",
                ports: [22, 8080], web: 8080, ssh: true),
            row(15, "living-room-tv.local", mac: "A8:23:FE:13:4C:92", vendor: "LG Electronics"),
            row(19, "studio-mac.local", mac: "3C:22:FB:90:61:D4", vendor: "Apple",
                ports: [22, 445, 5900], ssh: true, smb: true, vnc: true, wake: true),
            row(23, "macbook.local", mac: "F0:2F:4B:11:9A:C3", vendor: "Apple", isSelf: true),
            row(31, "gaming-pc.local", mac: "04:42:1A:D9:33:7B", vendor: "ASUSTek",
                ports: [445, 3389], smb: true, rdp: true, wake: true, missed: 2),
            row(42, "iphone.local", mac: "6E:8B:21:C4:05:F7", vendor: nil, firstSeenDays: 3),
            row(57, "plug-kitchen", mac: "84:F3:EB:2D:61:0A", vendor: "Espressif"),
            row(60, "camera-door.local", mac: "BC:AD:28:E1:44:39", vendor: "Hikvision",
                ports: [80, 443], web: 80, https: true),
            row(88, nil, mac: "52:54:00:8E:3B:12", vendor: nil, firstSeenDays: 0.1),
        ]
    }

    static let suggestions: [NetworkSuggestion] = [
        NetworkSuggestion(kind: .network, target: scope.target, interfaceName: "en0",
                          displayName: "Wi-Fi"),
        NetworkSuggestion(kind: .gateway,
                          target: ScanTarget(raw: "192.168.50.1", kind: .ipv4, addressCount: 1, isPrivate: true),
                          interfaceName: "en0", displayName: "Router"),
    ]

    // MARK: - History

    static var history: [ScanRun] {
        func target(_ raw: String) -> ScanTarget {
            raw.contains("/")
                ? ScanTarget(raw: raw, kind: .cidr, addressCount: 256, isPrivate: true)
                : ScanTarget(raw: raw, kind: .ipv4, addressCount: 1, isPrivate: true)
        }
        func port(_ number: Int, _ service: String, _ product: String? = nil,
                  _ version: String? = nil) -> PortInfo {
            PortInfo(port: number, proto: "tcp", state: "open", reason: "syn-ack",
                     serviceName: service, product: product, version: version)
        }
        func host(_ last: Int, _ name: String, _ mac: String, _ vendor: String,
                  _ ports: [PortInfo], tags: [String] = []) -> HostResult {
            HostResult(address: "192.168.50.\(last)", addressType: "ipv4", mac: mac, vendor: vendor,
                       hostnames: [name], state: "up", ports: ports, tags: tags, macSource: .arpCache)
        }
        func run(_ profile: ScanProfile, _ targets: [String], hoursAgo: Double, seconds: Double,
                 hosts: [HostResult], status: ScanRunStatus = .completed) -> ScanRun {
            let started = now.addingTimeInterval(-hoursAgo * 3600)
            var arguments = profile.arguments + [profile.timing.flag, "--max-rate", "20000"]
            arguments += ["-oX", "<file>", "--"] + targets
            return ScanRun(
                profileName: L10n.profileName(profile), profileID: profile.id,
                targets: targets.map(target), arguments: arguments,
                startedAt: started, finishedAt: started.addingTimeInterval(seconds),
                status: status, author: "demo", exitCode: status == .completed ? 0 : nil,
                result: status == .completed
                    ? ScanResult(nmapVersion: "7.95", startedAt: started,
                                 finishedAt: started.addingTimeInterval(seconds),
                                 hosts: hosts, hostsUp: hosts.count, hostsDown: 256 - hosts.count)
                    : nil)
        }

        let router = host(1, "router.lan", "D8:07:B6:4A:10:01", "TP-Link",
                          [port(53, "domain", "dnsmasq", "2.90"), port(80, "http", "lighttpd"),
                           port(443, "https", "lighttpd")], tags: ["infra"])
        let nas = host(4, "nas.local", "00:11:32:9C:2E:51", "Synology",
                       [port(22, "ssh", "OpenSSH", "9.6"), port(80, "http", "nginx"),
                        port(443, "https", "nginx"), port(445, "microsoft-ds", "Samba smbd", "4.19"),
                        port(5000, "http", "Synology DSM")], tags: ["infra", "backup"])
        let printer = host(7, "printer.local", "30:05:5C:71:A8:0E", "Brother",
                           [port(80, "http", "Debut embedded httpd", "1.30"), port(443, "https"),
                            port(631, "ipp", "CUPS")])
        let assistant = host(12, "homeassistant.local", "DC:A6:32:5B:7F:20", "Raspberry Pi",
                             [port(22, "ssh", "OpenSSH", "9.7"), port(1883, "mqtt", "Mosquitto"),
                              port(8123, "http", "aiohttp", "3.9.5")])
        let studio = host(19, "studio-mac.local", "3C:22:FB:90:61:D4", "Apple",
                          [port(22, "ssh", "OpenSSH", "9.8"), port(445, "microsoft-ds"),
                           port(5900, "vnc", "Apple remote desktop vnc")])
        let camera = host(60, "camera-door.local", "BC:AD:28:E1:44:39", "Hikvision",
                          [port(80, "http"), port(443, "https"), port(554, "rtsp")])
        var newCamera = camera
        newCamera.ports.append(port(23, "telnet", "BusyBox telnetd"))

        return [
            run(BuiltInProfiles.service, ["192.168.50.0/24"], hoursAgo: 0.6, seconds: 94,
                hosts: [router, nas, printer, assistant, studio, newCamera]),
            run(BuiltInProfiles.quick, ["192.168.50.4", "192.168.50.12"], hoursAgo: 5, seconds: 6,
                hosts: [nas, assistant]),
            run(BuiltInProfiles.service, ["192.168.50.0/24"], hoursAgo: 26, seconds: 101,
                hosts: [router, nas, printer, assistant, camera]),
            run(BuiltInProfiles.fullTCP, ["192.168.50.60"], hoursAgo: 49, seconds: 40,
                hosts: [], status: .cancelled),
            run(BuiltInProfiles.discovery, ["192.168.50.0/24"], hoursAgo: 72, seconds: 3, hosts: []),
        ]
    }
}

/// `DOZOR_SCREENSHOTS=<dir>` (demo mode only) walks the main screens, writes a
/// light and a dark PNG of each into `<dir>`, and quits. The window draws
/// itself into a bitmap, so no Screen Recording permission is involved.
@MainActor
enum ScreenshotCapture {
    static func runIfRequested(_ model: AppModel) async {
        guard DemoMode.isActive,
              let path = ProcessInfo.processInfo.environment["DOZOR_SCREENSHOTS"] else { return }
        let directory = URL(fileURLWithPath: path, isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        await pause(1.5)
        guard let window = NSApp.windows.first(where: { $0.isVisible && $0.canBecomeMain }) else { return }
        window.setContentSize(NSSize(width: 1380, height: 800))
        window.center()

        for (suffix, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            NSApp.appearance = NSAppearance(named: appearance)

            model.route = .network
            await pause(1.5)
            selectRow(1, in: window)
            await snap(window, to: directory, name: "network-\(suffix)")

            model.route = .scan
            await pause(1)
            model.pendingNetworkTargets = "192.168.50.0/24"
            await snap(window, to: directory, name: "scan-\(suffix)")

            model.route = .history
            await pause(1)
            selectRow(0, in: window)
            await snap(window, to: directory, name: "history-\(suffix)")

            model.route = .profiles
            await pause(1)
            selectRow(3, in: window)
            await snap(window, to: directory, name: "profiles-\(suffix)")
        }
        NSApp.terminate(nil)
    }

    private static func pause(_ seconds: Double) async {
        try? await Task.sleep(for: .seconds(seconds))
    }

    /// Selects a row in the detail pane's topmost table. Selection lives in each
    /// view's private state, so it is driven the way a click would drive it.
    private static func selectRow(_ row: Int, in window: NSWindow) {
        guard let content = window.contentView else { return }
        var tables: [NSTableView] = []
        func walk(_ view: NSView) {
            if let table = view as? NSTableView { tables.append(table) }
            view.subviews.forEach(walk)
        }
        walk(content)
        let detail = tables
            .map { ($0, $0.convert($0.bounds, to: nil)) }
            .filter { $0.1.minX > 150 }                 // not the sidebar
            .max { $0.1.maxY < $1.1.maxY }?.0           // topmost
        guard let detail, row < detail.numberOfRows else { return }
        detail.selectRowIndexes([row], byExtendingSelection: false)
        detail.scrollRowToVisible(row)
    }

    private static func snap(_ window: NSWindow, to directory: URL, name: String) async {
        await pause(1)
        // The frame view, not the content view, so the title bar and toolbar
        // are in the picture as well.
        guard let view = window.contentView?.superview else { return }
        let scale = window.backingScaleFactor < 2 ? 2 : window.backingScaleFactor
        guard let rep = NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: Int(view.bounds.width * scale), pixelsHigh: Int(view.bounds.height * scale),
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)
        else { return }
        rep.size = view.bounds.size
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?
            .write(to: directory.appendingPathComponent("\(name).png"))
    }
}

import Foundation

public enum ExportFormat: String, CaseIterable, Sendable {
    case json, csv, xml, html

    public var fileExtension: String { rawValue }
}

public enum ExportError: Error, Sendable {
    case noResult
    case encodingFailed
}

public enum Exporter {

    public static func data(for run: ScanRun, format: ExportFormat,
                            strings: ReportStrings = .english) throws -> Data {
        switch format {
        case .json: return try json(run)
        case .csv: return try csv(run)
        case .xml: return try xml(run)
        case .html: return try html(run, strings: strings)
        }
    }

    public static func suggestedFilename(for run: ScanRun, format: ExportFormat) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmm"
        let stamp = formatter.string(from: run.startedAt)
        return "nmap-\(stamp).\(format.fileExtension)"
    }

    // MARK: - JSON

    static func json(_ run: ScanRun) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // Raw XML is dropped from the export: it duplicates the parsed content
        // and bloats the file. Export XML separately when it is wanted.
        var trimmed = run
        trimmed.rawXML = nil
        return try encoder.encode(trimmed)
    }

    // MARK: - CSV

    static func csv(_ run: ScanRun) throws -> Data {
        guard let result = run.result else { throw ExportError.noResult }
        var rows = ["host,hostname,mac,vendor,state,port,protocol,port_state,service,product,version,reason,tags"]
        for host in result.hosts {
            if host.ports.isEmpty {
                rows.append([host.address, host.bestName ?? "", host.mac ?? "", host.vendor ?? "",
                             host.state, "", "", "", "", "", "", "",
                             host.tags.joined(separator: " ")]
                    .map(escapeCSV).joined(separator: ","))
                continue
            }
            for port in host.ports {
                rows.append([
                    host.address,
                    host.bestName ?? "",
                    host.mac ?? "",
                    host.vendor ?? "",
                    host.state,
                    String(port.port),
                    port.proto,
                    port.state,
                    port.serviceName ?? "",
                    port.product ?? "",
                    port.version ?? "",
                    port.reason ?? "",
                    host.tags.joined(separator: " "),
                ].map(escapeCSV).joined(separator: ","))
            }
        }
        guard let data = rows.joined(separator: "\n").data(using: .utf8) else {
            throw ExportError.encodingFailed
        }
        return data
    }

    static func escapeCSV(_ field: String) -> String {
        guard field.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" }) else { return field }
        return "\"" + field.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    // MARK: - XML

    static func xml(_ run: ScanRun) throws -> Data {
        guard let raw = run.rawXML, let data = raw.data(using: .utf8) else {
            throw ExportError.noResult
        }
        return data
    }

    // MARK: - HTML

    /// Self-contained report: no external assets, so it opens offline and
    /// prints (or "Save as PDF"s) directly from any browser.
    static func html(_ run: ScanRun, strings: ReportStrings = .english) throws -> Data {
        guard let result = run.result else { throw ExportError.noResult }

        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium

        var body = ""
        body += "<h1>\(esc(strings.title))</h1>"
        body += "<table class='meta'>"
        body += row(strings.profile, esc(run.profileName))
        body += row(strings.targets, esc(run.targets.map(\.raw).joined(separator: ", ")))
        body += row(strings.started, esc(formatter.string(from: run.startedAt)))
        if let finished = run.finishedAt {
            body += row(strings.finished, esc(formatter.string(from: finished)))
        }
        if let duration = run.duration {
            body += row(strings.duration, String(format: "%.1f s", duration))
        }
        body += row(strings.author, esc(run.author))
        body += row(strings.command, "<code>\(esc(run.commandPreview()))</code>")
        body += row(strings.hostsUp, "\(result.hostsUp)")
        let openTotal = result.hosts.reduce(0) { $0 + $1.openPorts.count }
        body += row(strings.openPorts, "\(openTotal)")
        body += "</table>"

        for host in result.hosts.sorted(by: { $0.address < $1.address }) {
            body += "<section class='host'>"
            body += "<h2>\(esc(host.address))"
            if let name = host.bestName { body += " <span class='sub'>\(esc(name))</span>" }
            body += " <span class='badge \(host.state == "up" ? "up" : "down")'>\(esc(host.state))</span></h2>"
            if let os = host.osGuess { body += "<p class='sub'>OS: \(esc(os))</p>" }
            if let mac = host.mac {
                body += "<p class='sub'>MAC: \(esc(mac))\(host.vendor.map { " — " + esc($0) } ?? "")"
                if host.macSource == .arpCache {
                    body += " <em>(\(esc(strings.macFromArp)))</em>"
                }
                body += "</p>"
            }
            if !host.tags.isEmpty {
                body += "<p class='tags'>" + host.tags.map { "<span class='tag'>\(esc($0))</span>" }.joined() + "</p>"
            }
            let ports = host.ports.filter { $0.state != "closed" }
            if ports.isEmpty {
                body += "<p class='sub'>\(esc(strings.noOpenPorts))</p>"
            } else {
                body += "<table class='ports'><thead><tr>"
                body += "<th>\(esc(strings.port))</th><th>\(esc(strings.state))</th>"
                body += "<th>\(esc(strings.service))</th><th>\(esc(strings.version))</th>"
                body += "</tr></thead><tbody>"
                for port in ports {
                    body += "<tr>"
                    body += "<td>\(port.port)/\(esc(port.proto))</td>"
                    body += "<td class='state-\(esc(port.state))'>\(esc(port.state))</td>"
                    body += "<td>\(esc(port.serviceName ?? "—"))</td>"
                    body += "<td>\(esc(port.serviceSummary ?? "—"))</td>"
                    body += "</tr>"
                }
                body += "</tbody></table>"
            }
            body += "</section>"
        }

        let document = """
        <!doctype html>
        <html lang="\(strings.languageCode)">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>\(esc(strings.title)) — \(esc(formatter.string(from: run.startedAt)))</title>
        <style>\(css)</style>
        </head>
        <body>\(body)
        <footer>\(esc(strings.footer))</footer>
        </body></html>
        """

        guard let data = document.data(using: .utf8) else { throw ExportError.encodingFailed }
        return data
    }

    private static func row(_ label: String, _ value: String) -> String {
        "<tr><th>\(esc(label))</th><td>\(value)</td></tr>"
    }

    /// Escapes text for HTML. Every value that comes from a scanned host —
    /// service banners in particular — is attacker-controlled, so nothing is
    /// interpolated into the report unescaped.
    static func esc(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.count)
        for character in text {
            switch character {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&#39;"
            default: out.append(character)
            }
        }
        return out
    }

    private static let css = """
    :root { color-scheme: light dark; --bg:#fff; --fg:#1d1d1f; --muted:#6e6e73;
            --line:#d2d2d7; --accent:#0071e3; --up:#1d8f4e; --down:#b3261e; --card:#f5f5f7; }
    @media (prefers-color-scheme: dark) {
      :root { --bg:#1c1c1e; --fg:#f5f5f7; --muted:#98989d; --line:#3a3a3c;
              --accent:#0a84ff; --up:#30d158; --down:#ff453a; --card:#2c2c2e; }
    }
    * { box-sizing: border-box; }
    body { margin:0; padding:32px 24px; background:var(--bg); color:var(--fg);
           font:15px/1.5 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", Arial, sans-serif; }
    h1 { font-size:28px; letter-spacing:-0.02em; margin:0 0 20px; }
    h2 { font-size:18px; margin:0 0 8px; letter-spacing:-0.01em; }
    .sub { color:var(--muted); font-size:13px; margin:2px 0; }
    table { border-collapse:collapse; width:100%; margin:12px 0; font-size:14px; }
    th, td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
    table.meta { max-width:760px; }
    table.meta th { width:180px; color:var(--muted); font-weight:500; }
    section.host { background:var(--card); border-radius:12px; padding:16px 18px; margin:16px 0; }
    .badge { font-size:11px; padding:2px 8px; border-radius:20px; vertical-align:middle;
             background:var(--line); color:var(--fg); text-transform:uppercase; letter-spacing:0.04em; }
    .badge.up { background:var(--up); color:#fff; }
    .badge.down { background:var(--down); color:#fff; }
    .state-open { color:var(--up); font-weight:600; }
    .state-filtered { color:var(--muted); }
    .tag { display:inline-block; font-size:12px; padding:2px 8px; border-radius:6px;
           background:var(--line); margin-right:6px; }
    code { font:13px ui-monospace, SFMono-Regular, Menlo, monospace; word-break:break-all; }
    footer { margin-top:32px; color:var(--muted); font-size:12px; border-top:1px solid var(--line); padding-top:12px; }
    @media print { body { padding:0; } section.host { break-inside:avoid; background:none; border:1px solid var(--line); } }
    """
}

/// Report labels, kept separate so the HTML export can be produced in the
/// user's language without pulling the UI layer into DozorKit.
public struct ReportStrings: Sendable {
    public var languageCode: String
    public var title: String
    public var profile: String
    public var targets: String
    public var started: String
    public var finished: String
    public var duration: String
    public var author: String
    public var command: String
    public var hostsUp: String
    public var openPorts: String
    public var port: String
    public var state: String
    public var service: String
    public var version: String
    public var noOpenPorts: String
    public var macFromArp: String
    public var footer: String

    public init(languageCode: String, title: String, profile: String, targets: String,
                started: String, finished: String, duration: String, author: String,
                command: String, hostsUp: String, openPorts: String, port: String,
                state: String, service: String, version: String, noOpenPorts: String,
                macFromArp: String, footer: String) {
        self.languageCode = languageCode
        self.title = title
        self.profile = profile
        self.targets = targets
        self.started = started
        self.finished = finished
        self.duration = duration
        self.author = author
        self.command = command
        self.hostsUp = hostsUp
        self.openPorts = openPorts
        self.port = port
        self.state = state
        self.service = service
        self.version = version
        self.noOpenPorts = noOpenPorts
        self.macFromArp = macFromArp
        self.footer = footer
    }

    public static let english = ReportStrings(
        languageCode: "en", title: "Nmap scan report", profile: "Profile", targets: "Targets",
        started: "Started", finished: "Finished", duration: "Duration", author: "Author",
        command: "Command", hostsUp: "Hosts up", openPorts: "Open ports", port: "Port",
        state: "State", service: "Service", version: "Version",
        noOpenPorts: "No open or filtered ports found.",
        macFromArp: "from this Mac's ARP cache, not from the scan",
        footer: "Generated by Dozor. Scan only assets you are authorised to test."
    )

    public static let ukrainian = ReportStrings(
        languageCode: "uk", title: "Звіт сканування Nmap", profile: "Профіль", targets: "Цілі",
        started: "Початок", finished: "Завершення", duration: "Тривалість", author: "Автор",
        command: "Команда", hostsUp: "Активних хостів", openPorts: "Відкритих портів",
        port: "Порт", state: "Стан", service: "Сервіс", version: "Версія",
        noOpenPorts: "Відкритих або фільтрованих портів не знайдено.",
        macFromArp: "з ARP-кешу цього Mac, не зі сканування",
        footer: "Згенеровано Dozor. Скануйте лише активи, на які маєте дозвіл."
    )
}

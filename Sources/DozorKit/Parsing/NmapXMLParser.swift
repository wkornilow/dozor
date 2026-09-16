import Foundation

public enum NmapXMLParseError: Error, Equatable, Sendable {
    case malformed(String)
    case empty
}

/// Streaming parser for Nmap's `-oX` output. Uses `XMLParser` (libxml2) with
/// external entity resolution left off, so a hostile XML file cannot reach the
/// filesystem or the network.
public final class NmapXMLParser: NSObject {

    private var result = ScanResult()
    private var host: HostResult?
    private var port: PortInfo?
    private var currentScriptID: String?
    private var parseError: NmapXMLParseError?

    public override init() { super.init() }

    public func parse(data: Data) throws -> ScanResult {
        guard !data.isEmpty else { throw NmapXMLParseError.empty }
        result = ScanResult()
        let parser = XMLParser(data: data)
        parser.delegate = self
        parser.shouldResolveExternalEntities = false
        parser.externalEntityResolvingPolicy = .never

        if !parser.parse() {
            // Nmap truncates the XML when interrupted; keep whatever parsed so
            // far rather than losing the run, but report a hard failure when
            // nothing at all came through.
            if result.hosts.isEmpty && result.nmapVersion == nil {
                throw parseError ?? .malformed(parser.parserError?.localizedDescription ?? "unknown")
            }
            result.warnings.append("xml.truncated")
        }
        return result
    }
}

extension NmapXMLParser: XMLParserDelegate {

    public func parser(_ parser: XMLParser, didStartElement elementName: String,
                       namespaceURI: String?, qualifiedName: String?,
                       attributes attrs: [String: String] = [:]) {
        switch elementName {
        case "nmaprun":
            result.nmapVersion = attrs["version"]
            result.commandLine = attrs["args"]
            result.startedAt = attrs["start"].flatMap(Self.date)

        case "host":
            host = HostResult(address: "", addressType: "", state: "unknown")

        case "status":
            host?.state = attrs["state"] ?? "unknown"

        case "address":
            guard var current = host else { break }
            let addr = attrs["addr"] ?? ""
            switch attrs["addrtype"] {
            case "mac":
                current.mac = addr
                current.vendor = attrs["vendor"]
            default:
                // First non-MAC address wins; extras are ignored.
                if current.address.isEmpty {
                    current.address = addr
                    current.addressType = attrs["addrtype"] ?? "ipv4"
                }
            }
            host = current

        case "hostname":
            if let name = attrs["name"], !name.isEmpty { host?.hostnames.append(name) }

        case "port":
            port = PortInfo(port: Int(attrs["portid"] ?? "") ?? 0,
                            proto: attrs["protocol"] ?? "tcp",
                            state: "unknown")

        case "state":
            guard port != nil else { break }
            port?.state = attrs["state"] ?? "unknown"
            port?.reason = attrs["reason"]

        case "service":
            port?.serviceName = attrs["name"]
            port?.product = attrs["product"]
            port?.version = attrs["version"]
            port?.extraInfo = attrs["extrainfo"]

        case "script":
            currentScriptID = attrs["id"]
            if let id = attrs["id"], let output = attrs["output"] {
                if port != nil {
                    port?.scripts[id] = output
                }
            }

        case "osmatch":
            if host?.osGuess == nil, let name = attrs["name"] {
                let accuracy = attrs["accuracy"].map { " (\($0)%)" } ?? ""
                host?.osGuess = name + accuracy
            }

        case "hosts":
            result.hostsUp = Int(attrs["up"] ?? "") ?? 0
            result.hostsDown = Int(attrs["down"] ?? "") ?? 0

        case "finished":
            result.finishedAt = attrs["time"].flatMap(Self.date)

        default:
            break
        }
    }

    public func parser(_ parser: XMLParser, didEndElement elementName: String,
                       namespaceURI: String?, qualifiedName: String?) {
        switch elementName {
        case "host":
            if var finished = host, !finished.address.isEmpty {
                finished.ports.sort { $0.port < $1.port }
                result.hosts.append(finished)
            }
            host = nil
        case "port":
            if let finished = port { host?.ports.append(finished) }
            port = nil
        case "script":
            currentScriptID = nil
        default:
            break
        }
    }

    public func parser(_ parser: XMLParser, parseErrorOccurred error: any Error) {
        parseError = .malformed(error.localizedDescription)
    }

    static func date(_ epoch: String) -> Date? {
        guard let seconds = Double(epoch) else { return nil }
        return Date(timeIntervalSince1970: seconds)
    }
}

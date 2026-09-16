import Foundation
import DozorKit

private let sampleXML = """
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" start="1700000000" version="7.95">
<host starttime="1700000000" endtime="1700000010">
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
<hostnames><hostname name="router.lan" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="protocol 2.0"/>
<script id="ssh-hostkey" output="2048 aa:bb"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.24.0"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="reset"/></port>
</ports>
<os><osmatch name="Linux 5.4" accuracy="95"/></os>
</host>
<runstats><finished time="1700000010"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""

func runParsingTests() {
    suite("XML parsing") {
        test("reads hosts, ports, services and metadata") {
            let result = try NmapXMLParser().parse(data: Data(sampleXML.utf8))
            expectEqual(result.nmapVersion, "7.95", "version")
            expectEqual(result.hostsUp, 1, "hosts up")
            expectEqual(result.hosts.count, 1, "host count")

            let host = try require(result.hosts.first)
            expectEqual(host.address, "192.168.1.1", "address")
            expectEqual(host.mac, "AA:BB:CC:DD:EE:FF", "mac")
            expectEqual(host.vendor, "Acme", "vendor")
            expectEqual(host.hostnames, ["router.lan"], "hostnames")
            expectEqual(host.osGuess, "Linux 5.4 (95%)", "os")
            expectEqual(host.ports.count, 3, "port count")
            expectEqual(host.openPorts.count, 2, "open ports")

            let ssh = try require(host.ports.first { $0.port == 22 })
            expectEqual(ssh.serviceName, "ssh", "service name")
            expectEqual(ssh.serviceSummary, "OpenSSH 9.6p1 (protocol 2.0)", "service summary")
            expectEqual(ssh.scripts["ssh-hostkey"], "2048 aa:bb", "script output")
        }

        test("empty input throws, truncated input is salvaged") {
            do {
                _ = try NmapXMLParser().parse(data: Data())
                expect(false, "expected an error for empty input")
            } catch {
                expectEqual(error as? NmapXMLParseError, .empty, "empty error")
            }
            let truncated = String(sampleXML.prefix(sampleXML.count / 2))
            let result = try NmapXMLParser().parse(data: Data(truncated.utf8))
            expectEqual(result.nmapVersion, "7.95", "version survives truncation")
            expect(result.warnings.contains("xml.truncated"), "truncation flagged")
        }

        test("external entities are not resolved") {
            let hostile = """
            <?xml version="1.0"?>
            <!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <nmaprun version="7.95"><host><status state="up"/>
            <address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>
            """
            let result = try? NmapXMLParser().parse(data: Data(hostile.utf8))
            let addresses = result?.hosts.map(\.address) ?? []
            expect(!addresses.contains { $0.contains("root:") }, "no file contents leaked into results")
        }

        test("progress lines are recognised") {
            let line = "Stats: 0:00:12 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan"
                + " SYN Stealth Scan Timing: About 34.56% done; ETC: 12:01 (0:00:23 remaining)"
            let parsed = NmapRunner.parseProgress(line)
            expectEqual(parsed?.0, 0.3456, "fraction")
            expectEqual(parsed?.1, 23, "eta seconds")
            expect(NmapRunner.parseProgress("Starting Nmap 7.95") == nil, "non-progress line ignored")
        }
    }
}

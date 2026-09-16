import Foundation
import DozorKit

func runValidationTests() {
    suite("Target validation") {
        test("accepts addresses, networks, ranges and hostnames") {
            let (targets, errors) = TargetValidator.parse("192.168.1.10 10.0.0.0/24 192.168.1.1-20 host.local ::1")
            expect(errors.isEmpty, "no errors expected, got \(errors)")
            expectEqual(targets.count, 5, "target count")
            expectEqual(targets[0].kind, .ipv4, "plain address")
            expectEqual(targets[1].kind, .cidr, "cidr")
            expectEqual(targets[1].addressCount, 256, "cidr size")
            expectEqual(targets[2].kind, .ipv4Range, "range")
            expectEqual(targets[2].addressCount, 20, "range size")
            expectEqual(targets[3].kind, .hostname, "hostname")
            expectEqual(targets[4].kind, .ipv6, "ipv6")
        }

        test("rejects shell metacharacters and option-looking tokens") {
            let hostile = [
                "192.168.1.1;rm -rf /",
                "$(whoami)",
                "`id`",
                "10.0.0.1|nc",
                "--script=http-all",
                "-oN /etc/passwd",
                "192.168.1.1 && curl evil.test",
                "10.0.0.1 > /etc/hosts",
            ]
            for text in hostile {
                let (targets, errors) = TargetValidator.parse(text)
                expect(!errors.isEmpty, "expected rejection for \(text)")
                expect(!targets.contains { $0.raw.contains(where: { ";|&`$()<>".contains($0) }) },
                       "metacharacter survived in \(text)")
                expect(!targets.contains { $0.raw.hasPrefix("-") }, "option survived in \(text)")
            }
        }

        test("classifies private and public space") {
            expectEqual(try? TargetValidator.validate("10.1.2.3").get().isPrivate, true, "10/8")
            expectEqual(try? TargetValidator.validate("192.168.0.1").get().isPrivate, true, "192.168/16")
            expectEqual(try? TargetValidator.validate("172.16.5.5").get().isPrivate, true, "172.16/12")
            expectEqual(try? TargetValidator.validate("172.32.5.5").get().isPrivate, false, "172.32 is public")
            expectEqual(try? TargetValidator.validate("8.8.8.8").get().isPrivate, false, "public")
            expectEqual(try? TargetValidator.validate("fe80::1").get().isPrivate, true, "link-local v6")
        }

        test("refuses oversized networks") {
            expectEqual(TargetValidator.validate("10.0.0.0/8"),
                        .failure(.tooManyAddresses("10.0.0.0/8", 16_777_216)),
                        "/8 must be refused")
        }

        test("refuses malformed input") {
            expect(TargetValidator.validate("192.168.1.0/33").isFailure, "prefix > 32")
            expect(TargetValidator.validate("192.168.1.300").isFailure, "octet > 255")
            expect(TargetValidator.validate("192.168.1.20-5").isFailure, "reversed range")
            expect(TargetValidator.parse("").errors.first == .empty, "empty input")
        }
    }

    suite("Argument policy") {
        test("accepts allow-listed flags") {
            expect(ArgumentPolicy.validate(["-sT", "--top-ports", "100", "--open"]).isEmpty, "connect scan")
            expect(ArgumentPolicy.validate(["-sV", "--version-intensity", "5"]).isEmpty, "version detection")
            expect(ArgumentPolicy.validate(["-p", "22,80,443,8000-8100"]).isEmpty, "port list")
            expect(ArgumentPolicy.validate(["--host-timeout", "30s"]).isEmpty, "duration")
            expect(ArgumentPolicy.validate(["--top-ports=200"]).isEmpty, "equals form")
        }

        test("refuses output redirection and unknown flags") {
            // The value that follows a forbidden flag is reported too, since it
            // is not a valid flag on its own.
            expect(ArgumentPolicy.validate(["-oN", "/etc/passwd"]).contains(.outputFlagNotAllowed("-oN")), "-oN")
            expect(ArgumentPolicy.validate(["--datadir", "/tmp"]).contains(.outputFlagNotAllowed("--datadir")), "--datadir")
            expect(ArgumentPolicy.validate(["-iL", "/etc/hosts"]).contains(.outputFlagNotAllowed("-iL")), "-iL")
            expectEqual(ArgumentPolicy.validate(["--totally-made-up"]), [.notAllowed("--totally-made-up")], "unknown")
            expectEqual(ArgumentPolicy.validate(["; rm -rf /"]), [.notAllowed("; rm -rf /")], "shell text")
        }

        test("refuses malformed values") {
            expectEqual(ArgumentPolicy.validate(["-p", "70000"]), [.malformedValue("-p 70000")], "port range")
            expectEqual(ArgumentPolicy.validate(["--top-ports", "abc"]), [.malformedValue("--top-ports abc")], "not a number")
            expectEqual(ArgumentPolicy.validate(["--script", "../../evil"]), [.malformedValue("--script ../../evil")], "path")
            expectEqual(ArgumentPolicy.validate(["--script", "http-all*"]), [.malformedValue("--script http-all*")], "glob")
        }

        test("builder appends app-owned flags and a -- separator") {
            do {
                let target = try TargetValidator.validate("192.168.1.0/28").get()
                let plan = try ArgumentBuilder.build(profile: BuiltInProfiles.quick,
                                                     targets: [target], policy: .default,
                                                     xmlURL: URL(fileURLWithPath: "/tmp/out.xml"))
                expect(plan.arguments.contains("--max-rate"), "rate limit applied")
                expect(plan.arguments.contains("-oX"), "xml output requested")
                let separator = try require(plan.arguments.firstIndex(of: "--"), "missing -- separator")
                expect(plan.arguments[separator...].contains("192.168.1.0/28"), "target after separator")
                expect(!plan.arguments[..<separator].contains("192.168.1.0/28"), "target not before separator")
                expectEqual(plan.addressCount, 16, "address count")
            } catch {
                expect(false, "builder threw \(error)")
            }
        }

        test("builder refuses a profile carrying a forbidden flag") {
            var profile = BuiltInProfiles.quick
            profile.arguments += ["-oN", "/tmp/evil"]
            do {
                _ = try ArgumentBuilder.build(profile: profile, targets: [
                    try TargetValidator.validate("10.0.0.1").get()
                ], policy: .default, xmlURL: URL(fileURLWithPath: "/tmp/out.xml"))
                expect(false, "expected the build to fail")
            } catch let error as ArgumentBuilder.BuildError {
                expectEqual(error, .policy([.outputFlagNotAllowed("-oN"), .notAllowed("/tmp/evil")]),
                            "policy errors reported")
            } catch {
                expect(false, "unexpected error \(error)")
            }
        }
    }
}

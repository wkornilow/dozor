import Foundation
import DozorKit

func runPolicyTests() {
    suite("Policy engine") {
        func target(_ text: String) throws -> ScanTarget {
            try TargetValidator.validate(text).get()
        }

        test("private targets at light intensity pass without prompting") {
            let verdict = PolicyEngine.evaluate(targets: [try target("192.168.1.0/24")],
                                                profile: BuiltInProfiles.quick,
                                                policy: .default, isRoot: false)
            expectEqual(verdict, .allowed, "private /24 should be allowed")
        }

        test("public targets are blocked unless allow-listed") {
            let verdict = PolicyEngine.evaluate(targets: [try target("8.8.8.8")],
                                                profile: BuiltInProfiles.quick,
                                                policy: .default, isRoot: false)
            guard case .blocked(let findings) = verdict else {
                expect(false, "expected blocked, got \(verdict)")
                return
            }
            expect(findings.contains { $0.kind == .unauthorisedTarget }, "unauthorised finding present")
        }

        test("allow-listed public targets only need confirmation") {
            var policy = ScanPolicy.default
            policy.authorisedAssets = ["8.8.8.0/24"]
            let verdict = PolicyEngine.evaluate(targets: [try target("8.8.8.8")],
                                                profile: BuiltInProfiles.quick,
                                                policy: policy, isRoot: false)
            guard case .needsConfirmation(let findings) = verdict else {
                expect(false, "expected confirmation, got \(verdict)")
                return
            }
            expect(findings.allSatisfy { !$0.isBlocking }, "no blocking findings")
        }

        test("hostname wildcards authorise subdomains") {
            var policy = ScanPolicy.default
            policy.authorisedAssets = ["*.example.com"]
            let verdict = PolicyEngine.evaluate(targets: [try target("api.example.com")],
                                                profile: BuiltInProfiles.quick,
                                                policy: policy, isRoot: false)
            if case .blocked = verdict {
                expect(false, "wildcard entry should authorise api.example.com")
            }
        }

        test("root-only profiles are blocked for non-root users") {
            let verdict = PolicyEngine.evaluate(targets: [try target("192.168.1.1")],
                                                profile: BuiltInProfiles.udpTop,
                                                policy: .default, isRoot: false)
            guard case .blocked(let findings) = verdict else {
                expect(false, "expected blocked, got \(verdict)")
                return
            }
            expect(findings.contains { $0.kind == .rootRequired }, "root finding present")
        }

        test("scope over the per-run maximum is blocked") {
            var policy = ScanPolicy.default
            policy.maxAddressesPerRun = 64
            let verdict = PolicyEngine.evaluate(targets: [try target("10.0.0.0/24")],
                                                profile: BuiltInProfiles.quick,
                                                policy: policy, isRoot: false)
            guard case .blocked(let findings) = verdict else {
                expect(false, "expected blocked, got \(verdict)")
                return
            }
            expect(findings.contains { $0.kind == .scopeOverLimit }, "scope finding present")
        }

        test("intensity above the confirmation threshold prompts, above the block threshold refuses") {
            var policy = ScanPolicy.default
            policy.maxIntensityWithoutConfirmation = .light
            let prompt = PolicyEngine.evaluate(targets: [try target("10.0.0.1")],
                                               profile: BuiltInProfiles.aggressive,
                                               policy: policy, isRoot: false)
            guard case .needsConfirmation = prompt else {
                expect(false, "expected confirmation, got \(prompt)")
                return
            }
            policy.blockedIntensity = .aggressive
            let blocked = PolicyEngine.evaluate(targets: [try target("10.0.0.1")],
                                                profile: BuiltInProfiles.aggressive,
                                                policy: policy, isRoot: false)
            guard case .blocked = blocked else {
                expect(false, "expected blocked, got \(blocked)")
                return
            }
        }
    }
}

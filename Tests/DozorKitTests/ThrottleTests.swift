import Foundation
import DozorKit

func runThrottleTests() {
    suite("Rate limiting") {
        func target(_ text: String) throws -> ScanTarget {
            try TargetValidator.validate(text).get()
        }

        test("a zero cap omits the flag instead of passing 0") {
            var policy = ScanPolicy.default
            policy.maxPacketRate = 0
            policy.maxParallelism = 0
            policy.maxHostGroup = 0
            let plan = try ArgumentBuilder.build(profile: BuiltInProfiles.quick,
                                                 targets: [try target("10.0.0.1")],
                                                 policy: policy,
                                                 xmlURL: URL(fileURLWithPath: "/tmp/out.xml"))
            expect(!plan.arguments.contains("--max-rate"), "no --max-rate")
            expect(!plan.arguments.contains("--max-parallelism"), "no --max-parallelism")
            expect(!plan.arguments.contains("--max-hostgroup"), "no --max-hostgroup")
            expect(!plan.arguments.contains("0"), "no bare zero left in argv")
        }

        test("a set cap is still applied") {
            var policy = ScanPolicy.default
            policy.maxPacketRate = 1_000
            let plan = try ArgumentBuilder.build(profile: BuiltInProfiles.quick,
                                                 targets: [try target("10.0.0.1")],
                                                 policy: policy,
                                                 xmlURL: URL(fileURLWithPath: "/tmp/out.xml"))
            let index = try require(plan.arguments.firstIndex(of: "--max-rate"))
            expectEqual(plan.arguments[index + 1], "1000", "cap value passed through")
        }

        test("probe counts are read out of the profile's own arguments") {
            expectEqual(ArgumentBuilder.probesPerHost(BuiltInProfiles.quick), 100, "--top-ports 100")
            expectEqual(ArgumentBuilder.probesPerHost(BuiltInProfiles.standard), 1000, "--top-ports 1000")
            expectEqual(ArgumentBuilder.probesPerHost(BuiltInProfiles.fullTCP), 65_535, "-p 1-65535")
            expectEqual(ArgumentBuilder.probesPerHost(BuiltInProfiles.discovery), 2, "discovery only pings")
        }

        test("the estimate never promises less time than the cap allows") {
            var policy = ScanPolicy.default
            policy.maxPacketRate = 500
            // 65535 probes at 500 packets/second cannot finish in under ~131 s,
            // which is exactly how long a measured run of this profile took.
            let estimate = ArgumentBuilder.estimateSeconds(profile: BuiltInProfiles.fullTCP,
                                                           addresses: 1, policy: policy)
            expect(estimate >= 131, "estimate \(estimate) must respect the cap")
        }

        test("the binding constraint is reported") {
            var throttled = ScanPolicy.default
            throttled.maxPacketRate = 500
            expect(ArgumentBuilder.isRateLimitBinding(profile: BuiltInProfiles.fullTCP,
                                                      addresses: 1, policy: throttled),
                   "500 pps must be flagged as binding")

            let shipped = ScanPolicy.default
            expect(!ArgumentBuilder.isRateLimitBinding(profile: BuiltInProfiles.quick,
                                                       addresses: 254, policy: shipped),
                   "the shipped default must not bind on an ordinary LAN scan")
        }

        test("shipped defaults do not throttle an ordinary scan into a crawl") {
            let policy = ScanPolicy.default
            let probes = Double(254 * ArgumentBuilder.probesPerHost(BuiltInProfiles.standard))
            let floor = probes / Double(policy.maxPacketRate)
            expect(floor < 30, "a /24 standard scan must not be capped to \(floor) s")
        }
    }

    suite("Policy migration") {
        test("limits written by the first version are raised on load") {
            let old = """
            {"authorisedAssets":["10.0.0.0/8"],"blockUnauthorisedTargets":true,
             "maxIntensityWithoutConfirmation":"moderate","maxPacketRate":500,
             "maxParallelism":32,"maxHostGroup":32,"maxAddressesPerRun":4096,
             "serialiseScans":true}
            """
            let decoded = try JSONDecoder().decode(ScanPolicy.self, from: Data(old.utf8))
            expectEqual(decoded.schemaVersion, 1, "old file is version 1")

            let migrated = decoded.migratedIfNeeded()
            expectEqual(migrated.maxPacketRate, ScanPolicy.default.maxPacketRate, "rate raised")
            expectEqual(migrated.maxParallelism, ScanPolicy.default.maxParallelism, "parallelism raised")
            expectEqual(migrated.schemaVersion, ScanPolicy.currentSchemaVersion, "version bumped")
            expectEqual(migrated.authorisedAssets, ["10.0.0.0/8"], "user's asset list kept")
            expect(migrated.blockUnauthorisedTargets, "user's blocking choice kept")
        }

        test("a current policy is left alone") {
            let policy = ScanPolicy.default
            expectEqual(policy.migratedIfNeeded(), policy, "no change expected")
        }
    }
}

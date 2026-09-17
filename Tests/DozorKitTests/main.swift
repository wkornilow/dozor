import Foundation
import DozorKit

runValidationTests()
runPolicyTests()
runParsingTests()
runDiffTests()
runExportTests()
runThrottleTests()
runLocalNetworkTests()
runHostEnrichmentTests()
runSweepTests()
runEchoTests()
runActionTests()
runInventoryTests()
runSweepPolicyTests()
dumpLiveSweep()
dumpLocalNetworks()
runLiveScanTests()

TestRunner.shared.finish()

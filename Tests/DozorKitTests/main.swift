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
dumpLocalNetworks()
runLiveScanTests()

TestRunner.shared.finish()

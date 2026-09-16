// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Dozor",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "Dozor", targets: ["Dozor"]),
        .executable(name: "DozorKitTests", targets: ["DozorKitTests"]),
        .library(name: "DozorKit", targets: ["DozorKit"]),
    ],
    targets: [
        // Platform-independent core: process execution, parsing, storage, export.
        .target(
            name: "DozorKit",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // macOS SwiftUI front-end.
        .executableTarget(
            name: "Dozor",
            dependencies: ["DozorKit"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // XCTest and swift-testing ship with Xcode, not the Command Line
        // Tools, so the suite is a plain executable: `swift run DozorKitTests`.
        .executableTarget(
            name: "DozorKitTests",
            dependencies: ["DozorKit"],
            path: "Tests/DozorKitTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)

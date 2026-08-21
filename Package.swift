// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "Lockbox",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v10),
        .visionOS(.v1)
    ],
    products: [
        .library(name: "Lockbox", targets: ["Lockbox"])
    ],
    dependencies: [
        .package(
            url: "https://github.com/swiftlang/swift-docc-plugin",
            exact: "1.5.0"
        )
    ],
    targets: [
        .target(name: "Lockbox"),
        .testTarget(name: "LockboxTests", dependencies: ["Lockbox"])
    ],
    swiftLanguageModes: [.v6]
)

// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SingTun",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(
            name: "SingTun",
            targets: ["SingTun"]
        ),
    ],
    targets: [
        .target(
            name: "SingTun",
            path: "Sources/SingTun",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "SingTunTests",
            dependencies: ["SingTun"],
            path: "Tests/SingTunTests"
        ),
    ]
)

// swift-tools-version: 6.2
import PackageDescription

// Applied to every Swift target: opt fully into the Swift 6 language mode so the
// whole package is checked under complete data-race safety on every platform.
let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6)
]

let package = Package(
    name: "Stream64",
    // Minimum deployment targets for Apple platforms. Non-Apple platforms
    // (Linux, Android, Windows, WASI) are supported without an entry here.
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6),
        .macCatalyst(.v13),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "Stream64",
            targets: ["Stream64"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    ],
    targets: [
        // Portable C bit-stream codec. `publicHeadersPath: "."` puts the header
        // directory on the include path and propagates it to dependents, so no
        // extra `cSettings` (header search paths) are needed — keeping the
        // manifest portable across macOS/iOS/Linux/Android/WASI.
        .target(
            name: "CStream64",
            sources: ["CStream64.c"],
            publicHeadersPath: "."),
        .target(
            name: "Stream64",
            dependencies: [
                "CStream64",
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: swiftSettings),
        .testTarget(
            name: "Stream64Tests",
            dependencies: ["Stream64"],
            swiftSettings: swiftSettings),
    ],
    swiftLanguageModes: [.v6]
)

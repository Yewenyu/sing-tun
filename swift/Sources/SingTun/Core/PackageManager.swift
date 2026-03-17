// Package manager stub for non-Android platforms.
// On Android the real implementation reads from /data/system/packages.xml.
// Mirrors packages_stub.go from the Go implementation.

// MARK: - StubPackageManager

/// A no-op `PackageManager` used on platforms other than Android.
public final class StubPackageManager: PackageManager {
    public init() {}

    public func start() throws {}
    public func close() throws {}

    public func id(forPackage packageName: String) -> UInt32? { nil }
    public func id(forSharedPackage sharedPackage: String) -> UInt32? { nil }
    public func package(forID id: UInt32) -> String? { nil }
    public func sharedPackage(forID id: UInt32) -> String? { nil }
}

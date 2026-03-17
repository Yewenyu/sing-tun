// Auto-redirect support structures.
// On Linux the real implementation manages iptables/nftables rules.
// On Darwin the TUN handles all traffic via routing rules instead.
// Mirrors redirect.go from the Go implementation.

import Foundation

// MARK: - AutoRedirectConstants

public enum AutoRedirectConstants {
    public static let defaultInputMark:  UInt32 = 0x2023
    public static let defaultOutputMark: UInt32 = 0x2024
}

// MARK: - AutoRedirectOptions

public struct AutoRedirectOptions {
    public var tunOptions:          TunOptions
    public var networkMonitor:      NetworkUpdateMonitor?
    public var tableName:           String
    public var disableNFTables:     Bool
    public var customRedirectPort:  (() -> Int)?
    public var logger:              Logger

    public init(tunOptions: TunOptions, logger: Logger) {
        self.tunOptions       = tunOptions
        self.networkMonitor   = nil
        self.tableName        = "sing-tun"
        self.disableNFTables  = false
        self.customRedirectPort = nil
        self.logger           = logger
    }
}

// MARK: - StubAutoRedirect

/// A no-op `AutoRedirect` for platforms where automatic firewall redirect
/// rules are not supported (e.g. macOS / iOS; traffic is steered via routes
/// set up by `NativeTun.start()` instead).
public final class StubAutoRedirect: AutoRedirect {
    public init() {}
    public func start() throws {}
    public func close() throws {}
    public func updateRouteAddressSet() {}
}

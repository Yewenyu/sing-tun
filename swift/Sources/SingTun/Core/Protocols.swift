// Core protocols mirroring the Go sing-tun interfaces.

import Foundation

// MARK: - Handler

/// Handler processes proxied TCP and UDP connections from the TUN stack.
public protocol Handler: AnyObject {
    /// Called before accepting a connection to allow early routing decisions.
    /// Returns a `DirectRouteDestination` if the packet should be routed directly,
    /// or `nil` to allow normal handling.
    func prepareConnection(
        network: String,
        source: SocksAddr,
        destination: SocksAddr,
        routeContext: DirectRouteContext?,
        timeout: TimeInterval
    ) async throws -> DirectRouteDestination?

    /// Handle an inbound TCP connection.
    func handleTCPConnection(_ conn: TCPConn, metadata: ConnectionMetadata) async

    /// Handle an inbound UDP packet flow.
    func handleUDPConnection(_ conn: UDPConn, metadata: ConnectionMetadata) async
}

// MARK: - DirectRouteContext

/// Allows the handler to write a raw IP packet back into the TUN device.
public protocol DirectRouteContext: AnyObject {
    func writePacket(_ packet: Data) throws
}

// MARK: - DirectRouteDestination

/// Represents an active direct-route session that can receive raw IP packets.
public protocol DirectRouteDestination: AnyObject {
    func writePacket(_ packet: Data) throws
    func close() throws
    var isClosed: Bool { get }
}

// MARK: - Tun

/// Cross-platform TUN device interface.
public protocol Tun: AnyObject {
    /// Read a single IP packet from the device into `buffer`.
    func read(into buffer: inout Data) throws -> Int

    /// Write a single IP packet to the device.
    @discardableResult
    func write(_ packet: Data) throws -> Int

    /// Return the OS name of this TUN interface (e.g., `"utun0"`).
    func name() throws -> String

    /// Bring up the interface and configure routes.
    func start() throws

    /// Tear down the interface and clean up routes.
    func close() throws

    /// Reconfigure routing options without recreating the device.
    func updateRouteOptions(_ options: TunOptions) throws
}

// MARK: - DarwinTUN

/// Extended interface for Darwin (macOS / iOS) with batch I/O.
public protocol DarwinTUN: Tun {
    func batchRead() throws -> [Data]
    func batchWrite(_ packets: [Data]) throws
}

// MARK: - Stack

/// A network stack that processes packets from a TUN device.
public protocol Stack: AnyObject {
    func start() throws
    func close() throws
}

// MARK: - NetworkUpdateMonitor

public typealias NetworkUpdateCallback = () -> Void
public typealias DefaultInterfaceUpdateCallback = (NetworkInterface?, Int) -> Void

/// Monitors kernel routing table changes and delivers update callbacks.
public protocol NetworkUpdateMonitor: AnyObject {
    func start() throws
    func close() throws
    @discardableResult
    func registerCallback(_ callback: @escaping NetworkUpdateCallback) -> CallbackToken
    func unregisterCallback(_ token: CallbackToken)
}

// MARK: - DefaultInterfaceMonitor

/// Tracks the currently active default network interface.
public protocol DefaultInterfaceMonitor: AnyObject {
    func start() throws
    func close() throws
    var defaultInterface: NetworkInterface? { get }
    var overrideAndroidVPN: Bool { get }
    var androidVPNEnabled: Bool { get }
    @discardableResult
    func registerCallback(_ callback: @escaping DefaultInterfaceUpdateCallback) -> CallbackToken
    func unregisterCallback(_ token: CallbackToken)
    func registerMyInterface(name: String)
    var myInterface: String { get }
}

// MARK: - AutoRedirect

/// Manages automatic firewall/redirect rules so that traffic is steered
/// into the TUN device without per-application configuration.
public protocol AutoRedirect: AnyObject {
    func start() throws
    func close() throws
    func updateRouteAddressSet()
}

// MARK: - PackageManager (Android-only concept; stub on Apple platforms)

/// Maps Android package names to UIDs. On non-Android platforms this is a stub.
public protocol PackageManager: AnyObject {
    func start() throws
    func close() throws
    func id(forPackage packageName: String) -> UInt32?
    func id(forSharedPackage sharedPackage: String) -> UInt32?
    func package(forID id: UInt32) -> String?
    func sharedPackage(forID id: UInt32) -> String?
}

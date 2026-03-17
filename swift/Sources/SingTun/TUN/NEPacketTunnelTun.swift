// TUN device implementation backed by Apple's Network Extension framework.
// Targets macOS (13+) and iOS (16+); Linux support has been removed.
//
// Usage (inside your NEPacketTunnelProvider subclass):
//
//   // 1. Apply network settings to the OS tunnel interface.
//   let settings = tunOptions.buildNetworkSettings()
//   try await self.setTunnelNetworkSettings(settings)
//
//   // 2. Wrap the packet flow and start the stack.
//   let tun   = NEPacketTunnelTun(packetFlow: self.packetFlow)
//   let stack = try newStack(options: StackOptions(tun: tun, ...))
//   try stack.start()
//
// Unlike NativeTun (which opens a raw utun socket), this class:
//  - Does NOT create the TUN interface (the NE framework does that).
//  - Does NOT install routes (call setTunnelNetworkSettings instead).
//  - Does NOT add a 4-byte AF_ family prefix; NEPacketTunnelFlow delivers
//    clean IP datagrams.

#if canImport(NetworkExtension)

import Foundation
import NetworkExtension
import Darwin

// MARK: - NEPacketTunnelTun

/// `DarwinTUN` implementation that reads and writes raw IP packets via
/// `NEPacketTunnelFlow` (the packet flow vended by `NEPacketTunnelProvider`).
public final class NEPacketTunnelTun: DarwinTUN {

    // MARK: - State

    private let packetFlow: NEPacketTunnelFlow
    private let _name:      String
    private var _stopped:   Bool = false
    private let stopLock  = NSLock()

    // MARK: - Init

    /// - Parameters:
    ///   - packetFlow: The `NEPacketTunnelFlow` from `NEPacketTunnelProvider.packetFlow`.
    ///   - interfaceName: The logical name of this TUN interface (e.g. `"utun0"`).
    ///                    Purely informational; the real name is assigned by the OS.
    public init(packetFlow: NEPacketTunnelFlow, interfaceName: String = "utun0") {
        self.packetFlow = packetFlow
        self._name      = interfaceName
    }

    // MARK: - Tun

    public func name() throws -> String { _name }

    public func start() throws {
        // The NEPacketTunnelProvider is responsible for calling
        // `setTunnelNetworkSettings(_:completionHandler:)`.
        // Nothing to do here.
    }

    public func close() throws {
        stopLock.lock()
        _stopped = true
        stopLock.unlock()
    }

    public func updateRouteOptions(_ options: TunOptions) throws {
        // Route changes must be applied by the caller via
        // `NEPacketTunnelProvider.setTunnelNetworkSettings(_:completionHandler:)`.
    }

    /// Read a single IP packet. Blocks until at least one packet is available,
    /// then returns the first packet and discards the rest of the batch.
    public func read(into buffer: inout Data) throws -> Int {
        let packets = try batchRead()
        guard let first = packets.first else {
            buffer = Data()
            return 0
        }
        buffer = first
        return first.count
    }

    /// Write a single IP packet back through the tunnel flow.
    @discardableResult
    public func write(_ packet: Data) throws -> Int {
        try batchWrite([packet])
        return packet.count
    }

    // MARK: - DarwinTUN

    /// Read a batch of raw IP packets from the tunnel flow.
    ///
    /// Blocks the calling thread until `NEPacketTunnelFlow.readPacketObjects`
    /// delivers packets (this may be an empty array when the extension is idle).
    public func batchRead() throws -> [Data] {
        guard !isStopped else { throw NEPacketTunnelTunError.closed }
        var result: [Data] = []
        let sema = DispatchSemaphore(value: 0)
        packetFlow.readPacketObjects { packets in
            result = packets.map { $0.data }
            sema.signal()
        }
        sema.wait()
        return result
    }

    /// Write a batch of raw IP packets back through the tunnel flow.
    ///
    /// Each `Data` element is a complete IPv4 or IPv6 datagram.
    /// The IP version is detected from the first byte of each packet.
    public func batchWrite(_ packets: [Data]) throws {
        guard !isStopped else { throw NEPacketTunnelTunError.closed }
        let nePackets: [NEPacket] = packets.compactMap { data in
            guard !data.isEmpty else { return nil }
            let version = (data[data.startIndex] >> 4) & 0x0F
            let family: Int32 = (version == 6) ? AF_INET6 : AF_INET
            return NEPacket(data: data, protocolFamily: sa_family_t(family))
        }
        guard !nePackets.isEmpty else { return }
        packetFlow.writePacketObjects(nePackets)
    }

    // MARK: - Private

    private var isStopped: Bool {
        stopLock.lock(); defer { stopLock.unlock() }
        return _stopped
    }
}

// MARK: - NEPacketTunnelTunError

public enum NEPacketTunnelTunError: Error, LocalizedError {
    case closed

    public var errorDescription: String? {
        switch self {
        case .closed: return "NEPacketTunnelTun has been closed"
        }
    }
}

// MARK: - TunOptions + NEPacketTunnelNetworkSettings

public extension TunOptions {

    /// Build an `NEPacketTunnelNetworkSettings` from this `TunOptions`.
    ///
    /// Typical usage inside `NEPacketTunnelProvider.startTunnel(options:completionHandler:)`:
    ///
    /// ```swift
    /// let settings = tunOptions.buildNetworkSettings()
    /// try await self.setTunnelNetworkSettings(settings)
    /// ```
    ///
    /// The returned settings include:
    ///  - IPv4 / IPv6 interface addresses and their prefix lengths
    ///  - A matching set of included routes (from `buildAutoRouteRanges`)
    ///  - DNS servers
    ///  - MTU
    func buildNetworkSettings() -> NEPacketTunnelNetworkSettings {
        // Use the loopback address as the tunnel remote address – it is only
        // used internally by the NE framework and never actually routed.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        // ── IPv4 ────────────────────────────────────────────────────────────
        if !inet4Address.isEmpty {
            let addrs   = inet4Address.map { $0.addr.description }
            let masks   = inet4Address.map { prefixLenToMask4($0.bits) }
            let ipv4    = NEIPv4Settings(addresses: addrs, subnetMasks: masks)

            // Included routes
            let autoRanges = buildAutoRouteRanges(underNetworkExtension: true)
            let v4routes   = autoRanges.filter { $0.addr.isV4 }.map { prefix in
                NEIPv4Route(destinationAddress: prefix.addr.description,
                            subnetMask:         prefixLenToMask4(prefix.bits))
            }
            if !v4routes.isEmpty {
                ipv4.includedRoutes = v4routes
            }

            // Excluded routes
            let exclRoutes = inet4RouteExcludeAddress.map { prefix in
                NEIPv4Route(destinationAddress: prefix.addr.description,
                            subnetMask:         prefixLenToMask4(prefix.bits))
            }
            if !exclRoutes.isEmpty {
                ipv4.excludedRoutes = exclRoutes
            }

            settings.ipv4Settings = ipv4
        }

        // ── IPv6 ────────────────────────────────────────────────────────────
        if !inet6Address.isEmpty {
            let addrs       = inet6Address.map { $0.addr.description }
            let prefixLens  = inet6Address.map { NSNumber(value: $0.bits) }
            let ipv6        = NEIPv6Settings(addresses: addrs, networkPrefixLengths: prefixLens)

            let autoRanges  = buildAutoRouteRanges(underNetworkExtension: true)
            let v6routes    = autoRanges.filter { $0.addr.isV6 }.map { prefix in
                NEIPv6Route(destinationAddress: prefix.addr.description,
                            networkPrefixLength: NSNumber(value: prefix.bits))
            }
            if !v6routes.isEmpty {
                ipv6.includedRoutes = v6routes
            }

            let exclRoutes = inet6RouteExcludeAddress.map { prefix in
                NEIPv6Route(destinationAddress: prefix.addr.description,
                            networkPrefixLength: NSNumber(value: prefix.bits))
            }
            if !exclRoutes.isEmpty {
                ipv6.excludedRoutes = exclRoutes
            }

            settings.ipv6Settings = ipv6
        }

        // ── DNS ─────────────────────────────────────────────────────────────
        if !dnsServers.isEmpty && !disableDNSHijack {
            settings.dnsSettings = NEDNSSettings(servers: dnsServers.map { $0.description })
        }

        // ── MTU ─────────────────────────────────────────────────────────────
        settings.mtu = NSNumber(value: mtu)

        return settings
    }

    // MARK: - Private helpers

    /// Convert a prefix-length (0–32) to a dotted-decimal subnet mask string.
    private func prefixLenToMask4(_ bits: UInt8) -> String {
        let bits32 = bits >= 32 ? UInt32.max : ~(UInt32.max >> bits)
        let b0 = UInt8((bits32 >> 24) & 0xFF)
        let b1 = UInt8((bits32 >> 16) & 0xFF)
        let b2 = UInt8((bits32 >>  8) & 0xFF)
        let b3 = UInt8( bits32        & 0xFF)
        return "\(b0).\(b1).\(b2).\(b3)"
    }
}

#endif // canImport(NetworkExtension)

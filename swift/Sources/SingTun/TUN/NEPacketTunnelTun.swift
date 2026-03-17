// TUN device implementation backed by Apple's Network Extension framework.
// Replaces the low-level utun socket approach used by NativeTun on
// platforms where a NEPacketTunnelProvider is the entry point (iOS, macOS
// Network Extensions).
//
// Usage (inside your NEPacketTunnelProvider subclass):
//
//   let tun = NEPacketTunnelTun(packetFlow: self.packetFlow)
//   let stack = try newStack(options: StackOptions(tun: tun, ...))
//   try stack.start()
//
// Unlike NativeTun (which opens a raw utun socket), this class:
//  - Does NOT create the TUN interface (the NE framework does that).
//  - Does NOT install routes (use NEPacketTunnelNetworkSettings instead).
//  - Does NOT add a 4-byte AF_ family prefix to packets; NEPacketTunnelFlow
//    delivers and accepts clean IP datagrams.

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

#endif // canImport(NetworkExtension)

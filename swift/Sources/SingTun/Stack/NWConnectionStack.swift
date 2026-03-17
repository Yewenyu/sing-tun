// Network.framework-based TCP listener and connection implementations.
//
// Targeting macOS (13+) and iOS (16+) exclusively; Linux support has been removed.
//
// Architecture with NEPacketTunnelTun + NWListenerTCPListener:
//
//  1. NEPacketTunnelTun.batchRead()
//       ← reads raw IP packets from NEPacketTunnelFlow
//  2. SystemStack processes IP packets, does TCP NAT rewrite:
//       src=device:sport, dst=real_dst:dport  →  src=next:natPort, dst=tun_addr:localPort
//  3. NEPacketTunnelTun.write() sends rewritten packet back through the flow
//       → kernel routes dst=tun_addr:localPort to our NWListener
//  4. NWListenerTCPListener.accept() returns NWConnectionTCPConn
//  5. acceptLoop reverse-NATs using natPort → original session
//  6. handler.handleTCPConnection(nwConn, metadata:) proxies the data

#if canImport(Network)

import Foundation
import Network

// MARK: - NWListenerTCPListener

/// TCP listener backed by `Network.framework`'s `NWListener`.
/// Conforms to the internal `AnyTCPListener` protocol.
final class NWListenerTCPListener: AnyTCPListener {

    // MARK: State

    private let address:  IPAddr
    private var listener: NWListener?
    private(set) var port: UInt16 = 0

    private let queue     = DispatchQueue(label: "sing-tun.nwlistener", qos: .utility)
    private let condition = NSCondition()
    private var pending:  [NWConnection] = []
    private var stopped  = false

    // MARK: Init

    init(address: IPAddr) {
        self.address = address
    }

    // MARK: AnyTCPListener

    func start() throws {
        let params = NWParameters.tcp

        // Bind to the TUN interface address so NAT-rewritten packets are delivered here.
        let host = NWEndpoint.Host(address.description)
        params.requiredLocalEndpoint = .hostPort(host: host, port: .any)

        let l = try NWListener(using: params)
        listener = l

        // Receive incoming connections.
        l.newConnectionHandler = { [weak self] conn in
            self?.enqueue(conn)
        }

        // Wait synchronously for the listener to reach `.ready`.
        let sema = DispatchSemaphore(value: 0)
        var startError: Error?

        l.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                if let rawPort = self?.listener?.port?.rawValue {
                    self?.port = rawPort
                }
                sema.signal()
            case .failed(let error):
                startError = error
                sema.signal()
            case .cancelled:
                sema.signal()
            default:
                break
            }
        }

        l.start(queue: queue)
        sema.wait()

        if let err = startError { throw err }
    }

    /// Block the calling thread until a new connection arrives.
    /// Returns `nil` once `stop()` has been called.
    func accept() -> PortedTCPConn? {
        condition.lock()
        defer { condition.unlock() }
        while pending.isEmpty && !stopped {
            condition.wait()
        }
        guard !stopped else { return nil }
        let conn = pending.removeFirst()
        return NWConnectionTCPConn(conn: conn)
    }

    func stop() {
        condition.lock()
        stopped = true
        condition.broadcast()
        condition.unlock()
        listener?.cancel()
        listener = nil
    }

    // MARK: Private

    private func enqueue(_ conn: NWConnection) {
        condition.lock()
        pending.append(conn)
        condition.signal()
        condition.unlock()
    }
}

// MARK: - NWConnectionTCPConn

/// `TCPConn` backed by `Network.framework`'s `NWConnection`.
///
/// The `remotePort` property returns the connecting peer's port number —
/// which for NAT-rewritten connections equals the `natPort` used by `TCPNat`.
public final class NWConnectionTCPConn: PortedTCPConn {

    // MARK: State

    private let conn:  NWConnection
    private let queue: DispatchQueue

    /// The remote port of the connection, extracted from `conn.endpoint`.
    /// For NAT-rewritten connections this equals the `natPort` from `TCPNat`.
    public var remotePort: UInt16 {
        if case .hostPort(_, let p) = conn.endpoint {
            return p.rawValue
        }
        return 0
    }

    // MARK: Init

    init(conn: NWConnection) {
        self.conn  = conn
        self.queue = DispatchQueue(label: "sing-tun.nwconn-\(ObjectIdentifier(conn))", qos: .utility)
        conn.start(queue: queue)
    }

    deinit { conn.cancel() }

    // MARK: - TCPConn

    public func read(into buffer: inout Data) throws -> Int {
        var received: Data?
        var recvError: NWError?
        let sema = DispatchSemaphore(value: 0)

        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, error in
            received  = data
            recvError = error
            sema.signal()
        }
        sema.wait()

        if let error = recvError { throw error }
        buffer = received ?? Data()
        return buffer.count
    }

    public func write(_ data: Data) throws -> Int {
        var writeError: NWError?
        let sema = DispatchSemaphore(value: 0)

        conn.send(content: data, completion: .contentProcessed { error in
            writeError = error
            sema.signal()
        })
        sema.wait()

        if let error = writeError { throw error }
        return data.count
    }

    public func closeWrite() throws {
        // Mark the sending direction as complete.
        conn.send(
            content:        nil,
            contentContext: .finalMessage,
            isComplete:     true,
            completion:     .idempotent
        )
    }

    public func close() throws {
        conn.cancel()
    }
}

// MARK: - NWConnectionUDPConn

/// A single UDP datagram flow backed by `Network.framework`'s `NWConnection`.
///
/// Each instance wraps one logical UDP flow identified by its 4-tuple.
/// Used by SystemStack when forwarding UDP packets to the handler.
public final class NWConnectionUDPConn: UDPConn {

    private let conn:    NWConnection
    private let remote:  SocksAddr
    private let queue =  DispatchQueue(label: "sing-tun.nwudp", qos: .utility)

    public init(remote: SocksAddr) throws {
        guard let remoteAddr = remote.addr else {
            throw NWConnectionError.invalidAddress
        }
        let host = NWEndpoint.Host(remoteAddr.description)
        let port = NWEndpoint.Port(rawValue: remote.port) ?? .any
        self.conn   = NWConnection(host: host, port: port, using: .udp)
        self.remote = remote
        conn.start(queue: queue)
    }

    deinit { conn.cancel() }

    public func readFrom() throws -> (Data, SocksAddr) {
        var received: Data?
        var recvError: NWError?
        let sema = DispatchSemaphore(value: 0)

        conn.receiveMessage { data, _, _, error in
            received  = data
            recvError = error
            sema.signal()
        }
        sema.wait()

        if let error = recvError { throw error }
        return (received ?? Data(), remote)
    }

    public func writeTo(_ data: Data, addr: SocksAddr) throws {
        var writeError: NWError?
        let sema = DispatchSemaphore(value: 0)

        conn.send(content: data, completion: .contentProcessed { error in
            writeError = error
            sema.signal()
        })
        sema.wait()

        if let error = writeError { throw error }
    }

    public func close() throws {
        conn.cancel()
    }
}

// MARK: - NWConnectionError

public enum NWConnectionError: Error, LocalizedError {
    case invalidAddress

    public var errorDescription: String? {
        switch self {
        case .invalidAddress: return "NWConnectionUDPConn: remote address has no IP component"
        }
    }
}

#endif // canImport(Network)


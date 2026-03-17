// TCP NAT table for the system network stack.
// Mirrors stack_system_nat.go from the Go implementation.

import Foundation

// MARK: - TCPSession

/// Represents one NAT-translated TCP session.
public final class TCPSession {
    public let source:      (addr: IPAddr, port: UInt16)
    public let destination: (addr: IPAddr, port: UInt16)
    public var lastActive:  Date

    private let lock = NSLock()

    public init(source: (IPAddr, UInt16), destination: (IPAddr, UInt16)) {
        self.source      = source
        self.destination = destination
        self.lastActive  = Date()
    }

    public func touch() {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        if now.timeIntervalSince(lastActive) > 1 {
            lastActive = now
        }
    }

    public func isExpired(timeout: TimeInterval) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return Date().timeIntervalSince(lastActive) > timeout
    }
}

// MARK: - TCPNat

/// Maintains a bidirectional mapping between original (source, dest) address
/// pairs and an ephemeral port number used for NAT.
///
/// Mirrors the Go `TCPNat` struct in `stack_system_nat.go`.
public final class TCPNat {
    // MARK: State

    private let timeout: TimeInterval
    private var portIndex: UInt16 = 10000

    private var addrMap: [AddrPortKey: UInt16]      = [:]
    private var portMap: [UInt16: TCPSession]        = [:]

    private let portLock = NSLock()
    private let addrLock = NSLock()

    // MARK: Init

    public init(timeout: TimeInterval) {
        self.timeout = timeout
    }

    // MARK: Public API

    /// Start the background timeout-cleanup loop.
    public func startCleanup(stopSignal: @escaping () -> Bool) {
        Thread.detachNewThread { [weak self] in
            guard let self else { return }
            while !stopSignal() {
                Thread.sleep(forTimeInterval: self.timeout)
                self.checkTimeout()
            }
        }
    }

    /// Look up the NAT port for a returning packet (inbound direction).
    public func lookupBack(port: UInt16) -> TCPSession? {
        portLock.lock()
        let session = portMap[port]
        portLock.unlock()
        session?.touch()
        return session
    }

    /// Translate an outgoing packet: return (or create) the NAT port for
    /// the given (source, destination) pair. The `needRoute` closure is called
    /// once when a new session is created; if it throws, no mapping is stored.
    public func lookup(
        sourceAddr: IPAddr, sourcePort: UInt16,
        destinationAddr: IPAddr, destinationPort: UInt16,
        needRoute: () throws -> Void
    ) throws -> UInt16 {
        let key = AddrPortKey(addr: sourceAddr, port: sourcePort)

        addrLock.lock()
        let existing = addrMap[key]
        addrLock.unlock()

        if let port = existing { return port }

        // Call the route check before creating the mapping.
        try needRoute()

        addrLock.lock()
        defer { addrLock.unlock() }

        // Double-check after acquiring the lock.
        if let port = addrMap[key] { return port }

        let natPort = nextPort()
        addrMap[key] = natPort

        let session = TCPSession(
            source:      (sourceAddr, sourcePort),
            destination: (destinationAddr, destinationPort)
        )
        portLock.lock()
        portMap[natPort] = session
        portLock.unlock()

        return natPort
    }

    // MARK: Private

    private func nextPort() -> UInt16 {
        let port = portIndex
        portIndex = portIndex == UInt16.max ? 10000 : portIndex + 1
        return port
    }

    private func checkTimeout() {
        portLock.lock()
        addrLock.lock()
        defer { portLock.unlock(); addrLock.unlock() }

        for (natPort, session) in portMap where session.isExpired(timeout: timeout) {
            let key = AddrPortKey(addr: session.source.addr, port: session.source.port)
            addrMap.removeValue(forKey: key)
            portMap.removeValue(forKey: natPort)
        }
    }
}

// MARK: - AddrPortKey

private struct AddrPortKey: Hashable {
    let addr: IPAddr
    let port: UInt16
}

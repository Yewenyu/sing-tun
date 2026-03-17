// Internal protocols that abstract the TCP listener / connection pair.
// This lets SystemStack work exclusively with Network.framework's
// NWListener/NWConnection on iOS and macOS.

// MARK: - PortedTCPConn

/// A `TCPConn` that also exposes the remote port number.
/// The remote port is the NAT-assigned ephemeral port and is used by the
/// accept loop to reverse-look-up the original (source, destination) session
/// in the `TCPNat` table.
internal protocol PortedTCPConn: TCPConn {
    var remotePort: UInt16 { get }
}

// MARK: - AnyTCPListener

/// Abstraction over a TCP listener; implemented by `NWListenerTCPListener`
/// (Network.framework) for iOS and macOS.
internal protocol AnyTCPListener: AnyObject {
    /// The port the listener is bound to (available after `start()`).
    var port: UInt16 { get }

    /// Bind and start listening.
    func start() throws

    /// Block until the next inbound connection arrives, then return it.
    /// Returns `nil` when the listener has been stopped.
    func accept() -> PortedTCPConn?

    /// Stop accepting new connections and release the listening socket.
    func stop()
}

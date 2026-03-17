// ICMP ping implementation for Darwin (macOS / iOS).
// Mirrors ping/ping.go and ping/socket_unix.go from the Go implementation.

#if os(macOS) || os(iOS)
import Foundation
import Darwin

// MARK: - PingConn

/// A raw ICMP socket connection that can send echo requests and receive replies.
/// Mirrors the Go `Conn` struct in `ping/ping.go`.
public final class PingConn {

    // MARK: State

    private var sockFd:      Int32 = -1
    private let destination: IPAddr
    private var source:      IPAddr?
    private let isIPv6:      Bool
    private let closed:      AtomicBool = AtomicBool()

    // MARK: Init

    /// Open a raw ICMP socket towards `destination`.
    public init(destination: IPAddr, privileged: Bool = true) throws {
        self.destination = destination
        self.isIPv6      = destination.isV6

        let domain:   Int32 = isIPv6 ? AF_INET6   : AF_INET
        let proto:    Int32 = isIPv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP

        sockFd = socket(domain, SOCK_RAW, proto)
        guard sockFd >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }

        // Connect so that write() / read() are addressed automatically
        if isIPv6 {
            var addr = sockaddr_in6()
            addr.sin6_len    = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = UInt8(AF_INET6)
            withUnsafeMutableBytes(of: &addr.sin6_addr) { ptr in
                destination.rawBytes.withUnsafeBytes { src in ptr.copyMemory(from: src) }
            }
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(sockFd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        } else {
            var addr = sockaddr_in()
            addr.sin_len    = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = UInt8(AF_INET)
            let raw = destination.rawBytes
            addr.sin_addr   = in_addr(s_addr: (UInt32(raw[0]) << 24 | UInt32(raw[1]) << 16
                                              | UInt32(raw[2]) << 8 | UInt32(raw[3])).bigEndian)
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(sockFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    deinit { if sockFd >= 0 { Darwin.close(sockFd) } }

    // MARK: Public API

    /// Store the local (source) address for reconstructing full IP packets
    /// in `readIP`.
    public func setLocalAddr(_ addr: IPAddr) {
        source = addr
    }

    /// Set a read deadline (absolute time).
    public func setReadDeadline(_ date: Date) {
        let interval = max(0, date.timeIntervalSinceNow)
        var tv = timeval(
            tv_sec: __darwin_time_t(interval),
            tv_usec: suseconds_t((interval - floor(interval)) * 1_000_000)
        )
        setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    /// Write a raw ICMP payload (without IP header) to the destination.
    public func writeICMP(_ data: Data) throws {
        var buf = data
        let n   = buf.withUnsafeMutableBytes { ptr in
            Darwin.write(sockFd, ptr.baseAddress!, ptr.count)
        }
        guard n >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
    }

    /// Write a full IP packet; strips the IP header before sending.
    public func writeIP(_ packet: Data) throws {
        let ipPayload: Data
        if isIPv6 {
            guard let ipHdr = IPv6Header(packet) else { return }
            ipPayload = ipHdr.payload
        } else {
            guard let ipHdr = IPv4Header(packet) else { return }
            ipPayload = ipHdr.payload
        }
        try writeICMP(ipPayload)
    }

    /// Read a raw ICMP reply and return it as a complete IP packet.
    public func readIP() throws -> Data {
        var rawBuf = Data(count: 65536)
        var srcAddr = sockaddr_storage()
        var srcLen  = socklen_t(MemoryLayout<sockaddr_storage>.size)

        let n = rawBuf.withUnsafeMutableBytes { payload in
            withUnsafeMutablePointer(to: &srcAddr) { sa in
                sa.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    recvfrom(sockFd, payload.baseAddress!, payload.count, 0, saPtr, &srcLen)
                }
            }
        }
        guard n >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }

        let icmpPayload = rawBuf[rawBuf.startIndex..<(rawBuf.startIndex + n)]
        return buildIPPacket(icmpPayload: icmpPayload, srcAddr: &srcAddr)
    }

    /// Read a raw ICMP reply without an IP header.
    public func readICMP() throws -> Data {
        var buf = Data(count: 65536)
        let n   = buf.withUnsafeMutableBytes { ptr in
            Darwin.read(sockFd, ptr.baseAddress!, ptr.count)
        }
        guard n >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
        return buf[..<n]
    }

    public func close() throws {
        closed.store(true)
        if sockFd >= 0 { Darwin.close(sockFd); sockFd = -1 }
    }

    public var isClosed: Bool { closed.load() }

    // MARK: Private helpers

    private func buildIPPacket(icmpPayload: Data, srcAddr: inout sockaddr_storage) -> Data {
        let replySource: IPAddr
        if srcAddr.ss_family == UInt8(AF_INET) {
            let sin = withUnsafePointer(to: srcAddr) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            }
            replySource = IPAddr(v4: withUnsafeBytes(of: sin.sin_addr.s_addr.bigEndian) { Array($0) })
        } else {
            let sin6 = withUnsafePointer(to: srcAddr) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            }
            replySource = IPAddr(v6: withUnsafeBytes(of: sin6.sin6_addr) { Array($0) })
        }

        let dest = source ?? (isIPv6
            ? IPAddr(v6: [UInt8](repeating: 0, count: 16))
            : IPAddr(v4: [127, 0, 0, 1]))

        if !isIPv6 {
            let totalLen = IPv4Header.minimumSize + icmpPayload.count
            var ipPkt    = Data(count: totalLen)
            ipPkt[0]     = 0x45                             // version=4, IHL=5
            ipPkt[1]     = 0                                // DSCP/ECN
            ipPkt[2]     = UInt8(totalLen >> 8)
            ipPkt[3]     = UInt8(totalLen & 0xFF)
            ipPkt[8]     = 64                               // TTL
            ipPkt[9]     = UInt8(TransportProtocol.icmpV4.rawValue)
            ipPkt.replaceSubrange(12..<16, with: replySource.rawBytes)
            ipPkt.replaceSubrange(16..<20, with: dest.rawBytes)
            // IP checksum
            let cs = internetChecksum(ipPkt[..<20])
            ipPkt[10] = UInt8(cs >> 8); ipPkt[11] = UInt8(cs & 0xFF)
            ipPkt.replaceSubrange(20..., with: icmpPayload)
            return ipPkt
        } else {
            let payloadLen = icmpPayload.count
            var ipPkt      = Data(count: IPv6Header.minimumSize + payloadLen)
            ipPkt[0]       = 0x60   // version=6
            ipPkt[4]       = UInt8(payloadLen >> 8)
            ipPkt[5]       = UInt8(payloadLen & 0xFF)
            ipPkt[6]       = UInt8(TransportProtocol.icmpV6.rawValue)
            ipPkt[7]       = 64     // hop limit
            ipPkt.replaceSubrange(8..<24,  with: replySource.rawBytes)
            ipPkt.replaceSubrange(24..<40, with: dest.rawBytes)
            ipPkt.replaceSubrange(40...,   with: icmpPayload)
            return ipPkt
        }
    }
}

// MARK: - AtomicBool

private final class AtomicBool {
    private var value: Bool = false
    private let lock  = NSLock()

    func store(_ v: Bool) { lock.lock(); value = v; lock.unlock() }
    func load() -> Bool   { lock.lock(); defer { lock.unlock() }; return value }
}

#endif // os(macOS) || os(iOS)

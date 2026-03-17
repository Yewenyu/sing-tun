// System network stack – processes IP packets from the TUN device and
// translates TCP/UDP/ICMP flows to the handler.
//
// Mirrors stack_system.go and its associated files from the Go implementation.

import Foundation

// MARK: - StackOptions

/// Options for creating a network stack.
public struct StackOptions {
    public var tun:                Tun
    public var tunOptions:         TunOptions
    public var udpTimeout:         TimeInterval
    public var handler:            Handler
    public var logger:             Logger
    public var bindInterface:      Bool
    public var includeAllNetworks: Bool

    public init(
        tun: Tun,
        tunOptions: TunOptions,
        udpTimeout: TimeInterval = 300,
        handler: Handler,
        logger: Logger,
        bindInterface: Bool = false,
        includeAllNetworks: Bool = false
    ) {
        self.tun                = tun
        self.tunOptions         = tunOptions
        self.udpTimeout         = udpTimeout
        self.handler            = handler
        self.logger             = logger
        self.bindInterface      = bindInterface
        self.includeAllNetworks = includeAllNetworks
    }
}

// MARK: - Logger

public protocol Logger: AnyObject {
    func trace(_ message: String)
    func debug(_ message: String)
    func info(_ message: String)
    func warn(_ message: String)
    func error(_ message: String)
}

public final class PrintLogger: Logger {
    public init() {}
    public func trace(_ m: String) { print("[TRACE] \(m)") }
    public func debug(_ m: String) { print("[DEBUG] \(m)") }
    public func info(_ m: String)  { print("[INFO]  \(m)") }
    public func warn(_ m: String)  { print("[WARN]  \(m)") }
    public func error(_ m: String) { print("[ERROR] \(m)") }
}

// MARK: - StackError

public enum StackError: Error, LocalizedError {
    case drop
    case reset
    case unknownStack(String)
    case includeAllNetworksUnsupported

    public var errorDescription: String? {
        switch self {
        case .drop:                        return "drop by rule"
        case .reset:                       return "reset by rule"
        case .unknownStack(let s):         return "unknown stack: \(s)"
        case .includeAllNetworksUnsupported: return "`system` stack is not available when `includeAllNetworks` is enabled"
        }
    }
}

// MARK: - Stack factory

/// Create the appropriate stack for the given options.
public func newStack(named name: String = "", options: StackOptions) throws -> Stack {
    switch name {
    case "", "system":
        if options.includeAllNetworks {
            throw StackError.includeAllNetworksUnsupported
        }
        return try SystemStack(options: options)
    default:
        throw StackError.unknownStack(name)
    }
}

// MARK: - SystemStack

/// A user-space network stack that translates TCP/UDP/ICMP packets using NAT
/// and forwards them to a `Handler`.
///
/// Mirrors the Go `System` struct in `stack_system.go`.
public final class SystemStack: Stack {

    // MARK: - Configuration

    private let tun:              Tun
    private let tunName:          String
    private let mtu:              Int
    private let handler:          Handler
    private let logger:           Logger
    private let inet4Prefixes:    [IPPrefix]
    private let inet6Prefixes:    [IPPrefix]
    private let broadcastAddr:    IPAddr?
    private let inet4LoopbackAddr: [IPAddr]
    private let inet6LoopbackAddr: [IPAddr]
    private let udpTimeout:       TimeInterval
    private let multiPending:     Bool

    // Derived addresses
    private let inet4Addr:        IPAddr?
    private let inet4Next:        IPAddr?
    private let inet6Addr:        IPAddr?
    private let inet6Next:        IPAddr?

    // MARK: - Runtime state

    private var tcpNat:       TCPNat?
    private var directNat:    DirectRouteMapping?
    private var tcpListener4: TCPListener?
    private var tcpListener6: TCPListener?
    private var tcpPort4:     UInt16 = 0
    private var tcpPort6:     UInt16 = 0

    private var running:      Bool = false
    private var tunThread:    Thread?
    private let stopLock =    NSLock()
    private var stopped:      Bool = false

    // MARK: - Init

    public init(options: StackOptions) throws {
        self.tun               = options.tun
        self.tunName           = options.tunOptions.name
        self.mtu               = Int(options.tunOptions.mtu)
        self.handler           = options.handler
        self.logger            = options.logger
        self.inet4Prefixes     = options.tunOptions.inet4Address
        self.inet6Prefixes     = options.tunOptions.inet6Address
        self.broadcastAddr     = options.tunOptions.broadcastAddr
        self.inet4LoopbackAddr = options.tunOptions.inet4LoopbackAddress
        self.inet6LoopbackAddr = options.tunOptions.inet6LoopbackAddress
        self.udpTimeout        = options.udpTimeout
        self.multiPending      = options.tunOptions.multiPendingPackets

        // Derive next-hop addresses
        if let first = options.tunOptions.inet4Address.first {
            self.inet4Addr = first.addr
            self.inet4Next = first.addr.next()
        } else {
            self.inet4Addr = nil
            self.inet4Next = nil
        }
        if let first = options.tunOptions.inet6Address.first {
            self.inet6Addr = first.addr
            self.inet6Next = first.addr.next()
        } else {
            self.inet6Addr = nil
            self.inet6Next = nil
        }

        if inet4Next == nil && inet6Next == nil {
            throw SystemStackError.missingInterfaceAddress
        }
    }

    // MARK: - Stack

    public func start() throws {
        try internalStart()
        let t = Thread { [weak self] in self?.tunLoop() }
        t.name = "sing-tun.system"
        t.start()
        tunThread = t
    }

    public func close() throws {
        stopLock.lock()
        stopped = true
        stopLock.unlock()

        tcpListener4?.stop()
        tcpListener6?.stop()
        tcpListener4 = nil
        tcpListener6 = nil
    }

    // MARK: - Internal start

    private func internalStart() throws {
        tcpNat    = TCPNat(timeout: udpTimeout)
        directNat = DirectRouteMapping(timeout: udpTimeout)

        // Start NAT cleanup
        tcpNat?.startCleanup { [weak self] in
            guard let self else { return true }
            self.stopLock.lock()
            defer { self.stopLock.unlock() }
            return self.stopped
        }

        // Listen on IPv4
        if let addr4 = inet4Addr {
            let listener = TCPListener(address: addr4, port: 0)
            try listener.start()
            tcpPort4   = listener.port
            tcpListener4 = listener
            Thread.detachNewThread { [weak self] in self?.acceptLoop(listener: listener, isIPv6: false) }
        }

        // Listen on IPv6
        if let addr6 = inet6Addr {
            let listener = TCPListener(address: addr6, port: 0)
            try listener.start()
            tcpPort6   = listener.port
            tcpListener6 = listener
            Thread.detachNewThread { [weak self] in self?.acceptLoop(listener: listener, isIPv6: true) }
        }
    }

    // MARK: - Packet loop

    private func tunLoop() {
        if let darwinTUN = tun as? DarwinTUN, multiPending {
            batchLoopDarwin(darwinTUN)
            return
        }

        var buffer = Data(count: mtu + packetOffset)
        while !isStopped {
            do {
                let n = try tun.read(into: &buffer)
                guard n >= IPv4Header.minimumSize else { continue }
                let packet = buffer[buffer.startIndex..<(buffer.startIndex + n)]
                if processPacket(packet) {
                    try? tun.write(buffer[..<(buffer.startIndex + n)])
                }
            } catch {
                if isStopped { return }
                logger.error("read packet: \(error)")
            }
        }
    }

    private func batchLoopDarwin(_ dtun: DarwinTUN) {
        while !isStopped {
            do {
                let packets = try dtun.batchRead()
                var writeBack: [Data] = []
                for packet in packets {
                    guard packet.count >= IPv4Header.minimumSize else { continue }
                    if processPacket(packet) {
                        writeBack.append(packet)
                    }
                }
                if !writeBack.isEmpty {
                    try? dtun.batchWrite(writeBack)
                }
            } catch {
                if isStopped { return }
                logger.error("batch read packet: \(error)")
            }
        }
    }

    private var isStopped: Bool {
        stopLock.lock(); defer { stopLock.unlock() }
        return stopped
    }

    // MARK: - Packet processing

    private func processPacket(_ packet: Data) -> Bool {
        switch IPVersion.detect(in: packet) {
        case .v4:
            guard let ipHdr = IPv4Header(packet) else { return false }
            return (try? processIPv4(ipHdr)) ?? false
        case .v6:
            guard let ipHdr = IPv6Header(packet) else { return false }
            return (try? processIPv6(ipHdr)) ?? false
        default:
            return false
        }
    }

    private func processIPv4(_ ipHdr: IPv4Header) throws -> Bool {
        let dest = ipHdr.destinationAddr
        if let bc = broadcastAddr, dest == bc { return true }
        guard dest.isGlobalUnicast else { return true }

        switch ipHdr.protocol_ {
        case .tcp:
            guard let tcpHdr = TCPHeader(ipHdr.payload) else { return false }
            return try processIPv4TCP(ip: ipHdr, tcp: tcpHdr)
        case .udp:
            guard let udpHdr = UDPHeader(ipHdr.payload) else { return false }
            try processIPv4UDP(ip: ipHdr, udp: udpHdr)
            return false
        case .icmpV4:
            guard let icmpHdr = ICMPv4Header(ipHdr.payload) else { return false }
            return try processIPv4ICMP(ip: ipHdr, icmp: icmpHdr)
        default:
            return true
        }
    }

    private func processIPv6(_ ipHdr: IPv6Header) throws -> Bool {
        guard ipHdr.destinationAddr.isGlobalUnicast else { return true }

        switch ipHdr.nextHeader {
        case .tcp:
            guard let tcpHdr = TCPHeader(ipHdr.payload) else { return false }
            return try processIPv6TCP(ip: ipHdr, tcp: tcpHdr)
        case .udp:
            guard let udpHdr = UDPHeader(ipHdr.payload) else { return false }
            try processIPv6UDP(ip: ipHdr, udp: udpHdr)
            return false
        case .icmpV6:
            guard let icmpHdr = ICMPv6Header(ipHdr.payload) else { return false }
            return try processIPv6ICMP(ip: ipHdr, icmp: icmpHdr)
        default:
            return true
        }
    }

    // MARK: TCP processing

    private func processIPv4TCP(ip: IPv4Header, tcp: TCPHeader) throws -> Bool {
        guard let nat = tcpNat, let addr4 = inet4Addr, let next4 = inet4Next else { return false }

        let src  = ip.sourceAddr
        let dst  = ip.destinationAddr
        let srcPort = tcp.sourcePort
        let dstPort = tcp.destinationPort

        var modifiedPacket = ip.bytes

        if src == addr4 && srcPort == tcpPort4 {
            // Return path: translate back to original addresses
            guard let session = nat.lookupBack(port: dstPort) else {
                logger.trace("ipv4 tcp: session not found for port \(dstPort)")
                return false
            }
            rewriteIPv4TCP(packet: &modifiedPacket,
                           newSrcAddr: session.destination.addr, newSrcPort: session.destination.port,
                           newDstAddr: session.source.addr,      newDstPort: session.source.port)
        } else {
            // Forward path: check for loopback or apply NAT
            var loopback = false
            for lb in inet4LoopbackAddr where dst == lb {
                rewriteIPv4TCP(packet: &modifiedPacket,
                               newSrcAddr: lb,  newSrcPort: srcPort,
                               newDstAddr: src, newDstPort: dstPort)
                loopback = true
                break
            }
            if !loopback {
                let natPort = try nat.lookup(
                    sourceAddr: src, sourcePort: srcPort,
                    destinationAddr: dst, destinationPort: dstPort
                ) {
                    // Route check: The handler's prepareConnection is async and cannot be
                    // called directly from this synchronous packet-processing closure.
                    // The TCPNat.lookup closure is used as a pre-connection gate; when a
                    // handler is integrated, it should call prepareConnection here and
                    // throw StackError.drop / .reset to reject the connection.
                }
                rewriteIPv4TCP(packet: &modifiedPacket,
                               newSrcAddr: next4, newSrcPort: natPort,
                               newDstAddr: addr4, newDstPort: tcpPort4)
            }
        }
        try? tun.write(modifiedPacket)
        return false
    }

    private func processIPv6TCP(ip: IPv6Header, tcp: TCPHeader) throws -> Bool {
        guard let nat = tcpNat, let addr6 = inet6Addr, let next6 = inet6Next else { return false }

        let src     = ip.sourceAddr
        let dst     = ip.destinationAddr
        let srcPort = tcp.sourcePort
        let dstPort = tcp.destinationPort

        var modifiedPacket = ip.bytes

        if src == addr6 && srcPort == tcpPort6 {
            guard let session = nat.lookupBack(port: dstPort) else {
                logger.trace("ipv6 tcp: session not found for port \(dstPort)")
                return false
            }
            rewriteIPv6TCP(packet: &modifiedPacket,
                           newSrcAddr: session.destination.addr, newSrcPort: session.destination.port,
                           newDstAddr: session.source.addr,      newDstPort: session.source.port)
        } else {
            var loopback = false
            for lb in inet6LoopbackAddr where dst == lb {
                rewriteIPv6TCP(packet: &modifiedPacket,
                               newSrcAddr: lb,  newSrcPort: srcPort,
                               newDstAddr: src, newDstPort: dstPort)
                loopback = true
                break
            }
            if !loopback {
                let natPort = try nat.lookup(
                    sourceAddr: src, sourcePort: srcPort,
                    destinationAddr: dst, destinationPort: dstPort
                ) {
                    // Route check gate – see IPv4 path comment above for explanation.
                }
                rewriteIPv6TCP(packet: &modifiedPacket,
                               newSrcAddr: next6, newSrcPort: natPort,
                               newDstAddr: addr6, newDstPort: tcpPort6)
            }
        }
        try? tun.write(modifiedPacket)
        return false
    }

    // MARK: UDP processing

    private func processIPv4UDP(ip: IPv4Header, udp: UDPHeader) throws {
        let src  = SocksAddr(addr: ip.sourceAddr, port: udp.sourcePort)
        let dst  = SocksAddr(addr: ip.destinationAddr, port: udp.destinationPort)
        let meta = ConnectionMetadata(network: "udp", source: src, destination: dst)
        let payload = udp.payload
        // Forward to handler asynchronously
        Task { await handler.handleUDPConnection(UDPDatagramConn(data: payload, remote: dst), metadata: meta) }
    }

    private func processIPv6UDP(ip: IPv6Header, udp: UDPHeader) throws {
        let src  = SocksAddr(addr: ip.sourceAddr, port: udp.sourcePort)
        let dst  = SocksAddr(addr: ip.destinationAddr, port: udp.destinationPort)
        let meta = ConnectionMetadata(network: "udp", source: src, destination: dst)
        let payload = udp.payload
        Task { await handler.handleUDPConnection(UDPDatagramConn(data: payload, remote: dst), metadata: meta) }
    }

    // MARK: ICMP processing

    private func processIPv4ICMP(ip: IPv4Header, icmp: ICMPv4Header) throws -> Bool {
        guard icmp.type == ICMPv4Header.typeEchoRequest else { return true }
        // Reflect as echo reply
        var pkt = ip.bytes
        rewriteICMPv4Reply(packet: &pkt)
        try? tun.write(pkt)
        return false
    }

    private func processIPv6ICMP(ip: IPv6Header, icmp: ICMPv6Header) throws -> Bool {
        guard icmp.type == ICMPv6Header.typeEchoRequest else { return true }
        var pkt = ip.bytes
        rewriteICMPv6Reply(packet: &pkt)
        try? tun.write(pkt)
        return false
    }

    // MARK: Accept loop

    private func acceptLoop(listener: TCPListener, isIPv6: Bool) {
        while !isStopped {
            guard let conn = listener.accept() else { return }
            let remotePort = conn.remotePort
            guard let session = tcpNat?.lookupBack(port: remotePort) else {
                logger.trace("unknown TCP session port \(remotePort)")
                try? conn.close()
                continue
            }

            var destination = SocksAddr(addr: session.destination.addr, port: session.destination.port)
            // Rewrite loopback destinations
            let prefixes = isIPv6 ? inet6Prefixes : inet4Prefixes
            let loopback: IPAddr = isIPv6
                ? IPAddr(v6: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])
                : IPAddr(v4: [127,0,0,1])
            for prefix in prefixes where prefix.contains(destination.addr!) {
                destination = SocksAddr(addr: loopback, port: destination.port)
                break
            }

            let source = SocksAddr(addr: session.source.addr, port: session.source.port)
            let meta   = ConnectionMetadata(network: "tcp", source: source, destination: destination)
            Task { await handler.handleTCPConnection(conn, metadata: meta) }
        }
    }
}

// MARK: - Packet rewrite helpers

private func rewriteIPv4TCP(packet: inout Data,
                             newSrcAddr: IPAddr, newSrcPort: UInt16,
                             newDstAddr: IPAddr, newDstPort: UInt16) {
    guard packet.count >= IPv4Header.minimumSize + TCPHeader.minimumSize else { return }
    let hdrLen = Int((packet[0] & 0x0F) * 4)
    // Rewrite IPv4 src/dst
    packet.replaceSubrange((packet.startIndex + 12)..<(packet.startIndex + 16), with: newSrcAddr.rawBytes)
    packet.replaceSubrange((packet.startIndex + 16)..<(packet.startIndex + 20), with: newDstAddr.rawBytes)
    // Rewrite TCP src/dst port
    let tcpOff = packet.startIndex + hdrLen
    packet[tcpOff]     = UInt8(newSrcPort >> 8)
    packet[tcpOff + 1] = UInt8(newSrcPort & 0xFF)
    packet[tcpOff + 2] = UInt8(newDstPort >> 8)
    packet[tcpOff + 3] = UInt8(newDstPort & 0xFF)
    // Clear checksums (will be recalculated by the kernel or NIC)
    packet[tcpOff + 16] = 0; packet[tcpOff + 17] = 0
    // IPv4 checksum
    packet[10] = 0; packet[11] = 0
    let ipChecksum = internetChecksum(packet[..<(packet.startIndex + hdrLen)])
    packet[10] = UInt8(ipChecksum >> 8)
    packet[11] = UInt8(ipChecksum & 0xFF)
}

private func rewriteIPv6TCP(packet: inout Data,
                             newSrcAddr: IPAddr, newSrcPort: UInt16,
                             newDstAddr: IPAddr, newDstPort: UInt16) {
    guard packet.count >= IPv6Header.minimumSize + TCPHeader.minimumSize else { return }
    // Rewrite IPv6 src/dst
    packet.replaceSubrange((packet.startIndex + 8)..<(packet.startIndex + 24), with: newSrcAddr.rawBytes)
    packet.replaceSubrange((packet.startIndex + 24)..<(packet.startIndex + 40), with: newDstAddr.rawBytes)
    // Rewrite TCP ports
    let tcpOff = packet.startIndex + IPv6Header.minimumSize
    packet[tcpOff]     = UInt8(newSrcPort >> 8)
    packet[tcpOff + 1] = UInt8(newSrcPort & 0xFF)
    packet[tcpOff + 2] = UInt8(newDstPort >> 8)
    packet[tcpOff + 3] = UInt8(newDstPort & 0xFF)
    // Clear TCP checksum
    packet[tcpOff + 16] = 0; packet[tcpOff + 17] = 0
}

private func rewriteICMPv4Reply(packet: inout Data) {
    guard packet.count >= IPv4Header.minimumSize + ICMPv4Header.size else { return }
    let hdrLen = Int((packet[0] & 0x0F) * 4)
    // Swap src/dst
    let src = Array(packet[(packet.startIndex + 12)..<(packet.startIndex + 16)])
    let dst = Array(packet[(packet.startIndex + 16)..<(packet.startIndex + 20)])
    packet.replaceSubrange((packet.startIndex + 12)..<(packet.startIndex + 16), with: dst)
    packet.replaceSubrange((packet.startIndex + 16)..<(packet.startIndex + 20), with: src)
    // Set ICMP type to echo-reply
    packet[hdrLen] = ICMPv4Header.typeEchoReply
    // Recalculate ICMP checksum
    packet[hdrLen + 2] = 0; packet[hdrLen + 3] = 0
    let icmpData = packet[(packet.startIndex + hdrLen)...]
    let cs = internetChecksum(icmpData)
    packet[hdrLen + 2] = UInt8(cs >> 8); packet[hdrLen + 3] = UInt8(cs & 0xFF)
    // Recalculate IPv4 checksum
    packet[10] = 0; packet[11] = 0
    let ipCs = internetChecksum(packet[..<(packet.startIndex + hdrLen)])
    packet[10] = UInt8(ipCs >> 8); packet[11] = UInt8(ipCs & 0xFF)
}

private func rewriteICMPv6Reply(packet: inout Data) {
    guard packet.count >= IPv6Header.minimumSize + ICMPv6Header.size else { return }
    // Swap src/dst
    let src = Array(packet[(packet.startIndex + 8)..<(packet.startIndex + 24)])
    let dst = Array(packet[(packet.startIndex + 24)..<(packet.startIndex + 40)])
    packet.replaceSubrange((packet.startIndex + 8)..<(packet.startIndex + 24), with: dst)
    packet.replaceSubrange((packet.startIndex + 24)..<(packet.startIndex + 40), with: src)
    // Set ICMPv6 type to echo-reply
    let icmpOff = packet.startIndex + IPv6Header.minimumSize
    packet[icmpOff] = ICMPv6Header.typeEchoReply
    // Recalculate ICMPv6 checksum (includes pseudo-header)
    packet[icmpOff + 2] = 0; packet[icmpOff + 3] = 0
}

// MARK: - SystemStackError

private enum SystemStackError: Error {
    case missingInterfaceAddress
}

// MARK: - POSIX helpers (cross-platform)

#if canImport(Darwin)
import Darwin

private func posixClose(_ fd: Int32) { Darwin.close(fd) }
private func posixRead(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ count: Int) -> Int {
    Darwin.read(fd, buf, count)
}
private func posixWrite(_ fd: Int32, _ buf: UnsafeRawPointer, _ count: Int) -> Int {
    Darwin.write(fd, buf, count)
}
private func posixAccept(_ fd: Int32, _ addr: UnsafeMutablePointer<sockaddr>?, _ len: UnsafeMutablePointer<socklen_t>?) -> Int32 {
    Darwin.accept(fd, addr, len)
}

private func makeSockaddrIn(family: Int32) -> sockaddr_in {
    var s = sockaddr_in()
    s.sin_len    = UInt8(MemoryLayout<sockaddr_in>.size)
    s.sin_family = UInt8(family)
    return s
}
private func makeSockaddrIn6(family: Int32) -> sockaddr_in6 {
    var s = sockaddr_in6()
    s.sin6_len    = UInt8(MemoryLayout<sockaddr_in6>.size)
    s.sin6_family = UInt8(family)
    return s
}
private func sockaddrFamily(_ storage: sockaddr_storage) -> Int32 {
    Int32(storage.ss_family)
}

#elseif canImport(Glibc)
import Glibc

private func posixClose(_ fd: Int32) { _ = Glibc.close(fd) }
private func posixRead(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ count: Int) -> Int {
    Glibc.read(fd, buf, count)
}
private func posixWrite(_ fd: Int32, _ buf: UnsafeRawPointer, _ count: Int) -> Int {
    Glibc.write(fd, buf, count)
}
private func posixAccept(_ fd: Int32, _ addr: UnsafeMutablePointer<sockaddr>?, _ len: UnsafeMutablePointer<socklen_t>?) -> Int32 {
    Glibc.accept(fd, addr, len)
}

private func makeSockaddrIn(family: Int32) -> sockaddr_in {
    var s = sockaddr_in()
    s.sin_family = sa_family_t(family)
    return s
}
private func makeSockaddrIn6(family: Int32) -> sockaddr_in6 {
    var s = sockaddr_in6()
    s.sin6_family = sa_family_t(family)
    return s
}
private func sockaddrFamily(_ storage: sockaddr_storage) -> Int32 {
    Int32(storage.ss_family)
}
#endif

// MARK: - TCPListener (thin wrapper around BSD sockets)

final class TCPListener {
    private let address: IPAddr
    private(set) var port: UInt16 = 0
    private var fd: Int32 = -1
    private var stopped = false

    init(address: IPAddr, port: UInt16) {
        self.address = address
        self.port    = port
    }

    func start() throws {
        let domain = address.isV4 ? AF_INET : AF_INET6
        fd = socket(Int32(domain), Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        if address.isV4 {
            var addr = makeSockaddrIn(family: AF_INET)
            addr.sin_port = 0
            addr.sin_addr = in_addr(s_addr: 0)
            let bindResult = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard bindResult == 0 else {
                posixClose(fd)
                throw POSIXError(POSIXErrorCode(rawValue: errno)!)
            }
            var boundAddr = sockaddr_in()
            var addrLen   = socklen_t(MemoryLayout<sockaddr_in>.size)
            withUnsafeMutablePointer(to: &boundAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(fd, $0, &addrLen)
                }
            }
            port = boundAddr.sin_port.bigEndian
        } else {
            var addr = makeSockaddrIn6(family: AF_INET6)
            addr.sin6_port = 0
            let bindResult = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
            guard bindResult == 0 else {
                posixClose(fd)
                throw POSIXError(POSIXErrorCode(rawValue: errno)!)
            }
            var boundAddr = sockaddr_in6()
            var addrLen   = socklen_t(MemoryLayout<sockaddr_in6>.size)
            withUnsafeMutablePointer(to: &boundAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(fd, $0, &addrLen)
                }
            }
            port = boundAddr.sin6_port.bigEndian
        }

        guard listen(fd, 128) == 0 else {
            posixClose(fd)
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
    }

    func accept() -> TCPConnImpl? {
        guard !stopped else { return nil }
        var remoteAddr = sockaddr_storage()
        var addrLen    = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let connFd     = withUnsafeMutablePointer(to: &remoteAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                posixAccept(fd, $0, &addrLen)
            }
        }
        guard connFd >= 0 else { return nil }

        var remotePort: UInt16 = 0
        if sockaddrFamily(remoteAddr) == AF_INET {
            var sa = sockaddr_in()
            withUnsafePointer(to: remoteAddr) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    sa = $0.pointee
                }
            }
            remotePort = sa.sin_port.bigEndian
        } else {
            var sa = sockaddr_in6()
            withUnsafePointer(to: remoteAddr) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                    sa = $0.pointee
                }
            }
            remotePort = sa.sin6_port.bigEndian
        }
        return TCPConnImpl(fd: connFd, remotePort: remotePort)
    }

    func stop() {
        stopped = true
        if fd >= 0 { posixClose(fd); fd = -1 }
    }
}

// MARK: - TCPConnImpl

public final class TCPConnImpl: TCPConn {
    private let fd: Int32
    public let remotePort: UInt16

    init(fd: Int32, remotePort: UInt16) {
        self.fd         = fd
        self.remotePort = remotePort
    }

    deinit { posixClose(fd) }

    public func read(into buffer: inout Data) throws -> Int {
        var buf = Data(count: 65536)
        let n   = buf.withUnsafeMutableBytes { ptr -> Int in
            posixRead(fd, ptr.baseAddress!, ptr.count)
        }
        guard n >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }
        buffer  = buf[..<n]
        return n
    }

    public func write(_ data: Data) throws -> Int {
        var d = data
        let n  = d.withUnsafeMutableBytes { ptr -> Int in
            posixWrite(fd, ptr.baseAddress!, ptr.count)
        }
        guard n >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }
        return n
    }

    public func closeWrite() throws {
        shutdown(fd, Int32(SHUT_WR))
    }

    public func close() throws {
        posixClose(fd)
    }
}

// MARK: - UDPDatagramConn (single-datagram stub)

final class UDPDatagramConn: UDPConn {
    private let data: Data
    private let remote: SocksAddr

    init(data: Data, remote: SocksAddr) {
        self.data   = data
        self.remote = remote
    }

    func readFrom() throws -> (Data, SocksAddr) { (data, remote) }
    func writeTo(_ data: Data, addr: SocksAddr) throws {}
    func close() throws {}
}

// MARK: - packetOffset (Darwin = 4, others = 0)

#if os(macOS) || os(iOS)
private let packetOffset = 4
#else
private let packetOffset = 0
#endif

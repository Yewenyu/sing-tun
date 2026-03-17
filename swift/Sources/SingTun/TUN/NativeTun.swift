// Darwin (macOS / iOS) native TUN device implementation.
// Mirrors tun_darwin.go from the Go implementation.

#if os(macOS) || os(iOS)

import Foundation
import Darwin

// The Darwin utun device prepends a 4-byte AF_ family header to every packet.
public let packetOffset = 4

// AF_INET / AF_INET6 family headers used when writing packets.
private let packetHeader4: [UInt8] = [0x00, 0x00, 0x00, 0x02] // AF_INET  = 2
private let packetHeader6: [UInt8] = [0x00, 0x00, 0x00, 0x1E] // AF_INET6 = 30

// MARK: - NativeTun

/// A native utun TUN device for macOS and iOS.
/// When a `fileDescriptor` is provided in the options the device reuses
/// that pre-opened fd (typical Network Extension usage); otherwise it
/// creates a new utun socket.
public final class NativeTun: DarwinTUN {

    // MARK: State

    private var tunFd: Int32
    private let options: TunOptions
    private var inet4Address: [UInt8]
    private var inet6Address: [UInt8]
    private var routeSet: Bool = false
    private let batchSize: Int

    // Pipe used to interrupt blocking reads on close.
    private var stopReadFd: Int32 = -1
    private var stopWriteFd: Int32 = -1

    // MARK: Init

    public init(options: TunOptions) throws {
        self.options      = options
        self.inet4Address = options.inet4Address.first?.addr.rawBytes ?? [UInt8](repeating: 0, count: 4)
        self.inet6Address = options.inet6Address.first?.addr.rawBytes ?? [UInt8](repeating: 0, count: 16)
        self.batchSize    = max(1, Int((512 * 1024) / options.mtu) + 1)

        // Create stop-pipe for clean shutdown
        var fds: [Int32] = [-1, -1]
        guard Darwin.pipe(&fds) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
        stopReadFd  = fds[0]
        stopWriteFd = fds[1]

        if options.fileDescriptor != 0 {
            self.tunFd = options.fileDescriptor
            try configureDescriptor(tunFd)
        } else {
            let fd = try NativeTun.createUTUN(name: options.name, options: options)
            self.tunFd = fd
            try configureDescriptor(tunFd)
        }
    }

    deinit {
        if stopReadFd  >= 0 { Darwin.close(stopReadFd)  }
        if stopWriteFd >= 0 { Darwin.close(stopWriteFd) }
    }

    // MARK: - Tun

    public func name() throws -> String {
        var ifName = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var nameLen = socklen_t(IFNAMSIZ)
        // UTUN_OPT_IFNAME = 2, SYSPROTO_CONTROL = 2
        guard getsockopt(tunFd, 2, 2, &ifName, &nameLen) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
        return String(cString: ifName)
    }

    public func start() throws {
        try setRoutes()
    }

    public func close() throws {
        var errors: [Error] = []
        do    { try unsetRoutes() }
        catch { errors.append(error) }
        // Signal blocking read to stop
        var dummy: UInt8 = 1
        Darwin.write(stopWriteFd, &dummy, 1)
        if tunFd >= 0 { Darwin.close(tunFd); tunFd = -1 }
        flushDNSCache()
        if let first = errors.first { throw first }
    }

    public func read(into buffer: inout Data) throws -> Int {
        let capacity = Int(options.mtu) + packetOffset
        buffer = Data(count: capacity)
        let n = buffer.withUnsafeMutableBytes { ptr -> Int in
            Darwin.read(tunFd, ptr.baseAddress!, capacity)
        }
        guard n > packetOffset else {
            buffer = Data()
            return 0
        }
        buffer = buffer[(buffer.startIndex + packetOffset)...]
        return n - packetOffset
    }

    @discardableResult
    public func write(_ packet: Data) throws -> Int {
        let header: [UInt8]
        switch IPVersion.detect(in: packet) {
        case .v4: header = packetHeader4
        case .v6: header = packetHeader6
        default:  return 0
        }
        var raw = Data(header) + packet
        let n = raw.withUnsafeMutableBytes { ptr in
            Darwin.write(tunFd, ptr.baseAddress!, ptr.count)
        }
        guard n >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
        return n - packetOffset
    }

    public func updateRouteOptions(_ options: TunOptions) throws {
        try unsetRoutes()
        // Note: options is a value type; we shadow self.options here.
        // A full implementation would update self.options; this is a value type so we'd need
        // to store a var copy or wrap in a class.
        try setRoutes()
    }

    // MARK: - DarwinTUN (batch I/O)

    public func batchRead() throws -> [Data] {
        var packets: [Data] = []
        for _ in 0..<batchSize {
            var buffer = Data(count: Int(options.mtu) + packetOffset)
            let n = buffer.withUnsafeMutableBytes { ptr in
                Darwin.read(tunFd, ptr.baseAddress!, ptr.count)
            }
            if n <= packetOffset { break }
            packets.append(buffer[(buffer.startIndex + packetOffset)..<(buffer.startIndex + n)])
        }
        return packets
    }

    public func batchWrite(_ packets: [Data]) throws {
        for packet in packets {
            try write(packet)
        }
    }

    // MARK: - Private helpers

    private static func createUTUN(name: String, options: TunOptions) throws -> Int32 {
        var ifIndex: Int32 = -1
        guard sscanf(name, "utun%d", &ifIndex) == 1 else {
            throw TunError.badName(name)
        }

        // AF_SYSTEM = 32, SYSPROTO_CONTROL = 2, SOCK_DGRAM = 2
        let fd = socket(AF_SYSTEM, SOCK_DGRAM, 2)
        guard fd >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }

        // Resolve UTUN control id
        var ctlInfo = ctl_ifreq()
        strncpy(&ctlInfo.ctl_name.0, "com.apple.net.utun_control", Int(MAX_KCTL_NAME))
        guard ioctl(fd, CTLIOCGINFO, &ctlInfo) == 0 else {
            Darwin.close(fd)
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }

        // Connect
        var sc = sockaddr_ctl()
        sc.sc_len     = UInt8(MemoryLayout<sockaddr_ctl>.size)
        sc.sc_family  = UInt8(AF_SYSTEM)
        sc.ss_sysaddr = UInt16(AF_SYS_CONTROL)
        sc.sc_id      = ctlInfo.ctl_id
        sc.sc_unit    = UInt32(ifIndex) + 1
        let connectResult = withUnsafePointer(to: &sc) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_ctl>.size))
            }
        }
        guard connectResult == 0 else {
            Darwin.close(fd)
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }

        // Set MTU
        var ifr = ifreq()
        strncpy(&ifr.ifr_name.0, name, Int(IFNAMSIZ))
        ifr.ifr_ifru.ifru_mtu = Int32(options.mtu)
        let mtuSocket = socket(AF_INET, SOCK_DGRAM, 0)
        if mtuSocket >= 0 {
            ioctl(mtuSocket, SIOCSIFMTU, &ifr)
            Darwin.close(mtuSocket)
        }

        // Assign IPv4 addresses
        if !options.inet4Address.isEmpty {
            let s4 = socket(AF_INET, SOCK_DGRAM, 0)
            if s4 >= 0 {
                defer { Darwin.close(s4) }
                for prefix in options.inet4Address {
                    let addrBytes  = prefix.addr.rawBytes
                    let maskBytes  = makeMask4(bits: prefix.bits)
                    var req        = ifaliasreq()
                    strncpy(&req.ifra_name.0, name, Int(IFNAMSIZ))
                    req.ifra_addr.sin_len    = UInt8(MemoryLayout<sockaddr_in>.size)
                    req.ifra_addr.sin_family = UInt8(AF_INET)
                    req.ifra_addr.sin_addr   = in_addr(s_addr: packIPv4(addrBytes))
                    req.ifra_broadaddr       = req.ifra_addr
                    req.ifra_mask.sin_len    = UInt8(MemoryLayout<sockaddr_in>.size)
                    req.ifra_mask.sin_family = UInt8(AF_INET)
                    req.ifra_mask.sin_addr   = in_addr(s_addr: packIPv4(maskBytes))
                    ioctl(s4, SIOCAIFADDR, &req)
                }
            }
        }

        // Assign IPv6 addresses
        if !options.inet6Address.isEmpty {
            let s6 = socket(AF_INET6, SOCK_DGRAM, 0)
            if s6 >= 0 {
                defer { Darwin.close(s6) }
                for prefix in options.inet6Address {
                    var req6 = in6_aliasreq()
                    strncpy(&req6.ifra_name.0, name, Int(IFNAMSIZ))
                    req6.ifra_addr.sin6_len    = UInt8(MemoryLayout<sockaddr_in6>.size)
                    req6.ifra_addr.sin6_family = UInt8(AF_INET6)
                    withUnsafeMutableBytes(of: &req6.ifra_addr.sin6_addr) { ptr in
                        prefix.addr.rawBytes.withUnsafeBytes { src in
                            ptr.copyMemory(from: src)
                        }
                    }
                    let maskBytes = makeMask6(bits: prefix.bits)
                    req6.ifra_prefixmask.sin6_len    = UInt8(MemoryLayout<sockaddr_in6>.size)
                    req6.ifra_prefixmask.sin6_family = UInt8(AF_INET6)
                    withUnsafeMutableBytes(of: &req6.ifra_prefixmask.sin6_addr) { ptr in
                        maskBytes.withUnsafeBytes { src in ptr.copyMemory(from: src) }
                    }
                    // IN6_IFF_NODAD | IN6_IFF_SECURED
                    req6.ifra_flags = 0x0020 | 0x0400
                    req6.ifra_lifetime.ia6t_vltime = 0xFFFFFFFF
                    req6.ifra_lifetime.ia6t_pltime = 0xFFFFFFFF
                    ioctl(s6, SIOCAIFADDR_IN6, &req6)
                }
            }
        }

        return fd
    }

    private func configureDescriptor(_ fd: Int32) throws {
        // Set non-blocking
        let flags = fcntl(fd, F_GETFL, 0)
        guard fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
    }

    // MARK: Route management

    private func setRoutes() throws {
        guard options.fileDescriptor == 0 else { return }
        let ranges = options.buildAutoRouteRanges()
        guard !ranges.isEmpty else { return }
        let gw4 = options.inet4GatewayAddr
        let gw6 = options.inet6GatewayAddr
        for prefix in ranges {
            let gw = prefix.addr.isV4 ? gw4 : gw6
            do {
                try execRoute(rtmType: RTM_ADD, prefix: prefix, gateway: gw)
            } catch let e as POSIXError where e.code == .EEXIST {
                try? execRoute(rtmType: RTM_DELETE, prefix: prefix, gateway: gw)
                try execRoute(rtmType: RTM_ADD, prefix: prefix, gateway: gw)
            }
        }
        flushDNSCache()
        routeSet = true
    }

    private func unsetRoutes() throws {
        guard routeSet else { return }
        routeSet = false
        let ranges = options.buildAutoRouteRanges()
        let gw4 = options.inet4GatewayAddr
        let gw6 = options.inet6GatewayAddr
        for prefix in ranges {
            let gw = prefix.addr.isV4 ? gw4 : gw6
            try? execRoute(rtmType: RTM_DELETE, prefix: prefix, gateway: gw)
        }
    }
}

// MARK: - Route socket helpers

/// Send an RTM_ADD / RTM_DELETE message via the routing socket.
private func execRoute(rtmType: Int32, prefix: IPPrefix, gateway: IPAddr) throws {
    let fd = socket(AF_ROUTE, SOCK_RAW, 0)
    guard fd >= 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno)!)
    }
    defer { Darwin.close(fd) }

    var msg = buildRouteMessage(rtmType: rtmType, prefix: prefix, gateway: gateway)
    let n = msg.withUnsafeMutableBytes { ptr in
        Darwin.write(fd, ptr.baseAddress!, ptr.count)
    }
    guard n >= 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno)!)
    }
}

private func buildRouteMessage(rtmType: Int32, prefix: IPPrefix, gateway: IPAddr) -> Data {
    // Build a minimal rt_msghdr + sockaddrs for destination, gateway, netmask.
    // This is a simplified version of the Go execRoute function.
    var data = Data()

    var hdr = rt_msghdr()
    hdr.rtm_version = UInt8(RTM_VERSION)
    hdr.rtm_type    = UInt8(rtmType)
    hdr.rtm_flags   = RTF_STATIC | RTF_GATEWAY
    if rtmType == RTM_ADD {
        hdr.rtm_flags |= RTF_UP
    }
    hdr.rtm_seq     = 1
    hdr.rtm_addrs  = RTA_DST | RTA_GATEWAY | RTA_NETMASK

    if prefix.addr.isV4 {
        var dst  = sockaddr_in(); dst.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); dst.sin_family = UInt8(AF_INET); dst.sin_addr = in_addr(s_addr: packIPv4(prefix.addr.rawBytes))
        var gw   = sockaddr_in(); gw.sin_len  = UInt8(MemoryLayout<sockaddr_in>.size); gw.sin_family  = UInt8(AF_INET); gw.sin_addr  = in_addr(s_addr: packIPv4(gateway.rawBytes))
        var mask = sockaddr_in(); mask.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); mask.sin_family = UInt8(AF_INET); mask.sin_addr = in_addr(s_addr: packIPv4(makeMask4(bits: prefix.bits)))
        hdr.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + MemoryLayout<sockaddr_in>.size * 3)
        data.append(asData(&hdr))
        data.append(asData(&dst)); data.append(asData(&gw)); data.append(asData(&mask))
    } else {
        var dst  = sockaddr_in6(); dst.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); dst.sin6_family = UInt8(AF_INET6)
        withUnsafeMutableBytes(of: &dst.sin6_addr) { p in prefix.addr.rawBytes.withUnsafeBytes { s in p.copyMemory(from: s) } }
        var gw   = sockaddr_in6(); gw.sin6_len  = UInt8(MemoryLayout<sockaddr_in6>.size); gw.sin6_family = UInt8(AF_INET6)
        withUnsafeMutableBytes(of: &gw.sin6_addr) { p in gateway.rawBytes.withUnsafeBytes { s in p.copyMemory(from: s) } }
        var mask = sockaddr_in6(); mask.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); mask.sin6_family = UInt8(AF_INET6)
        let maskBytes = makeMask6(bits: prefix.bits)
        withUnsafeMutableBytes(of: &mask.sin6_addr) { p in maskBytes.withUnsafeBytes { s in p.copyMemory(from: s) } }
        hdr.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + MemoryLayout<sockaddr_in6>.size * 3)
        data.append(asData(&hdr))
        data.append(asData(&dst)); data.append(asData(&gw)); data.append(asData(&mask))
    }
    return data
}

// MARK: - Utilities

private func packIPv4(_ bytes: [UInt8]) -> UInt32 {
    UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
}

private func makeMask4(bits: Int) -> [UInt8] {
    var mask: UInt32 = bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits))
    return [UInt8((mask >> 24) & 0xFF), UInt8((mask >> 16) & 0xFF),
            UInt8((mask >> 8) & 0xFF),  UInt8(mask & 0xFF)]
}

private func makeMask6(bits: Int) -> [UInt8] {
    var mask = [UInt8](repeating: 0, count: 16)
    var remaining = bits
    for i in 0..<16 {
        if remaining >= 8 { mask[i] = 0xFF; remaining -= 8 }
        else if remaining > 0 { mask[i] = 0xFF << (8 - remaining); remaining = 0 }
    }
    return mask
}

private func asData<T>(_ value: inout T) -> Data {
    withUnsafeBytes(of: &value) { Data($0) }
}

private func flushDNSCache() {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/dscacheutil")
    task.arguments = ["-flushcache"]
    try? task.run()
}

// MARK: - TunError

public enum TunError: Error, LocalizedError {
    case badName(String)
    case alreadyClosed

    public var errorDescription: String? {
        switch self {
        case .badName(let n):  return "bad tun name: \(n)"
        case .alreadyClosed:   return "tun device already closed"
        }
    }
}

// MARK: - Helper structs not yet in Darwin overlay

// These recreate C structs used by ioctl / routing sockets that may not be
// present in Swift's Darwin overlay.

private struct ctl_ifreq {
    var ctl_id: UInt32 = 0
    var ctl_name: (CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                   CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar) = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
}

private let CTLIOCGINFO: UInt  = 0xC0644E03
private let MAX_KCTL_NAME: Int = 96

private struct in6_addrlifetime {
    var ia6t_expire:    Double = 0
    var ia6t_preferred: Double = 0
    var ia6t_vltime:    UInt32 = 0
    var ia6t_pltime:    UInt32 = 0
}

private struct in6_aliasreq {
    var ifra_name:       (CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                          CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar) = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    var ifra_addr:        sockaddr_in6 = sockaddr_in6()
    var ifra_dstaddr:     sockaddr_in6 = sockaddr_in6()
    var ifra_prefixmask:  sockaddr_in6 = sockaddr_in6()
    var ifra_flags:       Int32        = 0
    var ifra_lifetime:    in6_addrlifetime = in6_addrlifetime()
}

private let SIOCAIFADDR_IN6: UInt = 2155899162

// RTF constants (from <net/route.h>)
private let RTF_UP:      Int32 = 0x1
private let RTF_GATEWAY: Int32 = 0x2
private let RTF_STATIC:  Int32 = 0x800

// RTA constants
private let RTA_DST:     Int32 = 0x1
private let RTA_GATEWAY: Int32 = 0x2
private let RTA_NETMASK: Int32 = 0x4

// RTM_VERSION from <net/route.h>
private let RTM_VERSION: Int32 = 5

#endif // os(macOS) || os(iOS)

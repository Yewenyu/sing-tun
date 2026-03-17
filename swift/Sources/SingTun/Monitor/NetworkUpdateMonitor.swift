// Network update monitor that watches the kernel routing socket for changes.
// Mirrors monitor_darwin.go + monitor_shared.go from the Go implementation.

#if os(macOS) || os(iOS)
import Foundation
import Darwin

// MARK: - NetworkUpdateMonitorImpl

/// Listens to the BSD routing socket (AF_ROUTE) and delivers callbacks whenever
/// the routing table changes.  Mirrors `networkUpdateMonitor` from monitor_darwin.go.
public final class NetworkUpdateMonitorImpl: NetworkUpdateMonitor {

    private let lock       = NSLock()
    private var callbacks: [CallbackToken: NetworkUpdateCallback] = [:]
    private var routeFd:   Int32 = -1
    private var running    = false
    private var stopped    = false
    private var thread:    Thread?

    public init() {}

    // MARK: NetworkUpdateMonitor

    public func start() throws {
        guard !running else { return }
        running = true
        let t = Thread { [weak self] in self?.loopUpdate() }
        t.name = "sing-tun.network-monitor"
        t.start()
        thread = t
    }

    public func close() throws {
        stopped = true
        // Close the routing socket to unblock the blocking read
        lock.lock()
        let fd = routeFd
        lock.unlock()
        if fd >= 0 { Darwin.close(fd) }
    }

    @discardableResult
    public func registerCallback(_ callback: @escaping NetworkUpdateCallback) -> CallbackToken {
        let token = CallbackToken()
        lock.lock()
        callbacks[token] = callback
        lock.unlock()
        return token
    }

    public func unregisterCallback(_ token: CallbackToken) {
        lock.lock()
        callbacks.removeValue(forKey: token)
        lock.unlock()
    }

    // MARK: Private

    private func loopUpdate() {
        while !stopped {
            guard let fd = openRouteSocket() else {
                Thread.sleep(forTimeInterval: 1)
                continue
            }
            lock.lock()
            routeFd = fd
            lock.unlock()

            readLoop(fd: fd)

            Darwin.close(fd)
            lock.lock()
            routeFd = -1
            lock.unlock()
        }
    }

    private func openRouteSocket() -> Int32? {
        let fd = socket(AF_ROUTE, SOCK_RAW, 0)
        guard fd >= 0 else { return nil }
        var flags = fcntl(fd, F_GETFL, 0)
        flags |= O_NONBLOCK
        fcntl(fd, F_SETFL, flags)
        return fd
    }

    private func readLoop(fd: Int32) {
        var buffer = [UInt8](repeating: 0, count: 4096)
        while !stopped {
            let n = Darwin.read(fd, &buffer, buffer.count)
            if n < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    // Use select to block until data is ready
                    var readSet = fd_set()
                    fdZero(&readSet)
                    fdSet(fd, &readSet)
                    var timeout = timeval(tv_sec: 1, tv_usec: 0)
                    select(fd + 1, &readSet, nil, nil, &timeout)
                    continue
                }
                break
            }
            if n == 0 { break }

            // Check if it's a route message
            if isRouteMessage(buffer: buffer, count: n) {
                emit()
            }
        }
    }

    private func isRouteMessage(buffer: [UInt8], count: Int) -> Bool {
        guard count >= MemoryLayout<rt_msghdr>.size else { return false }
        return buffer.withUnsafeBytes { ptr -> Bool in
            let hdr = ptr.load(as: rt_msghdr.self)
            return hdr.rtm_type == RTM_ADD || hdr.rtm_type == RTM_DELETE || hdr.rtm_type == RTM_CHANGE
        }
    }

    private func emit() {
        lock.lock()
        let cbs = Array(callbacks.values)
        lock.unlock()
        for cb in cbs { cb() }
    }
}

// MARK: - fd_set helpers (not available in Swift overlay)

private func fdZero(_ set: inout fd_set) {
    set = fd_set()
}

private func fdSet(_ fd: Int32, _ set: inout fd_set) {
    let intSize = MemoryLayout<Int32>.size
    let offset  = Int(fd) / (intSize * 8)
    let bit     = Int(fd) % (intSize * 8)
    withUnsafeMutableBytes(of: &set) { ptr in
        let base = ptr.baseAddress!.assumingMemoryBound(to: Int32.self)
        base[offset] |= Int32(1 << bit)
    }
}

// MARK: - DefaultInterfaceMonitorImpl

/// Tracks the primary (default-route) network interface by periodically
/// inspecting the routing table, and delivers callbacks on changes.
///
/// Mirrors `defaultInterfaceMonitor` from monitor_shared.go + monitor_darwin.go.
public final class DefaultInterfaceMonitorImpl: DefaultInterfaceMonitor {

    // MARK: Configuration

    private let networkMonitor:         NetworkUpdateMonitor
    private let underNetworkExtension:  Bool
    private let _overrideAndroidVPN:    Bool
    private let logger:                 Logger

    // MARK: State

    private let lock =        NSLock()
    private var callbacks:   [CallbackToken: DefaultInterfaceUpdateCallback] = [:]
    private var _defaultInterface: NetworkInterface? = nil
    private var _myInterface: String = ""
    private var noRoute:      Bool = false
    private var monitorToken: CallbackToken?
    private var updateTimer:  Timer?
    private var _androidVPNEnabled: Bool = false

    // MARK: DefaultInterfaceMonitor

    public var defaultInterface: NetworkInterface? {
        lock.lock(); defer { lock.unlock() }
        return _defaultInterface
    }

    public var overrideAndroidVPN: Bool { _overrideAndroidVPN }
    public var androidVPNEnabled:  Bool {
        lock.lock(); defer { lock.unlock() }
        return _androidVPNEnabled
    }
    public var myInterface: String {
        lock.lock(); defer { lock.unlock() }
        return _myInterface
    }

    // MARK: Init

    public init(
        networkMonitor: NetworkUpdateMonitor,
        logger: Logger,
        overrideAndroidVPN: Bool = false,
        underNetworkExtension: Bool = false
    ) {
        self.networkMonitor        = networkMonitor
        self.logger                = logger
        self._overrideAndroidVPN   = overrideAndroidVPN
        self.underNetworkExtension = underNetworkExtension
    }

    // MARK: Lifecycle

    public func start() throws {
        postCheckUpdate()
        monitorToken = networkMonitor.registerCallback { [weak self] in
            self?.delayCheckUpdate()
        }
    }

    public func close() throws {
        if let token = monitorToken {
            networkMonitor.unregisterCallback(token)
            monitorToken = nil
        }
        updateTimer?.invalidate()
        updateTimer = nil
    }

    // MARK: Callbacks

    @discardableResult
    public func registerCallback(_ callback: @escaping DefaultInterfaceUpdateCallback) -> CallbackToken {
        let token = CallbackToken()
        lock.lock(); callbacks[token] = callback; lock.unlock()
        return token
    }

    public func unregisterCallback(_ token: CallbackToken) {
        lock.lock(); callbacks.removeValue(forKey: token); lock.unlock()
    }

    public func registerMyInterface(name: String) {
        lock.lock(); _myInterface = name; lock.unlock()
    }

    // MARK: Private

    private func delayCheckUpdate() {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.updateTimer?.invalidate()
            self.updateTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: false) { [weak self] _ in
                self?.postCheckUpdate()
            }
        }
    }

    private func postCheckUpdate() {
        do {
            let iface = try checkUpdate()
            lock.lock()
            let old = _defaultInterface
            _defaultInterface = iface
            noRoute = false
            lock.unlock()

            let changed = old?.name != iface?.name || old?.index != iface?.index
            if changed { emit(iface, 0) }
        } catch {
            lock.lock()
            let wasNoRoute = noRoute
            lock.unlock()
            if !wasNoRoute {
                lock.lock(); noRoute = true; _defaultInterface = nil; lock.unlock()
                emit(nil, 0)
            }
            logger.error("check interface: \(error)")
        }
    }

    private func checkUpdate() throws -> NetworkInterface? {
        if underNetworkExtension {
            return try getDefaultInterfaceBySocket()
        }
        return try getDefaultInterfaceFromRouteTable()
    }

    // MARK: Route table inspection

    private func getDefaultInterfaceFromRouteTable() throws -> NetworkInterface? {
        let ifaces = try systemInterfaces()
        // Look for the interface with a default (0.0.0.0/0) route
        // On Darwin we read /proc/net/route equivalent via sysctl MIB
        // For simplicity, use `route get 0.0.0.0` parsing approach:
        return try getDefaultInterfaceViaSysctl(interfaces: ifaces)
    }

    private func getDefaultInterfaceViaSysctl(interfaces: [NetworkInterface]) throws -> NetworkInterface? {
        // Use CTL_NET / PF_ROUTE / AF_INET / NET_RT_FLAGS / RTF_GATEWAY sysctl
        // to enumerate routes and find the default (destination == 0.0.0.0).
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, Int32(RTF_GATEWAY | RTF_UP)]
        var needed: size_t = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &needed, nil, 0) == 0, needed > 0 else {
            return nil
        }
        var buf = [UInt8](repeating: 0, count: needed)
        guard sysctl(&mib, UInt32(mib.count), &buf, &needed, nil, 0) == 0 else {
            return nil
        }

        var idx = 0
        while idx < needed {
            guard idx + MemoryLayout<rt_msghdr>.size <= needed else { break }
            let msgLen = buf.withUnsafeBytes { ptr -> Int in
                let hdr = ptr.baseAddress!.advanced(by: idx).assumingMemoryBound(to: rt_msghdr.self)
                return Int(hdr.pointee.rtm_msglen)
            }
            guard msgLen > 0, idx + msgLen <= needed else { break }

            let ifIndex = buf.withUnsafeBytes { ptr -> Int32 in
                let hdr = ptr.baseAddress!.advanced(by: idx).assumingMemoryBound(to: rt_msghdr.self)
                return Int32(hdr.pointee.rtm_index)
            }
            let rtFlags = buf.withUnsafeBytes { ptr -> Int32 in
                let hdr = ptr.baseAddress!.advanced(by: idx).assumingMemoryBound(to: rt_msghdr.self)
                return hdr.pointee.rtm_flags
            }
            let rtAddrs = buf.withUnsafeBytes { ptr -> Int32 in
                let hdr = ptr.baseAddress!.advanced(by: idx).assumingMemoryBound(to: rt_msghdr.self)
                return hdr.pointee.rtm_addrs
            }

            if rtFlags & RTF_UP != 0 && rtFlags & RTF_GATEWAY != 0 {
                // Parse the destination sockaddr immediately after the header
                let saOff = idx + MemoryLayout<rt_msghdr>.size
                if rtAddrs & RTA_DST != 0 && saOff + MemoryLayout<sockaddr_in>.size <= needed {
                    let isDefault = buf.withUnsafeBytes { ptr -> Bool in
                        let sa = ptr.baseAddress!.advanced(by: saOff).assumingMemoryBound(to: sockaddr_in.self)
                        return sa.pointee.sin_family == UInt8(AF_INET) && sa.pointee.sin_addr.s_addr == 0
                    }
                    if isDefault, let iface = interfaces.first(where: { $0.index == Int(ifIndex) }) {
                        return iface
                    }
                }
            }
            idx += msgLen
        }
        return nil
    }

    // MARK: Socket-based detection (Network Extension mode)

    private func getDefaultInterfaceBySocket() throws -> NetworkInterface? {
        let sockFd = socket(AF_INET, SOCK_STREAM, 0)
        guard sockFd >= 0 else { return nil }
        defer { Darwin.close(sockFd) }

        // Attempt a non-blocking connect to 10.255.255.255:80
        var flags = fcntl(sockFd, F_GETFL, 0)
        fcntl(sockFd, F_SETFL, flags | O_NONBLOCK)

        var dest = sockaddr_in()
        dest.sin_family = UInt8(AF_INET)
        dest.sin_port   = UInt16(80).bigEndian
        dest.sin_addr   = in_addr(s_addr: (UInt32(10) << 24 | UInt32(255) << 16
                                          | UInt32(255) << 8 | UInt32(255)).bigEndian)
        withUnsafePointer(to: &dest) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                _ = Darwin.connect(sockFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        // Poll getsockname until a local address is bound
        let deadline = Date().addingTimeInterval(1.0)
        while Date() < deadline {
            var name = sockaddr_in()
            var nameLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            withUnsafeMutablePointer(to: &name) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(sockFd, $0, &nameLen)
                }
            }
            if name.sin_family == UInt8(AF_INET) && name.sin_addr.s_addr != 0 {
                let bytes = withUnsafeBytes(of: name.sin_addr.s_addr.bigEndian) { Array($0) }
                let addr  = IPAddr(v4: bytes)
                let ifaces = try systemInterfaces()
                return ifaces.first { $0.addresses.contains(addr) }
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return nil
    }

    // MARK: Emit

    private func emit(_ iface: NetworkInterface?, _ flags: Int) {
        lock.lock()
        let cbs = Array(callbacks.values)
        lock.unlock()
        for cb in cbs { cb(iface, flags) }
    }
}

// MARK: - System interface enumeration

func systemInterfaces() throws -> [NetworkInterface] {
    var result: [NetworkInterface] = []
    var ifList: UnsafeMutablePointer<ifaddrs>? = nil
    guard getifaddrs(&ifList) == 0, let list = ifList else {
        throw POSIXError(POSIXErrorCode(rawValue: errno)!)
    }
    defer { freeifaddrs(list) }

    var ptr: UnsafeMutablePointer<ifaddrs>? = list
    while let current = ptr {
        let name  = String(cString: current.pointee.ifa_name)
        let flags = current.pointee.ifa_flags
        let index = Int(if_nametoindex(current.pointee.ifa_name))

        var addr: IPAddr? = nil
        if let sa = current.pointee.ifa_addr {
            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                let sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                addr = IPAddr(v4: withUnsafeBytes(of: sin.sin_addr.s_addr.bigEndian) { Array($0) })
            case AF_INET6:
                let sin6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                addr = IPAddr(v6: withUnsafeBytes(of: sin6.sin6_addr) { Array($0) })
            default: break
            }
        }

        if let existing = result.firstIndex(where: { $0.index == index }) {
            if let a = addr { result[existing].addresses.append(a) }
        } else {
            var iface = NetworkInterface(index: index, name: name, flags: flags)
            if let a = addr { iface.addresses.append(a) }
            result.append(iface)
        }
        ptr = current.pointee.ifa_next
    }
    return result
}

// MARK: - Darwin routing constants (not always in Swift overlay)

private let NET_RT_FLAGS: Int32 = 2
private let PF_ROUTE:     Int32 = 17
private let RTF_UP:       Int32 = 0x1
private let RTF_GATEWAY:  Int32 = 0x2
private let RTA_DST:      Int32 = 0x1

#endif // os(macOS) || os(iOS)

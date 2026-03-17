import XCTest
#if canImport(Network)
import Network
#endif
#if canImport(NetworkExtension)
import NetworkExtension
#endif
@testable import SingTun

final class SingTunTests: XCTestCase {

    // MARK: - IPAddr tests

    func testIPAddrV4Creation() {
        let addr = IPAddr(v4: [192, 168, 1, 1])
        XCTAssertTrue(addr.isV4)
        XCTAssertFalse(addr.isV6)
        XCTAssertEqual(addr.rawBytes, [192, 168, 1, 1])
        XCTAssertEqual(addr.description, "192.168.1.1")
    }

    func testIPAddrV4FromString() {
        let addr = IPAddr(string: "10.0.0.1")
        XCTAssertNotNil(addr)
        XCTAssertTrue(addr!.isV4)
    }

    func testIPAddrV6Creation() {
        let bytes = [UInt8](repeating: 0, count: 16)
        let addr  = IPAddr(v6: bytes)
        XCTAssertTrue(addr.isV6)
        XCTAssertTrue(addr.isUnspecified)
    }

    func testIPAddrNext() {
        let addr = IPAddr(v4: [10, 0, 0, 1])
        let next = addr.next()
        XCTAssertEqual(next?.rawBytes, [10, 0, 0, 2])
    }

    func testIPAddrNextWrap() {
        let addr = IPAddr(v4: [255, 255, 255, 255])
        XCTAssertNil(addr.next())
    }

    func testIPAddrIsGlobalUnicast() {
        XCTAssertTrue(IPAddr(v4:  [8, 8, 8, 8]).isGlobalUnicast)
        XCTAssertFalse(IPAddr(v4: [127, 0, 0, 1]).isGlobalUnicast)
        XCTAssertFalse(IPAddr(v4: [0, 0, 0, 0]).isGlobalUnicast)
        XCTAssertFalse(IPAddr(v4: [224, 0, 0, 1]).isGlobalUnicast)
    }

    // MARK: - IPPrefix tests

    func testIPPrefixContains() {
        let prefix = IPPrefix(addr: IPAddr(v4: [10, 0, 0, 0]), bits: 8)
        XCTAssertTrue(prefix.contains(IPAddr(v4: [10, 1, 2, 3])))
        XCTAssertFalse(prefix.contains(IPAddr(v4: [11, 0, 0, 1])))
    }

    func testIPPrefixMasked() {
        let prefix = IPPrefix(addr: IPAddr(v4: [192, 168, 1, 5]), bits: 24)
        let masked = prefix.masked
        XCTAssertEqual(masked.addr.rawBytes, [192, 168, 1, 0])
    }

    func testIPPrefixFromString() {
        let prefix = IPPrefix(string: "198.18.0.0/15")
        XCTAssertNotNil(prefix)
        XCTAssertEqual(prefix?.bits, 15)
    }

    // MARK: - SocksAddr tests

    func testSocksAddrDescription() {
        let addr  = IPAddr(v4: [8, 8, 8, 8])
        let socks = SocksAddr(addr: addr, port: 53)
        XCTAssertEqual(socks.description, "8.8.8.8:53")
    }

    func testSocksAddrFromString() {
        let socks = SocksAddr.from(ipPort: "1.2.3.4:80")
        XCTAssertNotNil(socks)
        XCTAssertEqual(socks?.port, 80)
    }

    // MARK: - TunOptions tests

    func testDefaultOptions() {
        let opts = TunOptions(name: "utun0", mtu: 1500)
        XCTAssertEqual(opts.name, "utun0")
        XCTAssertEqual(opts.mtu, 1500)
        XCTAssertFalse(opts.autoRoute)
        XCTAssertTrue(opts.inet4Address.isEmpty)
    }

    func testBroadcastAddr() {
        var opts = TunOptions(name: "utun0", mtu: 1500)
        opts.inet4Address = [IPPrefix(addr: IPAddr(v4: [198, 18, 0, 1]), bits: 15)]
        let bc = opts.broadcastAddr
        XCTAssertNotNil(bc)
        // 198.18.0.1/15 -> broadcast is 198.19.255.255
        XCTAssertEqual(bc?.rawBytes, [198, 19, 255, 255])
    }

    func testBuildAutoRouteRangesNoRoute() {
        let opts = TunOptions(name: "utun0", mtu: 1500)
        let ranges = opts.buildAutoRouteRanges()
        XCTAssertTrue(ranges.isEmpty)
    }

    func testBuildAutoRouteRangesWithAutoRoute() {
        var opts = TunOptions(name: "utun0", mtu: 1500)
        opts.inet4Address = [IPPrefix(addr: IPAddr(v4: [198, 18, 0, 1]), bits: 15)]
        opts.autoRoute    = true
        let ranges = opts.buildAutoRouteRanges(underNetworkExtension: false)
        // Darwin sub-ranges: 8 prefixes
        XCTAssertEqual(ranges.count, 8)
    }

    func testBuildAutoRouteRangesNetworkExtension() {
        var opts = TunOptions(name: "utun0", mtu: 1500)
        opts.inet4Address = [IPPrefix(addr: IPAddr(v4: [198, 18, 0, 1]), bits: 15)]
        opts.autoRoute    = true
        let ranges = opts.buildAutoRouteRanges(underNetworkExtension: true)
        // Network extension: default route 0.0.0.0/0
        XCTAssertEqual(ranges.count, 1)
        XCTAssertEqual(ranges.first?.bits, 0)
    }

    // MARK: - IPHeader tests

    func testIPVersionDetectionV4() {
        let packet = Data([0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                           0x40, 0x06, 0x00, 0x00,
                           0x7F, 0x00, 0x00, 0x01,
                           0x7F, 0x00, 0x00, 0x01])
        XCTAssertEqual(IPVersion.detect(in: packet), .v4)
    }

    func testIPVersionDetectionV6() {
        var packet = Data(count: 40)
        packet[0] = 0x60
        XCTAssertEqual(IPVersion.detect(in: packet), .v6)
    }

    func testIPv4Header() {
        // Minimal IPv4 packet: version=4, IHL=5, proto=TCP, src=1.2.3.4, dst=5.6.7.8
        let packet = Data([
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x01, 0x02, 0x03, 0x04,   // src
            0x05, 0x06, 0x07, 0x08    // dst
        ])
        let hdr = IPv4Header(packet)
        XCTAssertNotNil(hdr)
        XCTAssertEqual(hdr?.protocol_, .tcp)
        XCTAssertEqual(hdr?.sourceAddr.rawBytes, [1, 2, 3, 4])
        XCTAssertEqual(hdr?.destinationAddr.rawBytes, [5, 6, 7, 8])
    }

    // MARK: - Checksum tests

    func testInternetChecksum() {
        // All-zeros should give 0xFFFF (complement of 0)
        let data = Data(repeating: 0, count: 20)
        let cs = internetChecksum(data)
        XCTAssertEqual(cs, 0xFFFF)
    }

    // MARK: - TCPNat tests

    func testTCPNatLookupAndBack() throws {
        let nat = TCPNat(timeout: 300)
        let src = IPAddr(v4: [10, 0, 0, 2])
        let dst = IPAddr(v4: [8, 8, 8, 8])

        var routeCalled = false
        let port = try nat.lookup(
            sourceAddr: src, sourcePort: 12345,
            destinationAddr: dst, destinationPort: 80
        ) { routeCalled = true }

        XCTAssertTrue(routeCalled)
        XCTAssertGreaterThan(port, 0)

        let session = nat.lookupBack(port: port)
        XCTAssertNotNil(session)
        XCTAssertEqual(session?.source.addr.rawBytes, [10, 0, 0, 2])
        XCTAssertEqual(session?.source.port, 12345)
        XCTAssertEqual(session?.destination.addr.rawBytes, [8, 8, 8, 8])
        XCTAssertEqual(session?.destination.port, 80)
    }

    func testTCPNatSameSourceReturnsSamePort() throws {
        let nat = TCPNat(timeout: 300)
        let src = IPAddr(v4: [10, 0, 0, 3])
        let dst = IPAddr(v4: [1, 1, 1, 1])

        let port1 = try nat.lookup(
            sourceAddr: src, sourcePort: 54321,
            destinationAddr: dst, destinationPort: 443
        ) {}
        let port2 = try nat.lookup(
            sourceAddr: src, sourcePort: 54321,
            destinationAddr: dst, destinationPort: 443
        ) {}

        XCTAssertEqual(port1, port2)
    }

    // MARK: - DirectRouteMapping tests

    func testDirectRouteMappingLookup() throws {
        let mapping = DirectRouteMapping(timeout: 60)
        let session = DirectRouteSession(
            source:      IPAddr(v4: [10, 0, 0, 1]),
            destination: IPAddr(v4: [8, 8, 8, 8])
        )
        var constructCount = 0
        let dest = try mapping.lookup(session: session) { _ in
            constructCount += 1
            return MockDirectRouteDestination()
        }
        XCTAssertNotNil(dest)
        XCTAssertEqual(constructCount, 1)

        // Second lookup should reuse the same destination
        _ = try mapping.lookup(session: session) { _ in
            constructCount += 1
            return MockDirectRouteDestination()
        }
        XCTAssertEqual(constructCount, 1)
    }

    // MARK: - StubPackageManager tests

    func testStubPackageManager() throws {
        let pm = StubPackageManager()
        try pm.start()
        XCTAssertNil(pm.id(forPackage: "com.example.app"))
        XCTAssertNil(pm.id(forSharedPackage: "shared"))
        XCTAssertNil(pm.package(forID: 1234))
        XCTAssertNil(pm.sharedPackage(forID: 1234))
        try pm.close()
    }

    // MARK: - CallbackToken tests

    func testCallbackTokenEquality() {
        let t1 = CallbackToken()
        let t2 = CallbackToken()
        XCTAssertNotEqual(t1, t2)
        XCTAssertEqual(t1, t1)
    }

    // MARK: - NWConnectionStack tests (macOS / iOS only)

#if canImport(Network)
    /// Verify that NWListenerTCPListener starts, reports a non-zero port,
    /// and that an NWConnectionTCPConn can send and receive data through it.
    func testNWListenerAndConnection() throws {
        // Bind to loopback so no special entitlements are needed.
        let loopback = IPAddr(v4: [127, 0, 0, 1])
        let listener = NWListenerTCPListener(address: loopback)
        try listener.start()
        let listenPort = listener.port
        XCTAssertGreaterThan(listenPort, 0, "listener should bind to a non-zero port")

        // Client connection to loopback:listenPort
        let clientEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: listenPort)!)
        let clientConn     = NWConnection(to: clientEndpoint, using: .tcp)
        let clientQueue    = DispatchQueue(label: "test.client")
        clientConn.start(queue: clientQueue)

        // Accept the server-side connection
        let serverConn = listener.accept()
        XCTAssertNotNil(serverConn, "listener.accept() should return a connection")

        // Send "hello" from client → server
        let payload = "hello".data(using: .utf8)!
        var writeErr: Error?
        let writeSema = DispatchSemaphore(value: 0)
        clientConn.send(content: payload, completion: .contentProcessed { error in
            writeErr = error
            writeSema.signal()
        })
        writeSema.wait()
        XCTAssertNil(writeErr, "client send should succeed")

        // Read on the server side
        var readBuf = Data()
        let readResult = try serverConn?.read(into: &readBuf)
        XCTAssertEqual(readBuf, payload, "server should receive the exact payload")
        XCTAssertEqual(readResult, payload.count)

        // Teardown
        try serverConn?.close()
        clientConn.cancel()
        listener.stop()
    }

    /// Verify that NWListenerTCPListener.accept() unblocks when stop() is called.
    func testNWListenerStopUnblocksAccept() throws {
        let loopback = IPAddr(v4: [127, 0, 0, 1])
        let listener = NWListenerTCPListener(address: loopback)
        try listener.start()

        let expectation = XCTestExpectation(description: "accept unblocks after stop")
        Thread.detachNewThread {
            let result = listener.accept()
            XCTAssertNil(result, "accept() should return nil after stop()")
            expectation.fulfill()
        }

        // Give the thread time to start and block in accept()
        Thread.sleep(forTimeInterval: 0.1)
        listener.stop()

        wait(for: [expectation], timeout: 2.0)
    }
#endif  // canImport(Network)

    // MARK: - NEPacketTunnelNetworkSettings builder tests (macOS / iOS only)

#if canImport(NetworkExtension)
    func testBuildNetworkSettingsIPv4Only() {
        var opts = TunOptions(name: "utun0", mtu: 1500)
        opts.inet4Address = [IPPrefix(addr: IPAddr(v4: [198, 18, 0, 1]), bits: 16)]
        opts.autoRoute    = true

        let settings = opts.buildNetworkSettings()

        XCTAssertNotNil(settings.ipv4Settings, "ipv4Settings must be set")
        XCTAssertNil(settings.ipv6Settings,    "ipv6Settings must be nil when no IPv6 addresses are configured")
        XCTAssertEqual(settings.mtu, NSNumber(value: 1500))

        let ipv4 = settings.ipv4Settings!
        XCTAssertEqual(ipv4.addresses, ["198.18.0.1"])
        // /16 → 255.255.0.0
        XCTAssertEqual(ipv4.subnetMasks, ["255.255.0.0"])
        XCTAssertNotNil(ipv4.includedRoutes, "auto-route should produce included routes")
        XCTAssertFalse(ipv4.includedRoutes!.isEmpty, "should have at least one included route")
    }

    func testBuildNetworkSettingsIPv6Only() {
        var opts = TunOptions(name: "utun0", mtu: 9000)
        let v6addr = IPAddr(v6: [0x26, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        opts.inet6Address = [IPPrefix(addr: v6addr, bits: 48)]
        opts.autoRoute    = true

        let settings = opts.buildNetworkSettings()

        XCTAssertNil(settings.ipv4Settings)
        XCTAssertNotNil(settings.ipv6Settings)
        XCTAssertEqual(settings.mtu, NSNumber(value: 9000))

        let ipv6 = settings.ipv6Settings!
        XCTAssertEqual(ipv6.networkPrefixLengths, [NSNumber(value: 48)])
        XCTAssertNotNil(ipv6.includedRoutes)
        XCTAssertFalse(ipv6.includedRoutes!.isEmpty)
    }

    func testBuildNetworkSettingsDNS() {
        var opts = TunOptions(name: "utun0", mtu: 1500)
        opts.inet4Address = [IPPrefix(addr: IPAddr(v4: [10, 0, 0, 1]), bits: 8)]
        opts.dnsServers   = [IPAddr(v4: [8, 8, 8, 8]), IPAddr(v4: [8, 8, 4, 4])]

        let settings = opts.buildNetworkSettings()

        XCTAssertNotNil(settings.dnsSettings, "dnsSettings must be set when dnsServers is non-empty")
        XCTAssertEqual(settings.dnsSettings?.servers, ["8.8.8.8", "8.8.4.4"])
    }

    func testBuildNetworkSettingsDNSHijackDisabled() {
        var opts = TunOptions(name: "utun0", mtu: 1500)
        opts.inet4Address    = [IPPrefix(addr: IPAddr(v4: [10, 0, 0, 1]), bits: 8)]
        opts.dnsServers      = [IPAddr(v4: [8, 8, 8, 8])]
        opts.disableDNSHijack = true

        let settings = opts.buildNetworkSettings()

        XCTAssertNil(settings.dnsSettings, "dnsSettings must be nil when disableDNSHijack is true")
    }

    func testBuildNetworkSettingsExcludedRoutes() {
        var opts = TunOptions(name: "utun0", mtu: 1500)
        opts.inet4Address             = [IPPrefix(addr: IPAddr(v4: [198, 18, 0, 1]), bits: 16)]
        opts.autoRoute                = true
        opts.inet4RouteExcludeAddress = [IPPrefix(addr: IPAddr(v4: [192, 168, 0, 0]), bits: 16)]

        let settings = opts.buildNetworkSettings()

        XCTAssertNotNil(settings.ipv4Settings?.excludedRoutes)
        let excluded = settings.ipv4Settings?.excludedRoutes ?? []
        XCTAssertTrue(excluded.contains { $0.destinationAddress == "192.168.0.0" },
                      "excluded routes should contain 192.168.0.0/16")
    }
#endif  // canImport(NetworkExtension)
}

// MARK: - Test Helpers

private final class MockDirectRouteDestination: DirectRouteDestination {
    private var _closed = false
    func writePacket(_ packet: Data) throws {}
    func close() throws { _closed = true }
    var isClosed: Bool { _closed }
}

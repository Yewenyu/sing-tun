// Lightweight IP / TCP / UDP / ICMP header parsers used by the system stack.
// These mirror the structures found in internal/gtcpip/header/ of the Go code.

import Foundation

// MARK: - IP Version

public enum IPVersion: UInt8 {
    case v4 = 4
    case v6 = 6
    case unknown = 0

    public static func detect(in packet: Data) -> IPVersion {
        guard !packet.isEmpty else { return .unknown }
        let versionNibble = (packet[packet.startIndex] >> 4) & 0x0F
        return IPVersion(rawValue: versionNibble) ?? .unknown
    }
}

// MARK: - Transport Protocol Numbers

public enum TransportProtocol: UInt8 {
    case icmpV4 = 1
    case tcp    = 6
    case udp    = 17
    case icmpV6 = 58
    case unknown = 0xFF
}

// MARK: - IPv4 Header (view, not copy)

public struct IPv4Header {
    // Minimum header length in bytes (20 bytes, no options).
    public static let minimumSize = 20

    private let data: Data

    public init?(_ data: Data) {
        guard data.count >= Self.minimumSize else { return nil }
        guard IPVersion.detect(in: data) == .v4 else { return nil }
        self.data = data
    }

    private func byte(_ offset: Int) -> UInt8 { data[data.startIndex + offset] }
    private func u16(_ offset: Int) -> UInt16 {
        UInt16(byte(offset)) << 8 | UInt16(byte(offset + 1))
    }

    public var headerLength: Int { Int((byte(0) & 0x0F) * 4) }
    public var totalLength: Int  { Int(u16(2)) }
    public var protocol_: TransportProtocol { TransportProtocol(rawValue: byte(9)) ?? .unknown }

    public var sourceAddr: IPAddr {
        IPAddr(v4: [byte(12), byte(13), byte(14), byte(15)])
    }
    public var destinationAddr: IPAddr {
        IPAddr(v4: [byte(16), byte(17), byte(18), byte(19)])
    }

    /// The transport-layer payload (no IP header).
    public var payload: Data {
        let start = data.startIndex + headerLength
        guard start < data.endIndex else { return Data() }
        return data[start...]
    }

    /// The full IPv4 datagram bytes.
    public var bytes: Data { data }
}

// MARK: - IPv6 Header

public struct IPv6Header {
    public static let minimumSize = 40

    private let data: Data

    public init?(_ data: Data) {
        guard data.count >= Self.minimumSize else { return nil }
        guard IPVersion.detect(in: data) == .v6 else { return nil }
        self.data = data
    }

    private func byte(_ offset: Int) -> UInt8 { data[data.startIndex + offset] }

    public var nextHeader: TransportProtocol {
        TransportProtocol(rawValue: byte(6)) ?? .unknown
    }
    public var payloadLength: Int {
        Int(UInt16(byte(4)) << 8 | UInt16(byte(5)))
    }

    public var sourceAddr: IPAddr {
        IPAddr(v6: Array(data[(data.startIndex + 8)..<(data.startIndex + 24)]))
    }
    public var destinationAddr: IPAddr {
        IPAddr(v6: Array(data[(data.startIndex + 24)..<(data.startIndex + 40)]))
    }

    public var payload: Data {
        let start = data.startIndex + Self.minimumSize
        guard start < data.endIndex else { return Data() }
        return data[start...]
    }

    public var bytes: Data { data }
}

// MARK: - TCP Header

public struct TCPHeader {
    public static let minimumSize = 20

    private let data: Data

    public init?(_ data: Data) {
        guard data.count >= Self.minimumSize else { return nil }
        self.data = data
    }

    private func byte(_ offset: Int) -> UInt8 { data[data.startIndex + offset] }
    private func u16(_ offset: Int) -> UInt16 {
        UInt16(byte(offset)) << 8 | UInt16(byte(offset + 1))
    }
    private func u32(_ offset: Int) -> UInt32 {
        UInt32(byte(offset)) << 24 | UInt32(byte(offset+1)) << 16
            | UInt32(byte(offset+2)) << 8 | UInt32(byte(offset+3))
    }

    public var sourcePort: UInt16      { u16(0) }
    public var destinationPort: UInt16 { u16(2) }
    public var sequenceNumber: UInt32  { u32(4) }
    public var ackNumber: UInt32       { u32(8) }
    public var dataOffset: Int         { Int((byte(12) >> 4) * 4) }
    public var flags: UInt8            { byte(13) }
    public var windowSize: UInt16      { u16(14) }
    public var checksum: UInt16        { u16(16) }

    public var isSYN: Bool { flags & 0x02 != 0 }
    public var isACK: Bool { flags & 0x10 != 0 }
    public var isFIN: Bool { flags & 0x01 != 0 }
    public var isRST: Bool { flags & 0x04 != 0 }
}

// MARK: - UDP Header

public struct UDPHeader {
    public static let size = 8

    private let data: Data

    public init?(_ data: Data) {
        guard data.count >= Self.size else { return nil }
        self.data = data
    }

    private func byte(_ offset: Int) -> UInt8 { data[data.startIndex + offset] }
    private func u16(_ offset: Int) -> UInt16 {
        UInt16(byte(offset)) << 8 | UInt16(byte(offset + 1))
    }

    public var sourcePort: UInt16      { u16(0) }
    public var destinationPort: UInt16 { u16(2) }
    public var length: UInt16          { u16(4) }
    public var checksum: UInt16        { u16(6) }

    public var payload: Data {
        let start = data.startIndex + Self.size
        guard start < data.endIndex else { return Data() }
        return data[start...]
    }
}

// MARK: - ICMPv4 Header

public struct ICMPv4Header {
    public static let size = 8

    private let data: Data

    public init?(_ data: Data) {
        guard data.count >= Self.size else { return nil }
        self.data = data
    }

    private func byte(_ offset: Int) -> UInt8 { data[data.startIndex + offset] }
    private func u16(_ offset: Int) -> UInt16 {
        UInt16(byte(offset)) << 8 | UInt16(byte(offset + 1))
    }

    public var type: UInt8     { byte(0) }
    public var code: UInt8     { byte(1) }
    public var checksum: UInt16 { u16(2) }

    public static let typeEchoRequest:  UInt8 = 8
    public static let typeEchoReply:    UInt8 = 0
}

// MARK: - ICMPv6 Header

public struct ICMPv6Header {
    public static let size = 8

    private let data: Data

    public init?(_ data: Data) {
        guard data.count >= Self.size else { return nil }
        self.data = data
    }

    private func byte(_ offset: Int) -> UInt8 { data[data.startIndex + offset] }

    public var type: UInt8 { byte(0) }
    public var code: UInt8 { byte(1) }

    public static let typeEchoRequest:  UInt8 = 128
    public static let typeEchoReply:    UInt8 = 129
}

// MARK: - Internet checksum

/// Compute the one's-complement sum for a pseudo-header + payload.
public func internetChecksum(_ data: Data) -> UInt16 {
    var sum: UInt32 = 0
    var index = data.startIndex
    while index < data.endIndex {
        let nextIndex = data.index(after: index)
        let high = UInt32(data[index]) << 8
        let low: UInt32
        if nextIndex < data.endIndex {
            low = UInt32(data[nextIndex])
            index = data.index(after: nextIndex)
        } else {
            low = 0
            index = nextIndex
        }
        sum += high | low
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ~UInt16(sum)
}

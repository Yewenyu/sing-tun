// Core value types used throughout SingTun.

import Foundation

// MARK: - SocksAddr

/// A network address combining an IP address (or host name) and a port,
/// mirroring `M.Socksaddr` from the Go implementation.
public struct SocksAddr: Hashable, CustomStringConvertible {
    public var addr: IPAddr?
    public var fqdn: String?
    public var port: UInt16

    public init(addr: IPAddr, port: UInt16) {
        self.addr = addr
        self.fqdn = nil
        self.port = port
    }

    public init(fqdn: String, port: UInt16) {
        self.addr = nil
        self.fqdn = fqdn
        self.port = port
    }

    public var description: String {
        let host = fqdn ?? addr?.description ?? "?"
        return "\(host):\(port)"
    }

    public static func from(ipPort: String) -> SocksAddr? {
        guard let lastColon = ipPort.lastIndex(of: ":"),
              let port = UInt16(ipPort[ipPort.index(after: lastColon)...])
        else { return nil }
        let hostPart = String(ipPort[..<lastColon])
        let stripped = hostPart.hasPrefix("[") && hostPart.hasSuffix("]")
            ? String(hostPart.dropFirst().dropLast()) : hostPart
        if let ip = IPAddr(string: stripped) {
            return SocksAddr(addr: ip, port: port)
        }
        return SocksAddr(fqdn: stripped, port: port)
    }
}

// MARK: - IPAddr

/// A version-agnostic IP address (IPv4 or IPv6), analogous to `netip.Addr`.
public struct IPAddr: Hashable, CustomStringConvertible {
    public enum Kind { case v4, v6 }

    private let storage: [UInt8]   // 4 or 16 bytes
    public let kind: Kind

    /// Parse a dotted-decimal IPv4 or colon-hex IPv6 string.
    public init?(string: String) {
        if let bytes = IPAddr.parseIPv4(string) {
            storage = bytes
            kind = .v4
        } else if let bytes = IPAddr.parseIPv6(string) {
            storage = bytes
            kind = .v6
        } else {
            return nil
        }
    }

    public init(v4 bytes: (UInt8, UInt8, UInt8, UInt8)) {
        storage = [bytes.0, bytes.1, bytes.2, bytes.3]
        kind = .v4
    }

    public init(v4 bytes: [UInt8]) {
        precondition(bytes.count == 4)
        storage = bytes
        kind = .v4
    }

    public init(v6 bytes: [UInt8]) {
        precondition(bytes.count == 16)
        storage = bytes
        kind = .v6
    }

    public var rawBytes: [UInt8] { storage }

    public var isV4: Bool { kind == .v4 }
    public var isV6: Bool { kind == .v6 }

    public var isUnspecified: Bool {
        storage.allSatisfy { $0 == 0 }
    }

    public var isLoopback: Bool {
        if kind == .v4 { return storage[0] == 127 }
        // ::1
        return storage.prefix(15).allSatisfy { $0 == 0 } && storage[15] == 1
    }

    public var isGlobalUnicast: Bool {
        !isUnspecified && !isLoopback && !isMulticast && !isLinkLocal
    }

    public var isMulticast: Bool {
        if kind == .v4 { return storage[0] >= 224 && storage[0] <= 239 }
        return storage[0] == 0xFF
    }

    public var isLinkLocal: Bool {
        if kind == .v4 { return storage[0] == 169 && storage[1] == 254 }
        return storage[0] == 0xFE && (storage[1] & 0xC0) == 0x80
    }

    public func next() -> IPAddr? {
        var bytes = storage
        var carry: Int = 1
        for i in stride(from: bytes.count - 1, through: 0, by: -1) {
            let sum = Int(bytes[i]) + carry
            bytes[i] = UInt8(sum & 0xFF)
            carry = sum >> 8
            if carry == 0 { break }
        }
        if carry != 0 { return nil }
        return kind == .v4 ? IPAddr(v4: bytes) : IPAddr(v6: bytes)
    }

    public var description: String {
        if kind == .v4 {
            return storage.map { String($0) }.joined(separator: ".")
        }
        // Minimal IPv6 printer (no :: compression)
        var groups: [String] = []
        for i in stride(from: 0, to: 16, by: 2) {
            let value = UInt16(storage[i]) << 8 | UInt16(storage[i + 1])
            groups.append(String(value, radix: 16))
        }
        return groups.joined(separator: ":")
    }

    // MARK: - Parsing helpers

    static func parseIPv4(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var bytes = [UInt8](repeating: 0, count: 4)
        for (i, part) in parts.enumerated() {
            guard let v = UInt8(part) else { return nil }
            bytes[i] = v
        }
        return bytes
    }

    static func parseIPv6(_ s: String) -> [UInt8]? {
        // Handle :: expansion
        var result = [UInt8](repeating: 0, count: 16)
        let sides = s.components(separatedBy: "::")
        guard sides.count <= 2 else { return nil }

        func parseGroups(_ part: String) -> [[UInt8]]? {
            if part.isEmpty { return [] }
            let gs = part.split(separator: ":", omittingEmptySubsequences: false)
            var out: [[UInt8]] = []
            for g in gs {
                // Handle IPv4-mapped suffix (e.g., ::ffff:192.168.1.1)
                if g.contains(".") {
                    guard let v4 = parseIPv4(String(g)) else { return nil }
                    out.append([v4[0], v4[1]])
                    out.append([v4[2], v4[3]])
                } else {
                    guard let v = UInt16(g, radix: 16) else { return nil }
                    out.append([UInt8(v >> 8), UInt8(v & 0xFF)])
                }
            }
            return out
        }

        if sides.count == 1 {
            guard let groups = parseGroups(sides[0]), groups.count == 8 else { return nil }
            for (i, g) in groups.enumerated() {
                result[i * 2]     = g[0]
                result[i * 2 + 1] = g[1]
            }
        } else {
            guard let left  = parseGroups(sides[0]),
                  let right = parseGroups(sides[1])
            else { return nil }
            guard left.count + right.count <= 8 else { return nil }
            for (i, g) in left.enumerated() {
                result[i * 2] = g[0]; result[i * 2 + 1] = g[1]
            }
            let rightStart = 8 - right.count
            for (i, g) in right.enumerated() {
                result[(rightStart + i) * 2]     = g[0]
                result[(rightStart + i) * 2 + 1] = g[1]
            }
        }
        return result
    }
}

// MARK: - IPPrefix

/// An IP network prefix (address + prefix length).
public struct IPPrefix: Hashable, CustomStringConvertible {
    public var addr: IPAddr
    public var bits: Int

    public init(addr: IPAddr, bits: Int) {
        self.addr = addr
        self.bits = bits
    }

    public init?(string: String) {
        let parts = string.split(separator: "/")
        guard parts.count == 2,
              let addr = IPAddr(string: String(parts[0])),
              let bits = Int(parts[1])
        else { return nil }
        self.addr = addr
        self.bits = bits
    }

    public var masked: IPPrefix {
        var bytes = addr.rawBytes
        let totalBits = bytes.count * 8
        for i in bits..<totalBits {
            let byteIdx = i / 8
            let bitIdx  = 7 - (i % 8)
            bytes[byteIdx] &= ~(1 << bitIdx)
        }
        let maskedAddr = addr.isV4 ? IPAddr(v4: bytes) : IPAddr(v6: bytes)
        return IPPrefix(addr: maskedAddr, bits: bits)
    }

    public func contains(_ other: IPAddr) -> Bool {
        guard addr.kind == other.kind else { return false }
        let selfBytes  = addr.rawBytes
        let otherBytes = other.rawBytes
        let fullBytes  = bits / 8
        let remBits    = bits % 8
        for i in 0..<fullBytes {
            if selfBytes[i] != otherBytes[i] { return false }
        }
        if remBits > 0 {
            let mask = UInt8(0xFF) << (8 - remBits)
            if (selfBytes[fullBytes] & mask) != (otherBytes[fullBytes] & mask) { return false }
        }
        return true
    }

    public var description: String { "\(addr)/\(bits)" }
}

// MARK: - NetworkInterface

/// A snapshot of a network interface's properties.
public struct NetworkInterface: Equatable {
    public var index: Int
    public var name: String
    public var addresses: [IPAddr]
    public var flags: UInt32

    public init(index: Int, name: String, addresses: [IPAddr] = [], flags: UInt32 = 0) {
        self.index  = index
        self.name   = name
        self.addresses = addresses
        self.flags  = flags
    }

    public func equals(_ other: NetworkInterface) -> Bool {
        index == other.index && name == other.name
    }
}

// MARK: - ConnectionMetadata

/// Metadata carried with each proxied connection.
public struct ConnectionMetadata {
    public var network: String          // "tcp" or "udp"
    public var source: SocksAddr
    public var destination: SocksAddr

    public init(network: String, source: SocksAddr, destination: SocksAddr) {
        self.network     = network
        self.source      = source
        self.destination = destination
    }
}

// MARK: - TCPConn / UDPConn placeholders

/// A proxied TCP connection.
public protocol TCPConn: AnyObject {
    func read(into buffer: inout Data) throws -> Int
    func write(_ data: Data) throws -> Int
    func closeWrite() throws
    func close() throws
}

/// A proxied UDP "connection" (a logical flow sharing source/destination).
public protocol UDPConn: AnyObject {
    func readFrom() throws -> (Data, SocksAddr)
    func writeTo(_ data: Data, addr: SocksAddr) throws
    func close() throws
}

// MARK: - CallbackToken

/// An opaque handle returned when registering a callback, used to unregister it.
public final class CallbackToken: Hashable {
    private let id: UUID = UUID()
    public init() {}
    public static func == (lhs: CallbackToken, rhs: CallbackToken) -> Bool { lhs.id == rhs.id }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

// TunOptions mirrors the Go `Options` struct and contains all configuration
// needed to bring up a TUN device and its routing rules.

import Foundation

// MARK: - TunOptions

public struct TunOptions {
    /// The OS name of the interface, e.g. `"utun0"`.
    public var name: String

    /// IPv4 addresses to assign (CIDR notation, e.g. "198.18.0.1/16").
    public var inet4Address: [IPPrefix]

    /// IPv6 addresses to assign.
    public var inet6Address: [IPPrefix]

    /// Maximum Transmission Unit in bytes.
    public var mtu: UInt32

    /// Enable Generic Segmentation Offload (Linux only; ignored elsewhere).
    public var gso: Bool

    /// Automatically add routes for all traffic through this TUN.
    public var autoRoute: Bool

    /// Restrict routes to the named interface scope (Darwin).
    public var interfaceScope: Bool

    /// Override the IPv4 gateway address.
    public var inet4Gateway: IPAddr?

    /// Override the IPv6 gateway address.
    public var inet6Gateway: IPAddr?

    /// DNS server addresses to advertise / hijack.
    public var dnsServers: [IPAddr]

    /// ip rule / ip route table index (Linux).
    public var ipRoute2TableIndex: Int

    /// ip rule priority index (Linux).
    public var ipRoute2RuleIndex: Int

    /// Use mark-based redirect mode instead of port-based (Linux).
    public var autoRedirectMarkMode: Bool
    public var autoRedirectInputMark: UInt32
    public var autoRedirectOutputMark: UInt32

    /// Exclude MPTCP connections from the TUN (Linux).
    public var excludeMPTCP: Bool

    /// Additional loopback addresses for the IPv4/IPv6 stack.
    public var inet4LoopbackAddress: [IPAddr]
    public var inet6LoopbackAddress: [IPAddr]

    /// Enforce strict routing (no hairpin; Linux/Darwin).
    public var strictRoute: Bool

    /// Explicit route prefixes to install (overrides auto-route).
    public var inet4RouteAddress: [IPPrefix]
    public var inet6RouteAddress: [IPPrefix]

    /// Prefixes to exclude from routing.
    public var inet4RouteExcludeAddress: [IPPrefix]
    public var inet6RouteExcludeAddress: [IPPrefix]

    /// Only route traffic from / exclude traffic from these interfaces.
    public var includeInterface: [String]
    public var excludeInterface: [String]

    /// UID ranges to include / exclude (Android).
    public var includeUID: [ClosedRange<UInt32>]
    public var excludeUID: [ClosedRange<UInt32>]

    /// Android user IDs to include.
    public var includeAndroidUser: [Int]

    /// Android package names to include / exclude.
    public var includePackage: [String]
    public var excludePackage: [String]

    /// Use an already-open file descriptor rather than opening a new TUN socket.
    public var fileDescriptor: Int32

    /// Suppress DNS hijacking (for library embedders).
    public var disableDNSHijack: Bool

    /// Enable multi-pending-packet mode (experimental, Darwin).
    public var multiPendingPackets: Bool

    /// Use sendmsg_x for batch writes (experimental, may crash on Darwin).
    public var sendMsgX: Bool

    public init(name: String = "utun", mtu: UInt32 = 1500) {
        self.name                     = name
        self.inet4Address             = []
        self.inet6Address             = []
        self.mtu                      = mtu
        self.gso                      = false
        self.autoRoute                = false
        self.interfaceScope           = false
        self.inet4Gateway             = nil
        self.inet6Gateway             = nil
        self.dnsServers               = []
        self.ipRoute2TableIndex       = 2022
        self.ipRoute2RuleIndex        = 9000
        self.autoRedirectMarkMode     = false
        self.autoRedirectInputMark    = 0x2023
        self.autoRedirectOutputMark   = 0x2024
        self.excludeMPTCP             = false
        self.inet4LoopbackAddress     = []
        self.inet6LoopbackAddress     = []
        self.strictRoute              = false
        self.inet4RouteAddress        = []
        self.inet6RouteAddress        = []
        self.inet4RouteExcludeAddress = []
        self.inet6RouteExcludeAddress = []
        self.includeInterface         = []
        self.excludeInterface         = []
        self.includeUID               = []
        self.excludeUID               = []
        self.includeAndroidUser       = []
        self.includePackage           = []
        self.excludePackage           = []
        self.fileDescriptor           = 0
        self.disableDNSHijack         = false
        self.multiPendingPackets      = false
        self.sendMsgX                 = false
    }
}

// MARK: - Gateway helpers

public extension TunOptions {
    /// Effective IPv4 gateway: either the explicit override or derived from the first prefix.
    var inet4GatewayAddr: IPAddr {
        if let gw = inet4Gateway { return gw }
        guard let first = inet4Address.first else {
            return IPAddr(v4: [0, 0, 0, 0])
        }
        // Darwin: gateway == interface address
        // Other: gateway == address + 1 (if within prefix)
        return first.addr.next() ?? first.addr
    }

    /// Effective IPv6 gateway.
    var inet6GatewayAddr: IPAddr {
        if let gw = inet6Gateway { return gw }
        guard let first = inet6Address.first else {
            return IPAddr(v6: [UInt8](repeating: 0, count: 16))
        }
        return first.addr.next() ?? first.addr
    }
}

// MARK: - Auto-route range builder

public extension TunOptions {
    /// Build the set of route prefixes that should be installed for this TUN.
    ///
    /// Mirrors `Options.BuildAutoRouteRanges` from the Go implementation.
    func buildAutoRouteRanges(underNetworkExtension: Bool = false) -> [IPPrefix] {
        var result: [IPPrefix] = []

        // IPv4
        if !inet4Address.isEmpty {
            var ranges: [IPPrefix] = []
            if !inet4RouteAddress.isEmpty {
                ranges = inet4RouteAddress
                // On Darwin always include the interface subnet as well
                for addr in inet4Address where addr.bits < 32 {
                    ranges.append(addr.masked)
                }
            } else if autoRoute {
                if !underNetworkExtension {
                    // Darwin avoids installing a default route; use sub-ranges
                    ranges = Self.darwinIPv4SubRanges
                } else {
                    ranges = [IPPrefix(addr: IPAddr(v4: [0, 0, 0, 0]), bits: 0)]
                }
            } else {
                for addr in inet4Address where addr.bits < 32 {
                    ranges.append(addr.masked)
                }
            }

            if inet4RouteExcludeAddress.isEmpty {
                result.append(contentsOf: ranges)
            } else {
                result.append(contentsOf: subtract(ranges: ranges, excluding: inet4RouteExcludeAddress))
            }
        }

        // IPv6
        if !inet6Address.isEmpty {
            var ranges: [IPPrefix] = []
            if !inet6RouteAddress.isEmpty {
                ranges = inet6RouteAddress
                for addr in inet6Address where addr.bits < 128 {
                    ranges.append(addr.masked)
                }
            } else if autoRoute {
                if !underNetworkExtension {
                    ranges = Self.darwinIPv6SubRanges
                } else {
                    ranges = [IPPrefix(addr: IPAddr(v6: [UInt8](repeating: 0, count: 16)), bits: 0)]
                }
            } else {
                for addr in inet6Address where addr.bits < 128 {
                    ranges.append(addr.masked)
                }
            }

            if inet6RouteExcludeAddress.isEmpty {
                result.append(contentsOf: ranges)
            } else {
                result.append(contentsOf: subtract(ranges: ranges, excluding: inet6RouteExcludeAddress))
            }
        }

        return result
    }

    // Sub-ranges that cover 0.0.0.0/0 without the actual default route entry
    // (avoids breaking the host routing table on Darwin).
    private static let darwinIPv4SubRanges: [IPPrefix] = [
        IPPrefix(addr: IPAddr(v4: [1, 0, 0, 0]),   bits: 8),
        IPPrefix(addr: IPAddr(v4: [2, 0, 0, 0]),   bits: 7),
        IPPrefix(addr: IPAddr(v4: [4, 0, 0, 0]),   bits: 6),
        IPPrefix(addr: IPAddr(v4: [8, 0, 0, 0]),   bits: 5),
        IPPrefix(addr: IPAddr(v4: [16, 0, 0, 0]),  bits: 4),
        IPPrefix(addr: IPAddr(v4: [32, 0, 0, 0]),  bits: 3),
        IPPrefix(addr: IPAddr(v4: [64, 0, 0, 0]),  bits: 2),
        IPPrefix(addr: IPAddr(v4: [128, 0, 0, 0]), bits: 1),
    ]

    private static let darwinIPv6SubRanges: [IPPrefix] = [
        IPPrefix(addr: IPAddr(v6: withFirstByte(1)),   bits: 8),
        IPPrefix(addr: IPAddr(v6: withFirstByte(2)),   bits: 7),
        IPPrefix(addr: IPAddr(v6: withFirstByte(4)),   bits: 6),
        IPPrefix(addr: IPAddr(v6: withFirstByte(8)),   bits: 5),
        IPPrefix(addr: IPAddr(v6: withFirstByte(16)),  bits: 4),
        IPPrefix(addr: IPAddr(v6: withFirstByte(32)),  bits: 3),
        IPPrefix(addr: IPAddr(v6: withFirstByte(64)),  bits: 2),
        IPPrefix(addr: IPAddr(v6: withFirstByte(128)), bits: 1),
    ]

    // Naive prefix subtraction: returns `ranges` minus every address in `excluding`.
    // A production implementation would use a proper IP-set library.
    private func subtract(ranges: [IPPrefix], excluding: [IPPrefix]) -> [IPPrefix] {
        // For now, return the original ranges minus any that are fully contained
        // in an exclusion prefix. Partial overlaps are kept (conservative approach).
        ranges.filter { prefix in
            !excluding.contains { exc in
                exc.contains(prefix.addr) && exc.bits <= prefix.bits
            }
        }
    }
}

private func withFirstByte(_ b: UInt8) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: 16)
    bytes[0] = b
    return bytes
}

// MARK: - Broadcast address

public extension TunOptions {
    /// IPv4 broadcast address for the first configured prefix.
    var broadcastAddr: IPAddr? {
        guard let first = inet4Address.first else { return nil }
        let addrBytes = first.addr.rawBytes
        let bits      = first.bits
        var broadcast = addrBytes
        for i in bits..<32 {
            let byteIdx = i / 8
            let bitIdx  = 7 - (i % 8)
            broadcast[byteIdx] |= (1 << bitIdx)
        }
        return IPAddr(v4: broadcast)
    }
}

// MARK: - Interface name calculator

public func calculateInterfaceName(requested: String) -> String {
    let prefix: String
    #if os(macOS) || os(iOS)
    prefix = "utun"
    #else
    prefix = requested.isEmpty ? "tun" : requested
    #endif

    var maxIndex = -1
    if let interfaces = try? FileManager.default.contentsOfDirectory(atPath: "/sys/class/net") {
        for iface in interfaces {
            if iface.hasPrefix(prefix),
               let idx = Int(iface.dropFirst(prefix.count)) {
                maxIndex = max(maxIndex, idx)
            }
        }
    }
    return "\(prefix)\(maxIndex + 1)"
}

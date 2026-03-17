# sing-tun

Simple transparent proxy library.

For Linux, Windows, macOS and iOS.

## Architecture Analysis

### Overview

sing-tun is a cross-platform TUN (network tunnel) library that intercepts IP packets at the OS network interface level and dispatches them to application-layer handlers. It is designed to be used as the foundation of transparent proxy and VPN applications.

The general data flow is:

```
OS Network Interface (TUN device)
    │
    ▼
Platform-specific Tun implementation
(reads raw IP packets from the OS)
    │
    ▼
Stack implementation (GVisor / System / Mixed)
(parses packets, performs NAT, tracks sessions)
    │
    ▼
Handler interface (application-provided)
(routes and proxies the connection)
```

---

### Core Interfaces (`tun.go`, `stack.go`)

**`Tun`** — The raw OS tunnel interface. Platform-specific implementations wrap the OS TUN device and expose `Read`/`Write` for raw packet I/O.  Additional sub-interfaces provide platform-optimised batch I/O:

- **`LinuxTUN`** — `BatchRead` / `BatchWrite` with GSO/GRO offload support.
- **`WinTun`** — `ReadPacket` using the ring-buffer WinTUN driver.
- **`DarwinTUN`** — `BatchRead` / `BatchWrite` using `iovec` scatter-gather I/O.

**`Stack`** — Parses packets from the `Tun` device and invokes the `Handler`. Created via `NewStack(name, options)`, which selects one of three implementations:

| Stack name | Default selection criteria |
|---|---|
| `"gvisor"` | Always uses the gvisor userspace TCP/IP stack. Required when `IncludeAllNetworks` is true. |
| `"system"` | Uses the host OS TCP/IP stack via NAT. Preferred when GSO is enabled or gvisor is not compiled in. |
| `"mixed"` (default) | TCP via the system stack, UDP via gvisor. Best balance of performance and compatibility. |

**`Handler`** — Implemented by the application. Receives new TCP/UDP connections or ICMP flows intercepted from the TUN device:

- `PrepareConnection` — Called before a new connection is created to let the application decide whether to accept, reject, or direct-route the connection.
- `NewConnectionEx` — Delivers a new TCP connection.
- `NewPacketConnectionEx` — Delivers a new UDP packet-connection.

---

### Stack Implementations

#### System Stack (`stack_system.go`)

The system stack uses the host OS TCP/IP stack for reliable transport and performs source-NAT translation to redirect packets to a local TCP listener.

**Startup sequence:**

1. Opens a TCP listener on a random local port (`tcpListener` / `tcpListener6`).
2. Starts a goroutine (`tunLoop`) that reads packets from the TUN device in a platform-optimised batch loop.
3. Starts a goroutine (`acceptLoop`) that accepts inbound TCP connections arriving at the local listener.

**Packet processing (`processPacket` → `processIPv4` / `processIPv6`):**

```
Read packet from TUN
    │
    ├─ IPv4/IPv6 header validation
    │
    ├─ TCP  ──► processIPv4TCP / processIPv6TCP
    │               │
    │               ├─ TCPNat.Lookup(source, destination)
    │               │       allocates a NAT port, calls Handler.PrepareConnection
    │               │
    │               └─ Rewrite destination to 127.0.0.1:<tcpPort>
    │                  Rewrite source port to NAT port
    │                  Write packet back to TUN  ──► OS delivers to local listener
    │
    ├─ UDP  ──► processIPv4UDP / processIPv6UDP
    │               │
    │               └─ udpnat.Service dispatches to Handler.NewPacketConnectionEx
    │
    └─ ICMP ──► processIPv4ICMP / processIPv6ICMP
                    │
                    └─ DirectRouteMapping (ping forwarding via raw socket)
```

TCP connections looped back through the OS arrive at `acceptLoop`, which calls `Handler.NewConnectionEx` with the original source and destination addresses recovered from the NAT table.

#### TCP NAT Table (`stack_system_nat.go`)

`TCPNat` maintains bidirectional mappings between client source `AddrPort` values and synthetic local port numbers:

- **`addrMap`** — `source AddrPort → NAT port` (used when forwarding outbound packets).
- **`portMap`** — `NAT port → TCPSession` (used when recovering the original session on incoming connections).

A background goroutine runs every `timeout` interval and purges idle sessions. The port index starts at 10 000 and wraps, making port reuse predictable.

#### GVisor Stack (`stack_gvisor.go`, `stack_gvisor_tcp.go`, `stack_gvisor_udp.go`)

The GVisor stack feeds raw IP packets directly into a fully-featured userspace TCP/IP stack based on [Google gVisor](https://github.com/google/gvisor). No host OS TCP/IP processing is involved.

A `channel.Endpoint` bridges the TUN device and the gVisor stack:

- Inbound packets (TUN → gVisor): the `tunLoop` injects packets into the endpoint via `InjectInbound`.
- Outbound packets (gVisor → TUN): the `packetLoop` dequeues packets from the endpoint's `ReadContext` and writes them to the TUN device.

Protocol handlers registered on the gVisor stack:

| Protocol | Handler |
|---|---|
| TCP | `TCPForwarder` — accepts new connections and calls `Handler.NewConnectionEx` |
| UDP | `UDPForwarder` — dispatches datagrams to `Handler.NewPacketConnectionEx` |
| ICMPv4/v6 | `ICMPHandler` — handles ping echo request/reply |

#### Mixed Stack (`stack_mixed.go`)

The mixed stack composes the system stack (for TCP) with the gVisor stack (for UDP):

- TCP packets are handled by the embedded `*System` — they go through the host TCP/IP stack and arrive at the local listener.
- UDP packets are intercepted in `tunLoop` and injected into the gVisor endpoint, bypassing system-stack UDP processing.

---

### Platform-Specific TUN Implementations

#### Linux (`tun_linux.go`, `tun_offload_linux.go`)

- Uses `/dev/net/tun` via the `syscall` package.
- Supports **Batch I/O** — reads/writes multiple packets per syscall using `readv`/`writev`.
- Supports **GSO** (Generic Segmentation Offload) and **GRO** (Generic Receive Offload) via `tun_offload_linux.go`, which coalesces small UDP datagrams or large TCP segments to reduce syscall overhead.
- Manages policy routing rules (`ip rule`, `ip route`) for auto-route mode via `tun_rules.go`.
- Supports traffic redirect via **nftables** (`redirect_nftables.go`) or **iptables** (`redirect_linux.go`).

#### Windows (`tun_windows.go`)

- Uses the **WinTUN** kernel driver (`internal/wintun`) via a DLL loaded at runtime.
- The WinTUN driver exposes a shared-memory ring buffer; `ReadPacket` returns a zero-copy pointer to the next available packet.
- IP configuration (addresses, routes, DNS) is applied via `winipcfg` (Win32 IP Helper API).
- Windows Firewall integration via `internal/winfw`.

#### macOS / iOS (`tun_darwin.go`)

- Uses the **utun** virtual interface created via a socket with `SYSPROTO_CONTROL` / `UTUN_CONTROL_NAME`.
- Batch I/O uses `iovec` structures and `readv`/`writev` system calls.
- Uses `fdbased_darwin` for the gVisor channel endpoint on Darwin.

---

### Traffic Redirect (Linux, `redirect_nftables.go`)

When `AutoRoute` is enabled, sing-tun installs OS-level firewall rules to redirect all outbound traffic into the TUN interface:

1. An nftables (or iptables) ruleset marks packets belonging to target UIDs/processes.
2. Policy routing rules (`ip rule fwmark`) direct marked packets to a custom routing table that sends them via the TUN interface.
3. Traffic from the TUN interface itself is excluded to avoid routing loops.

OpenWrt-specific rules are generated separately (`redirect_nftables_rules_openwrt.go`).

---

### ICMP / Ping Forwarding (`ping/`)

The `ping` package implements transparent ICMP echo (ping) proxying:

- `Destination` opens a raw ICMP socket (privileged) or an unprivileged ICMP datagram socket (Linux) to the real target host.
- Outbound ping requests from the TUN device are forwarded via `WritePacket`, which records the `(source, destination, id, seq)` tuple to allow response matching.
- Responses received on the raw socket are matched against the recorded requests and written back to the TUN device via `DirectRouteContext.WritePacket`.
- On platforms that receive all ICMP traffic on a shared socket (Windows, macOS), a destination filter (`needFilter`) is applied to ensure only replies to known requests are forwarded.

---

### Network Change Monitoring (`monitor.go`, platform files)

`NetworkUpdateMonitor` and `DefaultInterfaceMonitor` watch for OS network configuration changes (interface up/down, route changes, default gateway changes) and notify the application so it can update routing decisions accordingly:

| Platform | Mechanism |
|---|---|
| Linux | netlink `RTMGRP_LINK` / `RTMGRP_IPV4_ROUTE` socket |
| macOS | `PF_ROUTE` socket with `kqueue` |
| Windows | `NotifyRouteChange2` / `NotifyUnicastIpAddressChange` Win32 APIs |
| Android | VPN service callbacks |

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```
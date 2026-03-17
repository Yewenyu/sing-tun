// Direct-route session cache.
// Mirrors route_direct.go from the Go implementation.

import Foundation

// MARK: - DirectRouteSession

/// Key identifying a direct-route flow.
public struct DirectRouteSession: Hashable {
    public var source:      IPAddr
    public var destination: IPAddr

    public init(source: IPAddr, destination: IPAddr) {
        self.source      = source
        self.destination = destination
    }
}

// MARK: - DirectRouteMapping

/// An LRU-style cache mapping (source, destination) pairs to their
/// `DirectRouteDestination` handlers with automatic timeout eviction.
///
/// Mirrors `DirectRouteMapping` from `route_direct.go`.
public final class DirectRouteMapping {
    private let timeout:   TimeInterval
    private let lock =     NSLock()
    private var cache:     [DirectRouteSession: Entry] = [:]
    private let maxSize =  1024

    private struct Entry {
        let destination: DirectRouteDestination
        var expires:     Date
    }

    public init(timeout: TimeInterval) {
        self.timeout = timeout
    }

    /// Look up or create a `DirectRouteDestination` for the given session.
    public func lookup(
        session: DirectRouteSession,
        constructor: (TimeInterval) throws -> DirectRouteDestination
    ) throws -> DirectRouteDestination {
        lock.lock()

        // Evict expired / closed entries
        evictLocked()

        if let entry = cache[session], !entry.destination.isClosed {
            cache[session]?.expires = Date().addingTimeInterval(timeout)
            lock.unlock()
            return entry.destination
        }

        lock.unlock()

        // Create outside the lock to avoid deadlock in constructor.
        let dest = try constructor(timeout)

        lock.lock()
        defer { lock.unlock() }

        // Another thread may have created it in the meantime; prefer ours.
        if let existing = cache[session], !existing.destination.isClosed {
            try? dest.close()
            return existing.destination
        }

        cache[session] = Entry(destination: dest, expires: Date().addingTimeInterval(timeout))
        return dest
    }

    // MARK: Private

    private func evictLocked() {
        let now = Date()
        cache = cache.filter { _, entry in
            !entry.destination.isClosed && entry.expires > now
        }
        if cache.count > maxSize {
            // Evict oldest quarter by expiry
            let sorted = cache.sorted { $0.value.expires < $1.value.expires }
            for (key, entry) in sorted.prefix(cache.count / 4) {
                try? entry.destination.close()
                cache.removeValue(forKey: key)
            }
        }
    }
}

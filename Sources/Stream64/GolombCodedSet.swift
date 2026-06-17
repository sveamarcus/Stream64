//===----------------------------------------------------------------------===//
//
// This source file is part of the Stream64 open source project
//
// Copyright (c) 2022-2026 fltrWallet AG and the Stream64 project authors
// Licensed under Apache License v2.0
//
// See LICENSE.md for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import CStream64
import Logging

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#elseif canImport(WASILibc)
import WASILibc
#endif

/// Operation-boundary logger for the GCS codec. Messages are emoji-rich and only
/// rendered when the host raises the log level (autoclosures keep the hot path
/// free) — nothing is ever logged from inside a per-element loop.
let gcsLog = Logger(label: "com.fltrwallet.stream64.gcs")

@inline(__always)
func monotonicNanos() -> UInt64 {
    var ts = timespec()
    clock_gettime(CLOCK_MONOTONIC, &ts)
    return UInt64(ts.tv_sec) &* 1_000_000_000 &+ UInt64(ts.tv_nsec)
}

/// A pluggable Golomb-Coded-Set codec front end.
///
/// `Stream64` is a generic Golomb-Rice + delta codec over caller-supplied sorted
/// `UInt64` values.
public struct GolombCodedSetClient: Sendable {
    public init(decode: @escaping @Sendable ([UInt8], Int, Int) -> [UInt64]?,
                encode: @escaping @Sendable ([UInt64], Int) -> [UInt8]?) {
        self.decode0 = decode
        self.encode0 = encode
    }

    public func decode(compressed: [UInt8], n: Int, p: Int) -> [UInt64]? {
        guard n > 0
        else { return [] }

        return self.decode0(compressed, n, p)
    }
    let decode0: @Sendable ([UInt8], Int, Int) -> [UInt64]?

    public func encode(sorted: [UInt64], p: Int) -> [UInt8]? {
        guard sorted.count > 0
        else { return [] }

        return self.encode0(sorted, p)
    }
    let encode0: @Sendable ([UInt64], Int) -> [UInt8]?

    public func encode(unsorted: [UInt64], p: Int) -> [UInt8]? {
        self.encode(sorted: unsorted.sorted(), p: p)
    }
}

enum Stream64GCS {
    /// Valid Golomb parameter range for this codec. Lower bound 1; upper bound 56
    /// matches the encoder (`write_bitstream`/`write_gcs` reject `p > 56`) and
    /// stays within the reader's `bitpos + p <= 64` window invariant.
    static let validP = 1...56

    static func decode(compressed: [UInt8], n: Int, p: Int) -> [UInt64]? {
        guard n > 0
        else { return [] }

        guard validP.contains(p)
        else {
            gcsLog.error("❌ GCS decode rejected — 🚫 invalid p=\(p) (valid 1...56) 🧯")
            return nil
        }

        guard !compressed.isEmpty, n <= compressed.count * 8
        else {
            gcsLog.warning("⚠️ GCS decode rejected — 🐘 implausible n=\(n) for \(compressed.count) B buffer (capping alloc, possible hostile filter) 🛡️")
            return nil
        }

        gcsLog.trace("🔓 GCS decode ▶️  n=\(n) · p=\(p) · 📥 \(compressed.count) B")
        let started = monotonicNanos()

        var overflow: Int32 = 0
        var produced = 0
        let result = [UInt64](unsafeUninitializedCapacity: n) { buffer, setSizeTo in
            guard let out = buffer.baseAddress
            else { setSizeTo = 0; return }

            produced = compressed.withUnsafeBufferPointer { source -> Int in
                guard let base = source.baseAddress
                else { return 0 }
                return read_gcs(base, source.count, n, p, out, &overflow)
            }
            setSizeTo = produced
        }
        let elapsed = monotonicNanos() &- started

        if overflow != 0 {
            gcsLog.error("💥 GCS decode aborted — ♾️ accumulator overflowed UInt64 after \(produced) value(s) (corrupt/hostile filter) 🧨")
            return nil
        }
        guard produced == n
        else {
            gcsLog.trace("⚠️ GCS decode truncated — 🪓 \(produced)/\(n) values (payload shorter than declared n) ✂️")
            return nil
        }

        gcsLog.trace("✅ GCS decode 📦 \(produced) values ⟵ \(compressed.count) B · ⏱️ \(Self.duration(elapsed)) · \(Self.rate(produced, elapsed)) 🎉")
        return result
    }

    static func encode(sorted: [UInt64], p: Int) -> [UInt8]? {
        guard sorted.count > 0
        else { return [] }

        guard validP.contains(p)
        else {
            gcsLog.error("❌ GCS encode rejected — 🚫 invalid p=\(p) (valid 1...56) 🧯")
            return nil
        }

        gcsLog.trace("🔐 GCS encode ▶️  \(sorted.count) values · p=\(p) 🧮")
        let started = monotonicNanos()

        // Safe upper bound on the encoded size of a non-decreasing input:
        //   total bits ≤ (maxValue >> p) + count·(p + 1)
        // (Σ of the unary quotients ≤ maxValue >> p; each element adds 1 + p bits.)
        // Computed with overflow checks so a pathological input fails cleanly
        // instead of mis-sizing the buffer.
        let maxValue = sorted.last ?? 0
        let upperBits = maxValue >> UInt64(p)
        let (perElementBits, mulOverflow) = UInt64(sorted.count).multipliedReportingOverflow(by: UInt64(p + 1))
        let (subtotal, addOverflow1) = upperBits.addingReportingOverflow(perElementBits)
        let (totalBits, addOverflow2) = subtotal.addingReportingOverflow(64)
        guard !mulOverflow, !addOverflow1, !addOverflow2
        else {
            gcsLog.error("❌ GCS encode rejected — 🌌 input too sparse to size a buffer for (count=\(sorted.count), p=\(p)) 🧱")
            return nil
        }
        let byteBound = totalBits / 8 + 16
        guard byteBound <= UInt64(Int.max)
        else {
            gcsLog.error("❌ GCS encode rejected — 🌌 encoded size would exceed addressable memory 🧱")
            return nil
        }
        let capacity = Int(byteBound)

        var written = 0
        var cRet: UInt32 = 1
        let result = [UInt8](unsafeUninitializedCapacity: capacity) { buffer, setSizeTo in
            guard let dest = buffer.baseAddress
            else { setSizeTo = 0; return }

            cRet = sorted.withUnsafeBufferPointer { source -> UInt32 in
                guard let base = source.baseAddress
                else { return 1 }
                return write_gcs(p, base, source.count, dest, buffer.count, &written)
            }
            setSizeTo = (cRet == 0) ? written : 0
        }
        let elapsed = monotonicNanos() &- started

        guard cRet == 0, !result.isEmpty
        else {
            // Reachable when the input is not actually sorted (its wrapped deltas
            // explode past `capacity`) — fail safe rather than overrun.
            gcsLog.error("❌ GCS encode failed — 🧨 capacity exceeded (input not non-decreasing?) for \(sorted.count) values, p=\(p) 🚧")
            return nil
        }

        gcsLog.debug("✅ GCS encode 🗜️ \(sorted.count) values ⟶ \(result.count) B · \(Self.ratio(values: sorted.count, bytes: result.count)) · ⏱️ \(Self.duration(elapsed)) 🎁")
        return result
    }

    // MARK: Pretty log formatting (integer math only — no Foundation; only
    // evaluated inside log autoclosures, so it never touches the hot path).

    /// One-decimal fixed-point string for `value / 10` (e.g. 2503 -> "250.3").
    private static func oneDecimal(_ tenths: UInt64) -> String {
        "\(tenths / 10).\(tenths % 10)"
    }

    static func duration(_ nanos: UInt64) -> String {
        if nanos >= 1_000_000 { return "\(oneDecimal(nanos / 100_000)) ms" }   // tenths of ms
        if nanos >= 1_000 { return "\(oneDecimal(nanos / 100)) µs" }           // tenths of µs
        return "\(nanos) ns"
    }

    static func rate(_ count: Int, _ nanos: UInt64) -> String {
        guard nanos > 0 else { return "🚀 ∞ M/s" }
        // M values/s × 10  =  count × 10_000 / nanos
        let mpsTenths = UInt64(count) &* 10_000 / nanos
        let gauge = mpsTenths >= 1500 ? "🚀" : mpsTenths >= 500 ? "🏎️" : mpsTenths >= 100 ? "🏃" : "🐢"
        return "\(gauge) \(oneDecimal(mpsTenths)) M values/s"
    }

    static func ratio(values: Int, bytes: Int) -> String {
        guard values > 0 else { return "" }
        let bitsPerValueTenths = UInt64(bytes) &* 80 / UInt64(values)          // (bytes*8/values) × 10
        // 8-segment bar: how much of a raw 64-bit value the encoding keeps.
        let filled = min(8, Int(bitsPerValueTenths / 80))                       // (bits/value) / 8
        let bar = String(repeating: "▰", count: filled) + String(repeating: "▱", count: 8 - filled)
        return "\(bar) \(oneDecimal(bitsPerValueTenths)) bits/value"
    }
}

public extension GolombCodedSetClient {
    /// The default Stream64-backed GCS codec.
    static let stream64 = GolombCodedSetClient(
        decode: { Stream64GCS.decode(compressed: $0, n: $1, p: $2) },
        encode: { Stream64GCS.encode(sorted: $0, p: $1) }
    )
}

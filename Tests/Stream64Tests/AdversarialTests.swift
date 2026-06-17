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
// Adversarial / hostile-input regression tests. Every case here corresponds to a
// memory-safety or robustness defect found during the security & crypto audit.
// "Returns nil and the process survives" IS the assertion: a regression that
// reintroduces an out-of-bounds read/write or an overflow trap fails the suite.
import Stream64
import Testing

@Suite struct AdversarialTests {
    let client = GolombCodedSetClient.stream64

    // MARK: Decode — out-of-bounds read (attacker-controlled n / truncated payload)

    @Test func decodeImplausibleNRejectedByGuard() {
        // Tiny payload, huge declared element count: rejected up front by the
        // Swift `n <= count*8` memory-exhaustion guard (never allocates n UInt64s).
        #expect(client.decode(compressed: [0, 0, 0, 0], n: 100_000, p: 19) == nil)
        #expect(client.decode(compressed: [UInt8](repeating: 0xFF, count: 32), n: 10_000, p: 19) == nil)
    }

    @Test func decodeOversizedNWithinGuardStopsViaCBoundsCheck() {
        // n == count*8 PASSES the Swift guard, so read_gcs is actually entered.
        // The payload encodes only a few values, so the C reader walks into the
        // bounded zero-padded tail; the truncation check (NOT an OOB read) stops
        // it. If the C bounds-check were reverted this would over-read the buffer
        // (caught under ASan); with it, decode fails cleanly.
        let encoded = client.encode(sorted: [1, 2, 3, 100, 524_288], p: 19)!
        let oversized = encoded.count * 8           // the largest n the guard allows
        #expect(client.decode(compressed: encoded, n: oversized, p: 19) == nil)
        // All-ones payload (no terminator) with n at the guard limit: must
        // terminate via zero-pad + truncation, never loop or over-read.
        let allOnes = [UInt8](repeating: 0xFF, count: 24)
        #expect(client.decode(compressed: allOnes, n: allOnes.count * 8, p: 19) == nil)
    }

    @Test func decodeAccumulatorOverflowReturnsNil() {
        // Two deltas of 2^63 (p=56) — a hostile filter a real encoder cannot
        // produce, since the 2nd accumulator would be 2^64. read_gcs must detect
        // the UInt64 overflow (__builtin_add_overflow) and fail, never trap/wrap.
        let hostile = gcsBitstream(deltas: [UInt64(1) << 63, UInt64(1) << 63], p: 56)
        #expect(client.decode(compressed: hostile, n: 2, p: 56) == nil)
    }

    @Test func truncationBoundaryIsExact() {
        // Deterministic boundary: decoding exactly `count` values succeeds;
        // asking for one more must truncate (the element-count bit boundary).
        let input: [UInt64] = [3, 9, 9, 40, 1000, 1_000_000]
        let encoded = client.encode(sorted: input, p: 19)!
        #expect(client.decode(compressed: encoded, n: input.count, p: 19) == input)
        #expect(client.decode(compressed: encoded, n: input.count + 1, p: 19) == nil)
    }

    @Test func decodeEmptyOrShortBuffer() {
        #expect(client.decode(compressed: [], n: 1, p: 19) == nil)
        #expect(client.decode(compressed: [0x01], n: 1, p: 19) == nil)
        #expect(client.decode(compressed: [], n: 0, p: 19) == [])
    }

    @Test func decodeAllOnesNoTerminatorTerminates() {
        // A run of 1-bits with no terminating 0 used to walk readUnary off the end
        // unboundedly. Bounded reads must make it terminate and fail cleanly.
        let hostile = [UInt8](repeating: 0xFF, count: 256)
        #expect(client.decode(compressed: hostile, n: 5, p: 19) == nil)
    }

    @Test(arguments: [0, -1, 57, 58, 64, 1000]) func decodeRejectsInvalidP(p: Int) {
        #expect(client.decode(compressed: [UInt8](repeating: 0, count: 64), n: 4, p: p) == nil)
    }

    // MARK: Encode — heap overflow (sparse input overruns the old count*8 buffer)

    @Test(arguments: [UInt64(1) << 25, 1 << 30, 1 << 35, 1 << 40])
    func encodeSparseDeltaDoesNotOverflow(delta: UInt64) throws {
        // The 2nd delta needs (delta >> 19) unary bits — for delta=2^40 that is
        // ~262 KB, vastly more than the old sorted.count*8 = 16-byte allocation.
        // Must size correctly, encode, and round-trip — not corrupt the heap.
        let input: [UInt64] = [0, delta]
        let encoded = try #require(client.encode(sorted: input, p: 19))
        let decoded = client.decode(compressed: encoded, n: input.count, p: 19)
        #expect(decoded == input)
    }

    @Test func encodeUnsortedFailsSafely() {
        // Non-monotonic input makes a delta wrap to a huge UInt64; the capacity
        // bound must catch it and return nil rather than overrun the buffer.
        #expect(client.encode(sorted: [100, 50, 10], p: 19) == nil)
    }

    @Test(arguments: [0, -1, 57, 64]) func encodeRejectsInvalidP(p: Int) {
        #expect(client.encode(sorted: [1, 2, 3], p: p) == nil)
    }

    // MARK: Codec correctness on adversarial-but-valid inputs (clz unary path)

    @Test func largeQuotientsRoundTrip() throws {
        // Quotients that span multiple 64-bit windows (63/64/65/127/128/129…)
        // exercise the clz bulk-unary boundary and the all-ones clz(0) case.
        let quotients: [UInt64] = [0, 1, 62, 63, 64, 65, 126, 127, 128, 129, 191, 192, 300, 1000]
        var acc: UInt64 = 0
        let input: [UInt64] = quotients.map { q in acc &+= (q << 19) &+ (q & 0x7FFFF); return acc }
        let encoded = try #require(client.encode(sorted: input, p: 19))
        #expect(client.decode(compressed: encoded, n: input.count, p: 19) == input)
    }

    @Test func duplicateValuesRoundTrip() throws {
        let input: [UInt64] = [5, 5, 5, 100, 100, 100, 100, 1_000_000]
        let encoded = try #require(client.encode(sorted: input, p: 19))
        #expect(client.decode(compressed: encoded, n: input.count, p: 19) == input)
    }

    @Test func singleElementRoundTrip() throws {
        for v: UInt64 in [0, 1, 524_287, 524_288, 1 << 40] {
            let encoded = try #require(client.encode(sorted: [v], p: 19))
            #expect(client.decode(compressed: encoded, n: 1, p: 19) == [v])
        }
    }

    // MARK: Property: round-trip holds for random sorted sets across all p

    @Test(arguments: [1, 2, 7, 8, 11, 19, 23, 31, 32, 40, 56])
    func randomRoundTrip(p: Int) throws {
        let maxLower: UInt64 = (UInt64(1) << p) - 1
        for _ in 0..<8 {
            let target = Int.random(in: 1...3000)
            var acc: UInt64 = 0
            var input: [UInt64] = []
            input.reserveCapacity(target)
            for _ in 0..<target {
                // Mix small and occasionally larger gaps to stress the unary path.
                let q: UInt64 = UInt64.random(in: 0...3) == 0 ? UInt64.random(in: 0...80) : 0
                let delta = (q << UInt64(p)) &+ UInt64.random(in: 0...maxLower)
                // Stop before the accumulator would wrap so the input stays a
                // genuine non-decreasing sequence (large p overflows UInt64 fast).
                let (next, overflow) = acc.addingReportingOverflow(delta)
                if overflow { break }
                acc = next
                input.append(acc)
            }
            guard !input.isEmpty else { continue }
            let encoded = try #require(client.encode(sorted: input, p: p))
            #expect(client.decode(compressed: encoded, n: input.count, p: p) == input)
        }
    }
}

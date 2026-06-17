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

extension String {
    var hex2Bytes: [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(count / 2)
        var index = startIndex
        while let next = self.index(index, offsetBy: 2, limitedBy: endIndex) {
            guard let byte = UInt8(self[index..<next], radix: 16) else { return result }
            result.append(byte)
            index = next
        }
        return result
    }
}

/// Build a raw GCS bitstream for arbitrary deltas, mirroring the C encoder's bit
/// layout (unary quotient 1-bits, a 0 terminator, then `p` remainder bits,
/// MSB-first). Unlike the public encoder it takes deltas directly — including
/// ones whose accumulation overflows UInt64 — so tests can craft hostile filters
/// that a valid encoder would never produce (e.g. to exercise the decode
/// overflow guard).
func gcsBitstream(deltas: [UInt64], p: Int) -> [UInt8] {
    precondition((1...56).contains(p))
    let mask: UInt64 = (UInt64(1) << p) - 1
    var bits: [Bool] = []
    for delta in deltas {
        var quotient = delta >> UInt64(p)
        while quotient > 0 { bits.append(true); quotient -= 1 }   // unary 1s
        bits.append(false)                                        // 0 terminator
        let lower = delta & mask
        for shift in stride(from: p - 1, through: 0, by: -1) {    // p bits, MSB-first
            bits.append((lower >> UInt64(shift)) & 1 == 1)
        }
    }
    var bytes: [UInt8] = []
    var current: UInt8 = 0
    var filled = 0
    for bit in bits {
        current = (current << 1) | (bit ? 1 : 0)
        filled += 1
        if filled == 8 { bytes.append(current); current = 0; filled = 0 }
    }
    if filled > 0 { bytes.append(current << (8 - filled)) }       // pad final byte MSB-first
    return bytes
}

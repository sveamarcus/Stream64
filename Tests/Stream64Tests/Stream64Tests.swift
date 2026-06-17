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
import Stream64
import Testing

@Suite struct Stream64BitstreamTests {
    @Test func writeReadUnary() throws {
        let input = (0..<103).map { _ in UInt64(1) } + [0]
        let result = try Stream64.streamWrite(values: input, p: 1)
        let expected: [UInt8] = [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254]
        #expect(result == expected)

        let stream64 = Stream64(data: result, count: input.count, p: 1)
        #expect([UInt64](stream64) == input)
    }

    @Test func writeReadP11() throws {
        let input: [UInt64] = [0, 2047, 0, 2047]
        let expected: [UInt8] = [0, 31, 252, 0, 127, 240]

        let result = try Stream64.streamWrite(values: input, p: 11)
        #expect(result == expected)
        #expect([UInt64](Stream64(data: result, p: 11)) == input)
    }

    @Test func writeReadP19() throws {
        let input: [UInt64] = [0, 524287, 0, 524287]
        let expected: [UInt8] = [0, 0, 0x1f, 0xff, 0xfc, 0, 0, 127, 0xff, 0xf0]

        let result = try Stream64.streamWrite(values: input, p: 19)
        #expect(result == expected)
        #expect([UInt64](Stream64(data: result, p: 19)) == input)
    }

    @Test func writeReadRoundtrip() throws {
        let input = (0..<100_000).map { _ in UInt64(2047) }
        let result = try Stream64.streamWrite(values: input, p: 11)

        let resultCount = input.count / 8 * 11
        #expect(result.count == resultCount)
        #expect(result == (0..<resultCount).map { _ in UInt8.max })

        #expect([UInt64](Stream64(data: result, p: 11)) == input)
    }

    @Test(arguments: 1...56) func writeReadRandom(p: Int) throws {
        let maxValue: UInt64 = (UInt64(1) << p) - 1
        let count = Int.random(in: 1..<20_000)
        let input = (0..<count).map { _ in UInt64.random(in: 0...maxValue) }

        let result = try Stream64.streamWrite(values: input, p: p)
        let stream64 =
            p > 7
            ? Stream64(data: result, p: p)
            : Stream64(data: result, count: input.count, p: p)

        let all = [UInt64](stream64)
        #expect(all.count == input.count)
        for (offset, element) in stream64.enumerated() {
            #expect(input[offset] == element)
        }
    }
}

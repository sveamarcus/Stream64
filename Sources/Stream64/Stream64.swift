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

/// A lazily-decoded sequence of fixed-width `p`-bit values packed MSB-first.
///
/// The backing `CStream64` reader is bounds-checked against `data.count`, so the
/// sequence is safe to construct over short or untrusted input.
public struct Stream64: Codable, Sequence, Sendable {
    @usableFromInline
    let data: [UInt8]
    @usableFromInline
    let count: Int
    @usableFromInline
    let p: Int

    @inlinable
    public init(data: [UInt8], count: Int, p: Int) {
        precondition((1...57).contains(p))
        self.data = data
        self.count = count
        self.p = p
    }

    @inlinable
    public init(data: [UInt8], p: Int) {
        precondition((8...57).contains(p))
        self.count = data.count * 8 / p
        self.data = data
        self.p = p
    }

    @inlinable
    public func makeIterator() -> StreamIterator {
        StreamIterator(self)
    }
}

public struct StreamIterator: IteratorProtocol {
    @usableFromInline
    let stream64: Stream64
    @usableFromInline
    var state: CStream64.gcs_state
    @usableFromInline
    var index: Int = 0

    @inlinable
    public init(_ stream64: Stream64) {
        self.stream64 = stream64
        self.state = CStream64.initialize()
    }

    @inlinable
    public mutating func next() -> UInt64? {
        guard self.index < self.stream64.count
        else {
            return nil
        }

        defer { self.index += 1 }

        return self.stream64.data.withUnsafeBufferPointer {
            guard let base = $0.baseAddress
            else { return 0 }
            return read_p(
                base,
                $0.count,
                self.stream64.p,
                &self.state)
        }
    }
}

public enum Stream64Error: Error {
    case illegalInput
}

public extension Stream64 {
    @inlinable
    static func streamWrite(values: [UInt64], p: Int) throws -> [UInt8] {
        precondition((1...56).contains(p))
        guard !values.isEmpty
        else { return [] }

        let bitsCount = values.count * p
        let bytesCountCeil = (bitsCount + 7) / 8

        return try Array(unsafeUninitializedCapacity: bytesCountCeil) { buffer, setSizeTo in
            let cRet = values.withUnsafeBufferPointer { values in
                write_bitstream(
                    values.baseAddress!, values.count, p, buffer.baseAddress, buffer.count,
                    &setSizeTo)
            }
            guard cRet == 0
            else { throw Stream64Error.illegalInput }
        }
    }
}

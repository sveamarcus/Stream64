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
//
// CStream64 — a small, fast, big-endian (MSB-first) bit-stream codec for
// Golomb-Rice / Golomb-Coded-Set (GCS) data, as used by BIP158 compact block
// filters.
//
// PORTABILITY: Requires a little-endian target and a clang/gcc-compatible
// compiler (uses __builtin_bswap64 / __builtin_clzll). A _Static_assert in the
// .c file enforces little-endian at build time.
//
//===----------------------------------------------------------------------===//
#ifndef INCLUDE_CSTREAM64_H
#define INCLUDE_CSTREAM64_H

#include <stdint.h>
#include <stddef.h>

/// Mutable cursor into a big-endian bit stream.
///   - bitbuf: the current 64-bit big-endian window
///   - bitpos: number of bits already consumed from the top of `bitbuf` (0..63)
///   - bufpos: byte offset of `bitbuf` within the backing buffer
typedef struct gcs_state {
    uint64_t bitbuf;
    size_t bitpos;
    size_t bufpos;
} gcs_state;

/// A freshly-zeroed decoder cursor.
extern gcs_state initialize(void);

// MARK: - Reading (decode)

/// Read the next `p`-bit value from a fixed-width bit stream.
///
/// `length` is the real byte count of `base`. Reads are clamped to `[0, length)`
extern uint64_t read_p(const uint8_t *base, size_t length, size_t p, gcs_state *state);

/// Bulk-decode up to `n` delta-coded GCS values from `base[0, length)` into `out`
/// (which must have capacity for `n` UInt64s).
extern size_t read_gcs(const uint8_t *base, size_t length, size_t n, size_t p,
                       uint64_t *out, int *overflow);

// MARK: - Writing (encode)

/// Pack `data_size` fixed-width `p`-bit values into `dest` (capacity `dest_capacity`
/// bytes), MSB-first. Writes `*result_bytes` bytes on success.
/// Returns 0 on success, 1 on invalid argument or insufficient capacity.
extern uint32_t write_bitstream(const uint64_t *data, size_t data_size, size_t p,
                                uint8_t *dest, size_t dest_capacity, size_t *result_bytes);

/// Golomb-Rice + delta encode `data_size` sorted (non-decreasing) values into
/// `dest` (capacity `dest_capacity` bytes). Writes `*result_bytes` bytes on success.
/// Returns 0 on success, 1 on invalid argument or insufficient capacity (the
/// latter also fires for non-sorted input, whose deltas wrap to huge values).
extern uint32_t write_gcs(size_t p, const uint64_t *sorted, size_t data_size,
                          uint8_t *dest, size_t dest_capacity, size_t *result_bytes);

#define GCS_UNARY 0x0000000000000001ULL
#define GCS_UNARY_EOF 0x0000000000000000ULL

#endif /* INCLUDE_CSTREAM64_H */

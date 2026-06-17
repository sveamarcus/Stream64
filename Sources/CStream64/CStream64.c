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
// Big-endian (MSB-first) Golomb-Rice / GCS bit-stream codec. See CStream64.h
// for scope, portability, and safety notes.
//
// Design notes:
//  * All 64-bit window loads go through memcpy (read64be) — well-defined at any
//    alignment and free of strict-aliasing UB. On arm64/x86_64 at -O it lowers
//    to a single load (ldr) + byte reverse (rev).
//  * The decoder is bounds-checked against the caller's `length`: the tail is
//    read as if zero-padded, so truncated / malicious input can never read out
//    of bounds and never loops unboundedly.
//  * The unary quotient is decoded in bulk with __builtin_clzll (count leading
//    1-bits per 64-bit window).
//
//===----------------------------------------------------------------------===//
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "CStream64.h"

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
               "CStream64 currently requires a little-endian target.");
#endif

static inline uint64_t read64be(const uint8_t *byteptr) {
    uint64_t load;
    memcpy(&load, byteptr, sizeof load);
    return __builtin_bswap64(load);
}

// MARK: - Reading (decode)

// Refill the 64-bit window from `base`, advancing past fully-consumed bytes.
static inline void refill(gcs_state *const state,
                          const uint8_t *const base,
                          const size_t length) {
    state->bufpos += state->bitpos >> 3;
    const size_t pos = state->bufpos;

    uint64_t load;
    if (pos + 8 <= length) {
        // Fast path: a full window is in bounds (the common case; the branch is
        // perfectly predicted, so this costs nothing versus an unchecked load).
        memcpy(&load, base + pos, 8);
    } else {
        // Tail path: zero-pad the part that lies at/after the buffer end.
        uint8_t tmp[8] = { 0 };
        const size_t avail = (pos < length) ? (length - pos) : 0;
        memcpy(tmp, base + pos, avail);
        memcpy(&load, tmp, 8);
    }

    state->bitbuf = __builtin_bswap64(load);
    state->bitpos &= 7;
}

// Top `count` bits of the window, after discarding the already-consumed bits.
// Requires 1 <= count <= 57 and bitpos + count <= 64 (callers guarantee this).
static inline uint64_t peekbits(const size_t count,
                                const uint64_t bitbuf,
                                const size_t bitpos) {
    const uint64_t remaining = bitbuf << bitpos;
    return remaining >> (64 - count);
}

// Read `count` fixed-width bits (1..57).
static inline uint64_t getbits(const size_t count,
                               gcs_state *const state,
                               const uint8_t *const base,
                               const size_t length) {
    refill(state, base, length);
    const uint64_t result = peekbits(count, state->bitbuf, state->bitpos);
    state->bitpos += count;
    return result;
}

// Decode one delta value: a unary quotient (run of 1-bits ending in a 0) shifted
// left by `p`, plus a `p`-bit remainder. The quotient is counted in bulk with
// __builtin_clzll over the inverted window rather than bit by bit.
static inline uint64_t gcs_next(const uint8_t *const base,
                                const size_t length,
                                const size_t p,
                                gcs_state *const state) {
    uint64_t upper = 0;
    for (;;) {
        refill(state, base, length);
        const size_t available = 64 - state->bitpos;
        const uint64_t shifted = state->bitbuf << state->bitpos; // valid bits at MSB
        const uint64_t inverted = ~shifted;
        // Number of leading 1-bits. clzll(0) is UB, which only happens when the
        // whole window is 1s (inverted == 0) — handled as "all available are 1s".
        const size_t ones = inverted ? (size_t)__builtin_clzll(inverted) : 64;

        if (ones < available) {
            upper += ones;
            const size_t consumed = ones + 1;            // ones + the 0 terminator
            const size_t remaining = available - consumed;
            if (remaining >= p) {
                // Remainder fits in the same window — whole element, one refill.
                const uint64_t lower = (shifted << consumed) >> (64 - p);
                state->bitpos += consumed + p;
                return (upper << p) + lower;
            }
            // Remainder straddles the window boundary: consume the unary part,
            // then read the remainder across the next refill.
            state->bitpos += consumed;
            const uint64_t lower = getbits(p, state, base, length);
            return (upper << p) + lower;
        }

        // Entire window was 1s: count them all and continue into the next window.
        upper += available;
        state->bitpos += available;
    }
}

gcs_state initialize(void) {
    gcs_state state;
    state.bitbuf = 0;
    state.bitpos = 0;
    state.bufpos = 0;
    return state;
}

uint64_t read_p(const uint8_t *base, size_t length, size_t p, gcs_state *state) {
    return getbits(p, state, base, length);
}

size_t read_gcs(const uint8_t *base, size_t length, size_t n, size_t p,
                uint64_t *out, int *overflow) {
    *overflow = 0;
    gcs_state state = { 0, 0, 0 };
    uint64_t accumulator = 0;
    size_t produced = 0;

    for (size_t i = 0; i < n; ++i) {
        const uint64_t value = gcs_next(base, length, p, &state);

        // Reject any element whose bits extended past the real data (i.e. that
        // was decoded from the zero-padded tail) — the input was too short for
        // `n` values. Computed without forming length*8 so it cannot overflow
        // size_t on 32-bit targets.
        const size_t remaining = (state.bufpos < length) ? (length - state.bufpos) : 0;
        if (remaining < 8 && state.bitpos > remaining * 8) {
            break; // truncated
        }

        uint64_t sum;
        if (__builtin_add_overflow(accumulator, value, &sum)) {
            *overflow = 1;
            break;
        }
        accumulator = sum;
        out[produced++] = accumulator;
    }

    return produced;
}

// MARK: - Writing (encode)

static inline void write_byte_be(const uint64_t data,
                                 const size_t byte_number,
                                 uint8_t *dest_ptr) {
    const size_t index = 7 - byte_number;
    *dest_ptr = (uint8_t)(data >> (8 * index));
}

// Flush whole consumed bytes from the bit container to `dest`. Returns 1 if that
// would exceed `cap` (offset never advances past `cap`, so `cap - *off` is safe).
static inline int refill_write(uint64_t *const bits_container,
                               size_t *const bits_position,
                               uint8_t *const dest_ptr,
                               size_t *dest_offset,
                               const size_t cap) {
    const size_t full_bytes = *bits_position >> 3;
    if (full_bytes > cap - *dest_offset) {
        return 1;
    }
    for (size_t i = 0; i < full_bytes; ++i) {
        write_byte_be(*bits_container, i, dest_ptr + *dest_offset + i);
    }
    *dest_offset += full_bytes;
    *bits_container <<= full_bytes * 8;
    *bits_position &= 7;
    return 0;
}

static inline void bits_write(const uint64_t value,
                              const size_t count,
                              uint64_t *bits_container,
                              const size_t bits_position) {
    const uint64_t leftShift = value << (64 - count);
    *bits_container |= leftShift >> bits_position;
}

static inline int putbits(const uint64_t value,
                          const size_t count,
                          uint64_t *bits_container,
                          size_t *bits_position,
                          uint8_t *const dest_ptr,
                          size_t *dest_offset,
                          const size_t cap) {
    if (refill_write(bits_container, bits_position, dest_ptr, dest_offset, cap)) {
        return 1;
    }
    bits_write(value, count, bits_container, *bits_position);
    *bits_position += count;
    return 0;
}

static inline int finalize_write(uint64_t bits_container,
                                 size_t bits_position,
                                 uint8_t *const dest_ptr,
                                 size_t *dest_offset,
                                 const size_t cap) {
    if (refill_write(&bits_container, &bits_position, dest_ptr, dest_offset, cap)) {
        return 1;
    }
    if (bits_position > 0) {
        if (*dest_offset >= cap) {
            return 1;
        }
        dest_ptr[*dest_offset] = (uint8_t)(bits_container >> 56);
        (*dest_offset)++;
    }
    return 0;
}

uint32_t write_bitstream(const uint64_t *const data,
                         const size_t data_size,
                         const size_t p,
                         uint8_t *const dest_ptr,
                         const size_t dest_capacity,
                         size_t *result_bytes) {
    if (p < 1 || p > 56) {
        return 1;
    }

    uint64_t bits_container = 0;
    size_t bits_position = 0;
    size_t dest_offset = 0;

    for (size_t i = 0; i < data_size; ++i) {
        if (putbits(data[i], p, &bits_container, &bits_position, dest_ptr, &dest_offset, dest_capacity)) {
            return 1;
        }
    }

    if (finalize_write(bits_container, bits_position, dest_ptr, &dest_offset, dest_capacity)) {
        return 1;
    }

    if (dest_offset == 0) {
        return 1;
    }
    *result_bytes = dest_offset;
    return 0;
}

uint32_t write_gcs(const size_t p,
                   const uint64_t *const sorted_data,
                   const size_t data_size,
                   uint8_t *const dest_ptr,
                   const size_t dest_capacity,
                   size_t *result_bytes) {
    if (p < 1 || p > 56) {
        return 1;
    }
    // 64-bit mask (the original `1 << p` was a 32-bit signed shift — UB and a
    // wrong mask for p >= 31).
    const uint64_t lower_mask = ((uint64_t)1 << p) - 1;

    uint64_t accumulator = 0, bits_container = 0;
    size_t bits_position = 0, dest_offset = 0;

    for (size_t i = 0; i < data_size; ++i) {
        const uint64_t next = sorted_data[i] - accumulator; // sorted => non-negative
        accumulator = sorted_data[i];                       // == accumulator + next
        const uint64_t lower = next & lower_mask;
        const uint64_t upper = next >> p;

        for (uint64_t acc = 0; acc < upper; ++acc) {
            if (putbits(GCS_UNARY, 1, &bits_container, &bits_position, dest_ptr, &dest_offset, dest_capacity)) {
                return 1;
            }
        }
        if (putbits(GCS_UNARY_EOF, 1, &bits_container, &bits_position, dest_ptr, &dest_offset, dest_capacity)) {
            return 1;
        }
        if (putbits(lower, p, &bits_container, &bits_position, dest_ptr, &dest_offset, dest_capacity)) {
            return 1;
        }
    }

    if (finalize_write(bits_container, bits_position, dest_ptr, &dest_offset, dest_capacity)) {
        return 1;
    }

    if (dest_offset == 0) {
        return 1;
    }
    *result_bytes = dest_offset;
    return 0;
}

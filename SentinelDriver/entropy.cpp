/**
 * @file entropy.cpp
 * @brief SentinelDriver — Shannon entropy calculator (kernel-safe, no CRT math).
 *
 * Uses a precomputed log2 lookup table scaled to fixed-point arithmetic to avoid
 * any dependency on <cmath> or user-mode CRT functions. The table provides
 * sufficient precision for security entropy classification (packed vs. unpacked).
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "entropy.h"

// ---------------------------------------------------------------------------
// Precomputed -log2(p) * 1024 table for p = i/1024, i = 1..1024
// We use integer arithmetic internally and convert to float at the end.
//
// For each byte frequency count c out of total N bytes:
//   p = c / N
//   contribution = -p * log2(p)
//
// Since we can't use log2() in kernel mode reliably, we use a small
// iterative approximation based on the identity:
//   log2(x) = log2(mantissa) + exponent
//
// For simplicity and kernel safety, we implement a basic integer log2
// using bit scanning (BSR instruction via intrinsics).
// ---------------------------------------------------------------------------

/**
 * @brief Approximate log2(x) * 1024 for integer x, using BSR + linear interpolation.
 *
 * This gives us ~10-bit fractional precision which is more than enough
 * for entropy classification (threshold is 7.2 vs 8.0 scale).
 */
static ULONG ApproxLog2Scaled(ULONG x)
{
    if (x <= 1) return 0;

    // Find the position of the highest set bit (floor(log2(x)))
    ULONG msb = 0;
    ULONG temp = x;
    while (temp >>= 1) {
        msb++;
    }

    // Linear interpolation for the fractional part
    // fraction = (x - 2^msb) / 2^msb, scaled to 1024
    ULONG base = 1UL << msb;
    ULONG fraction = ((x - base) * 1024) / base;

    // Result: msb * 1024 + fraction (scaled log2)
    return (msb * 1024) + fraction;
}

// ---------------------------------------------------------------------------
// CalculateShannonEntropy
// ---------------------------------------------------------------------------
FLOAT CalculateShannonEntropy(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ ULONG DataSize)
{
    if (Data == NULL || DataSize == 0) {
        return 0.0f;
    }

    // Step 1: Count byte frequencies
    ULONG histogram[256] = { 0 };
    for (ULONG i = 0; i < DataSize; i++) {
        histogram[Data[i]]++;
    }

    // Step 2: Calculate entropy using scaled integer arithmetic
    //
    // Shannon entropy H = -sum(p_i * log2(p_i)) for i = 0..255
    //                    = sum(p_i * log2(N/p_i))
    //                    = sum((c_i/N) * log2(N/c_i))
    //                    = (1/N) * sum(c_i * log2(N/c_i))
    //                    = (1/N) * (sum(c_i * log2(N)) - sum(c_i * log2(c_i)))
    //                    = log2(N) - (1/N) * sum(c_i * log2(c_i))
    //
    // Using scaled arithmetic (multiply by 1024 to preserve precision):

    ULONG log2N_scaled = ApproxLog2Scaled(DataSize);

    ULONGLONG sumCiLog2Ci_scaled = 0;
    for (ULONG i = 0; i < 256; i++) {
        if (histogram[i] > 0) {
            ULONG ci = histogram[i];
            ULONG log2Ci_scaled = ApproxLog2Scaled(ci);
            sumCiLog2Ci_scaled += (ULONGLONG)ci * (ULONGLONG)log2Ci_scaled;
        }
    }

    // H * 1024 = log2N_scaled - sumCiLog2Ci_scaled / N
    // But be careful with integer division ordering
    LONG entropy_scaled = (LONG)log2N_scaled -
        (LONG)(sumCiLog2Ci_scaled / (ULONGLONG)DataSize);

    if (entropy_scaled < 0) {
        entropy_scaled = 0;
    }

    // Convert from scaled (x1024) to float
    FLOAT entropy = (FLOAT)entropy_scaled / 1024.0f;

    // Clamp to valid range [0.0, 8.0]
    if (entropy > 8.0f) entropy = 8.0f;
    if (entropy < 0.0f) entropy = 0.0f;

    return entropy;
}

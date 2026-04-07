/**
 * @file entropy.h
 * @brief SentinelDriver — Shannon entropy calculator for kernel mode.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include "sentinel_common_driver.h"

/**
 * @brief Calculate Shannon entropy of a data buffer.
 *
 * Returns a value between 0.0 (completely uniform) and 8.0 (maximum entropy).
 * Uses a precomputed log2 lookup table to avoid floating-point library dependencies
 * in kernel mode.
 *
 * @param Data     Pointer to the data buffer.
 * @param DataSize Size of the data in bytes.
 * @return Shannon entropy value (0.0 to 8.0).
 */
FLOAT CalculateShannonEntropy(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ ULONG DataSize);

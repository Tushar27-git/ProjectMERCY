/**
 * @file sha256.h
 * @brief SentinelDriver — Kernel-safe SHA-256 hash computation.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include "sentinel_common_driver.h"

#define SHA256_DIGEST_LENGTH    32

/**
 * @brief Compute SHA-256 hash of a data buffer using BCrypt kernel API.
 * @param Data        Pointer to data to hash.
 * @param DataSize    Size of data in bytes.
 * @param HashOutput  Output buffer (must be at least 32 bytes).
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS ComputeSha256(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ ULONG DataSize,
    _Out_writes_bytes_(SHA256_DIGEST_LENGTH) PUCHAR HashOutput);

/**
 * @file sha256.cpp
 * @brief SentinelDriver — SHA-256 implementation using Windows BCrypt API (kernel-safe).
 *
 * The algorithm provider handle is cached globally (opened once in InitializeSha256Provider
 * called from DriverEntry, closed in CleanupSha256Provider called from FilterUnloadCallback)
 * to avoid per-call overhead and repeated BCryptOpenAlgorithmProvider IRQL risk.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "sentinel_common_driver.h"
#include "sha256.h"

#pragma comment(lib, "cng.lib")

// ---------------------------------------------------------------------------
// Cached BCrypt algorithm handle — opened once, reused across all hash calls
// ---------------------------------------------------------------------------
static BCRYPT_ALG_HANDLE g_hSha256Algorithm = NULL;

// ---------------------------------------------------------------------------
// InitializeSha256Provider — call once from DriverEntry
// ---------------------------------------------------------------------------
NTSTATUS InitializeSha256Provider()
{
    if (g_hSha256Algorithm != NULL) {
        return STATUS_SUCCESS;  // Already initialized
    }

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &g_hSha256Algorithm,
        BCRYPT_SHA256_ALGORITHM,
        NULL,   // MS_PRIMITIVE_PROVIDER
        0);

    if (!NT_SUCCESS(status)) {
        SentinelDbgPrint("SHA256: BCryptOpenAlgorithmProvider failed (0x%08X)", status);
        g_hSha256Algorithm = NULL;
    } else {
        SentinelDbgPrint("SHA256: Algorithm provider initialized.");
    }

    return status;
}

// ---------------------------------------------------------------------------
// CleanupSha256Provider — call once from FilterUnloadCallback
// ---------------------------------------------------------------------------
VOID CleanupSha256Provider()
{
    if (g_hSha256Algorithm != NULL) {
        BCryptCloseAlgorithmProvider(g_hSha256Algorithm, 0);
        g_hSha256Algorithm = NULL;
        SentinelDbgPrint("SHA256: Algorithm provider closed.");
    }
}

// ---------------------------------------------------------------------------
// ComputeSha256 — BCrypt-based SHA-256 using the cached algorithm handle
// ---------------------------------------------------------------------------
NTSTATUS ComputeSha256(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ ULONG DataSize,
    _Out_writes_bytes_(SHA256_DIGEST_LENGTH) PUCHAR HashOutput)
{
    NTSTATUS status = STATUS_SUCCESS;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR hashObject = NULL;
    ULONG hashObjectSize = 0;
    ULONG resultSize = 0;

    if (Data == NULL || HashOutput == NULL || DataSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_hSha256Algorithm == NULL) {
        SentinelDbgPrint("SHA256: Provider not initialized.");
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(HashOutput, SHA256_DIGEST_LENGTH);

    __try {
        // Query hash object size from cached handle
        status = BCryptGetProperty(
            g_hSha256Algorithm,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&hashObjectSize,
            sizeof(hashObjectSize),
            &resultSize,
            0);

        if (!NT_SUCCESS(status)) {
            SentinelDbgPrint("SHA256: BCryptGetProperty failed (0x%08X)", status);
            __leave;
        }

        // Allocate hash object
        hashObject = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, hashObjectSize, SENTINEL_TAG);
        if (hashObject == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // Create hash instance using cached provider handle
        status = BCryptCreateHash(
            g_hSha256Algorithm,
            &hHash,
            hashObject,
            hashObjectSize,
            NULL,   // No HMAC secret
            0,
            0);

        if (!NT_SUCCESS(status)) {
            SentinelDbgPrint("SHA256: BCryptCreateHash failed (0x%08X)", status);
            __leave;
        }

        // Hash data in 64 KB chunks
        const ULONG CHUNK_SIZE = 64 * 1024;
        ULONG offset = 0;
        while (offset < DataSize) {
            ULONG chunkLen = min(CHUNK_SIZE, DataSize - offset);
            status = BCryptHashData(hHash, Data + offset, chunkLen, 0);
            if (!NT_SUCCESS(status)) {
                SentinelDbgPrint("SHA256: BCryptHashData failed at offset %lu (0x%08X)", offset, status);
                __leave;
            }
            offset += chunkLen;
        }

        // Finalise
        status = BCryptFinishHash(hHash, HashOutput, SHA256_DIGEST_LENGTH, 0);
        if (!NT_SUCCESS(status)) {
            SentinelDbgPrint("SHA256: BCryptFinishHash failed (0x%08X)", status);
            __leave;
        }

        SentinelDbgPrint("SHA256: Hash computed (%lu bytes).", DataSize);
    }
    __finally {
        if (hHash)      { BCryptDestroyHash(hHash); }
        if (hashObject) { ExFreePoolWithTag(hashObject, SENTINEL_TAG); }
        // g_hSha256Algorithm is the cached global — NOT closed here.
    }

    return status;
}

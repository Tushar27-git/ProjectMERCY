/**
 * @file minifilter.h
 * @brief SentinelDriver — Minifilter registration and callback declarations.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include "common.h"

// ---------------------------------------------------------------------------
// Minifilter Registration Constants
// ---------------------------------------------------------------------------
#define SENTINEL_FILTER_NAME    L"SentinelDriver"

// ---------------------------------------------------------------------------
// Context Definitions (if needed in future phases)
// ---------------------------------------------------------------------------
typedef struct _SENTINEL_STREAM_CONTEXT {
    UNICODE_STRING  FileName;
    BOOLEAN         IsPeFile;
    BOOLEAN         Scanned;
} SENTINEL_STREAM_CONTEXT, *PSENTINEL_STREAM_CONTEXT;

// ---------------------------------------------------------------------------
// Function Prototypes
// ---------------------------------------------------------------------------

/**
 * @brief Register the minifilter with the Filter Manager.
 * @param DriverObject  The driver object from DriverEntry.
 * @param RegistryPath  The registry path for driver parameters.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS RegisterMinifilter(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath);

/**
 * @brief Start filtering I/O operations.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS StartFiltering(VOID);

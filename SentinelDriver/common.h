/**
 * @file common.h
 * @brief SentinelDriver — Driver-local shared definitions and helpers.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include <fltKernel.h>
#include <ntddk.h>
#include <wdm.h>

// Tag for pool allocations: 'SntC'
#define SENTINEL_TAG 'CtnS'

// Debug print macro
#if DBG
#define SentinelDbgPrint(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[SentinelCore] " fmt "\n", ##__VA_ARGS__)
#else
#define SentinelDbgPrint(fmt, ...)
#endif

// ---------------------------------------------------------------------------
// Global Driver Data
// ---------------------------------------------------------------------------
typedef struct _SENTINEL_DRIVER_DATA {
    PFLT_FILTER     Filter;             // Minifilter handle
    PFLT_PORT       ServerPort;         // Communication server port
    PFLT_PORT       ClientPort;         // Connected client port (single connection)
    KSPIN_LOCK      ClientPortLock;     // Protects ClientPort and ClientConnected
    volatile LONG   ClientConnected;    // Is userland agent connected? (use interlocked)
    PDRIVER_OBJECT  DriverObject;       // Cached driver object
} SENTINEL_DRIVER_DATA, *PSENTINEL_DRIVER_DATA;

extern SENTINEL_DRIVER_DATA g_DriverData;

// ---------------------------------------------------------------------------
// Forward Declarations — Minifilter Operations
// ---------------------------------------------------------------------------
DRIVER_INITIALIZE DriverEntry;
NTSTATUS FLTAPI FilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS FLTAPI PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext);

// ---------------------------------------------------------------------------
// Forward Declarations — Communication Port
// ---------------------------------------------------------------------------
NTSTATUS InitializeCommunicationPort(_In_ PFLT_FILTER Filter);
VOID CloseCommunicationPort(VOID);
NTSTATUS SendTelemetryToAgent(
    _In_reads_bytes_(PayloadSize) PVOID Payload,
    _In_ ULONG PayloadSize,
    _In_ ULONG MessageType);

// ---------------------------------------------------------------------------
// Forward Declarations — Kernel Callbacks
// ---------------------------------------------------------------------------
NTSTATUS RegisterKernelCallbacks();
VOID UnregisterKernelCallbacks();
VOID ResetBsodBootCounter();

// ---------------------------------------------------------------------------
// Forward Declarations — PE Parser
// ---------------------------------------------------------------------------
BOOLEAN IsPeFile(_In_reads_bytes_(BufferSize) PUCHAR Buffer, _In_ ULONG BufferSize);
NTSTATUS ParsePeHeaders(
    _In_reads_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ struct FeatureVector* pFeatureVector);

// ---------------------------------------------------------------------------
// Forward Declarations — Crypto / Entropy
// ---------------------------------------------------------------------------

// Call once in DriverEntry to cache the BCrypt algorithm handle
NTSTATUS InitializeSha256Provider();

// Call in FilterUnloadCallback to release the cached handle
VOID CleanupSha256Provider();

NTSTATUS ComputeSha256(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ ULONG DataSize,
    _Out_writes_bytes_(32) PUCHAR HashOutput);

FLOAT CalculateShannonEntropy(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ ULONG DataSize);

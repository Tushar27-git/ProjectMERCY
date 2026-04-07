/**
 * @file minifilter.cpp
 * @brief SentinelDriver — KMDF Minifilter at Altitude 320000 (FSFilter Anti-Virus).
 *
 * Implements DriverEntry, filter registration, and pre-operation callbacks for
 * IRP_MJ_CREATE and IRP_MJ_WRITE. On file write, the driver parses PE headers,
 * computes SHA-256 and Shannon entropy, builds a FeatureVector, and sends it
 * to the userland agent via FltSendMessage.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "common.h"
#include "minifilter.h"
#include "pe_parser.h"
#include "sha256.h"
#include "entropy.h"
#include "comm_port.h"
#include "telemetry_pool.h"
#include "../SentinelCommon/feature_vector.h"
#include "../SentinelCommon/ipc_protocol.h"
#include "../SentinelCommon/sentinel_constants.h"
#include <ntstrsafe.h>

// ---------------------------------------------------------------------------
// Forward Declarations
// ---------------------------------------------------------------------------
extern "C" {
    FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreateCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_result_maybenull_ PVOID* CompletionContext);
    FLT_PREOP_CALLBACK_STATUS FLTAPI PreWriteCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_result_maybenull_ PVOID* CompletionContext);
    NTSTATUS FLTAPI FilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
}

// ---------------------------------------------------------------------------
// Global Driver Data
// ---------------------------------------------------------------------------
SENTINEL_DRIVER_DATA g_DriverData = { 0 };

// ---------------------------------------------------------------------------
// Operation Registration
// ---------------------------------------------------------------------------
static const FLT_OPERATION_REGISTRATION g_OperationCallbacks[] = {
    {
        IRP_MJ_CREATE,                          // Major function
        0,                                       // Flags
        PreCreateCallback,                       // Pre-operation
        NULL                                     // Post-operation
    },
    {
        IRP_MJ_WRITE,                            // Major function
        0,                                       // Flags
        PreWriteCallback,                        // Pre-operation
        NULL                                     // Post-operation
    },
    { IRP_MJ_OPERATION_END }
};

// ---------------------------------------------------------------------------
// Filter Registration
// ---------------------------------------------------------------------------
static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),                    // Size
    FLT_REGISTRATION_VERSION,                    // Version
    0,                                           // Flags
    NULL,                                        // Context registrations
    g_OperationCallbacks,                        // Operation callbacks
    FilterUnloadCallback,                        // FilterUnload
    NULL,                                        // InstanceSetup
    NULL,                                        // InstanceQueryTeardown
    NULL,                                        // InstanceTeardownStart
    NULL,                                        // InstanceTeardownComplete
    NULL,                                        // GenerateFileName
    NULL,                                        // NormalizeNameComponent
    NULL                                         // NormalizeContextCleanup
};

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------
extern "C"
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    SentinelDbgPrint("DriverEntry: Initializing SentinelCore Kernel Driver...");

    UNREFERENCED_PARAMETER(RegistryPath);

    // Cache driver object
    g_DriverData.DriverObject = DriverObject;

    // Step 1: Register the minifilter
    status = FltRegisterFilter(
        DriverObject,
        &g_FilterRegistration,
        &g_DriverData.Filter);

    if (!NT_SUCCESS(status)) {
        SentinelDbgPrint("DriverEntry: FltRegisterFilter failed (0x%08X)", status);
        return status;
    }

    SentinelDbgPrint("DriverEntry: Minifilter registered successfully.");

    // Step 1.5: Initialize cached SHA-256 BCrypt provider
    status = InitializeSha256Provider();
    if (!NT_SUCCESS(status)) {
        SentinelDbgPrint("DriverEntry: InitializeSha256Provider failed (0x%08X)", status);
        FltUnregisterFilter(g_DriverData.Filter);
        return status;
    }
    SentinelDbgPrint("DriverEntry: SHA-256 provider initialized.");

    // Step 2: Initialize the communication port for userland agent
    status = InitializeCommunicationPort(g_DriverData.Filter);
    if (!NT_SUCCESS(status)) {
        SentinelDbgPrint("DriverEntry: InitializeCommunicationPort failed (0x%08X)", status);
        CleanupSha256Provider();
        FltUnregisterFilter(g_DriverData.Filter);
        return status;
    }

    SentinelDbgPrint("DriverEntry: Communication port initialized.");
    
    // Step 2.2: Initialize Telemetry Pool
    status = SentinelInitializeTelemetryPool();
    if (!NT_SUCCESS(status)) {
        SentinelDbgPrint("DriverEntry: SentinelInitializeTelemetryPool failed (0x%08X)", status);
        CloseCommunicationPort();
        CleanupSha256Provider();
        FltUnregisterFilter(g_DriverData.Filter);
        return status;
    }

    // Step 2.5: Register Process/Thread/Image/Ob callbacks
    status = RegisterKernelCallbacks();
    if (!NT_SUCCESS(status)) {
        SentinelDbgPrint("DriverEntry: RegisterKernelCallbacks failed (0x%08X). Ensure /INTEGRITYCHECK is set.", status);
        CloseCommunicationPort();
        CleanupSha256Provider();
        FltUnregisterFilter(g_DriverData.Filter);
        return status;
    }
    SentinelDbgPrint("DriverEntry: Kernel Callbacks registered successfully.");

    // Step 3: Start filtering
    status = FltStartFiltering(g_DriverData.Filter);
    if (!NT_SUCCESS(status)) {
        SentinelDbgPrint("DriverEntry: FltStartFiltering failed (0x%08X)", status);
        CloseCommunicationPort();
        CleanupSha256Provider();
        FltUnregisterFilter(g_DriverData.Filter);
        return status;
    }

    SentinelDbgPrint("DriverEntry: SentinelCore driver started. Altitude %ws", SENTINEL_ALTITUDE);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// FilterUnloadCallback
// ---------------------------------------------------------------------------
NTSTATUS FLTAPI FilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    SentinelDbgPrint("FilterUnloadCallback: Unloading SentinelCore driver...");

    // Unregister kernel callbacks FIRST to avoid race conditions
    UnregisterKernelCallbacks();

    // Close communication port
    CloseCommunicationPort();

    // Cleanup telemetry pool
    SentinelCleanupTelemetryPool();

    // Release cached BCrypt SHA-256 provider
    CleanupSha256Provider();

    // Unregister the filter
    if (g_DriverData.Filter) {
        FltUnregisterFilter(g_DriverData.Filter);
        g_DriverData.Filter = NULL;
    }

    SentinelDbgPrint("FilterUnloadCallback: Driver unloaded successfully.");
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// PreCreateCallback — IRP_MJ_CREATE
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    // Only intercept if userland agent is connected
    if (!InterlockedOr(&g_DriverData.ClientConnected, 0)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip kernel-mode requests
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Extract file name information for logging
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &fileNameInfo);

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(fileNameInfo);

        SentinelDbgPrint("PreCreate: PID=%lu File=%wZ",
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
            &fileNameInfo->Name);

        FltReleaseFileNameInformation(fileNameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// PreWriteCallback — IRP_MJ_WRITE
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    // Only process if agent is connected
    if (!InterlockedOr(&g_DriverData.ClientConnected, 0)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip kernel-mode requests
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    PUCHAR writeBuffer = NULL;
    ULONG writeLength = 0;
    FeatureVector featureVector = { 0 };

    __try {
        // Get write parameters
        PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
        writeLength = iopb->Parameters.Write.Length;

        // Skip very small writes (not interesting for PE analysis)
        if (writeLength < 64) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        // Get the write buffer
        if (iopb->Parameters.Write.MdlAddress != NULL) {
            writeBuffer = (PUCHAR)MmGetSystemAddressForMdlSafe(
                iopb->Parameters.Write.MdlAddress,
                NormalPagePriority | MdlMappingNoExecute);
        } else {
            writeBuffer = (PUCHAR)iopb->Parameters.Write.WriteBuffer;
        }

        if (writeBuffer == NULL) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        // Quick check: is this a PE file?
        if (!IsPeFile(writeBuffer, writeLength)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        SentinelDbgPrint("PreWrite: PE file detected! Length=%lu PID=%lu",
            writeLength, (ULONG)(ULONG_PTR)PsGetCurrentProcessId());

        // --- Build Feature Vector ---

        // Compute SHA-256
        status = ComputeSha256(writeBuffer, writeLength, featureVector.sha256_hash);
        if (!NT_SUCCESS(status)) {
            SentinelDbgPrint("PreWrite: SHA-256 computation failed (0x%08X)", status);
            RtlZeroMemory(featureVector.sha256_hash, sizeof(featureVector.sha256_hash));
        }

        // SSDeep placeholder
        RtlStringCbCopyA(featureVector.ssdeep_placeholder,
            sizeof(featureVector.ssdeep_placeholder),
            "PLACEHOLDER:ssdeep_not_implemented");

        // Parse PE headers and extract section information
        status = ParsePeHeaders(writeBuffer, writeLength, &featureVector);
        if (!NT_SUCCESS(status)) {
            SentinelDbgPrint("PreWrite: PE parsing failed (0x%08X)", status);
            // Continue anyway — we still have the hash
        }

        // Set metadata
        featureVector.file_size = (UINT64)writeLength;
        featureVector.is_pe = TRUE;
        featureVector.source_pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();

        LARGE_INTEGER timestamp;
        KeQuerySystemTimePrecise(&timestamp);
        featureVector.timestamp = (UINT64)timestamp.QuadPart;

        // Get filename for the feature vector
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &fileNameInfo);

        if (NT_SUCCESS(status)) {
            FltParseFileNameInformation(fileNameInfo);
            ULONG copyLen = min(fileNameInfo->Name.Length, sizeof(featureVector.file_path) - sizeof(WCHAR));
            RtlCopyMemory(featureVector.file_path, fileNameInfo->Name.Buffer, copyLen);
            featureVector.file_path[copyLen / sizeof(WCHAR)] = L'\0';
            FltReleaseFileNameInformation(fileNameInfo);
            fileNameInfo = NULL;
        }

        // Queue feature vector to async pool: fixes [MEDIUM] Blocking Telemetry risk.
        SentinelQueueTelemetryItem(&featureVector, sizeof(FeatureVector), (ULONG)IpcMessageType::FILE_EVENT);
        SentinelDbgPrint("PreWrite: Feature vector queued for delivery.");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SentinelDbgPrint("PreWrite: EXCEPTION caught (0x%08X)", GetExceptionCode());
        if (fileNameInfo) {
            FltReleaseFileNameInformation(fileNameInfo);
        }
    }

    // Allow the write to proceed (never block in Phase 1)
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

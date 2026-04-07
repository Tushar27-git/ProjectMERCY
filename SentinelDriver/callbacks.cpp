/**
 * @file callbacks.cpp
 * @brief SentinelDriver — Native Kernel Callbacks implementation.
 *
 * Implements PsSetCreateProcessNotifyRoutineEx, PsSetCreateThreadNotifyRoutine,
 * PsSetLoadImageNotifyRoutine, and ObRegisterCallbacks.
 *
 * SAFETY: Every callback is wrapped in __try/__except to prevent BSODs.
 * SAFETY: Every callback uses SentinelQueueTelemetryItem for async delivery.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "sentinel_common_driver.h"
#include "callbacks.h"
#include "telemetry_pool.h"
#include "../SentinelCommon/feature_vector.h"
#include "../SentinelCommon/sentinel_ipc_protocol.h"
#include "../SentinelCommon/sentinel_constants.h"

// ---------------------------------------------------------------------------
// Global state for callback handles
// ---------------------------------------------------------------------------
static PVOID g_ObRegistrationHandle = NULL;
static BOOLEAN g_ProcessCallbackRegistered = FALSE;
static BOOLEAN g_ThreadCallbackRegistered = FALSE;
static BOOLEAN g_ImageCallbackRegistered = FALSE;
static BOOLEAN g_PassiveMode = FALSE;  // Set TRUE after 3 consecutive BSODs

// ---------------------------------------------------------------------------
// Registry key for BSOD crash counter
// ---------------------------------------------------------------------------
#define SENTINEL_REG_PATH   L"\\Registry\\Machine\\SOFTWARE\\SentinelCore"
#define SENTINEL_REG_BOOT   L"BootCount"
#define SENTINEL_MAX_BOOTS  3

// ---------------------------------------------------------------------------
// Obtain timestamp helper
// ---------------------------------------------------------------------------
static UINT64 GetTimestamp() {
    LARGE_INTEGER ts;
    KeQuerySystemTimePrecise(&ts);
    return (UINT64)ts.QuadPart;
}

// ---------------------------------------------------------------------------
// BSOD Protection: Registry-based crash counter
// ---------------------------------------------------------------------------
static NTSTATUS ReadBootCount(_Out_ PULONG pCount) {
    NTSTATUS status;
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;

    *pCount = 0;

    RtlInitUnicodeString(&keyPath, SENTINEL_REG_PATH);
    InitializeObjectAttributes(&oa, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        return status;  // Key doesn't exist yet — first boot
    }

    RtlInitUnicodeString(&valueName, SENTINEL_REG_BOOT);

    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    ULONG resultLength = 0;

    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation,
        buffer, sizeof(buffer), &resultLength);

    if (NT_SUCCESS(status)) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
        if (info->DataLength == sizeof(ULONG)) {
            *pCount = *(PULONG)info->Data;
        }
    }

    ZwClose(hKey);
    return STATUS_SUCCESS;
}

static NTSTATUS WriteBootCount(_In_ ULONG count) {
    NTSTATUS status;
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;

    RtlInitUnicodeString(&keyPath, SENTINEL_REG_PATH);
    InitializeObjectAttributes(&oa, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    ULONG disposition = 0;
    status = ZwCreateKey(&hKey, KEY_WRITE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&valueName, SENTINEL_REG_BOOT);
    status = ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &count, sizeof(ULONG));

    ZwClose(hKey);
    return status;
}

static BOOLEAN CheckBsodProtection() {
    ULONG bootCount = 0;
    ReadBootCount(&bootCount);

    bootCount++;
    WriteBootCount(bootCount);

    if (bootCount > SENTINEL_MAX_BOOTS) {
        SentinelDbgPrint("BSOD PROTECTION: Boot count %lu exceeds threshold %lu. PASSIVE MODE ACTIVE.",
            bootCount, SENTINEL_MAX_BOOTS);
        return TRUE;
    }

    SentinelDbgPrint("Boot count: %lu / %lu", bootCount, SENTINEL_MAX_BOOTS);
    return FALSE;
}

VOID ResetBsodBootCounter() {
    WriteBootCount(0);
    SentinelDbgPrint("BSOD Protection: Boot counter reset to 0.");
}

// ---------------------------------------------------------------------------
// Telemetry Callbacks — Refactored for Async Pool
// ---------------------------------------------------------------------------

static VOID NTAPI ProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    __try {
        ProcessEvent event = { 0 };
        event.pid = (UINT32)(ULONG_PTR)ProcessId;
        event.timestamp = GetTimestamp();

        if (CreateInfo != NULL) {
            event.is_creation = 1;
            event.ppid = (UINT32)(ULONG_PTR)CreateInfo->ParentProcessId;
            event.creating_pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
            event.creating_tid = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();

            if (CreateInfo->ImageFileName != NULL && CreateInfo->ImageFileName->Buffer != NULL) {
                ULONG copyLen = min(CreateInfo->ImageFileName->Length, (ULONG)(sizeof(event.image_path) - sizeof(WCHAR)));
                RtlCopyMemory(event.image_path, CreateInfo->ImageFileName->Buffer, copyLen);
                event.image_path[copyLen / sizeof(WCHAR)] = L'\0';
            }

            if (CreateInfo->CommandLine != NULL && CreateInfo->CommandLine->Buffer != NULL) {
                ULONG copyLen = min(CreateInfo->CommandLine->Length, (ULONG)(sizeof(event.command_line) - sizeof(WCHAR)));
                RtlCopyMemory(event.command_line, CreateInfo->CommandLine->Buffer, copyLen);
                event.command_line[copyLen / sizeof(WCHAR)] = L'\0';
            }
        } else {
            event.is_creation = 0;
        }

        SentinelQueueTelemetryItem(&event, sizeof(ProcessEvent), (ULONG)IpcMessageType::PROCESS_CREATE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SentinelDbgPrint("ProcessNotifyCallback: EXCEPTION (0x%08X)", GetExceptionCode());
    }
}

static VOID NTAPI ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create)
{
    __try {
        HANDLE currentPid = PsGetCurrentProcessId();
        if (Create && currentPid == ProcessId) return;

        ThreadEvent event = { 0 };
        event.pid = (UINT32)(ULONG_PTR)ProcessId;
        event.tid = (UINT32)(ULONG_PTR)ThreadId;
        event.timestamp = GetTimestamp();
        event.is_creation = Create ? 1 : 0;

        if (Create) {
            event.creating_pid = (UINT32)(ULONG_PTR)currentPid;
            event.creating_tid = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();
        }

        SentinelQueueTelemetryItem(&event, sizeof(ThreadEvent), (ULONG)IpcMessageType::THREAD_CREATE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SentinelDbgPrint("ThreadNotifyCallback: EXCEPTION (0x%08X)", GetExceptionCode());
    }
}

static VOID NTAPI ImageLoadNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    if (ProcessId == 0) return;

    __try {
        if (ImageInfo == NULL) return;

        ImageLoadEvent event = { 0 };
        event.pid = (UINT32)(ULONG_PTR)ProcessId;
        event.timestamp = GetTimestamp();
        event.image_base = (UINT64)ImageInfo->ImageBase;
        event.image_size = (UINT64)ImageInfo->ImageSize;
        event.is_system_module = ImageInfo->SystemModeImage ? 1 : 0;

        if (FullImageName != NULL && FullImageName->Buffer != NULL && FullImageName->Length > 0) {
            ULONG copyLen = min(FullImageName->Length, (ULONG)(sizeof(event.image_path) - sizeof(WCHAR)));
            RtlCopyMemory(event.image_path, FullImageName->Buffer, copyLen);
            event.image_path[copyLen / sizeof(WCHAR)] = L'\0';
        }

        SentinelQueueTelemetryItem(&event, sizeof(ImageLoadEvent), (ULONG)IpcMessageType::IMAGE_LOAD);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SentinelDbgPrint("ImageLoadNotifyCallback: EXCEPTION (0x%08X)", GetExceptionCode());
    }
}

static OB_PREOP_CALLBACK_STATUS NTAPI ObPreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    __try {
        if (OperationInformation == NULL || OperationInformation->KernelHandle) return OB_PREOP_SUCCESS;

        HandleEvent event = { 0 };
        event.timestamp = GetTimestamp();
        event.source_pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();

        if (OperationInformation->Parameters == NULL) return OB_PREOP_SUCCESS;
        event.desired_access = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        event.is_creation = (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) ? 1 : 0;

        if (OperationInformation->Object == NULL) return OB_PREOP_SUCCESS;

        if (OperationInformation->ObjectType == *PsProcessType) {
            event.target_pid = (UINT32)(ULONG_PTR)PsGetProcessId((PEPROCESS)OperationInformation->Object);
            event.is_thread_handle = 0;
        } else if (OperationInformation->ObjectType == *PsThreadType) {
            event.target_pid = (UINT32)(ULONG_PTR)PsGetThreadProcessId((PETHREAD)OperationInformation->Object);
            event.target_tid = (UINT32)(ULONG_PTR)PsGetThreadId((PETHREAD)OperationInformation->Object);
            event.is_thread_handle = 1;
        }

        if (event.source_pid != event.target_pid) {
            SentinelQueueTelemetryItem(&event, sizeof(HandleEvent), (ULONG)IpcMessageType::HANDLE_CREATE);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SentinelDbgPrint("ObPreOperationCallback: EXCEPTION (0x%08X)", GetExceptionCode());
    }

    return OB_PREOP_SUCCESS;
}

// ---------------------------------------------------------------------------
// RegisterKernelCallbacks
// ---------------------------------------------------------------------------
NTSTATUS RegisterKernelCallbacks() {
    NTSTATUS status;

    // BSOD Protection: Check crash counter
    g_PassiveMode = CheckBsodProtection();
    if (g_PassiveMode) {
        SentinelDbgPrint("PASSIVE MODE: Skipping kernel callback registration for safety.");
        return STATUS_SUCCESS;
    }

    // 1. Process Callback (requires /INTEGRITYCHECK)
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (NT_SUCCESS(status)) {
        g_ProcessCallbackRegistered = TRUE;
        SentinelDbgPrint("Registered: PsSetCreateProcessNotifyRoutineEx");
    } else {
        SentinelDbgPrint("PsSetCreateProcessNotifyRoutineEx FAILED (0x%08X). Check /INTEGRITYCHECK.", status);
        return status;
    }

    // 2. Thread Callback
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (NT_SUCCESS(status)) {
        g_ThreadCallbackRegistered = TRUE;
        SentinelDbgPrint("Registered: PsSetCreateThreadNotifyRoutine");
    } else {
        SentinelDbgPrint("PsSetCreateThreadNotifyRoutine FAILED (0x%08X)", status);
    }

    // 3. Image Load Callback
    status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyCallback);
    if (NT_SUCCESS(status)) {
        g_ImageCallbackRegistered = TRUE;
        SentinelDbgPrint("Registered: PsSetLoadImageNotifyRoutine");
    } else {
        SentinelDbgPrint("PsSetLoadImageNotifyRoutine FAILED (0x%08X)", status);
    }

    // 4. ObRegisterCallbacks (handle interception)
    OB_CALLBACK_REGISTRATION obReg = { 0 };
    OB_OPERATION_REGISTRATION opReg[2] = { {0}, {0} };

    opReg[0].ObjectType = PsProcessType;
    opReg[1].ObjectType = PsThreadType;
    opReg[0].Operations = opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = opReg[1].PreOperation = ObPreOperationCallback;

    RtlInitUnicodeString(&obReg.Altitude, SENTINEL_ALTITUDE);
    obReg.Version = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 2;
    obReg.OperationRegistration = opReg;
    obReg.RegistrationContext = NULL;

    status = ObRegisterCallbacks(&obReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        SentinelDbgPrint("ObRegisterCallbacks FAILED (0x%08X)", status);
    } else {
        SentinelDbgPrint("Registered: ObRegisterCallbacks");
    }

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// UnregisterKernelCallbacks
// ---------------------------------------------------------------------------
VOID UnregisterKernelCallbacks() {
    if (g_PassiveMode) {
        SentinelDbgPrint("Passive mode — no callbacks to unregister.");
        return;
    }

    if (g_ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        g_ProcessCallbackRegistered = FALSE;
        SentinelDbgPrint("Unregistered: ProcessNotifyCallback");
    }

    if (g_ThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_ThreadCallbackRegistered = FALSE;
        SentinelDbgPrint("Unregistered: ThreadNotifyCallback");
    }

    if (g_ImageCallbackRegistered) {
        PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyCallback);
        g_ImageCallbackRegistered = FALSE;
        SentinelDbgPrint("Unregistered: ImageLoadNotifyCallback");
    }

    if (g_ObRegistrationHandle) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
        SentinelDbgPrint("Unregistered: ObRegisterCallbacks");
    }

    SentinelDbgPrint("All kernel callbacks unregistered safely.");
}

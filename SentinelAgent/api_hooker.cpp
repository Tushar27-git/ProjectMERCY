/**
 * @file api_hooker.cpp
 * @brief SentinelAgent — Microsoft Detours hook implementation for ntdll.dll APIs.
 *
 * Hooks NtCreateProcess, NtAllocateVirtualMemory (RWX detection),
 * and NtWriteVirtualMemory using Detours transactions.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "api_hooker.h"
#include "thread_pool.h"
#include "logger.h"
#include "../SentinelCommon/sentinel_constants.h"

// Microsoft Detours
#include <detours.h>

#pragma comment(lib, "detours.lib")

namespace sentinel {

// ---------------------------------------------------------------------------
// Static context for hook callbacks
// ---------------------------------------------------------------------------
ThreadPool*                             ApiHooker::s_pool = nullptr;
SPSCRingBuffer<TelemetryRecord, 4096>*  ApiHooker::s_ringBuf = nullptr;
std::atomic<bool>*                      ApiHooker::s_active = nullptr;

// ---------------------------------------------------------------------------
// Native API Type Definitions
// ---------------------------------------------------------------------------

// NtCreateProcessEx
typedef NTSTATUS(NTAPI* pfnNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel);

// NtAllocateVirtualMemory
typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

// NtWriteVirtualMemory
typedef NTSTATUS(NTAPI* pfnNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

// ---------------------------------------------------------------------------
// Original function pointers (Detours will redirect these)
// ---------------------------------------------------------------------------
static pfnNtCreateProcessEx         TrueNtCreateProcessEx = nullptr;
static pfnNtAllocateVirtualMemory   TrueNtAllocateVirtualMemory = nullptr;
static pfnNtWriteVirtualMemory      TrueNtWriteVirtualMemory = nullptr;

// ---------------------------------------------------------------------------
// Helper: Create and push a TelemetryRecord
// ---------------------------------------------------------------------------
static void EmitHookEvent(const char* apiName, uint32_t pid, const char* paramsJson, uint32_t severity = 0) {
    if (!ApiHooker::s_pool || !ApiHooker::s_ringBuf) return;
    if (ApiHooker::s_active && !ApiHooker::s_active->load()) return;

    TelemetryRecord record;
    record.timestamp = TelemetryRecord::Now();
    record.pid = pid;
    record.ppid = 0;
    record.SetApiName(apiName);
    record.SetParameters(paramsJson);
    record.event_type = EventType::ApiHookEvent;
    record.severity = severity;

    // Get process name
    wchar_t processPath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, processPath, MAX_PATH);
    record.SetProcessName(processPath);

    ApiHooker::s_pool->Submit([record, ringBuf = ApiHooker::s_ringBuf]() {
        if (!ringBuf->try_push(record)) {
            LOG_WARN("ApiHooker: Ring buffer full — dropping hook event.");
        }
    });
}

// ---------------------------------------------------------------------------
// Hook: NtCreateProcessEx
// ---------------------------------------------------------------------------
static NTSTATUS NTAPI HookedNtCreateProcessEx(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel)
{
    DWORD callerPid = GetCurrentProcessId();

    char params[512];
    snprintf(params, sizeof(params),
        "{\"desired_access\":\"0x%08X\",\"flags\":\"0x%08X\",\"parent_handle\":\"0x%p\"}",
        DesiredAccess, Flags, ParentProcess);

    EmitHookEvent("NtCreateProcessEx", callerPid, params, 2);

    LOG_INFO("Hook: NtCreateProcessEx called by PID %lu", callerPid);

    // Call the original function
    return TrueNtCreateProcessEx(
        ProcessHandle, DesiredAccess, ObjectAttributes,
        ParentProcess, Flags, SectionHandle, DebugPort,
        ExceptionPort, JobMemberLevel);
}

// ---------------------------------------------------------------------------
// Hook: NtAllocateVirtualMemory
// ---------------------------------------------------------------------------
static NTSTATUS NTAPI HookedNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    DWORD callerPid = GetCurrentProcessId();

    // Check for RWX allocation (PAGE_EXECUTE_READWRITE = 0x40)
    bool isRwx = (Protect == PAGE_EXECUTE_READWRITE);
    bool isRwxExplicit = (Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

    if (isRwxExplicit) {
        char params[512];
        snprintf(params, sizeof(params),
            "{\"protect\":\"0x%08X\",\"rwx\":true,\"alloc_type\":\"0x%08X\","
            "\"region_size\":%llu,\"target_handle\":\"0x%p\"}",
            Protect, AllocationType,
            (unsigned long long)(RegionSize ? *RegionSize : 0),
            ProcessHandle);

        // RWX allocations are suspicious — medium-high severity
        EmitHookEvent("NtAllocateVirtualMemory", callerPid, params, 3);

        LOG_WARN("Hook: NtAllocateVirtualMemory RWX detected! PID=%lu Protect=0x%08X Size=%llu",
            callerPid, Protect,
            (unsigned long long)(RegionSize ? *RegionSize : 0));
    }

    return TrueNtAllocateVirtualMemory(
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

// ---------------------------------------------------------------------------
// Hook: NtWriteVirtualMemory (WriteProcessMemory underlying API)
// ---------------------------------------------------------------------------
static NTSTATUS NTAPI HookedNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    DWORD callerPid = GetCurrentProcessId();

    // Cross-process writes are suspicious
    DWORD targetPid = GetProcessId(ProcessHandle);
    bool isCrossProcess = (targetPid != 0 && targetPid != callerPid);

    if (isCrossProcess) {
        char params[512];
        snprintf(params, sizeof(params),
            "{\"target_pid\":%lu,\"base_address\":\"0x%p\","
            "\"bytes_to_write\":%llu,\"cross_process\":true}",
            targetPid, BaseAddress,
            (unsigned long long)NumberOfBytesToWrite);

        EmitHookEvent("NtWriteVirtualMemory", callerPid, params, 3);

        LOG_WARN("Hook: NtWriteVirtualMemory cross-process write! "
                 "PID=%lu → TargetPID=%lu BaseAddr=0x%p Size=%llu",
            callerPid, targetPid, BaseAddress,
            (unsigned long long)NumberOfBytesToWrite);
    }

    return TrueNtWriteVirtualMemory(
        ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToWrite, NumberOfBytesWritten);
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
ApiHooker::ApiHooker()
    : m_active(false)
    , m_eventsCaptured(0)
{}

ApiHooker::~ApiHooker() {
    RemoveHooks();
}

// ---------------------------------------------------------------------------
// InitializeHooks
// ---------------------------------------------------------------------------
bool ApiHooker::InitializeHooks(
    ThreadPool* pool,
    SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf)
{
    if (m_active) return true;

    s_pool = pool;
    s_ringBuf = ringBuf;
    s_active = &m_active;

    // Resolve ntdll.dll function addresses
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        LOG_ERROR("ApiHooker: Failed to get ntdll.dll handle.");
        return false;
    }

    TrueNtCreateProcessEx = (pfnNtCreateProcessEx)
        GetProcAddress(hNtdll, "NtCreateProcessEx");
    TrueNtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)
        GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    TrueNtWriteVirtualMemory = (pfnNtWriteVirtualMemory)
        GetProcAddress(hNtdll, "NtWriteVirtualMemory");

    if (!TrueNtAllocateVirtualMemory) {
        LOG_ERROR("ApiHooker: Failed to resolve NtAllocateVirtualMemory.");
        return false;
    }

    // Install hooks via Detours transaction
    LONG error;

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        LOG_ERROR("ApiHooker: DetourTransactionBegin failed (err=%ld)", error);
        return false;
    }

    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR) {
        DetourTransactionAbort();
        LOG_ERROR("ApiHooker: DetourUpdateThread failed (err=%ld)", error);
        return false;
    }

    // Attach hooks
    if (TrueNtCreateProcessEx) {
        error = DetourAttach(&(PVOID&)TrueNtCreateProcessEx, HookedNtCreateProcessEx);
        if (error != NO_ERROR) {
            LOG_WARN("ApiHooker: Failed to hook NtCreateProcessEx (err=%ld)", error);
        } else {
            LOG_INFO("ApiHooker: Hooked NtCreateProcessEx.");
        }
    }

    if (TrueNtAllocateVirtualMemory) {
        error = DetourAttach(&(PVOID&)TrueNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);
        if (error != NO_ERROR) {
            LOG_WARN("ApiHooker: Failed to hook NtAllocateVirtualMemory (err=%ld)", error);
        } else {
            LOG_INFO("ApiHooker: Hooked NtAllocateVirtualMemory.");
        }
    }

    if (TrueNtWriteVirtualMemory) {
        error = DetourAttach(&(PVOID&)TrueNtWriteVirtualMemory, HookedNtWriteVirtualMemory);
        if (error != NO_ERROR) {
            LOG_WARN("ApiHooker: Failed to hook NtWriteVirtualMemory (err=%ld)", error);
        } else {
            LOG_INFO("ApiHooker: Hooked NtWriteVirtualMemory.");
        }
    }

    // Commit the transaction
    error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        LOG_ERROR("ApiHooker: DetourTransactionCommit failed (err=%ld)", error);
        return false;
    }

    m_active = true;
    LOG_INFO("ApiHooker: All hooks installed successfully.");
    return true;
}

// ---------------------------------------------------------------------------
// RemoveHooks
// ---------------------------------------------------------------------------
void ApiHooker::RemoveHooks() {
    if (!m_active.exchange(false)) return;

    LONG error;

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        LOG_ERROR("ApiHooker: DetourTransactionBegin (remove) failed (err=%ld)", error);
        return;
    }

    DetourUpdateThread(GetCurrentThread());

    if (TrueNtCreateProcessEx) {
        DetourDetach(&(PVOID&)TrueNtCreateProcessEx, HookedNtCreateProcessEx);
    }
    if (TrueNtAllocateVirtualMemory) {
        DetourDetach(&(PVOID&)TrueNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);
    }
    if (TrueNtWriteVirtualMemory) {
        DetourDetach(&(PVOID&)TrueNtWriteVirtualMemory, HookedNtWriteVirtualMemory);
    }

    error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        LOG_ERROR("ApiHooker: DetourTransactionCommit (remove) failed (err=%ld)", error);
    }

    LOG_INFO("ApiHooker: All hooks removed. Events captured: %llu",
        m_eventsCaptured.load());
}

} // namespace sentinel

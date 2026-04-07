/**
 * @file etw_consumer.cpp
 * @brief SentinelAgent — ETW real-time trace session for security event monitoring.
 *
 * Subscribes to Microsoft-Windows-Kernel-Process for process lifecycle events.
 * Microsoft-Windows-Threat-Intelligence is gated behind SENTINEL_ENABLE_ETW_TI
 * (requires PPL / ELAM certification).
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "etw_consumer.h"
#include "thread_pool.h"
#include "logger.h"
#include "../SentinelCommon/sentinel_constants.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace sentinel {

// ---------------------------------------------------------------------------
// Static members for ETW callback context
// ---------------------------------------------------------------------------
ThreadPool*                             EtwConsumer::s_pool = nullptr;
SPSCRingBuffer<TelemetryRecord, 4096>*  EtwConsumer::s_ringBuf = nullptr;
std::atomic<bool>*                      EtwConsumer::s_running = nullptr;

// ETW Provider GUIDs
// Microsoft-Windows-Kernel-Process: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID KernelProcessProviderGuid =
    { 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };

#ifdef SENTINEL_ENABLE_ETW_TI
// Microsoft-Windows-Threat-Intelligence: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
static const GUID ThreatIntelProviderGuid =
    { 0xF4E1897C, 0xBB5D, 0x5668, { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 } };
#endif

// Trace session name
static const WCHAR SESSION_NAME[] = L"SentinelCoreEtwSession";

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
EtwConsumer::EtwConsumer()
    : m_sessionHandle(0)
    , m_traceHandle(INVALID_PROCESSTRACE_HANDLE)
    , m_running(false)
    , m_eventsProcessed(0)
{}

EtwConsumer::~EtwConsumer() {
    Stop();
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
bool EtwConsumer::Start(ThreadPool* pool, SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf) {
    if (m_running) return true;

    s_pool = pool;
    s_ringBuf = ringBuf;
    s_running = &m_running;

    // Create trace session
    if (!CreateTraceSession()) {
        LOG_ERROR("EtwConsumer: Failed to create trace session.");
        return false;
    }

    // Enable providers
    if (!EnableProviders()) {
        LOG_ERROR("EtwConsumer: Failed to enable providers.");
        Stop();
        return false;
    }

    m_running = true;

    // Start the ProcessTrace thread
    m_processThread = std::thread(&EtwConsumer::ProcessTraceThread, this);

    LOG_INFO("EtwConsumer: Started ETW trace session '%S'.", SESSION_NAME);
    return true;
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------
void EtwConsumer::Stop() {
    if (!m_running.exchange(false)) return;

    // Stop the trace session
    if (m_sessionHandle) {
        // Allocate properties for ControlTrace
        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SESSION_NAME) + 64;
        auto* properties = (EVENT_TRACE_PROPERTIES*)calloc(1, bufferSize);
        if (properties) {
            properties->Wnode.BufferSize = bufferSize;
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

            ControlTraceW(m_sessionHandle, SESSION_NAME, properties,
                EVENT_TRACE_CONTROL_STOP);
            free(properties);
        }
        m_sessionHandle = 0;
    }

    // Close the trace handle to unblock ProcessTrace
    if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(m_traceHandle);
        m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    // Wait for the processing thread
    if (m_processThread.joinable()) {
        m_processThread.join();
    }

    LOG_INFO("EtwConsumer: Stopped. Events processed: %llu", m_eventsProcessed.load());
}

// ---------------------------------------------------------------------------
// CreateTraceSession
// ---------------------------------------------------------------------------
bool EtwConsumer::CreateTraceSession() {
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SESSION_NAME) + 64;
    auto* properties = (EVENT_TRACE_PROPERTIES*)calloc(1, bufferSize);
    if (!properties) return false;

    properties->Wnode.BufferSize = bufferSize;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1;  // QPC for timestamps
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // Try to stop any existing session first
    ControlTraceW(0, SESSION_NAME, properties, EVENT_TRACE_CONTROL_STOP);

    // Reset and start new session
    memset(properties, 0, bufferSize);
    properties->Wnode.BufferSize = bufferSize;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&m_sessionHandle, SESSION_NAME, properties);
    free(properties);

    if (status != ERROR_SUCCESS) {
        LOG_ERROR("EtwConsumer: StartTrace failed (err=%lu)", status);
        return false;
    }

    LOG_INFO("EtwConsumer: Trace session created (handle=0x%llX)", (uint64_t)m_sessionHandle);
    return true;
}

// ---------------------------------------------------------------------------
// EnableProviders
// ---------------------------------------------------------------------------
bool EtwConsumer::EnableProviders() {
    // Enable Microsoft-Windows-Kernel-Process
    ULONG status = EnableTraceEx2(
        m_sessionHandle,
        &KernelProcessProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,      // MatchAnyKeyword (all events)
        0,      // MatchAllKeyword
        0,      // Timeout
        NULL);  // EnableParameters

    if (status != ERROR_SUCCESS) {
        LOG_ERROR("EtwConsumer: EnableTraceEx2 (Kernel-Process) failed (err=%lu)", status);
        return false;
    }
    LOG_INFO("EtwConsumer: Enabled Microsoft-Windows-Kernel-Process provider.");

#ifdef SENTINEL_ENABLE_ETW_TI
    // Enable Microsoft-Windows-Threat-Intelligence (requires PPL)
    status = EnableTraceEx2(
        m_sessionHandle,
        &ThreatIntelProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0, 0, 0, NULL);

    if (status != ERROR_SUCCESS) {
        LOG_WARN("EtwConsumer: EnableTraceEx2 (Threat-Intelligence) failed (err=%lu). "
                 "This provider requires PPL/ELAM.", status);
        // Non-fatal: continue without TI events
    } else {
        LOG_INFO("EtwConsumer: Enabled Microsoft-Windows-Threat-Intelligence provider.");
    }
#endif

    return true;
}

// ---------------------------------------------------------------------------
// ProcessTraceThread
// ---------------------------------------------------------------------------
void EtwConsumer::ProcessTraceThread() {
    LOG_INFO("EtwConsumer: ProcessTrace thread started (TID=%lu)", GetCurrentThreadId());

    // Open trace for real-time consumption
    EVENT_TRACE_LOGFILEW traceLogfile = {};
    traceLogfile.LoggerName = const_cast<LPWSTR>(SESSION_NAME);
    traceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLogfile.EventRecordCallback = EventRecordCallback;

    m_traceHandle = OpenTraceW(&traceLogfile);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        LOG_ERROR("EtwConsumer: OpenTrace failed (err=%lu)", GetLastError());
        return;
    }

    // ProcessTrace blocks until the session is stopped
    ULONG status = ProcessTrace(&m_traceHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        LOG_ERROR("EtwConsumer: ProcessTrace ended with error (err=%lu)", status);
    }

    LOG_INFO("EtwConsumer: ProcessTrace thread exiting.");
}

// ---------------------------------------------------------------------------
// EventRecordCallback — static callback invoked by ETW for each event
// ---------------------------------------------------------------------------
VOID WINAPI EtwConsumer::EventRecordCallback(PEVENT_RECORD pEventRecord) {
    if (!s_running || !s_running->load()) return;
    if (!pEventRecord) return;

    // Build a TelemetryRecord from the ETW event
    TelemetryRecord record;
    record.timestamp = TelemetryRecord::Now();
    record.pid = pEventRecord->EventHeader.ProcessId;
    record.event_type = EventType::EtwEvent;
    record.severity = 0;  // Info by default

    // Extract event metadata
    char apiName[64];
    snprintf(apiName, sizeof(apiName), "ETW:Provider=%u:Opcode=%u",
        pEventRecord->EventHeader.ProviderId.Data1,
        pEventRecord->EventHeader.EventDescriptor.Opcode);
    record.SetApiName(apiName);

    // Parse event-specific data using TDH
    ULONG bufferSize = 0;
    TDHSTATUS tdhStatus = TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);

    if (tdhStatus == ERROR_INSUFFICIENT_BUFFER && bufferSize > 0) {
        auto* eventInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (eventInfo) {
            tdhStatus = TdhGetEventInformation(pEventRecord, 0, NULL, eventInfo, &bufferSize);
            if (tdhStatus == ERROR_SUCCESS) {
                // Extract task/opcode name if available
                if (eventInfo->TaskNameOffset > 0) {
                    LPCWSTR taskName = (LPCWSTR)((PUCHAR)eventInfo + eventInfo->TaskNameOffset);
                    char taskNameNarrow[64] = {};
                    WideCharToMultiByte(CP_UTF8, 0, taskName, -1,
                        taskNameNarrow, sizeof(taskNameNarrow), NULL, NULL);
                    record.SetApiName(taskNameNarrow);
                }

                // Build parameters JSON from event properties
                char params[512];
                snprintf(params, sizeof(params),
                    "{\"event_id\":%u,\"version\":%u,\"channel\":%u,\"level\":%u,\"opcode\":%u}",
                    pEventRecord->EventHeader.EventDescriptor.Id,
                    pEventRecord->EventHeader.EventDescriptor.Version,
                    pEventRecord->EventHeader.EventDescriptor.Channel,
                    pEventRecord->EventHeader.EventDescriptor.Level,
                    pEventRecord->EventHeader.EventDescriptor.Opcode);
                record.SetParameters(params);
            }
            free(eventInfo);
        }
    }

    // Dispatch to thread pool
    if (s_pool) {
        s_pool->Submit([record, ringBuf = s_ringBuf]() {
            if (ringBuf && !ringBuf->try_push(record)) {
                LOG_WARN("EtwConsumer: Ring buffer full — dropping ETW event.");
            }
        });
    }
}

} // namespace sentinel

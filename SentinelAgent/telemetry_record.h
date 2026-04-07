/**
 * @file telemetry_record.h
 * @brief SentinelAgent — Standardized telemetry event record.
 *
 * All sensor components (minifilter, AMSI, ETW, hooker, memory scanner)
 * normalize their events into this common record format before pushing
 * to the ring buffer / IPC bus.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include "../SentinelCommon/ipc_protocol.h"

namespace sentinel {

// ---------------------------------------------------------------------------
// Event Type (maps to IpcMessageType for serialization)
// ---------------------------------------------------------------------------
enum class EventType : uint32_t {
    FileIOEvent     = static_cast<uint32_t>(IpcMessageType::FILE_EVENT),
    AmsiScan        = static_cast<uint32_t>(IpcMessageType::AMSI_SCAN),
    EtwEvent        = static_cast<uint32_t>(IpcMessageType::ETW_EVENT),
    ApiHookEvent    = static_cast<uint32_t>(IpcMessageType::API_HOOK_EVENT),
    MemoryAlert     = static_cast<uint32_t>(IpcMessageType::MEMORY_ALERT),
    ProcessCreation = static_cast<uint32_t>(IpcMessageType::PROCESS_CREATE),
    ThreadCreation  = static_cast<uint32_t>(IpcMessageType::THREAD_CREATE),
    ModuleLoad      = static_cast<uint32_t>(IpcMessageType::IMAGE_LOAD),
    HandleAccess    = static_cast<uint32_t>(IpcMessageType::HANDLE_CREATE),
};

// ---------------------------------------------------------------------------
// TelemetryRecord — the universal event struct
// ---------------------------------------------------------------------------
struct TelemetryRecord {
    uint64_t    timestamp;                      // Epoch time in milliseconds
    uint32_t    pid;                            // Process ID
    uint32_t    ppid;                           // Parent Process ID
    wchar_t     process_name[260];              // Process image name (MAX_PATH)
    char        api_name[64];                   // API / operation name
    char        parameters[512];                // JSON-serialized parameters
    EventType   event_type;                     // Category of event
    uint32_t    severity;                       // 0=info, 1=low, 2=medium, 3=high, 4=critical
    uint8_t     data_hash[32];                  // Optional SHA-256 of related data
    uint32_t    flags;                          // Reserved for future use

    // Default-initialize
    TelemetryRecord() {
        memset(this, 0, sizeof(TelemetryRecord));
    }

    // Helper: set the process name from a wide string
    void SetProcessName(const wchar_t* name) {
        if (name) {
            wcsncpy_s(process_name, _countof(process_name), name, _TRUNCATE);
        }
    }

    // Helper: set the API name from a narrow string
    void SetApiName(const char* name) {
        if (name) {
            strncpy_s(api_name, sizeof(api_name), name, _TRUNCATE);
        }
    }

    // Helper: set parameters as a JSON string
    void SetParameters(const char* json) {
        if (json) {
            strncpy_s(parameters, sizeof(parameters), json, _TRUNCATE);
        }
    }

    // Helper: get current timestamp in milliseconds
    static uint64_t Now() {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        // Convert FILETIME (100ns units since 1601) to epoch ms
        return (uli.QuadPart - 116444736000000000ULL) / 10000ULL;
    }
};

// Ensure the record is a reasonable size for the ring buffer
static_assert(sizeof(TelemetryRecord) < 2048, "TelemetryRecord too large for ring buffer");

} // namespace sentinel

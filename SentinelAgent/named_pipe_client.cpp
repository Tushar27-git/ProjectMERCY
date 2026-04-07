/**
 * @file named_pipe_client.cpp
 * @brief SentinelAgent — IPC bus implementation with JSON serialization.
 *
 * Phase 1: Writes JSON-wrapped telemetry records to a .jsonl file.
 * Phase 2: Will send via Named Pipe to the Python ML pipeline server.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "named_pipe_client.h"
#include "logger.h"
#include "../SentinelCommon/sentinel_constants.h"
#include <sstream>
#include <iomanip>

namespace sentinel {

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
NamedPipeClient::NamedPipeClient()
    : m_mode(TransportMode::FILE_LOG)
    , m_connected(false)
    , m_recordsSent(0)
    , m_hPipe(INVALID_HANDLE_VALUE)
{}

NamedPipeClient::~NamedPipeClient() {
    Shutdown();
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------
bool NamedPipeClient::Initialize(TransportMode mode) {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_mode = mode;

    if (mode == TransportMode::FILE_LOG) {
        // Ensure output directory exists
        CreateDirectoryW(SENTINEL_LOG_DIRECTORY, NULL);

        // Open telemetry file for appending
        m_file.open(SENTINEL_TELEMETRY_FILE,
            std::ios::app | std::ios::out);

        if (!m_file.is_open()) {
            LOG_ERROR("NamedPipeClient: Failed to open telemetry file.");
            return false;
        }

        m_connected = true;
        LOG_INFO("NamedPipeClient: Initialized in FILE_LOG mode → %S",
            SENTINEL_TELEMETRY_FILE);
        return true;
    }
    else if (mode == TransportMode::PIPE_SEND) {
        // Phase 2: Connect to named pipe
        bool result = ConnectToPipe();
        LOG_INFO("NamedPipeClient: Initialized in PIPE_SEND mode → %s",
            result ? "connected" : "failed");
        return result;
    }

    return false;
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------
void NamedPipeClient::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_connected = false;

    if (m_file.is_open()) {
        m_file.flush();
        m_file.close();
    }

    if (m_hPipe != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(m_hPipe);
        DisconnectNamedPipe(m_hPipe);
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }

    LOG_INFO("NamedPipeClient: Shutdown complete. Total records sent: %llu",
        m_recordsSent.load());
}

// ---------------------------------------------------------------------------
// SendRecord
// ---------------------------------------------------------------------------
bool NamedPipeClient::SendRecord(const TelemetryRecord& record) {
    if (!m_connected) return false;

    std::string json = SerializeToJson(record);

    bool success = false;
    if (m_mode == TransportMode::FILE_LOG) {
        success = WriteToFile(json);
    } else {
        success = WriteToPipe(json);
    }

    if (success) {
        m_recordsSent++;
    }

    return success;
}

// ---------------------------------------------------------------------------
// IsConnected
// ---------------------------------------------------------------------------
bool NamedPipeClient::IsConnected() const {
    return m_connected.load();
}

// ---------------------------------------------------------------------------
// SerializeToJson — Convert TelemetryRecord to JSON string
// ---------------------------------------------------------------------------
std::string NamedPipeClient::SerializeToJson(const TelemetryRecord& record) {
    std::ostringstream oss;

    // Convert wide process name to narrow for JSON
    char processNameNarrow[520] = {};
    WideCharToMultiByte(CP_UTF8, 0, record.process_name, -1,
        processNameNarrow, sizeof(processNameNarrow), NULL, NULL);

    // Format SHA-256 hash as hex string
    char hashHex[65] = {};
    for (int i = 0; i < 32; i++) {
        snprintf(hashHex + (i * 2), 3, "%02x", record.data_hash[i]);
    }

    // Event type string
    const char* eventTypeStr = "unknown";
    switch (record.event_type) {
    case EventType::FileIOEvent:    eventTypeStr = "file_io"; break;
    case EventType::AmsiScan:       eventTypeStr = "amsi_scan"; break;
    case EventType::EtwEvent:       eventTypeStr = "etw_event"; break;
    case EventType::ApiHookEvent:   eventTypeStr = "api_hook"; break;
    case EventType::MemoryAlert:    eventTypeStr = "memory_alert"; break;
    case EventType::ProcessCreation: eventTypeStr = "process_create"; break;
    case EventType::ThreadCreation:  eventTypeStr = "thread_create"; break;
    case EventType::ModuleLoad:      eventTypeStr = "image_load"; break;
    case EventType::HandleAccess:    eventTypeStr = "handle_create"; break;
    }

    // Build JSON (manual to avoid external dependency)
    oss << "{"
        << "\"timestamp\":" << record.timestamp << ","
        << "\"pid\":" << record.pid << ","
        << "\"ppid\":" << record.ppid << ","
        << "\"process_name\":\"" << processNameNarrow << "\","
        << "\"api_name\":\"" << record.api_name << "\","
        << "\"parameters\":" << (record.parameters[0] ? record.parameters : "{}") << ","
        << "\"event_type\":\"" << eventTypeStr << "\","
        << "\"severity\":" << record.severity << ","
        << "\"data_hash\":\"" << hashHex << "\","
        << "\"flags\":" << record.flags
        << "}";

    return oss.str();
}

// ---------------------------------------------------------------------------
// WriteToFile
// ---------------------------------------------------------------------------
bool NamedPipeClient::WriteToFile(const std::string& jsonLine) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_file.is_open()) return false;

    m_file << jsonLine << "\n";
    m_file.flush();
    return true;
}

// ---------------------------------------------------------------------------
// ConnectToPipe (Phase 2 stub)
// ---------------------------------------------------------------------------
bool NamedPipeClient::ConnectToPipe() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }

    // Wait for pipe availability (with timeout)
    if (!WaitNamedPipeW(SENTINEL_PIPE_NAME, SENTINEL_PIPE_TIMEOUT_MS)) {
        LOG_WARN("NamedPipeClient: Pipe %S not available — is ML server running?", SENTINEL_PIPE_NAME);
        return false;
    }

    m_hPipe = CreateFileW(
        SENTINEL_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,              // No sharing
        NULL,           // Default security
        OPEN_EXISTING,
        0,              // Default attributes
        NULL);          // No template file

    if (m_hPipe == INVALID_HANDLE_VALUE) {
        LOG_ERROR("NamedPipeClient: Failed to connect to pipe (err=%lu)", GetLastError());
        return false;
    }

    // Change to message-read mode
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(m_hPipe, &mode, NULL, NULL)) {
        LOG_ERROR("NamedPipeClient: SetNamedPipeHandleState failed (err=%lu)", GetLastError());
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
        return false;
    }

    m_connected = true;
    LOG_INFO("NamedPipeClient: Successfully connected to ML pipeline server.");
    return true;
}

// ---------------------------------------------------------------------------
// WriteToPipe (Phase 2 stub)
// ---------------------------------------------------------------------------
bool NamedPipeClient::WriteToPipe(const std::string& data) {
    if (m_hPipe == INVALID_HANDLE_VALUE) return false;

    // Use a lock to ensure thread-safety for pipe writes
    std::lock_guard<std::mutex> lock(m_mutex);

    DWORD bytesWritten = 0;
    BOOL result = WriteFile(
        m_hPipe,
        data.c_str(),
        static_cast<DWORD>(data.size()),
        &bytesWritten,
        NULL);

    if (!result) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
            LOG_WARN("NamedPipeClient: ML server disconnected. Closing pipe.");
            m_connected = false;
        } else {
            LOG_ERROR("NamedPipeClient: WriteToPipe failed (err=%lu)", err);
        }
        return false;
    }

    return (bytesWritten == data.size());
}

} // namespace sentinel

/**
 * @file named_pipe_client.h
 * @brief SentinelAgent — IPC bus with file-logging stub and future named pipe transport.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <fstream>
#include <mutex>
#include <atomic>

#include "telemetry_record.h"

namespace sentinel {

/**
 * @brief Transport mode for the IPC bus.
 */
enum class TransportMode {
    FILE_LOG,   // Phase 1: Write JSON records to a .jsonl file
    PIPE_SEND   // Phase 2: Send via Windows Named Pipe to Python ML server
};

/**
 * @brief NamedPipeClient — routes telemetry records to the configured transport.
 *
 * Phase 1: Serializes TelemetryRecords as JSON and appends to a .jsonl file.
 * Phase 2: Connects to a named pipe and sends serialized records.
 */
class NamedPipeClient {
public:
    NamedPipeClient();
    ~NamedPipeClient();

    // Non-copyable
    NamedPipeClient(const NamedPipeClient&) = delete;
    NamedPipeClient& operator=(const NamedPipeClient&) = delete;

    /**
     * @brief Initialize the client in the specified transport mode.
     * @param mode  Transport mode (FILE_LOG or PIPE_SEND).
     * @return true on success.
     */
    bool Initialize(TransportMode mode = TransportMode::FILE_LOG);

    /**
     * @brief Shutdown and flush all pending data.
     */
    void Shutdown();

    /**
     * @brief Send a telemetry record through the transport.
     * @param record  The record to send.
     * @return true if sent/written successfully.
     */
    bool SendRecord(const TelemetryRecord& record);

    /**
     * @brief Check if the transport is connected/open.
     */
    bool IsConnected() const;

    /**
     * @brief Get the number of records sent since initialization.
     */
    uint64_t RecordsSent() const { return m_recordsSent.load(); }

private:
    /**
     * @brief Serialize a TelemetryRecord to a JSON string.
     */
    std::string SerializeToJson(const TelemetryRecord& record);

    /**
     * @brief Write a JSON line to the telemetry file.
     */
    bool WriteToFile(const std::string& jsonLine);

    /**
     * @brief Connect to the named pipe (Phase 2).
     */
    bool ConnectToPipe();

    /**
     * @brief Write data to the named pipe (Phase 2).
     */
    bool WriteToPipe(const std::string& data);

    TransportMode           m_mode;
    std::atomic<bool>       m_connected;
    std::atomic<uint64_t>   m_recordsSent;
    std::mutex              m_mutex;

    // File transport
    std::ofstream           m_file;

    // Pipe transport (Phase 2)
    HANDLE                  m_hPipe;
};

} // namespace sentinel

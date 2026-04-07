/**
 * @file memory_scanner.h
 * @brief SentinelAgent — Background RWX memory region scanner.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atomic>
#include <thread>

#include "ring_buffer.h"
#include "telemetry_record.h"

namespace sentinel {

class ThreadPool;

/**
 * @brief Periodic memory scanner that detects suspicious RWX regions.
 *
 * Runs every 30 seconds (configurable), iterates all processes via
 * CreateToolhelp32Snapshot, uses VirtualQueryEx to find PAGE_EXECUTE_READWRITE
 * regions, and calculates Shannon entropy to detect packed/encrypted payloads.
 */
class MemoryScanner {
public:
    MemoryScanner();
    ~MemoryScanner();

    /**
     * @brief Start the periodic scan loop.
     * @param pool      Thread Pool 4 (low priority) for scan dispatch.
     * @param ringBuf   Ring buffer for alert output.
     * @return true on success.
     */
    bool Start(ThreadPool* pool, SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf);

    /**
     * @brief Stop the scan loop.
     */
    void Stop();

    bool IsRunning() const { return m_running.load(); }
    uint64_t ScansCompleted() const { return m_scansCompleted.load(); }
    uint64_t AlertsRaised() const { return m_alertsRaised.load(); }

private:
    /**
     * @brief Main scan loop thread.
     */
    void ScanLoopThread();

    /**
     * @brief Scan a single process for RWX regions.
     * @param pid  Process ID to scan.
     */
    void ScanProcess(DWORD pid);

    /**
     * @brief Calculate Shannon entropy of a memory buffer.
     */
    float CalculateEntropy(const uint8_t* data, size_t size);

    std::atomic<bool>       m_running;
    std::atomic<uint64_t>   m_scansCompleted;
    std::atomic<uint64_t>   m_alertsRaised;
    std::thread             m_scanThread;

    ThreadPool*                             m_pool;
    SPSCRingBuffer<TelemetryRecord, 4096>*  m_ringBuf;
};

} // namespace sentinel

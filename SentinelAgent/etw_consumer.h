/**
 * @file etw_consumer.h
 * @brief SentinelAgent — ETW real-time trace session consumer.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <atomic>
#include <thread>

#include "ring_buffer.h"
#include "telemetry_record.h"

namespace sentinel {

class ThreadPool;

/**
 * @brief Real-time ETW consumer for security-relevant providers.
 *
 * Subscribes to:
 *   - Microsoft-Windows-Kernel-Process (process creation/termination)
 *   - Microsoft-Windows-Threat-Intelligence (guarded, requires PPL — Phase 2)
 */
class EtwConsumer {
public:
    EtwConsumer();
    ~EtwConsumer();

    /**
     * @brief Start the ETW trace session and processing thread.
     * @param pool      Thread Pool 3 for event dispatch.
     * @param ringBuf   Ring buffer for telemetry output.
     * @return true on success.
     */
    bool Start(ThreadPool* pool, SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf);

    /**
     * @brief Stop the ETW trace session.
     */
    void Stop();

    bool IsRunning() const { return m_running.load(); }
    uint64_t EventsProcessed() const { return m_eventsProcessed.load(); }

private:
    /**
     * @brief Create and configure the trace session.
     */
    bool CreateTraceSession();

    /**
     * @brief Enable the desired ETW providers.
     */
    bool EnableProviders();

    /**
     * @brief The ProcessTrace thread function.
     */
    void ProcessTraceThread();

    /**
     * @brief Static callback for EVENT_RECORD processing.
     */
    static VOID WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord);

    // Session handles
    TRACEHANDLE                 m_sessionHandle;
    TRACEHANDLE                 m_traceHandle;
    std::atomic<bool>           m_running;
    std::atomic<uint64_t>       m_eventsProcessed;
    std::thread                 m_processThread;

    // Dispatch targets (set during Start, used in callback)
    static ThreadPool*                              s_pool;
    static SPSCRingBuffer<TelemetryRecord, 4096>*   s_ringBuf;
    static std::atomic<bool>*                       s_running;
};

} // namespace sentinel

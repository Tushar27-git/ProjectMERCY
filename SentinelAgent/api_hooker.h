/**
 * @file api_hooker.h
 * @brief SentinelAgent — Microsoft Detours API hooking manager.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atomic>

#include "ring_buffer.h"
#include "telemetry_record.h"

namespace sentinel {

class ThreadPool;

/**
 * @brief Manages Microsoft Detours hooks on ntdll.dll native API functions.
 *
 * Target APIs:
 *   - NtCreateProcess / NtCreateProcessEx
 *   - NtAllocateVirtualMemory (watching for RWX flags)
 *   - WriteProcessMemory (from kernel32 → NtWriteVirtualMemory)
 */
class ApiHooker {
public:
    ApiHooker();
    ~ApiHooker();

    /**
     * @brief Initialize and install all hooks.
     * @param pool      Thread Pool 3 for event dispatch.
     * @param ringBuf   Ring buffer for telemetry output.
     * @return true if hooks installed successfully.
     */
    bool InitializeHooks(
        ThreadPool* pool,
        SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf);

    /**
     * @brief Remove all hooks and restore original functions.
     */
    void RemoveHooks();

    bool IsActive() const { return m_active.load(); }
    uint64_t EventsCaptured() const { return m_eventsCaptured.load(); }

private:
    std::atomic<bool>       m_active;
    std::atomic<uint64_t>   m_eventsCaptured;

    // Static context for hook callbacks
    static ThreadPool*                              s_pool;
    static SPSCRingBuffer<TelemetryRecord, 4096>*   s_ringBuf;
    static std::atomic<bool>*                       s_active;
};

} // namespace sentinel

/**
 * @file memory_scanner.cpp
 * @brief SentinelAgent — Background RWX memory region scanner implementation.
 *
 * Iterates all processes every 30 seconds using CreateToolhelp32Snapshot,
 * queries memory regions with VirtualQueryEx, flags PAGE_EXECUTE_READWRITE
 * regions with Shannon entropy > 7.2, and dumps the first 1KB for analysis.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "memory_scanner.h"
#include "thread_pool.h"
#include "logger.h"
#include "../SentinelCommon/sentinel_constants.h"

#include <tlhelp32.h>
#include <psapi.h>
#include <cmath>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace sentinel {

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
MemoryScanner::MemoryScanner()
    : m_running(false)
    , m_scansCompleted(0)
    , m_alertsRaised(0)
    , m_pool(nullptr)
    , m_ringBuf(nullptr)
{}

MemoryScanner::~MemoryScanner() {
    Stop();
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
bool MemoryScanner::Start(ThreadPool* pool, SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf) {
    if (m_running) return true;

    m_pool = pool;
    m_ringBuf = ringBuf;
    m_running = true;

    m_scanThread = std::thread(&MemoryScanner::ScanLoopThread, this);

    LOG_INFO("MemoryScanner: Started (interval=%ums, entropy_threshold=%.1f)",
        SENTINEL_MEMORY_SCAN_INTERVAL_MS, (double)SENTINEL_ENTROPY_THRESHOLD);
    return true;
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------
void MemoryScanner::Stop() {
    if (!m_running.exchange(false)) return;

    // Timed join: wait up to 5 seconds for the scan thread to exit cleanly.
    // If pool tasks are backed up, we detach rather than block the shutdown.
    if (m_scanThread.joinable()) {
        std::mutex wMutex;
        std::condition_variable wCv;
        bool joined = false;

        std::thread watcher([&]() {
            if (m_scanThread.joinable()) {
                m_scanThread.join();
            }
            std::unique_lock<std::mutex> lk(wMutex);
            joined = true;
            wCv.notify_one();
        });

        {
            std::unique_lock<std::mutex> lk(wMutex);
            if (!wCv.wait_for(lk, std::chrono::seconds(5), [&] { return joined; })) {
                LOG_WARN("MemoryScanner: Stop() timed out — detaching scan thread.");
                watcher.detach();
            } else {
                watcher.join();
            }
        }
    }

    LOG_INFO("MemoryScanner: Stopped. Scans=%llu, Alerts=%llu",
        m_scansCompleted.load(), m_alertsRaised.load());
}

// ---------------------------------------------------------------------------
// ScanLoopThread — runs every 30 seconds
// ---------------------------------------------------------------------------
void MemoryScanner::ScanLoopThread() {
    LOG_INFO("MemoryScanner: Scan thread started (TID=%lu)", GetCurrentThreadId());

    while (m_running) {
        // Take a snapshot of all processes
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            LOG_ERROR("MemoryScanner: CreateToolhelp32Snapshot failed (err=%lu)",
                GetLastError());
            Sleep(SENTINEL_MEMORY_SCAN_INTERVAL_MS);
            continue;
        }

        PROCESSENTRY32W pe32 = {};
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                // Skip System and our own process
                if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4 ||
                    pe32.th32ProcessID == GetCurrentProcessId()) {
                    continue;
                }

                // Submit scan to Thread Pool 4
                DWORD pid = pe32.th32ProcessID;
                m_pool->Submit([this, pid]() {
                    ScanProcess(pid);
                });

            } while (Process32NextW(hSnapshot, &pe32) && m_running);
        }

        CloseHandle(hSnapshot);
        m_scansCompleted++;

        LOG_DEBUG("MemoryScanner: Scan cycle #%llu complete.", m_scansCompleted.load());

        // Wait for the next scan interval (interruptible)
        for (uint32_t elapsed = 0;
             elapsed < SENTINEL_MEMORY_SCAN_INTERVAL_MS && m_running;
             elapsed += 500)
        {
            Sleep(500);
        }
    }

    LOG_INFO("MemoryScanner: Scan thread exiting.");
}

// ---------------------------------------------------------------------------
// ScanProcess — scan a single process for RWX regions
// ---------------------------------------------------------------------------
void MemoryScanner::ScanProcess(DWORD pid) {
    // Open the process with query + read permissions
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        // Access denied is expected for many system processes
        return;
    }

    // Get process name
    wchar_t processName[MAX_PATH] = L"<unknown>";
    GetModuleBaseNameW(hProcess, NULL, processName, MAX_PATH);

    // Query memory regions
    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID address = NULL;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        // Look for committed RWX regions
        if (mbi.State == MEM_COMMIT &&
            mbi.Protect == PAGE_EXECUTE_READWRITE &&
            mbi.Type == MEM_PRIVATE)
        {
            SIZE_T regionSize = mbi.RegionSize;

            // Read a sample for entropy analysis
            SIZE_T sampleSize = min(regionSize, (SIZE_T)SENTINEL_ENTROPY_SAMPLE_SIZE);
            std::vector<uint8_t> sample(sampleSize);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProcess, mbi.BaseAddress, sample.data(),
                sampleSize, &bytesRead) && bytesRead > 0)
            {
                float entropy = CalculateEntropy(sample.data(), (size_t)bytesRead);

                if (entropy > SENTINEL_ENTROPY_THRESHOLD) {
                    // HIGH-ENTROPY RWX REGION DETECTED!
                    LOG_WARN("MemoryScanner: ALERT! PID=%lu (%S) RWX @ 0x%p "
                             "Size=%llu Entropy=%.2f",
                        pid, processName, mbi.BaseAddress,
                        (unsigned long long)regionSize, (double)entropy);

                    m_alertsRaised++;

                    // Build telemetry record
                    TelemetryRecord record;
                    record.timestamp = TelemetryRecord::Now();
                    record.pid = pid;
                    record.ppid = 0;
                    record.SetProcessName(processName);
                    record.SetApiName("MemoryScan:RWX_HighEntropy");
                    record.event_type = EventType::MemoryAlert;
                    record.severity = 4;  // Critical

                    // Dump first 1KB of the region
                    SIZE_T dumpSize = min(bytesRead, (SIZE_T)SENTINEL_DUMP_SIZE);
                    char dumpHex[SENTINEL_DUMP_SIZE * 2 + 1] = {};
                    for (SIZE_T i = 0; i < min(dumpSize, (SIZE_T)64); i++) {
                        snprintf(dumpHex + (i * 2), 3, "%02x", sample[i]);
                    }

                    char params[512];
                    snprintf(params, sizeof(params),
                        "{\"base_address\":\"0x%p\",\"region_size\":%llu,"
                        "\"entropy\":%.4f,\"protect\":\"PAGE_EXECUTE_READWRITE\","
                        "\"dump_preview\":\"%s...\"}",
                        mbi.BaseAddress, (unsigned long long)regionSize,
                        (double)entropy, dumpHex);
                    record.SetParameters(params);

                    // Push to ring buffer
                    if (m_ringBuf && !m_ringBuf->try_push(record)) {
                        LOG_WARN("MemoryScanner: Ring buffer full — dropping alert.");
                    }
                }
            }
        }

        // Advance to the next region
        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);

        // Safety check: prevent infinite loop on wraparound
        if ((ULONG_PTR)address < (ULONG_PTR)mbi.BaseAddress) break;
    }

    CloseHandle(hProcess);
}

// ---------------------------------------------------------------------------
// CalculateEntropy — Shannon entropy of a memory buffer (userland version)
// ---------------------------------------------------------------------------
float MemoryScanner::CalculateEntropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0f;

    // Count byte frequencies
    uint32_t histogram[256] = {};
    for (size_t i = 0; i < size; i++) {
        histogram[data[i]]++;
    }

    // Calculate Shannon entropy
    float entropy = 0.0f;
    float fSize = static_cast<float>(size);

    for (int i = 0; i < 256; i++) {
        if (histogram[i] > 0) {
            float p = static_cast<float>(histogram[i]) / fSize;
            entropy -= p * log2f(p);
        }
    }

    return entropy;
}

} // namespace sentinel

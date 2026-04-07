/**
 * @file main.cpp
 * @brief SentinelAgent — Main entry point and orchestrator.
 *
 * Initializes all sensor subsystems, starts four thread pools, connects
 * to the kernel minifilter, and enters the service loop. Can run as a
 * Windows Service (via SCM) or as a console application (for debugging).
 *
 * Architecture:
 *   ┌─────────────────────────────────────────────────┐
 *   │  Thread Pool 1  ← MinifilterClient (kernel IPC) │
 *   │  Thread Pool 2  ← AMSI Provider (COM events)    │
 *   │  Thread Pool 3  ← ETW Consumer + API Hooker     │
 *   │  Thread Pool 4  ← Memory Scanner (30s interval) │
 *   │         │                                        │
 *   │         ▼                                        │
 *   │   SPSC Ring Buffer (lock-free)                   │
 *   │         │                                        │
 *   │         ▼                                        │
 *   │   NamedPipeClient (JSON file log / future pipe)  │
 *   └─────────────────────────────────────────────────┘
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

#include "logger.h"
#include "service_controller.h"
#include "thread_pool.h"
#include "ring_buffer.h"
#include "telemetry_record.h"
#include "named_pipe_client.h"
#include "ml_pipeline_interface.h"
#include "minifilter_client.h"
#include "api_hooker.h"
#include "memory_scanner.h"
#include "../SentinelCommon/sentinel_constants.h"

using namespace sentinel;

// ---------------------------------------------------------------------------
// Global Components
// ---------------------------------------------------------------------------
static SPSCRingBuffer<TelemetryRecord, SENTINEL_RINGBUF_CAPACITY>   g_ringBuffer;
static NamedPipeClient      g_pipeClient;
static MLPipelineInterface  g_mlPipeline;
static MinifilterClient     g_minifilterClient;
static ApiHooker            g_apiHooker;
static MemoryScanner        g_memoryScanner;

// Thread pools (constructed in ServiceWorkerThread)
static ThreadPool* g_pool1 = nullptr;   // Minifilter events
static ThreadPool* g_pool2 = nullptr;   // AMSI scans
static ThreadPool* g_pool3 = nullptr;   // ETW + API hooks
static ThreadPool* g_pool4 = nullptr;   // Memory scanner

// ---------------------------------------------------------------------------
// Telemetry Drain Thread — consumes from ring buffer, writes to transport
// ---------------------------------------------------------------------------
static std::atomic<bool> g_drainRunning(false);

static void TelemetryDrainThread() {
    LOG_INFO("TelemetryDrain: Started (TID=%lu)", GetCurrentThreadId());

    while (g_drainRunning || !g_ringBuffer.empty()) {
        TelemetryRecord record;

        if (g_ringBuffer.try_pop(record)) {
            g_pipeClient.SendRecord(record);
        } else {
            // No data — brief sleep to avoid busy-waiting
            Sleep(10);
        }
    }

    LOG_INFO("TelemetryDrain: Stopped. Total records sent: %llu",
        g_pipeClient.RecordsSent());
}

// ---------------------------------------------------------------------------
// ServiceWorkerThread — the main initialization and run loop
// ---------------------------------------------------------------------------
namespace sentinel {
void ServiceWorkerThread() {
    LOG_INFO("=== SentinelCore EDR Agent v1.0 — Phase 1 ===");
    LOG_INFO("Initializing components...");

    // -----------------------------------------------------------------------
    // Step 1: Initialize the telemetry transport (ML Pipeline via Named Pipe)
    // -----------------------------------------------------------------------
    if (!g_pipeClient.Initialize(TransportMode::PIPE_SEND)) {
        LOG_WARN("Failed to connect to ML Pipeline (Python). Falling back to local logging...");
        g_pipeClient.Initialize(TransportMode::FILE_LOG);
    }
    LOG_INFO("[OK] Telemetry transport initialized.");

    // -----------------------------------------------------------------------
    // Step 2: Configure the ML Pipeline stub
    // -----------------------------------------------------------------------
    g_mlPipeline.SetPipeClient(&g_pipeClient);
    g_mlPipeline.SetKillSwitch(false);  // Default: allow all
    LOG_INFO("[OK] ML Pipeline interface initialized (Phase 1 stub: ALLOW all).");

    // -----------------------------------------------------------------------
    // Step 3: Create thread pools
    // -----------------------------------------------------------------------
    g_pool1 = new ThreadPool("Pool1-Minifilter", SENTINEL_POOL1_THREADS,
        THREAD_PRIORITY_ABOVE_NORMAL, SENTINEL_POOL1_LATENCY_MAX_MS);
    g_pool2 = new ThreadPool("Pool2-AMSI", SENTINEL_POOL2_THREADS,
        THREAD_PRIORITY_NORMAL);
    g_pool3 = new ThreadPool("Pool3-API-Hook", SENTINEL_POOL3_THREADS,
        THREAD_PRIORITY_NORMAL);
    g_pool4 = new ThreadPool("Pool4-MemScan", SENTINEL_POOL4_THREADS,
        THREAD_PRIORITY_BELOW_NORMAL);

    g_pool1->Start();
    g_pool2->Start();
    g_pool3->Start();
    g_pool4->Start();
    LOG_INFO("[OK] Thread pools started (4+2+4+1 = 11 workers).");

    // -----------------------------------------------------------------------
    // Step 4: Start telemetry drain thread
    // -----------------------------------------------------------------------
    g_drainRunning = true;
    std::thread drainThread(TelemetryDrainThread);
    LOG_INFO("[OK] Telemetry drain thread started.");

    // -----------------------------------------------------------------------
    // Step 5: Connect to kernel minifilter driver
    // -----------------------------------------------------------------------
    if (g_minifilterClient.Connect()) {
        g_minifilterClient.StartReceiveLoop(g_pool1, &g_ringBuffer, &g_mlPipeline);
        LOG_INFO("[OK] Connected to kernel minifilter driver.");
    } else {
        LOG_WARN("[!!] Failed to connect to kernel minifilter. "
                 "Driver may not be loaded. Continuing without file I/O monitoring.");
    }

    // -----------------------------------------------------------------------
    // Step 6: ETW consumer (DEPRECATED)
    // -----------------------------------------------------------------------
    LOG_INFO("[OK] ETW Consumer deprecated. Deep telemetry now handled by Kernel Callbacks via Pool 1.");

    // -----------------------------------------------------------------------
    // Step 7: Install API hooks (Detours)
    // -----------------------------------------------------------------------
    if (g_apiHooker.InitializeHooks(g_pool3, &g_ringBuffer)) {
        LOG_INFO("[OK] API hooks installed (NtCreateProcessEx, "
                 "NtAllocateVirtualMemory, NtWriteVirtualMemory).");
    } else {
        LOG_WARN("[!!] Failed to install API hooks. "
                 "Detours may not be available. Continuing without hooks.");
    }

    // -----------------------------------------------------------------------
    // Step 8: Start memory scanner
    // -----------------------------------------------------------------------
    if (g_memoryScanner.Start(g_pool4, &g_ringBuffer)) {
        LOG_INFO("[OK] Memory scanner started (interval=%ums, threshold=%.1f).",
            SENTINEL_MEMORY_SCAN_INTERVAL_MS, (double)SENTINEL_ENTROPY_THRESHOLD);
    } else {
        LOG_WARN("[!!] Failed to start memory scanner.");
    }

    LOG_INFO("=== SentinelCore Agent fully initialized. Monitoring active. ===");

    // -----------------------------------------------------------------------
    // Main service loop — wait for shutdown signal
    // -----------------------------------------------------------------------
    while (g_serviceRunning) {
        Sleep(1000);

        // Periodic status logging (every ~30 seconds)
        static int counter = 0;
        if (++counter >= 30) {
            counter = 0;
            LOG_INFO("Status: MinifilterMsgs/KernelCallbacks=%llu, "
                     "HookEvents=%llu, MemScans=%llu, MemAlerts=%llu, "
                     "RingBufSize=%zu, TelemetrySent=%llu, ML_Queries=%llu",
                g_minifilterClient.MessagesReceived(),
                g_apiHooker.EventsCaptured(),
                g_memoryScanner.ScansCompleted(),
                g_memoryScanner.AlertsRaised(),
                g_ringBuffer.size(),
                g_pipeClient.RecordsSent(),
                g_mlPipeline.TotalQueries());
        }
    }

    // -----------------------------------------------------------------------
    // Shutdown sequence
    // -----------------------------------------------------------------------
    LOG_INFO("=== SentinelCore Agent shutting down... ===");

    // Stop components in reverse order
    g_memoryScanner.Stop();
    LOG_INFO("[OK] Memory scanner stopped.");

    g_apiHooker.RemoveHooks();
    LOG_INFO("[OK] API hooks removed.");

    g_minifilterClient.StopReceiveLoop();
    g_minifilterClient.Disconnect();
    LOG_INFO("[OK] Minifilter client disconnected.");

    // Stop thread pools
    g_pool1->Stop();
    g_pool2->Stop();
    g_pool3->Stop();
    g_pool4->Stop();
    LOG_INFO("[OK] Thread pools stopped.");

    // Drain remaining telemetry
    g_drainRunning = false;
    if (drainThread.joinable()) {
        drainThread.join();
    }
    LOG_INFO("[OK] Telemetry drain complete.");

    // Shutdown transport
    g_pipeClient.Shutdown();
    LOG_INFO("[OK] Telemetry transport closed.");

    // Cleanup
    delete g_pool1; g_pool1 = nullptr;
    delete g_pool2; g_pool2 = nullptr;
    delete g_pool3; g_pool3 = nullptr;
    delete g_pool4; g_pool4 = nullptr;

    LOG_INFO("=== SentinelCore Agent shutdown complete. ===");
}
} // namespace sentinel

// ---------------------------------------------------------------------------
// main() — Application Entry Point
// ---------------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[]) {
    // Initialize the logger first
    CreateDirectoryW(SENTINEL_LOG_DIRECTORY, NULL);
    Logger::Instance().Initialize(SENTINEL_LOG_FILE, LogLevel::INFO);

    LOG_INFO("SentinelCore Agent process starting (PID=%lu)...", GetCurrentProcessId());

    // Check for console mode flag
    bool consoleMode = false;
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--console") == 0 ||
            _wcsicmp(argv[i], L"-c") == 0) {
            consoleMode = true;
        }
        if (_wcsicmp(argv[i], L"--debug") == 0) {
            Logger::Instance().SetMinLevel(LogLevel::TRACE);
            LOG_INFO("Debug logging enabled.");
        }
    }

    if (consoleMode) {
        // Run directly in console mode (for debugging)
        LOG_INFO("Running in CONSOLE mode (use Ctrl+C to stop).");

        g_serviceRunning = true;

        // Set up Ctrl+C handler
        SetConsoleCtrlHandler([](DWORD ctrlType) -> BOOL {
            if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
                LOG_INFO("Ctrl+C received. Shutting down...");
                g_serviceRunning = false;
                return TRUE;
            }
            return FALSE;
        }, TRUE);

        ServiceWorkerThread();
    } else {
        // Register with SCM and run as a Windows Service
        if (!InitializeService()) {
            LOG_ERROR("Failed to initialize Windows Service. "
                      "Try running with --console flag for debugging.");
            return 1;
        }
    }

    Logger::Instance().Shutdown();
    return 0;
}

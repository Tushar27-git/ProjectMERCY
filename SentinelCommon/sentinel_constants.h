/**
 * @file sentinel_constants.h
 * @brief SentinelCore — Global constants, GUIDs, and configuration values.
 *
 * Single source of truth for all magic strings, port names, registry paths,
 * timing constants, and ETW provider GUIDs used across the project.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

// ---------------------------------------------------------------------------
// Minifilter Communication Port
// ---------------------------------------------------------------------------
#define SENTINEL_PORT_NAME          L"\\SentinelCorePort"
#define SENTINEL_ALTITUDE           L"320000"
#define SENTINEL_MAX_CONNECTIONS    4

// ---------------------------------------------------------------------------
// Named Pipe (Userland <-> ML Pipeline)
// ---------------------------------------------------------------------------
#define SENTINEL_PIPE_NAME          L"\\\\.\\pipe\\SentinelCorePipe"
#define SENTINEL_PIPE_BUFFER_SIZE   8192
#define SENTINEL_PIPE_TIMEOUT_MS    5000

// ---------------------------------------------------------------------------
// File Paths
// ---------------------------------------------------------------------------
#define SENTINEL_LOG_DIRECTORY      L"C:\\ProgramData\\SentinelCore"
#define SENTINEL_LOG_FILE           L"C:\\ProgramData\\SentinelCore\\sentinel.log"
#define SENTINEL_TELEMETRY_FILE     L"C:\\ProgramData\\SentinelCore\\telemetry.jsonl"

// ---------------------------------------------------------------------------
// Service Configuration
// ---------------------------------------------------------------------------
#define SENTINEL_SERVICE_NAME       L"SentinelCoreAgent"
#define SENTINEL_SERVICE_DISPLAY    L"SentinelCore EDR Agent"
#define SENTINEL_SERVICE_DESC       L"SentinelCore Endpoint Detection & Response Sensor Engine"
#define SENTINEL_DRIVER_NAME        L"SentinelDriver"

// ---------------------------------------------------------------------------
// AMSI Provider
// ---------------------------------------------------------------------------
// {7C3A1B2D-4E5F-6A7B-8C9D-0E1F2A3B4C5D}
#define SENTINEL_AMSI_PROVIDER_CLSID_STR    L"{7C3A1B2D-4E5F-6A7B-8C9D-0E1F2A3B4C5D}"
#define SENTINEL_AMSI_PROVIDER_PROGID        L"SentinelCore.AmsiProvider.1"
#define SENTINEL_AMSI_PROVIDER_DESCRIPTION   L"SentinelCore AMSI Provider"

// CLSID as GUID struct (for COM registration)
// {7C3A1B2D-4E5F-6A7B-8C9D-0E1F2A3B4C5D}
#ifndef _KERNEL_MODE
#include <guiddef.h>
// clang-format off
DEFINE_GUID(CLSID_SentinelAmsiProvider,
    0x7C3A1B2D, 0x4E5F, 0x6A7B,
    0x8C, 0x9D, 0x0E, 0x1F, 0x2A, 0x3B, 0x4C, 0x5D);
// clang-format on
#endif

// ---------------------------------------------------------------------------
// ETW Provider GUIDs
// ---------------------------------------------------------------------------
// Microsoft-Windows-Kernel-Process: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
#define ETW_KERNEL_PROCESS_GUID_STR     L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"

// Microsoft-Windows-Threat-Intelligence: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
#define ETW_THREAT_INTEL_GUID_STR       L"{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}"

#define SENTINEL_ETW_SESSION_NAME       L"SentinelCoreEtwSession"

// ---------------------------------------------------------------------------
// Thread Pool Configuration
// ---------------------------------------------------------------------------
#define SENTINEL_POOL1_THREADS      4       // Mini-filter callbacks
#define SENTINEL_POOL2_THREADS      2       // AMSI scan requests
#define SENTINEL_POOL3_THREADS      4       // ETW + API Hooking
#define SENTINEL_POOL4_THREADS      1       // Memory scanner

// ---------------------------------------------------------------------------
// Timing Constants
// ---------------------------------------------------------------------------
#define SENTINEL_MEMORY_SCAN_INTERVAL_MS    30000   // 30 seconds
#define SENTINEL_POOL1_LATENCY_MAX_MS       300     // Max latency for Pool 1
#define SENTINEL_HEARTBEAT_INTERVAL_MS      10000   // 10 seconds
#define SENTINEL_PIPE_RECONNECT_DELAY_MS    3000    // Reconnect delay

// ---------------------------------------------------------------------------
// Ring Buffer Configuration
// ---------------------------------------------------------------------------
#define SENTINEL_RINGBUF_CAPACITY   4096    // Must be power of 2

// ---------------------------------------------------------------------------
// Memory Scanner Thresholds
// ---------------------------------------------------------------------------
#define SENTINEL_ENTROPY_THRESHOLD  7.2f    // Flag RWX regions above this
#define SENTINEL_DUMP_SIZE          1024    // Bytes to dump from suspicious region
#define SENTINEL_ENTROPY_SAMPLE_SIZE 4096   // Bytes to sample for entropy calculation

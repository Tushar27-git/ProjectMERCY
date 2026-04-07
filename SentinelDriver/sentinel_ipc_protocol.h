/**
 * @file sentinel_ipc_protocol.h
 * @brief SentinelCore — Shared IPC message protocol between kernel and userland.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <cstdint>
#endif

// ---------------------------------------------------------------------------
// 1. Structural Alignment (Wire Format)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)

// IPC Message Types
enum class IpcMessageType : uint32_t {
    FILE_EVENT          = 0x0001,   // File I/O event from minifilter
    AMSI_SCAN           = 0x0002,   // Script scan from AMSI provider
    ETW_EVENT           = 0x0003,   // ETW trace event (DEPRECATED -> Kernel Callbacks)
    API_HOOK_EVENT      = 0x0004,   // Detours API hook event
    MEMORY_ALERT        = 0x0005,   // RWX memory region alert
    PROCESS_CREATE      = 0x0006,   // Kernel PsSetCreateProcessNotifyRoutineEx
    THREAD_CREATE       = 0x0007,   // Kernel PsSetCreateThreadNotifyRoutine
    IMAGE_LOAD          = 0x0008,   // Kernel PsSetLoadImageNotifyRoutine
    HANDLE_CREATE       = 0x0009,   // Kernel ObRegisterCallbacks (e.g., OpenProcess)
    HEARTBEAT           = 0x00FF,   // Keepalive / health check
    VERDICT_REQUEST     = 0x0100,   // Request ML verdict
    VERDICT_RESPONSE    = 0x0101,   // ML verdict response
    KILL_SWITCH_TOGGLE  = 0x0200,   // Enable/disable kill switch
};

// IPC Message Header
struct IpcMessageHeader {
    uint32_t        magic;              // Protocol magic: 0x534E544C ('SNTL')
    uint32_t        version;            // Protocol version (1)
    IpcMessageType  msg_type;           // Type of payload
    uint32_t        payload_size;       // Size of payload following this header
    uint64_t        sequence_number;    // Monotonically increasing sequence
    uint64_t        timestamp;          // Message creation timestamp
};

// Protocol constants
#define IPC_MAGIC    0x534E544CU
#define IPC_VERSION  1U

// Minifilter Communication
struct KernelToUserMessage {
    IpcMessageHeader    header;
    // Payload follows (FeatureVector for FILE_EVENT, raw bytes for others)
    uint8_t             payload[1];     // Variable-length payload (C flexible member)
};

// Reply from userland agent to kernel driver
struct UserToKernelReply {
    uint32_t    verdict;        // Maps to MLVerdict enum
    uint32_t    flags;          // Reserved for future use
};

#pragma pack(pop)

// Maximum message sizes
#define MAX_IPC_PAYLOAD_SIZE     8192
#define MAX_KERNEL_MESSAGE_SIZE  (sizeof(IpcMessageHeader) + MAX_IPC_PAYLOAD_SIZE)

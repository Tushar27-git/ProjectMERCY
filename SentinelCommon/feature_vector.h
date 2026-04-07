/**
 * @file feature_vector.h
 * @brief SentinelCore — Shared feature vector definitions for ML pipeline integration.
 *
 * This header is shared between the kernel driver and userland agent.
 * All structures use #pragma pack for binary compatibility across the kernel/user boundary.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <cstdint>
#include <cstring>
#endif

#pragma pack(push, 1)

// ---------------------------------------------------------------------------
// ML Verdict Enum
// ---------------------------------------------------------------------------
enum class MLVerdict : uint32_t {
    ALLOW       = 0,    // No threat detected, allow operation
    BLOCK       = 1,    // Threat detected, block operation
    QUARANTINE  = 2,    // Move to quarantine for further analysis
    DEFER       = 3     // Await async ML pipeline verdict
};

// ---------------------------------------------------------------------------
// Feature Vector — sent from kernel driver to userland for ML inference
// ---------------------------------------------------------------------------
struct FeatureVector {
    // File identity
    uint8_t     sha256_hash[32];            // SHA-256 digest of file content
    char        ssdeep_placeholder[128];     // SSDeep fuzzy hash (placeholder for Phase 2)

    // PE metadata
    uint32_t    section_count;              // Number of PE sections
    float       max_entropy;                // Highest Shannon entropy across sections
    uint32_t    has_rwx_section;            // Boolean: any section with RWX flags?
    uint64_t    file_size;                  // Total file size in bytes
    uint32_t    is_pe;                      // Boolean: valid PE file?

    // Section-level detail (up to 16 sections)
    struct SectionInfo {
        char        name[8];                // Section name (null-padded)
        uint32_t    virtual_size;           // Virtual size
        uint32_t    raw_size;               // Size of raw data
        uint32_t    characteristics;        // Section characteristics flags
        float       entropy;                // Shannon entropy of this section
    } sections[16];

    // Timing
    uint64_t    timestamp;                  // FILETIME / epoch timestamp
    uint32_t    source_pid;                 // Process that triggered the event

    // Path info
    wchar_t     file_path[260];             // Full file path (MAX_PATH)
};

// ---------------------------------------------------------------------------
// Process Event — sent on PsSetCreateProcessNotifyRoutineEx
// ---------------------------------------------------------------------------
struct ProcessEvent {
    uint32_t    pid;
    uint32_t    ppid;
    uint32_t    creating_pid;
    uint32_t    creating_tid;
    uint64_t    timestamp;
    uint8_t     is_creation;                // 1 = create, 0 = exit
    
    wchar_t     image_path[260];
    wchar_t     command_line[512];
};

// ---------------------------------------------------------------------------
// Thread Event — sent on PsSetCreateThreadNotifyRoutine
// ---------------------------------------------------------------------------
struct ThreadEvent {
    uint32_t    pid;
    uint32_t    tid;
    uint32_t    creating_pid;
    uint32_t    creating_tid;
    uint64_t    timestamp;
    uint8_t     is_creation;                // 1 = create, 0 = exit
};

// ---------------------------------------------------------------------------
// Image Load Event — sent on PsSetLoadImageNotifyRoutine
// ---------------------------------------------------------------------------
struct ImageLoadEvent {
    uint32_t    pid;
    uint64_t    timestamp;
    uint64_t    image_base;
    uint64_t    image_size;
    uint8_t     is_system_module;
    
    wchar_t     image_path[260];
};

// ---------------------------------------------------------------------------
// Handle Event — sent on ObRegisterCallbacks (OpenProcess/OpenThread)
// ---------------------------------------------------------------------------
struct HandleEvent {
    uint32_t    source_pid;
    uint32_t    target_pid;
    uint32_t    target_tid;                 // 0 if opening process
    uint64_t    timestamp;
    uint32_t    desired_access;
    uint8_t     is_thread_handle;           // 1 = Thread, 0 = Process
    uint8_t     is_creation;                // 1 = Create/Open, 0 = Duplicate
};

// ---------------------------------------------------------------------------
// Scan Result — returned from ML pipeline to kernel/agent
// ---------------------------------------------------------------------------
struct ScanResult {
    MLVerdict   verdict;
    uint32_t    confidence;                 // 0-100 confidence score
    char        reason[256];                // Human-readable reason string
};

#pragma pack(pop)

// Compile-time size validation
static_assert(sizeof(FeatureVector) < 4096, "FeatureVector must fit in a single page");

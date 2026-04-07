/**
 * @file callbacks.h
 * @brief SentinelDriver — Native Kernel Callbacks for deep telemetry.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include "sentinel_common_driver.h"

// Initialize native Windows kernel callbacks (Process, Thread, Image, Handle).
// If the BSOD crash counter exceeds the threshold, enters passive mode instead.
NTSTATUS RegisterKernelCallbacks();

// Remove all registered callbacks. Safe to call even in passive mode.
VOID UnregisterKernelCallbacks();

// Reset the BSOD boot counter (call when agent connects successfully).
VOID ResetBsodBootCounter();

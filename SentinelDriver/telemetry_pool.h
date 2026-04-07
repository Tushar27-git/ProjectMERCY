/**
 * @file telemetry_pool.h
 * @brief SentinelDriver — Pre-allocated telemetry memory pool and async worker.
 *
 * Provides a fixed-size pool of buffers to prevent pool exhaustion BSODs
 * and a system thread to handle FltSendMessage asynchronously.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include "sentinel_common_driver.h"

#define MAX_TELEMETRY_ITEMS 512

typedef struct _TELEMETRY_ITEM {
  LIST_ENTRY ListEntry;
  ULONG MessageType;
  ULONG PayloadSize;
  UCHAR Payload[MAX_IPC_PAYLOAD_SIZE];
} TELEMETRY_ITEM, *PTELEMETRY_ITEM;

/**
 * @brief Initialize the telemetry pool and start the async worker thread.
 */
NTSTATUS SentinelInitializeTelemetryPool();

/**
 * @brief Cleanup the telemetry pool and stop the worker thread.
 */
VOID SentinelCleanupTelemetryPool();

/**
 * @brief Queue a telemetry event for asynchronous delivery.
 *
 * Pulls a pre-allocated item from the free list, copies the payload,
 * and pushes it to the busy list for the worker thread to send.
 * Safe to call from IRQL <= DISPATCH_LEVEL.
 */
VOID SentinelQueueTelemetryItem(_In_reads_bytes_(PayloadSize) PVOID Payload,
                                _In_ ULONG PayloadSize, _In_ ULONG MessageType);

/**
 * @brief Reset the BSOD crash counter (helper from callbacks.cpp).
 */
VOID ResetBsodBootCounter();

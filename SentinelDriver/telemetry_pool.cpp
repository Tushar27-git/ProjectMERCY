/**
 * @file telemetry_pool.cpp
 * @brief SentinelDriver — Implementation of pre-allocated telemetry memory pool.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "telemetry_pool.h"
#include "comm_port.h"
#include <ntstrsafe.h>

// ---------------------------------------------------------------------------
// Global Queue Data
// ---------------------------------------------------------------------------
static struct {
    KSPIN_LOCK          Lock;
    LIST_ENTRY          FreeList;
    LIST_ENTRY          BusyList;
    KEVENT              Event;
    PVOID               WorkerThread;
    BOOLEAN             Shutdown;
    PTELEMETRY_ITEM     Buffer;         // Contiguous block of pre-allocated items
    ULONG               ItemsDroppedCount;
} g_TelemetryPool;

// ---------------------------------------------------------------------------
// Worker Thread Routine
// ---------------------------------------------------------------------------
static VOID SentinelTelemetryWorkerRoutine(_In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    PLIST_ENTRY entry;
    PTELEMETRY_ITEM item;

    SentinelDbgPrint("TelemetryWorker: Starting async worker thread...");

    while (!g_TelemetryPool.Shutdown) {
        // Wait for work or shutdown
        KeWaitForSingleObject(&g_TelemetryPool.Event, Executive, KernelMode, FALSE, NULL);

        if (g_TelemetryPool.Shutdown) break;

        // Process all busy items
        while (TRUE) {
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_TelemetryPool.Lock, &oldIrql);

            if (IsListEmpty(&g_TelemetryPool.BusyList)) {
                KeReleaseSpinLock(&g_TelemetryPool.Lock, oldIrql);
                break;
            }

            entry = RemoveHeadList(&g_TelemetryPool.BusyList);
            KeReleaseSpinLock(&g_TelemetryPool.Lock, oldIrql);

            item = CONTAINING_RECORD(entry, TELEMETRY_ITEM, ListEntry);

            // Send to userland (this may block/timeout - and that's okay here)
            SendTelemetryToAgent(item->Payload, item->PayloadSize, item->MessageType);

            // Return to free list
            KeAcquireSpinLock(&g_TelemetryPool.Lock, &oldIrql);
            InsertTailList(&g_TelemetryPool.FreeList, &item->ListEntry);
            KeReleaseSpinLock(&g_TelemetryPool.Lock, oldIrql);
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ---------------------------------------------------------------------------
// SentinelInitializeTelemetryPool
// ---------------------------------------------------------------------------
NTSTATUS SentinelInitializeTelemetryPool()
{
    RtlZeroMemory(&g_TelemetryPool, sizeof(g_TelemetryPool));
    KeInitializeSpinLock(&g_TelemetryPool.Lock);
    InitializeListHead(&g_TelemetryPool.FreeList);
    InitializeListHead(&g_TelemetryPool.BusyList);
    KeInitializeEvent(&g_TelemetryPool.Event, SynchronizationEvent, FALSE);

    // Pre-allocate the pool as a single contiguous block
    SIZE_T poolSize = sizeof(TELEMETRY_ITEM) * MAX_TELEMETRY_ITEMS;
    g_TelemetryPool.Buffer = (PTELEMETRY_ITEM)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        poolSize,
        SENTINEL_TAG);

    if (g_TelemetryPool.Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_TelemetryPool.Buffer, poolSize);

    // Populate the free list
    for (ULONG i = 0; i < MAX_TELEMETRY_ITEMS; i++) {
        InsertTailList(&g_TelemetryPool.FreeList, &g_TelemetryPool.Buffer[i].ListEntry);
    }

    // Start the worker thread
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hThread;
    NTSTATUS status = PsCreateSystemThread(
        &hThread,
        THREAD_ALL_ACCESS,
        &oa,
        NULL,
        NULL,
        SentinelTelemetryWorkerRoutine,
        NULL);

    if (NT_SUCCESS(status)) {
        // Resolve the thread handle to an object for cleanup
        status = ObReferenceObjectByHandle(
            hThread,
            THREAD_ALL_ACCESS,
            NULL,
            KernelMode,
            &g_TelemetryPool.WorkerThread,
            NULL);
        
        ZwClose(hThread);
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_TelemetryPool.Buffer, SENTINEL_TAG);
        g_TelemetryPool.Buffer = NULL;
        return status;
    }

    SentinelDbgPrint("TelemetryPool: Initialized with %d pre-allocated slots (Size=%llu KB).", 
        MAX_TELEMETRY_ITEMS, (UINT64)poolSize / 1024);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// SentinelCleanupTelemetryPool
// ---------------------------------------------------------------------------
VOID SentinelCleanupTelemetryPool()
{
    g_TelemetryPool.Shutdown = TRUE;
    KeSetEvent(&g_TelemetryPool.Event, IO_NO_INCREMENT, FALSE);

    if (g_TelemetryPool.WorkerThread) {
        KeWaitForSingleObject(g_TelemetryPool.WorkerThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_TelemetryPool.WorkerThread);
        g_TelemetryPool.WorkerThread = NULL;
    }

    if (g_TelemetryPool.Buffer) {
        ExFreePoolWithTag(g_TelemetryPool.Buffer, SENTINEL_TAG);
        g_TelemetryPool.Buffer = NULL;
    }

    SentinelDbgPrint("TelemetryPool: Cleanup complete.");
}

// ---------------------------------------------------------------------------
// SentinelQueueTelemetryItem
// ---------------------------------------------------------------------------
VOID SentinelQueueTelemetryItem(
    _In_reads_bytes_(PayloadSize) PVOID Payload,
    _In_ ULONG PayloadSize,
    _In_ ULONG MessageType)
{
    // Filter by connection state first (fast check)
    if (!InterlockedOr(&g_DriverData.ClientConnected, 0)) {
        return;
    }

    if (Payload == NULL || PayloadSize == 0 || PayloadSize > MAX_IPC_PAYLOAD_SIZE) {
        return;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_TelemetryPool.Lock, &oldIrql);

    if (IsListEmpty(&g_TelemetryPool.FreeList)) {
        g_TelemetryPool.ItemsDroppedCount++;
        KeReleaseSpinLock(&g_TelemetryPool.Lock, oldIrql);
        
        // Log dropped messages under extreme stress
        if (g_TelemetryPool.ItemsDroppedCount % 100 == 1) {
            SentinelDbgPrint("TelemetryPool: WARNING - Pool exhausted. Dropped %lu events.", 
                g_TelemetryPool.ItemsDroppedCount);
        }
        return;
    }

    // Pull from free list
    PLIST_ENTRY entry = RemoveHeadList(&g_TelemetryPool.FreeList);
    PTELEMETRY_ITEM item = CONTAINING_RECORD(entry, TELEMETRY_ITEM, ListEntry);

    // Fill data
    item->MessageType = MessageType;
    item->PayloadSize = PayloadSize;
    RtlCopyMemory(item->Payload, Payload, PayloadSize);

    // Push to busy list
    InsertTailList(&g_TelemetryPool.BusyList, &item->ListEntry);
    
    KeReleaseSpinLock(&g_TelemetryPool.Lock, oldIrql);

    // Wake up worker thread
    KeSetEvent(&g_TelemetryPool.Event, IO_NO_INCREMENT, FALSE);
}

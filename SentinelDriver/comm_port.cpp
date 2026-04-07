/**
 * @file comm_port.cpp
 * @brief SentinelDriver — FltCommunicationPort implementation.
 *
 * Creates and manages the communication channel between the kernel minifilter
 * and the userland SentinelAgent service. Uses FltCreateCommunicationPort for
 * the server side, with Connect/Disconnect/Message callbacks.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "comm_port.h"
#include "../SentinelCommon/ipc_protocol.h"
#include "../SentinelCommon/sentinel_constants.h"

// ---------------------------------------------------------------------------
// Static sequence counter for IPC messages
// ---------------------------------------------------------------------------
static volatile LONG64 g_SequenceNumber = 0;

// ---------------------------------------------------------------------------
// Communication Port Callbacks — Forward Declarations
// ---------------------------------------------------------------------------
static NTSTATUS FLTAPI ConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie);

static VOID FLTAPI DisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie);

static NTSTATUS FLTAPI MessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

// ---------------------------------------------------------------------------
// InitializeCommunicationPort
// ---------------------------------------------------------------------------
NTSTATUS InitializeCommunicationPort(_In_ PFLT_FILTER Filter)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    RtlInitUnicodeString(&portName, SENTINEL_PORT_NAME);

    // Build a security descriptor that allows userland SYSTEM processes to connect
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        SentinelDbgPrint("CommPort: FltBuildDefaultSecurityDescriptor failed (0x%08X)", status);
        return status;
    }

    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        sd);

    // Initialize the spinlock for client port protection
    KeInitializeSpinLock(&g_DriverData.ClientPortLock);

    status = FltCreateCommunicationPort(
        Filter,
        &g_DriverData.ServerPort,
        &oa,
        NULL,                           // ServerPortCookie
        ConnectNotifyCallback,
        DisconnectNotifyCallback,
        MessageNotifyCallback,
        1);                             // Max 1 connection (enforced atomically in ConnectNotifyCallback)

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        SentinelDbgPrint("CommPort: FltCreateCommunicationPort failed (0x%08X)", status);
        return status;
    }

    SentinelDbgPrint("CommPort: Communication port '%wZ' created successfully.", &portName);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// CloseCommunicationPort
// ---------------------------------------------------------------------------
VOID CloseCommunicationPort(VOID)
{
    KIRQL oldIrql;
    PFLT_PORT portToClose = NULL;

    KeAcquireSpinLock(&g_DriverData.ClientPortLock, &oldIrql);
    portToClose = g_DriverData.ClientPort;
    g_DriverData.ClientPort = NULL;
    InterlockedExchange(&g_DriverData.ClientConnected, FALSE);
    KeReleaseSpinLock(&g_DriverData.ClientPortLock, oldIrql);

    if (portToClose) {
        FltCloseClientPort(g_DriverData.Filter, &portToClose);
    }

    if (g_DriverData.ServerPort) {
        FltCloseCommunicationPort(g_DriverData.ServerPort);
        g_DriverData.ServerPort = NULL;
    }

    SentinelDbgPrint("CommPort: Communication port closed.");
}

// ---------------------------------------------------------------------------
// ConnectNotifyCallback
// ---------------------------------------------------------------------------
static NTSTATUS FLTAPI ConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    KIRQL oldIrql;

    // Atomically reject a second client if one is already connected
    KeAcquireSpinLock(&g_DriverData.ClientPortLock, &oldIrql);
    if (g_DriverData.ClientPort != NULL) {
        KeReleaseSpinLock(&g_DriverData.ClientPortLock, oldIrql);
        SentinelDbgPrint("CommPort: Rejected second client connection — already connected.");
        return STATUS_CONNECTION_COUNT_LIMIT;
    }
    g_DriverData.ClientPort = ClientPort;
    InterlockedExchange(&g_DriverData.ClientConnected, TRUE);
    KeReleaseSpinLock(&g_DriverData.ClientPortLock, oldIrql);

    SentinelDbgPrint("CommPort: Client connected (PID=%lu)",
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId());

    // Reset BSOD protection counter
    ResetBsodBootCounter();

    if (ConnectionPortCookie) {
        *ConnectionPortCookie = NULL;
    }

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// DisconnectNotifyCallback
// ---------------------------------------------------------------------------
static VOID FLTAPI DisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    KIRQL oldIrql;
    PFLT_PORT portToClose = NULL;

    KeAcquireSpinLock(&g_DriverData.ClientPortLock, &oldIrql);
    portToClose = g_DriverData.ClientPort;
    g_DriverData.ClientPort = NULL;
    InterlockedExchange(&g_DriverData.ClientConnected, FALSE);
    KeReleaseSpinLock(&g_DriverData.ClientPortLock, oldIrql);

    if (portToClose) {
        FltCloseClientPort(g_DriverData.Filter, &portToClose);
    }

    SentinelDbgPrint("CommPort: Client disconnected.");
}

// ---------------------------------------------------------------------------
// MessageNotifyCallback — handle messages FROM userland
// ---------------------------------------------------------------------------
static NTSTATUS FLTAPI MessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);

    if (ReturnOutputBufferLength) {
        *ReturnOutputBufferLength = 0;
    }

    // Validate input
    if (InputBuffer == NULL || InputBufferLength < sizeof(IpcMessageHeader)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        const IpcMessageHeader* header = (const IpcMessageHeader*)InputBuffer;

        // Validate magic
        if (header->magic != IPC_MAGIC) {
            SentinelDbgPrint("CommPort: Invalid message magic (0x%08X)", header->magic);
            return STATUS_INVALID_PARAMETER;
        }

        switch (header->msg_type) {
        case IpcMessageType::HEARTBEAT:
            SentinelDbgPrint("CommPort: Heartbeat received (seq=%llu)", header->sequence_number);
            break;

        case IpcMessageType::KILL_SWITCH_TOGGLE:
            SentinelDbgPrint("CommPort: Kill switch toggle received.");
            // Future: toggle driver-side enforcement
            break;

        default:
            SentinelDbgPrint("CommPort: Unknown message type (0x%04X)", (ULONG)header->msg_type);
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SentinelDbgPrint("CommPort: Exception in MessageNotifyCallback (0x%08X)", GetExceptionCode());
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// SendTelemetryToAgent
// ---------------------------------------------------------------------------
NTSTATUS SendTelemetryToAgent(
    _In_reads_bytes_(PayloadSize) PVOID Payload,
    _In_ ULONG PayloadSize,
    _In_ ULONG MessageType)
{
    // --- Spinlock-protected port snapshot ---
    KIRQL oldIrql;
    PFLT_PORT clientPort = NULL;

    KeAcquireSpinLock(&g_DriverData.ClientPortLock, &oldIrql);
    if (InterlockedOr(&g_DriverData.ClientConnected, 0) && g_DriverData.ClientPort != NULL) {
        clientPort = g_DriverData.ClientPort;
        // Note: FltSendMessage holds its own internal reference; we just need the
        // port handle to be valid at call time. The spinlock guarantees it won't
        // be NULLed while we hold it, and FltSendMessage is safe to call under it
        // only at PASSIVE_LEVEL. Callers from PASSIVE_LEVEL callbacks are fine;
        // callbacks that may run at APC_LEVEL queue via work items (callbacks.cpp).
    }
    KeReleaseSpinLock(&g_DriverData.ClientPortLock, oldIrql);

    if (clientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }

    if (Payload == NULL || PayloadSize == 0 || PayloadSize > MAX_IPC_PAYLOAD_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    // Build the IPC message
    const ULONG totalSize = sizeof(IpcMessageHeader) + PayloadSize;

    PUCHAR messageBuffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, totalSize, SENTINEL_TAG);
    if (messageBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Fill header
    IpcMessageHeader* header = (IpcMessageHeader*)messageBuffer;
    header->magic = IPC_MAGIC;
    header->version = IPC_VERSION;
    header->msg_type = (IpcMessageType)MessageType;
    header->payload_size = PayloadSize;
    header->sequence_number = (UINT64)InterlockedIncrement64(&g_SequenceNumber);

    LARGE_INTEGER timestamp;
    KeQuerySystemTimePrecise(&timestamp);
    header->timestamp = (UINT64)timestamp.QuadPart;

    // Save sequence_number BEFORE the pool free (fix: use-after-free #5)
    UINT64 seqNum = header->sequence_number;

    // Copy payload
    RtlCopyMemory(messageBuffer + sizeof(IpcMessageHeader), Payload, PayloadSize);

    // Send via FltSendMessage (with 5-second timeout)
    LARGE_INTEGER timeout;
    timeout.QuadPart = -50000000LL;  // 5 seconds in 100ns units (negative = relative)

    UserToKernelReply reply = { 0 };
    ULONG replyLength = sizeof(reply);

    NTSTATUS status = FltSendMessage(
        g_DriverData.Filter,
        &clientPort,
        messageBuffer,
        totalSize,
        &reply,
        &replyLength,
        &timeout);

    ExFreePoolWithTag(messageBuffer, SENTINEL_TAG);

    if (NT_SUCCESS(status)) {
        SentinelDbgPrint("CommPort: Telemetry sent (seq=%llu, type=%u, verdict=%u)",
            seqNum, MessageType, reply.verdict);
    } else if (status == STATUS_TIMEOUT) {
        SentinelDbgPrint("CommPort: FltSendMessage timed out.");
    } else {
        SentinelDbgPrint("CommPort: FltSendMessage failed (0x%08X)", status);
    }

    return status;
}

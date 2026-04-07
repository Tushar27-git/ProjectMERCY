/**
 * @file comm_port.h
 * @brief SentinelDriver — Communication port between kernel driver and userland agent.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include "common.h"
#include "../SentinelCommon/feature_vector.h"

/**
 * @brief Initialize the FltCommunicationPort for userland agent connection.
 * @param Filter  The registered minifilter handle.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS InitializeCommunicationPort(_In_ PFLT_FILTER Filter);

/**
 * @brief Close and cleanup the communication port.
 */
VOID CloseCommunicationPort(VOID);

/**
 * @brief Send a generic telemetry payload to the connected userland agent.
 * @param Payload       Pointer to the payload data.
 * @param PayloadSize   Size of the payload in bytes.
 * @param MessageType   IPC message type (cast from IpcMessageType).
 * @return STATUS_SUCCESS on success, STATUS_PORT_DISCONNECTED if no client.
 */
NTSTATUS SendTelemetryToAgent(
    _In_reads_bytes_(PayloadSize) PVOID Payload,
    _In_ ULONG PayloadSize,
    _In_ ULONG MessageType);

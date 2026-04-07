/**
 * @file minifilter_client.h
 * @brief SentinelAgent — Userland client for the kernel minifilter communication port.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fltuser.h>
#include <atomic>

#include "ring_buffer.h"
#include "telemetry_record.h"
#include "../SentinelCommon/feature_vector.h"

namespace sentinel {

// Forward declarations
class ThreadPool;
class MLPipelineInterface;

/**
 * @brief Client-side handler for the kernel minifilter communication port.
 *
 * Connects to the driver's \SentinelCorePort, receives FeatureVectors via
 * FilterGetMessage, and dispatches them to Thread Pool 1.
 */
class MinifilterClient {
public:
    MinifilterClient();
    ~MinifilterClient();

    /**
     * @brief Connect to the kernel minifilter communication port.
     * @return true on success.
     */
    bool Connect();

    /**
     * @brief Disconnect from the kernel minifilter.
     */
    void Disconnect();

    /**
     * @brief Start the message receive loop (runs in a dedicated thread).
     * @param pool      Thread pool to dispatch received events to.
     * @param ringBuf   Ring buffer for telemetry output.
     * @param pipeline  ML pipeline interface for verdict checking.
     */
    void StartReceiveLoop(
        ThreadPool* pool,
        SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf,
        MLPipelineInterface* pipeline);

    /**
     * @brief Stop the receive loop.
     */
    void StopReceiveLoop();

    /**
     * @brief Check if connected to the driver.
     */
    bool IsConnected() const { return m_connected.load(); }

    uint64_t MessagesReceived() const { return m_messagesReceived.load(); }

    /**
     * @brief The receive loop thread function.
     */
    void ReceiveThreadFunc(
        ThreadPool* pool,
        SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf,
        MLPipelineInterface* pipeline);

private:
    HANDLE                  m_hPort;
    std::atomic<bool>       m_connected;
    std::atomic<bool>       m_receiving;
    std::atomic<uint64_t>   m_messagesReceived;
    HANDLE                  m_receiveThread;
};

} // namespace sentinel

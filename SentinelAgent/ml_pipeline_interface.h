/**
 * @file ml_pipeline_interface.h
 * @brief SentinelAgent — ML Pipeline integration stub.
 *
 * Phase 1: Returns ALLOW for all verdicts.
 * Phase 2: Will send FeatureVector via NamedPipeClient to Python ML engine
 *          and await the response.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include "../SentinelCommon/feature_vector.h"
#include "logger.h"
#include <atomic>
#include <mutex>
#include <string>

namespace sentinel {

// Forward declaration for Phase 2 integration
class NamedPipeClient;

/**
 * @brief Interface for the ML inference pipeline.
 *
 * Currently a stub that always returns ALLOW. Designed to be upgraded
 * to a NamedPipe-based client that sends FeatureVectors to a Python
 * ML server and receives verdicts asynchronously.
 */
class MLPipelineInterface {
public:
    MLPipelineInterface()
        : m_killSwitch(false)
        , m_pipeClient(nullptr)
        , m_totalQueries(0)
        , m_allowCount(0)
        , m_blockCount(0)
    {}

    ~MLPipelineInterface() = default;

    /**
     * @brief Get a verdict for the given feature vector.
     *
     * Phase 1: Always returns ALLOW (or BLOCK if kill switch is active).
     * Phase 2: Serializes FeatureVector → JSON, sends via NamedPipeClient,
     *          waits for Python ML engine response with timeout.
     *
     * @param fv  The feature vector to evaluate.
     * @return MLVerdict indicating the recommended action.
     */
    MLVerdict GetVerdict(const FeatureVector& fv) {
        m_totalQueries++;

        // Kill switch: block everything (for integration testing)
        if (m_killSwitch.load(std::memory_order_acquire)) {
            LOG_WARN("MLPipeline: Kill switch ACTIVE — blocking (sha256=%.8s..., pid=%u)",
                FormatHash(fv.sha256_hash).c_str(), fv.source_pid);
            m_blockCount++;
            return MLVerdict::BLOCK;
        }

        // Phase 2 integration point:
        // if (m_pipeClient && m_pipeClient->IsConnected()) {
        //     auto response = m_pipeClient->SendAndWait(SerializeFeatureVector(fv));
        //     return ParseVerdict(response);
        // }

        // Phase 1 stub: always ALLOW
        LOG_TRACE("MLPipeline: GetVerdict → ALLOW (sha256=%.8s..., entropy=%.2f, sections=%u)",
            FormatHash(fv.sha256_hash).c_str(),
            (double)fv.max_entropy,
            fv.section_count);

        m_allowCount++;
        return MLVerdict::ALLOW;
    }

    // -----------------------------------------------------------------------
    // Kill Switch Control
    // -----------------------------------------------------------------------

    /**
     * @brief Enable or disable the kill switch.
     * When active, all verdicts return BLOCK regardless of ML analysis.
     */
    void SetKillSwitch(bool enabled) {
        m_killSwitch.store(enabled, std::memory_order_release);
        LOG_INFO("MLPipeline: Kill switch %s", enabled ? "ACTIVATED" : "DEACTIVATED");
    }

    bool IsKillSwitchActive() const {
        return m_killSwitch.load(std::memory_order_acquire);
    }

    // -----------------------------------------------------------------------
    // Phase 2: Set the pipe client for ML engine communication
    // -----------------------------------------------------------------------
    void SetPipeClient(NamedPipeClient* pipeClient) {
        m_pipeClient = pipeClient;
        LOG_INFO("MLPipeline: Pipe client %s", pipeClient ? "attached" : "detached");
    }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------
    uint64_t TotalQueries() const { return m_totalQueries.load(); }
    uint64_t AllowCount() const { return m_allowCount.load(); }
    uint64_t BlockCount() const { return m_blockCount.load(); }

private:
    /**
     * @brief Format a SHA-256 hash as a hex string (first 8 chars for logging).
     */
    static std::string FormatHash(const uint8_t hash[32]) {
        char buf[9];
        snprintf(buf, sizeof(buf), "%02x%02x%02x%02x",
            hash[0], hash[1], hash[2], hash[3]);
        return std::string(buf);
    }

    std::atomic<bool>       m_killSwitch;
    NamedPipeClient*        m_pipeClient;   // Non-owning, Phase 2
    std::atomic<uint64_t>   m_totalQueries;
    std::atomic<uint64_t>   m_allowCount;
    std::atomic<uint64_t>   m_blockCount;
};

} // namespace sentinel

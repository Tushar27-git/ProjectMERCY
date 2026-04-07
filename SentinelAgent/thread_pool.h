/**
 * @file thread_pool.h
 * @brief SentinelAgent — Configurable thread pool with priority and latency controls.
 *
 * Four independent pools serve different sensor subsystems:
 *   Pool 1: Mini-filter callbacks   (4 threads, ABOVE_NORMAL, <300ms latency)
 *   Pool 2: AMSI scan requests      (2 threads, NORMAL)
 *   Pool 3: ETW + API Hook events   (4 threads, NORMAL)
 *   Pool 4: Memory scanner          (1 thread,  BELOW_NORMAL)
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <functional>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <string>

#include "logger.h"

namespace sentinel {

// ---------------------------------------------------------------------------
// ThreadPool — Generic work-stealing pool with configurable thread priority
// ---------------------------------------------------------------------------
class ThreadPool {
public:
    using Task = std::function<void()>;

    /**
     * @brief Construct a thread pool.
     * @param name          Human-readable pool name for logging.
     * @param threadCount   Number of worker threads.
     * @param priority      Windows thread priority (e.g., THREAD_PRIORITY_ABOVE_NORMAL).
     * @param maxLatencyMs  Target max latency in ms (0 = no enforcement).
     */
    ThreadPool(const std::string& name, size_t threadCount, int priority, uint32_t maxLatencyMs = 0)
        : m_name(name)
        , m_priority(priority)
        , m_maxLatencyMs(maxLatencyMs)
        , m_running(false)
        , m_totalTasks(0)
        , m_completedTasks(0)
        , m_droppedTasks(0)
    {
        m_workers.reserve(threadCount);
    }

    ~ThreadPool() {
        Stop();
    }

    // Non-copyable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    /**
     * @brief Start all worker threads.
     */
    void Start() {
        if (m_running.exchange(true)) return; // Already running

        LOG_INFO("ThreadPool '%s': Starting %zu workers (priority=%d, latency_target=%ums)",
            m_name.c_str(), m_workers.capacity(), m_priority, m_maxLatencyMs);

        size_t workerCount = m_workers.capacity();
        for (size_t i = 0; i < workerCount; i++) {
            m_workers.emplace_back([this, i]() {
                // Set thread priority
                SetThreadPriority(GetCurrentThread(), m_priority);

                // Name the thread for debugging
                char threadName[64];
                snprintf(threadName, sizeof(threadName), "%s-Worker-%zu", m_name.c_str(), i);
                LOG_DEBUG("ThreadPool: %s started (TID=%lu)", threadName, GetCurrentThreadId());

                WorkerLoop();

                LOG_DEBUG("ThreadPool: %s stopped (TID=%lu)", threadName, GetCurrentThreadId());
            });
        }
    }

    /**
     * @brief Stop all worker threads and drain the queue.
     */
    void Stop() {
        if (!m_running.exchange(false)) return; // Already stopped

        m_cv.notify_all();

        for (auto& worker : m_workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        m_workers.clear();

        LOG_INFO("ThreadPool '%s': Stopped. Total=%llu, Completed=%llu, Dropped=%llu",
            m_name.c_str(), m_totalTasks.load(), m_completedTasks.load(), m_droppedTasks.load());
    }

    /**
     * @brief Submit a task to the pool.
     * @param task  The callable to execute.
     * @return true if enqueued, false if pool is stopped.
     */
    bool Submit(Task task) {
        if (!m_running) return false;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_taskQueue.push({
                std::move(task),
                std::chrono::steady_clock::now()
            });
            m_totalTasks++;
        }
        m_cv.notify_one();
        return true;
    }

    /**
     * @brief Get the number of pending tasks.
     */
    size_t PendingCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_taskQueue.size();
    }

    /**
     * @brief Get statistics.
     */
    uint64_t TotalTasks() const { return m_totalTasks.load(); }
    uint64_t CompletedTasks() const { return m_completedTasks.load(); }
    uint64_t DroppedTasks() const { return m_droppedTasks.load(); }
    bool IsRunning() const { return m_running.load(); }

private:
    struct TimedTask {
        Task task;
        std::chrono::steady_clock::time_point enqueueTime;
    };

    void WorkerLoop() {
        while (m_running) {
            TimedTask timedTask;

            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait_for(lock, std::chrono::milliseconds(100), [this]() {
                    return !m_taskQueue.empty() || !m_running;
                });

                if (!m_running && m_taskQueue.empty()) break;
                if (m_taskQueue.empty()) continue;

                timedTask = std::move(m_taskQueue.front());
                m_taskQueue.pop();
            }

            // Check latency: if task waited too long and we have a latency target, skip it
            if (m_maxLatencyMs > 0) {
                auto waitTime = std::chrono::steady_clock::now() - timedTask.enqueueTime;
                auto waitMs = std::chrono::duration_cast<std::chrono::milliseconds>(waitTime).count();

                if (waitMs > m_maxLatencyMs) {
                    LOG_WARN("ThreadPool '%s': Task dropped — waited %lldms (max=%ums)",
                        m_name.c_str(), waitMs, m_maxLatencyMs);
                    m_droppedTasks++;
                    continue;
                }
            }

            // Execute the task
            try {
                timedTask.task();
                m_completedTasks++;
            }
            catch (const std::exception& ex) {
                LOG_ERROR("ThreadPool '%s': Task threw exception: %s", m_name.c_str(), ex.what());
            }
            catch (...) {
                LOG_ERROR("ThreadPool '%s': Task threw unknown exception.", m_name.c_str());
            }
        }
    }

    std::string                     m_name;
    int                             m_priority;
    uint32_t                        m_maxLatencyMs;
    std::atomic<bool>               m_running;
    std::atomic<uint64_t>           m_totalTasks;
    std::atomic<uint64_t>           m_completedTasks;
    std::atomic<uint64_t>           m_droppedTasks;

    mutable std::mutex              m_mutex;
    std::condition_variable         m_cv;
    std::queue<TimedTask>           m_taskQueue;
    std::vector<std::thread>        m_workers;
};

} // namespace sentinel

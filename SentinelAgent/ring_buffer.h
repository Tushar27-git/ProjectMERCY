/**
 * @file ring_buffer.h
 * @brief SentinelAgent — Lock-free SPSC (Single Producer Single Consumer) Ring Buffer.
 *
 * Header-only implementation using C++17 atomics with acquire-release semantics.
 * Designed for the "hot path" of telemetry: producers (thread pools) push events,
 * the telemetry consumer (NamedPipeClient) pops and serializes them.
 *
 * Key properties:
 *   - Wait-free for both producer and consumer
 *   - Cache-line aligned head/tail to prevent false sharing
 *   - Power-of-2 capacity for branchless wrapping via bitmask
 *   - No dynamic allocation after construction
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <cstring>
#include <type_traits>
#include <new>

namespace sentinel {

// Cache line size (64 bytes on x86-64)
#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 64
#endif

/**
 * @brief Lock-free SPSC Ring Buffer.
 * @tparam T        Element type (must be trivially copyable for memcpy safety).
 * @tparam Capacity Buffer capacity (must be a power of 2).
 */
template <typename T, size_t Capacity>
class SPSCRingBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0,
        "SPSCRingBuffer capacity must be a power of 2");
    static_assert(Capacity >= 2,
        "SPSCRingBuffer capacity must be at least 2");

public:
    SPSCRingBuffer() : m_head(0), m_tail(0) {
        memset(m_buffer, 0, sizeof(m_buffer));
    }

    // Non-copyable, non-movable
    SPSCRingBuffer(const SPSCRingBuffer&) = delete;
    SPSCRingBuffer& operator=(const SPSCRingBuffer&) = delete;

    /**
     * @brief Try to push an item (producer only).
     * @param item  The item to push.
     * @return true if pushed, false if buffer is full.
     */
    bool try_push(const T& item) noexcept {
        const size_t tail = m_tail.load(std::memory_order_relaxed);
        const size_t next_tail = (tail + 1) & kMask;

        // Check if buffer is full
        if (next_tail == m_head.load(std::memory_order_acquire)) {
            return false;
        }

        m_buffer[tail] = item;

        // Release: ensure the data write is visible before advancing tail
        m_tail.store(next_tail, std::memory_order_release);
        return true;
    }

    /**
     * @brief Try to push an item using move semantics (producer only).
     * @param item  The item to move-push.
     * @return true if pushed, false if buffer is full.
     */
    bool try_push(T&& item) noexcept {
        const size_t tail = m_tail.load(std::memory_order_relaxed);
        const size_t next_tail = (tail + 1) & kMask;

        if (next_tail == m_head.load(std::memory_order_acquire)) {
            return false;
        }

        m_buffer[tail] = std::move(item);
        m_tail.store(next_tail, std::memory_order_release);
        return true;
    }

    /**
     * @brief Try to pop an item (consumer only).
     * @param item  Output: the popped item.
     * @return true if popped, false if buffer is empty.
     */
    bool try_pop(T& item) noexcept {
        const size_t head = m_head.load(std::memory_order_relaxed);

        // Check if buffer is empty
        if (head == m_tail.load(std::memory_order_acquire)) {
            return false;
        }

        item = m_buffer[head];

        // Release: ensure the read is complete before advancing head
        m_head.store((head + 1) & kMask, std::memory_order_release);
        return true;
    }

    /**
     * @brief Peek at the front item without removing it (consumer only).
     * @param item  Output: copy of the front item.
     * @return true if peeked, false if buffer is empty.
     */
    bool peek(T& item) const noexcept {
        const size_t head = m_head.load(std::memory_order_relaxed);

        if (head == m_tail.load(std::memory_order_acquire)) {
            return false;
        }

        item = m_buffer[head];
        return true;
    }

    /**
     * @brief Current number of items in the buffer (approximate, racy).
     */
    size_t size() const noexcept {
        const size_t tail = m_tail.load(std::memory_order_acquire);
        const size_t head = m_head.load(std::memory_order_acquire);
        return (tail - head) & kMask;
    }

    /**
     * @brief Check if the buffer is empty (approximate).
     */
    bool empty() const noexcept {
        return m_head.load(std::memory_order_acquire) ==
               m_tail.load(std::memory_order_acquire);
    }

    /**
     * @brief Check if the buffer is full (approximate).
     */
    bool full() const noexcept {
        const size_t tail = m_tail.load(std::memory_order_acquire);
        const size_t next_tail = (tail + 1) & kMask;
        return next_tail == m_head.load(std::memory_order_acquire);
    }

    /**
     * @brief Maximum capacity of the buffer.
     */
    constexpr size_t capacity() const noexcept {
        return Capacity - 1;  // One slot reserved for full/empty distinction
    }

private:
    static constexpr size_t kMask = Capacity - 1;

    // Data buffer
    T m_buffer[Capacity];

    // Cache-line aligned atomics to prevent false sharing
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> m_head;
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> m_tail;
};

} // namespace sentinel

/**
 * @file logger.h
 * @brief SentinelAgent — Thread-safe structured logging utility.
 *
 * Singleton logger with severity levels, file output, and OutputDebugString.
 * Format: [TIMESTAMP][LEVEL][THREAD_ID] message
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <mutex>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstdio>

namespace sentinel {

// ---------------------------------------------------------------------------
// Log Severity Levels
// ---------------------------------------------------------------------------
enum class LogLevel : int {
    TRACE   = 0,
    DBG     = 1,    // 'DEBUG' conflicts with Windows macro
    INFO    = 2,
    WARN    = 3,
    ERR     = 4,    // 'ERROR' conflicts with Windows macro
    FATAL   = 5
};

inline const char* LogLevelToString(LogLevel level) {
    switch (level) {
    case LogLevel::TRACE: return "TRACE";
    case LogLevel::DBG:   return "DEBUG";
    case LogLevel::INFO:  return "INFO ";
    case LogLevel::WARN:  return "WARN ";
    case LogLevel::ERR:   return "ERROR";
    case LogLevel::FATAL: return "FATAL";
    default:               return "?????";
    }
}

// ---------------------------------------------------------------------------
// Logger Singleton
// ---------------------------------------------------------------------------
class Logger {
public:
    static Logger& Instance() {
        static Logger instance;
        return instance;
    }

    // Initialize the logger. Must be called once before use.
    bool Initialize(const std::wstring& logFilePath, LogLevel minLevel = LogLevel::INFO) {
        std::lock_guard<std::mutex> lock(m_mutex);

        m_minLevel = minLevel;

        // Ensure directory exists
        std::wstring dir = logFilePath.substr(0, logFilePath.find_last_of(L'\\'));
        CreateDirectoryW(dir.c_str(), NULL);

        m_file.open(logFilePath, std::ios::app | std::ios::out);
        if (!m_file.is_open()) {
            OutputDebugStringA("[SentinelCore] FATAL: Failed to open log file!\n");
            return false;
        }

        m_initialized = true;
        Log(LogLevel::INFO, "Logger initialized. Min level: %s", LogLevelToString(minLevel));
        return true;
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_file.is_open()) {
            m_file.flush();
            m_file.close();
        }
        m_initialized = false;
    }

    void SetMinLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_minLevel = level;
    }

    template<typename... Args>
    void Log(LogLevel level, const char* fmt, Args... args) {
        if (level < m_minLevel) return;

        char msgBuffer[2048];
        snprintf(msgBuffer, sizeof(msgBuffer), fmt, args...);

        // Build formatted line
        auto now = std::chrono::system_clock::now();
        auto timeT = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        struct tm tmBuf;
        localtime_s(&tmBuf, &timeT);

        char lineBuffer[2560];
        snprintf(lineBuffer, sizeof(lineBuffer),
            "[%04d-%02d-%02d %02d:%02d:%02d.%03lld][%s][%05lu] %s\n",
            tmBuf.tm_year + 1900, tmBuf.tm_mon + 1, tmBuf.tm_mday,
            tmBuf.tm_hour, tmBuf.tm_min, tmBuf.tm_sec,
            (long long)ms.count(),
            LogLevelToString(level),
            GetCurrentThreadId(),
            msgBuffer);

        // Write to file and debug output
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_initialized && m_file.is_open()) {
                m_file << lineBuffer;
                m_file.flush();
            }
        }

        OutputDebugStringA(lineBuffer);

        // Fatal: also trigger debugger break in debug builds
#if defined(_DEBUG) || defined(DBG)
        if (level == LogLevel::FATAL) {
            __debugbreak();
        }
#endif
    }

private:
    Logger() = default;
    ~Logger() { Shutdown(); }
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::mutex      m_mutex;
    std::ofstream   m_file;
    LogLevel        m_minLevel = LogLevel::INFO;
    bool            m_initialized = false;
};

// ---------------------------------------------------------------------------
// Convenience Macros
// ---------------------------------------------------------------------------
#define LOG_TRACE(fmt, ...)  sentinel::Logger::Instance().Log(sentinel::LogLevel::TRACE, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)  sentinel::Logger::Instance().Log(sentinel::LogLevel::DBG,   fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)   sentinel::Logger::Instance().Log(sentinel::LogLevel::INFO,  fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)   sentinel::Logger::Instance().Log(sentinel::LogLevel::WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)  sentinel::Logger::Instance().Log(sentinel::LogLevel::ERR,   fmt, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...)  sentinel::Logger::Instance().Log(sentinel::LogLevel::FATAL, fmt, ##__VA_ARGS__)

} // namespace sentinel

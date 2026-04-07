/**
 * @file amsi_provider.h
 * @brief SentinelAmsiProvider — IAntimalwareProvider COM implementation.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include <windows.h>
#include <amsi.h>
#include <atomic>

/**
 * @brief SentinelCore AMSI Provider — intercepts script content from
 *        PowerShell, VBA, and other AMSI-aware applications.
 *
 * Scan() captures plaintext script buffers, routes them to the telemetry bus,
 * and returns AMSI_RESULT_NOT_DETECTED by default. A kill switch can be
 * toggled to return AMSI_RESULT_DETECTED for integration testing.
 */
class SentinelAmsiProvider : public IAntimalwareProvider {
public:
    SentinelAmsiProvider();
    virtual ~SentinelAmsiProvider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // IAntimalwareProvider
    IFACEMETHODIMP Scan(
        _In_ IAmsiStream* stream,
        _Out_ AMSI_RESULT* result) override;

    IFACEMETHODIMP_(void) CloseSession(
        _In_ ULONGLONG session) override;

    IFACEMETHODIMP DisplayName(
        _Out_ LPWSTR* displayName) override;

    // Kill switch (for integration testing)
    static void SetKillSwitch(bool enabled);
    static bool IsKillSwitchActive();

private:
    LONG m_refCount;
    static std::atomic<bool> s_killSwitch;
};

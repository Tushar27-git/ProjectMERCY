/**
 * @file class_factory.h
 * @brief SentinelAmsiProvider — COM class factory for the AMSI provider.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#include <windows.h>
#include <unknwn.h>

/**
 * @brief Standard COM Class Factory that creates SentinelAmsiProvider instances.
 */
class SentinelAmsiClassFactory : public IClassFactory {
public:
    SentinelAmsiClassFactory();
    virtual ~SentinelAmsiClassFactory();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // IClassFactory
    IFACEMETHODIMP CreateInstance(
        _In_opt_ IUnknown* pUnkOuter,
        _In_ REFIID riid,
        _Out_ void** ppv) override;

    IFACEMETHODIMP LockServer(_In_ BOOL fLock) override;

private:
    LONG m_refCount;
};

// Global server lock count
extern LONG g_serverLockCount;
extern LONG g_objectCount;

/**
 * @file class_factory.cpp
 * @brief SentinelAmsiProvider — COM class factory implementation.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "class_factory.h"
#include "amsi_provider.h"

LONG g_serverLockCount = 0;
LONG g_objectCount = 0;

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
SentinelAmsiClassFactory::SentinelAmsiClassFactory()
    : m_refCount(1)
{
    InterlockedIncrement(&g_objectCount);
}

SentinelAmsiClassFactory::~SentinelAmsiClassFactory() {
    InterlockedDecrement(&g_objectCount);
}

// ---------------------------------------------------------------------------
// IUnknown
// ---------------------------------------------------------------------------
IFACEMETHODIMP SentinelAmsiClassFactory::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_IClassFactory))
    {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) SentinelAmsiClassFactory::AddRef() {
    return InterlockedIncrement(&m_refCount);
}

IFACEMETHODIMP_(ULONG) SentinelAmsiClassFactory::Release() {
    LONG count = InterlockedDecrement(&m_refCount);
    if (count == 0) {
        delete this;
    }
    return count;
}

// ---------------------------------------------------------------------------
// IClassFactory::CreateInstance
// ---------------------------------------------------------------------------
IFACEMETHODIMP SentinelAmsiClassFactory::CreateInstance(
    _In_opt_ IUnknown* pUnkOuter,
    _In_ REFIID riid,
    _Out_ void** ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    // No aggregation support
    if (pUnkOuter != nullptr) {
        return CLASS_E_NOAGGREGATION;
    }

    // Create the provider
    SentinelAmsiProvider* provider = new (std::nothrow) SentinelAmsiProvider();
    if (!provider) {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = provider->QueryInterface(riid, ppv);
    provider->Release();

    return hr;
}

// ---------------------------------------------------------------------------
// IClassFactory::LockServer
// ---------------------------------------------------------------------------
IFACEMETHODIMP SentinelAmsiClassFactory::LockServer(_In_ BOOL fLock) {
    if (fLock) {
        InterlockedIncrement(&g_serverLockCount);
    } else {
        InterlockedDecrement(&g_serverLockCount);
    }
    return S_OK;
}

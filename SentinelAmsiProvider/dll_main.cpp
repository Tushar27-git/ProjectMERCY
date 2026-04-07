/**
 * @file dll_main.cpp
 * @brief SentinelAmsiProvider — DLL entry points for COM AMSI provider.
 *
 * Exports:
 *   - DllGetClassObject    (COM class factory creation)
 *   - DllCanUnloadNow      (COM server lifetime)
 *   - DllRegisterServer    (COM + AMSI registry registration)
 *   - DllUnregisterServer  (COM + AMSI registry cleanup)
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include <windows.h>
#include <olectl.h>
#include <strsafe.h>

#include "class_factory.h"
#include "amsi_provider.h"
#include "../SentinelCommon/sentinel_constants.h"

// Module handle
static HMODULE g_hModule = NULL;

// ---------------------------------------------------------------------------
// DllMain
// ---------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(lpReserved);

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

// ---------------------------------------------------------------------------
// DllGetClassObject — COM entry point for creating class factory
// ---------------------------------------------------------------------------
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    // Check if the requested CLSID matches our provider
    if (!IsEqualCLSID(rclsid, CLSID_SentinelAmsiProvider)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    SentinelAmsiClassFactory* factory = new (std::nothrow) SentinelAmsiClassFactory();
    if (!factory) {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();

    return hr;
}

// ---------------------------------------------------------------------------
// DllCanUnloadNow — COM lifetime check
// ---------------------------------------------------------------------------
STDAPI DllCanUnloadNow() {
    return (g_objectCount == 0 && g_serverLockCount == 0) ? S_OK : S_FALSE;
}

// ---------------------------------------------------------------------------
// Helper: Set a registry string value
// ---------------------------------------------------------------------------
static HRESULT SetRegValue(HKEY hKey, LPCWSTR valueName, LPCWSTR value) {
    LSTATUS status = RegSetValueExW(hKey, valueName, 0, REG_SZ,
        (const BYTE*)value, (DWORD)((wcslen(value) + 1) * sizeof(WCHAR)));
    return HRESULT_FROM_WIN32(status);
}

// ---------------------------------------------------------------------------
// DllRegisterServer — Register COM class + AMSI provider in registry
// ---------------------------------------------------------------------------
STDAPI DllRegisterServer() {
    HRESULT hr = S_OK;
    HKEY hKey = NULL;
    WCHAR dllPath[MAX_PATH] = {};

    // Get DLL path
    GetModuleFileNameW(g_hModule, dllPath, MAX_PATH);

    // -----------------------------------------------------------------------
    // Register COM class: HKCR\CLSID\{our-guid}
    // -----------------------------------------------------------------------
    WCHAR clsidKey[256];
    StringCchPrintfW(clsidKey, _countof(clsidKey),
        L"SOFTWARE\\Classes\\CLSID\\%s", SENTINEL_AMSI_PROVIDER_CLSID_STR);

    LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, clsidKey,
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);

    SetRegValue(hKey, NULL, SENTINEL_AMSI_PROVIDER_DESCRIPTION);
    RegCloseKey(hKey);

    // Register InprocServer32
    WCHAR inprocKey[512];
    StringCchPrintfW(inprocKey, _countof(inprocKey),
        L"%s\\InprocServer32", clsidKey);

    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, inprocKey,
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);

    SetRegValue(hKey, NULL, dllPath);
    SetRegValue(hKey, L"ThreadingModel", L"Both");
    RegCloseKey(hKey);

    // -----------------------------------------------------------------------
    // Register AMSI provider: HKLM\SOFTWARE\Microsoft\AMSI\Providers\{guid}
    // -----------------------------------------------------------------------
    WCHAR amsiKey[256];
    StringCchPrintfW(amsiKey, _countof(amsiKey),
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s",
        SENTINEL_AMSI_PROVIDER_CLSID_STR);

    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, amsiKey,
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);

    RegCloseKey(hKey);

    OutputDebugStringW(L"[SentinelCore] AMSI Provider registered successfully.\n");
    return S_OK;
}

// ---------------------------------------------------------------------------
// DllUnregisterServer — Remove COM + AMSI registry entries
// ---------------------------------------------------------------------------
STDAPI DllUnregisterServer() {
    // Remove AMSI provider registration
    WCHAR amsiKey[256];
    StringCchPrintfW(amsiKey, _countof(amsiKey),
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s",
        SENTINEL_AMSI_PROVIDER_CLSID_STR);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, amsiKey);

    // Remove COM class registration
    WCHAR clsidKey[256];
    StringCchPrintfW(clsidKey, _countof(clsidKey),
        L"SOFTWARE\\Classes\\CLSID\\%s", SENTINEL_AMSI_PROVIDER_CLSID_STR);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, clsidKey);

    OutputDebugStringW(L"[SentinelCore] AMSI Provider unregistered.\n");
    return S_OK;
}

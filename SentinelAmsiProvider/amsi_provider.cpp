/**
 * @file amsi_provider.cpp
 * @brief SentinelAmsiProvider — IAntimalwareProvider implementation.
 *
 * Intercepts script content (PowerShell, VBA, etc.) via the Windows AMSI
 * framework. Each scan buffer is hashed and routed to the telemetry bus.
 *
 * Default behavior: AMSI_RESULT_NOT_DETECTED
 * Kill switch active: AMSI_RESULT_DETECTED (blocks execution)
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "amsi_provider.h"
#include "../SentinelCommon/sentinel_constants.h"
#include <wincrypt.h>
#include <sstream>
#include <fstream>
#include <mutex>

#pragma comment(lib, "crypt32.lib")

// ---------------------------------------------------------------------------
// Static members
// ---------------------------------------------------------------------------
std::atomic<bool> SentinelAmsiProvider::s_killSwitch(false);

// Simple file logger for the AMSI provider (DLL context, no shared logger)
static std::mutex g_amsiLogMutex;

static void AmsiLog(const char* fmt, ...) {
    // Write to telemetry file directly (DLL doesn't share agent's logger)
    std::lock_guard<std::mutex> lock(g_amsiLogMutex);

    CreateDirectoryW(SENTINEL_LOG_DIRECTORY, NULL);

    FILE* f = nullptr;
    _wfopen_s(&f, SENTINEL_TELEMETRY_FILE, L"a");
    if (!f) return;

    // Timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);

    char prefix[64];
    snprintf(prefix, sizeof(prefix), "[%04d-%02d-%02d %02d:%02d:%02d][AMSI] ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    fputs(prefix, f);

    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);

    fputc('\n', f);
    fclose(f);
}

/**
 * @brief Escape a UTF-8 string for safe embedding inside a JSON string value.
 * Replaces '\' with '\\' and '"' with '\"'. Output is always null-terminated.
 */
static void JsonEscapeString(const char* src, char* dst, size_t dstSize) {
    size_t wi = 0;
    for (const char* p = src; *p && wi + 2 < dstSize; ++p) {
        if (*p == '"' || *p == '\\') {
            dst[wi++] = '\\';
        }
        dst[wi++] = *p;
    }
    dst[wi] = '\0';
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
SentinelAmsiProvider::SentinelAmsiProvider()
    : m_refCount(1)
{
    AmsiLog("SentinelAmsiProvider constructed.");
}

SentinelAmsiProvider::~SentinelAmsiProvider() {
    AmsiLog("SentinelAmsiProvider destroyed.");
}

// ---------------------------------------------------------------------------
// IUnknown Implementation
// ---------------------------------------------------------------------------
IFACEMETHODIMP SentinelAmsiProvider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;

    *ppv = nullptr;

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, __uuidof(IAntimalwareProvider)))
    {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) SentinelAmsiProvider::AddRef() {
    return InterlockedIncrement(&m_refCount);
}

IFACEMETHODIMP_(ULONG) SentinelAmsiProvider::Release() {
    LONG count = InterlockedDecrement(&m_refCount);
    if (count == 0) {
        delete this;
    }
    return count;
}

// ---------------------------------------------------------------------------
// Scan — the core AMSI callback
// ---------------------------------------------------------------------------
IFACEMETHODIMP SentinelAmsiProvider::Scan(
    _In_ IAmsiStream* stream,
    _Out_ AMSI_RESULT* result)
{
    if (!stream || !result) return E_INVALIDARG;

    // Default: not detected
    *result = AMSI_RESULT_NOT_DETECTED;

    // Read stream attributes
    ULONG actualSize = 0;
    ULONGLONG contentSize = 0;
    HRESULT hrAttr;

    // Get content size
    hrAttr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE,
        sizeof(contentSize), (PUCHAR)&contentSize, &actualSize);
    if (FAILED(hrAttr)) {
        AmsiLog("Scan: GetAttribute(CONTENT_SIZE) failed (0x%08X)", hrAttr);
        contentSize = 0;
    }

    // Get content name (script filename or identifier)
    WCHAR nameBuffer[512] = {};
    hrAttr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_NAME,
        sizeof(nameBuffer), (PUCHAR)nameBuffer, &actualSize);
    if (FAILED(hrAttr)) {
        nameBuffer[0] = L'\0';
    }

    // Get app name
    WCHAR appBuffer[256] = {};
    hrAttr = stream->GetAttribute(AMSI_ATTRIBUTE_APP_NAME,
        sizeof(appBuffer), (PUCHAR)appBuffer, &actualSize);
    if (FAILED(hrAttr)) {
        appBuffer[0] = L'\0';
    }

    // Read the content buffer
    ULONG readSize = (ULONG)min(contentSize, 4096ULL);  // Cap at 4KB for Phase 1
    PUCHAR contentBuffer = nullptr;

    if (readSize > 0) {
        contentBuffer = (PUCHAR)malloc(readSize);
        if (contentBuffer) {
            hrAttr = stream->Read(0, readSize, contentBuffer, &actualSize);

            if (SUCCEEDED(hrAttr) && actualSize > 0) {
                // Compute a simple hash for telemetry
                DWORD hashValue = 0;
                for (ULONG i = 0; i < actualSize; i++) {
                    hashValue = (hashValue * 31) + contentBuffer[i];
                }

                // Convert to UTF-8 and JSON-escape before embedding
                char rawApp[256] = {};
                char rawName[512] = {};
                WideCharToMultiByte(CP_UTF8, 0, appBuffer, -1,
                    rawApp, sizeof(rawApp), NULL, NULL);
                WideCharToMultiByte(CP_UTF8, 0, nameBuffer, -1,
                    rawName, sizeof(rawName), NULL, NULL);

                char safeApp[512] = {};
                char safeName[1024] = {};
                JsonEscapeString(rawApp, safeApp, sizeof(safeApp));
                JsonEscapeString(rawName, safeName, sizeof(safeName));

                // Use UTC-based epoch timestamp (FILETIME units: 100ns since 1601)
                // Convert to milliseconds since Unix epoch for interoperability
                FILETIME ft;
                GetSystemTimeAsFileTime(&ft);
                ULONGLONG ftVal = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
                // FILETIME epoch: Jan 1 1601; Unix epoch: Jan 1 1970. Delta = 116444736000000000 * 100ns
                ULONGLONG unixMs = (ftVal - 116444736000000000ULL) / 10000ULL;

                // Log to telemetry file as JSON
                char jsonRecord[1024];
                snprintf(jsonRecord, sizeof(jsonRecord),
                    "{\"timestamp\":%llu,\"pid\":%lu,\"event_type\":\"amsi_scan\","
                    "\"api_name\":\"AMSI:Scan\",\"severity\":1,"
                    "\"parameters\":{\"app\":\"%s\",\"content_name\":\"%s\","
                    "\"content_size\":%llu,\"content_hash\":\"0x%08X\","
                    "\"kill_switch\":%s,\"result\":\"%s\"}}",
                    (unsigned long long)unixMs,
                    GetCurrentProcessId(),
                    safeApp, safeName,
                    (unsigned long long)contentSize, hashValue,
                    s_killSwitch.load() ? "true" : "false",
                    s_killSwitch.load() ? "DETECTED" : "NOT_DETECTED");

                AmsiLog("%s", jsonRecord);
            }

            free(contentBuffer);
        }
    }

    // Kill switch: if active, block everything
    if (s_killSwitch.load(std::memory_order_acquire)) {
        *result = AMSI_RESULT_DETECTED;
        AmsiLog("KILL SWITCH ACTIVE — returning AMSI_RESULT_DETECTED for '%S' from '%S'",
            nameBuffer, appBuffer);
    }

    return S_OK;
}

// ---------------------------------------------------------------------------
// CloseSession
// ---------------------------------------------------------------------------
IFACEMETHODIMP_(void) SentinelAmsiProvider::CloseSession(
    _In_ ULONGLONG session)
{
    UNREFERENCED_PARAMETER(session);
    AmsiLog("CloseSession called (session=0x%llX)", session);
}

// ---------------------------------------------------------------------------
// DisplayName
// ---------------------------------------------------------------------------
IFACEMETHODIMP SentinelAmsiProvider::DisplayName(
    _Out_ LPWSTR* displayName)
{
    if (!displayName) return E_POINTER;

    const WCHAR name[] = L"SentinelCore AMSI Provider";
    *displayName = (LPWSTR)CoTaskMemAlloc(sizeof(name));

    if (!*displayName) return E_OUTOFMEMORY;

    wcscpy_s(*displayName, _countof(name), name);
    return S_OK;
}

// ---------------------------------------------------------------------------
// Kill Switch Control
// ---------------------------------------------------------------------------
void SentinelAmsiProvider::SetKillSwitch(bool enabled) {
    s_killSwitch.store(enabled, std::memory_order_release);
    AmsiLog("Kill switch %s", enabled ? "ACTIVATED" : "DEACTIVATED");
}

bool SentinelAmsiProvider::IsKillSwitchActive() {
    return s_killSwitch.load(std::memory_order_acquire);
}

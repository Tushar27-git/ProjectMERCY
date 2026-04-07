/**
 * @file service_controller.cpp
 * @brief SentinelAgent — Windows Service lifecycle implementation.
 *
 * Handles SCM registration, STOP/SHUTDOWN control signals, and service
 * status reporting. The actual worker logic is delegated to ServiceWorkerThread().
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "service_controller.h"
#include "logger.h"
#include "../SentinelCommon/sentinel_constants.h"

namespace sentinel {

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
std::atomic<bool> g_serviceRunning(false);

static SERVICE_STATUS          g_serviceStatus = {};
static SERVICE_STATUS_HANDLE   g_statusHandle = NULL;
static HANDLE                  g_stopEvent = NULL;

// ---------------------------------------------------------------------------
// InitializeService — called from main()
// ---------------------------------------------------------------------------
bool InitializeService() {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(SENTINEL_SERVICE_NAME), ServiceMain },
        { NULL, NULL }
    };

    // StartServiceCtrlDispatcher blocks until the service stops
    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // Running as a console app (not from SCM) — useful for debugging
            LOG_WARN("ServiceController: Not started by SCM. Running in console mode.");
            g_serviceRunning = true;
            ServiceWorkerThread();
            return true;
        }
        LOG_ERROR("ServiceController: StartServiceCtrlDispatcher failed (err=%lu)", err);
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// ServiceMain — SCM entry point
// ---------------------------------------------------------------------------
VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    // Register the control handler
    g_statusHandle = RegisterServiceCtrlHandlerW(
        SENTINEL_SERVICE_NAME, ServiceCtrlHandler);

    if (!g_statusHandle) {
        LOG_FATAL("ServiceController: RegisterServiceCtrlHandler failed (err=%lu)",
            GetLastError());
        return;
    }

    // Initialize service status
    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_serviceStatus.dwControlsAccepted = 0;
    g_serviceStatus.dwWin32ExitCode = NO_ERROR;
    g_serviceStatus.dwServiceSpecificExitCode = 0;
    g_serviceStatus.dwCheckPoint = 0;
    g_serviceStatus.dwWaitHint = 10000; // 10 seconds to start

    ReportServiceStatus(SERVICE_START_PENDING);

    // Create stop event
    g_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_stopEvent) {
        ReportServiceStatus(SERVICE_STOPPED, GetLastError());
        return;
    }

    // Report running
    g_serviceRunning = true;
    ReportServiceStatus(SERVICE_RUNNING);

    LOG_INFO("ServiceController: Service is RUNNING.");

    // Run the main worker
    ServiceWorkerThread();

    // Cleanup
    CloseHandle(g_stopEvent);
    g_stopEvent = NULL;

    ReportServiceStatus(SERVICE_STOPPED);
    LOG_INFO("ServiceController: Service STOPPED.");
}

// ---------------------------------------------------------------------------
// ServiceCtrlHandler — handle SCM control signals
// ---------------------------------------------------------------------------
VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
    case SERVICE_CONTROL_STOP:
        LOG_INFO("ServiceController: Received STOP signal.");
        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        g_serviceRunning = false;
        if (g_stopEvent) {
            SetEvent(g_stopEvent);
        }
        break;

    case SERVICE_CONTROL_SHUTDOWN:
        LOG_INFO("ServiceController: Received SHUTDOWN signal.");
        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        g_serviceRunning = false;
        if (g_stopEvent) {
            SetEvent(g_stopEvent);
        }
        break;

    case SERVICE_CONTROL_INTERROGATE:
        // Report current status
        break;

    default:
        break;
    }

    // Always re-report current state for INTERROGATE
    ReportServiceStatus(g_serviceStatus.dwCurrentState);
}

// ---------------------------------------------------------------------------
// ReportServiceStatus
// ---------------------------------------------------------------------------
void ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint) {
    static DWORD checkPoint = 1;

    g_serviceStatus.dwCurrentState = currentState;
    g_serviceStatus.dwWin32ExitCode = exitCode;
    g_serviceStatus.dwWaitHint = waitHint;

    if (currentState == SERVICE_START_PENDING) {
        g_serviceStatus.dwControlsAccepted = 0;
    } else {
        g_serviceStatus.dwControlsAccepted =
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        g_serviceStatus.dwCheckPoint = 0;
    } else {
        g_serviceStatus.dwCheckPoint = checkPoint++;
    }

    if (g_statusHandle) {
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
    }
}

} // namespace sentinel

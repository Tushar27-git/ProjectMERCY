/**
 * @file service_controller.h
 * @brief SentinelAgent — Windows Service lifecycle management.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atomic>

namespace sentinel {

/**
 * @brief Global shutdown signal — all components check this flag.
 */
extern std::atomic<bool> g_serviceRunning;

/**
 * @brief Initialize and register the Windows Service with SCM.
 * @return true if the service started successfully.
 */
bool InitializeService();

/**
 * @brief The ServiceMain callback registered with SCM.
 */
VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv);

/**
 * @brief The service control handler callback.
 */
VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode);

/**
 * @brief Report service status to SCM.
 */
void ReportServiceStatus(DWORD currentState, DWORD exitCode = NO_ERROR, DWORD waitHint = 0);

/**
 * @brief The main service work loop — initializes all components.
 */
void ServiceWorkerThread();

} // namespace sentinel

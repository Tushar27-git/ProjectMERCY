# SentinelCore Phase 1.5 — Deep Telemetry via Kernel Callbacks

## Overview

Based on your requirement to get **deep telemetry from the start without PPL or Microsoft ETW-TI signatures**, we are pivoting the architecture. 

Instead of relying on User-Mode ETW (which requires PPL for the Threat-Intelligence feed), we will move the Process, Thread, Image Load, and Handle Creation telemetry directly into our **Kernel Minifilter Driver (`SentinelDriver.sys`)**. By registering native WDM kernel callbacks, our driver acts as a first-class citizen in the kernel, replicating the exact visibility of ETW-TI completely legitimately.

> [!IMPORTANT]
> The driver must be built with the `/INTEGRITYCHECK` linker flag, and test-signing must remain ON. Without `/INTEGRITYCHECK`, `PsSetCreateProcessNotifyRoutineEx` will return `STATUS_ACCESS_DENIED`.

## User Review Required

> [!WARNING]
> **BSOD Risk:** Kernel callbacks (especially `ObRegisterCallbacks`) run in the critical path of the Windows kernel. Any bugs, memory leaks, or slow code in these callbacks will cause immediate system-wide instability or bugchecks (BSODs). We will implement these with extreme care, using non-paged memory and rapid dispatch.
> 
> Please confirm you accept this risk for development.

## Proposed Changes

We will systematically expand the Kernel Driver and update the IPC structures to handle these new high-volume event types.

### 1. SentinelCommon (Shared Structures)

#### [MODIFY] [feature_vector.h](file:///e:/ProjectMercy/SentinelCommon/feature_vector.h)
- Expand the `IpcMessageType` (or a similar struct) to include `PROCESS_CREATE`, `THREAD_CREATE`, `IMAGE_LOAD`, and `HANDLE_CREATE`.
- Create targeted struct payloads for these events (e.g., `ProcessEvent`, `ImageLoadEvent`, `HandleEvent`) alongside `FeatureVector`.

### 2. SentinelDriver (Kernel Mode)

#### [NEW] [callbacks.h](file:///e:/ProjectMercy/SentinelDriver/callbacks.h) / [callbacks.cpp](file:///e:/ProjectMercy/SentinelDriver/callbacks.cpp)
- Implement `RegisterKernelCallbacks()` and `UnregisterKernelCallbacks()`.
- Implement `PsSetCreateProcessNotifyRoutineEx` to capture process creations and command lines.
- Implement `PsSetCreateThreadNotifyRoutine` to capture thread creations.
- Implement `PsSetLoadImageNotifyRoutine` to capture DLL/EXE loads.
- Implement `ObRegisterCallbacks` to intercept `OpenProcess` and `OpenThread` operations (this captures Mimikatz-style cross-process access).
- Route these events through `SendFeatureVectorToAgent` (which will be renamed/refactored to `SendTelemetryToAgent`).

#### [MODIFY] [minifilter.cpp](file:///e:/ProjectMercy/SentinelDriver/minifilter.cpp)
- Update `DriverEntry` to call `RegisterKernelCallbacks()` after the minifilter initializes.
- Update `FilterUnloadCallback` to call `UnregisterKernelCallbacks()` **before** closing the communication port (critical for preventing BSODs).

#### [MODIFY] [SentinelDriver.vcxproj](file:///e:/ProjectMercy/SentinelDriver/SentinelDriver.vcxproj)
- Add the `/INTEGRITYCHECK` linker flag required by `PsSetCreateProcessNotifyRoutineEx`.

### 3. SentinelAgent (User Mode)

#### [MODIFY] [etw_consumer.cpp](file:///e:/ProjectMercy/SentinelAgent/etw_consumer.cpp) / [etw_consumer.h](file:///e:/ProjectMercy/SentinelAgent/etw_consumer.h)
- **Deprecate/Remove** reliance on `Microsoft-Windows-Threat-Intelligence` and `Microsoft-Windows-Kernel-Process`. 
- We can completely remove `EtwConsumer` from the active pipeline, as the Kernel Driver now provides a strictly superior, tamper-resistant feed of the exact same data.

#### [MODIFY] [minifilter_client.cpp](file:///e:/ProjectMercy/SentinelAgent/minifilter_client.cpp)
- Update the `ReceiveThreadFunc` to parse the new `PROCESS_CREATE`, `IMAGE_LOAD`, and `HANDLE_CREATE` IPC message types coming from `SentinelDriver`.
- Format these into `TelemetryRecord` objects and push them to the ring buffer.

## Verification Plan

### Automated Build
- Verifying the `/INTEGRITYCHECK` linker flag is correctly applied to the `.sys` file.

### Manual Verification
- **Load the Driver**: Ensure `fltmc load SentinelDriver` succeeds without `STATUS_ACCESS_DENIED`.
- **Telemetry Check**: Launch a new process (e.g., `notepad.exe`) and verify that a `PROCESS_CREATE` event payload appears in `C:\ProgramData\SentinelCore\telemetry.jsonl` immediately.
- **Cross-Process Read (ObRegisterCallbacks)**: Open Task Manager (which calls `OpenProcess` on everything). Verify `HANDLE_CREATE` events are logged into the telemetry feed.

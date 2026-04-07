"""
config.py — Global configuration and IPC protocol for the SentinelCore ML Engine.
Copyright (c) 2026 SentinelCore Project. All rights reserved.
"""

import enum

# ---------------------------------------------------------------------------
# Named Pipe Configuration
# ---------------------------------------------------------------------------
PIPE_NAME = r'\\.\pipe\SentinelCorePipe'
BUFFER_SIZE = 65536  # 64KB for large feature vectors
MAX_CONNECTIONS = 20

# ---------------------------------------------------------------------------
# IPC Message Types (Must match SentinelCommon/ipc_protocol.h)
# ---------------------------------------------------------------------------
class MessageType(enum.IntEnum):
    FILE_EVENT = 101       # Full feature vector scan
    AMSI_SCAN = 102        # PowerShell/script scan
    ETW_EVENT = 103        # Process/registry activity
    API_HOOK_EVENT = 104   # Inline hook data
    MEMORY_ALERT = 105     # RWX region scan
    PROCESS_CREATE = 106   # Native callback
    THREAD_CREATE = 107    # Native callback
    IMAGE_LOAD = 108       # Native callback
    HANDLE_CREATE = 109    # Native callback
    HEARTBEAT = 110        # Keepalive

# ---------------------------------------------------------------------------
# Verdicts (Must match SentinelAgent/ml_pipeline_interface.h)
# ---------------------------------------------------------------------------
class Verdict(enum.IntEnum):
    ALLOW = 0
    BLOCK = 1
    MONITOR = 2
    ERROR = 3

# ---------------------------------------------------------------------------
# Detection Thresholds
# ---------------------------------------------------------------------------
STATIC_BLOCK_THRESHOLD = 0.95
STATIC_MONITOR_THRESHOLD = 0.50
BEHAVIORAL_KILL_THRESHOLD = 0.80
ENTROPY_SUSPICIOUS_THRESHOLD = 7.2

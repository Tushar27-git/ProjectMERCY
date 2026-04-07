"""
analyst.py — LSTM Behavioral Analyst inference wrapper.
Track sequences of telemetry events per-process to detect anomalies.
Copyright (c) 2026 SentinelCore Project. All rights reserved.
"""

import sys
import os
import json
import time
from collections import defaultdict, deque

# Add parent to path for config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

class BehavioralAnalyst:
    def __init__(self, model_path=None, window_size=256):
        self.model_path = model_path
        self.window_size = window_size
        self.process_state = defaultdict(lambda: deque(maxlen=window_size))
        # In Phase 3, this would load lstm_analyst.pt
        self.model_loaded = False if not model_path else True

    def process_event(self, record):
        """Processes a single telemetry record and returns a score."""
        pid = record.get("pid", 0)
        event_type = record.get("event_type", "unknown")
        api_name = record.get("api_name", "")
        
        # Add to sliding window
        event_data = {
            "type": event_type,
            "api": api_name,
            "ts": time.time()
        }
        self.process_state[pid].append(event_data)

        # Analyze current window (Mock LSTM Logic)
        score = self.analyze_window(pid)
        
        verdict = self.get_verdict(score)
        if verdict != config.Verdict.ALLOW:
            print(f"[LSTM] PID={pid} Sequence Alert: Score={score:.2f} -> {verdict.name}")
            
        return score

    def analyze_window(self, pid):
        """Mock LSTM sequence analysis for Phase 2."""
        window = list(self.process_state[pid])
        if len(window) < 2:
            return 0.1
            
        # Hardcoded High-Signal Sequences (Kill-Chain logic)
        # 1. PE Write -> Process Creation (classic dropper)
        # 2. WriteProcessMemory -> CreateRemoteThread (injection)
        # 3. RWX allocation -> High entropy write (shellcode)
        
        total_score = 0.1
        seq_apis = [ev["api"] for ev in window]
        
        # Detection: Thread Injection (Remote)
        if "WriteProcessMemory" in seq_apis and "CreateRemoteThread" in seq_apis:
             total_score += 0.8
             
        # Detection: Shellcode Staging
        if "NtAllocateVirtualMemory" in seq_apis and "NtWriteVirtualMemory" in seq_apis:
             # If we see RWX flag elsewhere, boost score
             total_score += 0.4

        return min(total_score, 1.0)

    def get_verdict(self, score):
        """Converts score to a Verdict enum."""
        if score >= config.BEHAVIORAL_KILL_THRESHOLD:
            return config.Verdict.BLOCK
        if score >= 0.4:
            return config.Verdict.MONITOR
        return config.Verdict.ALLOW

if __name__ == "__main__":
    analyst = BehavioralAnalyst()
    # Mock sequence: Staging shellcode
    analyst.process_event({"pid": 1234, "api_name": "NtAllocateVirtualMemory", "event_type": "api_hook"})
    print(f"Score after 1st event: {analyst.analyze_window(1234)}")
    analyst.process_event({"pid": 1234, "api_name": "NtWriteVirtualMemory", "event_type": "api_hook"})
    print(f"Score after 2nd event: {analyst.analyze_window(1234)}")

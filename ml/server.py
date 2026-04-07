"""
server.py — Multi-threaded Named Pipe Server for SentinelCore ML Engine.
Copyright (c) 2026 SentinelCore Project. All rights reserved.
"""

import os
import sys
import json
import threading
import win32pipe
import win32file
import win32api
import winerror
import time

# Add parent directory to path to allow absolute imports if needed
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import config

class SentinelMLServer:
    def __init__(self):
        self.running = False
        self.clients = []
        self.lock = threading.Lock()
        self.total_scans = 0

    def start(self):
        """Starts the main pipe listener loop."""
        self.running = True
        print(f"[*] SentinelCore ML Server starting on {config.PIPE_NAME}")
        print(f"[*] Press Ctrl+C to shutdown.")

        try:
            while self.running:
                # Create a new instance of the named pipe
                # PIPE_ACCESS_DUPLEX: Two-way communication
                # PIPE_TYPE_MESSAGE: Message-based (not byte stream)
                # PIPE_READMODE_MESSAGE: Read as messages
                # PIPE_WAIT: Blocking mode
                h_pipe = win32pipe.CreateNamedPipe(
                    config.PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    config.MAX_CONNECTIONS,
                    config.BUFFER_SIZE,
                    config.BUFFER_SIZE,
                    0,
                    None
                )

                if h_pipe == win32file.INVALID_HANDLE_VALUE:
                    print(f"[!] Failed to create pipe: {win32api.GetLastError()}")
                    time.sleep(1)
                    continue

                # Wait for a client to connect
                # This blocks until a client (C++ Agent) calls CreateFile()
                res = win32pipe.ConnectNamedPipe(h_pipe, None)
                if res == 0:  # Success
                    t = threading.Thread(target=self.handle_client, args=(h_pipe,))
                    t.daemon = True
                    t.start()
                    with self.lock:
                        self.clients.append(t)
                else:
                    # Client might have connected before we called ConnectNamedPipe
                    if res == winerror.ERROR_PIPE_CONNECTED:
                         t = threading.Thread(target=self.handle_client, args=(h_pipe,))
                         t.daemon = True
                         t.start()
                         with self.lock:  # Fix #13: was missing this append
                             self.clients.append(t)
                    else:
                        win32file.CloseHandle(h_pipe)

        except KeyboardInterrupt:
            self.shutdown()

    def handle_client(self, h_pipe):
        """Worker thread for a single connected C++ agent."""
        print(f"[*] Agent connected (CID={id(h_pipe)})")
        
        try:
            while self.running:
                # Read message from pipe
                # win32file.ReadFile returns (hr, data)
                hr, data = win32file.ReadFile(h_pipe, config.BUFFER_SIZE)
                
                if hr != 0:
                    if hr == winerror.ERROR_BROKEN_PIPE:
                        print(f"[*] Agent disconnected (CID={id(h_pipe)})")
                    else:
                        print(f"[!] ReadFile error: {hr}")
                    break

                if not data:
                    continue

                # Process the message
                try:
                    message_str = data.decode('utf-8').rstrip('\0')
                    message_json = json.loads(message_str)
                    
                    response_json = self.process_message(message_json)
                    
                    # Send response back
                    response_str = json.dumps(response_json) + '\0'
                    win32file.WriteFile(h_pipe, response_str.encode('utf-8'))
                    
                except Exception as e:
                    print(f"[!] Error processing message: {e}")
                    # Send error verdict
                    error_resp = {"verdict": int(config.Verdict.ERROR), "reason": str(e)}
                    win32file.WriteFile(h_pipe, json.dumps(error_resp).encode('utf-8'))

        finally:
            win32file.CloseHandle(h_pipe)

    def process_message(self, msg):
        """Routes messages to appropriate models and returns a verdict."""
        msg_type = msg.get("event_type", "unknown")
        pid = msg.get("pid", 0)
        
        # Phase 2: Stubs for models
        # In Phase 3, we'll replace these with actual XGBoost/LSTM calls
        verdict = config.Verdict.ALLOW
        reason = "Phase 2: Default ALLOW"

        if msg_type == "file_io":
            with self.lock:  # Fix #14/#15: protect total_scans from concurrent threads
                self.total_scans += 1
            # Simple heuristic for Phase 2 testing:
            # If entropy is very high, return MONITOR
            entropy = msg.get("parameters", {}).get("entropy", 0.0)
            if entropy > config.ENTROPY_SUSPICIOUS_THRESHOLD:
                verdict = config.Verdict.MONITOR
                reason = f"High entropy: {entropy}"
            
            print(f"[SCAN] PID={pid} {msg.get('process_name')} -> {verdict.name} ({reason})")

        return {
            "verdict": int(verdict),
            "reason": reason,
            "timestamp": int(time.time() * 1000)
        }

    def shutdown(self):
        print("\n[*] SentinelCore ML Server shutting down...")
        self.running = False
        # In a production environment, we'd wait for threads to join
        sys.exit(0)

if __name__ == "__main__":
    server = SentinelMLServer()
    server.start()

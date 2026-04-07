/**
 * @file minifilter_client.cpp
 * @brief SentinelAgent — Userland minifilter communication port consumer.
 *
 * Connects to the kernel driver via FilterConnectCommunicationPort,
 * receives FeatureVectors, and dispatches processing to Thread Pool 1.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#include "minifilter_client.h"
#include "thread_pool.h"
#include "ml_pipeline_interface.h"
#include "logger.h"
#include "../SentinelCommon/sentinel_constants.h"
#include "../SentinelCommon/ipc_protocol.h"

#pragma comment(lib, "fltlib.lib")

namespace sentinel {

// ---------------------------------------------------------------------------
// JSON string escaper — handles content that may come from attacker-controlled
// sources (command lines, file paths). Escapes '\' and '"' in UTF-16 strings
// converted to narrow before embedding in a JSON literal.
// ---------------------------------------------------------------------------
static void JsonEscapeNarrow(const char* src, char* dst, size_t dstSize) {
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
// Message buffer structure for FilterGetMessage
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct SENTINEL_MESSAGE {
    FILTER_MESSAGE_HEADER   header;
    IpcMessageHeader        ipcHeader;
    uint8_t                 payload[MAX_IPC_PAYLOAD_SIZE];
};
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Reply buffer structure for FilterReplyMessage
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct SENTINEL_REPLY {
    FILTER_REPLY_HEADER     header;
    UserToKernelReply       reply;
};
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
MinifilterClient::MinifilterClient()
    : m_hPort(INVALID_HANDLE_VALUE)
    , m_connected(false)
    , m_receiving(false)
    , m_messagesReceived(0)
    , m_receiveThread(NULL)
{}

MinifilterClient::~MinifilterClient() {
    StopReceiveLoop();
    Disconnect();
}

// ---------------------------------------------------------------------------
// Connect
// ---------------------------------------------------------------------------
bool MinifilterClient::Connect() {
    if (m_connected) return true;

    HRESULT hr = FilterConnectCommunicationPort(
        SENTINEL_PORT_NAME,
        0,          // Options
        NULL,       // Context
        0,          // Context size
        NULL,       // Security attributes
        &m_hPort);

    if (FAILED(hr)) {
        LOG_ERROR("MinifilterClient: FilterConnectCommunicationPort failed (hr=0x%08X)", hr);
        m_hPort = INVALID_HANDLE_VALUE;
        return false;
    }

    m_connected = true;
    LOG_INFO("MinifilterClient: Connected to kernel driver port '%S'", SENTINEL_PORT_NAME);
    return true;
}

// ---------------------------------------------------------------------------
// Disconnect
// ---------------------------------------------------------------------------
void MinifilterClient::Disconnect() {
    if (m_hPort != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPort);
        m_hPort = INVALID_HANDLE_VALUE;
    }
    m_connected = false;
    LOG_INFO("MinifilterClient: Disconnected from kernel driver.");
}

// ---------------------------------------------------------------------------
// StartReceiveLoop
// ---------------------------------------------------------------------------

// Thread parameter block for passing context to the receive thread
struct ReceiveThreadParams {
    MinifilterClient* self;
    ThreadPool* pool;
    SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf;
    MLPipelineInterface* pipeline;
};

static DWORD WINAPI ReceiveThreadProc(LPVOID param) {
    auto* params = static_cast<ReceiveThreadParams*>(param);
    if (params && params->self) {
        params->self->ReceiveThreadFunc(params->pool, params->ringBuf, params->pipeline);
    }
    delete params;
    return 0;
}

void MinifilterClient::StartReceiveLoop(
    ThreadPool* pool,
    SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf,
    MLPipelineInterface* pipeline)
{
    if (m_receiving) return;
    if (!m_connected) {
        LOG_ERROR("MinifilterClient: Cannot start receive loop — not connected.");
        return;
    }

    m_receiving = true;

    // Allocate parameter block (freed by the thread proc)
    auto* params = new ReceiveThreadParams{ this, pool, ringBuf, pipeline };

    m_receiveThread = CreateThread(
        NULL, 0,
        ReceiveThreadProc,
        params,
        0,       // Start immediately (not suspended)
        NULL);

    if (m_receiveThread == NULL) {
        LOG_ERROR("MinifilterClient: Failed to create receive thread (err=%lu)", GetLastError());
        delete params;
        m_receiving = false;
        return;
    }

    LOG_INFO("MinifilterClient: Receive loop started.");
}

// ---------------------------------------------------------------------------
// StopReceiveLoop
// ---------------------------------------------------------------------------
void MinifilterClient::StopReceiveLoop() {
    m_receiving = false;

    // Cancel any pending I/O
    if (m_hPort != INVALID_HANDLE_VALUE) {
        CancelIoEx(m_hPort, NULL);
    }

    if (m_receiveThread) {
        WaitForSingleObject(m_receiveThread, 5000);
        CloseHandle(m_receiveThread);
        m_receiveThread = NULL;
    }

    LOG_INFO("MinifilterClient: Receive loop stopped. Messages received: %llu",
        m_messagesReceived.load());
}

// ---------------------------------------------------------------------------
// ReceiveThreadFunc — the main message pump
// ---------------------------------------------------------------------------
void MinifilterClient::ReceiveThreadFunc(
    ThreadPool* pool,
    SPSCRingBuffer<TelemetryRecord, 4096>* ringBuf,
    MLPipelineInterface* pipeline)
{
    LOG_INFO("MinifilterClient: Receive thread started (TID=%lu)", GetCurrentThreadId());

    SENTINEL_MESSAGE message = {};
    DWORD bytesReturned = 0;

    while (m_receiving && m_connected) {
        // Wait for a message from the kernel driver
        HRESULT hr = FilterGetMessage(
            m_hPort,
            &message.header,
            sizeof(SENTINEL_MESSAGE),
            NULL);  // Synchronous (NULL overlapped)

        if (FAILED(hr)) {
            if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
                LOG_INFO("MinifilterClient: Receive cancelled (shutting down).");
                break;
            }
            LOG_ERROR("MinifilterClient: FilterGetMessage failed (hr=0x%08X)", hr);
            Sleep(100);  // Brief backoff on error
            continue;
        }

        m_messagesReceived++;

        // Validate IPC header
        if (message.ipcHeader.magic != IPC_MAGIC) {
            LOG_WARN("MinifilterClient: Invalid message magic (0x%08X)",
                message.ipcHeader.magic);
            continue;
        }

        // Dispatch to thread pool based on message type
        switch (message.ipcHeader.msg_type) {
            case IpcMessageType::FILE_EVENT: {
                if (message.ipcHeader.payload_size >= sizeof(FeatureVector)) {
                    FeatureVector fv;
                    memcpy(&fv, message.payload, sizeof(FeatureVector));

                    pool->Submit([this, fv, ringBuf, pipeline]() {
                        MLVerdict verdict = pipeline->GetVerdict(fv);
                        TelemetryRecord record;
                        record.timestamp = TelemetryRecord::Now();
                        record.pid = fv.source_pid;
                        record.ppid = 0;
                        record.SetProcessName(fv.file_path);
                        record.SetApiName("IRP_MJ_WRITE");
                        record.event_type = EventType::FileIOEvent;
                        record.severity = (fv.max_entropy > 7.2f) ? 3 : 0;
                        memcpy(record.data_hash, fv.sha256_hash, 32);

                        char params[512];
                        snprintf(params, sizeof(params),
                            "{\"sections\":%u,\"entropy\":%.2f,\"rwx\":%s,\"verdict\":\"%s\"}",
                            fv.section_count, (double)fv.max_entropy,
                            fv.has_rwx_section ? "true" : "false",
                            verdict == MLVerdict::ALLOW ? "ALLOW" : "BLOCK");
                        record.SetParameters(params);

                        if (!ringBuf->try_push(record)) {
                            LOG_WARN("MinifilterClient: Ring buffer full — dropping FILE_EVENT.");
                        }
                    });
                }
                break;
            }
            case IpcMessageType::PROCESS_CREATE: {
                if (message.ipcHeader.payload_size >= sizeof(ProcessEvent)) {
                    ProcessEvent ev;
                    memcpy(&ev, message.payload, sizeof(ProcessEvent));
                    
                    pool->Submit([this, ev, ringBuf]() {
                        TelemetryRecord record;
                        record.timestamp = ev.timestamp;
                        record.pid = ev.pid;
                        record.ppid = ev.ppid;
                        record.SetProcessName(ev.image_path);
                        record.SetApiName(ev.is_creation ? "ProcessCreate" : "ProcessExit");
                        record.event_type = EventType::ProcessCreation;

                        // Escape command_line — attacker-controlled (#4: JSON injection fix)
                        char rawCmdLine[1024] = {};
                        WideCharToMultiByte(CP_UTF8, 0, ev.command_line, -1,
                            rawCmdLine, sizeof(rawCmdLine), NULL, NULL);
                        char safeCmdLine[2048] = {};
                        JsonEscapeNarrow(rawCmdLine, safeCmdLine, sizeof(safeCmdLine));

                        char params[2176];
                        snprintf(params, sizeof(params), "{\"cmdline\":\"%s\",\"creating_pid\":%u}",
                            safeCmdLine, ev.creating_pid);
                        record.SetParameters(params);

                        if (!ringBuf->try_push(record)) LOG_WARN("Ring buffer full.");
                    });
                }
                break;
            }
            case IpcMessageType::THREAD_CREATE: {
                if (message.ipcHeader.payload_size >= sizeof(ThreadEvent)) {
                    ThreadEvent ev;
                    memcpy(&ev, message.payload, sizeof(ThreadEvent));
                    
                    pool->Submit([this, ev, ringBuf]() {
                        TelemetryRecord record;
                        record.timestamp = ev.timestamp;
                        record.pid = ev.pid;
                        record.SetApiName(ev.is_creation ? "ThreadCreate" : "ThreadExit");
                        record.event_type = EventType::ThreadCreation;
                        
                        char params[256];
                        snprintf(params, sizeof(params), "{\"tid\":%u,\"creating_pid\":%u}", 
                            ev.tid, ev.creating_pid);
                        record.SetParameters(params);

                        if (!ringBuf->try_push(record)) LOG_WARN("Ring buffer full.");
                    });
                }
                break;
            }
            case IpcMessageType::IMAGE_LOAD: {
                if (message.ipcHeader.payload_size >= sizeof(ImageLoadEvent)) {
                    ImageLoadEvent ev;
                    memcpy(&ev, message.payload, sizeof(ImageLoadEvent));
                    
                    pool->Submit([this, ev, ringBuf]() {
                        TelemetryRecord record;
                        record.timestamp = ev.timestamp;
                        record.pid = ev.pid;
                        record.SetProcessName(ev.image_path);
                        record.SetApiName("ImageLoad");
                        record.event_type = EventType::ModuleLoad;
                        
                        char params[256];
                        snprintf(params, sizeof(params), "{\"base\":\"0x%llX\",\"size\":%llu,\"system\":%s}", 
                            ev.image_base, ev.image_size, ev.is_system_module ? "true" : "false");
                        record.SetParameters(params);

                        if (!ringBuf->try_push(record)) LOG_WARN("Ring buffer full.");
                    });
                }
                break;
            }
            case IpcMessageType::HANDLE_CREATE: {
                if (message.ipcHeader.payload_size >= sizeof(HandleEvent)) {
                    HandleEvent ev;
                    memcpy(&ev, message.payload, sizeof(HandleEvent));
                    
                    pool->Submit([this, ev, ringBuf]() {
                        TelemetryRecord record;
                        record.timestamp = ev.timestamp;
                        record.pid = ev.source_pid;
                        record.SetApiName(ev.is_thread_handle ? "OpenThread" : "OpenProcess");
                        record.event_type = EventType::HandleAccess;
                        
                        char params[256];
                        snprintf(params, sizeof(params), "{\"target_pid\":%u,\"access\":\"0x%X\",\"is_create\":%s}", 
                            ev.target_pid, ev.desired_access, ev.is_creation ? "true" : "false");
                        record.SetParameters(params);

                        if (!ringBuf->try_push(record)) LOG_WARN("Ring buffer full.");
                    });
                }
                break;
            }
            default:
                break;
        }

        // Send reply to kernel driver
        SENTINEL_REPLY reply = {};
        reply.header.Status = 0;
        reply.header.MessageId = message.header.MessageId;
        reply.reply.verdict = static_cast<uint32_t>(MLVerdict::ALLOW);
        reply.reply.flags = 0;

        hr = FilterReplyMessage(
            m_hPort,
            &reply.header,
            sizeof(SENTINEL_REPLY));

        if (FAILED(hr)) {
            LOG_WARN("MinifilterClient: FilterReplyMessage failed (hr=0x%08X)", hr);
        }
    }

    LOG_INFO("MinifilterClient: Receive thread exiting.");
}

} // namespace sentinel

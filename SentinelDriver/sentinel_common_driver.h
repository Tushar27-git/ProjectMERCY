/**
 * @file sentinel_common_driver.h
 * @brief SentinelDriver — Driver-local shared definitions and helpers.
 *
 * Copyright (c) 2026 SentinelCore Project. All rights reserved.
 */

#pragma once
#include "feature_vector.h"
#include "sentinel_ipc_protocol.h"
#include "sentinel_constants.h"

// ---------------------------------------------------------------------------
// Linter Compatibility / Dummy Definitions
// ---------------------------------------------------------------------------
// Force use of stubs for the IDE environment to avoid pathing issues.

// 1. Primitive Type Definitions
#ifndef NULL
#define NULL 0
#endif

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef _NTSTATUS_
typedef long NTSTATUS;
#define _NTSTATUS_
#endif

typedef unsigned long ULONG;
typedef unsigned long *PULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
typedef unsigned char* PUCHAR;
typedef void VOID, *PVOID;
typedef int BOOLEAN;
typedef long LONG;
typedef long long LONG64;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef unsigned long long UINT64;
typedef unsigned int UINT32;
typedef unsigned long long ULONG_PTR;
typedef float FLOAT;
typedef unsigned long long SIZE_T;
typedef wchar_t WCHAR;
typedef void* HANDLE;
typedef void* PSECURITY_DESCRIPTOR;
typedef ULONG FLT_FILTER_UNLOAD_FLAGS;
typedef ULONG FLT_FILE_NAME_OPTIONS;
typedef ULONG KIRQL;
typedef ULONG KSPIN_LOCK;
typedef ULONG ACCESS_MASK;
typedef UCHAR KPROCESSOR_MODE;
typedef ULONG_PTR KAFFINITY;

// 2. Structural Definitions
typedef union _LARGE_INTEGER { 
    struct { ULONG LowPart; LONG HighPart; } u; 
    LONGLONG QuadPart; 
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _UNICODE_STRING { 
    unsigned short Length; 
    unsigned short MaximumLength; 
    wchar_t* Buffer; 
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LIST_ENTRY { 
    struct _LIST_ENTRY *Flink; 
    struct _LIST_ENTRY *Blink; 
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _KEVENT { int Dummy; } KEVENT;

typedef struct _OBJECT_ATTRIBUTES { 
    ULONG Length; 
    HANDLE RootDirectory; 
    PUNICODE_STRING ObjectName; 
    ULONG Attributes; 
    PVOID SecurityDescriptor; 
    PVOID SecurityQualityOfService; 
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _DRIVER_OBJECT { 
    PVOID DeviceObject; 
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef struct _FILE_OBJECT { 
    PVOID DeviceObject; 
    UNICODE_STRING FileName; 
} FILE_OBJECT, *PFILE_OBJECT;

typedef struct _FLT_FILE_NAME_INFORMATION { 
    UNICODE_STRING Name; 
} FLT_FILE_NAME_INFORMATION, *PFLT_FILE_NAME_INFORMATION;

typedef struct _FLT_IO_PARAMETER_BLOCK { 
    UCHAR MajorFunction;
    PFILE_OBJECT TargetFileObject; 
    union {
        struct {
            PVOID MdlAddress;
            PVOID Buffer;
            ULONG Length;
            PVOID WriteBuffer;
        } Write;
    } Parameters;
} FLT_IO_PARAMETER_BLOCK, *PFLT_IO_PARAMETER_BLOCK;

typedef struct _FLT_CALLBACK_DATA { 
    PFLT_IO_PARAMETER_BLOCK Iopb; 
    struct { NTSTATUS Status; ULONG_PTR Information; } IoStatus;
    KPROCESSOR_MODE RequestorMode;
} FLT_CALLBACK_DATA, *PFLT_CALLBACK_DATA;

typedef struct _FLT_RELATED_OBJECTS { 
    PVOID Filter; 
    PVOID Volume; 
    PVOID Instance; 
    PFILE_OBJECT FileObject; 
} FLT_RELATED_OBJECTS, *PCFLT_RELATED_OBJECTS;

typedef struct _PS_CREATE_NOTIFY_INFO {
    SIZE_T Size;
    union {
        ULONG Flags;
        struct {
            ULONG FileOpenNameQuery : 1;
            ULONG IsSubsystemProcess : 1;
            ULONG Reserved : 30;
        };
    };
    HANDLE ParentProcessId;
    PVOID CreatingThreadId;
    PFILE_OBJECT FileObject;
    PUNICODE_STRING ImageFileName;
    PUNICODE_STRING CommandLine;
    NTSTATUS CreationStatus;
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;

typedef struct _IMAGE_INFO {
    union {
        ULONG Properties;
        struct {
            ULONG ImageAddressingMode : 8;
            ULONG SystemModeImage : 1;
            ULONG ImageMappedToAllPids : 1;
            ULONG ExtendedInfoPresent : 1;
            ULONG Reserved : 21;
        };
    };
    PVOID ImageBase;
    ULONG ImageSelector;
    SIZE_T ImageSize;
    ULONG ImageSectionNumber;
} IMAGE_INFO, *PIMAGE_INFO;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef void* PFLT_FILTER;
typedef void* PFLT_PORT;
typedef void* PEPROCESS;
typedef void* PETHREAD;
typedef void* BCRYPT_ALG_HANDLE;
typedef void* BCRYPT_HASH_HANDLE;
typedef void* POBJECT_TYPE;

extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* PsThreadType;

typedef struct _OB_PRE_CREATE_HANDLE_INFORMATION {
    ACCESS_MASK DesiredAccess;
    ACCESS_MASK OriginalDesiredAccess;
} OB_PRE_CREATE_HANDLE_INFORMATION, *POB_PRE_CREATE_HANDLE_INFORMATION;

typedef union _OB_PRE_OPERATION_PARAMETERS {
    OB_PRE_CREATE_HANDLE_INFORMATION CreateHandleInformation;
} OB_PRE_OPERATION_PARAMETERS, *POB_PRE_OPERATION_PARAMETERS;

typedef struct _OB_PRE_OPERATION_INFORMATION {
    ULONG Operation;
    union {
        ULONG Flags;
        struct {
            ULONG KernelHandle : 1;
            ULONG Reserved : 31;
        };
    };
    PVOID Object;
    POBJECT_TYPE ObjectType;
    PVOID CallContext;
    POB_PRE_OPERATION_PARAMETERS Parameters;
} OB_PRE_OPERATION_INFORMATION, *POB_PRE_OPERATION_INFORMATION;

typedef struct _OB_OPERATION_REGISTRATION {
    POBJECT_TYPE* ObjectType;
    ULONG Operations;
    PVOID PreOperation;
    PVOID PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;

typedef struct _OB_CALLBACK_REGISTRATION {
    USHORT Version;
    USHORT OperationRegistrationCount;
    UNICODE_STRING Altitude;
    PVOID RegistrationContext;
    POB_OPERATION_REGISTRATION OperationRegistration;
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;

typedef struct _FLT_OPERATION_REGISTRATION { 
    int MajorFunction; 
    int Flags; 
    void* PreOp; 
    void* PostOp; 
} FLT_OPERATION_REGISTRATION;

typedef struct _FLT_REGISTRATION { 
    ULONG Size; 
    ULONG Version; 
    ULONG Flags; 
    void* Context; 
    const void* Operations; 
    void* Unload; 
    void* Setup; 
    void* Teardown; 
    void* TeardownStart; 
    void* TeardownComplete; 
    void* GenerateFileName; 
    void* NormalizeNameComponent; 
    void* NormalizeContextCleanup; 
    void* NormalizeContextCleanup2;
} FLT_REGISTRATION;

// PE Structures
typedef struct _IMAGE_DOS_HEADER { unsigned short e_magic; long e_lfanew; } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER { unsigned short Machine; unsigned short NumberOfSections; unsigned long TimeDateStamp; unsigned short SizeOfOptionalHeader; unsigned short Characteristics; } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY { unsigned long VirtualAddress; unsigned long Size; } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_NT_HEADERS64 { unsigned long Signature; IMAGE_FILE_HEADER FileHeader; unsigned char OptionalHeader[128]; } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
typedef struct _IMAGE_SECTION_HEADER { unsigned char Name[8]; union { unsigned long VirtualSize; } Misc; unsigned long VirtualAddress; unsigned long SizeOfRawData; unsigned long PointerToRawData; unsigned long Characteristics; } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

// Enums / Status
typedef enum _FLT_PREOP_CALLBACK_STATUS { FLT_PREOP_SUCCESS_NO_CALLBACK, FLT_PREOP_SUCCESS_WITH_CALLBACK, FLT_PREOP_PENDING, FLT_PREOP_SYNCHRONOUS_PAGING_IO } FLT_PREOP_CALLBACK_STATUS;
typedef enum _OB_PREOP_CALLBACK_STATUS { OB_PREOP_SUCCESS } OB_PREOP_CALLBACK_STATUS;
typedef enum _EVENT_TYPE { NotificationEvent, SynchronizationEvent } EVENT_TYPE;
typedef enum _KEY_VALUE_INFORMATION_CLASS { KeyValuePartialInformation } KEY_VALUE_INFORMATION_CLASS;

// Macros
#ifndef _In_
#define _In_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _Out_opt_
#define _Out_opt_
#endif
#ifndef _In_reads_bytes_
#define _In_reads_bytes_(s)
#endif
#ifndef _Out_writes_bytes_
#define _Out_writes_bytes_(s)
#endif
#ifndef _Outptr_result_maybenull_
#define _Outptr_result_maybenull_
#endif
#define NTAPI
#define FLTAPI
#define SHA256_DIGEST_LENGTH             32
#define BCRYPT_SHA256_ALGORITHM          L"SHA256"
#define BCRYPT_OBJECT_LENGTH             L"ObjectLength"
#define BCRYPT_HASH_REUSABLE_FLAG        0x00000020
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_PORT_DISCONNECTED        ((NTSTATUS)0xC0000037L)
#define STATUS_CONNECTION_COUNT_LIMIT   ((NTSTATUS)0xC0000441L)
#define STATUS_INVALID_IMAGE_FORMAT     ((NTSTATUS)0xC000007BL)
#define STATUS_UNHANDLED_EXCEPTION      ((NTSTATUS)0xC0000144L)
#define STATUS_INVALID_IMAGE_HASH       ((NTSTATUS)0xC0000428L)
#define STATUS_TIMEOUT                  ((NTSTATUS)0x00000102L)
#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)
#define UNREFERENCED_PARAMETER(P)        (P)
#ifndef TRUE
    #define TRUE 1
    #define FALSE 0
#endif
#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_OPERATION_END            0xFF
#define FLT_REGISTRATION_VERSION        0x0203
#define OB_OPERATION_HANDLE_CREATE      0x00000001
#define OB_OPERATION_HANDLE_DUPLICATE   0x00000002
#define OB_FLT_REGISTRATION_VERSION     0x0100
#define DPFLTR_IHVDRIVER_ID             1
#define DPFLTR_INFO_LEVEL               3
#define IO_NO_INCREMENT                 0
#define Executive                       0
#define KernelMode                      0
#define OBJ_KERNEL_HANDLE               0x00000200L
#define OBJ_CASE_INSENSITIVE            0x00000040L
#define THREAD_ALL_ACCESS               0x001FFFFFL
#define FLT_PORT_ALL_ACCESS             0x001F0001L
#define POOL_FLAG_NON_PAGED             0x0000000000000040UI64
#define KEY_READ                        0x20019L
#define KEY_WRITE                       0x20006L
#define REG_OPTION_NON_VOLATILE         0x00000000L
#define REG_DWORD                       4
#define IMAGE_DOS_SIGNATURE              0x5A4D
#define IMAGE_NT_SIGNATURE               0x00004550
#define EXCEPTION_EXECUTE_HANDLER        1
#define FLT_FILE_NAME_NORMALIZED         0x01
#define FLT_FILE_NAME_QUERY_DEFAULT      0x0100
#define NormalPagePriority               16
#define MdlMappingNoExecute              0x40000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define GetExceptionCode()               ((NTSTATUS)0)
#define CONTAINING_RECORD(address, type, field) ((type *)((unsigned char*)(address) - (unsigned long long)(&((type *)0)->field)))

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}

// 3. Function Prototypes
#ifdef __cplusplus
extern "C" {
#endif
void DbgPrintEx(ULONG, ULONG, const char*, ...);
PVOID ExAllocatePool2(ULONG, SIZE_T, ULONG);
void ExFreePoolWithTag(PVOID, ULONG);
void RtlZeroMemory(PVOID, SIZE_T);
void RtlCopyMemory(PVOID, const void*, SIZE_T);
void RtlInitUnicodeString(PUNICODE_STRING, const wchar_t*);
void InitializeListHead(PLIST_ENTRY);
void InsertTailList(PLIST_ENTRY, PLIST_ENTRY);
PLIST_ENTRY RemoveHeadList(PLIST_ENTRY);
int IsListEmpty(const PLIST_ENTRY);
void KeInitializeSpinLock(KSPIN_LOCK*);
void KeAcquireSpinLock(KSPIN_LOCK*, KIRQL*);
void KeReleaseSpinLock(KSPIN_LOCK*, KIRQL);
void KeInitializeEvent(KEVENT*, EVENT_TYPE, int);
void KeSetEvent(KEVENT*, int, int);
NTSTATUS KeWaitForSingleObject(void*, int, int, int, void*);
void KeQuerySystemTimePrecise(PLARGE_INTEGER);
NTSTATUS PsCreateSystemThread(HANDLE*, ULONG, POBJECT_ATTRIBUTES, HANDLE, void*, void*, PVOID);
void PsTerminateSystemThread(NTSTATUS);
NTSTATUS ObReferenceObjectByHandle(HANDLE, ULONG, void*, int, void**, void*);
void ObDereferenceObject(void*);
void ZwClose(HANDLE);
long InterlockedOr(volatile long*, long);
long InterlockedExchange(volatile long*, long);
long long InterlockedIncrement64(volatile long long*);
NTSTATUS FltBuildDefaultSecurityDescriptor(PSECURITY_DESCRIPTOR*, ACCESS_MASK);
void FltFreeSecurityDescriptor(PSECURITY_DESCRIPTOR);
NTSTATUS FltRegisterFilter(PDRIVER_OBJECT, const void*, PFLT_FILTER*);
void FltUnregisterFilter(PFLT_FILTER);
NTSTATUS FltStartFiltering(PFLT_FILTER);
NTSTATUS FltCreateCommunicationPort(PFLT_FILTER, PFLT_PORT*, POBJECT_ATTRIBUTES, PVOID, PVOID, PVOID, PVOID, LONG);
void FltCloseCommunicationPort(PFLT_PORT);
void FltCloseClientPort(PFLT_FILTER, PFLT_PORT*);
NTSTATUS FltSendMessage(PFLT_FILTER, PFLT_PORT*, PVOID, ULONG, PVOID, PULONG, void*);
NTSTATUS FltGetFileNameInformation(PFLT_CALLBACK_DATA, FLT_FILE_NAME_OPTIONS, PFLT_FILE_NAME_INFORMATION*);
void FltReleaseFileNameInformation(PFLT_FILE_NAME_INFORMATION);
NTSTATUS FltParseFileNameInformation(PFLT_FILE_NAME_INFORMATION);
NTSTATUS RtlStringCbCopyA(char*, size_t, const char*);
NTSTATUS BCryptOpenAlgorithmProvider(PVOID, const wchar_t*, const wchar_t*, ULONG);
NTSTATUS BCryptCreateHash(PVOID, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptHashData(PVOID, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptFinishHash(PVOID, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptGetProperty(PVOID, const wchar_t*, PUCHAR, ULONG, ULONG*, ULONG);
void BCryptDestroyHash(PVOID);
void BCryptCloseAlgorithmProvider(PVOID, ULONG);
NTSTATUS ZwOpenKey(HANDLE*, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS ZwQueryValueKey(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NTSTATUS ZwCreateKey(HANDLE*, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
NTSTATUS ZwSetValueKey(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
PVOID MmGetSystemAddressForMdlSafe(PVOID, ULONG);
HANDLE PsGetCurrentProcessId();
HANDLE PsGetCurrentThreadId();
HANDLE PsGetProcessId(PEPROCESS Process);
HANDLE PsGetThreadProcessId(PETHREAD Thread);
HANDLE PsGetThreadId(PETHREAD Thread);
NTSTATUS PsSetCreateProcessNotifyRoutineEx(PVOID NotifyRoutine, BOOLEAN Remove);
NTSTATUS PsSetCreateThreadNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS PsRemoveCreateThreadNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS PsSetLoadImageNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS PsRemoveLoadImageNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS ObRegisterCallbacks(POB_CALLBACK_REGISTRATION CallbackRegistration, PVOID* RegistrationHandle);
VOID ObUnRegisterCallbacks(PVOID RegistrationHandle);
#ifdef __cplusplus
}
#endif

// Tag for pool allocations: 'SntC'
#define SENTINEL_TAG 'CtnS'

// Debug print macro
#define SentinelDbgPrint(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[SentinelCore] " fmt "\n", ##__VA_ARGS__)

// ---------------------------------------------------------------------------
// Global Driver Data
// ---------------------------------------------------------------------------
typedef struct _SENTINEL_DRIVER_DATA {
    PFLT_FILTER     Filter;             // Minifilter handle
    PFLT_PORT       ServerPort;         // Communication server port
    PFLT_PORT       ClientPort;         // Connected client port (single connection)
    KSPIN_LOCK      ClientPortLock;     // Protects ClientPort and ClientConnected
    volatile LONG   ClientConnected;    // Is userland agent connected? (use interlocked)
    PDRIVER_OBJECT  DriverObject;       // Cached driver object
} SENTINEL_DRIVER_DATA, *PSENTINEL_DRIVER_DATA;

extern SENTINEL_DRIVER_DATA g_DriverData;

// ---------------------------------------------------------------------------
// Forward Declarations — Minifilter Operations
// ---------------------------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif
NTSTATUS FLTAPI FilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS FLTAPI PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext);
#ifdef __cplusplus
}
#endif

// ---------------------------------------------------------------------------
// Forward Declarations — Communication Port
// ---------------------------------------------------------------------------
NTSTATUS InitializeCommunicationPort(_In_ PFLT_FILTER Filter);
VOID CloseCommunicationPort(VOID);
NTSTATUS SendTelemetryToAgent(
    _In_reads_bytes_(PayloadSize) PVOID Payload,
    _In_ ULONG PayloadSize,
    _In_ ULONG MessageType);

// ---------------------------------------------------------------------------
// Forward Declarations — Kernel Callbacks
// ---------------------------------------------------------------------------
NTSTATUS RegisterKernelCallbacks();
VOID UnregisterKernelCallbacks();
VOID ResetBsodBootCounter();

// ---------------------------------------------------------------------------
// Forward Declarations — PE Parser
// ---------------------------------------------------------------------------
BOOLEAN IsPeFile(_In_reads_bytes_(BufferSize) PUCHAR Buffer, _In_ ULONG BufferSize);
NTSTATUS ParsePeHeaders(
    _In_reads_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ struct FeatureVector* pFeatureVector);

// ---------------------------------------------------------------------------
// Forward Declarations — Crypto / Entropy
// ---------------------------------------------------------------------------
NTSTATUS InitializeSha256Provider();
VOID CleanupSha256Provider();
NTSTATUS ComputeSha256(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ ULONG DataSize,
    _Out_writes_bytes_(SHA256_DIGEST_LENGTH) PUCHAR HashOutput);
FLOAT CalculateShannonEntropy(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ ULONG DataSize);

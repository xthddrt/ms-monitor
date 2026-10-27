#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define MSMON_DEVICE_NAME L"\\Device\\MsMon"
#define MSMON_DOS_DEVICE_NAME L"\\DosDevices\\MsMon"
#define MSMON_USER_DEVICE_PATH "\\\\.\\MsMon"
#define MSMON_PROTOCOL_VERSION 1u
#define MSMON_EVENT_TEXT_CHARS 192u
#define MSMON_EVENT_DETAIL_CHARS 192u
#define MSMON_READ_MAX_EVENTS 64u

typedef enum _MSMON_EVENT_TYPE {
    MsMonProcessStart = 1,
    MsMonProcessExit = 2,
    MsMonThreadStart = 3,
    MsMonThreadExit = 4,
    MsMonImageLoad = 5,
    MsMonFileCreate = 10,
    MsMonFileRead = 11,
    MsMonFileWrite = 12,
    MsMonFileSetInformation = 13,
    MsMonRegistryOpen = 20,
    MsMonRegistryCreate = 21,
    MsMonRegistrySetValue = 22,
    MsMonRegistryDelete = 23,
    MsMonRegistryRename = 24,
    MsMonRegistryQuery = 25,
    MsMonRegistryEnumerate = 26,
    MsMonNetworkConnect = 30,
    MsMonNetworkAccept = 31
} MSMON_EVENT_TYPE;

typedef enum _MSMON_EVENT_FLAGS {
    MsMonFlagExplicitTrack = 0x00000001u,
    MsMonFlagInheritedTrack = 0x00000002u,
    MsMonFlagTruncatedPath = 0x00000004u
} MSMON_EVENT_FLAGS;

#pragma pack(push, 8)
typedef struct _MSMON_EVENT {
    unsigned long Size;
    unsigned long Version;
    unsigned long Type;
    unsigned long Flags;
    unsigned __int64 Sequence;
    unsigned __int64 Timestamp;
    unsigned long ProcessId;
    unsigned long ParentProcessId;
    unsigned long ThreadId;
    long Status;
    unsigned __int64 Value0;
    unsigned __int64 Value1;
    wchar_t Text[MSMON_EVENT_TEXT_CHARS];
    wchar_t Detail[MSMON_EVENT_DETAIL_CHARS];
} MSMON_EVENT;

typedef struct _MSMON_READ_REQUEST {
    unsigned long TimeoutMilliseconds;
    unsigned long MaximumEvents;
} MSMON_READ_REQUEST;

typedef struct _MSMON_STATISTICS {
    unsigned __int64 QueuedEvents;
    unsigned __int64 DroppedEvents;
    unsigned __int64 TrackedProcesses;
} MSMON_STATISTICS;
#pragma pack(pop)

typedef MSMON_EVENT* PMSMON_EVENT;
typedef MSMON_READ_REQUEST* PMSMON_READ_REQUEST;
typedef MSMON_STATISTICS* PMSMON_STATISTICS;

#define MSMON_IOCTL_TRACK_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_READ_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define MSMON_IOCTL_STATISTICS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

#ifdef __cplusplus
}
#endif

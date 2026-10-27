#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include <sddl.h>
#include "../include/msmon_protocol.h"

#define MSMON_POOL_TAG 'noSM'
#define MSMON_MAX_QUEUED_EVENTS 4096u

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD MsMonDriverUnload;

NTSTATUS MsMonEventsInitialize(VOID);
VOID MsMonEventsUninitialize(VOID);
NTSTATUS MsMonLogEvent(
    ULONG Type,
    HANDLE ProcessId,
    HANDLE ParentProcessId,
    HANDLE ThreadId,
    ULONG Flags,
    NTSTATUS Status,
    ULONGLONG Value0,
    ULONGLONG Value1,
    PCWSTR Text,
    PCWSTR Detail
);
NTSTATUS MsMonReadEvents(PMSMON_EVENT Output, ULONG MaximumEvents, ULONG TimeoutMilliseconds, PULONG EventsRead);
VOID MsMonGetStatistics(PMSMON_STATISTICS Statistics);

NTSTATUS MsMonProcessInitialize(VOID);
VOID MsMonProcessUninitialize(VOID);
NTSTATUS MsMonTrackProcess(HANDLE ProcessId, BOOLEAN EmitEvent);
BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime);
ULONG MsMonTrackedProcessCount(VOID);

NTSTATUS MsMonFileFilterInitialize(PDRIVER_OBJECT DriverObject);
VOID MsMonFileFilterUninitialize(VOID);

NTSTATUS MsMonRegistryInitialize(PDRIVER_OBJECT DriverObject);
VOID MsMonRegistryUninitialize(VOID);

NTSTATUS MsMonNetworkInitialize(PDEVICE_OBJECT DeviceObject);
VOID MsMonNetworkUninitialize(VOID);

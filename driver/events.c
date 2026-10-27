#include "msmon.h"

typedef struct _MSMON_EVENT_BLOCK {
    LIST_ENTRY Link;
    MSMON_EVENT Event;
} MSMON_EVENT_BLOCK, *PMSMON_EVENT_BLOCK;

typedef struct _MSMON_EVENT_QUEUE {
    KSPIN_LOCK Lock;
    LIST_ENTRY Head;
    KEVENT DataAvailable;
    ULONGLONG Sequence;
    volatile LONG64 Dropped;
    volatile LONG Queued;
} MSMON_EVENT_QUEUE;

static MSMON_EVENT_QUEUE gQueue;

NTSTATUS MsMonEventsInitialize(VOID)
{
    KeInitializeSpinLock(&gQueue.Lock);
    InitializeListHead(&gQueue.Head);
    KeInitializeEvent(&gQueue.DataAvailable, SynchronizationEvent, FALSE);
    gQueue.Sequence = 0;
    gQueue.Dropped = 0;
    gQueue.Queued = 0;
    return STATUS_SUCCESS;
}

VOID MsMonEventsUninitialize(VOID)
{
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    entry = RemoveHeadList(&gQueue.Head);
    while (entry != &gQueue.Head) {
        ExFreePoolWithTag(CONTAINING_RECORD(entry, MSMON_EVENT_BLOCK, Link), MSMON_POOL_TAG);
        entry = RemoveHeadList(&gQueue.Head);
    }
    gQueue.Queued = 0;
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
}

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
)
{
    PMSMON_EVENT_BLOCK block;
    LARGE_INTEGER timestamp;
    KIRQL oldIrql;

    block = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*block), MSMON_POOL_TAG);
    if (block == NULL) {
        InterlockedIncrement64(&gQueue.Dropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(block, sizeof(*block));
    block->Event.Size = sizeof(block->Event);
    block->Event.Version = MSMON_PROTOCOL_VERSION;
    block->Event.Type = Type;
    block->Event.Flags = Flags;
    block->Event.ProcessId = HandleToULong(ProcessId);
    block->Event.ParentProcessId = HandleToULong(ParentProcessId);
    block->Event.ThreadId = HandleToULong(ThreadId);
    block->Event.Status = Status;
    block->Event.Value0 = Value0;
    block->Event.Value1 = Value1;
    KeQuerySystemTime(&timestamp);
    block->Event.Timestamp = (ULONGLONG)timestamp.QuadPart;

    if (Text != NULL) {
        if (!NT_SUCCESS(RtlStringCchCopyNW(block->Event.Text, MSMON_EVENT_TEXT_CHARS, Text, MSMON_EVENT_TEXT_CHARS - 1))) {
            block->Event.Flags |= MsMonFlagTruncatedPath;
        }
    }
    if (Detail != NULL) {
        (VOID)RtlStringCchCopyNW(block->Event.Detail, MSMON_EVENT_DETAIL_CHARS, Detail, MSMON_EVENT_DETAIL_CHARS - 1);
    }

    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    block->Event.Sequence = ++gQueue.Sequence;
    if (gQueue.Queued >= MSMON_MAX_QUEUED_EVENTS) {
        InterlockedIncrement64(&gQueue.Dropped);
        KeReleaseSpinLock(&gQueue.Lock, oldIrql);
        ExFreePoolWithTag(block, MSMON_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }
    InsertTailList(&gQueue.Head, &block->Link);
    InterlockedIncrement(&gQueue.Queued);
    KeSetEvent(&gQueue.DataAvailable, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS MsMonReadEvents(PMSMON_EVENT Output, ULONG MaximumEvents, ULONG TimeoutMilliseconds, PULONG EventsRead)
{
    ULONG count = 0;
    LARGE_INTEGER timeout;
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    PMSMON_EVENT_BLOCK block;

    *EventsRead = 0;
    if (Output == NULL || MaximumEvents == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    if (IsListEmpty(&gQueue.Head)) {
        KeResetEvent(&gQueue.DataAvailable);
    }
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);

    timeout.QuadPart = -((LONGLONG)TimeoutMilliseconds * 10000LL);
    if (TimeoutMilliseconds != 0) {
        (VOID)KeWaitForSingleObject(&gQueue.DataAvailable, Executive, KernelMode, FALSE, &timeout);
    }

    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    while (count < MaximumEvents && !IsListEmpty(&gQueue.Head)) {
        entry = RemoveHeadList(&gQueue.Head);
        block = CONTAINING_RECORD(entry, MSMON_EVENT_BLOCK, Link);
        RtlCopyMemory(&Output[count], &block->Event, sizeof(block->Event));
        ExFreePoolWithTag(block, MSMON_POOL_TAG);
        InterlockedDecrement(&gQueue.Queued);
        count++;
    }
    if (IsListEmpty(&gQueue.Head)) {
        KeResetEvent(&gQueue.DataAvailable);
    }
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    *EventsRead = count;
    return STATUS_SUCCESS;
}

VOID MsMonGetStatistics(PMSMON_STATISTICS Statistics)
{
    Statistics->QueuedEvents = (ULONGLONG)gQueue.Queued;
    Statistics->DroppedEvents = (ULONGLONG)gQueue.Dropped;
    Statistics->TrackedProcesses = MsMonTrackedProcessCount();
}

#include "msmon.h"

typedef struct _MSMON_PROCESS_ENTRY {
    LIST_ENTRY Link;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    LONGLONG StartTime;
    ULONG Flags;
} MSMON_PROCESS_ENTRY, *PMSMON_PROCESS_ENTRY;

static LIST_ENTRY gProcesses;
static KSPIN_LOCK gProcessLock;
static volatile LONG gProcessCount;

static BOOLEAN MsMonKnownImage(PCUNICODE_STRING ImageFileName)
{
    static const WCHAR* names[] = {
        L"MapleStory.exe", L"NGService.exe", L"DwarfAxe.exe", L"CrashReportClient.exe"
    };
    UNICODE_STRING image;
    UNICODE_STRING base;
    UNICODE_STRING expected;
    ULONG index;
    USHORT start;

    if (ImageFileName == NULL || ImageFileName->Buffer == NULL || ImageFileName->Length == 0) {
        return FALSE;
    }
    image = *ImageFileName;
    base = image;
    for (start = 0; start + sizeof(WCHAR) <= image.Length; start += sizeof(WCHAR)) {
        if (image.Buffer[start / sizeof(WCHAR)] == L'\\' || image.Buffer[start / sizeof(WCHAR)] == L'/') {
            base.Buffer = &image.Buffer[start / sizeof(WCHAR) + 1];
            base.Length = image.Length - start - sizeof(WCHAR);
            base.MaximumLength = base.Length;
        }
    }
    for (index = 0; index < RTL_NUMBER_OF(names); index++) {
        RtlInitUnicodeString(&expected, names[index]);
        if (RtlEqualUnicodeString(&base, &expected, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS MsMonTrackProcess(HANDLE ProcessId, BOOLEAN EmitEvent)
{
    PMSMON_PROCESS_ENTRY entry;
    PMSMON_PROCESS_ENTRY existing;
    PLIST_ENTRY link;
    PEPROCESS process = NULL;
    KIRQL oldIrql;
    BOOLEAN duplicate = FALSE;

    entry = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*entry), MSMON_POOL_TAG);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(entry, sizeof(*entry));
    entry->ProcessId = ProcessId;
    entry->Flags = MsMonFlagExplicitTrack;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        entry->StartTime = PsGetProcessCreateTimeQuadPart(process);
        entry->ParentProcessId = NULL;
        ObDereferenceObject(process);
    }

    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        existing = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (existing->ProcessId == ProcessId) {
            duplicate = TRUE;
            break;
        }
    }
    if (!duplicate) {
        InsertTailList(&gProcesses, &entry->Link);
        InterlockedIncrement(&gProcessCount);
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);

    if (duplicate) {
        ExFreePoolWithTag(entry, MSMON_POOL_TAG);
        return STATUS_SUCCESS;
    }
    if (EmitEvent) {
        (VOID)MsMonLogEvent(MsMonProcessStart, ProcessId, entry->ParentProcessId, NULL,
                            entry->Flags, STATUS_SUCCESS, (ULONGLONG)entry->StartTime, 0, NULL, NULL);
    }
    return STATUS_SUCCESS;
}

BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime)
{
    PLIST_ENTRY link;
    PMSMON_PROCESS_ENTRY entry;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        entry = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (entry->ProcessId == ProcessId && (StartTime == 0 || entry->StartTime == 0 || entry->StartTime == StartTime)) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);
    return found;
}

ULONG MsMonTrackedProcessCount(VOID)
{
    return (ULONG)gProcessCount;
}

static VOID MsMonForgetProcess(HANDLE ProcessId)
{
    PLIST_ENTRY link;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        PMSMON_PROCESS_ENTRY entry = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (entry->ProcessId == ProcessId) {
            RemoveEntryList(&entry->Link);
            ExFreePoolWithTag(entry, MSMON_POOL_TAG);
            InterlockedDecrement(&gProcessCount);
            break;
        }
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);
}

static VOID MsMonProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    LONGLONG startTime = PsGetProcessCreateTimeQuadPart(Process);
    BOOLEAN inherited;
    ULONG flags;

    if (CreateInfo == NULL) {
        if (MsMonIsTracked(ProcessId, startTime)) {
            (VOID)MsMonLogEvent(MsMonProcessExit, ProcessId, NULL, NULL, 0, STATUS_SUCCESS,
                                (ULONGLONG)startTime, 0, NULL, NULL);
            MsMonForgetProcess(ProcessId);
        }
        return;
    }

    inherited = MsMonIsTracked(CreateInfo->ParentProcessId, 0);
    if (!inherited && !MsMonKnownImage(CreateInfo->ImageFileName)) {
        return;
    }

    flags = inherited ? MsMonFlagInheritedTrack : MsMonFlagExplicitTrack;
    (VOID)MsMonTrackProcess(ProcessId, FALSE);
    (VOID)MsMonLogEvent(MsMonProcessStart, ProcessId, CreateInfo->ParentProcessId, NULL,
                        flags, STATUS_SUCCESS, (ULONGLONG)startTime, 0,
                        CreateInfo->ImageFileName != NULL ? CreateInfo->ImageFileName->Buffer : NULL,
                        CreateInfo->CommandLine != NULL ? CreateInfo->CommandLine->Buffer : NULL);
}

static VOID MsMonThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    if (!MsMonIsTracked(ProcessId, 0)) {
        return;
    }
    (VOID)MsMonLogEvent(Create ? MsMonThreadStart : MsMonThreadExit,
                        ProcessId, NULL, ThreadId, 0, STATUS_SUCCESS, 0, 0, NULL, NULL);
}

static VOID MsMonImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if (!MsMonIsTracked(ProcessId, 0)) {
        return;
    }
    (VOID)MsMonLogEvent(MsMonImageLoad, ProcessId, NULL, NULL, 0, STATUS_SUCCESS,
                        (ULONGLONG)ImageInfo->ImageBase, ImageInfo->ImageSize,
                        FullImageName != NULL ? FullImageName->Buffer : NULL, NULL);
}

NTSTATUS MsMonProcessInitialize(VOID)
{
    NTSTATUS status;

    InitializeListHead(&gProcesses);
    KeInitializeSpinLock(&gProcessLock);
    gProcessCount = 0;
    status = PsSetCreateProcessNotifyRoutineEx(MsMonProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = PsSetCreateThreadNotifyRoutine(MsMonThreadNotify);
    if (!NT_SUCCESS(status)) {
        (VOID)PsSetCreateProcessNotifyRoutineEx(MsMonProcessNotify, TRUE);
        return status;
    }
    status = PsSetLoadImageNotifyRoutine(MsMonImageNotify);
    if (!NT_SUCCESS(status)) {
        (VOID)PsRemoveCreateThreadNotifyRoutine(MsMonThreadNotify);
        (VOID)PsSetCreateProcessNotifyRoutineEx(MsMonProcessNotify, TRUE);
    }
    return status;
}

VOID MsMonProcessUninitialize(VOID)
{
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    (VOID)PsSetLoadImageNotifyRoutine(MsMonImageNotify);
    (VOID)PsRemoveCreateThreadNotifyRoutine(MsMonThreadNotify);
    (VOID)PsSetCreateProcessNotifyRoutineEx(MsMonProcessNotify, TRUE);
    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    while (!IsListEmpty(&gProcesses)) {
        entry = RemoveHeadList(&gProcesses);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, MSMON_PROCESS_ENTRY, Link), MSMON_POOL_TAG);
    }
    gProcessCount = 0;
    KeReleaseSpinLock(&gProcessLock, oldIrql);
}

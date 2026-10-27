#include <fltKernel.h>
#include "../include/msmon_protocol.h"

#define MSMON_POOL_TAG 'noSM'

BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime);
NTSTATUS MsMonLogEvent(ULONG Type, HANDLE ProcessId, HANDLE ParentProcessId, HANDLE ThreadId,
                       ULONG Flags, NTSTATUS Status, ULONGLONG Value0, ULONGLONG Value1,
                       PCWSTR Text, PCWSTR Detail);

static PFLT_FILTER gFilter;

static VOID MsMonFileEvent(
    PFLT_CALLBACK_DATA Data,
    ULONG Type,
    NTSTATUS Status,
    ULONGLONG Value0,
    ULONGLONG Value1,
    PCWSTR Detail
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PCWSTR path = NULL;

    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0)) {
        return;
    }
    if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
        path = nameInfo->Name.Buffer;
    }
    (VOID)MsMonLogEvent(Type, PsGetCurrentProcessId(), NULL, PsGetCurrentThreadId(), 0,
                        Status, Value0, Value1, path, Detail);
    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }
}

static FLT_POSTOP_CALLBACK_STATUS MsMonPostCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    MsMonFileEvent(Data, MsMonFileCreate, Data->IoStatus.Status,
                   Data->Iopb->Parameters.Create.Options, 0, NULL);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS MsMonPreReadWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
        MsMonFileEvent(Data, MsMonFileRead, STATUS_SUCCESS,
                       Data->Iopb->Parameters.Read.Length,
                       (ULONGLONG)Data->Iopb->Parameters.Read.ByteOffset.QuadPart, NULL);
    } else {
        MsMonFileEvent(Data, MsMonFileWrite, STATUS_SUCCESS,
                       Data->Iopb->Parameters.Write.Length,
                       (ULONGLONG)Data->Iopb->Parameters.Write.ByteOffset.QuadPart, NULL);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS MsMonPreSetInformation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    MsMonFileEvent(Data, MsMonFileSetInformation, STATUS_SUCCESS,
                   Data->Iopb->Parameters.SetFileInformation.FileInformationClass, 0, NULL);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static const FLT_OPERATION_REGISTRATION gOperations[] = {
    { IRP_MJ_CREATE, 0, NULL, MsMonPostCreate, NULL },
    { IRP_MJ_READ, 0, MsMonPreReadWrite, NULL, NULL },
    { IRP_MJ_WRITE, 0, MsMonPreReadWrite, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, MsMonPreSetInformation, NULL, NULL },
    { IRP_MJ_OPERATION_END, 0, NULL, NULL, NULL }
};

static const FLT_REGISTRATION gFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gOperations,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS MsMonFileFilterInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = FltRegisterFilter(DriverObject, &gFilterRegistration, &gFilter);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return status;
}

VOID MsMonFileFilterUninitialize(VOID)
{
    if (gFilter != NULL) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
}

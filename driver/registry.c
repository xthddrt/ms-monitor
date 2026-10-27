#include "msmon.h"

static LARGE_INTEGER gRegistryCookie;
static BOOLEAN gRegistryRegistered;

static PCWSTR MsMonRegistryPath(PVOID Object, PUNICODE_STRING Storage)
{
    PCUNICODE_STRING name = NULL;
    ULONG_PTR objectId = 0;

    Storage->Buffer = NULL;
    Storage->Length = 0;
    Storage->MaximumLength = 0;
    if (NT_SUCCESS(CmCallbackGetKeyObjectID(&gRegistryCookie, Object, &objectId, &name)) && name != NULL) {
        *Storage = *(PUNICODE_STRING)name;
        return Storage->Buffer;
    }
    return NULL;
}

static NTSTATUS MsMonRegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    REG_NOTIFY_CLASS operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    ULONG processId = HandleToULong(PsGetCurrentProcessId());
    UNICODE_STRING path;
    PCWSTR pathText = NULL;
    PCWSTR detail = NULL;
    ULONG type = MsMonRegistryOpen;
    ULONGLONG value = 0;

    UNREFERENCED_PARAMETER(CallbackContext);
    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0)) {
        return STATUS_SUCCESS;
    }

    switch (operation) {
    case RegNtPreOpenKeyEx: {
        PREG_OPEN_KEY_INFORMATION info = Argument2;
        pathText = info->CompleteName->Buffer;
        type = MsMonRegistryOpen;
        break;
    }
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION info = Argument2;
        pathText = info->CompleteName->Buffer;
        type = MsMonRegistryCreate;
        break;
    }
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = Argument2;
        pathText = MsMonRegistryPath(info->Object, &path);
        detail = info->ValueName->Buffer;
        value = info->DataSize;
        type = MsMonRegistrySetValue;
        break;
    }
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = Argument2;
        pathText = MsMonRegistryPath(info->Object, &path);
        type = MsMonRegistryDelete;
        break;
    }
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info = Argument2;
        pathText = MsMonRegistryPath(info->Object, &path);
        detail = info->ValueName->Buffer;
        type = MsMonRegistryDelete;
        break;
    }
    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION info = Argument2;
        pathText = MsMonRegistryPath(info->Object, &path);
        detail = info->NewName->Buffer;
        type = MsMonRegistryRename;
        break;
    }
    case RegNtPreQueryValueKey: {
        PREG_QUERY_VALUE_KEY_INFORMATION info = Argument2;
        pathText = MsMonRegistryPath(info->Object, &path);
        detail = info->ValueName->Buffer;
        value = info->KeyValueInformationClass;
        type = MsMonRegistryQuery;
        break;
    }
    case RegNtPreEnumerateKey: {
        PREG_ENUMERATE_KEY_INFORMATION info = Argument2;
        pathText = MsMonRegistryPath(info->Object, &path);
        value = info->Index;
        type = MsMonRegistryEnumerate;
        break;
    }
    case RegNtPreEnumerateValueKey: {
        PREG_ENUMERATE_VALUE_KEY_INFORMATION info = Argument2;
        pathText = MsMonRegistryPath(info->Object, &path);
        value = info->Index;
        type = MsMonRegistryEnumerate;
        break;
    }
    default:
        return STATUS_SUCCESS;
    }

    (VOID)MsMonLogEvent(type, UlongToHandle(processId), NULL, PsGetCurrentThreadId(), 0,
                        STATUS_SUCCESS, value, 0, pathText, detail);
    return STATUS_SUCCESS;
}

NTSTATUS MsMonRegistryInitialize(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING altitude;
    NTSTATUS status;

    RtlInitUnicodeString(&altitude, L"380010");
    status = CmRegisterCallbackEx(MsMonRegistryCallback, &altitude, DriverObject,
                                  NULL, &gRegistryCookie, NULL);
    gRegistryRegistered = NT_SUCCESS(status);
    return status;
}

VOID MsMonRegistryUninitialize(VOID)
{
    if (gRegistryRegistered) {
        (VOID)CmUnRegisterCallback(gRegistryCookie);
        gRegistryRegistered = FALSE;
    }
}

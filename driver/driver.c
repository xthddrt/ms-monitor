#include "msmon.h"
#include <wdmsec.h>

static const GUID MSMON_DEVICE_GUID = { 0xdb6a8ad5, 0xc08e, 0x4f95, { 0x8d, 0x15, 0x11, 0x5a, 0x72, 0x13, 0x6d, 0x40 } };

static NTSTATUS MsMonCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS MsMonDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);
    switch (code) {
    case MSMON_IOCTL_TRACK_PID:
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = MsMonTrackProcess(UlongToHandle(*(PULONG)Irp->AssociatedIrp.SystemBuffer), TRUE);
        break;
    case MSMON_IOCTL_READ_EVENTS: {
        PMSMON_READ_REQUEST request = Irp->AssociatedIrp.SystemBuffer;
        ULONG maximum = MSMON_READ_MAX_EVENTS;
        ULONG timeout = 500;
        ULONG count = 0;
        if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(*request)) {
            maximum = request->MaximumEvents;
            timeout = request->TimeoutMilliseconds;
        }
        if (maximum == 0 || maximum > MSMON_READ_MAX_EVENTS) {
            maximum = MSMON_READ_MAX_EVENTS;
        }
        if (timeout > 30000) {
            timeout = 30000;
        }
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MSMON_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        maximum = min(maximum, stack->Parameters.DeviceIoControl.OutputBufferLength / (ULONG)sizeof(MSMON_EVENT));
        status = MsMonReadEvents(Irp->AssociatedIrp.SystemBuffer, maximum, timeout, &count);
        information = (ULONG_PTR)count * sizeof(MSMON_EVENT);
        break;
    }
    case MSMON_IOCTL_STATISTICS:
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MSMON_STATISTICS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        MsMonGetStatistics(Irp->AssociatedIrp.SystemBuffer);
        information = sizeof(MSMON_STATISTICS);
        status = STATUS_SUCCESS;
        break;
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID MsMonDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosName;

    MsMonNetworkUninitialize();
    MsMonRegistryUninitialize();
    MsMonFileFilterUninitialize();
    MsMonProcessUninitialize();
    MsMonEventsUninitialize();
    RtlInitUnicodeString(&dosName, MSMON_DOS_DEVICE_NAME);
    (VOID)IoDeleteSymbolicLink(&dosName);
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING dosName;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = MsMonDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = MsMonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MsMonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MsMonDeviceControl;

    RtlInitUnicodeString(&deviceName, MSMON_DEVICE_NAME);
    RtlInitUnicodeString(&dosName, MSMON_DOS_DEVICE_NAME);
    status = IoCreateDeviceSecure(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN, FALSE,
                                  &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                                  &MSMON_DEVICE_GUID, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = IoCreateSymbolicLink(&dosName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    status = MsMonEventsInitialize();
    if (NT_SUCCESS(status)) status = MsMonProcessInitialize();
    if (NT_SUCCESS(status)) status = MsMonFileFilterInitialize(DriverObject);
    if (NT_SUCCESS(status)) status = MsMonRegistryInitialize(DriverObject);
    if (NT_SUCCESS(status)) status = MsMonNetworkInitialize(deviceObject);
    if (!NT_SUCCESS(status)) {
        MsMonNetworkUninitialize();
        MsMonRegistryUninitialize();
        MsMonFileFilterUninitialize();
        MsMonProcessUninitialize();
        MsMonEventsUninitialize();
        (VOID)IoDeleteSymbolicLink(&dosName);
        IoDeleteDevice(deviceObject);
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

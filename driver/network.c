#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable:4201)
#define NDIS630 1
#include <ndis.h>
#pragma warning(pop)
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>
#include "../include/msmon_protocol.h"

BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime);
NTSTATUS MsMonLogEvent(ULONG Type, HANDLE ProcessId, HANDLE ParentProcessId, HANDLE ThreadId,
                       ULONG Flags, NTSTATUS Status, ULONGLONG Value0, ULONGLONG Value1,
                       PCWSTR Text, PCWSTR Detail);
VOID MsMonNetworkUninitialize(VOID);

static const GUID MSMON_CALLOUT_CONNECT_V4 = { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x01 } };
static const GUID MSMON_CALLOUT_CONNECT_V6 = { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x02 } };
static const GUID MSMON_CALLOUT_ACCEPT_V4 = { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x03 } };
static const GUID MSMON_CALLOUT_ACCEPT_V6 = { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x04 } };

static HANDLE gEngine;
static UINT32 gCalloutIds[4];
static BOOLEAN gCalloutRegistered[4];

static VOID MsMonFormatIpv4(UINT32 Address, PWSTR Output, SIZE_T Characters)
{
    (VOID)RtlStringCchPrintfW(Output, Characters, L"%u.%u.%u.%u",
                              Address & 0xff, (Address >> 8) & 0xff,
                              (Address >> 16) & 0xff, (Address >> 24) & 0xff);
}

static VOID MsMonFormatIpv6(const FWP_BYTE_ARRAY16* Address, PWSTR Output, SIZE_T Characters)
{
    static const WCHAR hex[] = L"0123456789abcdef";
    ULONG index;
    ULONG offset = 0;

    if (Address == NULL || Characters < 40) {
        if (Characters != 0) Output[0] = L'\0';
        return;
    }
    for (index = 0; index < 16; index++) {
        Output[offset++] = hex[Address->byteArray16[index] >> 4];
        Output[offset++] = hex[Address->byteArray16[index] & 0xf];
        if ((index & 1) == 1 && index != 15) Output[offset++] = L':';
    }
    Output[offset] = L'\0';
}

static VOID NTAPI MsMonWfpClassify(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    void* LayerData,
    const void* ClassifyContext,
    const FWPS_FILTER3* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    BOOLEAN ipv6 = Filter->action.calloutId == gCalloutIds[1] || Filter->action.calloutId == gCalloutIds[3];
    BOOLEAN accept = Filter->action.calloutId == gCalloutIds[2] || Filter->action.calloutId == gCalloutIds[3];
    UINT16 localField = accept ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT : FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
    UINT16 remoteField = accept ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT : FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
    UINT16 protocolField = accept ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL : FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
    UINT32 localAddress = 0;
    UINT32 remoteAddress = 0;
    UINT16 localPort;
    UINT16 remotePort;
    WCHAR local[48];
    WCHAR remote[48];
    WCHAR endpoints[128];

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(FlowContext);

    if ((InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0 &&
        MsMonIsTracked(UlongToHandle((ULONG)InMetaValues->processId), 0)) {
        localPort = RtlUshortByteSwap(InFixedValues->incomingValue[localField].value.uint16);
        remotePort = RtlUshortByteSwap(InFixedValues->incomingValue[remoteField].value.uint16);
        if (ipv6) {
            UINT16 base = accept ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
            MsMonFormatIpv6(InFixedValues->incomingValue[base].value.byteArray16, local, RTL_NUMBER_OF(local));
            MsMonFormatIpv6(InFixedValues->incomingValue[base + 1].value.byteArray16, remote, RTL_NUMBER_OF(remote));
            localField = accept ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
            remoteField = accept ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
            protocolField = accept ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
            localPort = RtlUshortByteSwap(InFixedValues->incomingValue[localField].value.uint16);
            remotePort = RtlUshortByteSwap(InFixedValues->incomingValue[remoteField].value.uint16);
        } else {
            UINT16 base = accept ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS : FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
            localAddress = InFixedValues->incomingValue[base].value.uint32;
            remoteAddress = InFixedValues->incomingValue[base + 1].value.uint32;
            MsMonFormatIpv4(localAddress, local, RTL_NUMBER_OF(local));
            MsMonFormatIpv4(remoteAddress, remote, RTL_NUMBER_OF(remote));
        }
        (VOID)RtlStringCchPrintfW(endpoints, RTL_NUMBER_OF(endpoints), L"%ws:%u -> %ws:%u",
                                  local, localPort, remote, remotePort);
        (VOID)MsMonLogEvent(accept ? MsMonNetworkAccept : MsMonNetworkConnect,
                            UlongToHandle((ULONG)InMetaValues->processId), NULL, NULL, 0, STATUS_SUCCESS,
                            InFixedValues->incomingValue[protocolField].value.uint8,
                            ((ULONGLONG)localPort << 16) | remotePort, endpoints,
                            accept ? L"recv_accept" : L"connect");
    }

    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

static NTSTATUS NTAPI MsMonWfpNotify(
    FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    const GUID* FilterKey,
    const FWPS_FILTER3* Filter
)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

static NTSTATUS MsMonAddCallout(
    PDEVICE_OBJECT DeviceObject,
    const GUID* CalloutKey,
    const GUID* LayerKey,
    ULONG Index,
    PCWSTR Name
)
{
    FWPS_CALLOUT3 callout;
    FWPM_CALLOUT managerCallout;
    FWPM_FILTER filter;
    NTSTATUS status;

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *CalloutKey;
    callout.classifyFn = MsMonWfpClassify;
    callout.notifyFn = MsMonWfpNotify;
    status = FwpsCalloutRegister3(DeviceObject, &callout, &gCalloutIds[Index]);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    gCalloutRegistered[Index] = TRUE;

    RtlZeroMemory(&managerCallout, sizeof(managerCallout));
    managerCallout.calloutKey = *CalloutKey;
    managerCallout.displayData.name = (PWSTR)Name;
    managerCallout.displayData.description = (PWSTR)L"MapleStory application network metadata monitor";
    managerCallout.calloutId = gCalloutIds[Index];
    status = FwpmCalloutAdd(gEngine, &managerCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&filter, sizeof(filter));
    filter.displayData.name = (PWSTR)Name;
    filter.displayData.description = (PWSTR)L"Observe application network authorization events";
    filter.layerKey = *LayerKey;
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = *CalloutKey;
    filter.weight.type = FWP_EMPTY;
    return FwpmFilterAdd(gEngine, &filter, NULL, NULL);
}

NTSTATUS MsMonNetworkInitialize(PDEVICE_OBJECT DeviceObject)
{
    FWPM_SESSION session;
    NTSTATUS status;

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = (PWSTR)L"MsMon dynamic session";
    session.displayData.description = (PWSTR)L"Passive application network monitoring";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &gEngine);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MsMonAddCallout(DeviceObject, &MSMON_CALLOUT_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0, L"MsMon connect IPv4");
    if (NT_SUCCESS(status)) status = MsMonAddCallout(DeviceObject, &MSMON_CALLOUT_CONNECT_V6, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, 1, L"MsMon connect IPv6");
    if (NT_SUCCESS(status)) status = MsMonAddCallout(DeviceObject, &MSMON_CALLOUT_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, 2, L"MsMon accept IPv4");
    if (NT_SUCCESS(status)) status = MsMonAddCallout(DeviceObject, &MSMON_CALLOUT_ACCEPT_V6, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, 3, L"MsMon accept IPv6");
    if (!NT_SUCCESS(status)) {
        MsMonNetworkUninitialize();
    }
    return status;
}

VOID MsMonNetworkUninitialize(VOID)
{
    ULONG index;

    if (gEngine != NULL) {
        (VOID)FwpmEngineClose(gEngine);
        gEngine = NULL;
    }
    for (index = 0; index < RTL_NUMBER_OF(gCalloutRegistered); index++) {
        if (gCalloutRegistered[index]) {
            (VOID)FwpsCalloutUnregisterById(gCalloutIds[index]);
            gCalloutRegistered[index] = FALSE;
        }
    }
}

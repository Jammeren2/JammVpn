/*
 * JammVPN split-tunnel WFP callout driver — реализация (СКЕЛЕТ).
 *
 * СТАТУС: каркас. Логика классификации/редиректа помечена TODO. Требует WDK;
 * ещё не компилировался. Логика решения зеркалит jammvpn_core::split::decide:
 *   hairpin -> LAN/bypass -> force_direct -> force_tunnel -> по приложению -> kill-switch.
 */

#include "driver.h"

static PDEVICE_OBJECT gDeviceObject = NULL;
static HANDLE         gEngineHandle = NULL;
static UINT32         gCalloutIdV4  = 0;
static UINT32         gCalloutIdV6  = 0;

static JAMM_CONFIG    gConfig = {0};
static FAST_MUTEX     gConfigLock;

/* ------------------------------------------------------------------ WFP ---- */

/* classifyFn для FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6. */
static void NTAPI JammClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    /*
     * TODO:
     *  1. Извлечь ALE_APP_ID, IP_REMOTE_ADDRESS, IP_PROTOCOL, IP_REMOTE_PORT
     *     из inFixedValues.
     *  2. Под gConfigLock применить лестницу решений (зеркало decide()).
     *  3. Tunnel: FwpsAcquireWritableLayerDataPointer0 -> переписать
     *     remoteAddress/remotePort на 127.0.0.1:redirect_port; сохранить
     *     redirect-record (FwpsRedirectHandleCreate0) с original-dst.
     *  4. Block: classifyOut->actionType = FWP_ACTION_BLOCK; clear WRITE_FLAG.
     *  5. Direct: FWP_ACTION_PERMIT (или CONTINUE).
     */
    classifyOut->actionType = FWP_ACTION_PERMIT;
}

static NTSTATUS NTAPI JammNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static NTSTATUS JammRegisterCallouts(_In_ PDEVICE_OBJECT deviceObject)
{
    UNREFERENCED_PARAMETER(deviceObject);
    /*
     * TODO (в транзакции FwpmTransactionBegin0/Commit0):
     *  - FwpmEngineOpen0 (gEngineHandle), сессия FWPM_SESSION_FLAG_DYNAMIC;
     *  - FwpmProviderAdd0 (JAMM_PROVIDER_GUID);
     *  - FwpmSubLayerAdd0 (JAMM_SUBLAYER_GUID, weight);
     *  - FwpsCalloutRegister3 для V4 и V6 (JammClassify/JammNotify) -> gCalloutId*;
     *  - FwpmCalloutAdd0 + FwpmFilterAdd0 на ALE_CONNECT_REDIRECT_V4/V6;
     *  - отдельные фильтры-исключения (hairpin/LAN) с большим весом;
     *  - kill-switch block-фильтры (SPL-30..34).
     */
    return STATUS_NOT_IMPLEMENTED;
}

static void JammUnregisterCallouts(void)
{
    /* TODO: FwpsCalloutUnregisterById(gCalloutIdV4/V6); удалить provider/sublayer/
     * filters по GUID; FwpmEngineClose0. Динамическая сессия снимает объекты при
     * закрытии хендла (страховка от «сирот», SPL-39/41). */
    if (gEngineHandle != NULL) {
        /* FwpmEngineClose0(gEngineHandle); */
        gEngineHandle = NULL;
    }
}

/* -------------------------------------------------------------- IRP / IOCTL - */

NTSTATUS JammCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS JammDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case JAMM_IOCTL_SET_CONFIG:
        /* TODO: распарсить SystemBuffer (формат ipc.rs) -> временный JAMM_CONFIG,
         * затем под gConfigLock атомарно заменить gConfig. */
        status = STATUS_NOT_IMPLEMENTED;
        break;
    case JAMM_IOCTL_CLEAR:
        /* TODO: под gConfigLock очистить gConfig. */
        status = STATUS_NOT_IMPLEMENTED;
        break;
    case JAMM_IOCTL_GET_STATS:
        /* TODO: заполнить SystemBuffer статистикой (SPL-54). */
        status = STATUS_NOT_IMPLEMENTED;
        break;
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ----------------------------------------------------------- entry / unload - */

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING deviceName, symlinkName;

    ExInitializeFastMutex(&gConfigLock);

    RtlInitUnicodeString(&deviceName, JAMM_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_NETWORK,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &gDeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&symlinkName, JAMM_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gDeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = JammCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = JammCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = JammDeviceControl;
    DriverObject->DriverUnload                         = JammUnload;

    /* TODO: включить после готовности WFP-части:
     * status = JammRegisterCallouts(gDeviceObject);
     * if (!NT_SUCCESS(status)) { ... cleanup ... return status; } */
    (void)JammRegisterCallouts;

    return STATUS_SUCCESS;
}

VOID JammUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING symlinkName;

    JammUnregisterCallouts();

    RtlInitUnicodeString(&symlinkName, JAMM_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (gDeviceObject != NULL) {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
    }
}

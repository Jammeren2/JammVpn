/*
 * JammVPN split-tunnel WFP callout driver — заголовок.
 *
 * СТАТУС: скелет. Требует WDK для сборки; ещё не компилировался/не верифицировался.
 *
 * Значения IOCTL и путей ОБЯЗАНЫ совпадать с единым источником истины:
 *   crates/platform-windows/src/wfp/ipc.rs
 */
#pragma once

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>

#define JAMM_DEVICE_NAME   L"\\Device\\JammVpnSplit"
#define JAMM_SYMLINK_NAME  L"\\DosDevices\\JammVpnSplit"

/* CTL_CODE(FILE_DEVICE_NETWORK=0x12, function, METHOD_BUFFERED=0, access).
 * Должно совпадать с ctl_code(...) в ipc.rs. */
#define JAMM_IOCTL_SET_CONFIG  CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define JAMM_IOCTL_CLEAR       CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define JAMM_IOCTL_GET_STATS   CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

/* TODO: сгенерировать стабильные GUID (uuidgen) и подставить сюда. */
/* DEFINE_GUID(JAMM_PROVIDER_GUID,  ...); */
/* DEFINE_GUID(JAMM_SUBLAYER_GUID,  ...); */
/* DEFINE_GUID(JAMM_CALLOUT_V4_GUID,...); */
/* DEFINE_GUID(JAMM_CALLOUT_V6_GUID,...); */

/* Разобранный из IOCTL_SET_CONFIG набор правил (формат — см. ipc.rs).
 * TODO: полноценные поля (режим, redirect-порт, kill-switch, списки приложений
 * и CIDR, endpoints). Пока — заглушка. */
typedef struct _JAMM_CONFIG {
    UINT8  mode;          /* 0 = inclusive, 1 = exclusive */
    UINT8  kill_switch;   /* 0/1 */
    UINT16 redirect_port; /* порт локального прокси */
    /* TODO: apps[], bypass[], force_direct[], force_tunnel[], endpoints[] */
} JAMM_CONFIG, *PJAMM_CONFIG;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     JammUnload;

NTSTATUS JammDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS JammCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

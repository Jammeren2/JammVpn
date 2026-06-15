/*
 * JammVPN split-tunnel WFP callout driver — заголовок.
 *
 * СТАТУС: реализация логики (classify/redirect/parse). Требует WDK для сборки;
 * в sandbox-среде ассистента не компилировался и НЕ загружался (нужны
 * админ-права, test-signing, перезагрузка, kernel-отладчик). Проверка — на
 * целевой машине с WDK (см. README.md).
 *
 * Значения IOCTL/путей и бинарные форматы ОБЯЗАНЫ совпадать с единым источником
 * истины: crates/platform-windows/src/wfp/ipc.rs.
 */
#pragma once

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <guiddef.h>

#define JAMM_DEVICE_NAME   L"\\Device\\JammVpnSplit"
#define JAMM_SYMLINK_NAME  L"\\DosDevices\\JammVpnSplit"

/* Тег пула ('JmmV' в обратном порядке байт, как принято для ExAllocatePool*). */
#define JAMM_POOL_TAG 'VmmJ'

/* CTL_CODE(FILE_DEVICE_NETWORK=0x12, function, METHOD_BUFFERED=0, access).
 * Должно совпадать с ctl_code(...) в ipc.rs. */
#define JAMM_IOCTL_SET_CONFIG  CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define JAMM_IOCTL_CLEAR       CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define JAMM_IOCTL_GET_STATS   CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

/* Стабильные GUID подсистемы (зафиксированы; не менять — иначе «осиротевшие»
 * объекты WFP после обновления). Сгенерированы единожды для JammVPN. */
/* {9F3A1E10-4C2B-4D7E-8A11-2B3C4D5E6F70} */
DEFINE_GUID(JAMM_PROVIDER_GUID,
    0x9f3a1e10, 0x4c2b, 0x4d7e, 0x8a, 0x11, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70);
/* {9F3A1E11-4C2B-4D7E-8A11-2B3C4D5E6F71} */
DEFINE_GUID(JAMM_SUBLAYER_GUID,
    0x9f3a1e11, 0x4c2b, 0x4d7e, 0x8a, 0x11, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x71);
/* {9F3A1E12-4C2B-4D7E-8A11-2B3C4D5E6F72} */
DEFINE_GUID(JAMM_CALLOUT_V4_GUID,
    0x9f3a1e12, 0x4c2b, 0x4d7e, 0x8a, 0x11, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x72);
/* {9F3A1E13-4C2B-4D7E-8A11-2B3C4D5E6F73} */
DEFINE_GUID(JAMM_CALLOUT_V6_GUID,
    0x9f3a1e13, 0x4c2b, 0x4d7e, 0x8a, 0x11, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x73);

/* ----------------------------------------------------------------- модель --- */

/* IP-адрес: family 4/6; v4 — в первых 4 байтах addr (как push_ip в ipc.rs). */
typedef struct _JAMM_IP {
    UINT8 family;    /* 4 или 6 */
    UINT8 addr[16];
} JAMM_IP;

typedef struct _JAMM_CIDR {
    JAMM_IP ip;
    UINT8   prefix;
} JAMM_CIDR;

/* Приложение: byName -> имя процесса (сравнение по хвосту пути), иначе полный
 * путь. value хранится в UTF-16, нижний регистр, Buffer выделен из пула. */
typedef struct _JAMM_APP {
    BOOLEAN        byName;
    UNICODE_STRING value;
} JAMM_APP;

/* Снимок правил (разобранный из IOCTL_SET_CONFIG, формат — ipc.rs). Списки —
 * в невыгружаемом пуле; владелец — gConfig, освобождает JammFreeConfig. */
typedef struct _JAMM_CONFIG {
    UINT8      mode;          /* 0 inclusive, 1 exclusive */
    BOOLEAN    killSwitch;
    UINT16     redirectPort;  /* хостовый порядок байт */

    UINT16     appCount;
    JAMM_APP*  apps;

    UINT16     bypassCount;
    JAMM_CIDR* bypass;

    UINT16     forceDirectCount;
    JAMM_CIDR* forceDirect;

    UINT16     forceTunnelCount;
    JAMM_CIDR* forceTunnel;

    UINT16     endpointCount;
    JAMM_IP*   endpoints;
} JAMM_CONFIG, *PJAMM_CONFIG;

/* Решение классификатора (зеркало jammvpn_core::split::Action + Block). */
typedef enum _JAMM_DECISION {
    JAMM_DIRECT = 0,
    JAMM_TUNNEL,
    JAMM_BLOCK
} JAMM_DECISION;

/* redirect-context: original-dst, который прокси читает через
 * SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT. 19 байт, формат — ipc.rs
 * (encode_redirect_context): family(1) + addr(16) + port(2, big-endian). */
#define JAMM_REDIRECT_CONTEXT_LEN 19

/* ----------------------------------------------------------- прототипы ------ */

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     JammUnload;

NTSTATUS JammDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS JammCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

/* Разбор/освобождение конфига (формат — ipc.rs). */
NTSTATUS JammParseConfig(_In_reads_bytes_(len) const UCHAR* buf, _In_ SIZE_T len,
                         _Out_ PJAMM_CONFIG outCfg);
VOID     JammFreeConfig(_Inout_ PJAMM_CONFIG cfg);

/*
 * JammVPN split-tunnel WFP callout driver — реализация.
 *
 * СТАТУС: логика классификации/редиректа/разбора конфига реализована. Требует
 * WDK для сборки; в sandbox-среде ассистента НЕ компилировался и НЕ загружался.
 * Места, требующие сверки с WDK при сборке, помечены «СВЕРИТЬ:».
 *
 * Лестница решений зеркалит jammvpn_core::split::decide:
 *   hairpin -> LAN/bypass -> force_direct -> force_tunnel -> по приложению -> kill-switch.
 * Бинарные форматы (config, redirect-context) — crates/platform-windows/src/wfp/ipc.rs.
 */

#include "driver.h"

static PDEVICE_OBJECT gDeviceObject = NULL;
static HANDLE         gEngineHandle = NULL;
static UINT32         gCalloutIdV4  = 0;
static UINT32         gCalloutIdV6  = 0;
static HANDLE         gRedirectHandle = NULL;

static JAMM_CONFIG    gConfig = {0};
/* Защищает gConfig. KSPIN_LOCK (а не FAST_MUTEX/push-lock): classify слоёв
 * ALE_CONNECT_REDIRECT может вызываться вплоть до DISPATCH_LEVEL, где mutex/
 * push-lock запрещены. Под локом — только чтение/подмена полей конфига (память
 * из NonPagedPool); выделение/освобождение выполняется вне лока. */
static KSPIN_LOCK     gConfigLock;

/* Упреждающая декларация: используется в cleanup JammRegisterCallouts. */
static void JammUnregisterCallouts(void);

/* ======================================================================= */
/* Разбор конфига (формат encode_config из ipc.rs)                          */
/* ======================================================================= */

typedef struct _JAMM_READER {
    const UCHAR* p;
    SIZE_T       remaining;
    BOOLEAN      ok;
} JAMM_READER;

static const UCHAR* JammTake(JAMM_READER* r, SIZE_T n)
{
    if (!r->ok || r->remaining < n) { r->ok = FALSE; return NULL; }
    const UCHAR* s = r->p;
    r->p += n;
    r->remaining -= n;
    return s;
}

static UINT8 JammU8(JAMM_READER* r)
{
    const UCHAR* b = JammTake(r, 1);
    return b ? b[0] : 0;
}

static UINT16 JammU16(JAMM_READER* r)  /* little-endian, как push_u16 */
{
    const UCHAR* b = JammTake(r, 2);
    return b ? (UINT16)(b[0] | ((UINT16)b[1] << 8)) : 0;
}

static UINT32 JammU32(JAMM_READER* r)  /* little-endian, как push_u32 */
{
    const UCHAR* b = JammTake(r, 4);
    return b ? ((UINT32)b[0] | ((UINT32)b[1] << 8) | ((UINT32)b[2] << 16) | ((UINT32)b[3] << 24)) : 0;
}

/* Читает JAMM_IP: family(1) + 16 байт (v4 — в первых 4). */
static JAMM_IP JammReadIp(JAMM_READER* r)
{
    JAMM_IP ip = {0};
    UINT8 fam = JammU8(r);
    const UCHAR* b = JammTake(r, 16);
    if (b && (fam == 4 || fam == 6)) {
        ip.family = fam;
        RtlCopyMemory(ip.addr, b, 16);
    } else {
        r->ok = FALSE;
    }
    return ip;
}

/* Читает строку (len u16 + UTF-8) и конвертирует в UNICODE_STRING (нижний
 * регистр, Buffer из пула). При ошибке выставляет r->ok=FALSE. */
static UNICODE_STRING JammReadStr(JAMM_READER* r)
{
    UNICODE_STRING out = {0};
    UINT16 len = JammU16(r);
    const UCHAR* bytes = JammTake(r, len);
    if (!r->ok) return out;
    /* Пустая строка валидна (push_str допускает len==0) — возвращаем {0}. */
    if (len == 0) return out;

    ULONG wideBytes = 0;
    /* СВЕРИТЬ: RtlUTF8ToUnicodeN доступна в ядре (Windows 8+). */
    if (!NT_SUCCESS(RtlUTF8ToUnicodeN(NULL, 0, &wideBytes, (PCCH)bytes, len)) || wideBytes == 0) {
        r->ok = FALSE;
        return out;
    }
    PWCH buf = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, wideBytes, JAMM_POOL_TAG);
    if (!buf) { r->ok = FALSE; return out; }
    ULONG written = 0;
    if (!NT_SUCCESS(RtlUTF8ToUnicodeN(buf, wideBytes, &written, (PCCH)bytes, len))) {
        ExFreePoolWithTag(buf, JAMM_POOL_TAG);
        r->ok = FALSE;
        return out;
    }
    out.Buffer = buf;
    out.Length = (USHORT)written;
    out.MaximumLength = (USHORT)wideBytes;
    /* Нижний регистр для регистронезависимого сравнения с ALE_APP_ID. */
    for (USHORT i = 0; i < out.Length / sizeof(WCHAR); ++i) {
        out.Buffer[i] = RtlDowncaseUnicodeChar(out.Buffer[i]);
    }
    return out;
}

static JAMM_CIDR* JammReadCidrList(JAMM_READER* r, UINT16* outCount)
{
    UINT16 n = JammU16(r);
    *outCount = n;
    if (n == 0) return NULL;
    JAMM_CIDR* list = (JAMM_CIDR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                  (SIZE_T)n * sizeof(JAMM_CIDR), JAMM_POOL_TAG);
    if (!list) { r->ok = FALSE; *outCount = 0; return NULL; }
    for (UINT16 i = 0; i < n; ++i) {
        list[i].ip = JammReadIp(r);
        list[i].prefix = JammU8(r);
        if (!r->ok) break;
    }
    return list;
}

NTSTATUS JammParseConfig(_In_reads_bytes_(len) const UCHAR* buf, _In_ SIZE_T len, _Out_ PJAMM_CONFIG outCfg)
{
    RtlZeroMemory(outCfg, sizeof(*outCfg));
    JAMM_READER r = { buf, len, TRUE };

    const UCHAR* magic = JammTake(&r, 4);
    if (!magic || magic[0] != 'J' || magic[1] != 'V' || magic[2] != 'P' || magic[3] != '1')
        return STATUS_INVALID_PARAMETER;
    if (JammU16(&r) != 2)            /* версия формата (ipc.rs VERSION) */
        return STATUS_REVISION_MISMATCH;

    outCfg->mode = JammU8(&r);
    outCfg->killSwitch = JammU8(&r) != 0;
    outCfg->redirectPort = JammU16(&r);
    outCfg->redirectPid = JammU32(&r);

    /* приложения */
    UINT16 nApps = JammU16(&r);
    outCfg->appCount = nApps;
    if (nApps) {
        outCfg->apps = (JAMM_APP*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                  (SIZE_T)nApps * sizeof(JAMM_APP), JAMM_POOL_TAG);
        if (!outCfg->apps) { JammFreeConfig(outCfg); return STATUS_INSUFFICIENT_RESOURCES; }
        for (UINT16 i = 0; i < nApps; ++i) {
            outCfg->apps[i].byName = JammU8(&r) != 0;
            outCfg->apps[i].value = JammReadStr(&r);
            if (!r.ok) break;
        }
    }

    outCfg->bypass      = JammReadCidrList(&r, &outCfg->bypassCount);
    outCfg->forceDirect = JammReadCidrList(&r, &outCfg->forceDirectCount);
    outCfg->forceTunnel = JammReadCidrList(&r, &outCfg->forceTunnelCount);

    /* endpoints */
    UINT16 nEp = JammU16(&r);
    outCfg->endpointCount = nEp;
    if (nEp) {
        outCfg->endpoints = (JAMM_IP*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                      (SIZE_T)nEp * sizeof(JAMM_IP), JAMM_POOL_TAG);
        if (!outCfg->endpoints) { JammFreeConfig(outCfg); return STATUS_INSUFFICIENT_RESOURCES; }
        for (UINT16 i = 0; i < nEp; ++i) {
            outCfg->endpoints[i] = JammReadIp(&r);
            if (!r.ok) break;
        }
    }

    if (!r.ok) { JammFreeConfig(outCfg); return STATUS_INVALID_PARAMETER; }
    return STATUS_SUCCESS;
}

VOID JammFreeConfig(_Inout_ PJAMM_CONFIG cfg)
{
    if (cfg->apps) {
        for (UINT16 i = 0; i < cfg->appCount; ++i) {
            if (cfg->apps[i].value.Buffer)
                ExFreePoolWithTag(cfg->apps[i].value.Buffer, JAMM_POOL_TAG);
        }
        ExFreePoolWithTag(cfg->apps, JAMM_POOL_TAG);
    }
    if (cfg->bypass)      ExFreePoolWithTag(cfg->bypass, JAMM_POOL_TAG);
    if (cfg->forceDirect) ExFreePoolWithTag(cfg->forceDirect, JAMM_POOL_TAG);
    if (cfg->forceTunnel) ExFreePoolWithTag(cfg->forceTunnel, JAMM_POOL_TAG);
    if (cfg->endpoints)   ExFreePoolWithTag(cfg->endpoints, JAMM_POOL_TAG);
    RtlZeroMemory(cfg, sizeof(*cfg));
}

/* ======================================================================= */
/* Сопоставление IP/CIDR/приложений (зеркало core::split)                   */
/* ======================================================================= */

static BOOLEAN JammIpEqual(const JAMM_IP* a, const JAMM_IP* b)
{
    return a->family == b->family && RtlEqualMemory(a->addr, b->addr, 16);
}

/* Входит ли ip в cidr (зеркало v4_match/v6_match: сравнить первые prefix бит). */
static BOOLEAN JammCidrContains(const JAMM_CIDR* c, const JAMM_IP* ip)
{
    if (c->ip.family != ip->family) return FALSE;
    UINT8 maxBits = (ip->family == 4) ? 32 : 128;
    UINT8 prefix = c->prefix > maxBits ? maxBits : c->prefix;
    UINT8 fullBytes = prefix / 8;
    UINT8 remBits = prefix % 8;
    if (fullBytes && !RtlEqualMemory(c->ip.addr, ip->addr, fullBytes)) return FALSE;
    if (remBits) {
        UINT8 mask = (UINT8)(0xFF << (8 - remBits));
        if ((c->ip.addr[fullBytes] & mask) != (ip->addr[fullBytes] & mask)) return FALSE;
    }
    return TRUE;
}

static BOOLEAN JammIpInList(const JAMM_CIDR* list, UINT16 count, const JAMM_IP* ip)
{
    for (UINT16 i = 0; i < count; ++i)
        if (JammCidrContains(&list[i], ip)) return TRUE;
    return FALSE;
}

static BOOLEAN JammIpInEndpoints(const JAMM_IP* list, UINT16 count, const JAMM_IP* ip)
{
    for (UINT16 i = 0; i < count; ++i)
        if (JammIpEqual(&list[i], ip)) return TRUE;
    return FALSE;
}

/* Заканчивается ли строка hay (нижний регистр) на suffix (нижний регистр). */
static BOOLEAN JammEndsWithCi(PCUNICODE_STRING hay, PCUNICODE_STRING suffix)
{
    if (suffix->Length == 0 || suffix->Length > hay->Length) return FALSE;
    USHORT off = (hay->Length - suffix->Length) / sizeof(WCHAR);
    UNICODE_STRING tail;
    tail.Buffer = hay->Buffer + off;
    tail.Length = suffix->Length;
    tail.MaximumLength = suffix->Length;
    /* hay уже в нижнем регистре (ALE_APP_ID мы lowercase'им перед вызовом),
     * suffix — из конфига, тоже lowercase. Сравнение точное. */
    return RtlEqualUnicodeString(&tail, suffix, FALSE);
}

/* Совпадает ли appId (нижний регистр, NT-путь образа) с одним из приложений.
 * byName: appId оканчивается на "\<имя>" или == имя.
 * exe:    appId оканчивается на путь без буквы диска (ALE_APP_ID — NT-путь
 *         \device\harddiskvolumeN\..., а конфиг хранит Win32-путь C:\...; берём
 *         совпадение по хвосту). СВЕРИТЬ: при необходимости — точная
 *         Win32→NT конвертация пути. */
static BOOLEAN JammAppSelected(PCUNICODE_STRING appIdLower)
{
    for (UINT16 i = 0; i < gConfig.appCount; ++i) {
        const JAMM_APP* a = &gConfig.apps[i];
        if (a->byName) {
            if (RtlEqualUnicodeString(appIdLower, &a->value, FALSE)) return TRUE;
            /* хвост "\имя" */
            UNICODE_STRING sep; WCHAR sepBuf[1] = { L'\\' };
            sep.Buffer = sepBuf; sep.Length = sizeof(WCHAR); sep.MaximumLength = sizeof(WCHAR);
            if (a->value.Length + sizeof(WCHAR) <= appIdLower->Length) {
                USHORT off = (appIdLower->Length - a->value.Length) / sizeof(WCHAR);
                WCHAR sepCh = (off > 0) ? appIdLower->Buffer[off - 1] : 0;
                if ((sepCh == L'\\' || sepCh == L'/') && JammEndsWithCi(appIdLower, &a->value))
                    return TRUE;
            }
        } else {
            /* exe-путь: убираем "C:" (первые 2 wchar, если второй == ':') и
             * сверяем хвост. */
            UNICODE_STRING v = a->value;
            if (v.Length >= 2 * sizeof(WCHAR) && v.Buffer[1] == L':') {
                v.Buffer += 2;
                v.Length -= 2 * sizeof(WCHAR);
            }
            if (JammEndsWithCi(appIdLower, &v)) return TRUE;
        }
    }
    return FALSE;
}

/* Встроенный bypass: LAN/loopback/служебные — НИКОГДА не туннелировать (зеркало
 * ALWAYS_BYPASS_CIDRS, который в core гарантирован compile-time). Не зависим от
 * того, прислал ли их user-mode. addr — сетевой порядок, незаданные байты = 0. */
static const JAMM_CIDR gBuiltinBypass[] = {
    { { 4, { 10 } },                 8  },   /* 10.0.0.0/8 */
    { { 4, { 172, 16 } },            12 },   /* 172.16.0.0/12 */
    { { 4, { 192, 168 } },           16 },   /* 192.168.0.0/16 */
    { { 4, { 127 } },                8  },   /* 127.0.0.0/8 loopback */
    { { 4, { 169, 254 } },           16 },   /* 169.254.0.0/16 link-local */
    { { 4, { 224 } },                4  },   /* 224.0.0.0/4 multicast */
    { { 4, { 255, 255, 255, 255 } }, 32 },   /* 255.255.255.255/32 broadcast */
    { { 6, { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } }, 128 }, /* ::1/128 loopback */
    { { 6, { 0xfe, 0x80 } },         10 },   /* fe80::/10 link-local */
    { { 6, { 0xfc } },               7  },   /* fc00::/7 ULA */
    { { 6, { 0xff } },               8  },   /* ff00::/8 multicast */
};

/* Лестница решений под уже взятым локом конфига. */
static JAMM_DECISION JammDecide(PCUNICODE_STRING appIdLower, const JAMM_IP* remote)
{
    if (JammIpInEndpoints(gConfig.endpoints, gConfig.endpointCount, remote))
        return JAMM_DIRECT;                                   /* hairpin */
    if (JammIpInList(gBuiltinBypass, RTL_NUMBER_OF(gBuiltinBypass), remote))
        return JAMM_DIRECT;                                   /* встроенный LAN/loopback bypass */
    if (JammIpInList(gConfig.bypass, gConfig.bypassCount, remote))
        return JAMM_DIRECT;                                   /* доп. bypass из конфига */
    if (JammIpInList(gConfig.forceDirect, gConfig.forceDirectCount, remote))
        return JAMM_DIRECT;
    if (JammIpInList(gConfig.forceTunnel, gConfig.forceTunnelCount, remote))
        return JAMM_TUNNEL;

    BOOLEAN selected = JammAppSelected(appIdLower);
    /* Шаг 6 decide() (kill-switch при tunnel_down → Block, иначе Direct) здесь НЕ
     * моделируется: драйвер не получает сигнал готовности тоннеля. Реальный
     * kill-switch — через отдельные block-фильтры (см. README, «осталось»). При
     * недоступном прокси перенаправлённое соединение и так не установится; жёсткий
     * BLOCK выдаётся лишь при сбое самого redirect (см. JammClassify). */
    if (gConfig.mode == 0)   /* inclusive */
        return selected ? JAMM_TUNNEL : JAMM_DIRECT;
    else                     /* exclusive */
        return selected ? JAMM_DIRECT : JAMM_TUNNEL;
}

/* ======================================================================= */
/* WFP classify / notify                                                    */
/* ======================================================================= */

/* Заполняет JAMM_IP и redirect-context (19 байт) из значений слоя. */
static void JammBuildDst(BOOLEAN isV4, const FWPS_INCOMING_VALUES* in,
                         JAMM_IP* outIp, UINT16* outPortHost, UCHAR ctx[JAMM_REDIRECT_CONTEXT_LEN])
{
    RtlZeroMemory(outIp, sizeof(*outIp));
    RtlZeroMemory(ctx, JAMM_REDIRECT_CONTEXT_LEN);
    UINT16 port;
    if (isV4) {
        UINT32 v4 = in->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        port = in->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;
        outIp->family = 4;
        outIp->addr[0] = (UCHAR)(v4 >> 24);   /* host order -> сетевой порядок байт */
        outIp->addr[1] = (UCHAR)(v4 >> 16);
        outIp->addr[2] = (UCHAR)(v4 >> 8);
        outIp->addr[3] = (UCHAR)(v4);
        ctx[0] = 4;
        RtlCopyMemory(&ctx[1], outIp->addr, 4);
    } else {
        const UINT8* v6 = in->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16;
        port = in->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT].value.uint16;
        outIp->family = 6;
        RtlCopyMemory(outIp->addr, v6, 16);
        ctx[0] = 6;
        RtlCopyMemory(&ctx[1], v6, 16);
    }
    *outPortHost = port;
    ctx[17] = (UCHAR)(port >> 8);   /* port, big-endian (encode_redirect_context) */
    ctx[18] = (UCHAR)(port);
}

static void NTAPI JammClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    BOOLEAN isV4 = (inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4);

    /* Не наделены правом писать решение — выходим. */
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
        return;

    /* Не перенаправлять повторно собственный уже-перенаправленный сокет. */
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)) {
        FWPS_CONNECTION_REDIRECT_STATE st =
            FwpsQueryConnectionRedirectState0(inMetaValues->redirectRecords, gRedirectHandle, NULL);
        if (st == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
            st == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
    }

    /* ALE_APP_ID -> UNICODE_STRING (нижний регистр) для сравнения. */
    UNICODE_STRING appId = {0};
    UINT16 appIdField = isV4 ? FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID
                             : FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID;
    if (inFixedValues->incomingValue[appIdField].value.type == FWP_BYTE_BLOB_TYPE) {
        FWP_BYTE_BLOB* blob = inFixedValues->incomingValue[appIdField].value.byteBlob;
        if (blob && blob->data) {
            appId.Buffer = (PWCH)blob->data;
            appId.Length = (USHORT)blob->size;
            appId.MaximumLength = (USHORT)blob->size;
        }
    }
    /* Локальная нижне-регистровая копия appId (не мутируем буфер WFP). */
    UNICODE_STRING appLower = {0};
    if (appId.Length) {
        appLower.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, appId.Length, JAMM_POOL_TAG);
        if (appLower.Buffer) {
            appLower.Length = appId.Length;
            appLower.MaximumLength = appId.Length;
            for (USHORT i = 0; i < appId.Length / sizeof(WCHAR); ++i)
                appLower.Buffer[i] = RtlDowncaseUnicodeChar(appId.Buffer[i]);
        }
    }

    JAMM_IP remote; UINT16 portHost; UCHAR ctx[JAMM_REDIRECT_CONTEXT_LEN];
    JammBuildDst(isV4, inFixedValues, &remote, &portHost, ctx);

    JAMM_DECISION decision;
    UINT16 redirectPort;
    BOOLEAN killSwitch;

    KIRQL irql;
    KeAcquireSpinLock(&gConfigLock, &irql);
    decision = JammDecide(&appLower, &remote);
    redirectPort = gConfig.redirectPort;
    killSwitch = gConfig.killSwitch;
    KeReleaseSpinLock(&gConfigLock, irql);

    if (appLower.Buffer) ExFreePoolWithTag(appLower.Buffer, JAMM_POOL_TAG);

    if (decision == JAMM_BLOCK) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }
    if (decision == JAMM_DIRECT || redirectPort == 0) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    /* === ветка TUNNEL: connect-redirect на 127.0.0.1:redirectPort === */
    /* Для записи решения на слое нужен classify-handle. */
    UINT64 classifyHandle = 0;
    NTSTATUS status = FwpsAcquireClassifyHandle0((void*)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) {
        classifyOut->actionType = killSwitch ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
        if (killSwitch) classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    void* writable = NULL;
    status = FwpsAcquireWritableLayerDataPointer0(
        classifyHandle, filter->filterId, 0, &writable, classifyOut);
    if (!NT_SUCCESS(status) || writable == NULL) {
        /* Не смогли перенаправить: kill-switch -> BLOCK, иначе пропускаем. */
        FwpsReleaseClassifyHandle0(classifyHandle);
        classifyOut->actionType = killSwitch ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
        if (killSwitch) classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    FWPS_CONNECT_REQUEST0* cr = (FWPS_CONNECT_REQUEST0*)writable;

    /* Переписываем удалённый адрес на loopback:redirectPort. */
    if (isV4) {
        SOCKADDR_IN* sin = (SOCKADDR_IN*)&cr->remoteAddressAndPort;
        sin->sin_family = AF_INET;
        sin->sin_addr.S_un.S_addr = RtlUlongByteSwap(INADDR_LOOPBACK); /* 127.0.0.1, сетевой порядок */
        sin->sin_port = RtlUshortByteSwap(redirectPort);
    } else {
        SOCKADDR_IN6* sin6 = (SOCKADDR_IN6*)&cr->remoteAddressAndPort;
        sin6->sin6_family = AF_INET6;
        RtlZeroMemory(&sin6->sin6_addr, sizeof(sin6->sin6_addr));
        sin6->sin6_addr.u.Byte[15] = 1;                                /* ::1 */
        sin6->sin6_port = RtlUshortByteSwap(redirectPort);
    }

    /* PID процесса, принимающего перенаправленное на localhost соединение
     * (требование connect-redirect). TODO: пробросить реальный PID прокси через
     * IOCTL-конфиг; сейчас прокси и драйвер-клиент — один процесс jammvpn-app. */
    cr->localRedirectTargetPID = gConfig.redirectPid;

    /* redirect-context: original-dst (19 байт), который прокси прочитает через
     * SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT. WFP НЕ делает глубокую копию —
     * буфер должен жить до завершения перенаправленного соединения. ВАЖНО: НЕ
     * освобождать его здесь (синхронный free → use-after-free у прокси). Владение
     * передаётся WFP; освобождение — на teardown соединения/redirect-handle.
     * ДОРАБОТАТЬ по WDK-примеру connect-redirect (flow-delete notify / cleanup
     * classify-context); до этого — контролируемая утечка на соединение, что
     * безопаснее UAF. */
    UCHAR* ctxBuf = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, JAMM_REDIRECT_CONTEXT_LEN, JAMM_POOL_TAG);
    if (ctxBuf) {
        RtlCopyMemory(ctxBuf, ctx, JAMM_REDIRECT_CONTEXT_LEN);
        cr->localRedirectHandle = gRedirectHandle;
        cr->localRedirectContext = ctxBuf;
        cr->localRedirectContextSize = JAMM_REDIRECT_CONTEXT_LEN;
    }

    FwpsApplyModifiedLayerData0(classifyHandle, writable, 0);
    FwpsReleaseClassifyHandle0(classifyHandle);
    /* ctxBuf НЕ освобождаем — владение передано WFP. */

    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
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

/* ======================================================================= */
/* Регистрация / снятие каллаутов (одна транзакция)                         */
/* ======================================================================= */

static NTSTATUS JammAddCallout(PDEVICE_OBJECT dev, const GUID* calloutKey, UINT16 layerId, UINT32* outId)
{
    FWPS_CALLOUT3 sCallout = {0};
    sCallout.calloutKey = *calloutKey;
    sCallout.classifyFn = JammClassify;
    sCallout.notifyFn = JammNotify;
    NTSTATUS status = FwpsCalloutRegister3(dev, &sCallout, outId);
    if (!NT_SUCCESS(status)) return status;

    FWPM_CALLOUT0 mCallout = {0};
    mCallout.calloutKey = *calloutKey;
    mCallout.applicableLayer = (layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4)
        ? FWPM_LAYER_ALE_CONNECT_REDIRECT_V4 : FWPM_LAYER_ALE_CONNECT_REDIRECT_V6;
    mCallout.providerKey = (GUID*)&JAMM_PROVIDER_GUID;
    return FwpmCalloutAdd0(gEngineHandle, &mCallout, NULL, NULL);
}

static NTSTATUS JammAddRedirectFilter(const GUID* layerKey, const GUID* calloutKey)
{
    FWPM_FILTER0 filter = {0};
    filter.layerKey = *layerKey;
    filter.subLayerKey = JAMM_SUBLAYER_GUID;
    filter.providerKey = (GUID*)&JAMM_PROVIDER_GUID;
    filter.weight.type = FWP_EMPTY;                     /* авто-вес */
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING; /* каллаут всегда даёт PERMIT/BLOCK */
    filter.action.calloutKey = *calloutKey;
    filter.numFilterConditions = 0;                  /* весь трафик слоя -> каллаут */
    return FwpmFilterAdd0(gEngineHandle, &filter, NULL, NULL);
}

static NTSTATUS JammRegisterCallouts(_In_ PDEVICE_OBJECT deviceObject)
{
    NTSTATUS status;
    BOOLEAN inTransaction = FALSE;

    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;       /* объекты снимутся при закрытии хендла */
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &gEngineHandle);
    if (!NT_SUCCESS(status)) return status;

    status = FwpsRedirectHandleCreate0(&JAMM_PROVIDER_GUID, 0, &gRedirectHandle);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = FwpmTransactionBegin0(gEngineHandle, 0);
    if (!NT_SUCCESS(status)) goto cleanup;
    inTransaction = TRUE;

    FWPM_PROVIDER0 provider = {0};
    provider.providerKey = JAMM_PROVIDER_GUID;
    provider.displayData.name = L"JammVPN";
    status = FwpmProviderAdd0(gEngineHandle, &provider, NULL);
    if (!NT_SUCCESS(status)) goto cleanup;

    FWPM_SUBLAYER0 sub = {0};
    sub.subLayerKey = JAMM_SUBLAYER_GUID;
    sub.displayData.name = L"JammVPN split";
    sub.providerKey = (GUID*)&JAMM_PROVIDER_GUID;
    sub.weight = 0x8000;                              /* высокий вес */
    status = FwpmSubLayerAdd0(gEngineHandle, &sub, NULL);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = JammAddCallout(deviceObject, &JAMM_CALLOUT_V4_GUID, FWPS_LAYER_ALE_CONNECT_REDIRECT_V4, &gCalloutIdV4);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = JammAddCallout(deviceObject, &JAMM_CALLOUT_V6_GUID, FWPS_LAYER_ALE_CONNECT_REDIRECT_V6, &gCalloutIdV6);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = JammAddRedirectFilter(&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, &JAMM_CALLOUT_V4_GUID);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = JammAddRedirectFilter(&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, &JAMM_CALLOUT_V6_GUID);
    if (!NT_SUCCESS(status)) goto cleanup;

    /* СВЕРИТЬ/ДОБАВИТЬ: отдельные фильтры-исключения hairpin/LAN с большим весом
     * и kill-switch block-фильтры (SPL-30..34). Сейчас исключения учтены в
     * лестнице JammDecide (PERMIT), что покрывает базовый сценарий. */

    status = FwpmTransactionCommit0(gEngineHandle);
    if (!NT_SUCCESS(status)) goto cleanup;
    return STATUS_SUCCESS;

cleanup:
    if (inTransaction) FwpmTransactionAbort0(gEngineHandle);
    JammUnregisterCallouts();
    return status;
}

static void JammUnregisterCallouts(void)
{
    if (gCalloutIdV4) { FwpsCalloutUnregisterById0(gCalloutIdV4); gCalloutIdV4 = 0; }
    if (gCalloutIdV6) { FwpsCalloutUnregisterById0(gCalloutIdV6); gCalloutIdV6 = 0; }
    if (gRedirectHandle) { FwpsRedirectHandleDestroy0(gRedirectHandle); gRedirectHandle = NULL; }
    if (gEngineHandle) {
        /* Динамическая сессия снимает provider/sublayer/callouts/filters при
         * закрытии хендла (страховка от «сирот», SPL-39/41). */
        FwpmEngineClose0(gEngineHandle);
        gEngineHandle = NULL;
    }
}

/* ======================================================================= */
/* IRP / IOCTL                                                              */
/* ======================================================================= */

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
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case JAMM_IOCTL_SET_CONFIG: {
        JAMM_CONFIG parsed;
        status = JammParseConfig((const UCHAR*)Irp->AssociatedIrp.SystemBuffer, inLen, &parsed);
        if (NT_SUCCESS(status)) {
            /* Атомарная замена под локом; старый конфиг освобождаем после
             * (вне лока — JammFreeConfig вызывает ExFreePool). */
            KIRQL irql;
            KeAcquireSpinLock(&gConfigLock, &irql);
            JAMM_CONFIG old = gConfig;
            gConfig = parsed;
            KeReleaseSpinLock(&gConfigLock, irql);
            JammFreeConfig(&old);
        }
        break;
    }
    case JAMM_IOCTL_CLEAR: {
        KIRQL irql;
        KeAcquireSpinLock(&gConfigLock, &irql);
        JAMM_CONFIG old = gConfig;
        RtlZeroMemory(&gConfig, sizeof(gConfig));
        KeReleaseSpinLock(&gConfigLock, irql);
        JammFreeConfig(&old);
        status = STATUS_SUCCESS;
        break;
    }
    case JAMM_IOCTL_GET_STATS:
        /* TODO: статистика (SPL-54). */
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

/* ======================================================================= */
/* entry / unload                                                           */
/* ======================================================================= */

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING deviceName, symlinkName;

    KeInitializeSpinLock(&gConfigLock);

    RtlInitUnicodeString(&deviceName, JAMM_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_NETWORK,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &gDeviceObject);
    if (!NT_SUCCESS(status)) return status;

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

    status = JammRegisterCallouts(gDeviceObject);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symlinkName);
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

VOID JammUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING symlinkName;

    JammUnregisterCallouts();

    KIRQL irql;
    KeAcquireSpinLock(&gConfigLock, &irql);
    JAMM_CONFIG old = gConfig;
    RtlZeroMemory(&gConfig, sizeof(gConfig));
    KeReleaseSpinLock(&gConfigLock, irql);
    JammFreeConfig(&old);

    RtlInitUnicodeString(&symlinkName, JAMM_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (gDeviceObject != NULL) {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
    }
}

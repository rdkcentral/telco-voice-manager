/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/*
 * DHCP driven voice provisioning.
 *
 * Replaces the VOICE_MTA_SUPPORT block that used to live in ccsp-mta-agent and
 * talked to the vendor stack through the out of tree voice_dhcp_hal.h header.
 * Everything here goes over the telcovoice JSON HAL instead, so the vendor
 * contract is the schema in /etc/rdk/schemas/telcovoice_hal_schema.json and
 * nothing else.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <pthread.h>
#include <unistd.h>

#include "ansc_platform.h"
#include "ccsp_psm_helper.h"
#include "ipc_msg.h"
#include "syscfg/syscfg.h"
#include "telcovoicemgr_dhcp_voice.h"
#include "telcovoicemgr_dml_hal.h"
#include "telemetry_busmessage_sender.h"

#ifdef RBUS_BUILD_FLAG_ENABLE
#include <rbus.h>
#endif

#define VOICE_ROUTE_TABLE_NAME    "VOICE"
#define RT_TABLES_FILE            "/etc/iproute2/rt_tables"

#define DHCPV4_VOICE_PSM_PARAM    "dmsb.voicesupport.Interface.IP.DHCPV4Interface"
#define DHCP_MGR_DHCPV4_TABLE     "Device.DHCPv4.Client"
#define DEFAULT_VOICE_IFNAME      "mta0"

/* Members of Device.Services.VoiceService.{i}.X_RDK_SysAccess. */
#define SYSACCESS_PARAM_FMT       "Device.Services.VoiceService.%d.X_RDK_SysAccess.X_RDK_%s"

#define VOICE_SERVICE_INDEX       1
#define OPTION122_SUBOPT_PROV_SRV 3
#define DNS_SERVERS_BUF_LEN       256

extern ANSC_HANDLE bus_handle;

static const char g_subsystem[] = "eRT.";
static char g_dhcpv4ClientPath[64] = {0};
static char g_voiceIfName[IFNAMSIZ] = {0};
static pthread_mutex_t g_dhcpEventMutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef RBUS_BUILD_FLAG_ENABLE
static rbusHandle_t g_dhcpVoiceRbusHandle = NULL;
#endif

/*
 * @brief Reject anything that is not a plain interface name before it reaches a shell.
 */
static BOOL isSafeIfName(const char *pIfName)
{
    size_t i;

    if (NULL == pIfName || '\0' == pIfName[0] || strlen(pIfName) >= IFNAMSIZ)
    {
        return FALSE;
    }

    for (i = 0; pIfName[i] != '\0'; i++)
    {
        if (!isalnum((unsigned char)pIfName[i]) &&
            pIfName[i] != '.' && pIfName[i] != '_' && pIfName[i] != '-' && pIfName[i] != ':')
        {
            return FALSE;
        }
    }

    return TRUE;
}

/*
 * @brief Reject anything that is not a dotted quad before it reaches a shell.
 */
static BOOL isSafeIpv4(const char *pAddr)
{
    struct in_addr addr;

    return (NULL != pAddr && '\0' != pAddr[0] && inet_pton(AF_INET, pAddr, &addr) == 1) ? TRUE : FALSE;
}

/*
 * @brief Map the "VoiceSupport_Mode" syscfg value onto X_RDK_IpAddressFamily.
 */
static const char *voiceModeToAddressFamily(const char *pMode)
{
    if (NULL == pMode)
    {
        return NULL;
    }
    if (0 == strcmp(pMode, "IPv4_Only"))
    {
        return "IPv4";
    }
    if (0 == strcmp(pMode, "IPv6_Only"))
    {
        return "IPv6";
    }
    if (0 == strcmp(pMode, "Dual_Stack"))
    {
        return "Dual";
    }
    return NULL;
}

/*
 * @brief Queue one X_RDK_SysAccess string member onto a setParameters request.
 */
static void addSysAccessString(json_object *jmsg, const char *pMember, const char *pValue)
{
    hal_param_t param;

    if (NULL == jmsg || NULL == pMember || NULL == pValue)
    {
        return;
    }

    memset(&param, 0, sizeof(param));
    snprintf(param.name, sizeof(param.name), SYSACCESS_PARAM_FMT, VOICE_SERVICE_INDEX, pMember);
    snprintf(param.value, sizeof(param.value), "%s", pValue);
    param.type = PARAM_STRING;
    json_hal_add_param(jmsg, SET_REQUEST_MESSAGE, &param);
}

/*
 * @brief Queue one X_RDK_SysAccess boolean member onto a setParameters request.
 */
static void addSysAccessBool(json_object *jmsg, const char *pMember, BOOL bValue)
{
    hal_param_t param;

    if (NULL == jmsg || NULL == pMember)
    {
        return;
    }

    memset(&param, 0, sizeof(param));
    snprintf(param.name, sizeof(param.name), SYSACCESS_PARAM_FMT, VOICE_SERVICE_INDEX, pMember);
    snprintf(param.value, sizeof(param.value), "%s", bValue ? JSON_STR_TRUE : JSON_STR_FALSE);
    param.type = PARAM_BOOLEAN;
    json_hal_add_param(jmsg, SET_REQUEST_MESSAGE, &param);
}

/*
 * @brief Convert a hexadecimal string into its byte array representation.
 */
static void hexStringToByteArray(const char *pHexString, uint8_t *pByteArray, size_t byteArrayLen)
{
    size_t hexStringLen;
    size_t index;

    if (NULL == pHexString || NULL == pByteArray || 0 == byteArrayLen)
    {
        return;
    }

    hexStringLen = strlen(pHexString);
    for (index = 0; index < byteArrayLen && (index * 2 + 1) < hexStringLen; index++)
    {
        sscanf(&pHexString[index * 2], "%2hhx", &pByteArray[index]);
    }
}

/*
 * @brief Walk the DHCP option 122 TLV list and return the requested sub-option.
 *
 * @return 0 when the sub-option was found, -1 otherwise.
 */
static int getOption122SubOption(const uint8_t *pData, uint16_t dataLen, uint8_t wantedSubOption,
                                 const uint8_t **ppValue, uint8_t *pValueLen)
{
    uint16_t position = 0;

    if (NULL == pData || 0 == dataLen || NULL == ppValue || NULL == pValueLen)
    {
        return -1;
    }

    while (position + 2 <= dataLen)
    {
        uint8_t subOption = pData[position];
        uint8_t subOptionLen = pData[position + 1];

        if (position + 2 + subOptionLen > dataLen)
        {
            CcspTraceError(("%s: malformed option 122 payload\n", __FUNCTION__));
            return -1;
        }

        if (subOption == wantedSubOption)
        {
            *ppValue = &pData[position + 2];
            *pValueLen = subOptionLen;
            return 0;
        }

        position += 2 + subOptionLen;
    }

    return -1;
}

/*
 * @brief Install the source based routing that keeps voice traffic on the voice interface.
 *
 * Table VOICE is owned entirely by this function, so it is flushed and rebuilt on
 * every lease change. Only proto static routes are touched in the main table.
 */
static void applyVoicePolicyRoutes(const DHCP_MGR_IPV4_MSG *pLease, const char *pIfName,
                                   DHCP_MESSAGE_TYPE msgType)
{
    char cmd[256] = {0};
    char networkAddr[INET_ADDRSTRLEN] = {0};
    char networkAddrCidr[INET_ADDRSTRLEN + 8] = {0};
    struct in_addr ipAddr, netMask, network;

    if (NULL == pLease || !isSafeIfName(pIfName))
    {
        CcspTraceError(("%s: invalid lease or interface name\n", __FUNCTION__));
        return;
    }

    /* The lease contents come from the network, never hand them to a shell unvalidated. */
    if (!isSafeIpv4(pLease->address) || !isSafeIpv4(pLease->netmask) || !isSafeIpv4(pLease->gateway))
    {
        CcspTraceError(("%s: lease for %s has a malformed address/netmask/gateway\n", __FUNCTION__, pIfName));
        return;
    }

    if (access(RT_TABLES_FILE, R_OK) != 0)
    {
        CcspTraceError(("%s: %s not accessible: %s\n", __FUNCTION__, RT_TABLES_FILE, strerror(errno)));
        return;
    }

    inet_pton(AF_INET, pLease->address, &ipAddr);
    inet_pton(AF_INET, pLease->netmask, &netMask);
    network.s_addr = ipAddr.s_addr & netMask.s_addr;
    inet_ntop(AF_INET, &network, networkAddr, sizeof(networkAddr));
    snprintf(networkAddrCidr, sizeof(networkAddrCidr), "%s/%d",
             networkAddr, __builtin_popcount(ntohl(netMask.s_addr)));

    snprintf(cmd, sizeof(cmd), "ip rule flush table %s 2>/dev/null", VOICE_ROUTE_TABLE_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip route flush table %s 2>/dev/null", VOICE_ROUTE_TABLE_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip route flush dev %s proto static 2>/dev/null", pIfName);
    system(cmd);

    if (DHCP_LEASE_DEL == msgType || DHCP_CLIENT_STOPPED == msgType || DHCP_CLIENT_FAILED == msgType)
    {
        CcspTraceInfo(("%s: lease gone on %s, voice routes flushed\n", __FUNCTION__, pIfName));
        return;
    }

    snprintf(cmd, sizeof(cmd), "ip route add %s dev %s proto static", pLease->gateway, pIfName);
    system(cmd);

    if (isSafeIpv4(pLease->cTftpServer))
    {
        snprintf(cmd, sizeof(cmd), "ip route add %s via %s dev %s proto static",
                 pLease->cTftpServer, pLease->gateway, pIfName);
        system(cmd);
    }

    snprintf(cmd, sizeof(cmd), "ip rule add from %s table %s", pLease->address, VOICE_ROUTE_TABLE_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip route add %s dev %s src %s table %s",
             networkAddrCidr, pIfName, pLease->address, VOICE_ROUTE_TABLE_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip route add default via %s dev %s table %s",
             pLease->gateway, pIfName, VOICE_ROUTE_TABLE_NAME);
    system(cmd);

    CcspTraceInfo(("%s: voice routes installed on %s (addr %s, gw %s, net %s)\n",
                   __FUNCTION__, pIfName, pLease->address, pLease->gateway, networkAddrCidr));
}

/*
 * @brief Push the DHCPv4 provisioning snapshot to the vendor voice stack.
 *
 * This is the JSON HAL replacement for voice_hal_interface_info_notify(). All
 * members go out in a single setParameters request so the vendor stack sees a
 * consistent snapshot.
 */
static void pushDhcpv4Snapshot(const DHCP_MGR_IPV4_MSG *pLease, const char *pIfName)
{
    json_object *jmsg = NULL;
    char dnsServers[DNS_SERVERS_BUF_LEN] = {0};
    char provServer[BUFLEN_256] = {0};

    if (NULL == pLease || NULL == pIfName)
    {
        return;
    }

    jmsg = json_hal_client_get_request_header(SET_PARAMETER_METHOD);
    if (NULL == jmsg)
    {
        CcspTraceError(("%s: failed to build setParameters request\n", __FUNCTION__));
        return;
    }

    snprintf(dnsServers, sizeof(dnsServers), "%s", pLease->dnsServer);
    if (pLease->dnsServer1[0] != '\0')
    {
        size_t used = strlen(dnsServers);
        snprintf(dnsServers + used, sizeof(dnsServers) - used, "%s%s",
                 (used > 0) ? "," : "", pLease->dnsServer1);
    }

    /* Option 122 sub-option 3 carries the provisioning server. */
    {
        uint16_t option122Len = (uint16_t)(strlen(pLease->cOption122) / 2);
        if (option122Len > 0)
        {
            uint8_t option122[BUFLEN_256 / 2] = {0};
            const uint8_t *pSubOpt = NULL;
            uint8_t subOptLen = 0;

            if (option122Len > sizeof(option122))
            {
                option122Len = sizeof(option122);
            }
            hexStringToByteArray(pLease->cOption122, option122, option122Len);

            if (0 == getOption122SubOption(option122, option122Len, OPTION122_SUBOPT_PROV_SRV,
                                           &pSubOpt, &subOptLen))
            {
                size_t copyLen = (subOptLen < sizeof(provServer) - 1) ? subOptLen : sizeof(provServer) - 1;
                memcpy(provServer, pSubOpt, copyLen);
                provServer[copyLen] = '\0';
            }
            else
            {
                CcspTraceWarning(("%s: option 122 sub-option 3 not present\n", __FUNCTION__));
            }
        }
    }

    addSysAccessString(jmsg, "IfName", pIfName);
    addSysAccessBool(jmsg, "IsPhyUp", TRUE);
    addSysAccessBool(jmsg, "IsIpv4Up", TRUE);
    addSysAccessString(jmsg, "Ipv4Addr", pLease->address);
    addSysAccessString(jmsg, "Ipv4NextServerIp", pLease->cTftpServer);
    addSysAccessString(jmsg, "Ipv4BootFileName", pLease->cOption67);
    addSysAccessString(jmsg, "Ipv4DnsServers", dnsServers);
    addSysAccessString(jmsg, "Ipv4HostName", pLease->cHostName);
    addSysAccessString(jmsg, "Ipv4DomainName", pLease->cDomainName);
    addSysAccessString(jmsg, "Ipv4ProvServer", provServer);

    CcspTraceInfo(("%s: pushing DHCPv4 snapshot for %s: addr=%s tftp=%s bootfile=%s dns=%s prov=%s\n",
                   __FUNCTION__, pIfName, pLease->address, pLease->cTftpServer,
                   pLease->cOption67, dnsServers, provServer));

    if (TelcoVoiceMgrHal_SendJsonRequest(jmsg) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s: failed to push DHCPv4 snapshot for %s\n", __FUNCTION__, pIfName));
        t2_event_d("Failed to initialize the voice support", 1);
        return;
    }

    if (pLease->address[0] != '\0')
    {
        t2_event_d("IPv4 address assigned for MTA interface", 1);
    }
}

/*
 * @brief Tell the vendor voice stack that the IPv4 link is gone.
 */
static void pushDhcpv4Down(const char *pIfName)
{
    json_object *jmsg = json_hal_client_get_request_header(SET_PARAMETER_METHOD);

    if (NULL == jmsg)
    {
        return;
    }

    addSysAccessString(jmsg, "IfName", pIfName);
    addSysAccessBool(jmsg, "IsIpv4Up", FALSE);
    addSysAccessString(jmsg, "Ipv4Addr", "");

    CcspTraceInfo(("%s: reporting IPv4 down on %s\n", __FUNCTION__, pIfName));

    if (TelcoVoiceMgrHal_SendJsonRequest(jmsg) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s: failed to report IPv4 down on %s\n", __FUNCTION__, pIfName));
    }
}

#ifdef RBUS_BUILD_FLAG_ENABLE

/*
 * @brief Read the DHCPv4 client instance that serves the voice interface from PSM.
 */
static void resolveDhcpv4ClientPath(void)
{
    char *pParamValue = NULL;

    if (PSM_Get_Record_Value2(bus_handle, g_subsystem, DHCPV4_VOICE_PSM_PARAM, NULL, &pParamValue) != CCSP_SUCCESS ||
        NULL == pParamValue || '\0' == pParamValue[0])
    {
        CcspTraceWarning(("%s: %s unavailable, falling back to %s\n",
                          __FUNCTION__, DHCPV4_VOICE_PSM_PARAM, DHCP_MGR_DHCPV4_TABLE));
        snprintf(g_dhcpv4ClientPath, sizeof(g_dhcpv4ClientPath), "%s", DHCP_MGR_DHCPV4_TABLE);
    }
    else
    {
        snprintf(g_dhcpv4ClientPath, sizeof(g_dhcpv4ClientPath), "%s", pParamValue);
    }

    if (pParamValue)
    {
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(pParamValue);
    }

    CcspTraceInfo(("%s: voice DHCPv4 client is %s\n", __FUNCTION__, g_dhcpv4ClientPath));
}

/*
 * @brief Handle one DHCP manager lease event for the voice interface.
 */
static void dhcpVoiceEventHandler(rbusHandle_t handle, rbusEvent_t const *pEvent,
                                  rbusEventSubscription_t *pSubscription)
{
    rbusObject_t dataObj;
    rbusValue_t value;
    const char *pIfName = NULL;
    const uint8_t *pLeaseInfo = NULL;
    DHCP_MESSAGE_TYPE msgType;
    DHCP_MGR_IPV4_MSG lease;
    int leaseLen = 0;

    (void)handle;
    (void)pSubscription;

    if (NULL == pEvent)
    {
        return;
    }

    dataObj = pEvent->data;
    value = rbusObject_GetValue(dataObj, "initialValue");
    if (NULL != value)
    {
        /* publishOnSubscribe wraps the payload, and sends an empty string when there is no lease yet. */
        if (rbusValue_GetType(value) != RBUS_OBJECT)
        {
            CcspTraceInfo(("%s: no lease available yet on %s\n", __FUNCTION__, pEvent->name));
            return;
        }
        dataObj = rbusValue_GetObject(value);
    }

    value = rbusObject_GetValue(dataObj, "IfName");
    pIfName = (NULL != value) ? rbusValue_GetString(value, NULL) : NULL;
    if (!isSafeIfName(pIfName))
    {
        CcspTraceError(("%s: event %s carries no usable interface name\n", __FUNCTION__, pEvent->name));
        return;
    }

    value = rbusObject_GetValue(dataObj, "MsgType");
    if (NULL == value)
    {
        CcspTraceInfo(("%s: event %s carries no MsgType\n", __FUNCTION__, pEvent->name));
        return;
    }
    msgType = (DHCP_MESSAGE_TYPE)rbusValue_GetUInt32(value);

    value = rbusObject_GetValue(dataObj, "LeaseInfo");
    pLeaseInfo = (NULL != value) ? rbusValue_GetBytes(value, &leaseLen) : NULL;
    if (NULL == pLeaseInfo || leaseLen != (int)sizeof(DHCP_MGR_IPV4_MSG))
    {
        CcspTraceError(("%s: unexpected LeaseInfo size %d on %s\n", __FUNCTION__, leaseLen, pIfName));
        return;
    }
    memcpy(&lease, pLeaseInfo, sizeof(lease));

    CcspTraceInfo(("%s: DHCPv4 event type %d on %s\n", __FUNCTION__, msgType, pIfName));

    pthread_mutex_lock(&g_dhcpEventMutex);
    applyVoicePolicyRoutes(&lease, pIfName, msgType);
    if (DHCP_LEASE_DEL == msgType || DHCP_CLIENT_STOPPED == msgType || DHCP_CLIENT_FAILED == msgType)
    {
        pushDhcpv4Down(pIfName);
    }
    else
    {
        pushDhcpv4Snapshot(&lease, pIfName);
    }
    pthread_mutex_unlock(&g_dhcpEventMutex);
}

/*
 * @brief Retry the DHCP event subscription until the DHCP manager is up.
 */
static void *dhcpVoiceSubscribeThread(void *pArg)
{
    char eventName[96] = {0};
    rbusEventSubscription_t subscription;

    (void)pArg;
    pthread_detach(pthread_self());

    resolveDhcpv4ClientPath();
    snprintf(eventName, sizeof(eventName), "%s.Events", g_dhcpv4ClientPath);

    memset(&subscription, 0, sizeof(subscription));
    subscription.eventName = eventName;
    subscription.handler = dhcpVoiceEventHandler;
    subscription.publishOnSubscribe = true;

    while (1)
    {
        rbusError_t ret = rbusEvent_SubscribeEx(g_dhcpVoiceRbusHandle, &subscription, 1, 0);

        if (RBUS_ERROR_SUCCESS == ret || RBUS_ERROR_SUBSCRIPTION_ALREADY_EXIST == ret)
        {
            CcspTraceInfo(("%s: subscribed to %s\n", __FUNCTION__, eventName));
            break;
        }

        CcspTraceError(("%s: subscribe to %s failed (%s), retrying\n",
                        __FUNCTION__, eventName, rbusError_ToString(ret)));
        sleep(5);
    }

    return NULL;
}

#endif /* RBUS_BUILD_FLAG_ENABLE */

/*
 * @brief Bind the voice service to the configured interface and address family.
 */
static ANSC_STATUS applyVoiceBinding(const char *pAddressFamily)
{
    json_object *jmsg = json_hal_client_get_request_header(SET_PARAMETER_METHOD);
    hal_param_t param;

    if (NULL == jmsg)
    {
        return ANSC_STATUS_FAILURE;
    }

    memset(&param, 0, sizeof(param));
    snprintf(param.name, sizeof(param.name),
             "Device.Services.VoiceService.%d.X_RDK_BoundIfName", VOICE_SERVICE_INDEX);
    snprintf(param.value, sizeof(param.value), "%s", g_voiceIfName);
    param.type = PARAM_STRING;
    json_hal_add_param(jmsg, SET_REQUEST_MESSAGE, &param);

    memset(&param, 0, sizeof(param));
    snprintf(param.name, sizeof(param.name),
             "Device.Services.VoiceService.%d.X_RDK_IpAddressFamily", VOICE_SERVICE_INDEX);
    snprintf(param.value, sizeof(param.value), "%s", pAddressFamily);
    param.type = PARAM_STRING;
    json_hal_add_param(jmsg, SET_REQUEST_MESSAGE, &param);

    CcspTraceInfo(("%s: binding voice to %s (%s)\n", __FUNCTION__, g_voiceIfName, pAddressFamily));

    return TelcoVoiceMgrHal_SendJsonRequest(jmsg);
}

ANSC_STATUS TelcoVoiceMgrDhcpVoice_Init(void)
{
    char voiceSupportEnabled[8] = {0};
    char voiceSupportMode[32] = {0};
    const char *pAddressFamily = NULL;

    syscfg_get(NULL, "VoiceSupport_Enabled", voiceSupportEnabled, sizeof(voiceSupportEnabled));
    if (strcmp(voiceSupportEnabled, "true") != 0)
    {
        CcspTraceInfo(("%s: VoiceSupport_Enabled is not set, DHCP voice provisioning disabled\n", __FUNCTION__));
        return ANSC_STATUS_SUCCESS;
    }

    syscfg_get(NULL, "VoiceSupport_Mode", voiceSupportMode, sizeof(voiceSupportMode));
    pAddressFamily = voiceModeToAddressFamily(voiceSupportMode);
    if (NULL == pAddressFamily)
    {
        CcspTraceError(("%s: VoiceSupport_Mode '%s' is not valid\n", __FUNCTION__, voiceSupportMode));
        return ANSC_STATUS_FAILURE;
    }

    syscfg_get(NULL, "VoiceSupport_IfaceName", g_voiceIfName, sizeof(g_voiceIfName));
    if (!isSafeIfName(g_voiceIfName))
    {
        CcspTraceWarning(("%s: VoiceSupport_IfaceName unusable, defaulting to %s\n",
                          __FUNCTION__, DEFAULT_VOICE_IFNAME));
        snprintf(g_voiceIfName, sizeof(g_voiceIfName), "%s", DEFAULT_VOICE_IFNAME);
    }

    if (applyVoiceBinding(pAddressFamily) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s: failed to bind voice to %s\n", __FUNCTION__, g_voiceIfName));
        return ANSC_STATUS_FAILURE;
    }

#ifdef RBUS_BUILD_FLAG_ENABLE
    {
        pthread_t threadId;

        if (rbus_open(&g_dhcpVoiceRbusHandle, "TELCOVOICEMANAGER_DHCP") != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("%s: rbus_open failed\n", __FUNCTION__));
            return ANSC_STATUS_FAILURE;
        }

        if (pthread_create(&threadId, NULL, dhcpVoiceSubscribeThread, NULL) != 0)
        {
            CcspTraceError(("%s: failed to start the DHCP subscription thread\n", __FUNCTION__));
            return ANSC_STATUS_FAILURE;
        }
    }
#else
    CcspTraceError(("%s: rbus support is not built in, DHCP voice provisioning unavailable\n", __FUNCTION__));
    return ANSC_STATUS_FAILURE;
#endif

    return ANSC_STATUS_SUCCESS;
}

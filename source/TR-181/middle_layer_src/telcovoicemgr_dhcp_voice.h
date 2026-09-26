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

#ifndef _TELCOVOICEMGR_DHCP_VOICE_H
#define _TELCOVOICEMGR_DHCP_VOICE_H

#include "ansc_platform.h"

/**
 * @brief Start the DHCP driven voice provisioning feature.
 *
 * Binds the voice service to the interface named by the "VoiceSupport_IfaceName"
 * syscfg entry, applies the configured IP address family and subscribes to the
 * DHCP manager lease events for that interface. Each lease event installs the
 * voice policy routes and pushes the resulting DHCP provisioning snapshot to the
 * vendor voice stack over the JSON HAL.
 *
 * Does nothing unless syscfg "VoiceSupport_Enabled" is "true".
 *
 * @return Status of the operation
 * @retval ANSC_STATUS_SUCCESS if successful
 * @retval ANSC_STATUS_FAILURE if any error is detected
 */
ANSC_STATUS TelcoVoiceMgrDhcpVoice_Init(void);

#endif /* _TELCOVOICEMGR_DHCP_VOICE_H */

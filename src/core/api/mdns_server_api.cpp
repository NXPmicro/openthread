/*
 *  Copyright (c) 2023, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file implements the mDNS-SD Server APIs.
 */

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_MDNS_SERVER_ENABLE
#include "common/instance.hpp"
#include "net/dns_types.hpp"
#include "net/mdns_server.hpp"

#include <openthread/dns_client.h>
#include <openthread/mdns_server.h>

using namespace ot;

bool otMdnsServerIsRunning(otInstance *aInstance)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().IsRunning();
}

otError otMdnsServerStart(otInstance *aInstance)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().Start();
}

void otMdnsServerStop(otInstance *aInstance)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().Stop();
}

const otIp6Address *otMdnsServerGetAddresses(otInstance *aInstance, uint8_t *aNumAddresses)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().GetAddresses(*aNumAddresses);
}

otError otMdnsServerAddAddress(otInstance *aInstance, const otIp6Address *aIp6Address)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().AddAddress(AsCoreType(aIp6Address));
}

otError otMdnsServerSetHostName(otInstance *aInstance, const char *aHostName)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().SetHostName(aHostName);
}

const char *otMdnsServerGetHostName(otInstance *aInstance)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().GetHostName();
}

otError otMdnsServerAddService(otInstance          *aInstance,
                               const char          *aInstanceName,
                               const char          *aServiceName,
                               uint16_t             aPort,
                               const otDnsTxtEntry *aTxtEntries,
                               uint8_t              mNumTxtEntries)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().AddService(aInstanceName, aServiceName, aPort,
                                                                                     aTxtEntries, mNumTxtEntries);
}

otError otMdnsServerUpdateService(otInstance          *aInstance,
                                  const char          *aInstanceName,
                                  const char          *aServiceName,
                                  uint16_t             aPort,
                                  const otDnsTxtEntry *aTxtEntries,
                                  uint8_t              mNumTxtEntries)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().UpdateService(aInstanceName, aServiceName, aPort, 
                                                                                        aTxtEntries, mNumTxtEntries);
}

otError otMdnsServerRemoveService(otInstance *aInstance, const char *aInstanceName, const char *aServiceName)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().RemoveService(aInstanceName, aServiceName);
}

const otMdnsService *otMdnsServerGetNextService(otInstance          *aInstance,
                                                const otMdnsService *aPrevService,
                                                const char          *aServiceName,
                                                const char          *aInstanceName)
{
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().FindNextService(AsCoreTypePtr(aPrevService),
                                                                                          aServiceName, aInstanceName);
}

otError otMdnsServerResolveAddress(otInstance          *aInstance,
                                   const char          *aHostName,
                                   otDnsAddressCallback aCallback,
                                   void                *aContext)
{
    AssertPointerIsNotNull(aHostName);
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().ResolveAddress(aHostName, aCallback,
                                                                                         aContext);
}

otError otMdnsServerBrowse(otInstance         *aInstance,
                           const char         *aServiceName,
                           otDnsBrowseCallback aCallback,
                           void               *aContext)
{
    AssertPointerIsNotNull(aServiceName);
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().Browse(aServiceName, aCallback, aContext);
}

otError otMdnsServerResolveService(otInstance          *aInstance,
                                   const char          *aServiceName,
                                   otDnsServiceCallback aCallback,
                                   void                *aContext)
{
    AssertPointerIsNotNull(aServiceName);
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().ResolveService(aServiceName, aCallback,
                                                                                         aContext);
}

otError otMdnsServerStopQuery(otInstance *aInstance, const char *aName)
{
    AssertPointerIsNotNull(aName);
    return AsCoreType(aInstance).Get<Dns::ServiceDiscovery::MdnsServer>().StopQuery(aName);
}

const char *otMdnsServerServiceGetServiceName(const otMdnsService *aService)
{
    return AsCoreType(aService).GetServiceName();
}

const char *otMdnsServerServiceGetInstanceName(const otMdnsService *aService)
{
    return AsCoreType(aService).GetInstanceName();
}

uint16_t otMdnsServerServiceGetPort(const otMdnsService *aService) { return AsCoreType(aService).GetPort(); }

const uint8_t *otMdnsServerServiceGetTxtData(const otMdnsService *aService, uint16_t *aDataLength)
{
    *aDataLength = AsCoreType(aService).GetTxtDataLength();

    return AsCoreType(aService).GetTxtData();
}

#endif // OPENTHREAD_CONFIG_MDNS_SERVER_ENABLE

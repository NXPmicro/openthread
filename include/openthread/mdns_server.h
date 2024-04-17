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
 * @brief
 *  This file defines the mDNS-SD server APIs.
 */

#ifndef OPENTHREAD_MDNS_SERVER_H_
#define OPENTHREAD_MDNS_SERVER_H_

#include <stdint.h>

#include <openthread/dns_client.h>
#include <openthread/error.h>
#include <openthread/instance.h>
#include <openthread/srp_server.h>
#include <openthread/dns.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup api-mdns-server
 *
 * @brief
 *   This module includes APIs for mDNS-SD server.
 *
 * @{
 *
 */

/**
 * This opaque type represents a Mdns service.
 *
 */
typedef struct otMdnsService otMdnsService;

/**
 * This opaque type represents a Mdns service subtype entry.
 *
 */
typedef struct otMdnsServiceSubTypeEntry otMdnsServiceSubTypeEntry;

/**
 * The ID of a mDNS service update transaction on the mDNS Server.
 *
 */
typedef uint32_t otMdnsServerServiceUpdateId;

typedef struct
{
    char name[OT_DNS_MAX_NAME_SIZE];
    char label[OT_DNS_MAX_LABEL_SIZE];
} otMdnsServerProbingContext;

/**
 * Pointer is called whenever the mDNS Server probing procedure fails.
 *
 * @param[in] aContext  The user context pointer.
 *
 */
typedef void (*otMdnsServerProbingCallback)(void *aContext, otMdnsServerProbingContext *aProbingContext);

/**
 * Sets the mDNS Server probing procedure callback.
 *
 * @param[in] aInstance  A pointer to an OpenThread instance.
 * @param[in] aCallback  A pointer to the mDNS Server probing callback.
 * @param[in] aContext   A user context pointer.
 *
 */
void otMdnsServerSetProbingCallback(otInstance *aInstance, otMdnsServerProbingCallback aCallback, void *aContext);

/**
 * This function returns True if the Server has been started and is running.
 *
 * @param[in]  aInstance            A pointer to the OpenThread instance.
 *
 * @returns True if the server is running.
 */
bool otMdnsServerIsRunning(otInstance *aInstance);

/**
 * This function starts the server.
 *
 * @param[in]  aInstance            A pointer to the OpenThread instance.
 *
 * @retval OT_ERROR_NONE            The server has been started successfully
 * @retval OT_ERROR_ALREADY         The server is already running
 * @retval OT_ERROR_INVALID_STATE   The server can't be started since it doesn't have a hostname
 */
otError otMdnsServerStart(otInstance *aInstance);

/**
 * This function stops the server if running.
 *
 * @param[in]  aInstance            A pointer to the OpenThread instance.
 */
void otMdnsServerStop(otInstance *aInstance);

/**
 * This function returns an array of Ip6Addresses that where previously set for the DNS host.
 *
 * @param[in]  aInstance            A pointer to the OpenThread instance.
 * @param[out] numAddresses         The number of addresses returned in the array of addresses
 *
 * @returns A pointer to an array of otIp6Addresses or nullptr if list is empty
 */
const otIp6Address *otMdnsServerGetAddresses(otInstance *aInstance, uint8_t *numAddresses);

/**
 * This function adds a new address to the list of host IPv6 addresses.
 *
 * @param[in] aInstance           A pointer to the OpenThread instance.
 * @param[in] aIp6Addresses       A pointer to the an array containing the host IPv6 addresses.
 *
 * @retval OT_ERROR_NONE            The host IPv6 address list change finalized successfully.
 * @retval OT_ERROR_INVALID_ARGS    The address list is invalid (e.g., must contain at least one address).
 * @retval OT_ERROR_INVALID_STATE   Host is not initialized and therefore cannot change host address.
 */
otError otMdnsServerAddAddress(otInstance *aInstance, const otIp6Address *aIp6Address);

/**
 * This function clears the list of host IPv6 addresses.
 * 
 * @param[in] aInstance           A pointer to the OpenThread instance.
 */
void otMdnsServerClearAddresses(otInstance *aInstance);

/**
 * This function returns the host name.
 *
 * @param[in] aInstance           A pointer to the OpenThread instance.
 *
 * @returns A pointer to the null-terminated full host name.
 */
const char *otMdnsServerGetHostName(otInstance *aInstance);

/**
 * This function sets mDns host name label;
 *
 * @param[in] aInstance                A pointer to the OpenThread instance.
 * @param[in] aHostName                A pointer to host name label string (MUST NOT be NULL).
 *
 * @retval OT_ERROR_NONE               The host name label was set successfully.
 * @retval OT_ERROR_INVALID_ARGS       The @p aHostName is NULL.
 * @retval OT_ERROR_FAILED             The host name is already set and registered with the server.
 */
otError otMdnsServerSetHostName(otInstance *aInstance, const char *aHostName);

/**
 * This function requests a service to be registered with server.
 *  -  It is removed explicitly by a call to `otMdnsServerRemoveService()`
 *
 * @param[in] aInstance             A pointer to the OpenThread instance.
 * @param[in] aInstanceName         The service instance name label (e.g., "ins._http._tcp.local.") .
 * @param[in] aName                 The service labels (e.g., "_http._tcp.local.").
 * @param[in] aSubtypeLabels        The service subtypes labels (e.g., "_sub1.http._tcp.local.").
 * @param[in] aNumSubtypesEntries   Number of entries in the @p aSubtypeLabels array.
 * @param[in] aPort                 The service port number.
 * @param[in] aTxtEntries           A pointer to an array containing TXT entries (e.g., ["VAL1=1", "VAL2=2"])
 *                                  (`mNumTxtEntries` gives num of entries).
 * @param[in] mNumTxtEntries        Number of entries in the `aTxtEntries` array
 *
 * @retval OT_ERROR_NONE                The addition of service finalized successfully.
 * @retval OT_ERROR_INVALID_STATE       Host is not initialized and therefore service cannot be added.
 * @retval OT_ERROR_ALREADY             A service with the same service and instance names is already in the list.
 */
otError otMdnsServerAddService(otInstance          *aInstance,
                               const char          *aInstanceName,
                               const char          *aName,
                               const char         **aSubtypeLabels,
                               uint8_t              aNumSubtypesEntries,
                               uint16_t             aPort,
                               const otDnsTxtEntry *aTxtEntries,
                               uint8_t              mNumTxtEntries);

/**
 * This function requests a service to be updated with server.
 *
 * @param[in] aInstance             A pointer to the OpenThread instance.
 * @param[in] aInstanceName         The service instance name label (e.g., "ins._http._tcp.local.") .
 * @param[in] aName                 The service labels (e.g., "_http._tcp.local.").
 * @param[in] aPort                 The service port number.
 * @param[in] aTxtEntries           A pointer to an array containing TXT entries (e.g., ["VAL1=1", "VAL2=2"])
 *                                  (`mNumTxtEntries` gives num of entries).
 * @param[in] mNumTxtEntries        Number of entries in the `aTxtEntries` array
 *
 * @retval OT_ERROR_NONE                The update of service finalized successfully.
 * @retval OT_ERROR_INVALID_STATE       There is no 'base' service to be updated.
 * @retval OT_ERROR_FAILED              The service update failed.
 */
otError otMdnsServerUpdateService(otInstance          *aInstance,
                                  const char          *aInstanceName,
                                  const char          *aName,
                                  uint16_t             aPort,
                                  const otDnsTxtEntry *aTxtEntries,
                                  uint8_t              mNumTxtEntries);

/**
 * This function requests a service to be unregistered with server.
 *
 * @param[in] aInstance             A pointer to the OpenThread instance.
 * @param[in] aInstanceName         The service instance name label (e.g., "ins._http._tcp.local.") .
 * @param[in] aName                 The service labels (e.g., "_http._tcp.local.").
 *
 * @retval OT_ERROR_NONE                The removal of service finalized successfully.
 * @retval OT_ERROR_INVALID_STATE       Host is not initialized and therefore service cannot be removed.
 * @retval OT_ERROR_NOT_FOUND           The service could not be found in the list.
 */
otError otMdnsServerRemoveService(otInstance *aInstance, const char *aInstanceName, const char *aServiceName);

/**
 * This function gets the next service of the mDNS host.
 *
 * @param[in] aInstance             A pointer to the OpenThread instance.
 * @param[in] aService              Pointer to current service or NULL for starting from first
 *
 * @retval OT_ERROR_NONE                The service was returned successfully.
 * @retval OT_ERROR_NOT_FOUND           The service could not be found in the list.
 */
const otMdnsService *otMdnsServerGetNextService(otInstance          *aInstance,
                                                const otMdnsService *aService,
                                                const char          *aServiceName,
                                                const char          *aInstancenName);

/**
 * This function sends a mDNS query to resolve a host name to an IPv6 address.
 *
 * @param[in] aInstance     The OpenThread instance structure.
 * @param[in] aHostName     The full hostname.
 * @param[in] aCallback     A function pointer that shall be called on response reception or timeout
 * @param[in] aContext      A pointer to arbitrary context information
 *
 * @retval OT_ERROR_NONE          Query sent successfully. @p aCallback will be invoked to report the status.
 * @retval OT_ERROR_NO_BUFS       Insufficient buffer to prepare and send query.
 */
otError otMdnsServerResolveAddress(otInstance          *aInstance,
                                   const char          *aHostName,
                                   otDnsAddressCallback aCallback,
                                   void                *aContext);

/**
 * This function sends a mDNS browse query for a given service.
 *
 * @param[in] aInstance     The OpenThread instance structure.
 * @param[in] aServiceName  The full service name.
 * @param[in] aCallback     A function pointer that shall be called on response reception or timeout
 * @param[in] aContext      A pointer to arbitrary context information
 *
 * @retval OT_ERROR_NONE          Query sent successfully. @p aCallback will be invoked to report the status.
 * @retval OT_ERROR_NO_BUFS       Insufficient buffer to prepare and send query.
 */
otError otMdnsServerBrowse(otInstance         *aInstance,
                           const char         *aServiceName,
                           otDnsBrowseCallback aCallback,
                           void               *aContext);

/**
 * This function sends a mDNS query to resolve a service instance name to a host name.
 *
 * @param[in] aInstance     The OpenThread instance structure.
 * @param[in] aServiceName  The full service instance name.
 * @param[in] aCallback     A function pointer that shall be called on response reception or timeout
 * @param[in] aContext      A pointer to arbitrary context information
 *
 * @retval OT_ERROR_NONE          Query sent successfully. @p aCallback will be invoked to report the status.
 * @retval OT_ERROR_NO_BUFS       Insufficient buffer to prepare and send query.
 */
otError otMdnsServerResolveService(otInstance          *aInstance,
                                   const char          *aServiceName,
                                   otDnsServiceCallback aCallback,
                                   void                *aContext);

/**
 * This function stops an ongoing query. This can be either hostname/browse/service.
 *
 * @param[in] aInstance     The OpenThread instance structure.
 * @param[in] aHostName     The full hostname/service name/service instance name.
 *
 * @retval OT_ERROR_NONE          The query was stopped successfully.
 * @retval OT_ERROR_NOT_FOUND     The query name was not found.
 */
otError otMdnsServerStopQuery(otInstance *aInstance, const char *aName);

/**
 * This function returns the full service name of the service.
 *
 * @param[in]  aService  A pointer to the MDNS service.
 *
 * @returns  A pointer to the null-terminated service name string.
 *
 */
const char *otMdnsServerServiceGetServiceName(const otMdnsService *aService);

/**
 * This function returns the full service instance name of the service.
 *
 * @param[in]  aService  A pointer to the MDNS service.
 *
 * @returns  A pointer to the null-terminated service instance name string.
 *
 */
const char *otMdnsServerServiceGetInstanceName(const otMdnsService *aService);

/**
 * This function returns the port of the service instance.
 *
 * @param[in]  aService  A pointer to the MDNS service.
 *
 * @returns  The port of the service.
 *
 */
uint16_t otMdnsServerServiceGetPort(const otMdnsService *aService);

/**
 * This function returns the TXT record data of the service instance.
 *
 * @param[in]  aService        A pointer to the MDNS service.
 * @param[out] aDataLength     A pointer to return the TXT record data length. MUST NOT be NULL.
 *
 * @returns A pointer to the buffer containing the TXT record data (the TXT data length is returned in @p aDataLength).
 *
 */
const uint8_t *otMdnsServerServiceGetTxtData(const otMdnsService *aService, uint16_t *aDataLength);


/**
 * This function marks a specific service instance or a list of services matching a given service name to be deleted.
 *
 * @param[in] aInstance             A pointer to the OpenThread instance.
 * @param[in] aInstanceName         The service instance name label (e.g., "ins._http._tcp.local.") .
 * @param[in] aName                 The service labels (e.g., "_http._tcp.local.").
 *
 */
void otMdnsServerMarkServiceForRemoval(otInstance *aInstance, const char *aInstanceName, const char *aServiceName);

/**
 * This function removes previous marked as deleted services from the mDNS host's service list.
 */
void otMdnsServerRemoveMarkedServices(otInstance *aInstance);

/**
 * This function gets the next subtype entry of the given service.
 *
 * @param[in] aInstance                 A pointer to the OpenThread instance.
 * @param[in] aService                  Pointer to current service.
 * @param[in] aSubTypeEntry             Pointer to current subtypeEntry or NULL for starting from first
 *
 * @retval OT_ERROR_NONE                The subtype was returned successfully.
 * @retval OT_ERROR_NOT_FOUND           The subtype could not be found in the list.
 */
const otMdnsServiceSubTypeEntry *otMdnsServerServiceGetNextSubTypeEntry(const otMdnsService *aService, const otMdnsServiceSubTypeEntry *aSubTypeEntry);

/**
 * Gets the sub-type label from service name.
 *
 * The full service name for a sub-type service follows "<sub-label>._sub.<service-labels>.<domain>.". This function
 * copies the `<sub-label>` into the @p aLabel buffer.
 *
 * The @p aLabel is ensured to always be null-terminated after returning even in case of failure.
 * @param[in]  aEntry             A pointer to the current sub-type entry in service sub-type list.
 * @param[out] aLabel             A pointer to a buffer to copy the sub-type label name into.
 * @param[in]  aMaxSize           Maximum size of @p aLabel buffer.
 *
 * @retval OT_ERROR_NONE          @p aLabel was updated successfully.
 * @retval OT_ERROR_NO_BUFS       The sub-type label could not fit in @p aLabel buffer (number of chars from label
 *                                that could fit are copied in @p aLabel ensuring it is null-terminated).
 *
 */
otError otMdnsServerServiceGetServiceSubTypeLabel(const otMdnsServiceSubTypeEntry *aEntry, char *aLabel, uint8_t aMaxSize);
/**
 * @}
 *
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPENTHREAD_MDNS_SERVER_H_

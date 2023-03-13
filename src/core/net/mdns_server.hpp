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
 *   This file includes definitions for the MDNS server.
 */

#ifndef MDNS_SERVER_HPP_
#define MDNS_SERVER_HPP_

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_MDNS_SERVER_ENABLE

#include <openthread/dns_client.h>
#include <openthread/dns.h>

#include "common/error.hpp"
#include "common/message.hpp"
#include "common/non_copyable.hpp"
#include "common/retain_ptr.hpp"
#include "common/tasklet.hpp"

#include "net/dns_client.hpp"
#include "net/dns_types.hpp"
#include "net/dnssd_server.hpp"
#include "net/ip6.hpp"
#include "net/netif.hpp"

struct otMdnsService
{
};

namespace ot {
namespace Dns {
namespace ServiceDiscovery {

/**
 * This class implements MDNS-SD server.
 *
 */

class MdnsServer : public InstanceLocator, private NonCopyable
{
public:
    static constexpr uint16_t kPort             = OPENTHREAD_CONFIG_MDNS_SERVER_PORT; ///< The MDNS-SD server port.
    static constexpr uint8_t  kTXTMaxBufferSize = 255;
    /*the recommended TTL value for Multicast DNS
    resource records with a host name as the resource record’s name*/
    static constexpr uint32_t kDefaultTtlWithHostName = 120;
    static constexpr uint32_t kDefaultTtl             = 4500; // 75 minutes

    enum State : uint8_t
    {
        kStateStopped,
        kStateRunning,
    };

    /**
     * This constructor initializes the object.
     *
     * @param[in]  aInstance     A reference to the OpenThread instance.
     *
     */
    explicit MdnsServer(Instance &aInstance);

    /**
     * This method returns True if the mDNS server has started.
     *
     * @retval bool     True if the mDNS server is running
     */
    bool IsRunning(void) const { return (mState != kStateStopped); }

    /**
     * This method starts the mDNS server.
     *
     * @retval kErrorNone     Successfully started the mDNS server.
     * @retval kErrorFailed   If failed to open or bind the UDP socket.
     *
     */
    Error Start(void);

    /**
     * This method stops the mDNS server.
     *
     */
    void Stop(void);

    /**
     * This method searches for DNS service using mDNS.
     *
     * @param[in]   aQuery      The query pointer.
     * @param[out]  aName       The name output buffer.
     *
     * @retval kErrorNone     Successfully started the DNS-SD server.
     * @retval kErrorFailed   If failed to open or bind the UDP socket.
     *
     */
    Error ResolveAddress(const char *aHostName, Client::AddressCallback aCallback, void *aContext);

    /**
     * This method searches for DNS service using mDNS.
     *
     * @param[in]   aQuery      The query pointer.
     * @param[out]  aName       The name output buffer.
     *
     * @retval kErrorNone     Successfully started the DNS-SD server.
     * @retval kErrorFailed   If failed to open or bind the UDP socket.
     *
     */
    Error Browse(const char *aServiceName, Client::BrowseCallback aCallback, void *aContext);

    /**
     * This method searches for DNS service using mDNS.
     *
     * @param[in]   aQuery      The query pointer.
     * @param[out]  aName       The name output buffer.
     *
     * @retval kErrorNone     Successfully started the DNS-SD server.
     * @retval kErrorFailed   If failed to open or bind the UDP socket.
     *
     */
    Error ResolveService(const char *aName, Client::ServiceCallback aCallback, void *aContext);

    /**
     * This method stops searching for DNS service using mDNS.
     *
     * @param[in]   aQuery      The query pointer.
     * @param[out]  aName       The name output buffer.
     *
     * @retval kErrorNone     Successfully started the DNS-SD server.
     * @retval kErrorFailed   If failed to open or bind the UDP socket.
     *
     */
    Error StopQuery(const char *aName);

    /**
     * This function returns a list of host IPv6 address.
     * @param[out] aNumAddresses        The number of addresses in the @p aIp6Addresses array.
     *
     * @return the list of IPv6 addresses or a nullptr
     */
    const Ip6::Address *GetAddresses(uint8_t &aNumAddresses);

    /**
     * This function sets/updates the list of host IPv6 address.
     * @param[in] aIp6Addresses       A reference to the IPv6 addresses.
     *
     * @retval kErrorNone               The host IPv6 address list change finalized successfully.
     * @retval kErrorInvalidArgs        The address list is invalid (e.g., must contain at least one address).
     * @retval kErrorInvalidState       Host is not initialized and therefore cannot change host address.
     */
    Error AddAddress(const Ip6::Address &aIp6Address);

    /**
     * This function sets mDns host name label;
     *
     * @param[in] aHostName         A pointer to host name label string (MUST NOT be NULL).
     *
     * @retval kErrorNone               The host name label was set successfully.
     * @retval kErrorInvalidArgs        The @p aHostName is NULL.
     * @retval kErrorFailed             The host name is already set and registered with the server.
     */
    Error SetHostName(const char *aHostName);

    /**
     * This function returns the host name
     *
     * @returns A pointer to the null-terminated full host name.
     */
    const char *GetHostName();

    /**
     * This function requests a service to be registered with server.
     * @param[in] aInstanceName         The service instance name label (e.g., "ins._http._tcp.local.") .
     * @param[in] aServiceName          The service labels (e.g., "_http._tcp.local.").
     * @param[in] aPort                 The service port number.
     * @param[in] aTxtEntries           A pointer to an array containing TXT entries (e.g., ["VAL1=1", "VAL2=2"])
     *                                  (`mNumTxtEntries` gives num of entries).
     * @param[in] mNumTxtEntries        Number of entries in the `aTxtEntries` array
     *
     * @retval kErrorNone               The addition of service finalized successfully.
     * @retval kErrorInvalidState       Host is not initialized and therefore service cannot be added.
     * @retval kErrorAlready            A service with the same service and instance names is already in the list.
     */
    Error AddService(const char *aInstanceName, const char *aServiceName, uint16_t aPort, const otDnsTxtEntry *aTxtEntries,
                     uint8_t mNumTxtEntries);

    /**
     * This function requests a service to be updated with server.
     * @param[in] aInstanceName         The service instance name label (e.g., "ins._http._tcp.local.") .
     * @param[in] aServiceName          The service labels (e.g., "_http._tcp.local.").
     * @param[in] aPort                 The service port number.
     * @param[in] aTxtEntries           A pointer to an array containing TXT entries (e.g., ["VAL1=1", "VAL2=2"])
     *                                  (`mNumTxtEntries` gives num of entries).
     * @param[in] mNumTxtEntries        Number of entries in the `aTxtEntries` array
     *
     * @retval kErrorNone               The update finalized successfully.
     * @retval kErrorInvalidState       There is no 'base' service to be updated.
     * @retval kErrorFailed             The update failed.
     */
    Error UpdateService(const char *aInstanceName, const char *aServiceName, uint16_t aPort, const otDnsTxtEntry *aTxtEntries,
                        uint8_t mNumTxtEntries);

    /**
     * This method clears a service, immediately removing it from the mDNS host's service list.
     * @param[in] aInstanceName         The service instance name label (e.g., "ins._http._tcp.local.") .
     * @param[in] aServiceName          The service labels (e.g., "_http._tcp.local.").
     *
     * @retval kErrorNone               The removal of service finalized successfully.
     * @retval kErrorInvalidState       Host is not initialized and therefore service cannot be removed.
     * @retval kErrorNotFound           The service could not be found in the list.
     */
    Error RemoveService(const char *aInstanceName, const char *aServiceName);

    /**
     * This method is used to provide the next service in the Service list provided the previous service
     *
     * @param[in] aPrevService          Pointer to the previous service in list or nullptr
     *
     * @returns a pointer for the next service or nullptr if the list is empty
     */
    const Srp::Server::Service *FindNextService(const Srp::Server::Service *aPrevService);

    /**
     * This method is used by the DNS SD server to stop searching for DNS service in mDNS.
     *
     * @param[in]  aName      The name to stop searching for.
     *
     */
    void StopQueryFromDnsSd(const char *aName);

    /**
     * This method is used by the DNS SD server to search for a hostname/service on the local domain using mDNS
     *
     * @param[out]  aName         The name to search for.
     * @param[in]   aType         The type of query, hostname/browse(ptr)/service.
     *
     * @retval kErrorNone         Successfully started the mDNS query.
     * @retval kErrorInvalidArgs  If provided query type is not browse/resolve/resolve host
     * @retval kErrorNoBufs       If could not allocate memory to story the query transaction
     * @retval kErrorFailed       In case of other error
     *
     */
    Error ResolveQuestionFromDnsSd(const char *aName, Server::DnsQueryType aType);

    class Service : public otMdnsService, public LinkedListEntry<Service>, public Heap::Allocatable<Service>
    {
        friend class MdnsServer;
        friend class Heap::Allocatable<Service>;
        friend class LinkedList<Service>;
        friend class LinkedListEntry<Service>;

    public:
        /**
         * This method gets the full service name of the service.
         *
         * @returns     A pointer service name (as a null-terminated C string)
         *
         */
        const char *GetServiceName(void) const { return mServiceName.AsCString(); }

        /**
         * This method gets the full service instance name of the service.
         *
         * @returns  A pointer service instance name (as a null-terminated C string).
         *
         */
        const char *GetInstanceName(void) const { return mInstanceName.AsCString(); }

        /**
         * This method returns the weight of the service instance.
         *
         * @returns  The weight of the service.
         *
         */
        uint16_t GetWeight(void) const { return mWeight; }

        /**
         * This method returns the priority of the service instance.
         *
         * @returns  The priority of the service.
         *
         */
        uint16_t GetPriority(void) const { return mPriority; }

        /**
         * This method returns the port of the service instance.
         *
         * @returns  The port of the service.
         *
         */
        uint16_t GetPort(void) const { return mPort; }

        /**
         * This method returns the TTL of the service instance.
         *
         * @returns The TTL of the service instance.
         *
         */
        uint32_t GetTtl(void) const { return mTtl; }

        /**
         * This method returns the TXT record data of the service instance.
         *
         * @returns A pointer to the buffer containing the TXT record data.
         *
         */
        const uint8_t *GetTxtData(void) const { return mTxtData.GetBytes(); }

        /**
         * This method returns the TXT record data length of the service instance.
         *
         * @return The TXT record data length (number of bytes in buffer returned from `GetTxtData()`).
         *
         */
        uint16_t GetTxtDataLength(void) const { return mTxtData.GetLength(); }

    private:
        Error Init(const char *aServiceName, const char *aInstanceName, uint16_t aPort);
        bool  MatchesServiceName(const char *aServiceName) const;
        bool  MatchesInstanceName(const char *aInstanceName) const;

        Service     *mNext;
        Heap::String mServiceName;
        Heap::String mInstanceName;
        Heap::Data   mTxtData;
        uint16_t     mPriority;
        uint16_t     mWeight;
        uint16_t     mPort;
        uint32_t     mTtl;
        bool         mIsToBeAnnounced;
    };

    Service       *FindService(const char *aServiceName, const char *aInstanceName);
    const Service *FindNextService(const MdnsServer::Service *aPrevService,
                                   const char                *aServiceName  = nullptr,
                                   const char                *aInstanceName = nullptr) const;

    class Announcer : public InstanceLocator
    {
    public:
        enum State : uint8_t
        {
            kIdle,
            kAnnouncing,
            kAnnounced
        };

        // All time intervals are in msec
        static constexpr uint32_t kTxAnnounceInterval = 1000;
        static constexpr uint8_t  kMaxTxCount         = 2;

        Announcer(Instance &aInstance);
        void     EnqueueAnnounceMessage(Message &aAnnounceMessage) { mAnnouncements.Enqueue(aAnnounceMessage); };
        void     StartAnnouncing();
        void     HandleTimer();
        Message *CreateHostAndServicesAnnounceMessage();
        void     MdnsAnnouncingHandler();

    private:
        using AnnouncerTimer = TimerMilliIn<MdnsServer::Announcer, &MdnsServer::Announcer::HandleTimer>;

        uint8_t          mTxCount;
        AnnouncerTimer   mTimer;
        Announcer::State mState;

        MessageQueue mAnnouncements;

        void SetState(State aState) { mState = aState; }
    };

    MdnsServer::Announcer &GetAnnouncer() { return mAnnouncer; }
    Ip6::Udp::Socket      &GetMcastSocket() { return mSocket; }
    bool                   IsHostAnnounced() { return mHostIsToBeAnnounced; }
    void                   SetHostAnnounced(bool aValue) { mHostIsToBeAnnounced = aValue; }
    MdnsServer::Service   *GetServiceListHead() { return mServices.GetHead(); }

private:
    using NameCompressInfo         = Server::NameCompressInfo;
    using NameComponentsOffsetInfo = Server::NameComponentsOffsetInfo;

    union Callback
    {
        Client::AddressCallback mAddressCallback;
        Client::BrowseCallback  mBrowseCallback;
        Client::ServiceCallback mServiceCallback;
    };

    static void HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo);
    void        HandleUdpReceive();
    void        HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo);

    Error    AllocateQuery(const Client::QueryInfo &aInfo, const char *aName, Message *&aQuery);
    void     UpdateQuery(Message &aQuery, const Client::QueryInfo &aInfo) { aQuery.Write(0, aInfo); }
    void     UpdateTimeout(Message &aQuery, Client::QueryInfo &aInfo, bool bDouble);
    Message *FindQueryByName(const Message &aMessage, uint16_t &aOffset);
    Message *FindQueryByName(const char *aName);
    void     FreeQuery(Message &aQuery) { mQueries.DequeueAndFree(aQuery); }
    void     FinalizeQuery(Message &aQuery, Error aError);
    void     FinalizeQuery(Client::Response &aResponse, Error aError);
    Error    StartQuery(Client::QueryInfo &aInfo, const char *aName);
    Error    SendQuery(Message &aQuery, Client::QueryInfo &aInfo);
    Error    SendQuery(const char *aName, Message &aQuery, uint16_t qestionType, bool bUnicastQuestion);
    void     ProcessQuery(const Header &aRequestHeader, Message &aRequestMessage, const Ip6::MessageInfo &aMessageInfo);
    void  ProcessResponse(const Header &aRequestHeader, Message &aRequestMessage, const Ip6::MessageInfo &aMessageInfo);
    Error ParseResponse(const Header &aRequestHeader, Message &aRequestMessage, Client::Response &aResponse);
    uint16_t GetRecordType(Client::QueryType aQueryType);
    void     HandleTimer(void);
    State    GetState(void) const { return mState; }
    void     SetState(State aState) { mState = aState; }
    Error    ConvertDomainName(char       *aName,
                               const char *aInitName,
                               const char *aDomainName,
                               const char *aTargetDomaninName);
    void     HandleDnsSdResult(Client::Response &aResponse, Client::QueryInfo aInfo);

    void GetServiceInfoFromResponse(char                    *instanceName,
                                    char                    *serviceName,
                                    Client::ServiceResponse *serviceResponse,
                                    Client::BrowseResponse  *browseResponse);

    /**
     * This function converts an ASCII encoded string to it's corresponding hexstring representation as text.
     * This function is usually used to convert the TXT value for a specific service.
     *
     * For each character in @p aInputString, it outputs the a pair of characters that reperesent the
     * ASCII code (e.g., 'a' = 0x61, gets converted to '61').
     *
     * In addition to this, function adds as the first character of @p aOutputString the length of the input
     * @p aInputString (e.g., 'a' gets converted to '0161').
     *
     * @param[in] aInputString      A pointer to the ASCII string that needs to be converted.
     * @param[out] aOutputString    The resulting hexstring format.
     */
    void EncodeAsHexString(const char *aInputString, char *aOutputString);

    Error AnnounceServiceGoodbye(Service &aService);
    Error AnnounceHostGoodbye();
    Error AppendServiceInfo(Message &aMessage, Header &aHeader, Service &aService, NameCompressInfo &aCompressInfo);
    Error SendPacket(Message          &aMessage,
                     Header           &aHeader,
                     Header::Response  aResponseCode = Header::kResponseSuccess,
                     bool              aSendUnicast  = false,
                     Ip6::MessageInfo *aMessageInfo = nullptr);
    Header::Response ResolveQuery(const Header             &aRequestHeader,
                                  const Message            &aRequestMessage,
                                  Header                   &aResponseHeader,
                                  Message                  &aResponseMessage,
                                  Server::NameCompressInfo &aCompressInfo,
                                  bool                     &bUnicastResponse);
    Header::Response ResolveQuestion(const char       *aName,
                                     const Question   &aQuestion,
                                     Header           &aResponseHeader,
                                     Message          &aResponseMessage,
                                     NameCompressInfo &aCompressInfo,
                                     bool              aAdditional);

    using RetryTimer         = TimerMilliIn<MdnsServer, &MdnsServer::HandleTimer>;
    using RxTask             = TaskletIn<MdnsServer, &MdnsServer::HandleUdpReceive>;
    using MdnsAnnouncingTask = TaskletIn<MdnsServer::Announcer, &MdnsServer::Announcer::MdnsAnnouncingHandler>;

    static const char kDefaultDomainName[];
    static const char kThreadDefaultDomainName[];

    RetryTimer                    mTimer;
    Ip6::Udp::Socket              mSocket;
    MessageQueue                  mQueries;
    MessageQueue                  mRxPktQueue;
    State                         mState;
    Heap::String                  mHostName;
    Heap::Array<Ip6::Address>     mAddresses;
    RxTask                        mHandleUdpReceive;
    LinkedList<Service>           mServices;
    Announcer                     mAnnouncer;
    MdnsAnnouncingTask            mMdnsAnnouncing;
    bool                          mHostIsToBeAnnounced;
};

} // namespace ServiceDiscovery
} // namespace Dns

DefineCoreType(otMdnsService, Dns::ServiceDiscovery::MdnsServer::Service);

} // namespace ot

#endif // OPENTHREAD_CONFIG_MDNS_SERVER_ENABLE

#endif // MDNS_HPP

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

#include <openthread/dns.h>
#include <openthread/dns_client.h>
#include <openthread/mdns_server.h>

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

struct otMdnsServiceSubTypeEntry
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
     * The ID of mDNS service update transaction.
     *
     */
    typedef otMdnsServerServiceUpdateId ServiceUpdateId;

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
     * @param[in] aSubtypeLabels        The service subtypes labels (e.g., "_sub1.http._tcp.local.").
     * @param[in] aNumSubtypesEntries   Number of entries in the @p aSubtypeLabels array.
     * @param[in] aPort                 The service port number.
     * @param[in] aTxtEntries           A pointer to an array containing TXT entries (e.g., ["VAL1=1", "VAL2=2"])
     *                                  (`mNumTxtEntries` gives num of entries).
     * @param[in] mNumTxtEntries        Number of entries in the `aTxtEntries` array
     *
     * @retval kErrorNone               The addition of service finalized successfully.
     * @retval kErrorInvalidState       Host is not initialized and therefore service cannot be added.
     * @retval kErrorAlready            A service with the same service and instance names is already in the list.
     */
    Error AddService(const char          *aInstanceName,
                     const char          *aServiceName,
                     const char         **aSubtypeLabels,
                     uint8_t              aNumSubtypesEntries,
                     uint16_t             aPort,
                     const otDnsTxtEntry *aTxtEntries,
                     uint8_t              mNumTxtEntries);

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
    Error UpdateService(const char          *aInstanceName,
                        const char          *aServiceName,
                        uint16_t             aPort,
                        const otDnsTxtEntry *aTxtEntries,
                        uint8_t              mNumTxtEntries);

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

    ServiceUpdateId AllocateId(void) { return mServiceUpdateId++; }

    class Service : public otMdnsService, public LinkedListEntry<Service>, public Heap::Allocatable<Service>
    {
        friend class MdnsServer;
        friend class Heap::Allocatable<Service>;
        friend class LinkedList<Service>;
        friend class LinkedListEntry<Service>;

    public:
        class SubTypeEntry : public otMdnsServiceSubTypeEntry,
                             public Heap::Allocatable<SubTypeEntry>,
                             public LinkedListEntry<SubTypeEntry>
        {
            friend class Heap::Allocatable<SubTypeEntry>;
            friend class LinkedListEntry<SubTypeEntry>;

        public:
            SubTypeEntry(const char *aName) { mInstanceName.Set(aName); }
            const char *GetName() { return mInstanceName.AsCString(); }
            const char *GetName() const { return mInstanceName.AsCString(); }
            bool        Matches(const char *aInstanceName) const
            {
                return StringMatch(aInstanceName, mInstanceName.AsCString(), kStringCaseInsensitiveMatch);
            }
            Error GetServiceSubTypeLabel(char *aLabel, uint8_t aMaxSize) const;

        private:
            Heap::String  mInstanceName;
            SubTypeEntry *mNext;
        };

        enum State : uint8_t
        {
            kJustAdded = 0,
            kProbing,
            kProbed,
            kAnnouncing,
            kAnnounced
        };

        /**
         * This is the destructor for `Service` object.
         *
         */
        ~Service(void) { Free(); }

        /**
         * Frees any memory allocated by the `Service`.
         *
         * The `Service` destructor will automatically call `Free()`. This method allows caller to free memory explicitly.
         *
         */
        void Free(void)
        {
            for (SubTypeEntry &entry : mSubTypesList)
            {
                mSubTypesList.Remove(entry);
                entry.Free();
            }
        }

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

        /**
         * This method returns the mDNS state of the service instance.
         *
         * @return The mDNS state.
         *
         */
        State GetState(void) const { return mState; }

        /**
         * This method sets the mDNS state of the service instance.
         *
         *
         */
        void SetState(State aState) { mState = aState; }

        /**
         * This method gets the mDNS update Id of the service instance.
         *
         *
         */
        ServiceUpdateId GetServiceUpdateId(void) { return mId; }

        /**
         * This method checks if the given service Id matches an already existing service instance.
         *
         *
         */

        const SubTypeEntry *GetNextSubTypeEntry(const MdnsServer::Service::SubTypeEntry *aPrevSubTypeEntry) const;

        bool Matches(ServiceUpdateId aId) const { return mId == aId; }

        void PushSubTypeEntry(SubTypeEntry &aEntry) { mSubTypesList.Push(aEntry); }

        LinkedList<SubTypeEntry> GetSubTypeList(void) { return mSubTypesList; }

    private:
        Error Init(const char *aServiceName, const char *aInstanceName, uint16_t aPort, uint16_t aId);
        bool  MatchesServiceName(const char *aServiceName) const;
        bool  MatchesInstanceName(const char *aInstanceName) const;

        Service                 *mNext;
        Heap::String             mServiceName;
        Heap::String             mInstanceName;
        Heap::Data               mTxtData;
        uint16_t                 mPriority;
        uint16_t                 mWeight;
        uint16_t                 mPort;
        uint32_t                 mTtl;
        bool                     mIsToBeAnnounced;
        State                    mState;
        ServiceUpdateId          mId;
        LinkedList<SubTypeEntry> mSubTypesList;
    };

    Service       *FindServiceById(uint32_t aId) { return mServices.FindMatching(aId); }
    Service       *FindService(const char *aServiceName, const char *aInstanceName);
    const Service *FindNextService(const MdnsServer::Service *aPrevService,
                                   const char                *aServiceName  = nullptr,
                                   const char                *aInstanceName = nullptr) const;

    class OutstandingUpdate : public LinkedListEntry<OutstandingUpdate>, public Heap::Allocatable<OutstandingUpdate>
    {
        friend class LinkedListEntry<OutstandingUpdate>;
        friend class Heap::Allocatable<OutstandingUpdate>;

    public:
        enum Type : uint8_t
        {
            kTypeProbeAndAnnounce,
            kTypeAnnounce,
            kTypeHostGoodbyeAnnouncement,
            kTypeSrpHostGoodbyeAnnouncement,
            kTypeSrpServiceRemoved
        };

        enum State : uint8_t
        {
            kStateIdle,
            kStateProbing,
            kStateAnnouncing
        };

    public:
        bool                            Matches(const uint32_t aId) const { return mId == aId; }
        uint32_t                        GetId(void) { return mId; }
        const otSrpServerHost          *GetHost(void) { return mHost; }
        const char                     *GetHostName() {return mHostName.AsCString();}
        void                            SetService(const otSrpServerService *aService) { mService = aService; }
        LinkedList<MdnsServer::Service> GetServiceList(void) { return mServiceList; }
        const otSrpServerService       *GetService(void) { return mService; }

        void  SetState(State aState) { mState = aState; }
        State GetState(void) { return mState; }
        void  SetType(Type aType) { mType = aType; }
        Type  GetType(void) { return mType; }

        void PushService(Service &aService) { mServiceList.Push(aService); }
    private:
        uint32_t                        mId;
        const otSrpServerHost          *mHost;
        Heap::String                    mHostName;
        const otSrpServerService       *mService;
        LinkedList<MdnsServer::Service> mServiceList;
        State                           mState;
        Type                            mType;

        OutstandingUpdate *mNext;

        Error Init(uint32_t aId, otSrpServerHost *aHost, Type aType);
    };

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
        void EnqueueAnnounceMessage(Message &aAnnounceMessage) { mAnnouncements.Enqueue(aAnnounceMessage); };
        void StartAnnouncing();
        void HandleTimer();
        void Stop();

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
    MdnsServer::Service   *GetServiceListHead() { return mServices.GetHead(); }

    class Prober : public InstanceLocator
    {
    public:
        /*
            This class implements probe and announce features.
            'Start()' schedules a cycle of transmissions of 'kMaxTxCount' separated by
            'kTxInterval'. At the end of cycle, the callback 'HandleProberFinished()' is invoked to inform end
            of the cycle to 'MdnsServer'
        */

        enum State : uint8_t
        {
            kIdle,              // Idle state
            kTransitionToProbe, // Started timer, first probe yet not send
            kProbing,           // At least one probe has been sent; currently probing for unique records
            kCompleted          // Probing and announcing are now completed
        };

        enum LexicographicallyCompare : int
        {
            LEXICOGRAPHICALLY_EARLIER = -1,
            LEXICOGRAPHICALLY_EQUAL,
            LEXICOGRAPHICALLY_LATER
        };

        struct RREntry : public LinkedListEntry<RREntry>, public Heap::Allocatable<RREntry>
        {
            friend class LinkedListEntry<RREntry>;
            friend class Heap::Allocatable<RREntry>;

        public:
            Name     GetRRName(void) { return mName; }
            uint16_t GetRRStartOffset(void) { return mStartOffset; }
            uint16_t GetRREndOffset(void) { return mEndOffset; }

        private:
            Error Init(Name aName, uint16_t aStartOffset, uint16_t aEndOffset);

            Name     mName;
            uint16_t mStartOffset;
            uint16_t mEndOffset;
            RREntry *mNext;
        };

        Prober(Instance &aInstance);
        void          EnqueueProbeMessage(Message &aProbeMessage) { mQueries.Enqueue(aProbeMessage); };
        bool          IsInProgress(void) const { return mTimer.IsRunning(); }
        void          StartProbing(bool aIsFromHost);
        void          Stop(Error aError);
        void          HandleTimer();
        Prober::State GetState(void) const { return mState; }
        void          ProcessQuery(const Header &aRequestHeader, Message &aRequestMessage);
        void          ProcessResponse(const Header &aRequestHeader, Message &aRequestMessage);
        bool          IsProbingForHost(void) const { return (mProbeForHost == true); }

    private:
        enum TiebreakingResult : int
        {
            LOST = -1,
            TIE  = 0,
            WON  = 1
        };

        // All time intervals are in msec
        static constexpr uint32_t kMaxStartDelay         = 250; // Max random delay before sending the first probe.
        static constexpr uint32_t kTxProbeInterval       = 250;
        static constexpr uint32_t kProbeConflictWaitTime = 1000;
        static constexpr uint32_t kRateLimitedInterval   = 5000;
        static constexpr uint8_t  kMaxTxCount            = 3; // Number of Probes/Announces in one cycle.
        static constexpr uint32_t kMaxProbingConflictstimeInterval = 10000;
        static constexpr uint8_t  kMaxProbingConflicts             = 15;

        using ProberTimer = TimerMilliIn<MdnsServer::Prober, &MdnsServer::Prober::HandleTimer>;

        uint8_t       mTxCount;
        ProberTimer   mTimer;
        Prober::State mState;
        bool          mProbeForHost;
        MessageQueue  mQueries;
        uint8_t       mConflictsCount;
        bool          mProbeRateLimit;
        uint32_t      mTimeOfConflict[kMaxProbingConflicts];

        LinkedList<RREntry> mOwnTiebreakingRecords;
        LinkedList<RREntry> mIncomingTiebreakingRecords;

        void     AddRecordOffsetsFromAuthoritativeSection(const Header        &aHeader,
                                                          const Message       &aMessage,
                                                          const Name          &aName,
                                                          LinkedList<RREntry> &aList);
        uint16_t ReturnAuthoritativeOffsetFromQueryMessage(const Header &aHeader, const Message &aMessage);
        int      CompareResourceRecords(Message &aEntry1, Message &aEntry2);
        int      PerformTiebreak(const Header &aOwnHeader,
                                 Message      &aOwnMessage,
                                 const Header &aincomingHeader,
                                 Message      &aincomingMessage,
                                 Name         &aConflictingName);
        void     RestartProbing(uint32_t aDelay);
        void     SetState(Prober::State aState) { mState = aState; }
        void     FreeAllRREntries(LinkedList<RREntry> &aList);
        void     ProcessProbeConflict(void);
    };

    MdnsServer::Prober &GetProber() { return mProber; }

private:
    using NameCompressInfo         = Server::NameCompressInfo;
    using NameComponentsOffsetInfo = Server::NameComponentsOffsetInfo;

    union DnsCallback
    {
        Client::AddressCallback mAddressCallback;
        Client::BrowseCallback  mBrowseCallback;
        Client::ServiceCallback mServiceCallback;
    };

    static void HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo);
    void        HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo);
#if MDNS_USE_TASKLET
    void HandleUdpReceive();
#endif

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

    /**
     * This function requests a service content to be updated with server.
     * @param[in] aService                 A pointer to an existing service from mDNS services list.
     * @param[in] aPort                    The service port number.
     * @param[in] aTxtEntries              A pointer to an array containing TXT entries (e.g., ["VAL1=1", "VAL2=2"])
     *                                     (`mNumTxtEntries` gives num of entries).
     * @param[in] mNumTxtEntries           Number of entries in the `aTxtEntries` array
     *
     * @retval kErrorNone               The update finalized successfully.
     * @retval kErrorFailed             The update failed.
     */
    Error UpdateServiceContent(Service             *aService,
                               uint16_t             aPort,
                               const otDnsTxtEntry *aTxtEntries,
                               uint8_t              mNumTxtEntries);

    void  HandleProberFinished(Error aError);
    void  HandleAnnouncerFinished();
    Error AnnounceServiceGoodbye(Service &aService);
    Error AnnounceSrpServiceGoodbye(const otSrpServerService *aService);
    Error AnnounceHostGoodbye();
    Error AnnounceSrpHostGoodbye(const otSrpServerHost *aHost);
    Error AppendServiceInfo(Message &aMessage, Header &aHeader, Service &aService, NameCompressInfo &aCompressInfo);
    Error SendPacket(Message          &aMessage,
                     Header           &aHeader,
                     Header::Response  aResponseCode = Header::kResponseSuccess,
                     bool              aSendUnicast  = false,
                     Ip6::MessageInfo *aMessageInfo  = nullptr);
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

    void        MdnsProbingHandler();
    void        OutstandingUpdateHandler();
    void        MdnsAnnouncingHandler();
    static void SrpAdvertisingProxyHandler(otSrpServerServiceUpdateId aId,
                                           const otSrpServerHost     *aHost,
                                           uint32_t                   aTimeout,
                                           void                      *aContext);
    void SrpAdvertisingProxyHandler(otSrpServerServiceUpdateId aId, const otSrpServerHost *aHost, uint32_t aTimeout);
    void CheckForOutstandingUpdates(void);
    Message *CreateHostAndServicesAnnounceMessage(OutstandingUpdate *aUpdate);
    Message *CreateHostAndServicesPublishMessage(OutstandingUpdate *aUpdate);
    Error    PublishHostAndServices(OutstandingUpdate *aUpdate);
    Message *CreateSrpAnnounceMessage(const char *aHostName);
    Message *CreateSrpPublishMessage(const otSrpServerHost *aHost);
    Error    PublishFromSrp(const otSrpServerHost *aHost);
    bool     AddressIsFromLocalSubnet(const Ip6::Address &srcAddr);

    using RetryTimer = TimerMilliIn<MdnsServer, &MdnsServer::HandleTimer>;
#if MDNS_USE_TASKLET
    using RxTask = TaskletIn<MdnsServer, &MdnsServer::HandleUdpReceive>;
#endif
    using OutstandingUpdateTask = TaskletIn<MdnsServer, &MdnsServer::OutstandingUpdateHandler>;
    using MdnsProbingTask       = TaskletIn<MdnsServer, &MdnsServer::MdnsProbingHandler>;
    using MdnsAnnouncingTask    = TaskletIn<MdnsServer, &MdnsServer::MdnsAnnouncingHandler>;

    static const char kDefaultDomainName[];
    static const char kThreadDefaultDomainName[];

    RetryTimer                mTimer;
    Ip6::Udp::Socket          mSocket;
    MessageQueue              mQueries;
    MessageQueue              mRxPktQueue;
    State                     mState;
    Heap::String              mHostName;
    Heap::Array<Ip6::Address> mAddresses;
#if MDNS_USE_TASKLET
    RxTask mHandleUdpReceive;
#endif
    LinkedList<Service>           mServices;
    Announcer                     mAnnouncer;
    LinkedList<OutstandingUpdate> mOutstandingUpdates;
    MdnsProbingTask               mMdnsProbing;
    MdnsAnnouncingTask            mMdnsAnnouncing;
    ServiceUpdateId               mServiceUpdateId;
    Prober                        mProber;
    bool                          mIsHostVerifiedUnique;
    OutstandingUpdateTask         mMdnsOustandingUpdate;
};

} // namespace ServiceDiscovery
} // namespace Dns

DefineCoreType(otMdnsService, Dns::ServiceDiscovery::MdnsServer::Service);
DefineCoreType(otMdnsServiceSubTypeEntry, Dns::ServiceDiscovery::MdnsServer::Service::SubTypeEntry);

} // namespace ot

#endif // OPENTHREAD_CONFIG_MDNS_SERVER_ENABLE

#endif // MDNS_HPP

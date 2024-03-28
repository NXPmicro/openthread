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
 *   This file implements the MDNS server.
 */

#include "mdns_server.hpp"

#if OPENTHREAD_CONFIG_MDNS_SERVER_ENABLE
#include "srp_server.hpp"
#include "common/locator_getters.hpp"
#include "utils/parse_cmdline.hpp"

using ot::Utils::CmdLineParser::ParseAsHexString;

namespace ot {
namespace Dns {
namespace ServiceDiscovery {

// RegisterLogModule("DnssdServer");

#define HOST_MAX_IP6_ADDRESSES 2
#define TXT_DATA_BUFER_SIZE 100

const char         MdnsServer::kDefaultDomainName[]       = "local.";
const char         MdnsServer::kThreadDefaultDomainName[] = "default.service.arpa.";
static const char  kServiceSubTypeLabel[]                 = "._sub.";
const otIp6Address kMdnsMulticastGroup                    = {0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFB};
const otIp6Address kAnyAddress                            = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

MdnsServer::MdnsServer(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mTimer(aInstance)
    , mSocket(aInstance)
 #if MDNS_USE_TASKLET
    , mHandleUdpReceive(aInstance)
#endif
    , mServiceUpdateId(1)
    , mIsHostVerifiedUnique(false)
{
    SetState(kStateStopped);
}

Error MdnsServer::Start(void)
{
    Error error = kErrorNone;
    Prober  *prober = nullptr;
    Service *next   = nullptr;

    VerifyOrExit(!IsRunning(), error = kErrorAlready);
    VerifyOrExit(GetHostName() != nullptr, error = kErrorInvalidState);

    SuccessOrExit(error = mSocket.Open(&MdnsServer::HandleUdpReceive, this));
    SuccessOrExit(error = mSocket.Bind(kPort, Ip6::kNetifBackbone));
    SuccessOrExit(error = mSocket.JoinNetifMulticastGroup(Ip6::kNetifBackbone, AsCoreType(&kMdnsMulticastGroup)));

    Get<Srp::Server>().SetServiceHandler(SrpAdvertisingProxyHandler, this);

    SetState(kStateRunning);

    LogInfo("started");

    prober = AllocateProber(true, nullptr, 0);
    VerifyOrExit(prober != nullptr, error = kErrorNoBufs);

    if(!mServices.IsEmpty())
    {
        for (Service *service = mServices.GetHead(); service != nullptr; service = next)
        {
            next = service->GetNext();
            prober->PushServiceId(service->GetServiceUpdateId());
        }
    }

    PublishHostAndServices(prober);
exit:

    if (error != kErrorNone)
    {
        IgnoreError(mSocket.Close());
    }

    return error;
}

void MdnsServer::Stop(void)
{
    IgnoreError(mSocket.Close());

    AnnounceHostGoodbye();

    Get<Srp::Server>().SetServiceHandler(nullptr, nullptr);

    SetState(kStateStopped);

    LogInfo("stopped");
}

Error MdnsServer::ResolveAddress(const char *aHostName, Client::AddressCallback aCallback, void *aContext)
{
    Client::QueryInfo info;

    info.Clear();
    info.mCallback.mAddressCallback = aCallback;
    info.mCallbackContext           = aContext;
    info.mQueryType                 = Client::kIp6AddressQuery;

    info.mConfig.mResponseTimeout = 1000; // ms
    info.mConfig.mMaxTxAttempts =
        6; // calculated for a maximum resolve time of 64 sec with interval doubling for each new query

    return StartQuery(info, aHostName);
}

Error MdnsServer::Browse(const char *aServiceName, Client::BrowseCallback aCallback, void *aContext)
{
    Client::QueryInfo info;

    info.Clear();
    info.mCallback.mBrowseCallback = aCallback;
    info.mCallbackContext          = aContext;
    info.mQueryType                = Client::kBrowseQuery;

    info.mConfig.mResponseTimeout = 1000; // in ms
    info.mConfig.mMaxTxAttempts =
        7; // calculated for a maximum browse time of 128 sec with interval doubling for each new query

    return StartQuery(info, aServiceName);
}

Error MdnsServer::ResolveService(const char *aName, Client::ServiceCallback aCallback, void *aContext)
{
    Error             error = kErrorNone;
    Client::QueryInfo info;

    info.Clear();
    info.mCallback.mServiceCallback = aCallback;
    info.mCallbackContext           = aContext;
    info.mQueryType                 = Client::kServiceQuerySrvTxt;

    info.mConfig.mResponseTimeout = 1000; // ms
    info.mConfig.mMaxTxAttempts =
        6; // calculated for a maximum resolve time of 64 sec with interval doubling for each new query

    VerifyOrExit(aName != nullptr, error = kErrorInvalidArgs);

    error = StartQuery(info, aName);

exit:
    return error;
}

Error MdnsServer::StopQuery(const char *aName)
{
    Message *query = FindQueryByName(aName);
    if (query != nullptr)
    {
        FreeQuery(*query);
        return kErrorNone;
    }
    else
    {
        return kErrorNotFound;
    }
}

void MdnsServer::StopQueryFromDnsSd(const char *aName)
{
    char queryName[Name::kMaxNameSize];

    // Convert from thread domain to .local
    ConvertDomainName(queryName, aName, Server::kDefaultDomainName, kDefaultDomainName);

    IgnoreReturnValue(StopQuery(queryName));
}

Message *MdnsServer::NewPacket()
{
    Error    error  = kErrorNone;
    Message *packet = nullptr;

    VerifyOrExit((packet = mSocket.NewMessage(0)) != nullptr, error = kErrorNoBufs);
    SuccessOrExit(error = packet->SetLength(sizeof(Header)));

exit:
    FreeMessageOnError(packet, error);
    return packet;
}

void MdnsServer::HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    static_cast<MdnsServer *>(aContext)->HandleUdpReceive(AsCoreType(aMessage), AsCoreType(aMessageInfo));
}

void MdnsServer::HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
#if MDNS_USE_TASKLET
    aMessage.Append(aMessageInfo);
    mRxPktQueue.Enqueue(aMessage);

    mHandleUdpReceive.Post();
#else
    Header           requestHeader;
    
    if (kErrorNone == aMessage.Read(aMessage.GetOffset(), requestHeader))
    {
        if (requestHeader.GetType() == Header::kTypeQuery)
        {
            ProcessQuery(requestHeader, aMessage, aMessageInfo);
        }
        else if (requestHeader.GetType() == Header::kTypeResponse)
        {
            ProcessResponse(requestHeader, aMessage, aMessageInfo);
        }
    }
#endif
}

#if MDNS_USE_TASKLET
void MdnsServer::HandleUdpReceive()
{
    Message         *aMessage;
    Ip6::MessageInfo aMessageInfo;
    Header           requestHeader;

    aMessage = mRxPktQueue.GetHead();

    while (aMessage != nullptr)
    {
        if (kErrorNone == aMessage->Read(aMessage->GetLength() - sizeof(aMessageInfo), aMessageInfo))
        {
            if (kErrorNone == aMessage->Read(aMessage->GetOffset(), requestHeader))
            {
                // RFC 6762, section 18.3 OPCODE
                // RFC 6762, section 18.11 RCODE
                if ((requestHeader.GetQueryType() == Header::kQueryTypeStandard) &&
                    (Header::ResponseCodeToError(requestHeader.GetResponseCode()) == kErrorNone))
                {
                    if (requestHeader.GetType() == Header::kTypeQuery)
                    {
                        ProcessQuery(requestHeader, *aMessage, aMessageInfo);
                    }
                    else if (requestHeader.GetType() == Header::kTypeResponse)
                    {
                        ProcessResponse(requestHeader, *aMessage, aMessageInfo);
                    }
                }
            }
        }
        mRxPktQueue.DequeueAndFree(*aMessage);
        aMessage = mRxPktQueue.GetHead();
    }
}
#endif

void MdnsServer::ProcessQuery(const Dns::Header      &aRequestHeader,
                              Message                &aRequestMessage,
                              const Ip6::MessageInfo &aMessageInfo)
{
    Error                    error           = kErrorNone;
    Message                 *responseMessage = nullptr;
    Header                   responseHeader;
    Header::Response         responseCode;
    Server::NameCompressInfo compressInfo(kDefaultDomainName);
    bool                     bSendUnicast          = false;
    bool                     legacyUnicastResponse = false;
    uint16_t                 legacyOffset          = 0;

     // RFC 6762, sections 5.5
    if (!aMessageInfo.GetSockAddr().IsmDNSLinkLocalMulticast())
    {
        VerifyOrExit(aMessageInfo.GetPeerAddr().IsLinkLocal() || AddressIsFromLocalSubnet(aMessageInfo.GetPeerAddr()), error = kErrorDrop);
    }

    // Validate the query
    VerifyOrExit(!aRequestHeader.IsTruncationFlagSet(), error = kErrorDrop);
    VerifyOrExit(aRequestHeader.GetQuestionCount() > 0, error = kErrorDrop);

    VerifyOrExit(responseMessage = NewPacket(), error = kErrorNoBufs);

    if (aRequestHeader.GetAuthorityRecordCount() > 0 && aRequestHeader.GetAnswerCount() == 0)
    {
        for (Prober &p : mProbingInstances)
        {
            p.ProcessQuery(aRequestHeader, aRequestMessage);
        }
    }

    responseHeader.SetType(Header::kTypeResponse);

    // As per RFC6762, section 6.7 Legacy Unicast Responses, check if this a legacy query
    // A legacy query is sent on another port than 5353, and has only one question : it's not a fully implemented
    // multicast DNS responder, thus it has not the capability of aggregating questions.

    if (aMessageInfo.mPeerPort != kPort)
    {
        if (aRequestHeader.GetQuestionCount() == 1)
        {
            legacyUnicastResponse = true;
        }
        else
        {
            error = kErrorDrop;
            ExitNow();
        }
    }

    if (legacyUnicastResponse)
    {
        // Response MUST
        // 1. Repeat query id
        responseHeader.SetMessageId(aRequestHeader.GetMessageId());
        // 2. Repeat question given in the query message
        responseCode =
            Server::AddQuestions(aRequestHeader, aRequestMessage, responseHeader, *responseMessage, compressInfo);
        // 3. Cache-flush bit not set -> will be done by MarkRecordsAsLegacyUnicast() method call

        bSendUnicast |= true;
        legacyOffset = responseMessage->GetLength();
    }

    responseCode =
        ResolveQuery(aRequestHeader, aRequestMessage, responseHeader, *responseMessage, compressInfo, bSendUnicast);
    VerifyOrExit(responseCode == Header::kResponseSuccess, error = kErrorDrop);

    if (legacyUnicastResponse)
    {
        // Response SHOULD
        // 1. TTL given SHOULD not be greater than 10 seconds
        ResourceRecord::MarkRecordsAsLegacyUnicast(*responseMessage, legacyOffset,
                                                   responseHeader.GetAnswerCount() +
                                                       responseHeader.GetAdditionalRecordCount());
        SuccessOrExit(error = SendPacket(*responseMessage, responseHeader, responseCode, bSendUnicast,
                                         &AsNonConst(aMessageInfo)));
        ExitNow();
    }

    SuccessOrExit(error = SendPacket(*responseMessage, responseHeader, responseCode, bSendUnicast));

exit:
    FreeMessageOnError(responseMessage, error);
}

void MdnsServer::ProcessResponse(const Header           &aRequestHeader,
                                 Message                &aRequestMessage,
                                 const Ip6::MessageInfo &aMessageInfo)
{
    Client::Response  response;
    Client::QueryInfo info;

    response.mInstance = &Get<Instance>();
    response.mMessage  = &aRequestMessage;

    /* Ignore responses with a source port different from 5353 */
    /*The source UDP port in all Multicast DNS responses MUST be 5353 (the
    well-known port assigned to mDNS). Multicast DNS implementations
    MUST silently ignore any Multicast DNS responses they receive where
    the source UDP port is not 5353.*/

    if (aMessageInfo.mPeerPort != kPort)
    {
        return;
    }

    // RFC 6762, sections 11
    if (!aMessageInfo.GetSockAddr().IsmDNSLinkLocalMulticast())
    {
        VerifyOrExit(aMessageInfo.GetPeerAddr().IsLinkLocal() || AddressIsFromLocalSubnet(aMessageInfo.GetPeerAddr()));
    }

        for (Prober &p : mProbingInstances)
        {
            p.ProcessResponse(aRequestHeader, aRequestMessage);
        }

    // if (ans.info.type == DNS_RRTYPE_ANY || ans.info.klass != DNS_RRCLASS_IN) {
    /* Skip answers for ANY type or if class != IN */
    // continue;

    // We intentionally parse the response in a separate method
    // `ParseResponse()` to free all the stack allocated variables
    // (e.g., `QueryInfo`) used during parsing of the message before
    // finalizing the query and invoking the user's callback.
    SuccessOrExit(ParseResponse(aRequestHeader, aRequestMessage, response));

    info.ReadFrom(*response.mQuery);
    if (info.mCallback.mAddressCallback == nullptr)
    {
        // in this case we are handling a query from dns-sd server
        HandleDnsSdResult(response, info);
    }
    else
    {
        FinalizeQuery(response, kErrorNone);
    }
exit:
    return;
}

Error MdnsServer::AllocateQuery(const Client::QueryInfo &aInfo, const char *aName, Message *&aQuery)
{
    Error    error    = kErrorNone;
    uint16_t ansCount = 0;

    VerifyOrExit(aInfo.mConfig.GetResponseTimeout() <= TimerMilli::kMaxDelay, error = kErrorInvalidArgs);
    VerifyOrExit((aQuery = Get<MessagePool>().Allocate(Message::kTypeOther)) != nullptr, error = kErrorNoBufs);

    SuccessOrExit(error = aQuery->Append(aInfo));
    SuccessOrExit(error = Name::AppendName(aName, *aQuery));
    // Set the current ansert count to 0, after we receive answers this value will reflect the number of answers
    // located after it
    SuccessOrExit(error = aQuery->AppendBytes(&ansCount, sizeof(ansCount)));

exit:
    FreeAndNullMessageOnError(aQuery, error);
    return error;
}

Error MdnsServer::StartQuery(Client::QueryInfo &aInfo, const char *aName)
{
    Message *query = nullptr;
    Error    error = kErrorNone;

    SuccessOrExit(error = AllocateQuery(aInfo, aName, query));
    mQueries.Enqueue(*query);

    // Double the timeout between each new attempt
    UpdateTimeout(*query, aInfo, true);
    mTimer.FireAtIfEarlier(aInfo.mRetransmissionTime);

    SuccessOrExit(error = SendQuery(aName, *query, GetRecordType(aInfo.mQueryType), false));

exit:
    return error;
}

Error MdnsServer::SendQuery(Message &aQuery, Client::QueryInfo &aInfo)
{
    char     name[Name::kMaxNameSize];
    uint16_t offset = sizeof(Client::QueryInfo);

    Name::ReadName(aQuery, offset, name, sizeof(name));
    return SendQuery(name, aQuery, GetRecordType(aInfo.mQueryType), false);
}

Error MdnsServer::SendQuery(const char *aName, Message &aQuery, uint16_t qestionType, bool bUnicastQuestion)
{
    Error                    error          = kErrorNone;
    Message                 *requestMessage = nullptr;
    Header                   requestHeader;
    Question                 question(qestionType);
    Server::NameCompressInfo compressInfo(kDefaultDomainName);
    Ip6::MessageInfo         aMessageInfo;

    uint16_t offset = sizeof(Client::QueryInfo);
    offset += StringLength(aName, Name::kMaxNameLength) + 1;
    uint16_t ansCount = 0;

    // MDNS supports searching for services using the .local domain name
    VerifyOrExit(Name::IsSubDomainOf(aName, kDefaultDomainName), error = kErrorInvalidArgs);
    // Check if question type is supported
    VerifyOrExit(qestionType == ResourceRecord::kTypePtr || qestionType == ResourceRecord::kTypeSrv ||
                     qestionType == ResourceRecord::kTypeTxt || qestionType == ResourceRecord::kTypeAaaa ||
                     qestionType == ResourceRecord::kTypeAny,
                 error = kErrorInvalidArgs);

    // Setup initial DNS response header
    requestHeader.SetType(Header::kTypeQuery);
    // mDNS queries are sent with message ID 0
    requestHeader.SetQuestionCount(1);

    requestMessage = mSocket.NewMessage(0);
    VerifyOrExit(requestMessage != nullptr, error = kErrorNoBufs);

    // Allocate space for DNS header
    SuccessOrExit(error = requestMessage->SetLength(sizeof(Header)));
    // Add question to message buffer

    if (bUnicastQuestion)
    {
        question.SetQuQuestion();
    }
    VerifyOrExit(Server::AppendQuestion(aName, question, *requestMessage, compressInfo) == kErrorNone,
                 error = kErrorFailed);
    if (question.GetType() == ResourceRecord::kTypeSrv)
    {
        question.SetType(ResourceRecord::kTypeTxt);
        requestHeader.SetQuestionCount(2);
        VerifyOrExit(Server::AppendQuestion(aName, question, *requestMessage, compressInfo) == kErrorNone,
                     error = kErrorFailed);
    }

    // Check and append known answers after questions section
    aQuery.Read(offset, &ansCount, sizeof(ansCount));

    if (ansCount)
    {
        offset += sizeof(ansCount);
        requestMessage->AppendBytesFromMessage(aQuery, offset, aQuery.GetLength() - offset);
        requestHeader.SetAnswerCount(ansCount);
    }

    // Send the question using platform UDP
    requestMessage->Write(0, requestHeader);

    // Set src/dst parameters
    aMessageInfo.SetPeerAddr(AsCoreType(&kMdnsMulticastGroup));
    aMessageInfo.SetSockPort(kPort);
    aMessageInfo.SetPeerPort(kPort);
    aMessageInfo.SetIsHostInterface(true);

    error = mSocket.SendTo(*requestMessage, aMessageInfo);

    if (error != kErrorNone)
    {
        // LogWarn("failed to send mDNS query: %s", ErrorToString(error));
    }
    else
    {
        // LogInfo("send mDNS query: %s, aName);
    }
exit:
    FreeMessageOnError(requestMessage, error);
    return error;
}

Error MdnsServer::ParseResponse(const Header &aRequestHeader, Message &aRequestMessage, Client::Response &aResponse)
{
    Error    error      = kErrorNone;
    uint16_t offset     = aRequestMessage.GetOffset() + sizeof(Header);
    uint16_t nameOffset = offset;
    uint16_t ansCount   = 0;

    VerifyOrExit((aRequestHeader.GetQueryType() == Header::kQueryTypeStandard) &&
                     (aRequestHeader.GetAnswerCount() > 0) && !aRequestHeader.IsTruncationFlagSet(),
                 error = kErrorDrop);

    aResponse.mQuery = FindQueryByName(aRequestMessage, nameOffset);
    // The error is drop as we can receive all multicast responses from the network and this one was not meant for
    // us
    VerifyOrExit(aResponse.mQuery != nullptr, error = kErrorDrop);

    // Check the answer, authority and additional record sections
    aResponse.mAnswerOffset = offset;
    SuccessOrExit(error = ResourceRecord::ParseRecords(aRequestMessage, offset, aRequestHeader.GetAnswerCount()));
    SuccessOrExit(error =
                      ResourceRecord::ParseRecords(aRequestMessage, offset, aRequestHeader.GetAuthorityRecordCount()));
    aResponse.mAdditionalOffset = offset;
    SuccessOrExit(error =
                      ResourceRecord::ParseRecords(aRequestMessage, offset, aRequestHeader.GetAdditionalRecordCount()));

    aResponse.mAnswerRecordCount     = aRequestHeader.GetAnswerCount();
    aResponse.mAdditionalRecordCount = aRequestHeader.GetAdditionalRecordCount();

    // Read the current number of stored answers
    aResponse.mQuery->Read(nameOffset, &ansCount, sizeof(ansCount));
    ansCount += aResponse.mAnswerRecordCount;
    // Update the answer count value back in the query
    aResponse.mQuery->WriteBytes(nameOffset, &ansCount, sizeof(ansCount));
    // Append received answers to the query -> known answer suppression
    aResponse.mQuery->AppendBytesFromMessage(aRequestMessage, aResponse.mAnswerOffset,
                                             aResponse.mAdditionalOffset - aResponse.mAnswerOffset);

exit:
    if (error != kErrorNone)
    {
        // LogInfo("Failed to parse response %s", ErrorToString(error));
    }

    return error;
}

void MdnsServer::FinalizeQuery(Message &aQuery, Error aError)
{
    Client::Response  response;
    Client::QueryInfo info;

    response.mInstance = &Get<Instance>();
    response.mQuery    = &aQuery;
    info.ReadFrom(aQuery);

    FinalizeQuery(response, aError);
}

void MdnsServer::FinalizeQuery(Client::Response &aResponse, Error aError)
{
    Client::QueryInfo aInfo;
    aInfo.ReadFrom(*aResponse.mQuery);

    switch (aInfo.mQueryType)
    {
    case Client::kIp6AddressQuery:
        if (aInfo.mCallback.mAddressCallback != nullptr)
        {
            aInfo.mCallback.mAddressCallback(aError, &aResponse, aInfo.mCallbackContext);
        }
        break;

    case Client::kBrowseQuery:
        if (aInfo.mCallback.mBrowseCallback != nullptr)
        {
            aInfo.mCallback.mBrowseCallback(aError, &aResponse, aInfo.mCallbackContext);
        }
        break;

    case Client::kServiceQuerySrvTxt:
        if (aInfo.mCallback.mServiceCallback != nullptr)
        {
            aInfo.mCallback.mServiceCallback(aError, &aResponse, aInfo.mCallbackContext);
        }
        break;

    default:
        break;
    }

    if (aError == kErrorResponseTimeout)
    {
        FreeQuery(*aResponse.mQuery);
    }
}

Message *MdnsServer::FindQueryByName(const Message &aMessage, uint16_t &aOffset)
{
    Message *matchedQuery = nullptr;
    Name     queryName;
    uint16_t tmpOffset;

    for (Message &query : mQueries)
    {
        tmpOffset = sizeof(Client::QueryInfo);

        // the second offset (aOffset) doesn't get updated by the function
        if (kErrorNone == Name::CompareName(query, tmpOffset, aMessage, aOffset))
        {
            matchedQuery = &query;
            // return back the offset where the name ends in the query so it can be used to store the number of
            // known answers
            aOffset = tmpOffset;
            break;
        }
    }

    return matchedQuery;
}

Message *MdnsServer::FindQueryByName(const char *aName)
{
    Message *matchedQuery = nullptr;
    uint16_t tmpOffset;

    for (Message &query : mQueries)
    {
        tmpOffset = sizeof(Client::QueryInfo);
        ;

        if (kErrorNone == Name::CompareName(query, tmpOffset, aName))
        {
            matchedQuery = &query;
            break;
        }
    }

    return matchedQuery;
}

Header::Response MdnsServer::ResolveQuestion(const char                   *aName,
                                             const Question               &aQuestion,
                                             Header                       &aResponseHeader,
                                             Message                      &aResponseMessage,
                                             NameCompressInfo             &aCompressInfo,
                                             bool                          aAdditional,
                                             LinkedList<KnownAnswerEntry> &aKnownAnswersList)
{
    const Service    *service                  = nullptr;
    uint16_t          qtype                    = aQuestion.GetType();
    bool              needAdditionalAaaaRecord = false;
    bool              shouldSuppressAnswer     = false;
    Header::Response  responseCode             = Header::kResponseSuccess;

    bool serviceNameMatched = false;

    const char *subServiceName = nullptr;
    bool        isSubTypeQuery = false;

    subServiceName = StringFind(aName, kServiceSubTypeLabel, kStringCaseInsensitiveMatch);
    isSubTypeQuery = (subServiceName != nullptr);

    if (isSubTypeQuery)
    {
        // Skip over the "._sub." label to get to the base
        // service name.
        subServiceName += sizeof(kServiceSubTypeLabel) - 1;
    }

    while ((service = FindNextService(service)) != nullptr)
    {
        if (isSubTypeQuery)
        {
            serviceNameMatched = service->MatchesServiceName(subServiceName);
        }
        else
        {
            serviceNameMatched = service->MatchesServiceName(aName);
        }
        bool instanceNameMatched = service->MatchesInstanceName(aName);
        bool ptrQueryMatched =
            (qtype == ResourceRecord::kTypePtr || qtype == ResourceRecord::kTypeAny) && serviceNameMatched;
        bool srvQueryMatched =
            (qtype == ResourceRecord::kTypeSrv || qtype == ResourceRecord::kTypeAny) && instanceNameMatched;
        bool txtQueryMatched =
            (qtype == ResourceRecord::kTypeTxt || qtype == ResourceRecord::kTypeAny) && instanceNameMatched;

        for (KnownAnswerEntry &entry : aKnownAnswersList)
        {
            if (StringMatch(entry.GetServiceName(), service->GetServiceName(), kStringCaseInsensitiveMatch) &&
                StringMatch(entry.GetInstanceName(), service->GetInstanceName(), kStringCaseInsensitiveMatch) &&
                entry.GetRecord().GetTtl() > service->GetTtl() / 2)
            {
                shouldSuppressAnswer = true;
                break;
            }
        }

        if (shouldSuppressAnswer)
        {
            break;
        }

        if (ptrQueryMatched || srvQueryMatched)
        {
            needAdditionalAaaaRecord = true;
        }

        if (!aAdditional && ptrQueryMatched)
        {
            if (isSubTypeQuery)
            {
                for (Service::SubTypeEntry &entry : AsNonConst(service)->GetSubTypeList())
                {
                    if (StringMatch(entry.GetName(), aName, kStringExactMatch))
                    {
                        VerifyOrExit(
                            (Server::AppendPtrRecord(aResponseMessage, entry.GetName(), service->GetInstanceName(),
                                                     service->GetTtl(), aCompressInfo) == kErrorNone),
                            responseCode = Header::kResponseNameError);
                        Server::IncResourceRecordCount(aResponseHeader, false);

                        break;
                    }
                }
            }
            else
            {
                VerifyOrExit(
                    (Server::AppendPtrRecord(aResponseMessage, service->GetServiceName(), service->GetInstanceName(),
                                             service->GetTtl(), aCompressInfo) == kErrorNone),
                    responseCode = Header::kResponseNameError);
                Server::IncResourceRecordCount(aResponseHeader, false);
            }
        }

        if ((!aAdditional && srvQueryMatched) || (aAdditional && ptrQueryMatched))
        {
            VerifyOrExit((Server::AppendSrvRecord(aResponseMessage, service->GetInstanceName(), GetHostName(),
                                                  service->GetTtl(), service->GetPriority(), service->GetWeight(),
                                                  service->GetPort(), aCompressInfo, service->GetState() >= Service::State::kProbed) == kErrorNone),
                         responseCode = Header::kResponseNameError);
            Server::IncResourceRecordCount(aResponseHeader, aAdditional);
        }

        if ((!aAdditional && txtQueryMatched) || (aAdditional && ptrQueryMatched))
        {
            VerifyOrExit(
                (Server::AppendTxtRecord(aResponseMessage, service->GetInstanceName(), service->GetTxtData(),
                                         service->GetTxtDataLength(), kDefaultTtl, aCompressInfo, service->GetState() >= Service::State::kProbed) == kErrorNone),
                responseCode = Header::kResponseNameError);
            Server::IncResourceRecordCount(aResponseHeader, aAdditional);
        }
    }

    if ((!aAdditional && (qtype == ResourceRecord::kTypeAaaa || qtype == ResourceRecord::kTypeAny) &&
         (!strcmp(GetHostName(), aName))) ||
        (aAdditional && needAdditionalAaaaRecord))
    {
        uint8_t             addrNum;
        const Ip6::Address *addrs = GetAddresses(addrNum);

        for (uint8_t i = 0; i < addrNum; i++)
        {
            VerifyOrExit((Server::AppendAaaaRecord(aResponseMessage, GetHostName(), addrs[i], kDefaultTtlWithHostName,
                                                   aCompressInfo, mIsHostVerifiedUnique) == kErrorNone),
                         responseCode = Header::kResponseNameError);
            Server::IncResourceRecordCount(aResponseHeader, aAdditional);
        }
    }

exit:
    return responseCode;
}

Header::Response MdnsServer::ResolveQuestionBySrp(const char                   *aName,
                                                  const Question               &aQuestion,
                                                  Header                       &aResponseHeader,
                                                  Message                      &aResponseMessage,
                                                  NameCompressInfo             &aCompressInfo,
                                                  bool                          aAdditional,
                                                  LinkedList<KnownAnswerEntry> &aKnownAnswersList)
{
    Error                    error                = kErrorNone;
    const Srp::Server::Host *host                 = nullptr;
    TimeMilli                now                  = TimerMilli::GetNow();
    uint16_t                 qtype                = aQuestion.GetType();
    Header::Response         response             = Header::kResponseNameError;
    bool                     shouldSuppressAnswer = false;
    KnownAnswerEntry        *kaElement            = nullptr;

    if(!aKnownAnswersList.IsEmpty())
    {
        kaElement = aKnownAnswersList.GetHead();
    }

    while ((host = Get<Server>().GetNextSrpHost(host)) != nullptr)
    {
        bool        needAdditionalAaaaRecord = false;
        const char *hostName                 = host->GetFullName();

        // Handle PTR/SRV/TXT/ANY query
        if (qtype == ResourceRecord::kTypePtr || qtype == ResourceRecord::kTypeSrv ||
            qtype == ResourceRecord::kTypeTxt || qtype == ResourceRecord::kTypeAny)
        {
            const Srp::Server::Service *service = nullptr;

            while ((service = Get<Server>().GetNextSrpService(*host, service)) != nullptr)
            {
                uint32_t    instanceTtl         = TimeMilli::MsecToSec(service->GetExpireTime() - TimerMilli::GetNow());
                const char *instanceName        = service->GetInstanceName();
                char        convertedInstanceName[Dns::Name::kMaxNameSize];
                char        convertedServiceName[Dns::Name::kMaxNameSize];
                bool        serviceNameMatched  = service->MatchesServiceName(aName);
                bool        instanceNameMatched = (!service->IsSubType() && service->MatchesInstanceName(aName));
                bool        ptrQueryMatched =
                    (qtype == ResourceRecord::kTypePtr || qtype == ResourceRecord::kTypeAny) && serviceNameMatched;
                bool srvQueryMatched =
                    (qtype == ResourceRecord::kTypeSrv || qtype == ResourceRecord::kTypeAny) && instanceNameMatched;
                bool txtQueryMatched =
                    (qtype == ResourceRecord::kTypeTxt || qtype == ResourceRecord::kTypeAny) && instanceNameMatched;

                for (; kaElement != nullptr; kaElement = kaElement->GetNext())
                {
                    ConvertDomainName(convertedInstanceName, kaElement->GetInstanceName(), kDefaultDomainName,
                                      Server::kDefaultDomainName);
                    ConvertDomainName(convertedServiceName, kaElement->GetServiceName(), kDefaultDomainName,
                                      Server::kDefaultDomainName);

                    if (StringMatch(convertedServiceName, service->GetServiceName(), kStringCaseInsensitiveMatch) &&
                        StringMatch(convertedInstanceName, service->GetInstanceName(), kStringCaseInsensitiveMatch) &&
                        kaElement->GetRecord().GetTtl() > service->GetTtl() / 2)
                    {
                        shouldSuppressAnswer = true;
                        break;
                    }
                }

                if (shouldSuppressAnswer)
                {
                    break;
                }

                if (ptrQueryMatched || srvQueryMatched)
                {
                    needAdditionalAaaaRecord = true;
                }

                if (!aAdditional && ptrQueryMatched)
                {
                    SuccessOrExit(
                        error = Server::AppendPtrRecord(aResponseMessage, aName, instanceName, instanceTtl, aCompressInfo));
                    Server::IncResourceRecordCount(aResponseHeader, aAdditional);
                    response = Header::kResponseSuccess;
                }

                if ((!aAdditional && srvQueryMatched) ||
                    (aAdditional && ptrQueryMatched &&
                     !Server::HasQuestion(aResponseHeader, aResponseMessage, instanceName, ResourceRecord::kTypeSrv)))
                {
                    SuccessOrExit(error = Server::AppendSrvRecord(aResponseMessage, instanceName, hostName, instanceTtl,
                                                          service->GetPriority(), service->GetWeight(),
                                                          service->GetPort(), aCompressInfo));
                    Server::IncResourceRecordCount(aResponseHeader, aAdditional);
                    response = Header::kResponseSuccess;
                }

                if ((!aAdditional && txtQueryMatched) ||
                    (aAdditional && ptrQueryMatched &&
                     !Server::HasQuestion(aResponseHeader, aResponseMessage, instanceName, ResourceRecord::kTypeTxt)))
                {
                    SuccessOrExit(error = Server::AppendTxtRecord(aResponseMessage, instanceName, service->GetTxtData(),
                                                          service->GetTxtDataLength(), instanceTtl, aCompressInfo));
                    Server::IncResourceRecordCount(aResponseHeader, aAdditional);
                    response = Header::kResponseSuccess;
                }
            }
        }

        // Handle AAAA query
        if ((!aAdditional && (qtype == ResourceRecord::kTypeAaaa || qtype == ResourceRecord::kTypeAny) &&
             host->Matches(aName)) ||
            (aAdditional && needAdditionalAaaaRecord &&
             !Server::HasQuestion(aResponseHeader, aResponseMessage, hostName, ResourceRecord::kTypeAaaa)))
        {
            uint8_t             addrNum;
            const Ip6::Address *addrs   = host->GetAddresses(addrNum);
            uint32_t            hostTtl = TimeMilli::MsecToSec(host->GetExpireTime() - now);

            for (uint8_t i = 0; i < addrNum; i++)
            {
                SuccessOrExit(error = Server::AppendAaaaRecord(aResponseMessage, hostName, addrs[i], hostTtl, aCompressInfo));
                Server::IncResourceRecordCount(aResponseHeader, aAdditional);
            }

            response = Header::kResponseSuccess;
        }
    }

exit:
    return error == kErrorNone ? response : Header::kResponseServerFailure;
}

Header::Response MdnsServer::ResolveQuery(const Header             &aRequestHeader,
                                          const Message            &aRequestMessage,
                                          Header                   &aResponseHeader,
                                          Message                  &aResponseMessage,
                                          Server::NameCompressInfo &aCompressInfo,
                                          bool                     &bUnicastResponse)
{
    Question                 question;
    uint16_t                 readOffset;
    NameComponentsOffsetInfo nameComponentsOffsetInfo;
    Header::Response         responseCode = Header::kResponseSuccess;
    uint16_t                 knownAnswerOffset = ReturnKnownAnswerOffsetFromQuery(aRequestHeader, aRequestMessage);

    readOffset = sizeof(Header);

    if(knownAnswerOffset)
    {
        ResourceRecord record;
        for (uint8_t index = 0; index < aRequestHeader.GetAnswerCount(); index++)
        {
            char instanceName[Dns::Name::kMaxNameSize];
            char serviceName[Dns::Name::kMaxNameSize];

            Name::ReadName(aRequestMessage, knownAnswerOffset, serviceName, sizeof(serviceName));
            ResourceRecord::ReadRecord(aRequestMessage, knownAnswerOffset, record);
            Name::ReadName(aRequestMessage, knownAnswerOffset, instanceName, sizeof(instanceName));

            KnownAnswerEntry *kaEntry = KnownAnswerEntry::AllocateAndInit(serviceName, instanceName, record);
            if (!mReceivedKnownAnswers.ContainsMatching(*kaEntry))
            {
                mReceivedKnownAnswers.Push(*kaEntry);
            }
            else
            {
                kaEntry->Free();
            }
        }
    }

    /* Go through each question and attach the corresponding RRs in the answer section */
    for (uint16_t i = 0; i < aRequestHeader.GetQuestionCount(); i++)
    {
        uint16_t qtype;
        char     name[Name::kMaxNameSize];

        VerifyOrExit(Name::ReadName(aRequestMessage, readOffset, name, sizeof(name)) == kErrorNone,
                     responseCode = Header::kResponseFormatError);
        VerifyOrExit(aRequestMessage.Read(readOffset, question) == kErrorNone,
                     responseCode = Header::kResponseFormatError);

        readOffset += sizeof(question);

        qtype = question.GetType();
        bUnicastResponse |= question.IsQuQuestion();

        VerifyOrExit(qtype == ResourceRecord::kTypePtr || qtype == ResourceRecord::kTypeSrv ||
                         qtype == ResourceRecord::kTypeTxt || qtype == ResourceRecord::kTypeA ||
                         qtype == ResourceRecord::kTypeAaaa || qtype == ResourceRecord::kTypeAny,
                     responseCode = Header::kResponseNotImplemented);

        // For the moment, silently discard A query. If A query response will not be available, a NSEC record should be
        // returned.
        if (qtype == ResourceRecord::kTypeA)
        {
            continue;
        }

        VerifyOrExit(Server::FindNameComponents(name, aCompressInfo.GetDomainName(), nameComponentsOffsetInfo) ==
                         kErrorNone,
                     responseCode = Header::kResponseNameError);

        SuccessOrExit(responseCode =
                          ResolveQuestion(name, question, aResponseHeader, aResponseMessage, aCompressInfo, false, mReceivedKnownAnswers));

#if OPENTHREAD_CONFIG_SRP_SERVER_ENABLE
        // Convert from kDefaultMcastDomainName to kDefaultDomainName (.local -> default.service.arpa) for searching
        memcpy(name + nameComponentsOffsetInfo.mDomainOffset, kThreadDefaultDomainName,
               sizeof(kThreadDefaultDomainName));
        ResolveQuestionBySrp(name, question, aResponseHeader, aResponseMessage, aCompressInfo, false, mReceivedKnownAnswers);
#endif
    }

    /* Go through each question again and attach the corresponding RRs in the additional section */
    if (aResponseHeader.GetAnswerCount() > 0)
    {
        readOffset = sizeof(Header);

        for (uint16_t i = 0; i < aRequestHeader.GetQuestionCount(); i++)
        {
            char name[Name::kMaxNameSize];

            VerifyOrExit(Name::ReadName(aRequestMessage, readOffset, name, sizeof(name)) == kErrorNone,
                         responseCode = Header::kResponseFormatError);
            VerifyOrExit(aRequestMessage.Read(readOffset, question) == kErrorNone,
                         responseCode = Header::kResponseFormatError);

            readOffset += sizeof(question);

            VerifyOrExit(Server::FindNameComponents(name, aCompressInfo.GetDomainName(), nameComponentsOffsetInfo) ==
                             kErrorNone,
                         responseCode = Header::kResponseNameError);

            SuccessOrExit(responseCode =
                              ResolveQuestion(name, question, aResponseHeader, aResponseMessage, aCompressInfo, true, mReceivedKnownAnswers));

#if OPENTHREAD_CONFIG_SRP_SERVER_ENABLE
            // Convert from kDefaultMcastDomainName to kDefaultDomainName (.local -> default.service.arpa) for
            // searching
            memcpy(name + nameComponentsOffsetInfo.mDomainOffset, kThreadDefaultDomainName,
                   sizeof(kThreadDefaultDomainName));
            ResolveQuestionBySrp(name, question, aResponseHeader, aResponseMessage, aCompressInfo, true, mReceivedKnownAnswers);
#endif
        }
    }

exit:
    RemoveAllKnownAnswerEntries();
    return responseCode;
}

void MdnsServer::HandleDnsSdResult(Client::Response &aResponse, Client::QueryInfo aInfo)
{
    char     queryName[Name::kMaxNameSize];
    uint32_t iteratorIndex = 0;
    uint32_t addrIndex     = 0;

    // support returning HOST_MAX_IP6_ADDRESSES addresses, link local is ignored anyway
    otIp6Address ip6Address[HOST_MAX_IP6_ADDRESSES];

    if (aInfo.mQueryType == Client::kIp6AddressQuery)
    {
        otDnssdHostInfo          aHostInfo;
        Client::AddressResponse *addrResponse = static_cast<Client::AddressResponse *>(&aResponse);

        // change back to Thread domain name from .local
        addrResponse->GetHostName(queryName, sizeof(queryName));
        ConvertDomainName(queryName, nullptr, kDefaultDomainName, Server::kDefaultDomainName);

        while (kErrorNone ==
               addrResponse->GetAddress(iteratorIndex++, AsCoreType(&ip6Address[addrIndex]), aHostInfo.mTtl))
        {
            if (!AsCoreType(&ip6Address[addrIndex]).IsLinkLocal())
            {
                if (++addrIndex == HOST_MAX_IP6_ADDRESSES)
                    break;
            }
        }
        // no point in informing of a discovered host that has only link local address
        if (addrIndex > 0)
        {
            aHostInfo.mAddressNum = addrIndex;
            aHostInfo.mAddresses  = ip6Address;
            Get<Server>().HandleDiscoveredHost(queryName, aHostInfo);
        }
    }
    else
    {
        // handle browse and service queries
        char instanceName[Name::kMaxLabelSize];

        if (aInfo.mQueryType == Client::kBrowseQuery)
        {
            Client::BrowseResponse *browseResponse = static_cast<Client::BrowseResponse *>(&aResponse);
            while (kErrorNone ==
                   browseResponse->GetServiceInstance(iteratorIndex++, instanceName, sizeof(instanceName)))
            {
                browseResponse->GetServiceName(queryName, sizeof(queryName));
                GetServiceInfoFromResponse(instanceName, queryName, nullptr, browseResponse);
            }
        }
        else
        {
            Client::ServiceResponse *serviceResponse = static_cast<Client::ServiceResponse *>(&aResponse);

            serviceResponse->GetServiceName(instanceName, sizeof(instanceName), queryName, sizeof(queryName));
            GetServiceInfoFromResponse(instanceName, queryName, serviceResponse, nullptr);
        }
    }
}

Error MdnsServer::ResolveQuestionFromDnsSd(const char *aName, Server::DnsQueryType aType)
{
    Error             error = kErrorNone;
    char              localName[Name::kMaxNameSize];
    Client::QueryInfo info;

    // convert domanin name from thread domain to .local
    ConvertDomainName(localName, aName, Server::kDefaultDomainName, kDefaultDomainName);

    info.Clear();
    info.mCallback.mAddressCallback = nullptr;
    info.mCallbackContext           = nullptr;

    info.mConfig.mResponseTimeout = 1000; // ms
    info.mConfig.mMaxTxAttempts =
        7; // calculated for a maximum resolve time of 128 sec with interval doubling for each new query

    switch (aType)
    {
    case Server::kDnsQueryBrowse:
        info.mQueryType = Client::kBrowseQuery;
        break;
    case Server::kDnsQueryResolve:
        info.mQueryType = Client::kServiceQuerySrvTxt;
        break;
    case Server::kDnsQueryResolveHost:
        info.mQueryType = Client::kIp6AddressQuery;
        break;
    default:
        error = kErrorInvalidArgs;
        ExitNow();
        break;
    }

    error = StartQuery(info, localName);

exit:
    return error;
}

Error MdnsServer::ConvertDomainName(char       *aName,
                                    const char *aInitName,
                                    const char *aDomainName,
                                    const char *aTargetDomaninName)
{
    Error                            error = kErrorNone;
    Server::NameComponentsOffsetInfo nameComponentsOffsetInfo;
    uint16_t                         domainLen = StringLength(aTargetDomaninName, Name::kMaxNameLength) + 1;

    if (aInitName != nullptr)
    {
        memcpy(aName, aInitName, strlen(aInitName) + 1);
    }

    VerifyOrExit(kErrorNone == Server::FindNameComponents(aName, aDomainName, nameComponentsOffsetInfo),
                 error = kErrorParse);

    memcpy(aName + nameComponentsOffsetInfo.mDomainOffset, aTargetDomaninName, domainLen);

exit:
    return error;
}

void MdnsServer::GetServiceInfoFromResponse(char                    *instanceName,
                                            char                    *serviceName,
                                            Client::ServiceResponse *serviceResponse,
                                            Client::BrowseResponse  *browseResponse)
{
    Error   error = kErrorNone;
    char    hostName[Name::kMaxNameSize];
    char    fullName[Name::kMaxNameSize];
    uint8_t txtData[TXT_DATA_BUFER_SIZE];

    uint32_t iteratorIndex = 0;
    uint32_t addrIndex     = 0;

    uint32_t instLen;

    otDnsServiceInfo           replyInfo;
    otDnssdServiceInstanceInfo aServiceInfo;

    // support returning HOST_MAX_IP6_ADDRESSES addresses, link local is ignored anyway
    otIp6Address ip6Address[HOST_MAX_IP6_ADDRESSES];

    replyInfo.mHostNameBuffer     = hostName;
    replyInfo.mHostNameBufferSize = sizeof(hostName);
    replyInfo.mTxtData            = txtData;
    replyInfo.mTxtDataSize        = sizeof(txtData);
    if (serviceResponse)
    {
        VerifyOrExit(serviceResponse->GetServiceInfo(replyInfo) == kErrorNone);
    }
    else if (browseResponse)
    {
        VerifyOrExit(browseResponse->GetServiceInfo(instanceName, replyInfo) == kErrorNone);
    }
    else
    {
        return;
    }

    do
    {
        if (serviceResponse)
        {
            error = serviceResponse->GetHostAddress(hostName, iteratorIndex++, AsCoreType(&ip6Address[addrIndex]),
                                                    aServiceInfo.mTtl);
        }
        else
        {
            error = browseResponse->GetHostAddress(hostName, iteratorIndex++, AsCoreType(&ip6Address[addrIndex]),
                                                   aServiceInfo.mTtl);
        }
        if (error == kErrorNone)
        {
            if (!AsCoreType(&ip6Address[addrIndex]).IsLinkLocal())
            {
                if (++addrIndex == HOST_MAX_IP6_ADDRESSES)
                    error = kErrorNotFound;
            }
        }
    } while (error == kErrorNone);

    if (addrIndex)
    {
        aServiceInfo.mAddressNum = addrIndex;
        aServiceInfo.mAddresses  = ip6Address;
        aServiceInfo.mFullName   = fullName;
        aServiceInfo.mHostName   = hostName;
        aServiceInfo.mPort       = replyInfo.mPort;
        aServiceInfo.mPriority   = replyInfo.mPriority;
        aServiceInfo.mTtl        = replyInfo.mTtl;
        aServiceInfo.mWeight     = replyInfo.mWeight;
        aServiceInfo.mTxtData    = txtData;
        aServiceInfo.mTxtLength  = replyInfo.mTxtDataSize;

        // change back the full service instance name to the Thread domain name from .local
        ConvertDomainName(serviceName, nullptr, kDefaultDomainName, Server::kDefaultDomainName);
        // change back the host name to the Thread domain name from .local
        ConvertDomainName(hostName, nullptr, kDefaultDomainName, Server::kDefaultDomainName);

        // create full name
        instLen = strlen(instanceName);
        memcpy(fullName, instanceName, instLen);
        fullName[instLen++] = Name::kLabelSeparatorChar;
        memcpy(fullName + instLen, serviceName, strlen(serviceName) + 1);

        Get<Server>().HandleDiscoveredServiceInstance(serviceName, aServiceInfo);
    }

exit:
    return;
}

uint16_t MdnsServer::GetRecordType(Client::QueryType aQueryType)
{
    uint16_t recordType;

    switch (aQueryType)
    {
    case Client::kIp6AddressQuery:
        recordType = ResourceRecord::kTypeAaaa;
        break;
    case Client::kBrowseQuery:
        recordType = ResourceRecord::kTypePtr;
        break;
    case Client::kServiceQuerySrvTxt:
        recordType = ResourceRecord::kTypeSrv;
        break;
    default:
        recordType = ResourceRecord::kTypeAny;
        break;
    }
    return recordType;
}

void MdnsServer::UpdateTimeout(Message &aQuery, Client::QueryInfo &aInfo, bool bDouble)
{
    if (bDouble)
    {
        aInfo.mRetransmissionTime =
            TimerMilli::GetNow() + ((1 << aInfo.mTransmissionCount) * aInfo.mConfig.GetResponseTimeout());
    }
    else
    {
        aInfo.mRetransmissionTime = TimerMilli::GetNow() + aInfo.mConfig.GetResponseTimeout();
    }
    aInfo.mTransmissionCount++;

    // Update the query info
    UpdateQuery(aQuery, aInfo);
}

void MdnsServer::HandleTimer(void)
{
    TimeMilli         now      = TimerMilli::GetNow();
    TimeMilli         nextTime = now.GetDistantFuture();
    Client::QueryInfo info;

    for (Message &query : mQueries)
    {
        info.ReadFrom(query);

        if (now >= info.mRetransmissionTime)
        {
            if (info.mTransmissionCount >= info.mConfig.GetMaxTxAttempts())
            {
                FinalizeQuery(query, kErrorResponseTimeout);
                continue;
            }
            // Double the timeout between each new attempt
            UpdateTimeout(query, info, true);
            SendQuery(query, info);
        }

        if (nextTime > info.mRetransmissionTime)
        {
            nextTime = info.mRetransmissionTime;
        }
    }

    if (nextTime < now.GetDistantFuture())
    {
        mTimer.FireAt(nextTime);
    }
}

const Ip6::Address *MdnsServer::GetAddresses(uint8_t &aNumAddresses)
{
    aNumAddresses = ClampToUint8(mAddresses.GetLength());

    return mAddresses.AsCArray();
}

Error MdnsServer::AddAddress(const Ip6::Address &aIp6Address)
{
    Error error = kErrorNone;

    if (aIp6Address.IsMulticast() || aIp6Address.IsUnspecified() || aIp6Address.IsLoopback())
    {
        ExitNow(error = kErrorDrop);
    }

    VerifyOrExit(!mAddresses.Contains(aIp6Address), error = kErrorDrop);

    error = mAddresses.PushBack(aIp6Address);

exit:
    return error;
}

Error MdnsServer::SetHostName(const char *aHostName)
{
    Error error = kErrorNone;

    VerifyOrExit(aHostName != nullptr, error = kErrorInvalidArgs);

    if (mHostName.IsNull())
    {
        error = mHostName.Set(aHostName);
    }
    else
    {
        error = StringMatch(mHostName.AsCString(), aHostName, kStringCaseInsensitiveMatch) ? kErrorNone : kErrorFailed;
    }

exit:
    return error;
}

const char *MdnsServer::GetHostName() { return mHostName.AsCString(); }

Error MdnsServer::AddService(const char          *aInstanceName,
                             const char          *aServiceName,
                             const char          **aSubtypeLabels,
                             uint8_t              aNumSubtypesEntries,
                             uint16_t             aPort,
                             const otDnsTxtEntry *aTxtEntries,
                             uint8_t              mNumTxtEntries)
{
    Service *service = nullptr;
    Error    error   = kErrorNone;
    Prober  *prober  = nullptr;

    // Ensure the same service does not exist already.
    Service *existingService = FindService(aServiceName, aInstanceName);

    if (existingService)
    {
        if (!existingService->IsMarkedAsDeleted())
        {
            ExitNow(error = kErrorDuplicated);
        }
        else
        {
            existingService->UnmarkAsDeleted();

            if (UpdateServiceContent(existingService, aPort, aTxtEntries, mNumTxtEntries) == kErrorNone)
            {
                Announcer *announcer = ReturnAnnouncingInstanceContainingServiceId(existingService->GetServiceUpdateId());
                if (announcer != nullptr)
                {
                    announcer->Stop();
                    AnnounceHostAndServices(*announcer);
                }
                else
                {
                    announcer = AllocateAnnouncer(existingService->GetServiceUpdateId());
                    VerifyOrExit(announcer != nullptr, error = kErrorNoBufs);
                    AnnounceHostAndServices(*announcer);
                }
            }
        }
    }
    else
    {
        service = Service::AllocateAndInit(aServiceName, aInstanceName, aPort, AllocateId());
        VerifyOrExit(service != nullptr, error = kErrorFailed);

        if (aTxtEntries != nullptr)
        {
            if (aTxtEntries->mKey)
            {
                uint8_t  txtBuffer[kTXTMaxBufferSize] = {0};
                uint32_t txtBufferOffset              = 0;

                for (uint32_t i = 0; i < mNumTxtEntries; i++)
                {
                    uint32_t keySize = strlen(aTxtEntries[i].mKey);
                    // add TXT entry len + 1 is for '='
                    *(txtBuffer + txtBufferOffset++) = keySize + aTxtEntries[i].mValueLength + 1;

                    // add TXT entry key
                    memcpy(txtBuffer + txtBufferOffset, aTxtEntries[i].mKey, keySize);
                    txtBufferOffset += keySize;

                    // add TXT entry value if pointer is not null, if pointer is null it means we have bool value
                    if (aTxtEntries[i].mValue)
                    {
                        *(txtBuffer + txtBufferOffset++) = '=';
                        memcpy(txtBuffer + txtBufferOffset, aTxtEntries[i].mValue, aTxtEntries[i].mValueLength);
                        txtBufferOffset += aTxtEntries[i].mValueLength;
                    }
                }
                service->mTxtData.SetFrom(txtBuffer, txtBufferOffset);
            }
            else
            {
                service->mTxtData.SetFrom(aTxtEntries->mValue, aTxtEntries->mValueLength);
            }
        }

        mServices.Push(*service);

        for (uint8_t index = 0; index < aNumSubtypesEntries; index++)
        {
            String<Name::kMaxNameSize> instanceName;
            instanceName.Append("%s%s%s", aSubtypeLabels[index], kServiceSubTypeLabel, aServiceName);

            Service::SubTypeEntry *entry = Service::SubTypeEntry::Allocate(instanceName.AsCString());
            VerifyOrExit(entry != nullptr, error = kErrorNoBufs);
            service->PushSubTypeEntry(*entry);
        }

        if (GetState() == kStateRunning)
        {
            prober = AllocateProber(true, nullptr, service->GetServiceUpdateId());
            VerifyOrExit(prober != nullptr, error = kErrorNoBufs);
            PublishHostAndServices(prober);
        }
    }

exit:
    if (error != kErrorNone && service != nullptr)
    {
        if(FindService(service->GetServiceName(), service->GetInstanceName()) != nullptr)
        {
            mServices.Remove(*service);
        }
        service->Free();
    }
    return error;
}

Error MdnsServer::UpdateServiceContent(Service             *aService,
                                       uint16_t             aPort,
                                       const otDnsTxtEntry *aTxtEntries,
                                       uint8_t              mNumTxtEntries)
{
    Error error = kErrorDuplicated;

    if (aService->GetPort() != aPort)
    {
        aService->mPort = aPort;
        error = kErrorNone;
    }

    if (aTxtEntries != nullptr)
    {
        error = kErrorNone;

        if (aTxtEntries->mKey)
        {
            uint8_t  txtBuffer[kTXTMaxBufferSize] = {0};
            uint32_t txtBufferOffset              = 0;

            for (uint32_t i = 0; i < mNumTxtEntries; i++)
            {
                uint32_t keySize = strlen(aTxtEntries[i].mKey);
                // add TXT entry len + 1 is for '='
                *(txtBuffer + txtBufferOffset++) = keySize + aTxtEntries[i].mValueLength + 1;

                // add TXT entry key
                memcpy(txtBuffer + txtBufferOffset, aTxtEntries[i].mKey, keySize);
                txtBufferOffset += keySize;

                // add TXT entry value if pointer is not null, if pointer is null it means we have bool value
                if (aTxtEntries[i].mValue)
                {
                    *(txtBuffer + txtBufferOffset++) = '=';
                    memcpy(txtBuffer + txtBufferOffset, aTxtEntries[i].mValue, aTxtEntries[i].mValueLength);
                    txtBufferOffset += aTxtEntries[i].mValueLength;
                }
            }
            VerifyOrExit(memcmp(aService->mTxtData.GetBytes(), txtBuffer, txtBufferOffset) != 0,
                     error = kErrorDuplicated);
            VerifyOrExit(aService->mTxtData.SetFrom(txtBuffer, txtBufferOffset) == kErrorNone, error = kErrorFailed);
        }
        else
        {
            VerifyOrExit(memcmp(aService->mTxtData.GetBytes(), aTxtEntries->mValue, aTxtEntries->mValueLength) != 0,
                     error = kErrorDuplicated);
            VerifyOrExit(aService->mTxtData.SetFrom(aTxtEntries->mValue, aTxtEntries->mValueLength) == kErrorNone,
                         error = kErrorFailed);
        }
    }

exit:
    return error;
}

Error MdnsServer::UpdateService(const char          *aInstanceName,
                                const char          *aServiceName,
                                uint16_t             aPort,
                                const otDnsTxtEntry *aTxtEntries,
                                uint8_t              mNumTxtEntries)
{
    Error      error     = kErrorNone;
    Service   *service   = nullptr;
    Announcer *announcer = nullptr;

    // Ensure the service exists already.
    service = FindService(aServiceName, aInstanceName);
    VerifyOrExit(service != nullptr, error = kErrorNotFound);

    // Then add it back with it's changed content
    VerifyOrExit(UpdateServiceContent(service, aPort, aTxtEntries, mNumTxtEntries) == kErrorNone, error = kErrorFailed);

    VerifyOrExit(service->GetState() >= Service::kAnnouncing, error = kErrorInvalidState);

    announcer = ReturnAnnouncingInstanceContainingServiceId(service->GetServiceUpdateId());
    if (announcer != nullptr)
    {
        announcer->Stop();
        AnnounceHostAndServices(*announcer);
    }
    else
    {
        announcer = AllocateAnnouncer(service->GetServiceUpdateId());
        VerifyOrExit(announcer != nullptr, error = kErrorNoBufs);
        AnnounceHostAndServices(*announcer);
    }

exit:
    if (error == kErrorInvalidState)
    {
        if (service->GetState() == Service::State::kProbing)
        {
            const char *subTypes[OPENTHREAD_CONFIG_MDNS_BUFFERS_SERVICE_MAX_SUB_TYPES];
            uint8_t     index = 0;
            for (Service::SubTypeEntry &entry : service->GetSubTypeList())
            {
                subTypes[index++] = entry.GetName();
            }
            if (RemoveService(aInstanceName, aServiceName) == kErrorNone)
            {
                AddService(aInstanceName, aServiceName, subTypes, index, aPort, aTxtEntries, mNumTxtEntries);
            }
        }
    }
    return error;
}

Error MdnsServer::RemoveService(const char *aInstanceName, const char *aServiceName)
{
    Service       *service   = nullptr;
    Error          error     = kErrorNone;
    Service::State state;

    VerifyOrExit((service = FindService(aServiceName, aInstanceName)) != nullptr, error = kErrorNotFound);
    state = service->GetState();

    // handle the case when service was already probed and announce on the network
    if (state == Service::kAnnounced)
    {
        SuccessOrExit(error = AnnounceServiceGoodbye(*service));
    }
    else
    {
        RemoveServiceFromProbeOrAnnounceInstance(service, state);
    }

exit:
    if (service)
    {
        mServices.Remove(*service);
        service->Free();
    }
    return error;
}

void MdnsServer::RemoveServiceFromProbeOrAnnounceInstance(Service *aService, Service::State aState)
{
    Prober    *prober    = nullptr;
    Announcer *announcer = nullptr;

    // check if this service is included in an announce procedure
    if(aState == Service::State::kAnnouncing)
    {
        announcer = ReturnAnnouncingInstanceContainingServiceId(aService->GetServiceUpdateId());
        if(announcer != nullptr)
        {
            announcer->Stop();
            if(announcer->GetId())
            {
                RemoveAnnouncingInstance(announcer->GetId());
            }
            else
            {
                // recreate the announce message, and restart
                UpdateExistingAnnouncerDataEntries(*announcer, *aService);
            }
        }
    }
    // check if this service is included in a probe procedure
    else
    {
        prober = ReturnProbingInstanceContainingServiceId(aService->GetServiceUpdateId());
        if(prober != nullptr)
        {
            /*Remove service is called from 2 different application flows:
                1) Remove service  -> when an application wants to remove this specific service
                2) Service register failed to verify it's uniqueness. Remove service will be called after the prober
               instance for this service has been previously stopped.
            */
            if(prober->IsRunning())
            {
                prober->Stop(kErrorNotFound);
            }
            if(prober->GetId())
            {
                RemoveProbingInstance(prober->GetId());
            }
            else
            {
                // recreate the probing message and restart
                UpdateExistingProberDataEntries(*prober, *aService);
            }
        }
    }
}

void MdnsServer::MarkServiceForRemoval(const char *aInstanceName, const char *aServiceName)
{
    if (aInstanceName == nullptr)
    {
        for (Service &service : mServices)
        {
            if (service.MatchesServiceName(aServiceName))
            {
                RemoveServiceFromProbeOrAnnounceInstance(&service, service.GetState());
                service.MarkAsDeleted();
            }
        }
    }
    else
    {
        Service *service = FindService(aServiceName, aInstanceName);
        if (service != nullptr)
        {
            RemoveServiceFromProbeOrAnnounceInstance(service, service->GetState());
            service->MarkAsDeleted();
        }
    }
}

void MdnsServer::RemoveMarkedServices(void)
{
    AnnounceMarkedAsDeletedServicesGoodbye();

    for(Service &service : mServices)
    {
        if(service.IsMarkedAsDeleted())
        {
            mServices.Remove(service);
            service.Free();
        }
    }
}

Error MdnsServer::AnnounceServiceGoodbye(Service &aService)
{
    NameCompressInfo compressInfo(kDefaultDomainName);
    Message         *message = nullptr;
    Header           header;
    Error            error;

    Announcer *announcer = Announcer::Allocate(GetInstance());
    VerifyOrExit(announcer != nullptr, error = kErrorNoBufs);

    VerifyOrExit((message = NewPacket()) != nullptr, error = kErrorNoBufs);

    header.SetType(Header::kTypeResponse);

    SuccessOrExit(error = Server::AppendPtrRecord(*message, aService.GetServiceName(), aService.GetInstanceName(),
                                                  0, compressInfo));
    Server::IncResourceRecordCount(header, false);

    message->Write(0, header);

    VerifyOrExit(message->GetLength() > sizeof(Header), error = kErrorDrop);

    announcer->EnqueueAnnounceMessage(*message);
    announcer->StartAnnouncing();

exit:
    if (error != kErrorNone)
    {
        if (announcer)
        {
            announcer->Free();
        }
    }
    FreeMessageOnError(message, error);
    return error;
}

Error MdnsServer::AnnounceMarkedAsDeletedServicesGoodbye()
{
    NameCompressInfo compressInfo(kDefaultDomainName);
    Message         *message = nullptr;
    Header           header;
    Service         *service;
    Error            error = kErrorNone;

    Announcer *announcer = Announcer::Allocate(GetInstance());
    VerifyOrExit(announcer != nullptr, error = kErrorNoBufs);

    VerifyOrExit((message = NewPacket()) != nullptr, error = kErrorNoBufs);

    header.SetType(Header::kTypeResponse);

    for (service = mServices.GetHead(); service != nullptr; service = service->GetNext())
    {
        if(service->IsMarkedAsDeleted())
        {
            SuccessOrExit(error = Server::AppendPtrRecord(*message, service->GetServiceName(), service->GetInstanceName(),
                                                        0, compressInfo));
            Server::IncResourceRecordCount(header, false);
        }
    }

   message->Write(0, header);

   VerifyOrExit(message->GetLength() > sizeof(Header), error = kErrorDrop);

   announcer->EnqueueAnnounceMessage(*message);
   announcer->StartAnnouncing();

exit:
   if (error != kErrorNone)
   {
        if (announcer)
        {
            announcer->Free();
        }
   }
   FreeMessageOnError(message, error);
   return error;
}

Error MdnsServer::AnnounceHostGoodbye()
{
    NameCompressInfo compressInfo(kDefaultDomainName);
    Message         *message = nullptr;
    Header           header;
    Service         *service;
    Error            error = kErrorNone;

    Announcer *announcer = Announcer::Allocate(GetInstance());
    VerifyOrExit(announcer != nullptr, error = kErrorNoBufs);

    VerifyOrExit((message = NewPacket()) != nullptr, error = kErrorNoBufs);

    header.SetType(Header::kTypeResponse);

    for (service = mServices.GetHead(); service != nullptr; service = service->GetNext())
    {
        SuccessOrExit(error = Server::AppendPtrRecord(*message, service->GetServiceName(), service->GetInstanceName(),
                                                      0, compressInfo));
        Server::IncResourceRecordCount(header, false);
    }

   message->Write(0, header);

   VerifyOrExit(message->GetLength() > sizeof(Header), error = kErrorDrop);

   announcer->EnqueueAnnounceMessage(*message);
   announcer->StartAnnouncing();

exit:
   if (error != kErrorNone)
   {
        if (announcer)
        {
            announcer->Free();
        }
   }
   FreeMessageOnError(message, error);
   return error;
}

Error MdnsServer::AnnounceSrpHostGoodbye(otSrpServerServiceUpdateId aId, const otSrpServerHost *aHost)
{
    NameCompressInfo            compressInfo(kDefaultDomainName);
    Message                    *message = nullptr;
    Header                      header;
    const Srp::Server::Service *service = nullptr;
    Error                       error;

    Announcer *announcer = AllocateAnnouncer(aId);
    VerifyOrExit(announcer != nullptr, error = kErrorNoBufs);

    VerifyOrExit((message = NewPacket()) != nullptr, error = kErrorNoBufs);

    header.SetType(Header::kTypeResponse);

    while ((service = AsCoreType(aHost).FindNextService(service, OT_SRP_SERVER_FLAGS_BASE_TYPE_SERVICE_ONLY, nullptr,
                                                        nullptr)) != nullptr)
    {
        SuccessOrExit(
            error = Get<Server>().AppendPtrRecord(*message, service->GetServiceName(), service->GetInstanceName(), 0, compressInfo));
        Server::IncResourceRecordCount(header, false);
    }

    message->Write(0, header);

    VerifyOrExit(message->GetLength() > sizeof(Header), error = kErrorDrop);

    announcer->EnqueueAnnounceMessage(*message);
    announcer->StartAnnouncing();

exit:
    if (error != kErrorNone)
    {
        if (announcer)
        {
            RemoveAnnouncingInstance(announcer->GetId());
        }
    }
    FreeMessageOnError(message, error);
    return error;
}

Error MdnsServer::AppendServiceInfo(Message          &aMessage,
                                    Header           &aHeader,
                                    Service          &aService,
                                    NameCompressInfo &aCompressInfo)
{
    Error error;

    SuccessOrExit(error = Server::AppendPtrRecord(aMessage, aService.GetServiceName(), aService.GetInstanceName(),
                                                  aService.GetTtl(), aCompressInfo));
    Server::IncResourceRecordCount(aHeader, false);

    SuccessOrExit(error = Server::AppendSrvRecord(aMessage, aService.GetInstanceName(), GetHostName(),
                                                  aService.GetTtl(), aService.GetPriority(), aService.GetWeight(),
                                                  aService.GetPort(), aCompressInfo, aService.GetState() >= Service::kProbed));
    Server::IncResourceRecordCount(aHeader, false);

    SuccessOrExit(error = Server::AppendTxtRecord(aMessage, aService.GetInstanceName(), aService.GetTxtData(),
                                                  aService.GetTxtDataLength(), kDefaultTtl, aCompressInfo, aService.GetState() >= Service::kProbed));
    Server::IncResourceRecordCount(aHeader, false);

    if (!aService.GetSubTypeList().IsEmpty())
    {
        for (Service::SubTypeEntry &entry : aService.GetSubTypeList())
        {
            SuccessOrExit(error = Server::AppendPtrRecord(aMessage, entry.GetName(), aService.GetInstanceName(),
                                                          aService.GetTtl(), aCompressInfo));
            Server::IncResourceRecordCount(aHeader, false);
        }
    }

exit:
    return error;
}

Error MdnsServer::SendPacket(Message          &aMessage,
                             Header           &aHeader,
                             Header::Response  aResponseCode,
                             bool              aSendUnicast,
                             Ip6::MessageInfo *aMessageInfo)
{
    Ip6::MessageInfo rspMsgInfo;
    if (aMessageInfo)
    {
        rspMsgInfo = *aMessageInfo;
    }
    Error error;

    VerifyOrExit(aHeader.GetAnswerCount() > 0, error = kErrorDrop);

    if (!aSendUnicast)
    {
        rspMsgInfo.SetPeerAddr(AsCoreType(&kMdnsMulticastGroup));
        rspMsgInfo.SetSockAddr(AsCoreType(&kAnyAddress));
        rspMsgInfo.SetPeerPort(kPort);
    }
    // Make the source address 0 to signal that the IPv6 layer should use the source address selection algorithm
    // to select appropriate source address
    rspMsgInfo.SetSockAddr(AsCoreType(&kAnyAddress));
    aHeader.SetResponseCode(aResponseCode);
    aMessage.Write(0, aHeader);

    error = mSocket.SendTo(aMessage, rspMsgInfo);

exit:
    return error;
}

bool MdnsServer::Service::MatchesServiceName(const char *aServiceName) const
{
    return StringMatch(mServiceName.AsCString(), aServiceName, kStringCaseInsensitiveMatch);
}

bool MdnsServer::Service::MatchesInstanceName(const char *aInstanceName) const
{
    return StringMatch(mInstanceName.AsCString(), aInstanceName, kStringCaseInsensitiveMatch);
}

const MdnsServer::Service::SubTypeEntry *MdnsServer::Service::GetNextSubTypeEntry(
    const MdnsServer::Service::SubTypeEntry *aPrevSubTypeEntry) const
{
    const MdnsServer::Service::SubTypeEntry *subTypeEntry =
        (aPrevSubTypeEntry == nullptr) ? mSubTypesList.GetHead() : aPrevSubTypeEntry->GetNext();

    return subTypeEntry;
}

Error MdnsServer::Service::SubTypeEntry::GetServiceSubTypeLabel(char *aLabel, uint8_t aMaxSize) const
{
    Error       error       = kErrorNone;
    const char *serviceName = GetName();
    const char *subServiceName;
    uint8_t     labelLength;

    memset(aLabel, 0, aMaxSize);

    subServiceName = StringFind(serviceName, kServiceSubTypeLabel, kStringCaseInsensitiveMatch);
    OT_ASSERT(subServiceName != nullptr);

    if (subServiceName - serviceName < aMaxSize)
    {
        labelLength = static_cast<uint8_t>(subServiceName - serviceName);
    }
    else
    {
        labelLength = aMaxSize - 1;
        error       = kErrorNoBufs;
    }

    memcpy(aLabel, serviceName, labelLength);

    return error;
}

Error MdnsServer::Service::Init(const char *aServiceName, const char *aInstanceName, uint16_t aPort, uint16_t aId)
{
    mServiceName.Set(aServiceName);
    mInstanceName.Set(aInstanceName);

    mPriority          = 0;
    mWeight            = 0;
    mPort              = aPort;
    mTtl               = kDefaultTtlWithHostName;
    mState             = kJustAdded;
    mId                = aId;
    mIsMarkedAsDeleted = false;

    return kErrorNone;
}

const MdnsServer::Service *MdnsServer::FindNextService(const MdnsServer::Service *aPrevService,
                                                       const char                *aServiceName,
                                                       const char                *aInstanceName) const
{
    const MdnsServer::Service *service = (aPrevService == nullptr) ? mServices.GetHead() : aPrevService->GetNext();

    for (; service != nullptr; service = service->GetNext())
    {
        if ((aServiceName != nullptr) && !service->MatchesServiceName(aServiceName))
        {
            continue;
        }

        if ((aInstanceName != nullptr) && !service->MatchesInstanceName(aInstanceName))
        {
            continue;
        }

        break;
    }

    return service;
}

MdnsServer::Service *MdnsServer::FindService(const char *aServiceName, const char *aInstanceName)
{
    return AsNonConst(FindNextService(nullptr, aServiceName, aInstanceName));
}

void MdnsServer::HandleProberFinished(const Prober &aProber, Error aError, MdnsServerProbingContext *aContext)
{
    if (aProber.IsProbingForHost())
    {
        if (aError == kErrorNone)
        {
            (void)AnnounceHostAndServices(AsNonConst(aProber));

            if (!aProber.GetId())
            {
                mIsHostVerifiedUnique |= true;

                const uint32_t *ids;
                uint8_t         numIds = 0;

                ids = aProber.GetServicesIdList(numIds);

                for (uint8_t i = 0; i < numIds; i++)
                {
                    Service *s = mServices.FindMatching(ids[i]);
                    if (s != nullptr)
                    {
                        s->SetState(Service::State::kProbed);
                    }
                }
            }
            else
            {
                Service *s = mServices.FindMatching(aProber.GetId());
                if (s != nullptr)
                {
                    s->SetState(Service::kProbed);
                }
            }
        }
        else
        {
            if (aError == kErrorDuplicated)
            {
                MdnsServer::Service *service = mServices.GetHead();

                for (; service != nullptr; service = service->GetNext())

                {
                    if (service->MatchesInstanceName(aContext->name))
                    {
                        UpdateExistingProberDataEntries(AsNonConst(aProber), *service);
                        RemoveService(service->GetInstanceName(), service->GetServiceName());
                        break;
                    }
                }
                mCallback.InvokeIfSet(aContext);
            }
        }
    }
    else
    {
        otSrpServerServiceUpdateId id = aProber.GetId();
        AnnounceFromSrp(aProber.GetHost(), id);
    }
}

void MdnsServer::HandleAnnouncerFinished(const Announcer &aAnnouncer)
{
    const uint32_t *ids;
    uint8_t         numIds = 0;

    ids = aAnnouncer.GetServicesIdList(numIds);

    for (uint8_t i = 0; i < numIds; i++)
    {
        Service *s = mServices.FindMatching(ids[i]);
        if (s != nullptr)
        {
            s->SetState(Service::State::kAnnounced);
        }
    }
}

Message* MdnsServer::CreateHostAndServicesAnnounceMessage(Announcer &aAnnouncer)
{
    Error            error = kErrorNone;
    NameCompressInfo compressInfo(kDefaultDomainName);

    uint8_t             addrNum;
    const Ip6::Address *addrs   = nullptr;
    uint32_t            hostTtl = 0;
    const uint32_t     *ids;
    uint8_t             numIds = 0;

    ids = aAnnouncer.GetServicesIdList(numIds);

    if (!aAnnouncer.GetId())
    {
        addrs   = Get<MdnsServer>().GetAddresses(addrNum);
        hostTtl = 0;
    }

    MdnsServer::Service *service = nullptr;

    Message *message = nullptr;
    Header   header;

    VerifyOrExit((message = NewPacket()) != nullptr, error = kErrorNoBufs);

    header.SetType(Header::kTypeResponse);

    if (!aAnnouncer.GetId())
    {
        // AAAA Resource Record
        for (uint8_t i = 0; i < addrNum; i++)
        {
            SuccessOrExit(error = Get<Server>().AppendAaaaRecord(*message, GetHostName(), addrs[i],
                                                                 hostTtl, compressInfo, mIsHostVerifiedUnique));
            Server::IncResourceRecordCount(header, false);
        }
    }

    if (!numIds && aAnnouncer.GetId())
    {
        service = Get<MdnsServer>().FindServiceById(aAnnouncer.GetId());
        if (service != nullptr)
        {
            service->SetState(Service::kAnnouncing);
            SuccessOrExit(Get<MdnsServer>().AppendServiceInfo(*message, header, *service, compressInfo));
        }
    }
    else
    {
        for (uint8_t i = 0; i < numIds; i++)
        {
            service = mServices.FindMatching(ids[i]);
            if (service != nullptr)
            {
                service->SetState(Service::kAnnouncing);
                SuccessOrExit(Get<MdnsServer>().AppendServiceInfo(*message, header, *service, compressInfo));
            }
        }
    }

    message->Write(0, header);

    return message;

exit:
    FreeMessageOnError(message, error);
    return nullptr;
}

Message *MdnsServer::CreateHostAndServicesPublishMessage(Prober *aProber)
{
    Error            error = kErrorNone;
    NameCompressInfo compressInfo(kDefaultDomainName);

    uint8_t              addrNum;
    const uint32_t      *ids;
    uint8_t              numIds  = 0;
    const Ip6::Address  *addrs   = GetAddresses(addrNum);
    uint32_t             hostTtl = 0;
    MdnsServer::Service *service = nullptr;

    ids = aProber->GetServicesIdList(numIds);

    Header header;

    Message *message        = nullptr;

    Question question(ResourceRecord::kTypeAny, ResourceRecord::kClassInternet);
    VerifyOrExit((message = NewPacket()) != nullptr, error = kErrorNoBufs);

    question.SetQuQuestion();

    // Allocate space for DNS header
    SuccessOrExit(error = message->SetLength(sizeof(Header)));

    // Setup initial DNS response header
    header.SetType(Header::kTypeQuery);

    if (!mIsHostVerifiedUnique && !aProber->GetId())
    {
        // Hostname
        SuccessOrExit(error = Get<Server>().AppendHostName(*message, GetHostName(), compressInfo));
        message->Append(question);
        header.SetQuestionCount(header.GetQuestionCount() + 1);

    }

    if (!numIds && aProber->GetId())
    {
        service = mServices.FindMatching(aProber->GetId());
        if (service != nullptr)
        {
            SuccessOrExit(error =
                              Get<Server>().AppendInstanceName(*message, service->GetInstanceName(), compressInfo));
            message->Append(question);
            header.SetQuestionCount(header.GetQuestionCount() + 1);
        }
    }
    else
    {
        for (uint8_t i = 0; i < numIds; i++)
        {
            service = mServices.FindMatching(ids[i]);
            if (service != nullptr)
            {
                SuccessOrExit(
                    error = Get<Server>().AppendInstanceName(*message, service->GetInstanceName(), compressInfo));
                message->Append(question);
                header.SetQuestionCount(header.GetQuestionCount() + 1);
            }
        }
    }
    if (!mIsHostVerifiedUnique && !aProber->GetId())
    {
        // AAAA Resource Record
        for (uint8_t i = 0; i < addrNum; i++)
        {
            SuccessOrExit(error = Get<Server>().AppendAaaaRecord(*message, GetHostName(), addrs[i], hostTtl,
                                                                 compressInfo));
            header.SetAuthorityRecordCount(header.GetAuthorityRecordCount() + 1);
        }
    }

    if (!numIds && aProber->GetId())
    {
        service = mServices.FindMatching(aProber->GetId());
        if (service != nullptr)
        {
            SuccessOrExit(error = Get<Server>().AppendSrvRecord(
                              *message, service->GetInstanceName(), GetHostName(), service->GetTtl(),
                              service->GetPriority(), service->GetWeight(), service->GetPort(), compressInfo));
            header.SetAuthorityRecordCount(header.GetAuthorityRecordCount() + 1);

            service->SetState(Service::kProbing);
        }
    }
    else
    {
        for (uint8_t i = 0; i < numIds; i++)
        {
            service = mServices.FindMatching(ids[i]);
            if (service != nullptr)
            {
                SuccessOrExit(error = Get<Server>().AppendSrvRecord(
                                  *message, service->GetInstanceName(), GetHostName(), service->GetTtl(),
                                  service->GetPriority(), service->GetWeight(), service->GetPort(), compressInfo));
                header.SetAuthorityRecordCount(header.GetAuthorityRecordCount() + 1);
                service->SetState(Service::kProbing);
            }
        }
    }
    header.SetResponseCode(Header::kResponseSuccess);
    message->Write(0, header);

    return message;

exit:
    return nullptr;
}

Error MdnsServer::PublishHostAndServices(Prober *aProber)
{
    Error error = kErrorNone;

    Message *message = CreateHostAndServicesPublishMessage(aProber);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);
    VerifyOrExit(message->GetLength() != sizeof(Header), error = kErrorFailed);

    aProber->EnqueueProbeMessage(*message);
    aProber->StartProbing(aProber->IsProbingForHost());

exit:
    if(error != kErrorNone)
    {
        RemoveProbingInstance(aProber->GetId());
    }
    FreeMessageOnError(message, error);
    return error;
}

Error MdnsServer::AnnounceHostAndServices(Prober &aProber)
{
    Error      error     = kErrorNone;
    Message   *message   = nullptr;
    const uint32_t      *ids;
    uint8_t              numIds  = 0;
    Announcer *announcer = AllocateAnnouncer(aProber.GetId());
    VerifyOrExit(announcer != nullptr, error = kErrorNoBufs);

    if (!aProber.GetId())
    {
        ids = aProber.GetServicesIdList(numIds);
        for (uint8_t i = 0; i < numIds; i++)
        {
            announcer->PushServiceId(ids[i]);
        }
    }
    else
    {
        announcer->PushServiceId(aProber.GetId());
    }

    message = CreateHostAndServicesAnnounceMessage(*announcer);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);
    VerifyOrExit(message->GetLength() != sizeof(Header), error = kErrorFailed);

    announcer->EnqueueAnnounceMessage(*message);
    announcer->StartAnnouncing();

exit:
    if (error != kErrorNone)
    {
        if (announcer)
        {
            RemoveAnnouncingInstance(announcer->GetId());
        }
    }
    return error;
}

Error MdnsServer::AnnounceHostAndServices(Announcer &aAnnouncer)
{
    Error      error     = kErrorNone;
    Message   *message   = nullptr;

    message = CreateHostAndServicesAnnounceMessage(aAnnouncer);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);
    VerifyOrExit(message->GetLength() != sizeof(Header), error = kErrorFailed);

    aAnnouncer.EnqueueAnnounceMessage(*message);
    aAnnouncer.StartAnnouncing();

exit:
    if(error != kErrorNone)
    {
        RemoveAnnouncingInstance(aAnnouncer.GetId());
    }
    return error;
}

void MdnsServer::RemoveProbingInstance(uint32_t aProbingInstanceId)
{
    for (Prober &p : mProbingInstances)
    {
        if (p.GetId() == aProbingInstanceId)
        {
            mProbingInstances.Remove(p);
            p.Free();
        }
    }
}

void MdnsServer::RemoveAnnouncingInstance(uint32_t aAnnouncingInstanceId)
{
    for (Announcer &a : mAnnouncingInstances)
    {
        if (a.GetId() == aAnnouncingInstanceId)
        {
            mAnnouncingInstances.Remove(a);
            a.Free();
        }
    }
}

//---------------------------------------------------------------------------------------------------------------------
//Prober
MdnsServer::Prober::Prober(Instance &aInstance, bool aProbeForHost, const otSrpServerHost *aHost, uint32_t aId)
    : InstanceLocator(aInstance)
    , mTimer(aInstance, HandleTimer, this)
    , mState(Prober::State::kIdle)
    , mProbeForHost(aProbeForHost)
    , mId(aId)
{
    if(!aProbeForHost)
    {
        mHost = aHost;
    }
    else
    {
        mHost = nullptr;
    }
}

void MdnsServer::Prober::StartProbing(bool aIsFromHost)
{
    uint32_t delay;
    mProbeForHost = aIsFromHost;
    VerifyOrExit(!IsRunning());

    mIsRunning = true;

    delay    = Random::NonCrypto::GetUint32InRange(0, kMaxStartDelay);
    mTxCount = 0;
    SetState(kTransitionToProbe);

    mTimer.Start(delay);

exit:
    return;
}

void MdnsServer::Prober::RestartProbing(uint32_t aDelay)
{
    mTimer.Stop();

    mTxCount = 0;
    SetState(kIdle);

    mTimer.Start(aDelay);
}

void MdnsServer::Prober::Stop(Error aError, MdnsServerProbingContext *aContext)
{
    mTimer.Stop();
    SetState(kIdle);
    mIsRunning = false;
    Message *message = GetProbingMessage();
    mQueries.DequeueAndFree(*message);
    Get<MdnsServer>().HandleProberFinished(*this, aError, aContext);
}

void MdnsServer::Prober::HandleTimer(void)
{
    Error            error = kErrorNone;
    uint32_t         delay;
    Ip6::MessageInfo rspMsgInfo;
    Message         *probeRequest = nullptr;
    Message         *query        = GetProbingMessage();
    VerifyOrExit (query != nullptr, error = kErrorFailed);

    VerifyOrExit(!mTimer.IsRunning());

    if (mTxCount >= kMaxTxCount)
    {
        mTimer.Stop();
        SetState(kCompleted);
        mQueries.DequeueAndFree(*query);
        Get<MdnsServer>().HandleProberFinished(*this, kErrorNone);
        Get<MdnsServer>().RemoveProbingInstance(GetId());
        ExitNow();
    }

    rspMsgInfo.SetPeerAddr(AsCoreType(&kMdnsMulticastGroup));
    rspMsgInfo.SetPeerPort(kPort);
    rspMsgInfo.SetSockPort(kPort);
    rspMsgInfo.SetIsHostInterface(true);

    VerifyOrExit((probeRequest = Get<MdnsServer>().GetMcastSocket().NewMessage(0)) != nullptr, error = kErrorNoBufs);
    probeRequest->AppendBytesFromMessage(*query, 0, query->GetLength() - query->GetOffset());

    error = Get<MdnsServer>().GetMcastSocket().SendTo(*probeRequest, rspMsgInfo);

    if (error == kErrorNone)
    {
        if (mState == kTransitionToProbe)
        {
            SetState(kProbing);
        }
        mTxCount++;
        mProbeRateLimit ? delay = kRateLimitedInterval : delay = kTxProbeInterval;
    }
    else
    {
        Stop(kErrorAbort);
        Get<MdnsServer>().RemoveProbingInstance(GetId());
        ExitNow();
    }

    mTimer.Start(delay);
exit:
    return;
}

int MdnsServer::Prober::CompareResourceRecords(Message &aEntry1, Message &aEntry2)
{
    /*
        As per RFC 6762, Section 8.2.1 Simultaneous Probe Tiebreaking for Multiple Records
        When a host is probing for a set of records with the same name, or a
        message is received containing multiple tiebreaker records answering
        a given probe question in the Question Section, the host’s records
        and the tiebreaker records from the message are each sorted into
        order, and then compared pairwise, using the same comparison
        technique described above, until a difference is found.
    */
    int      result      = 0;
    uint16_t read1Offset = aEntry1.GetOffset();
    uint16_t read2Offset = aEntry2.GetOffset();

    Name::ParseName(aEntry1, read1Offset);
    Name::ParseName(aEntry2, read2Offset);

    ResourceRecord record1;
    ResourceRecord record2;

    record1.ReadFrom(aEntry1, read1Offset);
    record2.ReadFrom(aEntry2, read2Offset);

    record1.UnSetCacheFlushBit();
    record2.UnSetCacheFlushBit();

    if (record1.GetClass() != record2.GetClass())
    {
        if (record1.GetClass() > record2.GetClass())
        {
            return LEXICOGRAPHICALLY_LATER;
        }
        else
        {
            return LEXICOGRAPHICALLY_EARLIER;
        }
    }

    if (record1.GetType() != record2.GetType())
    {
        if (record1.GetType() > record2.GetType())
        {
            return LEXICOGRAPHICALLY_LATER;
        }
        else
        {
            return LEXICOGRAPHICALLY_EARLIER;
        }
    }

    // If we reach this point, we must perform raw comparison of data

    result = aEntry1.CompareBytesLexicographically(aEntry1.GetOffset() + read1Offset + sizeof(ResourceRecord), aEntry2,
                                                   aEntry2.GetOffset() + read2Offset + sizeof(ResourceRecord),
                                                   Min(aEntry1.GetLength(), aEntry2.GetLength()), nullptr);

    if (result == LEXICOGRAPHICALLY_EQUAL)
    {
        if (aEntry1.GetLength() != aEntry2.GetLength())
        {
            if (aEntry1.GetLength() > aEntry2.GetLength())
            {
                return LEXICOGRAPHICALLY_LATER;
            }
            else
            {
                return LEXICOGRAPHICALLY_EARLIER;
            }
        }
    }
    else if (result < 0)
    {
        return LEXICOGRAPHICALLY_EARLIER;
    }

    return LEXICOGRAPHICALLY_LATER;
}

void MdnsServer::Prober::ProcessQuery(const Header &aRequestHeader, Message &aRequestMessage)
{
    uint16_t ownReadOffset = sizeof(Header);
    Message *ownMessage    = GetProbingMessage();
    Header   ownHeader;
    ownMessage->Read(ownMessage->GetOffset(), ownHeader);

    char     ownName[Name::kMaxNameSize];
    Name     conflictingName(nullptr);
    bool     shouldTiebreak = false;
    uint16_t aNumQuestions  = ownHeader.GetQuestionCount();

    while (aNumQuestions > 0)
    {
        Name::ReadName(*ownMessage, ownReadOffset, ownName, sizeof(ownName));
        ownReadOffset += sizeof(Question);

        aNumQuestions--;
        conflictingName.Clear();

        if (Get<Server>().HasQuestion(aRequestHeader, aRequestMessage, ownName, ResourceRecord::kTypeAny))
        {
            shouldTiebreak = true;
            conflictingName.Set(ownName);
        }

        if (shouldTiebreak)
        {
            int result = PerformTiebreak(ownHeader, *ownMessage, aRequestHeader, aRequestMessage, conflictingName);

            FreeAllRREntries(mOwnTiebreakingRecords);
            FreeAllRREntries(mIncomingTiebreakingRecords);

            if (result == WON)
            {
                break;
            }
            else if (result == LOST)
            {
                ProcessProbeConflict();
                RestartProbing(kProbeConflictWaitTime);
            }
        }
    }
}

void MdnsServer::Prober::ProcessResponse(const Header &aRequestHeader, Message &aRequestMessage)
{
    uint16_t offset        = aRequestMessage.GetOffset() + sizeof(Header);
    uint16_t ownReadOffset = sizeof(Header);
    Message *ownMessage    = GetProbingMessage();
    Header   ownHeader;
    ownMessage->Read(ownMessage->GetOffset(), ownHeader);

    char     ownName[Name::kMaxNameSize];
    Name     conflictingName(nullptr);
    uint16_t aNumQuestions = ownHeader.GetQuestionCount();
    uint16_t tmpOffset     = offset;
    bool     conflictFound = false;

    while (aNumQuestions > 0)
    {
        Name::ReadName(*ownMessage, ownReadOffset, ownName, sizeof(ownName));
        ownReadOffset += sizeof(Question);

        aNumQuestions--;

        tmpOffset = aRequestMessage.GetOffset() + sizeof(Header);

        for (uint16_t i = 0; i < aRequestHeader.GetAnswerCount(); i++)
        {
            offset      = tmpOffset;
            Error error = Name::CompareName(aRequestMessage, offset, ownName);
            // A match is signaled by kErrorNone
            if (error == kErrorNone)
            {
                MdnsServerProbingContext *context = static_cast<MdnsServerProbingContext *>(Heap::CAlloc(1, sizeof(MdnsServerProbingContext)));
                memcpy(context->name, ownName, sizeof(ownName));
                Stop(kErrorDuplicated, context);
                conflictFound = true;
                ProcessProbeConflict();
                break;
            }
            IgnoreError(ResourceRecord::ParseRecords(aRequestMessage, tmpOffset, 1));
        }
        if (conflictFound)
        {
            break;
        }
    }
}

int MdnsServer::Prober::PerformTiebreak(const Header &aOwnHeader,
                                        Message      &aOwnMessage,
                                        const Header &aIncomingHeader,
                                        Message      &aIncomingMessage,
                                        Name         &aConflictingName)

{
    uint16_t incomingNumRecords = aIncomingHeader.GetAuthorityRecordCount();
    int      tiebreakingResult  = TIE;

    Prober::RREntry *ownHead      = nullptr;
    Prober::RREntry *incomingHead = nullptr;

    // we should get the authoritative section of the incoming packet
    // skip over all the questions in the packet

    uint16_t incomingOffset = ReturnAuthoritativeOffsetFromQueryMessage(aIncomingHeader, aIncomingMessage);

    VerifyOrExit(ResourceRecord::FindRecord(aIncomingMessage, incomingOffset, incomingNumRecords, aConflictingName) !=
                 kErrorNotFound);

    // we should now iterate over the incoming authoritative section and get all RR with that name;
    AddRecordOffsetsFromAuthoritativeSection(aIncomingHeader, aIncomingMessage, aConflictingName,
                                             mIncomingTiebreakingRecords);
    // we should also iterate over our authoritative section and get all RR with that name;
    AddRecordOffsetsFromAuthoritativeSection(aOwnHeader, aOwnMessage, aConflictingName, mOwnTiebreakingRecords);

    ownHead      = mOwnTiebreakingRecords.GetHead();
    incomingHead = mIncomingTiebreakingRecords.GetHead();

    while (ownHead != nullptr || incomingHead != nullptr)
    {
        if (ownHead == nullptr)
        {
            return LOST;
        }
        if (incomingHead == nullptr)
        {
            return WON;
        }

        Message *ownMsg      = Get<MessagePool>().Allocate(Message::kTypeOther, 0);
        Message *incomingMsg = Get<MessagePool>().Allocate(Message::kTypeOther, 0);

        ownHead->GetRRName().AppendTo(*ownMsg);
        incomingHead->GetRRName().AppendTo(*incomingMsg);

        ownMsg->AppendBytesFromMessage(aOwnMessage, ownHead->GetRRStartOffset(),
                                       ownHead->GetRREndOffset() - ownHead->GetRRStartOffset());
        incomingMsg->AppendBytesFromMessage(aIncomingMessage, incomingHead->GetRRStartOffset(),
                                            incomingHead->GetRREndOffset() - incomingHead->GetRRStartOffset());

        ownHead      = ownHead->GetNext();
        incomingHead = incomingHead->GetNext();

        tiebreakingResult = CompareResourceRecords(*ownMsg, *incomingMsg);

        FreeMessage(ownMsg);
        FreeMessage(incomingMsg);

        if (tiebreakingResult < 0)
        {
            // other host won the tiebreaking
            return LOST;
        }
        else if (tiebreakingResult > 0)
        {
            // our host won the tiebreak
            return WON;
        }
    }

    return TIE;

exit:
    return WON;
}

void MdnsServer::Prober::AddRecordOffsetsFromAuthoritativeSection(const Header        &aHeader,
                                                                       const Message       &aMessage,
                                                                       const Name          &aName,
                                                                       LinkedList<RREntry> &aList)
{
    uint16_t offset = ReturnAuthoritativeOffsetFromQueryMessage(aHeader, aMessage);
    if (offset)
    {
        for (uint16_t i = 0; i < aHeader.GetAuthorityRecordCount(); i++)
        {
            Error          error;
            ResourceRecord record;
            error                = Name::CompareName(aMessage, offset, aName);
            uint16_t startOffset = offset;
            record.ReadFrom(aMessage, offset);
            offset += static_cast<uint16_t>(record.GetSize());

            if (error == kErrorNone)
            {
                RREntry *entry = nullptr;

                entry = MdnsServer::Prober::RREntry::AllocateAndInit(aName, startOffset, offset);
                VerifyOrExit(entry != nullptr);

                RREntry *prev = nullptr;

                Message *msg1 = Get<MessagePool>().Allocate(Message::kTypeOther, 0);
                entry->GetRRName().AppendTo(*msg1);
                msg1->AppendBytesFromMessage(aMessage, entry->GetRRStartOffset(),
                                             entry->GetRREndOffset() - entry->GetRRStartOffset());

                for (RREntry &cur : aList)
                {
                    Message *msg2 = Get<MessagePool>().Allocate(Message::kTypeOther, 0);

                    cur.GetRRName().AppendTo(*msg2);

                    msg2->AppendBytesFromMessage(aMessage, cur.GetRRStartOffset(),
                                                 cur.GetRREndOffset() - cur.GetRRStartOffset());

                    if (CompareResourceRecords(*msg1, *msg2) == LEXICOGRAPHICALLY_EARLIER)
                    {
                        break;
                    }

                    prev = &cur;
                    FreeMessage(msg2);
                }

                FreeMessage(msg1);

                if (prev == nullptr)
                {
                    aList.Push(*entry);
                }
                else
                {
                    aList.PushAfter(*entry, *prev);
                }
            }
        }
    }
exit:
    return;
}

const uint32_t *MdnsServer::Prober::GetServicesIdList(uint8_t &aNumServices) const
{
    aNumServices = ClampToUint8(mServicesIdList.GetLength());

    return mServicesIdList.AsCArray();
}

uint16_t MdnsServer::Prober::ReturnAuthoritativeOffsetFromQueryMessage(const Header  &aHeader,
                                                                            const Message &aMessage)
{
    uint16_t retOffset = 0;

    if (aHeader.GetAuthorityRecordCount())
    {
        uint16_t readOffset = sizeof(Header);
        Name     aName(aMessage, readOffset);

        for (uint16_t i = 0; i < aHeader.GetQuestionCount(); i++)
        {
            Question question;

            Name::CompareName(aMessage, readOffset, aName);
            IgnoreError(aMessage.Read(readOffset, question));
            readOffset += sizeof(question);
            retOffset = readOffset;
        }
        if (aHeader.GetAnswerCount())
        {
            ResourceRecord::ParseRecords(aMessage, retOffset, aHeader.GetAnswerCount());
        }
    }
    return retOffset;
}

Error MdnsServer::Prober::RREntry::Init(Name aName, uint16_t aStartOffset, uint16_t aEndOffset)
{
    mName        = aName;
    mStartOffset = aStartOffset;
    mEndOffset   = aEndOffset;
    mNext        = nullptr;

    return kErrorNone;
}

void MdnsServer::Prober::FreeAllRREntries(LinkedList<RREntry> &aList)
{
    while (!aList.IsEmpty())
    {
        Prober::RREntry *entry = aList.GetHead();
        IgnoreError(aList.Remove(*entry));
        entry->Free();
    }
}

void MdnsServer::Prober::ProcessProbeConflict(void)
{
    mConflictsCount++;
    mTimeOfConflict[(mConflictsCount % kMaxProbingConflicts) - 1] = TimerMilli::GetNow().GetValue();

    if (mConflictsCount >= kMaxProbingConflicts)
    {
        if (mTimeOfConflict[(mConflictsCount % kMaxProbingConflicts) - 1] -
                mTimeOfConflict[mConflictsCount % kMaxProbingConflicts] <
            kMaxProbingConflictstimeInterval)
        {
            mProbeRateLimit = true;
        }
    }
}

void MdnsServer::Prober::HandleTimer(Timer &aTimer)
{
    static_cast<MdnsServer::Prober *>(static_cast<TimerMilliContext &>(aTimer).GetContext())->HandleTimer();
}

//---------------------------------------------------------------------------------------------------------------------
// Announcer

MdnsServer::Announcer::Announcer(Instance &aInstance, uint32_t aId)
    : InstanceLocator(aInstance)
    , mId(aId)
    , mTimer(aInstance, HandleTimer, this)
    , mTxCount(0)
    , mState(Announcer::kIdle)
{
    mHasId = true;
}

MdnsServer::Announcer::Announcer(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mTimer(aInstance, HandleTimer, this)
    , mTxCount(0)
    , mState(Announcer::kIdle)
{
    mHasId = false;
}

void MdnsServer::Announcer::StartAnnouncing()
{
    VerifyOrExit(!mTimer.IsRunning());
    mTxCount = 0;
    mTimer.Start(0);
exit:
    return;
}

void MdnsServer::Announcer::HandleTimer(Timer &aTimer)
{
    static_cast<MdnsServer::Announcer *>(static_cast<TimerMilliContext &>(aTimer).GetContext())->HandleTimer();
}

void MdnsServer::Announcer::HandleTimer(void)
{
    Error            error        = kErrorNone;
    Message         *announcement = mAnnouncements.GetHead();
    Message         *message      = nullptr;
    Ip6::MessageInfo rspMsgInfo;

    VerifyOrExit(!mTimer.IsRunning());

    if (mTxCount >= kMaxTxCount)
    {
        mTimer.Stop();
        SetState(Announcer::kAnnounced);
        mAnnouncements.DequeueAndFree(*announcement);
        Get<MdnsServer>().HandleAnnouncerFinished(*this);
        if(this->HasId())
        {
            Get<MdnsServer>().RemoveAnnouncingInstance(GetId());
        }
        else
        {
            this->Free();
        }
        ExitNow();
    }

    rspMsgInfo.SetPeerAddr(AsCoreType(&kMdnsMulticastGroup));
    rspMsgInfo.SetPeerPort(kPort);
    rspMsgInfo.SetSockPort(kPort);
    rspMsgInfo.SetIsHostInterface(true);

    VerifyOrExit((message = Get<MdnsServer>().GetMcastSocket().NewMessage(0)) != nullptr, error = kErrorNoBufs);

    SuccessOrExit(error = message->AppendBytesFromMessage(*announcement, 0,
                                                          announcement->GetLength() - announcement->GetOffset()));

    error = Get<MdnsServer>().GetMcastSocket().SendTo(*message, rspMsgInfo);
    if (error == kErrorNone)
    {
        mTxCount++;
        mTimer.Start(kTxAnnounceInterval);
    }
    else
    {
        Stop();
        if (this->HasId())
        {
            Get<MdnsServer>().RemoveAnnouncingInstance(GetId());
        }
        else
        {
            this->Free();
        }
        ExitNow();
    }

exit:
    return;
}

void MdnsServer::Announcer::Stop(void)
{
    mTimer.Stop();
    SetState(kIdle);
    Message *message = mAnnouncements.GetHead();
    mAnnouncements.DequeueAndFree(*message);
}

const uint32_t *MdnsServer::Announcer::GetServicesIdList(uint8_t &aNumServices) const
{
    aNumServices = ClampToUint8(mServicesIdList.GetLength());

    return mServicesIdList.AsCArray();
}

void MdnsServer::SrpAdvertisingProxyHandler(otSrpServerServiceUpdateId aId,
                                       const otSrpServerHost     *aHost,
                                       uint32_t                   aTimeout,
                                       void                      *aContext)
{
    static_cast<MdnsServer *>(aContext)->SrpAdvertisingProxyHandler(aId, aHost, aTimeout);
}
void MdnsServer::SrpAdvertisingProxyHandler(otSrpServerServiceUpdateId aId, const otSrpServerHost *aHost, uint32_t aTimeout)
{
    OT_UNUSED_VARIABLE(aTimeout);

    if (!AsCoreType(aHost).IsDeleted())
    {
        // Determine what should be done - probing for new services or announce for updates
        HandleSrpAdvertisingProxy(aId, aHost);
    }
    else
    {
        // try to handle srp disable case
        if(Get<Srp::Server>().GetState() == Srp::Server::State::kStateStopped)
        {
            AnnounceSrpHostGoodbye(aId, aHost);
        }
        else
        {
            // First, remove all possible existing entities for this host

            for (Prober &p : mProbingInstances)
            {
                if (p.GetHost() == aHost)
                {
                    RemoveProbingInstance(p.GetId());
                }
            }

            AnnounceSrpHostGoodbye(aId, aHost);
            Get<Srp::Server>().HandleServiceUpdateResult(aId, kErrorNone);
        }
    }
//exit:
  //  return;
}

void MdnsServer::HandleSrpAdvertisingProxy(otSrpServerServiceUpdateId aId, const otSrpServerHost *aHost)
{
    const Srp::Server::Host *host             = nullptr;
    LinkedList<SrpAdvertisingServiceInfo> servicesMarkedForProbing;
    LinkedList<SrpAdvertisingServiceInfo> servicesMarkedForAnnounce;
    bool verifyUniqueness = false;

    while ((host = Get<Srp::Server>().GetNextHost(host)) != nullptr)
    {
        if (StringMatch(host->GetFullName(), AsCoreType(aHost).GetFullName(), kStringCaseInsensitiveMatch))
        {
            break;
        }
    }

    if(host == nullptr)
    {
        Prober *prober = AllocateProber(false, aHost, aId);
        VerifyOrExit(prober != nullptr);
        PublishFromSrp(aHost, prober);
        ExitNow();
    }
    else
    {
        LinkedList<Srp::Server::Service> services = AsCoreType(aHost).GetServices();
        if (!services.IsEmpty())
        {
            for (Srp::Server::Service &s : services)
            {
                SrpAdvertisingServiceInfo *info =
                    SrpAdvertisingServiceInfo::AllocateAndInit(s.GetServiceName(), s.GetInstanceName());
                if(!s.IsDeleted())
                {
                    if ((host->FindService(s.GetServiceName(), s.GetInstanceName()) == nullptr) && !s.IsSubType())
                    {
                        servicesMarkedForProbing.Push(*info);
                    }
                    else // updates and removals
                    {
                        servicesMarkedForAnnounce.Push(*info);
                    }
                }
                else // removals
                {
                    servicesMarkedForAnnounce.Push(*info);
                }
            }
            if(!servicesMarkedForProbing.IsEmpty())
            {
                verifyUniqueness = true;
                Prober *prober = AllocateProber(false, aHost, aId);
                VerifyOrExit(prober != nullptr);
                PublishFromSrp(aHost, prober, servicesMarkedForProbing);
                for(SrpAdvertisingServiceInfo &si : servicesMarkedForProbing)
                {
                    servicesMarkedForProbing.Remove(si);
                    si.Free();
                }
            }
            if(!servicesMarkedForAnnounce.IsEmpty())
            {
                AnnounceFromSrp(aHost, servicesMarkedForAnnounce);
                for(SrpAdvertisingServiceInfo &si : servicesMarkedForAnnounce)
                {
                    servicesMarkedForAnnounce.Remove(si);
                    si.Free();
                }
                if(!verifyUniqueness)
                {
                    Get<Srp::Server>().HandleServiceUpdateResult(aId, kErrorNone);
                }
            }
        }
        else
        {
            // host update, like address update..
            AnnounceFromSrp(aHost, aId);
            Get<Srp::Server>().HandleServiceUpdateResult(aId, kErrorNone);
            ExitNow();
        }
    }
exit:
   return;
}

Message *MdnsServer::CreateSrpPublishMessage(const otSrpServerHost *aHost)
{
    Error            error = kErrorNone;
    NameCompressInfo compressInfo(kDefaultDomainName);
    char             name[Name::kMaxNameSize];

    uint8_t             addrNum;
    const Ip6::Address *addrs   = AsCoreType(aHost).GetAddresses(addrNum);
    uint32_t            hostTtl = TimeMilli::MsecToSec(AsCoreType(aHost).GetExpireTime() - TimerMilli::GetNow());
    const Srp::Server::Service *service = nullptr;

    Header header;

    Message *message = nullptr;

    Question question(ResourceRecord::kTypeAny, ResourceRecord::kClassInternet);

    bool                     shouldPublishHost = true;
    const Srp::Server::Host *host              = nullptr;

    VerifyOrExit((message = NewPacket()) != nullptr, error = kErrorNoBufs);

    question.SetQuQuestion();

    // Setup initial DNS response header
    header.SetType(Header::kTypeQuery);

    ConvertDomainName(name, AsCoreType(aHost).GetFullName(), kThreadDefaultDomainName, kDefaultDomainName);

    // Hostname
    while ((host = Get<Srp::Server>().GetNextHost(host)) != nullptr)
    {
        if (StringMatch(AsCoreType(aHost).GetFullName(), host->GetFullName(), kStringCaseInsensitiveMatch))
        {
            shouldPublishHost = false;
            break;
        }
    }

    if (shouldPublishHost)
    {
        // Hostname
        SuccessOrExit(error = Get<Server>().AppendHostName(*message, name, compressInfo));
        message->Append(question);
        header.SetQuestionCount(header.GetQuestionCount() + 1);
    }

    while ((service = AsCoreType(aHost).FindNextService(service, OT_SRP_SERVER_FLAGS_BASE_TYPE_SERVICE_ONLY, nullptr,
                                                        nullptr)) != nullptr)
    {
        char serviceName[Name::kMaxNameSize] = {0};

        if (!service->IsDeleted())
        {
            ConvertDomainName(serviceName, service->GetInstanceName(), kThreadDefaultDomainName, kDefaultDomainName);
            SuccessOrExit(error = Get<Server>().AppendInstanceName(*message, serviceName, compressInfo));
            message->Append(question);
            header.SetQuestionCount(header.GetQuestionCount() + 1);
        }
    }

    if (shouldPublishHost)
    {
        // AAAA Resource Record
        for (uint8_t i = 0; i < addrNum; i++)
        {
            SuccessOrExit(error = Get<Server>().AppendAaaaRecord(*message, name, addrs[i], hostTtl, compressInfo));
            header.SetAuthorityRecordCount(header.GetAuthorityRecordCount() + 1);
        }
    }

    while ((service = AsCoreType(aHost).FindNextService(service, OT_SRP_SERVER_FLAGS_BASE_TYPE_SERVICE_ONLY, nullptr,
                                                        nullptr)) != nullptr)

    {
        char serviceName[Name::kMaxNameSize] = {0};

        if (!service->IsDeleted())
        {
            ConvertDomainName(serviceName, service->GetInstanceName(), kThreadDefaultDomainName, kDefaultDomainName);
            SuccessOrExit(error = Get<Server>().AppendSrvRecord(*message, serviceName, name, service->GetTtl(),
                                                                service->GetPriority(), service->GetWeight(),
                                                                service->GetPort(), compressInfo));
            header.SetAuthorityRecordCount(header.GetAuthorityRecordCount() + 1);
        }
    }

    header.SetResponseCode(Header::kResponseSuccess);
    message->Write(0, header);

    return message;

exit:
    return nullptr;
}

Message *MdnsServer::CreateSrpPublishMessage(const otSrpServerHost *aHost, LinkedList<SrpAdvertisingServiceInfo> &aList)
{
    Error            error = kErrorNone;
    NameCompressInfo compressInfo(kDefaultDomainName);
    char             name[Name::kMaxNameSize];

    const Srp::Server::Service *service = nullptr;

    Header header;

    Message *message = nullptr;

    Question question(ResourceRecord::kTypeAny, ResourceRecord::kClassInternet);

    VerifyOrExit((message = NewPacket()) != nullptr, error = kErrorNoBufs);

    question.SetQuQuestion();

    // Setup initial DNS response header
    header.SetType(Header::kTypeQuery);

    ConvertDomainName(name, AsCoreType(aHost).GetFullName(), kThreadDefaultDomainName, kDefaultDomainName);

    for (SrpAdvertisingServiceInfo &si : aList)
    {
        if ((service = AsCoreType(aHost).FindNextService(service, OT_SRP_SERVER_FLAGS_BASE_TYPE_SERVICE_ONLY,
                                                         si.GetServiceName(), si.GetInstanceName())) != nullptr)
        {
            char serviceName[Name::kMaxNameSize] = {0};

            if (!service->IsDeleted())
            {
                ConvertDomainName(serviceName, service->GetInstanceName(), kThreadDefaultDomainName,
                                  kDefaultDomainName);
                SuccessOrExit(error = Get<Server>().AppendInstanceName(*message, serviceName, compressInfo));
                message->Append(question);
                header.SetQuestionCount(header.GetQuestionCount() + 1);
            }
        }
    }

    for (SrpAdvertisingServiceInfo &si : aList)
    {
        if ((service = AsCoreType(aHost).FindNextService(service, OT_SRP_SERVER_FLAGS_BASE_TYPE_SERVICE_ONLY,
                                                         si.GetServiceName(), si.GetInstanceName())) != nullptr)
        {
            char serviceName[Name::kMaxNameSize] = {0};

            if (!service->IsDeleted())
            {
                ConvertDomainName(serviceName, service->GetInstanceName(), kThreadDefaultDomainName,
                                  kDefaultDomainName);
                SuccessOrExit(error = Get<Server>().AppendSrvRecord(*message, serviceName, name, service->GetTtl(),
                                                                    service->GetPriority(), service->GetWeight(),
                                                                    service->GetPort(), compressInfo));
                header.SetAuthorityRecordCount(header.GetAuthorityRecordCount() + 1);
            }
        }
    }

    header.SetResponseCode(Header::kResponseSuccess);
    message->Write(0, header);

    return message;

exit:
    return nullptr;
}

Error MdnsServer::AnnounceFromSrp(const otSrpServerHost *aHost, uint32_t aId)
{
    Error      error     = kErrorNone;
    Message   *message   = nullptr;
    Announcer *announcer = AllocateAnnouncer(aId);
    VerifyOrExit(announcer != nullptr, error = kErrorFailed);

    message = CreateSrpAnnounceMessage(aHost);
    Get<Srp::Server>().HandleServiceUpdateResult(aId, kErrorNone);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);
    VerifyOrExit(message->GetLength() != sizeof(Header), error = kErrorFailed);

    announcer->EnqueueAnnounceMessage(*message);
    announcer->StartAnnouncing();
exit:
    if(error != kErrorNone)
    {
        if(announcer)
        {
            RemoveAnnouncingInstance(announcer->GetId());
        }
    }
    FreeMessageOnError(message, error);
    return error;
}

Error MdnsServer::AnnounceFromSrp(const otSrpServerHost *aHost, LinkedList<SrpAdvertisingServiceInfo> &aList)
{
    Error      error     = kErrorNone;
    Message   *message   = nullptr;
    Announcer *announcer = Announcer::Allocate(GetInstance());
    VerifyOrExit(announcer != nullptr, error = kErrorNoBufs);

    message = CreateSrpAnnounceMessage(aHost, aList);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);
    VerifyOrExit(message->GetLength() != sizeof(Header), error = kErrorFailed);

    announcer->EnqueueAnnounceMessage(*message);
    announcer->StartAnnouncing();
exit:
    return error;
}

bool MdnsServer::AddressIsFromLocalSubnet(const Ip6::Address &srcAddr)
{
    const Ip6::Address *addresses;
    uint8_t             numAddresses = 0;

    addresses = GetAddresses(numAddresses);

    for (uint8_t i = 0; i < numAddresses; i++)
    {
        if (otIp6PrefixMatch(reinterpret_cast<const otIp6Address *>(&srcAddr), reinterpret_cast<const otIp6Address *>(&addresses[i])))
        {
            return true;
        }
    }

    return false;
}

Message* MdnsServer::CreateSrpAnnounceMessage(const otSrpServerHost *aHost)
{
    Error            error = kErrorNone;
    NameCompressInfo compressInfo(kDefaultDomainName);
    char             name[Name::kMaxNameSize];

    uint8_t             addrNum;
    const Ip6::Address *addrs   = AsCoreType(aHost).GetAddresses(addrNum);
    uint32_t            hostTtl = TimeMilli::MsecToSec(AsCoreType(aHost).GetExpireTime() - TimerMilli::GetNow());
    const Srp::Server::Service *service    = nullptr;
    const Srp::Server::Service *subService = nullptr;

    Message *message = nullptr;
    Header   header;

    VerifyOrExit((message = NewPacket()) != nullptr, error = kErrorNoBufs);

    header.SetType(Header::kTypeResponse);

    Get<MdnsServer>().ConvertDomainName(name, AsCoreType(aHost).GetFullName(), kThreadDefaultDomainName, kDefaultDomainName);

    // AAAA Resource Record
    for (uint8_t i = 0; i < addrNum; i++)
    {
        SuccessOrExit(error = Get<Server>().AppendAaaaRecord(*message, name, addrs[i],
                                                             hostTtl, compressInfo, true));
        Server::IncResourceRecordCount(header, false);
    }

    while ((service = AsCoreType(aHost).FindNextService(service, OT_SRP_SERVER_FLAGS_BASE_TYPE_SERVICE_ONLY, nullptr,
                                                        nullptr)) != nullptr)
    {
        char        serviceName[Name::kMaxNameSize] = {0};
        const char *instanceName                    = service->GetInstanceName();

        Get<MdnsServer>().ConvertDomainName(serviceName, instanceName, kThreadDefaultDomainName,
                                            kDefaultDomainName);

        SuccessOrExit(error = Get<Server>().AppendSrvRecord(
                          *message, serviceName, name, service->GetTtl(),
                          service->GetPriority(), service->GetWeight(), service->GetPort(), compressInfo, true));
        Server::IncResourceRecordCount(header, false);

        SuccessOrExit(error =
                          Get<Server>().AppendPtrRecord(*message, service->GetServiceName(), instanceName,
                                                        service->GetTtl(), compressInfo));
        Server::IncResourceRecordCount(header, false);

        SuccessOrExit(error =
                          Get<Server>().AppendTxtRecord(*message, instanceName, service->GetTxtData(),
                                                        service->GetTxtDataLength(), service->GetTtl(), compressInfo, true));

        Server::IncResourceRecordCount(header, false);

        while ((subService = AsCoreType(aHost).FindNextService(
                    subService, (OT_SRP_SERVER_SERVICE_FLAG_SUB_TYPE | OT_SRP_SERVER_SERVICE_FLAG_ACTIVE), nullptr,
                    instanceName)) != nullptr)
        {
            SuccessOrExit(error = Get<Server>().AppendPtrRecord(*message, subService->GetServiceName(), instanceName,
                                                                subService->GetTtl(), compressInfo));
            Server::IncResourceRecordCount(header, false);
        }
    }

    message->Write(0, header);

    return message;

exit:
    FreeMessageOnError(message, error);
    return nullptr;
}

Message *MdnsServer::CreateSrpAnnounceMessage(const otSrpServerHost                 *aHost,
                                              LinkedList<SrpAdvertisingServiceInfo> &aList)
{
    Error            error = kErrorNone;
    NameCompressInfo compressInfo(kDefaultDomainName);
    char             name[Name::kMaxNameSize];

    uint8_t             addrNum;
    const Ip6::Address *addrs   = AsCoreType(aHost).GetAddresses(addrNum);
    uint32_t            hostTtl = TimeMilli::MsecToSec(AsCoreType(aHost).GetExpireTime() - TimerMilli::GetNow());
    const Srp::Server::Service *service    = nullptr;
    const Srp::Server::Service *subService = nullptr;

    Message *message = nullptr;
    Header   header;

    VerifyOrExit((message = NewPacket()) != nullptr, error = kErrorNoBufs);

    header.SetType(Header::kTypeResponse);

    Get<MdnsServer>().ConvertDomainName(name, AsCoreType(aHost).GetFullName(), kThreadDefaultDomainName,
                                        kDefaultDomainName);

    // AAAA Resource Record
    for (uint8_t i = 0; i < addrNum; i++)
    {
        SuccessOrExit(error = Get<Server>().AppendAaaaRecord(*message, name, addrs[i], hostTtl, compressInfo, true));
        Server::IncResourceRecordCount(header, false);
    }

    for (SrpAdvertisingServiceInfo &si : aList)
    {
        if ((service = AsCoreType(aHost).FindNextService(service, OT_SRP_SERVER_FLAGS_BASE_TYPE_SERVICE_ONLY,
                                                         si.GetServiceName(), si.GetInstanceName())) != nullptr)
        {
            SuccessOrExit(error = Get<Server>().AppendPtrRecord(*message, service->GetServiceName(),
                                                                service->GetInstanceName(), service->GetTtl(),
                                                                compressInfo));
            Server::IncResourceRecordCount(header, false);

            if (service->IsDeleted())
            {
                continue;
            }

            char        serviceName[Name::kMaxNameSize] = {0};
            const char *instanceName                    = service->GetInstanceName();

            Get<MdnsServer>().ConvertDomainName(serviceName, instanceName, kThreadDefaultDomainName,
                                                kDefaultDomainName);

            SuccessOrExit(error = Get<Server>().AppendSrvRecord(*message, serviceName, name, service->GetTtl(),
                                                                service->GetPriority(), service->GetWeight(),
                                                                service->GetPort(), compressInfo, true));
            Server::IncResourceRecordCount(header, false);


            SuccessOrExit(error = Get<Server>().AppendTxtRecord(*message, instanceName,
                                                                service->GetTxtData(), service->GetTxtDataLength(),
                                                                service->GetTtl(), compressInfo, true));

            Server::IncResourceRecordCount(header, false);

            while ((subService = AsCoreType(aHost).FindNextService(
                        subService, (OT_SRP_SERVER_SERVICE_FLAG_SUB_TYPE | OT_SRP_SERVER_SERVICE_FLAG_ACTIVE), nullptr,
                        instanceName)) != nullptr)
            {
                SuccessOrExit(error = Get<Server>().AppendPtrRecord(*message, subService->GetServiceName(),
                                                                    instanceName, subService->GetTtl(), compressInfo));
                Server::IncResourceRecordCount(header, false);
            }
        }
    }

    message->Write(0, header);

    return message;

exit:
    FreeMessageOnError(message, error);
    return nullptr;
}

Error MdnsServer::PublishFromSrp(const otSrpServerHost *aHost, Prober *aProber)
{
    Error error = kErrorNone;

    Message *message = CreateSrpPublishMessage(aHost);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    if (message->GetLength() == sizeof(Header))
    {
        ExitNow(error = kErrorFailed);
    }

    aProber->EnqueueProbeMessage(*message);
    aProber->StartProbing(aProber->IsProbingForHost());

exit:
    if (error != kErrorNone)
    {
        Get<Srp::Server>().HandleServiceUpdateResult(aProber->GetId(), kErrorFailed);
        RemoveProbingInstance(aProber->GetId());
    }
    FreeMessageOnError(message, error);
    return error;
}

Error MdnsServer::PublishFromSrp(const otSrpServerHost *aHost, Prober *aProber, LinkedList<SrpAdvertisingServiceInfo> &aList)
{
    Error error = kErrorNone;

    Message *message = CreateSrpPublishMessage(aHost, aList);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    if (message->GetLength() == sizeof(Header))
    {
        ExitNow(error = kErrorFailed);
    }

    aProber->EnqueueProbeMessage(*message);
    aProber->StartProbing(aProber->IsProbingForHost());

exit:
    if (error != kErrorNone)
    {
        Get<Srp::Server>().HandleServiceUpdateResult(aProber->GetId(), kErrorFailed);
        RemoveProbingInstance(aProber->GetId());
    }
    FreeMessageOnError(message, error);
    return error;
}

MdnsServer::Announcer* MdnsServer::ReturnAnnouncingInstanceContainingServiceId(const ServiceUpdateId &aServiceId)
{
    const uint32_t *ids;
    uint8_t         numIds = 0;

    for(MdnsServer::Announcer &announcer : mAnnouncingInstances)
    {
        if(announcer.GetId() == aServiceId)
        {
            return &announcer;
        }

        ids = announcer.GetServicesIdList(numIds);
        if(!numIds)
        {
            continue;
        }
        else
        {
            for (uint8_t i = 0; i < numIds; i++)
            {
                if(ids[i] == aServiceId)
                {
                    return &announcer;
                }
            }
        }
    }
    return nullptr;
}

MdnsServer::Prober* MdnsServer::ReturnProbingInstanceContainingServiceId(const ServiceUpdateId &aServiceId)
{
    const uint32_t *ids;
    uint8_t         numIds = 0;

    for(MdnsServer::Prober &prober : mProbingInstances)
    {
        if(prober.GetId() == aServiceId)
        {
            return &prober;
        }

        ids = prober.GetServicesIdList(numIds);
        if(!numIds)
        {
            continue;
        }
        else
        {
            for (uint8_t i = 0; i < numIds; i++)
            {
                if(ids[i] == aServiceId)
                {
                    return &prober;
                }
            }
        }
    }
    return nullptr;
}

Error MdnsServer::UpdateExistingProberDataEntries(Prober &aProber, Service &aService)
{
    const uint32_t *ids;
    uint8_t         numIds = 0;

    ids = aProber.GetServicesIdList(numIds);
    Heap::Array<uint32_t> newArray;
    uint32_t              idToRemove = aService.GetServiceUpdateId();

    for (uint8_t i = 0; i < numIds; i++)
    {
        if (ids[i] != idToRemove)
        {
            newArray.PushBack(ids[i]);
        }
    }
    AsNonConst(aProber).mServicesIdList.Free();
    AsNonConst(aProber).mServicesIdList.TakeFrom(static_cast<Heap::Array<uint32_t> &&>(newArray));
    return PublishHostAndServices(AsNonConst(&aProber));
}

Error MdnsServer::UpdateExistingAnnouncerDataEntries(Announcer &aAnnouncer, Service &aService)
{
    const uint32_t *ids;
    uint8_t         numIds = 0;

    ids = aAnnouncer.GetServicesIdList(numIds);
    Heap::Array<uint32_t> newArray;
    uint32_t              idToRemove = aService.GetServiceUpdateId();

    for (uint8_t i = 0; i < numIds; i++)
    {
        if (ids[i] != idToRemove)
        {
            newArray.PushBack(ids[i]);
        }
    }
    AsNonConst(aAnnouncer).mServicesIdList.Free();
    AsNonConst(aAnnouncer).mServicesIdList.TakeFrom(static_cast<Heap::Array<uint32_t> &&>(newArray));
    return AnnounceHostAndServices(aAnnouncer);
}

MdnsServer::Prober *MdnsServer::AllocateProber(bool aProbeForHost, const otSrpServerHost *aHost, uint32_t aId)
{
    Prober *prober = Prober::Allocate(GetInstance(), aProbeForHost, aHost, aId);
    VerifyOrExit(prober != nullptr);

    if (!mProbingInstances.ContainsMatching(prober->GetId()))
    {
        mProbingInstances.Push(*prober);
    }
    else
    {
        prober->Free();
        ExitNow();
    }

    return prober;

exit:
    return nullptr;
}

MdnsServer::Announcer *MdnsServer::AllocateAnnouncer(uint32_t aId)
{
    Announcer *announcer = Announcer::Allocate(GetInstance(), aId);
    VerifyOrExit(announcer != nullptr);

    if (!mAnnouncingInstances.ContainsMatching(announcer->GetId()))
    {
        mAnnouncingInstances.Push(*announcer);
    }
    else
    {
        announcer->Free();
        ExitNow();
    }

    return announcer;

exit:
    return nullptr;
}

Error MdnsServer::SrpAdvertisingServiceInfo::Init(const char *aServiceName, const char *aInstanceName)
{
    Error error = kErrorNone;

    // VerifyOrExit(mServiceName.Set(aServiceName) != kErrorNone, error = kErrorFailed);
    // VerifyOrExit(mInstanceName.Set(aInstanceName) != kErrorNone, error = kErrorFailed);

    mServiceName.Set(aServiceName);
    mInstanceName.Set(aInstanceName);

    return error;
}

uint16_t MdnsServer::ReturnKnownAnswerOffsetFromQuery(const Header &aHeader, const Message &aMessage)
{
    uint16_t retOffset = 0;

    if (aHeader.GetAnswerCount())
    {
        uint16_t readOffset = sizeof(Header);
        Name     aName(aMessage, readOffset);

        for (uint16_t i = 0; i < aHeader.GetQuestionCount(); i++)
        {
            Question question;

            Name::CompareName(aMessage, readOffset, aName);
            IgnoreError(aMessage.Read(readOffset, question));
            readOffset += sizeof(question);
            retOffset = readOffset;
        }
    }
    return retOffset;
}

Error MdnsServer::KnownAnswerEntry::Init(char *aServiceName, char *aInstanceName, ResourceRecord &aRecord)
{
    mServiceName.Set(aServiceName);
    mInstanceName.Set(aInstanceName);
    mRecord = aRecord;

    return kErrorNone;
}

void MdnsServer::RemoveAllKnownAnswerEntries(void)
{
    while(!mReceivedKnownAnswers.IsEmpty())
    {
        MdnsServer::KnownAnswerEntry *entry = mReceivedKnownAnswers.GetHead();
        IgnoreError(mReceivedKnownAnswers.Remove(*entry));
        entry->Free();
    }
}

} // namespace ServiceDiscovery
} // namespace Dns
} // namespace ot

#endif // OPENTHREAD_CONFIG_MDNS_SERVER_ENABLE
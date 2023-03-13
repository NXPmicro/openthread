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
const otIp6Address kMdnsMulticastGroup                    = {0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFB};
const otIp6Address kAnyAddress                            = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

MdnsServer::MdnsServer(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mTimer(aInstance)
    , mSocket(aInstance)
    , mHandleUdpReceive(aInstance)
    , mAnnouncer(aInstance)
    , mMdnsAnnouncing(aInstance)
    , mHostIsToBeAnnounced(true)
{
    SetState(kStateStopped);
}

Error MdnsServer::Start(void)
{
    Error              error  = kErrorNone;

    VerifyOrExit(!IsRunning(), error = kErrorAlready);
    VerifyOrExit(GetHostName() != nullptr, error = kErrorInvalidState);

    SuccessOrExit(error = mSocket.Open(&MdnsServer::HandleUdpReceive, this));
    SuccessOrExit(error = mSocket.Bind(kPort, Ip6::kNetifBackbone));
    SuccessOrExit(error = mSocket.JoinNetifMulticastGroup(Ip6::kNetifBackbone, AsCoreType(&kMdnsMulticastGroup)));

    SetState(kStateRunning);

    mMdnsAnnouncing.Post();

    LogInfo("started");
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

void MdnsServer::HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    static_cast<MdnsServer *>(aContext)->HandleUdpReceive(AsCoreType(aMessage), AsCoreType(aMessageInfo));
}

void MdnsServer::HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    aMessage.Append(aMessageInfo);
    mRxPktQueue.Enqueue(aMessage);

    mHandleUdpReceive.Post();
}

void MdnsServer::HandleUdpReceive()
{
    Message *aMessage;
    Ip6::MessageInfo aMessageInfo;
    Header requestHeader;

    aMessage = mRxPktQueue.GetHead();

    while (aMessage != nullptr)
    {
        if(kErrorNone == aMessage->Read(aMessage->GetLength() - sizeof(aMessageInfo), aMessageInfo))
        {
            if (kErrorNone == aMessage->Read(aMessage->GetOffset(), requestHeader))
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
        mRxPktQueue.DequeueAndFree(*aMessage);
        aMessage = mRxPktQueue.GetHead();
    }
}

void MdnsServer::ProcessQuery(const Dns::Header      &aRequestHeader,
                              Message                &aRequestMessage,
                              const Ip6::MessageInfo &aMessageInfo)
{
    Error                    error           = kErrorNone;
    Message                 *responseMessage = nullptr;
    Header                   responseHeader;
    Header::Response         responseCode;
    Server::NameCompressInfo compressInfo(kDefaultDomainName);
    bool                     bSendUnicast = false;

    OT_UNUSED_VARIABLE(aMessageInfo);

    // Validate the query
    VerifyOrExit(aRequestHeader.GetQueryType() == Header::kQueryTypeStandard, error = kErrorDrop);
    VerifyOrExit(!aRequestHeader.IsTruncationFlagSet(), error = kErrorDrop);
    VerifyOrExit(aRequestHeader.GetQuestionCount() > 0, error = kErrorDrop);

    VerifyOrExit((responseMessage = mSocket.NewMessage(0)) != nullptr, error = kErrorNoBufs);
    SuccessOrExit(error = responseMessage->SetLength(sizeof(Header)));

    responseHeader.SetType(Header::kTypeResponse);

    responseCode =
        ResolveQuery(aRequestHeader, aRequestMessage, responseHeader, *responseMessage, compressInfo, bSendUnicast);
    VerifyOrExit(responseCode == Header::kResponseSuccess, error = kErrorDrop);

    SuccessOrExit(error = SendPacket(*responseMessage, responseHeader, responseCode, bSendUnicast, &AsNonConst(aMessageInfo)));

exit:
    FreeMessageOnError(responseMessage, error);
}

void MdnsServer::ProcessResponse(const Header           &aRequestHeader,
                                 Message                &aRequestMessage,
                                 const Ip6::MessageInfo &aMessageInfo)
{
    OT_UNUSED_VARIABLE(aMessageInfo);

    Client::Response  response;
    Client::QueryInfo info;

    response.mInstance = &Get<Instance>();
    response.mMessage  = &aRequestMessage;

    /* Ignore responses with a source port different from 5353 */

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
    // The error is drop as we can receive all multicast responses from the network and this one was not meant for us
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
            // return back the offset where the name ends in the query so it can be used to store the number of known
            // answers
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

Header::Response MdnsServer::ResolveQuestion(const char       *aName,
                                             const Question   &aQuestion,
                                             Header           &aResponseHeader,
                                             Message          &aResponseMessage,
                                             NameCompressInfo &aCompressInfo,
                                             bool              aAdditional)
{
    const Service   *service                  = nullptr;
    uint16_t         qtype                    = aQuestion.GetType();
    bool             needAdditionalAaaaRecord = false;
    Header::Response responseCode             = Header::kResponseSuccess;

    while ((service = FindNextService(service)) != nullptr)
    {
        bool serviceNameMatched  = service->MatchesServiceName(aName);
        bool instanceNameMatched = service->MatchesInstanceName(aName);
        bool ptrQueryMatched =
            (qtype == ResourceRecord::kTypePtr || qtype == ResourceRecord::kTypeAny) && serviceNameMatched;
        bool srvQueryMatched =
            (qtype == ResourceRecord::kTypePtr || qtype == ResourceRecord::kTypeAny) && instanceNameMatched;
        bool txtQueryMatched =
            (qtype == ResourceRecord::kTypeTxt || qtype == ResourceRecord::kTypeAny) && instanceNameMatched;

        if (ptrQueryMatched || srvQueryMatched)
        {
            needAdditionalAaaaRecord = true;
        }

        if (!aAdditional && ptrQueryMatched)
        {
            VerifyOrExit(
                (Server::AppendPtrRecord(aResponseMessage, service->GetServiceName(), service->GetInstanceName(),
                                         service->GetTtl(), aCompressInfo) == kErrorNone),
                responseCode = Header::kResponseNameError);
            Server::IncResourceRecordCount(aResponseHeader, false);
        }

        if ((!aAdditional && srvQueryMatched) || (aAdditional && ptrQueryMatched))
        {
            VerifyOrExit((Server::AppendSrvRecord(aResponseMessage, service->GetInstanceName(), GetHostName(),
                                                  service->GetTtl(), service->GetPriority(), service->GetWeight(),
                                                  service->GetPort(), aCompressInfo) == kErrorNone),
                         responseCode = Header::kResponseNameError);
            Server::IncResourceRecordCount(aResponseHeader, aAdditional);
        }

        if ((!aAdditional && txtQueryMatched) || (aAdditional && ptrQueryMatched))
        {
            VerifyOrExit(
                (Server::AppendTxtRecord(aResponseMessage, service->GetInstanceName(), service->GetTxtData(),
                                         service->GetTxtDataLength(), kDefaultTtl, aCompressInfo) == kErrorNone),
                responseCode = Header::kResponseNameError);
            Server::IncResourceRecordCount(aResponseHeader, aAdditional);
        }
    }

    if ( (!aAdditional && (qtype == ResourceRecord::kTypeAaaa || qtype == ResourceRecord::kTypeAny) && (!strcmp(GetHostName(), aName))) ||
         (aAdditional && needAdditionalAaaaRecord))
    {
        uint8_t             addrNum;
        const Ip6::Address *addrs = GetAddresses(addrNum);

        for (uint8_t i = 0; i < addrNum; i++)
        {
            VerifyOrExit(
                (Server::AppendAaaaRecord(aResponseMessage, GetHostName(), addrs[i], kDefaultTtlWithHostName, aCompressInfo) == kErrorNone),
                responseCode = Header::kResponseNameError);
            Server::IncResourceRecordCount(aResponseHeader, aAdditional);
        }
    }

exit:
    return responseCode;
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

    readOffset = sizeof(Header);

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
                         qtype == ResourceRecord::kTypeTxt || qtype == ResourceRecord::kTypeAaaa ||
                         qtype == ResourceRecord::kTypeAny,
                     responseCode = Header::kResponseNotImplemented);

        VerifyOrExit(Server::FindNameComponents(name, aCompressInfo.GetDomainName(), nameComponentsOffsetInfo) ==
                         kErrorNone,
                     responseCode = Header::kResponseNameError);

        SuccessOrExit(responseCode =
                          ResolveQuestion(name, question, aResponseHeader, aResponseMessage, aCompressInfo, false));

#if OPENTHREAD_CONFIG_SRP_SERVER_ENABLE
        // Convert from kDefaultMcastDomainName to kDefaultDomainName (.local -> default.service.arpa) for searching
        memcpy(name + nameComponentsOffsetInfo.mDomainOffset, kThreadDefaultDomainName,
               sizeof(kThreadDefaultDomainName));
        Get<Server>().ResolveQuestionBySrp(name, question, aResponseHeader, aResponseMessage, aCompressInfo, false);
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
                              ResolveQuestion(name, question, aResponseHeader, aResponseMessage, aCompressInfo, true));

#if OPENTHREAD_CONFIG_SRP_SERVER_ENABLE
            // Convert from kDefaultMcastDomainName to kDefaultDomainName (.local -> default.service.arpa) for searching
            memcpy(name + nameComponentsOffsetInfo.mDomainOffset, kThreadDefaultDomainName,
                   sizeof(kThreadDefaultDomainName));
            Get<Server>().ResolveQuestionBySrp(name, question, aResponseHeader, aResponseMessage, aCompressInfo, true);
#endif
        }
    }

exit:
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

Error MdnsServer::AddService(const char *aInstanceName,
                             const char *aServiceName,
                             uint16_t    aPort,
                             const otDnsTxtEntry *aTxtEntries,
                             uint8_t mNumTxtEntries)
{
    Service *service = nullptr;

    Error error = kErrorNone;

    // Ensure the same service does not exist already.
    VerifyOrExit(FindNextService(nullptr, aServiceName, aInstanceName) == nullptr, error = kErrorFailed);

    service = Service::AllocateAndInit(aServiceName, aInstanceName, aPort);
    VerifyOrExit(service != nullptr, error = kErrorFailed);

    if (aTxtEntries != nullptr)
    {
        if (aTxtEntries->mKey)
        {
            uint8_t  txtBuffer[kTXTMaxBufferSize] = {0};
            uint32_t txtBufferOffset              = 0;

            for (uint32_t i =0; i < mNumTxtEntries; i++)
            {
                uint32_t keySize = strlen(aTxtEntries[i].mKey);
                //add TXT entry len + 1 is for '='    
                *(txtBuffer + txtBufferOffset++) = keySize + aTxtEntries[i].mValueLength + 1;
                
                //add TXT entry key
                memcpy(txtBuffer + txtBufferOffset, aTxtEntries[i].mKey, keySize);
                txtBufferOffset += keySize;
                
                //add TXT entry value if pointer is not null, if pointer is null it means we have bool value
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

    if (GetState() == kStateRunning)
    {
        mMdnsAnnouncing.Post();
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
    Error error = kErrorNone;

    // Ensure the service exists already.
    VerifyOrExit(FindService(aServiceName, aInstanceName) != nullptr, error = kErrorInvalidState);

    // First remove the existing service,
    VerifyOrExit(RemoveService(aInstanceName, aServiceName) != kErrorNotFound, error = kErrorFailed);

    // Then add it back with it's changed content
    VerifyOrExit(AddService(aInstanceName, aServiceName, aPort, aTxtEntries, mNumTxtEntries) != kErrorFailed, error = kErrorFailed);

exit:
    return error;
}

Error MdnsServer::RemoveService(const char *aInstanceName, const char *aServiceName)
{
    Service *service;
    Error    error;

    VerifyOrExit((service = FindService(aServiceName, aInstanceName)) != nullptr, error = kErrorNotFound);

    SuccessOrExit(error = AnnounceServiceGoodbye(*service));

    mServices.Remove(*service);
    service->Free();

exit:
    return error;
}

Error MdnsServer::AnnounceServiceGoodbye(Service &aService)
{
    NameCompressInfo compressInfo(kDefaultDomainName);
    Message         *message = nullptr;
    Header           header;
    Error            error;

    VerifyOrExit((message = mSocket.NewMessage(0)) != nullptr, error = kErrorNoBufs);
    SuccessOrExit(error = message->SetLength(sizeof(Header)));

    header.SetType(Header::kTypeResponse);

    SuccessOrExit(error = AppendServiceInfo(*message, header, aService, compressInfo));
    SuccessOrExit(error = SendPacket(*message, header));

exit:
    FreeMessageOnError(message, error);
    return error;
}

Error MdnsServer::AnnounceHostGoodbye()
{
    NameCompressInfo    compressInfo(kDefaultDomainName);
    Message            *message = nullptr;
    Header              header;
    Service            *service;
    uint8_t             addrNum;
    const Ip6::Address *addrs = GetAddresses(addrNum);
    Error               error;

    VerifyOrExit((message = mSocket.NewMessage(0)) != nullptr, error = kErrorNoBufs);
    SuccessOrExit(error = message->SetLength(sizeof(Header)));

    header.SetType(Header::kTypeResponse);

    for (service = mServices.GetHead(); service != nullptr; service = service->GetNext())
    {
        SuccessOrExit(error = AppendServiceInfo(*message, header, *service, compressInfo));
    }

    for (uint8_t i = 0; i < addrNum; i++)
    {
        SuccessOrExit(error = Server::AppendAaaaRecord(*message, GetHostName(), addrs[i], 0, compressInfo));
        Server::IncResourceRecordCount(header, false);
    }

    SuccessOrExit(error = SendPacket(*message, header));

exit:
    FreeMessage(message);
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
                                                  aService.GetPort(), aCompressInfo));
    Server::IncResourceRecordCount(aHeader, false);

    SuccessOrExit(error = Server::AppendTxtRecord(aMessage, aService.GetInstanceName(), aService.GetTxtData(),
                                                  aService.GetTxtDataLength(), kDefaultTtl, aCompressInfo));
    Server::IncResourceRecordCount(aHeader, false);

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
    //Make the source address 0 to signal that the IPv6 layer should use the source address selection algortihm 
    //to select appropriate source address
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

Error MdnsServer::Service::Init(const char *aServiceName, const char *aInstanceName, uint16_t aPort)
{
    mServiceName.Set(aServiceName);
    mInstanceName.Set(aInstanceName);

    mPriority        = 0;
    mWeight          = 0;
    mPort            = aPort;
    mTtl             = kDefaultTtlWithHostName;
    mIsToBeAnnounced = true;

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

//---------------------------------------------------------------------------------------------------------------------
// Announcer

MdnsServer::Announcer::Announcer(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mTxCount(0)
    , mTimer(aInstance)
    , mState(Announcer::kIdle)

{
}

void MdnsServer::Announcer::StartAnnouncing()
{
    VerifyOrExit(!mTimer.IsRunning());
    mTxCount = 0;
    mTimer.Start(0);
exit:
    return;
}

void MdnsServer::Announcer::MdnsAnnouncingHandler()
{
    Message *announceMessage = nullptr;

    announceMessage = Get<MdnsServer::Announcer>().CreateHostAndServicesAnnounceMessage();

    if (announceMessage != nullptr)
    {
        Get<MdnsServer::Announcer>().EnqueueAnnounceMessage(*announceMessage);
        StartAnnouncing();
    }
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
        Get<MdnsServer::Announcer>().SetState(Announcer::kAnnounced);
        mAnnouncements.DequeueAndFree(*announcement);
        if(!Get<MdnsServer>().IsHostAnnounced())
        {
            Get<MdnsServer>().SetHostAnnounced(true);
        }
        ExitNow();
    }

    rspMsgInfo.SetPeerAddr(AsCoreType(&kMdnsMulticastGroup));
    rspMsgInfo.SetPeerPort(kPort);
    rspMsgInfo.SetSockPort(kPort);
    rspMsgInfo.SetIsHostInterface(true);

    VerifyOrExit((message = Get<MdnsServer>().GetMcastSocket().NewMessage(0)) != nullptr, error = kErrorNoBufs);

    SuccessOrExit(
        error = message->AppendBytesFromMessage(*announcement, 0, announcement->GetLength() - announcement->GetOffset()));

    error = Get<MdnsServer>().GetMcastSocket().SendTo(*message, rspMsgInfo);
    if (error == kErrorNone)
    {
        mTxCount++;
        mTimer.Start(kTxAnnounceInterval);
    }
    else
    {
        Get<MdnsServer::Announcer>().SetState(Announcer::kIdle);
        mTxCount = 0;
        ExitNow();
    }

exit:
    return;
}

Message* MdnsServer::Announcer::CreateHostAndServicesAnnounceMessage()
{
    Error            error = kErrorNone;
    NameCompressInfo compressInfo(kDefaultDomainName);

    uint8_t              addrNum;
    const Ip6::Address  *addrs   = Get<MdnsServer>().GetAddresses(addrNum);
    uint32_t             hostTtl = 0;
    MdnsServer::Service *next    = nullptr;

    Message *message = nullptr;
    Header   header;

    VerifyOrExit((message = Get<MdnsServer>().GetMcastSocket().NewMessage(0)) != nullptr, error = kErrorNoBufs);
    SuccessOrExit(error = message->SetLength(sizeof(Header)));

    header.SetType(Header::kTypeResponse);
    if(!Get<MdnsServer>().IsHostAnnounced())
    {
        // AAAA Resource Record
        for (uint8_t i = 0; i < addrNum; i++)
        {
            SuccessOrExit(error = Get<Server>().AppendAaaaRecord(*message, Get<MdnsServer>().GetHostName(), addrs[i],
                                                                 hostTtl, compressInfo));
            Server::IncResourceRecordCount(header, false);
        }
    }

    for (MdnsServer::Service *service = Get<MdnsServer>().GetServiceListHead(); service != nullptr; service = next)
    {
        next = service->GetNext();
        if (service->mIsToBeAnnounced)
        {
            SuccessOrExit(error = Server::AppendPtrRecord(*message, service->GetServiceName(),
                                                          service->GetInstanceName(), service->GetTtl(), compressInfo));
            Server::IncResourceRecordCount(header, false);

            SuccessOrExit(error = Server::AppendSrvRecord(
                              *message, service->GetInstanceName(), Get<MdnsServer>().GetHostName(), service->GetTtl(),
                              service->GetPriority(), service->GetWeight(), service->GetPort(), compressInfo));
            Server::IncResourceRecordCount(header, false);

            SuccessOrExit(error =
                              Server::AppendTxtRecord(*message, service->GetInstanceName(), service->GetTxtData(),
                                                      service->GetTxtDataLength(), service->GetTtl(), compressInfo));
            Server::IncResourceRecordCount(header, false);

            service->mIsToBeAnnounced = false;
        }
    }

    message->Write(0, header);

    return message;

exit:
    return nullptr;
}

} // namespace ServiceDiscovery
} // namespace Dns
} // namespace ot

#endif // OPENTHREAD_CONFIG_MDNS_SERVER_ENABLE

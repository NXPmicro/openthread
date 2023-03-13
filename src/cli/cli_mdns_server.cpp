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
 *   This file implements a simple CLI for the MDNS Server.
 */

#include "cli_mdns_server.hpp"
#include "net/srp_server.hpp"
#include <openthread/dns.h>

#if OPENTHREAD_CONFIG_MDNS_SERVER_ENABLE

namespace ot {
namespace Cli {

MdnsServer::MdnsServer(otInstance *aInstance, OutputImplementer &aOutputImplementer)
    : Output(aInstance, aOutputImplementer)
{
}

template <> otError MdnsServer::Process<Cmd("address")>(Arg aArgs[])
{
    otError error = OT_ERROR_NONE;

    if (aArgs[0].IsEmpty())
    {
        const otIp6Address *addresses;
        uint8_t             numAddresses = 0;

        addresses = otMdnsServerGetAddresses(GetInstancePtr(), &numAddresses);

        for (uint8_t index = 0; index < numAddresses; index++)
        {
            OutputIp6AddressLine(addresses[index]);
        }
    }
    else
    {
        otIp6Address address;

        for (Arg *arg = &aArgs[0]; !arg->IsEmpty(); arg++)
        {
            SuccessOrExit(error = arg->ParseAsIp6Address(address));
            IgnoreError(error = otMdnsServerAddAddress(GetInstancePtr(), &address));
        }
    }

exit:
    return error;
}

template <> otError MdnsServer::Process<Cmd("hostname")>(Arg aArgs[])
{
    otError error = OT_ERROR_NONE;

    if (aArgs[0].IsEmpty())
    {
        const char *name = otMdnsServerGetHostName(GetInstancePtr());
        OutputLine("%s", (name != nullptr) ? name : "(null)");
    }
    else
    {
        VerifyOrExit(aArgs[1].IsEmpty(), error = OT_ERROR_INVALID_ARGS);

        error = otMdnsServerSetHostName(GetInstancePtr(), aArgs[0].GetCString());
    }

exit:
    return error;
}

template <> otError MdnsServer::Process<Cmd("service")>(Arg aArgs[])
{
    otError error = OT_ERROR_NONE;
    uint8_t txtBuffer[OPENTHREAD_CONFIG_SRP_CLIENT_BUFFERS_TXT_BUFFER_SIZE] = {0};
    otDnsTxtEntry txtEntry;
    otDnsTxtEntry *txtEntryPtr = nullptr;
    uint8_t numTxtEntries = 0;

    txtEntry.mKey= nullptr;
    txtEntry.mValue = txtBuffer;

    if (aArgs[0].IsEmpty())
    {
        const otMdnsService *service = nullptr;

        while ((service = otMdnsServerGetNextService(GetInstancePtr(), service, nullptr, nullptr)) != nullptr)
        {
            const char    *instanceName = otMdnsServerServiceGetInstanceName(service);
            const char    *serviceName  = otMdnsServerServiceGetServiceName(service);
            uint16_t       port         = otMdnsServerServiceGetPort(service);
            uint16_t       txtDataLength;
            const uint8_t *txtData;

            OutputFormat("%s %s %d", instanceName, serviceName, port);

            txtData = otMdnsServerServiceGetTxtData(service, &txtDataLength);
            if (txtDataLength == 0)
            {
                OutputNewLine();
                continue;
            }

            OutputFormat(" TXT: ");
            OutputDnsTxtData(txtData, txtDataLength);
            OutputNewLine();
        }
    }
    else if (aArgs[0] == "add")
    {
        const char *instanceName;
        const char *serviceName;
        uint16_t    port;

        VerifyOrExit(!aArgs[1].IsEmpty() && !aArgs[2].IsEmpty(), error = OT_ERROR_INVALID_ARGS);

        instanceName = aArgs[1].GetCString();
        serviceName  = aArgs[2].GetCString();

        SuccessOrExit(error = aArgs[3].ParseAsUint16(port));

        if (!aArgs[4].IsEmpty())
        {
            SuccessOrExit(error = aArgs[4].ParseAsHexString(txtEntry.mValueLength, txtBuffer));
            txtEntryPtr = &txtEntry;
            numTxtEntries = 1;
        }

        error = otMdnsServerAddService(GetInstancePtr(), instanceName, serviceName, port, txtEntryPtr, numTxtEntries);
    }
    else if (aArgs[0] == "update")
    {
        const char *instanceName;
        const char *serviceName;
        uint16_t    port;

        VerifyOrExit(!aArgs[1].IsEmpty() && !aArgs[2].IsEmpty(), error = OT_ERROR_INVALID_ARGS);

        instanceName = aArgs[1].GetCString();
        serviceName  = aArgs[2].GetCString();

        SuccessOrExit(error = aArgs[3].ParseAsUint16(port));

        if (!aArgs[4].IsEmpty())
        {
            SuccessOrExit(error = aArgs[4].ParseAsHexString(txtEntry.mValueLength, txtBuffer));
            txtEntryPtr = &txtEntry;
            numTxtEntries = 1;
        }

        error = otMdnsServerUpdateService(GetInstancePtr(), instanceName, serviceName, port, txtEntryPtr, numTxtEntries);
    }
    else if (aArgs[0] == "remove")
    {
        VerifyOrExit(!aArgs[1].IsEmpty() && !aArgs[2].IsEmpty(), error = OT_ERROR_INVALID_ARGS);

        error = otMdnsServerRemoveService(GetInstancePtr(), aArgs[1].GetCString(), aArgs[2].GetCString());
    }

exit:
    return error;
}

template <> otError MdnsServer::Process<Cmd("start")>(Arg aArgs[])
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(aArgs[0].IsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otMdnsServerStart(GetInstancePtr());

exit:
    return error;
}

template <> otError MdnsServer::Process<Cmd("state")>(Arg aArgs[])
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(aArgs[0].IsEmpty(), error = OT_ERROR_INVALID_ARGS);

    if (otMdnsServerIsRunning(GetInstancePtr()))
    {
        OutputLine("running");
    }
    else
    {
        OutputLine("stopped");
    }

exit:
    return error;
}

template <> otError MdnsServer::Process<Cmd("stop")>(Arg aArgs[])
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(aArgs[0].IsEmpty(), error = OT_ERROR_INVALID_ARGS);

    otMdnsServerStop(GetInstancePtr());

exit:
    return error;
}

otError MdnsServer::Process(Arg aArgs[])
{
#define CmdEntry(aCommandString)                                  \
    {                                                             \
        aCommandString, &MdnsServer::Process<Cmd(aCommandString)> \
    }

    static constexpr Command kCommands[] = {
        CmdEntry("address"), CmdEntry("hostname"), CmdEntry("service"),
        CmdEntry("start"),   CmdEntry("state"),    CmdEntry("stop"),
    };

    static_assert(BinarySearch::IsSorted(kCommands), "kCommands is not sorted");

    otError        error = OT_ERROR_INVALID_COMMAND;
    const Command *command;

    if (aArgs[0].IsEmpty() || (aArgs[0] == "help"))
    {
        OutputCommandTable(kCommands);
        ExitNow(error = aArgs[0].IsEmpty() ? error : OT_ERROR_NONE);
    }

    command = BinarySearch::Find(aArgs[0].GetCString(), kCommands);
    VerifyOrExit(command != nullptr);

    error = (this->*command->mHandler)(aArgs + 1);

exit:
    return error;
}

} // namespace Cli
} // namespace ot

#endif // OPENTHREAD_CONFIG_MDNS_SERVER_ENABLE

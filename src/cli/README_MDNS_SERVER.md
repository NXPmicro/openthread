# OpenThread CLI - mDNS Server

## Command List

- [help](#help)
- [address](#address)
- [hostname](#hostname)
- [service](#service)
- [start](#start)
- [state](#state)
- [stop](#stop)

## Command Details

### help

Usage: `mdns server help`

Print mDNS server help menu.

```bash
> mdns server help
address
hostname
service
start
state
stop
Done
```

### address

Usage: `mdns server address`

Gets the addresses used by the mDNS server.

```bash
> mdns server address
fe80:0:0:0:c295:daff:fe01:11b
2a02:2f01:7119:9f00:c295:daff:fe01:11b
Done
```

### hostname

Usage: `mdns server hostname`

Print hostname associated to the mDNS server.

```bash
> mdns server hostname
mDNS-serverHostName.local.
Done
```

### service

Usage: `mdns server service`

Print information of all registered services.

The TXT record is displayed as an array of entries. If an entry has a key, the key will be printed in ASCII format. The value portion will always be printed as hex bytes.

```bash
> mdns server service
    host: NXPBR-xxxx.local.
    addresses: [fe80:0:0:0:c295:daff:fe01:11b 2a02:2f01:7119:9f00:c295:daff:fe01:11b]

nxp-br._meshcop._udp.local.
    subtypes: (null)
    port: 49152
    TXT: [rv=31, tv=312e332e30, sb=00000021, nn=4f70656e5468726561642d62366665, xp=6d0ee1181f31851b, vn=4e5850, mn=78787878, dn=44656661756c74446f6d61696e, xa=ca4c9bf6b20c3814]
Done
```

### service add

Usage: `mdns server service add <instancename> <servicename> <port> [txt]`

Add a service with a given instance name, service name, port number and txt values.
The `<servicename>` can optionally include a list of service subtypes labels separated by comma.
The txt should follow hex-string format and is treated as an already encoded TXT data byte sequence. It is also optional and if not provided it is considered empty.

```bash
> mdns server service add testService._http._tcp.local. _http._tcp.local. 80
Done

> mdns server service add testService2._http._tcp.local. _http._tcp.local.,_sub1,_sub2 80
Done
```

### service update

Usage: `mdns server service update <instancename> <servicename> <port> [txt]`
Updates the port, txt values, or both for an existing service with given instance name and service name.

```bash
> mdns server service update testService._http._tcp.local. _http._tcp.local. 81
Done

> mdns server service update testService._http._tcp.local. _http._tcp.local. 81 0778797a3d58595a
Done
```

### service remove

Usage: `mdns server service remove <instancename> <servicename>`

Remove a service with a give instance name and service name.

```bash
> mdns server service remove testService._http._tcp.local. _http._tcp.local.
Done
```

### start

Usage: `mdns server start`

Start the mdns server.

```bash
> mdns server start
Done
```

### state

Usage: `mdns server state`

Print the state of mDNS server. It could be `stopped` or `running`.

- stopped: The mDNS server is not active. It will handle service registrations, but uniqueness of services will not be determined untill turned on.
- running: The mDNS server is active and will handle service registrations and will perform actions related to registering/updating services.

```bash
> mdns server state
running
Done
```

### stop

Usage: `mdns server stop`

Stop the mDNS server.

```bash
> mdns server stop
Done
```

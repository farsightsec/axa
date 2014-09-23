# Farsight AXA

The purpose of Farsight's SRA (SIE Remote Access) toolkit is to bring the 
capabilties of the Farsight Security Information Exchange (SIE) right to the 
subscriber's network rather than requirng a direct connection to Farsight SIE. 

The SRA service is delivered via Farsight's Advanced Exchange Access (AXA) 
protocol which allows SRA session initators to control a number of parameters
include:

* select and deselect SIE channels
* specify search patterns
* control rate limits and packet counts

After SRA session parameters have been established, SIE data is encrypted and 
streamed to the SRA subscriber via TCP/IP, using an SSH transport (similar to 
applications like [rsync](http://troy.jdmz.net/rsync/) or 
[git](http://git-scm.com/book/en/Git-on-the-Server-Setting-Up-the-Server)).

The following tools are provided to Farsight customers that subscribe to one
or more SRA channels:

* `libaxa`: middleware for AXA protocol including connection and 
encapsulation/decapsulation
* `sratunnel`: a tool that copies remote SIE data to the local network
* `sratool`: a debuging interface to exercise and examine AXA protocol 
operations

The `sratunnel` source code is intended as a working example of calling 
`libaxa` to set up an SRA session, turn on an SIE channel, set a single and 
simple filter, receive remote data over AXA, and decapsulate that data. SRA 
application developers can use the `sratunnel` source code as a template for 
other SRA applications, or get a quicker start by running the `sratunnel` 
program which will make the remote data available locally, and then use 
[`pcap`](http://www.tcpdump.org/) (for SIE channel 14) or 
[`nmsg`](https://github.com/farsightsec/nmsg) (for all other SIE channels) 
as they would on an analysis server directly conected to SIE itself. 

Of note, SRA can perform filtering. This feature is
highly desirable due to the very high volume of data caried by SIE which can
burst to hundreds of megabits per second in a single channel. On the flip side, 
when using SRA to access low volume channels, entire 
channels can be selected for remote distribution. However, when remotely 
accessing high volume SIE channels, the subscriber usually 
specifies a list of IP addresses and DNS names of interest, so that the SRA 
server can filter out everything else, and send to the subscriber only a 
subset of that channel's SIE data.

Also of note, AXA is a deliberately lossy protocol. If a subscriber requests 
more data than the network can carry, data overruns will occurr. When 
this happens, "loss markers" are transmitted reliably within the AXA stream 
to inform the subscriber. At this point, the subscriber's possible mitgation 
strategies include:

* ask for less data,
* increase their network capacity, or 
* treat the SRA stream as a chunky and non-representative sample of the 
total SIE data. 

The `sratool` program is intended primarily as a protocol demonstration and 
debuging interface, although it can also perform the same functions as 
`sratunnel`. The distributed AXA package constitutes the 
authoritative documentation of the AXA protocol. Farsight advises SRA 
subscribers to utilize the `libaxa` library for session management and data 
decapsulation rather than crafting hand drawn logic to perform these functions.
A later version of the AXA software is expected to include Python and Perl 
language bindings.

This document covers version `0.2.4`.

For specific details on `sratool` and `sratunnel` please see the respective
man pages included in the distribution.

## SRA server SSH details

As of the time of this writing, the SRA service answers at the following 
address via the SSH transport:

`sra-service@sra-eft.sie-remote.net`

You will need to create or edit your ~/.ssh/config file to specify the 
private half of the SSH key pair whose public half you will have registered 
with Farsight for SRA use, similar to:

~~~
Host *.sie-remote.net
    IdentityFile ~/.ssh/id_rsa_xyz
~~~

## Building and installing AXA

AXA can built manually or, on Debian systems, installed by using pre-built 
packages.

### Building manually

The `axa` suite has the following external dependencies:

 * C compiler (gcc or llvm)
 * [nmsg](https://github.com/farsightsec/nmsg)
 * [wdns](https://github.com/farsightsec/wdns)
 * [libedit](http://thrysoee.dk/editline/)
 * [libbsd](http://libbsd.freedesktop.org/wiki/) (should already be installed on BSDish systems)
 * Nimble fingers

After satisfying the above, build with something like:

`./autogen.sh` followed by `./configure` and `make`

Finally, to give the `axa` suite a home, `sudo make install`.

### Debian package install

On Debian systesm, the following packages should be installed:

 * `pkg-config`
 * `libpcap0.8-dev`
 * `zlib1g-dev`
 * `libbsd-dev`
 * `libedit-dev`
 * `libprotobuf-c0-dev`
 * `protobuf-c-compiler`
 * `libwdns-dev (>= 0.5)`
 * `libnmsg-dev (>= 0.8.0)`
 * `nmsg-msg-module-sie-dev (>= 0.16)`

The binary packages of AXA and its dependencies are available from 
[a Debian package repository maintained by Farsight Security](https://archive.farsightsecurity.com/SIE_Software_Installation_Debian/). These packages should be
used instead of building from source on Debian-based systems.

## Tool examples

So let's have a peek at a few examples of how to use `sratool` and `sratunnel`.
For all examples below, all user commands are prefaced with the `>` character.

### 1. Show me five packets

Here's a simple example using `sratool` to grab the first five packets seen on 
SIE channel 212 (Newly Observed Domains):

~~~
$ sratool
> connect ssh:sra-service@sra-eft.sie-remote.net
* HELLO srad version 0.2.3 AXA protocol 1
> count 5
> channel 212 on
* OK CHANNEL ON/OFF channel ch212 on
> 10 watch ch=212
10 OK WATCH started
10 ch212  SIE newdomain 
 fleurverhaar.nl/NS: fleurverhaar.nl
10 ch212  SIE newdomain 
 nr48a.tk/A: nr48a.tk
10 ch212  SIE newdomain 
 gphome.care/NS: gphome.care
10 ch212  SIE newdomain 
 lazyfilly.com/NS: lazyfilly.com
10 ch212  SIE newdomain 
 eovs3.tk/A: eovs3.tk
packet count limit exceeded
> quit
~~~

 1. `> connect ssh:sra-service@sra-eft.sie-remote.net`: we connected to 
Farsight's SRA server using the SSH transport. SSH used its keyring to prove 
the user's identity, so there was no 'password:' prompt. The `HELLO` response
from the remote end tells us its version number and the protocol level. 
 2. `> count 5`: we asked our `sratool` client to stop after five messages are 
output. 
 3. `> channel 212 on`: we then asked the remote end to listen to SIE channel 
212 which was `OK`'d by the server indicating that we are allowed to see this 
channel according to our authentication and authorization level. 
 4. `> 10 watch ch=212`: we then asked to watch all content on channel 212
(with no rate limiting or filtering), which is a common choice for 212 since 
its volume is low.

### 2. In-line subcommanding and rate-limting

Next, we introduce in-line connections and show rate limiting of SIE channel
204 (filtered passive DNS RRsets):

~~~
$ sratool 'connect ssh:sra-service@sra-eft.sie-remote.net'
* HELLO srad version 0.2.3 AXA protocol 1
> count 5
> limit 1
RATE LIMITS
    1 per second; current value=0
    10 seconds between reports
> channel 204 on
* OK CHANNEL ON/OFF channel ch204 on
> 10 watch ch=204
10 OK WATCH started
10 ch204  SIE dnsdedupe   EXPIRATION
  rdata=NS ns1.indoortenniscourt.com  rrname=indoortenniscourt.com
* MISSED
    lost 0 input packets, dropped 0 for congestion,
    28201 for per sec limit, 0 for per day limit
    since 2014/08/22 15:35:39
10 ch204  SIE dnsdedupe   EXPIRATION
  rdata=RRSIG  rrname=ga1qqse3dffik8o2no4j7ppvutfniig1.org
10 ch204  SIE dnsdedupe   INSERTION
  response_ip=194.146.106.74  rdata=NS ns1.fleish.com  rrname=fleishman.co.za
10 ch204  SIE dnsdedupe   EXPIRATION
  rdata=CNAME whatthefuckistheweatherlike.com  rrname=www.whatthefuckistheweatherlike.com
10 ch204  SIE dnsdedupe   INSERTION
  response_ip=2001:503:231d::2:30  rdata=NS ns17.worldnic.com  rrname=wizardwig.com
packet count limit exceeded
> quit
~~~

1. `sratool 'connect ssh:sra-service@sra-eft.sie-remote.net': `we put our 
first `sratool` subcommand on the command line of `sratool` itself. This is a 
shortcut that allows the first subcommand to come from the command line, while 
subsequent subdomains wil come from the control terminal. 
2. `> count 5`: we again asked for a limit of five total records 
3. `> limit 1`: this time we asked the remote end to limit our output to one 
mesage per second. 
4. `> channel 204 on`: as before, switch on channel 204
5. `> 10 watch ch=204`: as before, watch channel 204
6. `MISSED`: We then saw one message from channel 204, followed immediately 
by a loss marker showing that about twenty eight thousand (28,201) messages 
could not be sent to us because of our ratelimits. Note that loses due to rate 
limits are counted independently from losses due to congestion. After four 
more messages containing channel 204 data, our packet count limit was reached, 
and we terminated `sratool`.

### 3. sratunnel+nmsgtool

Here we introduce `sratunnel` and send some packets to a local endpoint and
view them with `nmsgtool` and watch packet flow via `tcpdump`.

First let's invoke `sratunnel`:

~~~
$ sratunnel -s 'ssh sra-service@sra-eft.sie-remote.net' -c ch212 -w 'ch=212' \
    -o nmsg:127.0.0.1,5000 &
[2]+ sratunel ...
~~~

Next let's have a look what this looks like using `tcpdump`:

~~~
# tcpdump -n -c 3 -i lo udp port 5000
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 65535 bytes
15:28:25.835048 IP 127.0.0.1.52459 > 127.0.0.1.5000: UDP, length 143
15:28:26.100146 IP 127.0.0.1.52459 > 127.0.0.1.5000: UDP, length 259
15:28:26.257624 IP 127.0.0.1.52459 > 127.0.0.1.5000: UDP, length 161
3 packets captured
6 packets received by filter
0 packets dropped by kernel
~~~

Yup, traffic is flowing. We can use `nmsgtool` to receive and de-encapsulate 
the data. Here we invoke it to capture three payloads:

~~~
$ nmsgtool -V SIE -T newdomain -l 127.0.0.1/5000 -c 3
[198] [2014-08-22 22:26:44.589695930] [2:5 SIE newdomain] [a1ba02cf] [] [] 
domain: scottbedard.net.
time_seen: 2014-08-22 22:24:11
rrname: scottbedard.net.
rrclass: IN (1)
rrtype: NS (2)
rdata: dns1.registrar-servers.com.
rdata: dns2.registrar-servers.com.
rdata: dns3.registrar-servers.com.
rdata: dns4.registrar-servers.com.
rdata: dns5.registrar-servers.com.

[89] [2014-08-22 22:26:47.515605926] [2:5 SIE newdomain] [a1ba02cf] [] [] 
domain: pastapizza.ch.
time_seen: 2014-08-22 22:23:59
rrname: pastapizza.ch.
rrclass: IN (1)
rrtype: NS (2)
rdata: dns1.mhs.ch.
rdata: dns2.mhs.ch.
rdata: dns3.mhs.ch.

[46] [2014-08-22 22:26:49.197557926] [2:5 SIE newdomain] [a1ba02cf] [] [] 
domain: alpa9.tk.
time_seen: 2014-08-22 22:24:53
rrname: alpa9.tk.
rrclass: IN (1)
rrtype: A (1)
rdata: 195.20.34.1
rdata: 195.20.34.2

$ kill %sratunnel
[2]- Exit 15 sratunnel ...
~~~

1. `sratunnel -s 'ssh sra-service@sra-eft.sie-remote.net' -c ch212 -w 'ch=212' 
-o nmsg:127.0.0.1,5000 &`: here, we started a background process to access 
remote SIE channel 212, and to deposit all received mesages in NMSG format 
using UDP on a local socket (host 127.0.0.1, port 5000). As before, no IP 
address or DNS name filters were used, since channel 212 is known to be very 
low volume. 
2. `tcpdump -n -c 3 -i lo udp port 5000`: we then used the tcpdump command to 
show that packets were being received on the local socket. 
3. `nmsgtool -V SIE -T newdomain -l 127.0.0.1/5000 -c 3`: We ran `nmsgtool`, 
specifying our input with the `-V`, `-T`, and `-l` options since the `nmsgtool` 
shortcut for channel notation (`-C`) only works for directly conected SIE 
clients. `nmsgtool` displayed three messages and exited. We then killed the 
background `sratunnel` process, concluding the demo.


## API Workflow

TODO.

## AXA Protocol

The AXA protocol is above a reliable stream protocol such as TCP and so has no 
provisions to detect or recover from duplicate, out-of-order, lost, or 
partially lost data. AXA data can be lost before encapsulation in AXA protocol 
messages or packets.

For most uses, a protocol such as ssh is used below the AXA layer and above TCP
to provide authentication, confidentiality, and integrity.

The AXA protocol consists of a pair of streams of messages between a "client" 
such as `sratool` and an AXA server, one stream in each direction, often 
ultimately over a single TCP connection.

The authoritative definition of the protocol starts with the 
`axalib/protocol.h` file. This document is merely an informal supplement to 
`protocol.h`.

Values that originate in SRA or RAD servers such as message lengths use little 
endian byte order in the AXA protocol. Other values such as IP addresses and 
port numbers are big endian for consistency with their sources such as host 
tables. SRA and RAD data such as nmsg messages and IP packets have their 
original byte orders.

The stream protocols below the AXA protocol are responsible for authentication 
and authorization. An AXA client and server pair on a computer can use 
unadorned TCP through the loop-back interface or use a UNIX domain socket. 
The AXA protocol assumes this is safe.

Between separate computers, the AXA protocol can use UNIX pipes to the stdin 
and stdout streams provided by the `ssh` command or the functions of an ssh 
library such as `libssh2`. Ssh must identify and authenticate the client and 
server to each other.

The AXA client starts by waiting for an `AXA_P_OP_HELLO` message from the 
server. Over a local stream, the client then sends an `AXA_P_OP_USER` message 
to tell the server which parameters to use. When `ssh` is used, the user name 
is provided by the ssh protocol.

### AXA message header

Every AXA message starts with a fixed size header:

~~~c
    typedef struct
    {
        uint32_t      len;
        axa_tag_t     tag;
        axa_p_pvers_t pvers;
        uint8_t       op;
    } axa_p_hdr_t;
~~~

 * `len`: The entire length of the AXA message including the header. Many AXA 
messages are variable length.
 * `tag`: A tag is a 16-bit identifier used to uniquely "tag" specific events 
during the lifetime of an AXA session. To refer to these events, the client or
server will use the tag. Some AXA messages do not require tags, in that case
the tag field should be `0`. Required tags must be unique during the lifetime 
of the corresponding client request. Some client requests such as a "watch" can
last indefinitely and will elicit many server responses all with the same tag.
 * `pvers`: A one-byte protocol version number that allows AXA clients and 
servers of different ages to find a mutually compatible version of the AXA 
protocol.
 * `op`: The op (opcode) specifies an operation requested by the client, a 
response from the server, or data from the server. The universe of opcodes is
discussed below.

For a detailed dicussions of the AXA protocol message types, see the doxygen
generated page for `protocol.h`

### AXA protocol specification quick reference

The following is an AXA protocol quick reference chart intended for application
developers building `axalib` programs.

 * OPCODE: The canonical name of the operation code as defined by 
`axalib/protocol.h`
 * VAL: The numerical value of the opcode.
 * SENT BY: Who can send the message
 * TAG: Boolean value indidcating if header tag is valid, as described above
 * DESCRIPTION: Short blurb describing opcode

| OPCODE              | VAL | SENT BY         | TAG   | DESCRIPTION            |
| ------------------- |----:|----------------:| -----:|----------------------------------------------------------------------------------------------:|
| `AXA_P_OP_NOP`      | 0   | CLIENT / SERVER | NO    | carries no data, is intended only to ensure that the TCP connection is still up               |
| `AXA_P_OP_HELLO`    | 1   | SERVER          | NO    | helps the client choose a compatible AXA protocol version                                     |
| `AXA_P_OP_OK`       | 2   | SERVER          | YES   | indicates the success of preceeding client request referenced by tag                          |
| `AXA_P_OP_ERROR`    | 3   | SERVER          | YES   | indicates the failure of preceeding client request referenced by tag                          |
| `AXA_P_OP_MISSED`   | 4   | SERVER          | NO    | carries details about data or packet loss due to rate limiting or network congestion          |
| `AXA_P_OP_WHIT`     | 5   | SERVER          | YES   | reports a "watch hit" or packet or nmsg message that matched an SRA watch referenced by tag   |
| `AXA_P_OP_WLIST`    | 6   | SERVER          | YES   | reports a current watch in response to `AXA_P_OP_WGET` from the client referenced by tag      |
| `AXA_P_OP_AHIT`     | 7   | CLIENT          | NO    | used by RAD client                                                                            |
| `AXA_P_OP_ALIST`    | 8   | CLIENT          | YES   | used by RAD client                                                                            |
| `AXA_P_OP_CLIST`    | 9   | SERVER          | NO    | reports the on/off state and specification of an SRA channel                                  |
| `AXA_P_OP_USER`     | 129 | CLIENT          | NO    | indicates the AXA protocol is used over a local stream and rejected otherwise                 |
| `AXA_P_OP_JOIN`     | 130 | CLIENT          | NO    | indicates bundling TCP connections                                                            |
| `AXA_P_OP_PAUSE`    | 131 | CLIENT          | NO    | ask the server to temporarily stop sending packets or nmsg messages                           |
| `AXA_P_OP_GO`       | 132 | CLIENT          | NO    | ask the server to resume sending packets or nmsg messages                                     |
| `AXA_P_OP_WATCH`    | 133 | CLIENT          | NO    | specify interesting packets or nmsg messages                                                  |
| `AXA_P_OP_WGET`     | 134 | SERVER (RAD)    | NO    | requests one or all current watches in `AXA_P_OP_WLIST` messages                              |
| `AXA_P_OP_ANOM`     | 135 | SERVER (SRA)    | NO    | used by RAD servers talking to SRA servers                                                    |
| `AXA_P_OP_AGET`     | 136 | SERVER          | NO    | used by RAD servers talking to SRA servers                                                    |
| `AXA_P_OP_STOP`     | 137 | CLIENT          | NO    | ask the SRA server to delete the watch referenced by tag                                      |
| `AXA_P_OP_ALL_STOP` | 138 | CLIENT          | NO    | ask the SRA server to delete all watches                                                      |
| `AXA_P_OP_CHANNEL`  | 139 | CLIENT          | NO    | tell the SRA server to enable or disable one channel or all channels                          |
| `AXA_P_OP_CGET`     | 140 | CLIENT          | NO    | get the specification and state of all channels                                               |
| `AXA_P_OP_OPT`      | 141 | CLIENT / SERVER | NO    | set various options (rate limiting) report rate limits, how much has been used                |
| `AXA_P_OP_ACCT`     | 142 | CLIENT / SERVER | NO    | request accounting information                                                                |

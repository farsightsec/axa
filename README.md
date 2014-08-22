# AXA (Advanced Exchange Access)
-------------------------------
The purpose of SRA is to make the capabilties of Farsight Security Information 
Exchange (SIE) available within a subscriber's network rather than requirng a 
direct connection to Farsight SIE. The SRA service is delivered via Farsight's
Advanced Exchange Aces (AXA) protocol which allows SRA session initators to 
select SIE chanels, to specify search paterns, and to control rate limits and 
other AXA session level parameters. After SRA session paramaters have been 
established, SIE data is encrypted and streamed to the SRA subscriber via 
TCP/IP, using an SSH transport (similar to rsync or git).

The following tools are available to Farsight customers that subscribe to one
or more SRA channels:

* `libaxa`: middleware for AXA protocol including connection and 
encapsulation/decapsulation
* `sratunnel`: by which remote SIE data is made to appear on a local socket
* `sratool`: a debuging interface capable of exercising and examining AXA

The `sratunnel` source code is intended as a working example of caling 
`libaxa` to set up an SRA session, turn on an SIE channel, set a single and 
simple filter, receive remote data over AXA, and decapsulate that data. SRA 
application developers can use the `sratunnel` source code as a template for 
other SRA aps, or get a quicker start by running the `sratunnel` program which 
wil make the remote data available locally, and then run a PCAP (for SIE 
channel 14) or NMSG (for all other SIE channels) program exactly as they would 
on an analysis server directly conected to SIE itself. 

Of note, SRA can perform filtering at the initator's request. This is due to 
the high volume of data caried by SIE, bursting to hundreds of megabits per 
second in a single channel. It's expected that when using SRA to access low 
volume channels, entire channels will be selected for remote distribution. 
However, when remotely accessing high volume SIE channels, it is expected that 
the subscriber will specify a list of IP addresses and DNS names of interest, 
so that the SRA server can filter out everything else, and send to the 
subscriber only a small subset of that channel's data.

Also of note, AXA is a deliberately lossy protocol. If a subscriber requests 
more data volume than the network can carry, data overruns wil occurr. When 
this hapens, "loss markers" will be transmitted reliably within the AXA stream 
to inform the subscriber of their losses. The subscriber's possible mitgation 
strategies at that point are to ask for less data, or increase their network 
capacity, or to treat the SRA stream as a chunky and non-representative sample 
of the underlying SIE channel data. 

The `sratool` program is intended primarily as a protocol demonstration and 
debuging interface, although it can also perform the same functions as 
`sratunnel`. The source code for the `sratool` program and the `libaxa` library
 presently constitute the authoritative documentation of the AXA protocol. 
Farsight advises SRA subscribers to utilize the `libaxa` library for session 
management and data decapsulation rather than crafting hand drawn logic to 
perform these functions. A later version of the AXA software is expected to 
include Python and Perl language bindings.


This manual covers version `0.2.4`.

## SRA Server
-------------
As of the time of this writing, the SRA service answers at he following address
via the SSH transport:

`sra-service@sra-eft.sie-remote.net`

Note, you will need to create or edit your ~/.ssh/config file to specify the 
private half of the SSH key pair whose public half you will have registered 
with Farsight for SRA use, similar to:

```
Host *.sie-remote.net
    IdentityFile ~/.ssh/id_rsa_xyz
```

## Building
-----------
`axa` has the following external dependencies:

* C compiler (gcc or llvm seem to work wonderfully)
* [nmsg](https://github.com/farsightsec/nmsg)
* [wdns](https://github.com/farsightsec/wdns)
* Nimble fingers

After satisfying the above, to build, try something like:

`./autogen.sh` followed by `./configure` and then a nice `make` 

Finally, to give `axa` a home, `sudo make install`

## Testing with sratool
-----------------------
What follows are a few examples of how to use `sratool`.

### Show me five packets
------------------------
Here's a simple example using `sratool` to grab the first five packets seen on 
SIE channel 212 (Newly Observed Domains):

```
$ sratool
> connect ssh sra-service@sra-eft.sie-remote.net
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

```

Discussion: here we connected to Farsight's SRA server using the SSH transport.
SSH used its key ring to prove the user's identity, so there was no 'password:'
prompt. In `HELLO`, the remote end tells us its version number and the 
protocol level. We asked our `sratool` client to stop after five messages are 
output. We then asked the remote end to listen to SIE channel 212 which was 
`OK`'d by the server indicating that we are allowed to see this channel 
according to our authentication and authorization level. We then asked to 
watch all content on channel 212, which is a common choice for channel 212 
since its volume is low.

### In-line subcommanding and rate-limting
------------------------------------------
Next, we introduce in-line connections and show rate limiting of SIE channel
204 (filtered passive DNS RRsets):

```
$ ./sratool 'connect ssh sra-service@sra-eft.sie-remote.net'
* HELLO srad version 0.2.3 AXA protocol 1
> count 5
> limit 1
RATE LIMITS
    1 per second; current value=0
    unlimited per day; current value=0
    10 seconds between reports
> channel 204 on
* OK CHANNEL ON/OFF channel ch204 on
> 10 watch ch=204
10 OK WATCH started
10 ch204  SIE dnsdedupe   EXPIRATION
  rdata=NS ns1.indoortenniscourt.com  rrname=indoortenniscourt.com
* MISSED
    lost 0input packets, dropped 0for congestion,
    28201for per sec limit, 0for per day limit
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
```

Discussion: here, we put our first `sratool` subcommand on the command line of 
`sratool` itself. This is a shortcut that allows the first subcommand to come 
from the command line, while subsequent subdomains wil come from the control
terminal. We again asked for a limit of 5 total records and then we asked the
remote end to limit our output to one mesage per second. We then saw one 
message from channel 204, followed immediately by a loss marker showing that 
about nine thousand (9065) messages could not be sent to us because of our rate
limits. Note that loses due to rate limits are counted independently from 
losses due to congestion. After four more messages containing channel 204 data,
our packet count limit was reached, and we terminated `sratool`.


## Testing with sratunnel
-----------------------
What follows are a few examples of how to use `sratunnel`.

### Introducing sratunnel, showing tcpdump and nmsgtool access:
---------------------------------------------------------------
Here we introduce `sratunnel` and watch packet flow via `tcpdump`.

First let's instaniate `sratunnel`:
```
$ sratunnel -s 'ssh sra-service@sra-eft.sie-remote.net' -c ch212 -w 'ch=212' \
    -o nmsg:127.0.0.1,5000 &
[2]+ sratunel ...
```
Next let's have a look what this looks like using `tcpdump`:
```
# tcpdump -n -c 3 -i lo udp port 5000
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 65535 bytes
15:28:25.835048 IP 127.0.0.1.52459 > 127.0.0.1.5000: UDP, length 143
15:28:26.100146 IP 127.0.0.1.52459 > 127.0.0.1.5000: UDP, length 259
15:28:26.257624 IP 127.0.0.1.52459 > 127.0.0.1.5000: UDP, length 161
3 packets captured
6 packets received by filter
0 packets dropped by kernel
```

```
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
```
Discussion: here, we started a background process to access remote SIE channel 
212, and to deposit all received mesages in NMSG format using UDP on a local 
socket (host 127.0.0.1, port 5000). As before, no IP address or DNS name
filters were used, since channel 212 is known to be very low volume. We then 
used the tcpdump command to show that packets were being received on the local 
socket. We ran nmsgtool, specifying our input with the -V, -T, and –l options
since the nmsgtool shortcut for channel notation (-C) only works for directly 
conected SIE clients. nmsgtool displayed three mesages and exited. We then 
killed the background `sratunnel` process, concluding the demo.

## API Workflow
--------------
TODO.

## API Reference
---------------
...doxygen...

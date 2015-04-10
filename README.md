# Farsight Advanced Exchange Access Toolkit

The purpose of Farsight's Advanced Exchange Access (AXA) toolkit is to bring
the capabilities of the Farsight Security Information Exchange (SIE) right to
the subscriber's network edge rather than requiring a direct connection to the
SIE. 

The Farsight AXA toolkit contains tools and C-based library code used to connect
to Farsight's SRA (SIE Remote Access) and RAD (Realtime Anomaly Detector)
servers.

SRA and RAD services are delivered via Farsight's AXA protocol which allows
session initiators to control a number of parameters including:

 * select and deselect SIE channels (SRA)
 * specify DNS and IP address watch patterns (SRA and RAD)
 * control packet rate limits, packet counts, sampling rate, and window sizes
 * set anomaly watches and specify anomaly modules (RAD)

The following tools are provided to Farsight customers that subscribe to one
or more SIE channels:

 * `sratool`: A command line tool used to connect to an SRA server, send AXA
    protocol messages and stream responses.
 * `radtool`: A command line tool used to connect to a RAD server, set anomaly
    watches, and stream responses.
 * `sratunnel`: SRA Tunnel. A tool that copies remote SIE data to the local
    network.
 * `radtunnel`: RAD Tunnel. A tool that copies RAD data to the local network.
 * `libaxa`: C API middleware for the AXA protocol including connection and 
    encapsulation/decapsulation

The `sratool` program is the reference implementation of the AXA protocol. It is
intended primarily as a protocol demonstration and debugging interface, although
it can also perform some of the same functions as `sratunnel`.

The `sratunnel` source code is intended as a working example of calling 
`libaxa` to set up an SRA session, turn on an SIE channel, set a single and 
simple filter, receive remote data over AXA, and decapsulate that data. SRA 
application developers can use the `sratunnel` source code as a template for 
other SRA applications, or get a quicker start by running the `sratunnel` 
program which will make the remote data available locally, and then use 
[`pcap`](http://www.tcpdump.org/) (for SIE channel 14) or 
[`nmsg`](https://github.com/farsightsec/nmsg) (for all other SIE channels) 
as they would on an analysis server directly connected to SIE itself. An
example of how to do this is included later in this document.

The `radtool` and `radtunnel` programs are used to stream RAD watch hits from a
remote RAD server to the local network. They actually share code bases with
their "sra-" counterparts and the program logic is such that it detects its
filename and invokes itself in RAD mode. 

## SRA Filtering

Of note, SRA can perform filtering. This feature is highly desirable due to the
very high volume of data carried by SIE which can burst to hundreds of megabits
per second in a single channel. On the flip side, when using SRA to access low 
volume channels, entire channels can be selected for remote distribution.
However, when remotely accessing high volume SIE channels, the subscriber
usually specifies a list of IP addresses and DNS names of interest, so that the
SRA server can filter out everything else, and send to the subscriber only a
subset of that channel's SIE data.

Also of note, AXA is a deliberately lossy protocol. If a subscriber requests 
more data than the network can carry, data overruns will occur. When 
this happens, "loss markers" are transmitted reliably within the AXA stream 
to inform the subscriber. At this point, the subscriber's possible mitigation 
strategies include:

 * ask for less data,
 * increase their network capacity, or 
 * treat the SRA stream as a chunky and non-representative sample of the 
    total SIE data. 

The distributed AXA package constitutes the authoritative documentation of the
AXA protocol. Farsight advises SRA subscribers needing custom functionality not
provided in `sratool`, `sratunnel`, `radtool`, or `radtunnel` to utilize the
`libaxa` library for session management and data decapsulation rather than
crafting hand drawn logic to perform these functions.

A later version of the AXA software will include Python language bindings.

For specific details on `sratool`, `radtool`, `sratunnel`, and `radtunnel`,
please see the respective man pages included in the distribution.

## Building and Installing AXA
AXA can built manually or, on Debian systems, installed by using pre-built 
packages.

### Building manually
The AXA suite has the following external dependencies:

 * C compiler (gcc or llvm)
 * [libpcap](http://www.tcpdump.org/)
 * [zlib](http://www.zlib.net/)
 * [nmsg](https://github.com/farsightsec/nmsg) (probably will want to configure
    with `--without-libxs`)
 * [protobuf-c](https://github.com/protobuf-c/protobuf-c) (be sure to use 2.x.x)
 * [sie-nmsg](https://github.com/farsightsec/sie-nmsg)
 * [wdns](https://github.com/farsightsec/wdns)
 * [libedit](http://thrysoee.dk/editline/)
 * [libbsd](http://libbsd.freedesktop.org/wiki/) (should already be installed
    on BSDish systems)
 * [libssl](http://openssl.org/)

Optional dependency:

 * [doxygen](http://www.stack.nl/~dimitri/doxygen/) (version 1.8.3 or newer
    that supports inlining markdown files)
    
After satisfying the above, build with something like:

`./autogen.sh` followed by `./configure` and `make`

To generate the API documentation (including an HTMLized version of this
document): `./make doc`. The html documentation will be in `doc/doxygen/html`
and can be rendered in any modern browser. Something like
`$ open html/index.html` should get you started.

Finally, to give the AXA suite a home, `sudo make install`.

### Debian package install
On Debian systems, the following packages should be installed:

 * `pkg-config`
 * `libpcap0.8-dev`
 * `zlib1g-dev`
 * `libbsd-dev`
 * `libedit-dev`
 * `libprotobuf-c0-dev (>= 1.0.1)`
 * `protobuf-c-compiler`
 * `libwdns-dev (>= 0.6.0)`
 * `libnmsg-dev (>= 0.9.1)`
 * `nmsg-msg-module-sie-dev (>= 1.0.0)`

The binary packages of AXA and its dependencies are available from 
[a Debian package repository maintained by Farsight Security](https://archive.farsightsecurity.com/SIE_Software_Installation_Debian/). These packages should be
used instead of building from source on Debian-based systems.

On a clean Debian install, the following brings in everything "external"
that is needed:

~~~
$ apt-get install build-essential autoconf libpcap-dev      \
                  zlib1g-dev libedit-dev libbsd-dev libtool \
                  libssl-dev pkg-config curl unzip
~~~

`unzip` is needed if you download the "zip" of the git repos and `curl` is
needed during the build of `protobuf`.

## SRA and RAD Server Encrypted Transport
After SRA and/or RAD session parameters have been established, SIE data is
encrypted and streamed to the SRA subscriber using either an SSH transport
(similar to applications like [rsync](http://troy.jdmz.net/rsync/) or
[git](http://git-scm.com/book/en/Git-on-the-Server-Setting-Up-the-Server) or
using TLS).

While both transports offer comparable encryption and compression, Farsight
recommends using TLS over SSH. On most systems, TLS performance should be
faster as it doesn't have to deal with piping data to or from the SSH server
process.

Before either method can be used, you first need to generate new
authentication keys and submit the public half to Farsight Security. 

### Setting up AXA SSH
As of the time of this writing, the SRA and RAD servers answer at the following 
addresses via the SSH transport:

 * **SRA**: `sra-service@sra.sie-remote.net`
 * **RAD**: `rad-service@rad.sie-remote.net`

Incoming SRA or RAD connections are handled on TCP port 22 by the SSH server.

To setup SSH access for SRA and/or RAD, you need to do the following:

 1. Generate a new SSH authentication key pair with `ssh-keygen`:

        $ ssh-keygen -t rsa -b 4096
        Generating public/private rsa key pair.
        Enter file in which to save the key (/home/user/.ssh/id_rsa):
        /home/user/.ssh/farsight-axa-id_rsa
        ...

 2. You will need to create or edit your `~/.ssh/config` file to specify the
    private half of the SSH key pair for the SRA and RAD servers:

        Host sra.sie-remote.net rad.sie-remote.net
            IdentityFile ~/.ssh/farsight-axa-id_rsa

 3. Email your public key (`~/.ssh/farsight-axa-id_rsa.pub`) to your Farsight
    Security account manager. DO NOT EVER SHARE YOUR PRIVATE KEY
    (`~/.ssh/farsight-axa-id_rsa`). This is the private half of your generated
    key pair that you should keep safe. As soon as your account is provisioned
    you will receive notification from Farsight Security.

### Setting up AXA TLS
As of the time of this writing, the SRA and RAD servers answer at the following 
addresses via the TLS transport:

 * **SRA**: sra.sie-remote.net,443
 * **RAD**: rad.sie-remote.net,80

The TCP port numbers 443 and 80 were chosen simply because of their ubiquity
in being let through firewalls.

To setup TLS access for SRA and/or RAD, you need to do the following:

 1. Install axa-tools (as per above). Installed alongside the AXA tools are
    three TLS helper scripts:
   * axa_make_cert: Generate AXA certificate and private key files
   * axa_server_cert: Retrieve the AXA server certificate fingerprint
   * axa_link_certs: Create AXA certificate links
 2. Generate and install the AXA user TLS certificates. This needs to be done
    as root because the install script copies the files to the AXA certs
    directory:

        # axa_make_cert -u username
        Create /usr/local/etc/axa/certs? y
        Generating a 2048 bit RSA private key
        ............+++
        .............+++
        writing new private key to 'username.key'
        -----

 3. Chown the private key to the user who will be running the AXA tools:

        # chown user. /usr/local/etc/axa/certs/username.key

 4. Retrieve and install the AXA server certificate. This is the equivalent of
    when you SSH to a new host for the first time and receive the "Are you
    sure you want to continue connecting (yes/no)?" message. This can be done
    bu connecting to either SRA or RAD since they both share the same TLS
    certificate:

        # axa_server_cert -s sra.sie-remote.net,443
        Obtained certificate for "farsight" with
        SHA1 Fingerprint=2D:0C:92:23:B9:6F:70:E7:F3:E3:7A:2B:D6:F5:D4:CA:1F:F8:CE:71
        Install it in /usr/local/etc/axa/certs/farsight.pem? yes

 5. Create AXA certificate links:

        # axa_link_certs
        Making new links in /usr/local/etc/axa/certs/

 6. Email your public certificate (`username.pem`) to your Farsight Security
    account manager. DO NOT EVER SHARE YOUR PRIVATE KEY (`username.key`).
    This is the private half of your generate key pair that you should
    keep safe. As soon as your account is provisioned you will receive
    notification from Farsight Security.

## AXA examples
The following are a few examples of how to use `sratool`, `sratunnel` and
`radtool`. For the interactive tools `sratool` and `radtool`, all user
commands are prefaced with `sra> ` or `rad> ` prompts.

### 1. Stream SIE traffic with sratool
Here's a simple example using `sratool` to grab the first five packets seen on 
SIE channel 212 (Newly Observed Domains):

~~~
$ sratool 
sra> connect ssh:sra-service@sra-eft.sie-remote.net
* HELLO srad version 1.1.0 sb6 AXA protocol 1
sra> count 5
sra> channel 212 on
* OK CHANNEL ON/OFF channel ch212 on
sra> 1 watch ch=212
1 OK WATCH started
1 ch212  SIE newdomain 
 shared-living.co/CNAME: shared-living.co
1 ch212  SIE newdomain 
 sb9b8.tk/A: sb9b8.tk
1 ch212  SIE newdomain 
 lipator.gq/NS: lipator.gq
1 ch212  SIE newdomain 
 feliksspibefolam.tk/A: feliksspibefolam.tk
1 ch212  SIE newdomain 
 cod4fightclub.tk/A: cod4fightclub.tk

packet count limit exceeded
sra> exit
~~~

 1. `sra> connect ssh:sra-service@sra-eft.sie-remote.net`: we connected to 
    an SRA server using the SSH transport. SSH used its keyring to prove 
    the user's identity, so there was no 'password:' prompt. The `HELLO`
    response from the remote end tells us its version number and the protocol
    level. 
 2. `sra> count 5`: we asked our `sratool` client to stop after five messages
    are output. 
 3. `sra> channel 212 on`: we then asked the remote end to listen to SIE
    channel 212 which was `OK`'d by the server indicating that we are
    provisioned for this channel according to our authentication and
    authorization level. 
 4. `sra> 1 watch ch=212`: we then asked to watch all content on channel 212
    (with no rate limiting or filtering), which is a common choice for 212
    since its volume is low.

### 2. In-line sub-commanding and rate-limiting with sratool
Next, we introduce in-line connections and show rate limiting of SIE channel
204 (filtered passive DNS RRsets):

~~~
$ sratool 'connect sra-service@sra-eft.sie-remote.net'
* HELLO srad version 1.1.0 sb6 AXA protocol 1
sra> count 5
sra> limit 1 5
* OPTION Rate LIMIT
    1 per second; current value=0
    5 seconds between reports
sra> channel 204 on
* OK CHANNEL ON/OFF channel ch204 on
sra> 1 watch ch=204
1 OK WATCH started
1 ch204  SIE dnsdedupe   INSERTION
  response_ip=84.53.139.129  rdata=A 65.55.223.29  rrname=dsn14.skype-dsn.akadns.net
* MISSED
    missed 0 input packets, dropped 0 for congestion,
    dropped 2299 for rate limit, filtered 69817
    since 2015/04/05 15:49:31
1 ch204  SIE dnsdedupe   EXPIRATION
  rdata=A 173.248.142.165  rrname=www.madivorceonline.com
1 ch204  SIE dnsdedupe   EXPIRATION
  rdata=A 127.0.0.1  rrname=rrihvmppyth.www.money238.com
1 ch204  SIE dnsdedupe   EXPIRATION
  rdata=RRSIG  rrname=o3bssvid9kejcvcd83oc7n2g546ol44t.pt
1 ch204  SIE dnsdedupe   EXPIRATION
  rdata=A 127.0.0.1  rrname=bfskbyb.www.money238.com
* MISSED
    missed 0 input packets, dropped 0 for congestion,
    dropped 32002 for rate limit, filtered 32006
    since 2015/04/05 15:49:35

packet count limit exceeded
sra> exit
~~~

 1. `sratool 'connect sra-service@sra-eft.sie-remote.net':` we put our
    first `sratool` subcommand on the command line of `sratool` itself. This is
    a shortcut that allows the first subcommand to come from the command line, 
    while subsequent subdomains wil come from the control terminal.
 2. `sra> count 5`: we again asked for a limit of five total records
 3. `sra> limit 1 5`: this time we asked the remote end to limit our output to
    one message per second and report every 5 seconds.
 4. `sra> channel 204 on`: as before, switch on channel 204
 5. `sra> 1 watch ch=204`: as before, watch channel 204
 6. `MISSED`: We then saw one message from channel 204, followed immediately
    by a loss marker showing that 2299 messages could not be sent to us because
    of our rate limit. Note that loses due to rate limits are counted
    independently from losses due to congestion. After four more messages
    containing channel 204 data, our packet count limit was reached. We received
    one more rate limit report before terminating `sratool`.

### 3. Tunnel SIE traffic with sratunnel and nmsgtool
Here we introduce `sratunnel` and send some packets to a local endpoint and
view them with `nmsgtool` and watch packet flow via `tcpdump`.

First we invoke `sratunnel`:

~~~
$ sratunnel -s 'ssh sra-service@sra.sie-remote.net' -c ch212 \
-w 'ch=212' -o nmsg:127.0.0.1,5000 &
[2]+ sratunnel ...
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

Indeed, traffic is flowing and we can use `nmsgtool` to receive and
decapsulate the data. Here we invoke it to capture and display three payloads:

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

 1. `sratunnel -s 'ssh sra-service@sra-eft.sie-remote.net' -c ch212 -w 'ch=212' -o nmsg:127.0.0.1,5000 &`:
    here, we started a background process to access remote SIE channel 212, and
    to deposit all received messages in NMSG format using UDP on a local socket
    (host 127.0.0.1, port 5000). As before, no IP address or DNS name filters
    were used, since channel 212 is known to be very low volume. 
 2. `tcpdump -n -c 3 -i lo udp port 5000`: we then used the tcpdump command to
    show that packets were being received on the local socket.
 3. `nmsgtool -V SIE -T newdomain -l 127.0.0.1/5000 -c 3`: We ran `nmsgtool`,
    specifying our input with the `-V`, `-T`, and `-l` options since the
    `nmsgtool` shortcut for channel notation (`-C`) only works for directly
    connected SIE clients. `nmsgtool` displayed three messages and exited. We
    then killed the background `sratunnel` process, concluding the demo.

### 4. Watch for IP anomalies with radtool
Next, `radtool` is used to watch for specified IP addresses in SIE channels. In
the example below, the `ip14-80` anomaly module, which looks for IP packets in
SIE channels 14 (Darknet) and 80 (Conficker Sinkhole) is used. Traffic appearing
in either of these feeds is often considered anomalous and worthy of deeper
investigation.

~~~
rad> connect ssh:rad-service@rad-eft.sie-remote.net
* HELLO radd version 1.1.0 sb6 AXA protocol 1
rad> count 5
rad> 1 watch ip=0.0.0.0/1
1 OK WATCH saved
rad> 1 watch ip=128.0.0.0/1
1 OK WATCH saved
rad> 1 anomaly ip14-80
1 OK ANOMALY anomaly detector started
1 ip14-80 ch80  base http ConfickerAB dstip=216.66.15.109
  srcip=197.199.210.41
1 ip14-80 ch80  base http ConfickerAB dstip=216.66.15.109
  srcip=195.210.191.101
1 ip14-80 ch80  base http ConfickerAB dstip=216.66.15.109
  srcip=195.210.191.101
1 ip14-80 ch80  base http ConfickerAB dstip=216.66.15.109
  srcip=122.176.119.59
1 ip14-80 ch80  base http ConfickerAB dstip=216.66.15.109
  srcip=116.106.33.94

packet count limit exceeded
rad> exit
~~~

 1. `rad> connect ssh:rad-service@rad-eft.sie-remote.net`: we connected to 
    a RAD server using the SSH transport. SSH used its keyring to prove 
    the user's identity, so there was no 'password:' prompt. The `HELLO`
    response from the remote end tells us its version number and the protocol
    level. 
 2. `rad> count 5`: we asked our `radtool` client to stop after five messages
    are output.
 3. `rad> 1 watch ip=0.0.0.0/1`: set a watch for all IP packets matching the
    specified CIDR mask.
 4. `rad> 1 watch ip=128.0.0.0/1`: set a watch for all IP packets matching the
    specified CIDR mask. In combination with the previous watch, all IP packets
    should be matched. In practice, a user would specify IP watches specific to
    addresses in his or her organization. Also of note here is the use of the
    same tag for two watches. This is because RAD clients use a common tag to
    group together one or more watches with a single anomaly module instance.
 5. `rad> 1 anomaly ip14-80`: switch on the anomaly detector. This mnemonic
    refers to the `ip_probe(1)` module tuned to watch SIE channels 14 and 80.
    Five watch hits are returned and then we exit.

### 5. Tunnel IP anomalies with radtunnel and nmsgtool
Using `radtunnel` is much the same process as using `sratunnel`. First
invoke `radtunnel` with the same anomaly watches as `radtool`:

~~~
$ radtunnel -s tls:user@rad.sie-remote.net,80 -w ip=0.0.0.0/1 \
-w ip=128.0.0.0/1 -a ip14-80 -o nmsg:127.0.0.1,8000 &
[2]+ radtunnel ...
~~~

Next let's have a look what this looks like on the network using `tcpdump`:

~~~
# tcpdump -n -c 3 -i lo udp port 8000
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 65535 bytes
18:02:44.327721 IP 127.0.0.1.58777 > 127.0.0.1.8000: UDP, length 894
18:02:44.327970 IP 127.0.0.1.58777 > 127.0.0.1.8000: UDP, length 1075
18:02:44.328331 IP 127.0.0.1.58777 > 127.0.0.1.8000: UDP, length 1046
3 packets captured
6 packets received by filter
0 packets dropped by kernel
~~~

We use `nmsgtool` to receive and decapsulate the data. Here we invoke it to
capture and display three payloads:

~~~
$ nmsgtool  -l 127.0.0.1/8000 -c 1
[220] [2015-04-09 18:02:46.472500700] [1:4 base http] [a1ba02cf] [FSI] [ConfickerAB] 
type: sinkhole
srcip: 36.40.81.20
srcport: 2819
dstip: 216.66.15.109
dstport: 80
request:
GET /search?q=24 HTTP/1.1
Via: 1.0 FW-XIY
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)
Host: 216.66.15.109
Pragma: no-cache
Connection: Keep-Alive

.

[301] [2015-04-09 18:02:46.473020506] [1:4 base http] [a1ba02cf] [FSI] [ConfickerAB] 
type: sinkhole
srcip: 95.139.254.67
srcport: 2771
dstip: 216.66.15.109
dstport: 80
request:
GET /search?q=0 HTTP/1.0
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; MRSPUTNIK 2, 4, 1, 328; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)
Host: 216.66.15.109
Pragma: no-cache

.

[158] [2015-04-09 18:02:46.473855844] [1:4 base http] [a1ba02cf] [FSI] [ConfickerAB] 
type: sinkhole
srcip: 178.95.12.160
srcport: 1765
dstip: 216.66.15.109
dstport: 80
request:
GET /search?q=6591 HTTP/1.0
User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)
Host: 216.66.15.109
Pragma: no-cache

.
$ kill %radtunnel
[2]- Exit 15 radtunnel ...
~~~

 1. `radtunnel -s tls:user@rad.sie-remote.net,80 -w ip=0.0.0.0/1 -w ip=128.0.0.0/1 -a ip14-80 -o nmsg:127.0.0.1,8000 &`: here, we started a background process
    to watch for the same IP-based amomalies as the `radtool` example, but this
    time the results will be sent in NMSG format using UDP on a local socket
    (host 127.0.0.1, port 8000).
 2. `tcpdump -n -c 3 -i lo udp port 8000`: we then used the tcpdump command to
    show that packets were being received on the local socket.
 3. `nmsgtool -l 127.0.0.1/8000 -c 3`: We ran `nmsgtool` which output three
    NMSGs, and then killed the background `radtunnel` process.

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
tables. SRA and RAD data such as NMSG messages and IP packets have their 
original byte orders.

The stream protocols below the AXA protocol are responsible for authentication 
and authorization. An AXA client and server pair on a computer can use 
unadorned TCP through the loop-back interface or use a UNIX domain socket. 
The AXA protocol assumes this is safe.

Between separate computers, the AXA protocol can use UNIX pipes to the `stdin` 
and `stdout` streams provided by the ssh command or the functions of an ssh 
library such as `libssh2` (ssh must identify and authenticate the client and 
server to each other) or the TLS library.

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

For a detailed discussions of the AXA protocol message types, see the doxygen
generated page for `protocol.h`

### AXA protocol specification quick reference

The following is an AXA protocol quick reference chart intended for application
developers building `axalib` programs.

 * OPCODE: The canonical name of the operation code as defined by 
`axalib/protocol.h`
 * VAL: The numerical value of the opcode.
 * SENT BY: Who can send the message
 * TAG: Boolean value indicating if header tag must be valid or non-zero,
as described above
 * DESCRIPTION: Short blurb describing opcode

| OPCODE              | VAL | SENT BY         | TAG   | DESCRIPTION            |
| ------------------- |----:|----------------:| -----:|----------------------------------------------------------------------------------------------:|
| `AXA_P_OP_NOP`      | 0   | CLIENT / SERVER | NO    | carries no data, is intended only to ensure that the TCP connection is still up               |
| `AXA_P_OP_HELLO`    | 1   | SERVER          | NO    | helps the client choose a compatible AXA protocol version                                     |
| `AXA_P_OP_OK`       | 2   | SERVER          | YES   | indicates the success of the preceding client request with the same tag                      |
| `AXA_P_OP_ERROR`    | 3   | SERVER          | YES   | indicates the failure of a preceeing client request with the same tag                        |
| `AXA_P_OP_MISSED`   | 4   | SERVER          | NO    | carries details about data or packet loss due to rate limiting or network congestion          |
| `AXA_P_OP_WHIT`     | 5   | SERVER (SRA)    | YES   | reports a "watch hit" or packet or NMSG message that matched an SRA watch with the same tag   |
| `AXA_P_OP_WLIST`    | 6   | SERVER (SRA)    | YES   | reports a current watch in response to `AXA_P_OP_WGET` from the client referenced by tag      |
| `AXA_P_OP_AHIT`     | 7   | SERVER (RAD)    | YES   | reports an "anomaly hit" or packet or NMSG message detected by a set of anomaly detector      |
| `AXA_P_OP_ALIST`    | 8   | SERVER (RAD)    | YES   | reports a current anomaly detector in response to `AXA_P_OP_AGET`                             |
| `AXA_P_OP_CLIST`    | 9   | SERVER (SRA)    | NO    | reports the on/off state and specification of an SRA channel                                  |
| `AXA_P_OP_USER`     | 129 | CLIENT          | NO    | indicates the AXA protocol is used over a local stream and rejected otherwise                 |
| `AXA_P_OP_JOIN`     | 130 | CLIENT          | NO    | used to bundle TCP connections                                                                |
| `AXA_P_OP_PAUSE`    | 131 | CLIENT          | NO    | ask the server to temporarily stop sending packets or NMSG messages                           |
| `AXA_P_OP_GO`       | 132 | CLIENT          | NO    | ask the server to resume sending packets or NMSG messages                                     |
| `AXA_P_OP_WATCH`    | 133 | CLIENT          | NO    | specify interesting packets or NMSG messages                                                  |
| `AXA_P_OP_WGET`     | 134 | SERVER (SRA)    | --    | requests one (with specified tag) or all (tag 0) current watches in `AXA_P_OP_WLIST` messages |
| `AXA_P_OP_ANOM`     | 135 | SERVER (RAD)    | YES   | specify an anomaly detector                                                                   |
| `AXA_P_OP_AGET`     | 136 | SERVER (RAD)    | --    | requests one or all current anomaly detectors                                                 |
| `AXA_P_OP_STOP`     | 137 | CLIENT          | NO    | ask the server to delete the watch or anomaly detector by tag                                 |
| `AXA_P_OP_ALL_STOP` | 138 | CLIENT          | NO    | ask the server to delete all watches or anomaly detectors                                     |
| `AXA_P_OP_CHANNEL`  | 139 | CLIENT (SRA)    | NO    | tell the SRA server to enable or disable one channel or all channels                          |
| `AXA_P_OP_CGET`     | 140 | CLIENT (SRA)    | NO    | get the specifications and states of all channels                                               |
| `AXA_P_OP_OPT`      | 141 | CLIENT / SERVER | NO    | set various options (rate limiting) report rate limits, how much has been used                |
| `AXA_P_OP_ACCT`     | 142 | CLIENT / SERVER | NO    | request accounting information                                                                |

## API Workflow

TODO.

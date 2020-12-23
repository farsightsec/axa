# Farsight Advanced Exchange Access Toolkit
This is the Advanced Exchange Access (AXA) toolkit. It contains tools and a C library to bring Farsight's real-time data and services directly from the [Farsight Security Information Exchange (SIE)](https://www.farsightsecurity.com/solutions/security-information-exchange/) to the subscriber's network edge.

AXA-based solutions are often preferable over procuring a direct, physical connection to the SIE, usually via a co-located blade.

## SRA and RAD
AXA enables subscribers to connect to Farsight's subscription-based SRA (SIE Remote Access) and RAD (Real-time Anomaly Detector) servers.  These servers provide access to data and services built from Farsight's SIE.  SRA streams real-time SIE data while RAD streams real-time anomaly detection data.

## Contents
The axa-tools distribution contains the following:

 * `sratool`: A test/debug/instructional command-line tool used to connect to an SRA server, set watches, enable SIE channels, and stream data.
 * `radtool`: A test/debug/instructional command-line tool used to connect to a RAD server, set watches, enable anomaly detection modules, and stream data.
 * `sratunnel`: A production command-line tool that streams SIE data to the local network.
 * `radtunnel`: A production command-line tool that streams anomaly data to the local network.
 * `libaxa`: A C library providing an API for the AXA protocol including:
  * connection instantiation/teardown,
  * message encapsulation/decapsulation,
  * watch parsing/loading,
  * trie storage and lookup,
  * control packet rate limits, sampling rates, window sizes, and many other AXA-specific functions.

For usage details on `sratool`, `radtool`, `sratunnel`, and `radtunnel`,
please see their respective man pages (included in the distribution).

Note that "AXA" is a bit of an overloaded term. Depending on the context, it can refer to actual AXA wire protocol, the C API, the suite of tools presented here, or even a clustered set of SRA and RAD servers. In this document, when apropos, context is provided in order to disambiguate these situations.

## AXA and High Bitrates
Some of the channels offered by the SIE network burst to an extremely high bitrate (some over 500Mbps). AXA has two ways to deal with such network-hungry situations: optional filtering and loss-tolerance built into the protocol.

Filtering can take one of the following forms:

 * Via the rate limit option to reduce the flow of ingress data to a certain number of packets per second.
 * Via one or more IP-based or DNS-based "watches" to limit the flow of data to specific assets the subscriber wishes to observe.

Finally, AXA is a deliberately lossy protocol. If a subscriber requests
more data than the network can carry, data overruns will occur. When
this happens, loss markers are transmitted reliably within the AXA stream to inform the subscriber via [the AXA accounting subsystem](https://www.farsightsecurity.com/2015/09/24/mschiffm-axa-accounting/). At this point, the subscriber's possible mitigation strategies include:

 * ask for less data via rate limiting,
 * increase their network capacity, or
 * treat the SRA stream as a chunky and non-representative sample of the total SIE data.

## Building and Installing AXA
AXA can built manually or, on Debian systems, installed by using pre-built packages.

### Building manually
The AXA suite has the following external dependencies:

 * C compiler (gcc or llvm)
 * [autoconf](https://www.gnu.org/software/autoconf/)
 * [automake](https://www.gnu.org/software/automake/)
 * [libtool](https://www.gnu.org/software/libtool/)
 * [libpcap](http://www.tcpdump.org/)
 * [zlib](http://www.zlib.net/)
 * [pkg-config](https://wiki.freedesktop.org/www/Software/pkg-config/)
 * [nmsg](https://github.com/farsightsec/nmsg) (probably will want to configure with `--without-libxs`, be sure to use version >= 0.11.2)
 * [protobuf-c](https://github.com/protobuf-c/protobuf-c) (be sure to use >= 1.2.1)
 * [sie-nmsg](https://github.com/farsightsec/sie-nmsg)
 * [wdns](https://github.com/farsightsec/wdns)
 * [libedit](http://thrysoee.dk/editline/)
 * [libbsd](http://libbsd.freedesktop.org/wiki/) (should already be installed on BSDish systems)
 * [libssl](http://openssl.org/) (recommended >= 1.0.2i)
 * [yajl](https://lloyd.github.io/yajl/) (be sure to use >= 2.1.0)
 * [liblmdb](lmdb.tech)

Optional dependencies:

 * [doxygen](http://www.stack.nl/~dimitri/doxygen/) (be sure to use >= 1.8.3 that supports inlining markdown files)
 * [check](http://check.sourceforge.net/doc/check_html/) (be sure to use >= 0.10.0)

After satisfying the above, build with something like:

`./autogen.sh` followed by `./configure` and `make`

To generate the API documentation (including an HTMLized version of this
document): `make doc`. The HTML documentation will be in the `html` directory and can be rendered in any modern browser. Something like `open html/index.html` should get you started.

Finally, to give the AXA suite a home, `sudo make install`.

### Debian package install
The binary packages of AXA and its dependencies are available from
[a Debian package repository maintained by Farsight Security](https://archive.farsightsecurity.com/SIE_Software_Installation_Debian/). These packages should be used instead of building from source on Debian-based systems.

To install the AXA Tools `sratool`, `radtool`, `sratunnel`, `radtunnel`:

~~~
# apt-get install axa-tools
~~~

To install AXA development files (if you wish to use the libaxa C API):

~~~
# apt-get install libaxa-dev
~~~

Once axa-tools is installed, you'll need to work with your account manager to decide which transport (described below) is best for your use case and then have your account provisioned.

## The AXA Transport Layer
AXA offers three encrypted transports for setting up sessions and tunneling
data:

 1. **Apikey**: Subscriber identifies and authenticates via an a priori
    (Farsight) provided alphanumeric "apikey". Session is encrypted via TLS using the `ECDHE-RSA-AES256-GCM-SHA384` suite offering "currently infeasible to break" encryption and
    [perfect forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy).
 2. **TLS**: Subscriber identifies and authenticates via an a priori
    subscriber-generated TLS keypair. Session is encrypted via TLS using the `ECDHE-RSA-AES256-GCM-SHA384` suite offering "currently infeasible to break" encryption and
    [perfect forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy).
 3. **SSH**: Subscriber identifies and authenticates via an a priori
    subscriber-generated SSH keypair.

In order to use AXA, one of these is required. While all three offer
commensurate security, Farsight strongly recommends using the apikey transport due to its ease of setup and use.

AXA compresses all [NMSGs](https://www.github.com/farsightsec/nmsg) before transmission across the network using NMSG's built-in compression capability (currently [zlib](http://www.zlib.net/)). IP packets are not compressed.

### Setting up and using AXA Apikey
Your Farsight Security account manager will provide you with an alphanumeric apikey string. This apikey is used to both identify you and authenticate your session to the AXA servers.

The AXA apikey transport listens at the following URIs:

 * **SRA**: `apikey:<your_apikey_here>@axa.sie-remote.net,1011`
 * **RAD**: `apikey:<your_apikey_here>@axa.sie-remote.net,1012`

SRA listens on `TCP/1011` and RAD listens on `TCP/1012` and both transit standard TLS data.

You can connect as per the following:

**Connecting via sratool**

  ~~~
  $ sratool
  sra> connect apikey:<your_apikey_here>@axa.sie-remote.net,1011
  * HELLO srad v2.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
  * Using AXA protocol 2
  * OK USER johndoe authorized
  ...
  ~~~

**Connecting via radtool**

  ~~~
  $ radtool
  rad> connect apikey:<your_apikey_here>@axa.sie-remote.net,1012
  * HELLO radd v2.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
  * Using AXA protocol 2
  * OK USER johndoe authorized
  ...
  ~~~

**Connecting via sratunnel**

  ~~~
  $ sratunnel -s apikey:<your_apikey_here>@axa.sie-remote.net,1011 ...
  ...
  ~~~

**Connecting via radtunnel**

  ~~~
  $ sratunnel -s apikey:<your_apikey_here>@axa.sie-remote.net,1012 ...
  ...
  ~~~


### Setting up and using AXA TLS
The AXA TLS transport listens at the following URIs:

 * **SRA**: `tls:user_name@sra.sie-remote.net,1021`
 * **RAD**: `tls:user_name@rad.sie-remote.net,1022`

SRA listens on TCP/1021 and RAD listens on TCP/1022 and both transit standard TLS data.

To setup TLS access for SRA and/or RAD, you need to do the following:

 1. Install axa-tools (as per above). Installed alongside the AXA tools are three TLS helper scripts:
   * `axa_make_cert`: Generate AXA certificate and private key files
   * `axa_server_cert`: Retrieve the AXA server certificate fingerprint
   * `axa_link_certs`: Create AXA certificate links
 2. Generate and install the AXA TLS certificates. This needs to be done
    as root because the install script copies the files to the AXA certs
    directory:

	~~~
	# axa_make_cert -u username
	Create /usr/local/etc/axa/certs? y
	Generating a 2048 bit RSA private key
	............+++
	.............+++
	writing new private key to 'username.key'
	~~~

 3. Chown the private key to the user who will be running the AXA tools:

	~~~
	# chown user. /usr/local/etc/axa/certs/username.key
	~~~

 4. Retrieve and install the AXA server certificate. This is the equivalent of when you SSH to a new host for the first time and receive the "Are you sure you want to continue connecting (yes/no)?" message. This can be done by connecting to either SRA or RAD since they both share the same TLS certificate:

	~~~
	# axa_server_cert -s axa.sie-remote.net,1021
	Obtained certificate for "farsight" with
	SHA1 Fingerprint=2D:0C:92:23:B9:6F:70:E7:F3:E3:7A:2B:D6:F5:D4:CA:1F:F8:CE:71
	Install it in /usr/local/etc/axa/certs/farsight.pem? yes
	~~~

 5. Email your public certificate (`username.pem`) to your Farsight Security account manager. DO NOT EVER SHARE YOUR PRIVATE KEY (`username.key`). This is the private half of your generate key pair that you should keep safe. As soon as your account is provisioned you will receive notification from Farsight Security.

You can connect as per the following:

**Connecting via sratool**

   ~~~
   $ sratool
   sra> connect tls:user_name@sra.sie-remote.net,1021
   * HELLO srad v2.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
   * Using AXA protocol 2
   * OK USER johndoe authorized
   ...
   ~~~

 **Connecting via radtool**

   ~~~
   $ radtool
   rad> connect tls:user_name@rad.sie-remote.net,1022
   * HELLO radd v2.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
   * Using AXA protocol 2
   * OK USER johndoe authorized
   ...
   ~~~

 **Connecting via sratunnel**

   ~~~
   $ sratunnel -s tls:user_name@sra.sie-remote.net,1021 ...
   ...
   ~~~

 **Connecting via radtunnel**

   ~~~
   $ radtunnel -s tls:user_name@rad.sie-remote.net,1022 ...
   ...
   ~~~

### Setting up and using AXA SSH
The AXA SSH transport listens at the following URIs:

 * **SRA**: `sra-service@sra.sie-remote.net`
 * **RAD**: `rad-service@rad.sie-remote.net`

Both services listen on TCP/22 for standard SSH traffic.

To setup SSH access for SRA and/or RAD, you need to do the following:

 1. Generate a new SSH authentication key pair with `ssh-keygen`:

	$ ssh-keygen -t rsa -b 4096 -f ~/.ssh/farsight-axa-id_rsa
	Generating public/private rsa key pair.
	Enter passphrase (empty for no passphrase):
	Enter same passphrase again:
	Your identification has been saved in /home/user/.ssh/farsight-axa-id_rsa.
	Your public key has been saved in /home/user/.ssh/farsight-axa-id_rsa.pub.
	The key fingerprint is:
	SHA256...

 2. You will need to create or edit your `~/.ssh/config` file to specify the private half of the SSH key pair for the SRA and RAD servers:

	~~~
	Host sra.sie-remote.net rad.sie-remote.net
	    IdentityFile ~/.ssh/farsight-axa-id_rsa
	~~~

 3. Email your public key (`~/.ssh/farsight-axa-id_rsa.pub`) to your Farsight Security account manager. DO NOT EVER SHARE YOUR PRIVATE KEY (`~/.ssh/farsight-axa-id_rsa`). This is the private half of your generated key pair that you should keep safe. As soon as your account is provisioned you will receive notification from Farsight Security.

You can connect as per the following:

**Connecting via sratool**

   ~~~
   $ sratool
   sra> connect ssh:sra-service@sra.sie-remote.net
   * HELLO srad v2.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
   * Using AXA protocol 2
   * OK USER johndoe authorized
   ...
   ~~~

**Connecting via radtool**

   ~~~
   $ radtool
   rad> connect ssh:rad-service@rad.sie-remote.net
   * HELLO radd v2.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
   * Using AXA protocol 2
   * OK USER johndoe authorized
   ...
   ~~~

**Connecting via sratunnel**

   ~~~
   $ sratunnel -s 'ssh:sra-service@sra.sie-remote.net' ...
   ...
   ~~~

**Connecting via radtunnel**

   ~~~
   $ radtunnel -s 'ssh:rad-service@rad.sie-remote.net' ...
   ...
   ~~~

#### AXA Config File Connection Aliases
AXA now requires a subscriber-side configuration file used as a convenience to
specify session defaults. By default AXA will look for it `~/.axa/config`. Currently it is used to store "connection aliases" that provide a facility to create shortcut mnemonics to specify the AXA server connection string. This is especially useful for long connection strings associated with the apikey transport. It can also be used for the other transports. As it can contain
sensitive information, the file must be readable/writable only by "owner" or AXA-based tools will refuse to load.

For example:

~~~
$ cat >> ~/.axa/config < EOF
# Aliases are of the form alias:<name>=<connection URI>

# SRA apikey
alias:sra-apikey=apikey:<your_apikey_here>@axa.sie-remote.net,1011
# RAD apikey
alias:rad-apikey=apikey:<your_apikey_here>@axa.sie-remote.net,1012
# SRA TLS
alias:sra-tls=tls:<your_username>@axa.sie-remote.net,1021
# RAD TLS
alias:rad-tls=tls:<your_username>@axa.sie-remote.net,1022
EOF

$ chmod 600 ~/.axa/config
~~~

After creating the above aliases, you can replace the server connection URI with your shortcut name as per the following:

~~~
$ sratool
sra> connect sra-apikey
* HELLO srad v2.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
* Using AXA protocol 2
* OK USER johndoe authorized
...
sra> disconnect
sra> mode rad
rad> connect rad-apikey
* HELLO radd v2.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
* Using AXA protocol 2
* OK USER johndoe authorized
...
~~~

The AXA config file is shared for `sratool`, `radtool`, `sratunnel`,
`radtunnel`, and is available via the API. As such, all of the tools (including the ones you may build) have access to these alias shortcuts.

## AXA examples
The following are a few examples of how to use `sratool`, `sratunnel` and `radtool`.

### 1. Stream SIE Traffic with sratool
Here's a simple example using `sratool` to stream five NMSGs seen on the
[Newly Observed Hostnames (NOH)](https://www.farsightsecurity.com/solutions/threat-intelligence-team/newly-observed-hostnames/) channel (channel 213):

~~~
$ sratool
sra> connect sra-apikey
* HELLO srad v2.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
* Using AXA protocol 2
* OK USER johndoe authorized
sra> count 5
sra> channel 213 on
* OK CHANNEL ON/OFF channel ch213 on
sra> 1 watch ch=213
1 OK WATCH started
1 ch213  SIE newdomain
 fd2d733e580keyaiqbitav3aahjzyqic4uh7qu-uoxyqssz1522793901-sonar.xz.fbcdn.net/A: fbcdn.net
1 ch213  SIE newdomain
 ddhc4g.dm.files.1drv.com/CNAME: 1drv.com
1 ch213  SIE newdomain
 accpots2ehi4qpqi22nzfcxl424kejn7mayzvqv6.r.nflxso.net/CNAME: nflxso.net
1 ch213  SIE newdomain
 networkstart-myipgcloindhvkms.islonline.net/A: islonline.net
1 ch213  SIE newdomain
 2d35abd9540041939e6b1c188bc7cc7c-1ad356638475.cdn5.forter.com/A: forter.com

packet count limit exceeded
sra> disconnect
disconnected
~~~

 1. `sra> connect sra-apikey`: we connected to an SRA server using the apikey
    transport. Under the hood, `sratool` consulted the AXA config file to
    search for the "sra-apikey" alias and extract the server connection URI.
    The `HELLO` response from the remote end provides its version number and
    the protocol level.
 2. `sra> count 5`: we asked our `sratool` client to stop after emitting five
    messages.
 3. `sra> channel 213 on`: we then asked the remote end to listen to SIE
    channel 213.
 4. `sra> 1 watch ch=213`: we then asked to watch all content on channel 213
    (with no rate limiting or filtering), which is a common choice for 213
    since its volume is low (~200kbps).

### 2. Stream SIE Traffic with sratunnel
The following example shows how to use `sratunnel` to stream NMSGs from NOH to a file and then read the resultant NMSG file with [nmsgtool](https://www.github.com/farsightsec/nmsg) display a single NMSG record as [new line delimited JSON](http://ndjson.org/) using the [jq](https://stedolan.github.io/jq/) program.

~~~
$ sratunnel -s sra-apikey -c 213 -w ch=213 -o nmsg:file:213.nmsg
...
^c
$ nmsgtool -c 1 -r 213.nmsg -J - -- | jq .
{
  "time": "2018-04-03 22:21:55.897547006",
  "vname": "SIE",
  "mname": "newdomain",
  "source": "a1ba02cf",
  "message": {
    "domain": "whatsapp.net.",
    "time_seen": "2018-04-03 22:20:36",
    "bailiwick": "snr.whatsapp.net.",
    "rrname": "wa409c4891kqn22dwa-gmztiojygy3dcnbr.snr.whatsapp.net.",
    "rrclass": "IN",
    "rrtype": "A",
    "rdata": [
      "185.60.219.53"
    ],
    "keys": [],
    "new_rr": []
  }
}
~~~

 1. `sratunnel -s sra-apikey -c 213 -w ch=213 -o nmsg:file:213.nmsg`: we invoked sratunnel and connected to SRA using the apikey transport. Channel 213 is enabled, and a 213 "all watch" is set. Finally, NMSGs are written to a file. The program runs for some time then we kill it via ctrl-c.
 2. `$ nmsgtool -c 1 -r 213.nmsg -J - -- | jq .`: The `nmsgtool` program is run to read a single NMSG from the output file and pipeline to the jq program to pretty print it.

### 3. Watch for Anomalies with radtool
Next, `radtool` is used to load the Brand Sentry anomaly module to watch for
suspected brand infringement in the Internationalized Domain Names (IDN) namespace for four
well-known brands.

~~~
rad> connect rad-apikey
* HELLO radd v2.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
* Using AXA protocol 2
* OK USER johndoe authorized
rad> verbose on
rad> 1 watch dns=*.
1 OK WATCH saved
rad> 1 anomaly brand_sentry brand=facebook,apple,netflix,google matcher=idn_homoglyph whitelist=*.facebook.com,*.apple.com,*.netflix.com,*.google.com
1 OK ANOMALY anomaly detector started
1 brand_sentry ch204  SIE dnsdedupe bailiwick=xn--fcebook-s3a.com
  type: INSERTION
  count: 1
  time_first: 2018-04-03 22:25:09
  time_last: 2018-04-03 22:25:09
  response_ip: 208.109.255.42
  bailiwick: xn--fcebook-s3a.com.
  rrname: xn--fcebook-s3a.com.
  rrclass: IN (1)
  rrtype: A (1)
  rrttl: 600
  rdata: 184.168.221.57
...
rad> exit
$ idn -u xn--fcebook-s3a.com.
fācebook.com.
~~~

 1. `rad> connect rad-apikey`: We connected to RAD over the apikey transport using the "rad-apikey" alias. The `HELLO` response from the remote end tells us its version number and the protocol level.
 2. `rad> verbose on`: We turn on verbose mode to get more information about each hit.
 3. `rad> 1 watch dns=*.`: We set a DNS wildcard "all-watch". This will match all dns hostnames which is what we want for Brand Sentry -- we want to look at the entire DNS namespace (except for four level domains, as per below).
 4. `rad> 1 anomaly brand_sentry brand=facebook,apple,netflix,google matcher=idn_homoglyph whitelist=*.facebook.com,*.apple.com,*.netflix.com,*.google.com`: We switched on the anomaly detector. This command enables the brand_sentry anomaly module looking for Internationalized Domain Names (IDNs) "suspiciously close" to "facebook, google, apple", or "netflix". Hostnames in the `*.facebook.com`, `*.apple.com`, `*.netflix.com`, and `*.google.com` are considered safe and are ignored.
 5. `$ idn -u xn--fcebook-s3a.com.`: We use the [GNU libidn idn](https://www.gnu.org/software/libidn/manual/html_node/Invoking-idn.html) command line tool to convert the punycode encoded domain into its Unicode representation.

### 5. Create Your Own Local SIE Node
With `sratunnel` and `nmsgtool`, you can create your own local "SIE node". This can be useful if you want cobble together your own local SIE cloud with the channels you're subscribed to. First, invoke `sratunnel` as per the following:

~~~
$ sratunnel -s sra-apikey -c 204 -w ch=204 -o nmsg:127.0.0.1,8000 &
[2]+ sratunnel ...
~~~

Before continuing, we confirm traffic flowing by checking with `tcpdump` (on OS X this looks like):

~~~
$ tcpdump -i lo0 -c 5 -nn udp port 8000
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo0, link-type NULL (BSD loopback), capture size 262144 bytes
14:00:13.521512 IP localhost.53996 > localhost.8000: UDP, length 1091
14:00:13.521659 IP localhost.53996 > localhost.8000: UDP, length 1094
14:00:13.521969 IP localhost.53996 > localhost.8000: UDP, length 1079
14:00:13.522116 IP localhost.53996 > localhost.8000: UDP, length 1111
14:00:13.522239 IP localhost.53996 > localhost.8000: UDP, length 1069

5 packets captured
12 packets received by filter
0 packets dropped by kernel
~~~

Finally, we use `nmsgtool` to receive and decapsulate the data. Here we invoke it to capture and display three payloads:

~~~
$ nmsgtool  -l 127.0.0.1/8000 -c 3
[76] [2018-04-03 22:35:21.747374163] [2:1 SIE dnsdedupe] [a1ba02cf] [] [] 
type: INSERTION
count: 1
time_first: 2018-04-03 22:34:03
time_last: 2018-04-03 22:34:03
response_ip: 174.128.246.102
bailiwick: yoga-power.com.
rrname: www.yoga-power.com.
rrclass: IN (1)
rrtype: A (1)
rrttl: 3600
rdata: 216.86.147.31

[138] [2018-04-03 22:35:21.747378349] [2:1 SIE dnsdedupe] [a1ba02cf] [] [] 
type: INSERTION
count: 1
time_first: 2018-04-03 22:34:03
time_last: 2018-04-03 22:34:03
response_ip: 174.128.246.102
bailiwick: yoga-power.com.
rrname: yoga-power.com.
rrclass: IN (1)
rrtype: NS (2)
rrttl: 3600
rdata: ns1.afraid.org.
rdata: ns2.afraid.org.
rdata: ns3.afraid.org.
rdata: ns4.afraid.org.

[141] [2018-04-03 22:35:21.747385912] [2:1 SIE dnsdedupe] [a1ba02cf] [] [] 
type: EXPIRATION
count: 1
time_first: 2018-04-03 20:09:54
time_last: 2018-04-03 20:09:54
bailiwick: vn.city.
rrname: c.vn.city.
rrclass: IN (1)
rrtype: RRSIG (46)
rrttl: 300
rdata: CNAME 13 3 300 1522876195 1522696195 35273 vn.city. xU5jsRsbUQFzegFol6xhWCSUSbX8CXUSCRV9ge5WCe6/fy8jgDMt6Zyt YZTDNd7wYoi/O5hemCRQXJvYSJ7JWQ==
~~~

 1. `sratunnel -s sra-apikey -c 204 -w ch=204 -o nmsg:127.0.0.1,8000 &`: invoke `sratunnel` and stream all of channel 204 ([Passive DNS traffic that has been de-duplicated, filtered, and verified](https://www.farsightsecurity.com/assets/media/download/fsi-sie-channel-guide.pdf)). The output is set to be NMSGs to the loopback interface on port UDP/8000 (UDP is the default NMSG transport protocol).
 2. `tcpdump -n -c 3 -i lo udp port 8000`: tcpdump is used to verify packets are being received.
 3. `nmsgtool -l 127.0.0.1/8000 -c 3`: `nmsgtool` is invoked to listen on the loopback interface on `UDP/8000` and three NMSGs are emitted to stdout.

## AXA Protocol

The AXA protocol consists of a pair of streams of messages between a subscriber's client (such as `sratool`) and an AXA server (such as SRA), one stream in each direction, currently over a single TCP connection.

AXA must sit on top of a reliable stream protocol such as TCP and so has no provisions to detect or recover from duplicate, out-of-order, lost, or partially lost data. Note that SIE data *can* be lost *before*
encapsulation into AXA protocol messages due to issues such as network
congestion, CPU overload, etc.

As mentioned above, protocols such as TLS or SSH are used below the AXA layer and above TCP to provide authentication, confidentiality, and integrity as shown below.

~~~
[AXA] - SIE message encapsulation
[TLS] - Authentication and encryption
[TCP] - Reliable transport
~~~

The authoritative definition of the AXA protocol is contained in the
[axa/protocol.h](axa/protocol.h) file.

Values that originate in SRA or RAD servers such as message lengths use little endian byte order in the AXA protocol. Other values such as IP addresses and port numbers are big endian for consistency with their sources such as host tables. SRA and RAD data such as NMSG messages and IP packets have their original byte orders.

The stream protocols below the AXA protocol are responsible for authentication and authorization. An AXA client and server pair on a computer can use unadorned TCP through the loop-back interface or use a UNIX domain socket. The AXA protocol assumes this is safe.

Between separate computers, the AXA protocol can use UNIX pipes to the `stdin` and `stdout` streams provided by the `ssh` command or the functions of an SSH library such as `libssh2` (SSH must identify and authenticate the client and server to each other) or the TLS library.

The AXA client starts by waiting for an `AXA_P_OP_HELLO` message from the server. Over a local stream, the client then sends an `AXA_P_OP_USER` message to tell the server which parameters to use. When SSH is used, the user name is provided through the SSH protocol.

### AXA message header

Every AXA message starts with the following 8 octet header:

~~~c
    typedef struct
    {
        uint32_t      len;
        axa_tag_t     tag;
        axa_p_pvers_t pvers;
        uint8_t       op;
    } axa_p_hdr_t;
~~~

 * `len`: A 32-bit value covering the entire length of the AXA message
   *including the header*. Many AXA  messages are variable length.
 * `tag`: A 16-bit identifier used to uniquely "tag" specific events
during the lifetime of an AXA session. To refer to these events, the client or server will use this tag. Some AXA messages do not require tags, in that case the tag field should be `AXA_TAG_NONE`. Required tags must be unique during the lifetime  of the corresponding client request. Some client requests such as a "watch" can last indefinitely and will elicit many server responses all with the same tag.
 * `pvers`: An 8-bit protocol version number that allows AXA clients and
servers of different ages to find a mutually compatible version of the AXA protocol.
 * `op`: The 8-bit op (opcode) specifies an operation requested by the client, a response from the server, or data from the server. The universe of opcodes is discussed below.

For a detailed discussions of the AXA protocol message types, see the doxygen generated page for `protocol.h`.

### AXA protocol specification quick reference

The following is an AXA protocol quick reference chart intended for application developers building libaxa programs.

 * OPCODE: The canonical name of the operation code as defined by [axa/protocol.h](axa/protocol.h).
 * VAL: The numerical value of the opcode.
 * SENT BY: Who can send the message.
 * TAG: Boolean value indicating if header tag must be valid or `AXA_TAG_NONE`, as described above.
 * DESCRIPTION: Short description of opcode.

| OPCODE              | VAL | SENT BY         | TAG   | DESCRIPTION            |
| ------------------- |----:|----------------:| -----:|----------------------------------------------------------------------------------------------:|
| `AXA_P_OP_NOP`      | 0   | CLIENT / SERVER | NO    | carries no data, is intended only to ensure that the TCP connection is still up               |
| `AXA_P_OP_HELLO`    | 1   | SERVER          | NO    | helps the client choose a compatible AXA protocol version                                     |
| `AXA_P_OP_OK`       | 2   | SERVER          | YES   | indicates the success of the preceding client request with the same tag                      |
| `AXA_P_OP_ERROR`    | 3   | SERVER          | YES   | indicates the failure of a preceding client request with the same tag                        |
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
| `AXA_P_OP_RADU`     | 143 | SERVER (RAD)    | NO    | request RAD Unit balance                                                                |

### JSON Format

See the [JSON schema](json-schema.yaml) describing the JSON output format.

~~~json
{"tag":4,"op":"HELLO","id":1,"pvers_min":2,"pvers_max":3,"str":"hello"}
{"tag":1,"op":"OK","orig_op":"WATCH HIT","str":"success"}
{"tag":1,"op":"ERROR","orig_op":"OK","str":"failure"}
{"tag":1,"op":"MISSED","missed":2,"dropped":3,"rlimit":4,"filtered":5,"last_report":6}
{"tag":1,"op":"RAD MISSED","sra_missed":2,"sra_dropped":3,"sra_rlimit":4,"sra_filtered":5,"dropped":6,"rlimit":7,"filtered":8,"last_report":9}
{"tag":1,"op":"WATCH HIT","channel":"ch123","field_idx":1,"val_idx":2,"vname":"base","mname":"pkt","time":"1970-01-01 00:00:01.000000002","nmsg":{"time":"1970-01-01 00:00:01.000000002","vname":"base","mname":"pkt","message":{"len_frame":32,"payload":"RQAAIBI0QAD/EVmFAQIDBAUGBwgAewHIAAxP4t6tvu8="}}}
{"tag":1,"op":"WATCH HIT","channel":"ch123","time":"1970-01-01 00:00:01.000002","af":"IPv4","src":"1.2.3.4","dst":"5.6.7.8","ttl":255,"proto":"UDP","src_port":123,"dst_port":456,"payload":"3q2+7w=="}
{"tag":1,"op":"WATCH HIT","channel":"ch123","time":"1970-01-01 00:00:01.000002","af":"IPv4","src":"1.2.3.4","dst":"5.6.7.8","ttl":255,"proto":"TCP","src_port":123,"dst_port":456,"flags":["SYN","ACK"],"payload":"3q2+7w=="}
{"tag":1,"op":"WATCH HIT","channel":"ch123","time":"1970-01-01 00:00:01.000002","af":"IPv6","src":"1:2:3:4:5:6:7:8","dst":"9:0:a:b:c:d:e:f","ttl":255,"proto":"UDP","src_port":123,"dst_port":456,"payload":"3q2+7w=="}
{"tag":1,"op":"WATCH","watch_type":"ipv4","watch":"IP=12.34.56.0/24"}
{"tag":1,"op":"WATCH","watch_type":"ipv4","watch":"IP=0.0.0.0/24"}
{"tag":1,"op":"WATCH","watch_type":"ipv4","watch":"IP=12.34.56.78/24"}
{"tag":1,"op":"WATCH","watch_type":"ipv6","watch":"IP=1:2:3:4:5:6::/48"}
{"tag":1,"op":"WATCH","watch_type":"dns","watch":"dns=fsi.io"}
{"tag":1,"op":"WATCH","watch_type":"dns","watch":"dns=*.fsi.io"}
{"tag":1,"op":"WATCH","watch_type":"dns","watch":"dns=*."}
{"tag":1,"op":"WATCH","watch_type":"dns","watch":"dns=fsi.io(shared)"}
{"tag":1,"op":"WATCH","watch_type":"channel","watch":"ch=ch123"}
{"tag":1,"op":"WATCH","watch_type":"errors","watch":"ERRORS"}
{"tag":1,"op":"ANOMALY","an":"test_anom","parms":"param1 param2"}
{"tag":1,"op":"CHANNEL ON/OFF","channel":"ch123","on":true}
{"tag":1,"op":"CHANNEL ON/OFF","channel":"ch123","on":false}
{"tag":1,"op":"CHANNEL ON/OFF","channel":"all","on":true}
{"tag":1,"op":"WATCH LIST","cur_tag":1,"watch_type":"ipv4","watch":"IP=12.34.56.0/24"}
{"tag":1,"op":"ANOMALY HIT","an":"test_anom","channel":"ch123","time":"1970-01-01 00:00:01.000002","af":"IPv4","src":"1.2.3.4","dst":"5.6.7.8","ttl":255,"proto":"UDP","src_port":123,"dst_port":456,"payload":"3q2+7w=="}
{"tag":1,"op":"ANOMALY LIST","cur_tag":1,"an":"test_anom","parms":"param1 param2"}
{"tag":1,"op":"CHANNEL LIST","channel":"ch123","on":true,"spec":"test channel"}
{"tag":1,"op":"USER","name":"test user"}
{"tag":1,"op":"OPTION","type":"TRACE","trace":3}
{"tag":1,"op":"OPTION","type":"TRACE","trace":"REQUEST TRACE VALUE"}
{"tag":1,"op":"OPTION","type":"RATE LIMIT","max_pkts_per_sec":123,"cur_pkts_per_sec":456,"report_secs":60}
{"tag":1,"op":"OPTION","type":"RATE LIMIT","max_pkts_per_sec":1000000000,"cur_pkts_per_sec":123,"report_secs":60}
{"tag":1,"op":"OPTION","type":"RATE LIMIT","max_pkts_per_sec":"off","cur_pkts_per_sec":123,"report_secs":60}
{"tag":1,"op":"OPTION","type":"RATE LIMIT","max_pkts_per_sec":null,"cur_pkts_per_sec":123,"report_secs":null}
{"tag":1,"op":"OPTION","type":"SAMPLE","sample":123}
{"tag":1,"op":"OPTION","type":"SNDBUF","bufsize":123}
~~~

## API Workflow

For a detailed walkthrough of a "Hello World", AXA-style, please see the
following Farsight Security Blog articles:

 * [Farsight's Advanced Exchange Access: The C Programming API, Part One](https://www.farsightsecurity.com/2015/07/30/mschiffm-axa-api-c-1/)
 * [Farsight's Advanced Exchange Access: The C Programming API, Part Two](https://www.farsightsecurity.com/2015/08/07/mschiffm-axa-api-c-2/)
 * [Farsight's Advanced Exchange Access: The C Programming API, Part Three](https://www.farsightsecurity.com/2015/08/11/mschiffm-axa-api-c-3/)

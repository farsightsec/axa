# Farsight Advanced Exchange Access Toolkit
This is the Advanced Exchange Access (AXA) toolkit. It contains tools and a C library to bring Farsight's real-time data and services directly from the [Farsight Security Information Exchange (SIE)](https://www.farsightsecurity.com/solutions/security-information-exchange/) to the subscriber's network edge.

AXA-based solutions are often preferable over procuring a direct, physical connection to the SIE, usually via a co-located blade.

## You Must Be A Farsight Security Customer To Use This Toolkit
In order to use the tools and C library to access Farsight Security's data, you must have a previously provisioned account. If are you not yet a customer, but are interested, please reach out to [Farsight Security Sales](sales@farsightsecurity.com) for more information.

## SRA and RAD
AXA enables subscribers to connect to Farsight's subscription-based SRA (SIE Remote Access) and RAD (Real-time Anomaly Detector) servers.  These servers provide access to data and services built from Farsight's SIE.  SRA streams real-time SIE data while RAD streams real-time anomaly detection data.

## Contents
The axa-tools distribution contains the following:

 * `sratool`: A test/debug/instructional command-line tool used to connect to an SRA server, set watches, enable SIE channels, and stream data.
 * `radtool`: A test/debug/instructional command-line tool used to connect to a RAD server, set watches, enable anomaly detection modules, and stream data.
 * `sratunnel`: A production-quality command-line tool that streams SIE data to the local network.
 * `radtunnel`: A production-quality command-line tool that streams anomaly data to the local network.
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
AXA can built manually from source or, on Debian systems, installed by using pre-built packages.

### Building Manually From Source
AXA should compile on most modern Unix-like operating systems with little or no modiciation. The following (very complete) guide will walk you through
getting it built.

This guide assumes the following support programs are installed (most of the which can be installed via your operating system's package management system).
If you need help with any of the following, please reach out to Farsight Security.

 * [gcc](https://gcc.gnu.org/) or [clang](https://clang.llvm.org/): Compiles C cpde
 * [g++](https://gcc.gnu.org/): Compiles C++ code
 * [make](https://www.gnu.org/software/make/): Controls the generation of executable code
 * [cmake](https://cmake.org): Manages the build process of software using a compiler-independent method
 * [wget](https://www.gnu.org/software/wget/): Retrieves files over HTTP/HTTPS
 * [m4](https://www.gnu.org/software/m4/m4): Parses m4 language files
 * [autoconf](https://www.gnu.org/software/autoconf): Produces shell scripts to automatically configure source code packages
 * [automake](https://www.gnu.org/software/automake): Produces support files necessary for the autoconfiguration process
 * [libtool](https://www.gnu.org/software/libtool): Simplifies the process of compiling programs
 * [flex](https://github.com/westes/flex): Generates programs that perform pattern-matching on text
 * [bison](https://www.gnu.org/software/bison/): Generates parsers
 * [pkg-config](https://wiki.freedesktop.org/www/Software/pkg-config/): Provides a unified interface for querying installed libraries for the purpose of compiling software from its source code


The AXA suite has the following external library dependencies that must be installed in the order they appear. Please note that, while in most cases the latest version of a depedency is preferred, sometimes an older version is required.

 * [libpcap](http://www.tcpdump.org/): Used for low-level packet capture.

~~~
$ wget https://www.tcpdump.org/release/libpcap-1.9.0.tar.gz
$ tar xf libpcap-1.9.0.tar.gz
$ cd libpcap-1.9.0
$ ./configure
$ make
$ sudo make install
~~~

 * [wdns](https://github.com/farsightsec/wdns): Used for low-level wire-format DNS routines.

~~~
$ git clone https://www.github.com/farsightsec/wdns
$ cd wdns
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
~~~

* [googletest](https://github.com/google/googletest): Used by protobuf for test mocking.

~~~
$ git clone https://github.com/google/googletest
$ cd googletest
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
~~~

 * [protobuf](https://github.com/protocolbuffers/protobuf): Used by libprotobuf-c for low-level data serialization. Currently nmsg protobufs support protocol buffers version 2 so you'll need to install 2.7.0. Also, because gmock is no longer a standalone
pacakge and is installed with gooletest, you may need to first edit the `autogen.sh` script and comment out the following stanza:

~~~
# Check that gmock is present.  Usually it is already there since the
# directory is set up as an SVN external.
if test  -e gmock; then
  echo "Google Mock not present.  Fetching gmock-1.7.0 from the web..."
  curl $curlopts -O https://googlemock.googlecode.com/files/gmock-1.7.0.zip
  unzip -q gmock-1.7.0.zip
  rm gmock-1.7.0.zip
  mv gmock-1.7.0 gmock
fi
~~~

~~~
$ git clone https://github.com/protocolbuffers/protobuf
$ cd protobuf
$ git checkout 2.7.0
$ ./autogen.sh
$ ./configure
$ make
$ # go get a cup of coffee (this one takes a while)
$ sudo make install
$ sudo ldconfig
~~~

 * [protobuf-c](https://github.com/protobuf-c/protobuf-c): Used by libnmsg for low-level data serialization.

~~~
$ git clone https://www.github.com/protobuf-c/protobuf-c
$ cd protobuf-c
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
~~~

 * [zlib](http://www.zlib.net/): Used for nmsg compression.

~~~
$ wget http://zlib.net/zlib-1.2.11.tar.gz
$ tar xf zlib-1.2.11.tar.gz
$ cd http://zlib.net/zlib-1.2.11
$ ./configure
$ make
$ sudo make install
~~~

 * [yajl](https://lloyd.github.io/yajl/): Used to serialize and deserialize json objects.

~~~
$ git clone https://www.github.com/lloyd/yajl
$ cd yajl
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
~~~

 * [nmsg](https://github.com/farsightsec/nmsg): Used for data encapsulation and export.

~~~
$ git clone https://www.github.com/farsightsec/nmsg
$ cd nmsg
$ ./autogen.sh
$ ./configure --without-libxs
$ make
$ sudo make install
~~~

 * [sie-nmsg](https://github.com/farsightsec/sie-nmsg): Used to decode SIE-specific message modules for libnmsg.

~~~
$ git clone https://www.github.com/farsightsec/sie-nmsg
$ cd sie-nmsg
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
~~~

 * [ncurses](https://www.gnu.org/software/ncurses/): Required by libedit.

~~~
$ wget https://ftp.gnu.org/gnu/ncurses/ncurses-6.1.tar.gz
$ tar xf ncurses-6.1.tar.gz
$ cd ncurses-6.1
$ ./configure
$ make
$ sudo make install
~~~

 * [libedit](http://thrysoee.dk/editline/)

~~~
$ wget http://thrysoee.dk/editline/libedit-20180525-3.1.tar.gz
$ tar xf libedit-20180525-3.1.tar.gz
$ cd libedit-20180525-3.1
$ ./configure
$ make
$ sudo make install
~~~

 * [libbsd](http://libbsd.freedesktop.org/wiki/): Used for `strlcpy()` (should already be installed on BSDish systems)

~~~
$ git clone https://anongit.freedesktop.org/git/libbsd.git
$ cd libbsd
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
~~~

 * [libssl](http://openssl.org/): Used for all crypto

~~~
$ wget https://www.openssl.org/source/openssl-1.1.1.tar.gz
$ tar xf openssl-1.1.1.tar.gz
$ cd openssl-1.1.1
$ ./config
$ make
$ sudo make install
~~~

 * [liblmdb](http://lmdb.tech): Used by {rad,sra}tunnel to write timestamp index files

~~~
$ git clone https://github.com/LMDB/lmdb
$ cd lmdb/libraries/liblmdb
$ make
$ sudo make install
~~~

Optional dependencies:

 * [doxygen](http://www.stack.nl/~dimitri/doxygen/): Optional, used to build htmlized API documentation.

~~~
$ git clone https://github.com/doxygen/doxygen
$ cd doxygen
$ mkdir build
$ cd build
$ cmake -G "Unix Makefiles" ..
$ make
$ sudo make install
~~~

 * [texinfo](https://ftp.gnu.org/gnu/texinfo/): Optional for axa but required for libcheck (see below).

~~~
$ wget https://ftp.gnu.org/gnu/texinfo/texinfo-6.5.tar.gz
$ tar xf texinfo-6.5.tar.gz
$ cd texinfo-6.5
$ ./configure
$ make
$ sudo make install
~~~

 * [libcheck](https://github.com/libcheck/check): Optional dependency for running (and writing) unit tests.

~~~
$ git clone https://github.com/libcheck/check.git
$ ./autoreconf --install
$ ./configure
$ make
$ sudo make install
$ sudo ldconfig
~~~

After satisfying the above, build, axa:

~~~
$ sudo ldconfig
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
~~~

If you installed libcheck you can run the unit tests by the following command:

~~~
$ make check
~~~

Please report any errors to Farsight Security.

If you installed Doxygen you can build the API documentation (including an HTMLized version of this document):

~~~
$ make doc
~~~

The HTML documentation will be in the `html` directory and can be rendered in any modern browser.

Congratulations, you're ready to stream data! You can proceed to the "AXA Transport Layer" section below.

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

Once axa-tools is installed, you'll need to work with your Farsight account manager to obtain your access credentials. In most cases, this will be an apikey.

## The AXA Transport Layer
AXA offers an encrypted transport for setting up sessions and tunneling data:

 1. **Apikey**: Subscriber identifies and authenticates via a previously
    (Farsight) provided alphanumeric "apikey". Session is encrypted via TLS using the `ECDHE-RSA-AES256-GCM-SHA384` suite offering "currently infeasible to break" encryption and
    [perfect forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy).

AXA compresses all [nmsgs](https://www.github.com/farsightsec/nmsg) before transmission across the network using nmsg's built-in compression capability. IP packets are not compressed.

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
  * HELLO srad v3.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
  * Using AXA protocol 2
  * OK USER johndoe authorized
  ...
  ~~~

**Connecting via radtool**

  ~~~
  $ radtool
  rad> connect apikey:<your_apikey_here>@axa.sie-remote.net,1012
  * HELLO radd v3.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
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
  $ radtunnel -s apikey:<your_apikey_here>@axa.sie-remote.net,1012 ...
  ...
  ~~~

#### AXA Config File Connection Aliases
AXA supports a subscriber-side configuration file used as a convenience to
specify session defaults. By default AXA will look for it `~/.axa/config`. Currently it is used to store "connection aliases" that provide a facility to create shortcut mnemonics to specify the AXA server connection string. This is especially useful for long connection strings associated with the apikey transport. As it can contain sensitive information, if it exists, the file must be readable/writable only by "owner" or AXA-based tools will refuse to load.

For example:

~~~
$ cat >> ~/.axa/config < EOF
# Aliases are of the form alias:<name>=<connection URI>

# SRA apikey
alias:sra-apikey=apikey:<your_apikey_here>@axa.sie-remote.net,1011
# RAD apikey
alias:rad-apikey=apikey:<your_apikey_here>@axa.sie-remote.net,1012
EOF

$ chmod 600 ~/.axa/config
~~~

After creating the above aliases, you can replace the server connection URI with your shortcut name as per the following:

~~~
$ sratool
sra> connect sra-apikey
* HELLO srad v3.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
* Using AXA protocol 2
* OK USER johndoe authorized
...
sra> disconnect
sra> mode rad
rad> connect rad-apikey
* HELLO radd v3.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
* Using AXA protocol 2
* OK USER johndoe authorized
...
~~~

The AXA config file is shared for `sratool`, `radtool`, `sratunnel`,
`radtunnel`, and is available via the API. As such, all of the tools (including the ones you may build) have access to these alias shortcuts.

## AXA examples
The following are a few examples of how to use `sratool`, `sratunnel` and `radtool`.

### 1. Stream SIE Traffic with sratool
Here's a simple example using `sratool` to stream five nmsgs seen on the
[Newly Observed Hostnames (NOH)](https://www.farsightsecurity.com/solutions/threat-intelligence-team/newly-observed-hostnames/) channel (channel 213):

~~~
$ sratool
sra> connect sra-apikey
* HELLO srad v3.0.0 dev-axa-multi-1 supporting AXA protocols v1 to v2; currently using v1
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
The following example shows how to use `sratunnel` to stream nmsgs from NOH to a file and then read the resultant nmsg file with [nmsgtool](https://www.github.com/farsightsec/nmsg) display a single nmsg record as [new line delimited JSON](http://ndjson.org/) using the [jq](https://stedolan.github.io/jq/) program.

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

 1. `sratunnel -s sra-apikey -c 213 -w ch=213 -o nmsg:file:213.nmsg`: we invoked sratunnel and connected to SRA using the apikey transport. Channel 213 is enabled, and a 213 "all watch" is set. Finally, nmsgs are written to a file. The program runs for some time then we kill it via ctrl-c.
 2. `$ nmsgtool -c 1 -r 213.nmsg -J - -- | jq .`: The `nmsgtool` program is run to read a single nmsg from the output file and pipeline to the jq program to pretty print it.

### 3. Watch for Anomalies with radtool
Next, `radtool` is used to load the Brand anomaly module to watch for
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
rad> 1 anomaly brand brand=facebook,apple,amazon,netflix,google matcher=idnhomograph whitelist=*.facebook.com,*.apple.com,*.netflix.com,*.google.com
1 OK ANOMALY anomaly detector started
1 brand ch204  SIE dnsdedupe bailiwick=xn--fcebook-s3a.com
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
 3. `rad> 1 watch dns=*.`: We set a DNS wildcard "all-watch". This will match all dns hostnames which is what we want for the Brand module -- we want to look at the entire DNS namespace (except for four level domains, as per below).
 4. `rad> 1 anomaly brand brand=facebook,apple,netflix,google matcher=idn_homoglyph whitelist=*.facebook.com,*.apple.com,*.netflix.com,*.google.com`: We switched on the anomaly detector. This command enables the brand anomaly module looking for Internationalized Domain Names (IDNs) "suspiciously close" to "facebook, google, apple", or "netflix". Hostnames in the `*.facebook.com`, `*.apple.com`, `*.netflix.com`, and `*.google.com` are considered safe and are ignored.
 5. `$ idn -u xn--fcebook-s3a.com.`: We use the [GNU libidn idn](https://www.gnu.org/software/libidn/manual/html_node/Invoking-idn.html) command line tool to convert the punycode encoded domain into its Unicode representation.

### 4. Create Your Own Local SIE Node
With `sratunnel` and `nmsgtool`, you can create your own local "SIE node". This can be useful if you want to cobble together your own local SIE cloud with the channels you're subscribed to. First, invoke `sratunnel` as per the following:

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

 1. `sratunnel -s sra-apikey -c 204 -w ch=204 -o nmsg:127.0.0.1,8000 &`: invoke `sratunnel` and stream all of channel 204 ([Passive DNS traffic that has been de-duplicated, filtered, and verified](https://www.farsightsecurity.com/assets/media/download/fsi-sie-channel-guide.pdf)). The output is set to be nmsgs to the loopback interface on port UDP/8000 (UDP is the default nmsg transport protocol).
 2. `tcpdump -n -c 3 -i lo udp port 8000`: tcpdump is used to verify packets are being received.
 3. `nmsgtool -l 127.0.0.1/8000 -c 3`: `nmsgtool` is invoked to listen on the loopback interface on `UDP/8000` and three nmsgs are emitted to stdout.


### 6. Use sratunnel's Timestamp Indexing Feature
The following example shows how to use `sratunnel` to capture 10,000,000 nmsgs from channel 204 to a newline delimited JSON file and create a companion "time stamp index" file. This time stamp index file is intended to be used to provide hints to speed subsequent
cherry-picking of nmsgs from the data file it backs. It is most useful when the corresponding nmsg data file is anticipated to grow large. We run sratunnel below, bookending its execution in invocations of the `date` command (this will aid us later when we want to extract specific data).

~~~
$ date +%s ; sratunnel -s sra-apikey -c 204 -w ch=204 -o nmsg:file_json:204.jsonl -i 100 -u -dd -C 10000000; date +%s
1540415096
writing timestamp offsets to 204.jsonl.mdb every 100 nmsgs
connecting to apikey:<apikey elided>@axa-1.dev.fsi.io,1011
connected to apikey:<apikey elided>@axa-1.dev.fsi.io,1011
forwarded 10000000 messages
1540415549
~~~

 1. `date +%s`: Emit epoch timestamp so we know when sratunnel started.
 2. `sratunnel -s sra-apikey -c 204 -w ch=204 -o nmsg:file_json:213.jsonl -i 100 -u -dd -C 10000000`: We invoked `sratunnel` and connected to SRA using the apikey transport. Channel 204 is enabled, and a 204 "all watch" is set. nmsgs are
then written to a file as new-line delimited json. We specify time stamp indexing interval of every 100 nmsgs, unbuffered mode, and two levels of debug messaging. Finally, we specify that we want 10,000,000 watch hits.
 3. `date +%s`: Emit epoch timestamp so we know when sratunnel stopped.

From the differences in the timestamps, we see sratunnel took ~7.5 minutes to complete; let's take a look at the files created:

~~~
$ ls -l 204.jsonl*
-rw-r--r-- 1 username username 3912958424 Oct 24 21:12 204.jsonl
-rw-r--r-- 1 username username      57344 Oct 24 21:12 204.jsonl.mdb
-rw-r--r-- 1 username username       8192 Oct 24 21:11 204.jsonl.mdb-lock
~~~

The 3.7G file `204.jsonl` contains the output from the session, the `204.jsonl.mdb` file contains its indexed timestamps while `204.jsonl.mdb-lock` is a lock file used to mediate access to the timestamp index database file. To quickly access a select range of nmsgs from this rather
large file we'll use the example time stamp index tool program that ships with axa to extract them:

~~~
$ axa_tsindextool -c 10 -s 1540415300 -j 204.jsonl -f 204.jsonl.mdb -vv
Found 1540415300 at offset 0x1866137600.
{"time":"2018-10-24 21:08:20.002873700","vname":"SIE","mname":"dnsdedupe","message":{"type":"EXPIRATION","count":1,"time_first":"2018-10-24 12:34:30","time_last":"2018-10-24 12:34:30","bailiwick":"com.br.","rrname":"jpbqfvilksvmami5bbjl6j9j33jl0gc4.com.br.","rrclass":"IN","rrtype":"NSEC3","rrttl":900,"rdata":["1 1 10 69811154eac0e5b7cd4f JPBTFHUVU3GGSQLDLFJ0HRCRNMV6V0LH NS DS RRSIG"]}}
{"time":"2018-10-24 21:08:20.002877019","vname":"SIE","mname":"dnsdedupe","message":{"type":"EXPIRATION","count":1,"time_first":"2018-10-24 18:46:04","time_last":"2018-10-24 18:46:04","bailiwick":"bjljme.com.","rrname":"bjljme.com.","rrclass":"IN","rrtype":"NS","rrttl":1800,"rdata":["dns1.registrar-servers.com.","dns2.registrar-servers.com."]}}
{"time":"2018-10-24 21:08:20.001785447","vname":"SIE","mname":"dnsdedupe","message":{"type":"INSERTION","count":1,"time_first":"2018-10-24 15:00:12","time_last":"2018-10-24 15:00:12","response_ip":"205.251.199.8","bailiwick":"app.link.","rrname":"qq0u-alternate.app.link.","rrclass":"IN","rrtype":"AAAA","rrttl":60,"rdata":["2600:9000:201d:1a00:19:9934:6a80:93a1","2600:9000:201d:3000:19:9934:6a80:93a1","2600:9000:201d:4e00:19:9934:6a80:93a1","2600:9000:201d:6c00:19:9934:6a80:93a1","2600:9000:201d:7400:19:9934:6a80:93a1","2600:9000:201d:7c00:19:9934:6a80:93a1","2600:9000:201d:ce00:19:9934:6a80:93a1","2600:9000:201d:d600:19:9934:6a80:93a1"]}}
{"time":"2018-10-24 21:08:20.002895331","vname":"SIE","mname":"dnsdedupe","message":{"type":"EXPIRATION","count":1,"time_first":"2018-10-24 18:46:04","time_last":"2018-10-24 18:46:04","bailiwick":"wilson-benesch.com.","rrname":"www.wilson-benesch.com.","rrclass":"IN","rrtype":"A","rrttl":43200,"rdata":["205.186.183.165"]}}
{"time":"2018-10-24 21:08:20.001818340","vname":"SIE","mname":"dnsdedupe","message":{"type":"INSERTION","count":1,"time_first":"2018-10-24 21:07:12","time_last":"2018-10-24 21:07:12","response_ip":"208.78.71.16","bailiwick":"catsurplus.com.","rrname":"catsurplus.com.","rrclass":"IN","rrtype":"A","rrttl":3600,"rdata":["192.56.231.67"]}}
{"time":"2018-10-24 21:08:20.002917696","vname":"SIE","mname":"dnsdedupe","message":{"type":"EXPIRATION","count":1,"time_first":"2018-10-24 18:46:04","time_last":"2018-10-24 18:46:04","bailiwick":"bjliuti.com.","rrname":"bjliuti.com.","rrclass":"IN","rrtype":"A","rrttl":3600,"rdata":["142.234.57.142"]}}
{"time":"2018-10-24 21:08:20.001835511","vname":"SIE","mname":"dnsdedupe","message":{"type":"INSERTION","count":1,"time_first":"2018-10-24 21:07:15","time_last":"2018-10-24 21:07:15","response_ip":"203.119.95.53","bailiwick":"153.in-addr.arpa.","rrname":"63.242.153.in-addr.arpa.","rrclass":"IN","rrtype":"NS","rrttl":86400,"rdata":["ns-kg001.ocn.ad.jp.","ns-kn001.ocn.ad.jp."]}}
{"time":"2018-10-24 21:08:20.002924021","vname":"SIE","mname":"dnsdedupe","message":{"type":"EXPIRATION","count":1,"time_first":"2018-10-24 18:46:04","time_last":"2018-10-24 18:46:04","bailiwick":"bjliuti.com.","rrname":"bjliuti.com.","rrclass":"IN","rrtype":"NS","rrttl":3600,"rdata":["ns1.dnsdun.com.","ns1.dnsdun.net."]}}
{"time":"2018-10-24 21:08:20.001839669","vname":"SIE","mname":"dnsdedupe","message":{"type":"INSERTION","count":1,"time_first":"2018-10-24 15:00:57","time_last":"2018-10-24 15:00:57","response_ip":"192.12.94.30","bailiwick":"com.","rrname":"gaselys.com.","rrclass":"IN","rrtype":"NS","rrttl":172800,"rdata":["a.ns.mailclub.fr.","b.ns.mailclub.eu.","c.ns.mailclub.com."]}}
{"time":"2018-10-24 21:08:20.002941544","vname":"SIE","mname":"dnsdedupe","message":{"type":"EXPIRATION","count":1,"time_first":"2018-10-24 12:33:26","time_last":"2018-10-24 12:33:26","bailiwick":"whitetriangle.agency.","rrname":"whitetriangle.agency.","rrclass":"IN","rrtype":"A","rrttl":3600,"rdata":["198.185.159.144"]}}
Wrote 10 nmsgs to 213.jsonl-tsindex.7259.json.
~~~

 1. `axa_tsindextool -s 1540415300 -c 10 -j 213.jsonl -f 213.jsonl.mdb -vv`: We invoke the helper tool telling it we want to start at epoch timestamp 1540415300, asking for 10 nmsgs, specify the data file and corresponding timestamp index file, and ask for two levels of
verbosity (which results in the messages being written to stdout in addition to the on-disk file).

### 7. Use sratunnel's Kickfile Feature
Both `sratunnel` and `radtunnel` support a "kicker" feature where it will continuously rotate the output file and optionally run a command on the rotated file. In this mode output file names are suffixed with a timestamp and `{rad,sra}tunnel` runs continuously,
rotating output files as payload counts or time intervals expire.  Optionally, a shell command may be specified to run against files after rotation (if the command is set to an empty string '', then no command is executed and only file rotation is performed).

~~~
$ sratunnel -s sra-dev-apikey -c ch213 -w ch=213 -o nmsg:file_json:213.jsonl -C 100 -k gzip -dd
connecting to apikey:<apikey elided>@axa-1.dev.fsi.io,1011
connected to apikey:<apikey elided>@axa-1.dev.fsi.io,1011
forwarded 100 messages, rotating ./213.jsonl.20181028.2036.1540787796.000962353.jsonl and running gzip
forwarded 100 messages, rotating ./213.jsonl.20181028.2036.1540787798.000101671.jsonl and running gzip
forwarded 100 messages, rotating ./213.jsonl.20181028.2036.1540787798.000344381.jsonl and running gzip
forwarded 100 messages, rotating ./213.jsonl.20181028.2036.1540787798.000727531.jsonl and running gzip
forwarded 100 messages, rotating ./213.jsonl.20181028.2036.1540787799.000129702.jsonl and running gzip
^C
~~~

1. `sratunnel -s sra-apikey -c ch213 -w ch=213 -o nmsg:file_json:213.jsonl -C 100 -k gzip -dd`: We invoked `sratunnel` against channel 213 and asked for the kickfile option to run the `gzip` command on each output file after every 100 watch hits.

## AXA Protocol

The AXA protocol consists of a pair of streams of messages between a subscriber's client (such as `sratool`) and an AXA server (such as SRA), one stream in each direction, currently over a single TCP connection.

AXA must sit on top of a reliable stream protocol such as TCP and so has no provisions to detect or recover from duplicate, out-of-order, lost, or partially lost data. Note that SIE data *can* be lost *before* encapsulation into AXA protocol messages due to issues such as network congestion, CPU overload, etc.

AXA relies on the TLS and TCP protocols to provide authentication, confidentiality, and integrity as shown below.

~~~
[AXA] - SIE message encapsulation
[TLS] - Authentication and encryption
[TCP] - Reliable transport
~~~

The authoritative definition of the AXA protocol is contained in the
[axa/protocol.h](axa/protocol.h) file.

Values that originate in SRA or RAD servers such as message lengths use little endian byte order in the AXA protocol. Other values such as IP addresses and port numbers are big endian for consistency with their sources such as host tables. SRA and RAD data such as nmsg messages and IP packets have their original byte orders.

The stream protocols below the AXA protocol are responsible for authentication and authorization. An AXA client and server pair on a computer can use unadorned TCP through the loop-back interface or use a UNIX domain socket. The AXA protocol assumes this is safe.

The AXA client starts by waiting for an `AXA_P_OP_HELLO` message from the server. Over a local stream, the client then sends an `AXA_P_OP_USER` message to tell the server which parameters to use.

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
| `AXA_P_OP_WHIT`     | 5   | SERVER (SRA)    | YES   | reports a "watch hit" or packet or nmsg message that matched an SRA watch with the same tag   |
| `AXA_P_OP_WLIST`    | 6   | SERVER (SRA)    | YES   | reports a current watch in response to `AXA_P_OP_WGET` from the client referenced by tag      |
| `AXA_P_OP_AHIT`     | 7   | SERVER (RAD)    | YES   | reports an "anomaly hit" or packet or nmsg message detected by a set of anomaly detector      |
| `AXA_P_OP_ALIST`    | 8   | SERVER (RAD)    | YES   | reports a current anomaly detector in response to `AXA_P_OP_AGET`                             |
| `AXA_P_OP_CLIST`    | 9   | SERVER (SRA)    | NO    | reports the on/off state and specification of an SRA channel                                  |
| `AXA_P_OP_USER`     | 129 | CLIENT          | NO    | indicates the AXA protocol is used over a local stream and rejected otherwise                 |
| `AXA_P_OP_JOIN`     | 130 | CLIENT          | NO    | used to bundle TCP connections                                                                |
| `AXA_P_OP_PAUSE`    | 131 | CLIENT          | NO    | ask the server to temporarily stop sending packets or nmsg messages                           |
| `AXA_P_OP_GO`       | 132 | CLIENT          | NO    | ask the server to resume sending packets or nmsg messages                                     |
| `AXA_P_OP_WATCH`    | 133 | CLIENT          | NO    | specify interesting packets or nmsg messages                                                  |
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

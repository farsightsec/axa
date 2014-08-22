/*
 * Tunnel SIE data from an SRA server.
 *
 *  Copyright (c) 2014 by Farsight Security, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <config.h>			/* used only for AXA_PVERS_STR */
#include <axa/client.h>
#include <axa/fields.h>
#include <axa/wire.h>

#include <nmsg.h>
#include <nmsg/base/defs.h>
#include <nmsg/base/packet.pb-c.h>

#include <net/ethernet.h>
#ifdef __linux
#include <netinet/ether.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux
#include <endian.h>
#else
#include <sys/endian.h>
#endif
#include <sysexits.h>
#include <sys/stat.h>
#include <unistd.h>


typedef struct arg arg_t;
struct arg {
	arg_t	*next;
	const char	*c;
};
static arg_t *chs = NULL;
static arg_t *watches = NULL;

static const char *srvr_addr;
static axa_p_user_t user;

static client_t client;			/* Connection to the SRA server. */

static axa_tag_t cur_tag;
static bool first_time;

static bool version;
static int terminated;
static const char *out_addr;
static struct timeval time_out_flush;
#define OUT_FLUSH_MS	10
static struct timeval out_complaint_last;
static bool out_complaint_skipped;
static int out_sock_type;
static pcap_t *out_pcap;
static pcap_dumper_t *out_pcap_dumper;
static int out_fd;
static struct {
	struct ether_addr   dst;
	struct ether_addr   src;
	uint16_t	    etype;
} out_mac;
static uint8_t out_buf[AXA_P_WHIT_IP_MAX*4];
static size_t out_buf_base, out_buf_len;
static nmsg_output_t out_nmsg_output;
static nmsg_msgmod_t out_nmsg_mod = NULL;
static void *out_nmsg_clos;
static bool out_nmsg_mod_checked = false;

static nmsg_input_t nmsg_input;


static void sigterm(int sig);
static void stop(int s) AXA_NORETURN;
static void disconnect(const char *p, ...) AXA_PF(1,2);
static bool out_open(void);
static void out_close(void);
static void out_flush(void);
static void sra_ssh_flush(void);
static void sra_connect(void);
static void sra_forward(void);
static bool srvr_send(axa_tag_t tag, axa_p_op_t op,
		      const void *b, size_t b_len);


static void AXA_NORETURN
usage(void)
{
	axa_error_msg("[-Vd] -s SRA-server [-u user]"
		      " -c channel -w watch -o out-addr\n");
	exit(EX_USAGE);
}

int AXA_NORETURN
main(int argc, char **argv)
{
	arg_t *arg;
	struct pollfd pollfds[2];
	int nfds;
	struct timeval now;
	time_t ms, poll_ms;
	nmsg_res res;
	int i;

	axa_set_core();
	axa_set_me(argv[0]);
	axa_clean_stdio();
	axa_client_init(&client);

	version = false;
	while ((i = getopt(argc, argv, "Vdo:u:s:c:w:")) != -1) {
		switch (i) {
		case 'V':
			version = true;
			break;

		case 'd':
			axa_debug = AXA_DEBUG_TRACE;
			break;

		case 'o':
			out_addr = optarg;
			break;

		case 'u':
			if (strlen(optarg) >= sizeof(user.name)) {
				fprintf(stderr, "user name \"%s\" too long",
					optarg);
			} else {
				strncpy(user.name, optarg, sizeof(user.name));
			}
			break;

		case 's':
			srvr_addr = optarg;
			break;

		case 'c':
			arg = malloc(sizeof(arg_t));
			AXA_ASSERT(arg != NULL);
			arg->c = optarg;
			arg->next = chs;
			chs = arg;
			break;

		case 'w':
			arg = malloc(sizeof(arg_t));
			AXA_ASSERT(arg != NULL);
			arg->c = optarg;
			arg->next = watches;
			watches = arg;
			break;

		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (version) {
		printf("%s "AXA_PVERS_STR" AXA protocol %d\n",
		       axa_prog_name, AXA_P_PVERS);
		if (srvr_addr == NULL && out_addr == NULL
		    && chs == NULL && watches == NULL)
			exit(0);
	}
	if (srvr_addr == NULL || out_addr == NULL
	    || chs == NULL || watches == NULL)
		usage();

	signal(SIGHUP, sigterm);
	signal(SIGTERM, sigterm);
	signal(SIGINT, sigterm);
#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif

	if (!out_open())
		exit(EX_IOERR);

	AXA_DEBUG_TO_NMSG();
	res = nmsg_init();
	if (res != nmsg_res_success)
		fprintf(stderr, "nmsg_init(): %s\n",
			nmsg_res_lookup(res));
	nmsg_input = nmsg_input_open_null();
	AXA_ASSERT(nmsg_input != NULL);

	/*
	 * Continually reconnect to the SRA server and forward SIE data.
	 */
	first_time = true;
	for (;;) {
		client.err_poll_nfd = -1;
		client.in_poll_nfd = -1;
		nfds = 0;

		/* (Re)connect to the SRA server if it is time. */
		gettimeofday(&now, NULL);
		poll_ms = AXA_KEEPALIVE_MS;
		if (client.in_sock < 0) {
			ms = axa_client_again(&client, &now);
			if (ms < 0) {
				sra_connect();
				continue;
			}
			if (poll_ms > ms)
				poll_ms = ms;

		} else {
			/* Flush the output buffer. */
			if (time_out_flush.tv_sec != 0) {
				poll_ms = (OUT_FLUSH_MS - axa_elapsed_ms(&now,
							&time_out_flush));
				/* deal with time jump */
				if (poll_ms < 0 || poll_ms > OUT_FLUSH_MS) {
					out_flush();
					continue;
				}
			}

			/* Send NOPs to check the health of the
			 * link to the SRA server. */
			ms = axa_elapsed_ms(&now, &client.alive);
			if (ms > AXA_KEEPALIVE_MS || ms < 0) {
				srvr_send(AXA_TAG_NONE, AXA_P_OP_NOP, NULL, 0);
				continue;
			}
			ms = AXA_KEEPALIVE_MS - ms;
			if (poll_ms > ms)
				poll_ms = ms;

			memset(pollfds, 0, sizeof(pollfds));
			pollfds[nfds].fd = client.in_sock;
			pollfds[nfds].events = AXA_POLL_IN;
			client.in_poll_nfd = nfds++;

			/* Watch stderr from ssh. */
			if (client.err_sock >= 0) {
				pollfds[nfds].fd = client.err_sock;
				pollfds[nfds].events = AXA_POLL_IN;
				client.err_poll_nfd = nfds++;
			}
		}

		AXA_ASSERT(nfds <= AXA_DIM(pollfds));

		i = poll(pollfds, nfds, poll_ms);
		if (i <= 0) {
			if (terminated != 0)
				stop(terminated);
			if (i < 0 && (errno != EAGAIN
				      && errno != EWOULDBLOCK
				      && errno != EINTR))
				disconnect("poll(): %s\n", strerror(errno));
			continue;
		}

		/* Repeat anything that the ssh process says. */
		if (client.err_poll_nfd >= 0
		    && pollfds[client.err_poll_nfd].revents != 0)
			sra_ssh_flush();

		/* Copy from SRA server to output. */
		if (client.in_poll_nfd >= 0
		    && pollfds[client.in_poll_nfd].revents != 0)
			sra_forward();
	}
}

static void
sigterm(int sig)
{
	terminated = sig;

	signal(sig, SIG_DFL);		/* quit early on repeated signals */
}

static void AXA_NORETURN
stop(int s)
{
	arg_t *arg;

	out_flush();

	/* Free everything when we close to check for memory leaks */
	axa_client_close(&client);
	out_flush();

	if (nmsg_input != NULL)
		nmsg_input_close(&nmsg_input);

	out_close();

	while ((arg = chs) != NULL) {
		chs = arg->next;
		free(arg);
	}
	while ((arg = watches) != NULL) {
		watches = arg->next;
		free(arg);
	}

	exit(s);
}

static void AXA_PF(1,2)
disconnect(const char *p, ...)
{
	va_list args;

	va_start(args, p);
	vfprintf(stderr, p, args);
	va_end(args);

	axa_client_close(&client);
	out_flush();
	axa_client_backoff(&client);
}

static void
out_close(void)
{
	if (out_pcap_dumper != NULL) {
		pcap_dump_close(out_pcap_dumper);
		out_pcap_dumper = NULL;
	}
	if (out_pcap != NULL) {
		pcap_close(out_pcap);
		out_pcap = NULL;
	}
	if (out_nmsg_output != NULL)
		nmsg_output_close(&out_nmsg_output);
	if (out_nmsg_mod != NULL) {
		nmsg_msgmod_fini(out_nmsg_mod, &out_nmsg_clos);
	}

	out_buf_base = out_buf_len = 0;
	time_out_flush.tv_sec = 0;
	out_nmsg_mod = NULL;
	out_nmsg_mod_checked = false;
	out_complaint_last.tv_sec = 0;
	out_complaint_skipped = false;
}

static void
out_flush(void)
{
	nmsg_res res;
	ssize_t wlen;

	if (out_buf_len != 0) {
		wlen = write(out_fd, &out_buf[out_buf_base],
			     out_buf_len - out_buf_base);
		if (wlen < 0) {
			if (errno != EAGAIN
			    && errno != EWOULDBLOCK
			    && errno != EINTR) {
				fprintf(stderr, "write(%s): %s\n",
					out_addr, strerror(errno));
				stop(EX_IOERR);
			}
		} else {
			out_buf_base += wlen;
			if (out_buf_base >= out_buf_len)
				out_buf_base = out_buf_len = 0;
		}
	}

	if (out_nmsg_output != NULL) {
		res = nmsg_output_flush(out_nmsg_output);
		if (res != nmsg_res_success
		    &&  (out_sock_type != SOCK_DGRAM
			 || res != nmsg_res_errno
			 || !AXA_IGNORED_UDP_ERRNO(errno))) {
			fprintf(stderr,
				"nmsg_output_flush(forward): %s\n",
				nmsg_res_lookup(res));
			stop(EX_IOERR);
		}
	}

	time_out_flush.tv_sec = 0;
}

static bool				/* false=cannot open output so exit() */
out_cmd_pcap_file(const char *addr, bool want_fifo)
{
	FILE *f;
	struct stat sb;
	bool have_file, have_fifo;

	if (*addr == '\0')
		return (false);

	if (0 <= stat(addr, &sb)) {
		have_file = true;
		have_fifo = S_ISFIFO(sb.st_mode);
	} else {
		if (errno != ENOENT) {
			fprintf(stderr, "stat(%s): %s\n",
				addr, strerror(errno));
			return (false);
		}
		have_file = false;
		have_fifo = false;
	}

	if (want_fifo && !have_fifo) {
		if (have_file) {
			fprintf(stderr, "\"%s\" exists but is not a FIFO\n",
				addr);
			return (false);
		}
		if (0 > mkfifo(addr, 0600)) {
			fprintf(stderr, "mkfifo(%s): %s\n",
				addr, strerror(errno));
			return (false);
		}
		have_fifo = true;
	}

	/* Create the stdio FILE manually to avoid blocking in the
	 * libpcap fopen() when the file is a pre-existing FIFO. */
	out_fd = open(addr, O_RDWR|O_CREAT|O_TRUNC|O_NONBLOCK|O_CLOEXEC, 0666);
	if (out_fd < 0) {
		fprintf(stderr, "open(%s): %s\n", addr, strerror(errno));
		return (false);
	}

	/* drain old bits from what might be a FIFO */
	if (have_fifo) {
		ssize_t rlen;
		size_t n;

		n = 0;
		for (;;) {
			rlen = read(out_fd, out_buf, sizeof(out_buf));
			if (rlen < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK
				    || errno == EINTR)
					break;
				fprintf(stderr, "read(%s): %s\n",
					addr, strerror(errno));
				return (false);
			}
			if (rlen == 0)
				break;
			if (++n >= (1024*1024)/sizeof(out_buf)) {
				fprintf(stderr,
					"\"%s\" seems to be an active fifo\n",
					addr);
				return (false);
			}
		}
	}

	f = fdopen(out_fd, "w");
	if (f == NULL) {
		fprintf(stderr, "fdopen(%s): %s\n", addr, strerror(errno));
		return (false);
	}
	out_pcap = pcap_open_dead(DLT_RAW, AXA_P_WHIT_IP_MAX);
	if (out_pcap == NULL) {
		fprintf(stderr, "pcap_open_dead() failed\n");
		return (false);
	}
	out_pcap_dumper = pcap_dump_fopen(out_pcap, f);
	if (out_pcap_dumper == NULL) {
		fprintf(stderr, "pcap_dump_open(%s): %s\n",
			addr, pcap_geterr(out_pcap));
		return (false);
	}

	/* Cajole the pcap library into writing its header, but write the
	 * packets themselves to allow non-blocking output to tcpdump. */
	if (0 > pcap_dump_flush(out_pcap_dumper)) {
		fprintf(stderr, "pcap_dump_flush(forward): %s\n",
			pcap_geterr(out_pcap));
		return (false);
	}

	return (true);
}

static bool				/* false=cannot open output so exit() */
out_cmd_pcap_if(const char *ifname)
{
	char ether[32];
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *p;
	int i;

	memset(&out_mac, 0, sizeof(out_mac));
	p = strchr(ifname, '/');
	if (p != NULL) {
		memset(ether, 0, sizeof(ether));
		memcpy(ether, ifname, min(sizeof(ether), p-ifname));
		ifname = p+1;
		if (ether_aton_r(ether, &out_mac.dst) == NULL
		    && ether_hostton(ether, &out_mac.dst) != 0) {
			fprintf(stderr,
				"cannot convert \"%s\" to a MAC address\n",
				ether);
			return (false);
		}
	}
	out_mac.etype = htons(0x800);
	memcpy(out_buf, &out_mac, sizeof(out_mac));

	out_pcap = pcap_create(ifname, errbuf);
	if (out_pcap == NULL) {
		fprintf(stderr, "pcap_create(%s): %s\n", ifname, errbuf);
		return (false);
	}
	i = pcap_activate(out_pcap);
	if (i != 0) {
		fprintf(stderr, "pcap_activate(%s): %s\n",
			ifname, pcap_geterr(out_pcap));
		pcap_close(out_pcap);

		out_pcap = NULL;
		return (false);
	}

	return (true);
}

static bool
out_open(void)
{
	const char *addr;
	struct addrinfo *ai;
	axa_socku_t su;
	int s;
	axa_emsg_t emsg;

	if (AXA_CLITCMP(out_addr, "pcap:"))
		return (out_cmd_pcap_file(out_addr + sizeof("pcap:")-1,
					  false));

	if (AXA_CLITCMP(out_addr, "pcap-fifo:"))
		return (out_cmd_pcap_file(out_addr + sizeof("pcap-fifo:")-1,
					  true));

	if (AXA_CLITCMP(out_addr, "pcap-if:"))
		return (out_cmd_pcap_if(out_addr + sizeof("pcap-if:")-1));

	if (!AXA_CLITCMP(out_addr, "nmsg:")) {
		fprintf(stderr, "unrecognized \"-o %s\"\n", out_addr);
		return (false);
	}

	addr = out_addr + sizeof("nmsg:")-1;
	if (AXA_CLITCMP(addr, "tcp:")) {
		addr += sizeof("tcp:")-1;
		out_sock_type = SOCK_STREAM;
	} else if (AXA_CLITCMP(addr, "udp:")) {
		addr += sizeof("udp:")-1;
		out_sock_type = SOCK_DGRAM;
	} else {
		out_sock_type = SOCK_DGRAM;
	}
	if (*addr == '\0') {
		fprintf(stderr, "invalid pcap output \"%s\"\n", out_addr);
		return (false);
	}

	if (!axa_get_srvr(&emsg, addr, false, &ai)) {
		fprintf(stderr, "%s\n", emsg.c);
		return (false);
	}
	memset(&su, 0, sizeof(su));
	memcpy(&su.sa, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);

	s = socket(su.sa.sa_family, out_sock_type, 0);
	if (s < 0) {
		fprintf(stderr, "socket(%s): %s\n", addr, strerror(errno));
		return (false);
	}

	if (0 > connect(s, &su.sa, AXA_SU_LEN(&su))) {
		fprintf(stderr, "connect(%s): %s\n", addr, strerror(errno));
		close(s);
		return (false);
	}

	if (!axa_set_sock(&emsg, s, addr, false)) {
		fprintf(stderr, "%s\n", emsg.c);
		close(s);
		return (false);
	}

	if (out_sock_type == SOCK_DGRAM) {
		out_nmsg_output = nmsg_output_open_sock(s, NMSG_WBUFSZ_ETHER);
		if (out_nmsg_output == NULL) {
			fprintf(stderr, "nmsg_output_open_sock(%s): failed\n",
				addr);
			close(s);
			return (false);
		}
	} else {
		out_nmsg_output = nmsg_output_open_file(s, NMSG_WBUFSZ_MAX);
		if (out_nmsg_output == NULL) {
			fprintf(stderr, "nmsg_output_open_file(%s) failed\n",
				addr);
			close(s);
			return (false);
		}
	}

	return (true);
}

static void
print_nop(void)
{
	char buf[80];

	if (axa_debug == 0)
		return;

	printf("%s\n", axa_p_to_str(buf, sizeof(buf), true,
				    &client.recv_hdr, client.recv_body));
}

static void
print_error(void)
{
	char buf[1024];

	fprintf(stderr, "%s\n", axa_p_to_str(buf, sizeof(buf), true,
					     &client.recv_hdr,
					     client.recv_body));
}

static void
print_missed(void)
{
	char tag_buf[AXA_TAG_STRLEN];
	char op_buf[AXA_P_OP_STRLEN];
	time_t epoch;
	const axa_p_missed_t *missed;
	char time_buf[32];

	if (axa_debug == 0)
		return;

	missed = &client.recv_body->missed;
	epoch = AXA_P2H32(missed->last_reported);
	strftime(time_buf, sizeof(time_buf), "%Y/%m/%d %T",
		 localtime(&epoch));

	printf("%s %s\n",
	       axa_tag_to_str(tag_buf, sizeof(tag_buf),
			      AXA_P2H16(client.recv_hdr.tag)),
	       axa_op_to_str(op_buf, sizeof(op_buf),
			     client.recv_hdr.op));
	printf("    lost %ld input packets,"
	       " dropped %ld for congestion,\n"
	       "\t%ld for per sec limit,"
	       " %ld for per day limit\n"
	       "\tsince %s\n",
	       AXA_P2H64(missed->input_dropped),
	       AXA_P2H64(missed->dropped),
	       AXA_P2H64(missed->sec_rlimited),
	       AXA_P2H64(missed->day_rlimited),
	       time_buf);
}

/* Send an SRA message to the SRA server */
static bool
srvr_send(axa_tag_t tag, axa_p_op_t op, const void *b, size_t b_len)
{
	axa_p_hdr_t hdr;
	axa_p_send_result_t result;
	size_t done;
	char pbuf[120];
	axa_emsg_t emsg;

	result = axa_p_send(&emsg, client.out_sock, AXA_P_PVERS, tag, op, &hdr,
			    b, b_len, NULL, 0, &done, client.addr,
			    AXA_P_TO_SRA, &client.alive);

	if (result == AXA_P_SEND_OK) {
		if (axa_debug != 0)
			printf("sending %s\n",
			       axa_p_to_str(pbuf, sizeof(pbuf), true, &hdr, b));
		return (true);
	}

	if (first_time || axa_debug != 0) {
		fprintf(stderr, "sending %s failed: %s\n",
		       axa_p_to_str(pbuf, sizeof(pbuf), true, &hdr, b),
		       emsg.c);
	}
	disconnect("%s\n", emsg.c);
	return (false);
}

/* Repeat anything that the ssh process says */
static void
sra_ssh_flush(void)
{
	char ebuf[240];
	int i;

	if (client.err_sock < 0)
		return;

	i = read(client.err_sock, ebuf, sizeof(ebuf));

	if (i > 0) {
		/* Set i = write() and discard i, because GNU gcc says that
		 * ignoring the result from write() is "either a security
		 * problem or always a bug" and casting write() to void
		 * does not prevent the gcc warning. */
		i = write(STDERR_FILENO, ebuf, i);
		return;
	}

	if (i <= 0) {
		if (i < 0 && (errno != EWOULDBLOCK
			      || errno != EAGAIN
			      || errno != EINTR))
			fprintf(stderr, "read(ssh stderr): %s\n",
				strerror(errno));
		close(client.err_sock);
		client.err_sock = -1;
	}
}

/* Send an SRA command to the SRA server and wait for the response. */
static bool				/* false=give up and re-connect */
srvr_cmd(axa_tag_t tag, axa_p_op_t op, const void *b, size_t b_len)
{
	bool result;
	struct pollfd pollfds[2];
	int nfds;
	char buf[1024];
	axa_emsg_t emsg;
	int i;

	if (!srvr_send(tag, op, b, b_len))
		return (false);

	result = false;
	for (;;) {
		memset(pollfds, 0, sizeof(pollfds));
		pollfds[0].fd = client.in_sock;
		pollfds[0].events = AXA_POLL_IN;
		nfds = 1;

		/* Watch stderr from ssh. */
		if (client.err_sock >= 0) {
			pollfds[nfds].fd = client.err_sock;
			pollfds[nfds].events = AXA_POLL_IN;
			client.err_poll_nfd = nfds++;
		} else {
			client.err_poll_nfd = -1;
		}

		i = poll(pollfds, nfds, INFTIM);
		if (i <= 0) {
			if (terminated != 0)
				stop(terminated);
			if (i < 0) {
				disconnect("poll(): %s\n", strerror(errno));
				return (false);
			}
			continue;
		}

		/* Repeat anything that the ssh process says */
		if (client.err_poll_nfd >= 0
		    && pollfds[client.err_poll_nfd].revents != 0) {
			sra_ssh_flush();
			continue;
		}

		if (pollfds[0].revents == 0)
			continue;

		switch (axa_p_recv(&emsg, client.in_sock,
				   &client.recv_hdr,
				   &client.recv_body, &client.recv_len,
				   client.addr,
				   AXA_P_FROM_SRA, &client.alive)) {
		case AXA_P_RECV_RESULT_INCOM:
			continue;
		case AXA_P_RECV_RESULT_ERR:
			if (first_time || axa_debug != 0)
				fprintf(stderr, "%s\n", emsg.c);
			goto out;
		case AXA_P_RECV_RESULT_DONE:
			break;
		default:
			AXA_FAIL("impossible axa_p_recv() result");
		}

		switch ((axa_p_op_t)client.recv_hdr.op) {
		case AXA_P_OP_NOP:
			print_nop();
			break;

		case AXA_P_OP_HELLO:
			axa_client_hello(&client, &client.recv_body->hello);
			if (axa_debug != 0)
				printf("%s\n", axa_p_to_str(buf, sizeof(buf),
							true, &client.recv_hdr,
							client.recv_body));
			result = true;
			goto out;

		case AXA_P_OP_OK:
		case AXA_P_OP_CHANNEL:
			if (axa_debug != 0)
				printf("%s\n", axa_p_to_str(buf, sizeof(buf),
							true, &client.recv_hdr,
							client.recv_body));
			result = true;
			goto out;

		case AXA_P_OP_ERROR:
			if (first_time || axa_debug != 0)
				print_error();
			goto out;

		case AXA_P_OP_MISSED:
			print_missed();
			break;

		case AXA_P_OP_WHIT:
			fprintf(stderr, "unexpected SRA watch hit\n");
			goto out;

		case AXA_P_OP_AHIT:
		case AXA_P_OP_WLIST:
		case AXA_P_OP_ALIST:
		case AXA_P_OP_CLIST:
		case AXA_P_OP_OPT:
			fprintf(stderr, "unexpected %s\n",
				axa_p_to_str(buf, sizeof(buf), false,
					     &client.recv_hdr,
					     client.recv_body));
			goto out;

		case AXA_P_OP_USER:
		case AXA_P_OP_JOIN:
		case AXA_P_OP_PAUSE:
		case AXA_P_OP_GO:
		case AXA_P_OP_WATCH:
		case AXA_P_OP_WGET:
		case AXA_P_OP_ANOM:
		case AXA_P_OP_AGET:
		case AXA_P_OP_STOP:
		case AXA_P_OP_ALL_STOP:
		case AXA_P_OP_CGET:
		case AXA_P_OP_ACCT:
		default:
			AXA_FAIL("impossible SRA op of %d from %s",
				 client.recv_hdr.op, client.addr);
		}

		axa_client_flush(&client);
	}

out:
	axa_client_flush(&client);

	if (!result) {
		axa_client_close(&client);
		out_flush();
		axa_client_backoff(&client);
	}
	return (result);
}

/* (Re)connect to the SRA server */
static void
sra_connect(void)
{
	arg_t *arg;
	axa_p_channel_t channel;
	axa_p_watch_t watch;
	size_t watch_len;
	axa_emsg_t emsg;

	if (!axa_client_open(&emsg, &client, srvr_addr, axa_debug, true)) {
		if (axa_debug != 0 || first_time)
			fprintf(stderr, "%s\n", emsg.c);
		return;
	}

	/* Send a NOP and expect to receive a HELLO from the SRA server.
	 * Our NOP tells the server our version of the AXA protocol. */
	if (!srvr_cmd(AXA_TAG_NONE, AXA_P_OP_NOP, NULL, 0))
		return;

	/* Send user name if known.  It is required when not using ssh. */
	if (user.name[0] != '\0'
	    && !srvr_cmd(AXA_TAG_NONE, AXA_P_OP_USER, &user, sizeof(user)))
		return;

	/* Turn on the channels	*/
	cur_tag = 1;
	for (arg = chs; arg != NULL; arg = arg->next) {
		memset(&channel, 0, sizeof(channel));
		if (!axa_parse_ch(&emsg, &channel.ch, arg->c, strlen(arg->c),
				  true, true)) {
			fprintf(stderr, "\"-c %s\": %s\n",
				arg->c, emsg.c);
			exit(EX_USAGE);
		}

		channel.on = 1;
		if (!srvr_cmd(++cur_tag, AXA_P_OP_CHANNEL,
			       &channel, sizeof(channel)))
			return;
	}

	/* Then start the watches. */
	for (arg = watches; arg != NULL; arg = arg->next) {
		if (!axa_parse_watch(&emsg, &watch, &watch_len,
				     arg->c)) {
			if (emsg.c[0] == '\0') {
				fprintf(stderr, "unrecognized \"-w %s\"",
					arg->c);
			} else {
				fprintf(stderr, "\"-w %s\": %s\n",
					arg->c, emsg.c);
			}
			exit(EX_USAGE);
		}

		if (!srvr_cmd(++cur_tag, AXA_P_OP_WATCH, &watch, watch_len))
			return;
	}

	/* Reset connection back-off after last watch has been started. */
	client.backoff = 0;
}

/* Create nmsg message from incoming watch hit containing a nmsg message */
static void
whit2nmsg(nmsg_message_t *msgp, axa_p_whit_t *whit, size_t whit_len)
{
	axa_emsg_t emsg;

	if (!axa_whit2nmsg(&emsg, nmsg_input, msgp, whit, whit_len)) {
		fprintf(stderr, "%s\n", emsg.c);
		stop(EX_IOERR);
	}
}

static bool
out_error_ok(void)
{
	struct timeval now;
	time_t ms;

	gettimeofday(&now, NULL);
	ms = axa_tv_diff2ms(&now, &out_complaint_last);

	/* allow a new complaint every 5 seconds */
	 if (ms < 0 || ms > 5000)
		 return (true);

	 /* count skipped complaints */
	 out_complaint_skipped = true;
	 return (false);
}

static void AXA_PF(1,2)
out_error(const char *p, ...)
{
	va_list args;

	if (!out_error_ok())
		return;

	if (out_complaint_skipped) {
		fputs("...", stderr);
		out_complaint_skipped = false;
	}
	va_start(args, p);
	vfprintf(stderr, p, args);
	va_end(args);
	fputc('\n', stderr);

	gettimeofday(&out_complaint_last, NULL);
}


/* forward watch hits as nmsg messages */
static void
out_whit_nmsg(axa_p_whit_t *whit, size_t whit_len)
{
	nmsg_message_t msg;
	struct timespec ts;
	static const union {
		uint    e;
		uint8_t	c[0];
	} pkt_enum = { .e = NMSG__BASE__PACKET_TYPE__IP };
	size_t len;
	nmsg_res res;

	switch ((axa_p_whit_enum_t)whit->hdr.type) {
	case AXA_P_WHIT_NMSG:
		/* pass nmsg messages along */
		whit2nmsg(&msg, whit, whit_len);
		break;

	case AXA_P_WHIT_IP:
		/* Convert raw IP packets to nmsg BASE_PACKET */
		len = whit_len - sizeof(whit->ip.hdr);
		if (whit->ip.hdr.orig_len != len)
			return;		/* Ignore incomplete packets. */

		if (!out_nmsg_mod_checked) {
			out_nmsg_mod_checked = true;
			out_nmsg_mod = nmsg_msgmod_lookup(NMSG_VENDOR_BASE_ID,
						NMSG_VENDOR_BASE_PACKET_ID);
			if (out_nmsg_mod == NULL) {
				out_error("cannot get BASE_PACKET module");
				return;
			}
			res = nmsg_msgmod_init(out_nmsg_mod, &out_nmsg_clos);
			if (res != nmsg_res_success) {
				out_error("cannot init BASE_PACKET module");
				out_nmsg_mod = NULL;
				return;
			}
		}
		if (out_nmsg_mod == NULL) {
			out_error("cannot forward IP as nmsg messages"
				  " without PACKET nmsg_msgmod");
			return;
		}

		msg = nmsg_message_init(out_nmsg_mod);
		AXA_ASSERT(msg != NULL);
		res = nmsg_message_set_field(msg, "payload_type", 0,
					     pkt_enum.c, sizeof(pkt_enum));
		AXA_ASSERT(res == nmsg_res_success);
		res = nmsg_message_set_field(msg, "payload", 0,
					     whit->ip.b, len);
		AXA_ASSERT(res == nmsg_res_success);
		ts.tv_sec = AXA_P2H32(whit->ip.hdr.ts.tv_sec);
		ts.tv_nsec = AXA_P2H32(whit->ip.hdr.ts.tv_usec) * 1000;
		nmsg_message_set_time(msg, &ts);
		break;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		out_error("cannot forward SRA #%d messages as nmsg messages",
			  whit->hdr.type);
		return;
#pragma clang diagnostic pop
	}

	res = nmsg_output_write(out_nmsg_output, msg);
	if (res != nmsg_res_success
	    &&  (out_sock_type != SOCK_DGRAM
		 || res != nmsg_res_errno
		 || !AXA_IGNORED_UDP_ERRNO(errno))) {
		fprintf(stderr, "nmsg_output_write(): %s\n",
			nmsg_res_lookup(res));
		stop(EX_IOERR);
	}

	nmsg_message_destroy(&msg);
	if (time_out_flush.tv_sec == 0)
		gettimeofday(&time_out_flush, NULL);
}

static void
out_ip_pcap_file(const uint8_t *pkt, size_t caplen, size_t len,
		 const struct timeval *tv)
{
	/* From pcap-int.h, which is not present on some systems,
	 * and written in the stone of uncounted saved pcap files. */
	struct {
		struct {
			int32_t	    tv_sec;
			int32_t	    tv_usec;
		} ts;			/* time stamp */
		bpf_u_int32 caplen;	/* length of portion present */
		bpf_u_int32 len;	/* length this packet (off wire) */
	} sf_hdr;

	if (caplen > sizeof(out_buf) - sizeof(sf_hdr) - out_buf_len
	    || out_buf_base != 0) {
		out_flush();
		if (caplen > sizeof(out_buf) - sizeof(sf_hdr) - out_buf_len) {
			out_error("forwarding output stalled; dropping");
			return;
		}
	}

	/* Use the official version of struct pcap_sf_pkthdr and hope
	 * even the "experts" with "patched" versions can handle the
	 * standard form. */
	sf_hdr.ts.tv_sec = tv->tv_sec;
	sf_hdr.ts.tv_usec = tv->tv_usec;
	sf_hdr.caplen = caplen;
	sf_hdr.len = len;

	memcpy(&out_buf[out_buf_len], &sf_hdr, sizeof(sf_hdr));
	out_buf_len += sizeof(sf_hdr);
	memcpy(&out_buf[out_buf_len], pkt, caplen);
	out_buf_len += caplen;
	if (time_out_flush.tv_sec == 0)
		gettimeofday(&time_out_flush, NULL);
}

static void
out_ip_pcap_inject(const uint8_t *pkt, size_t caplen)
{
	AXA_ASSERT(caplen < sizeof(out_buf) - sizeof(out_mac));

	memcpy(&out_buf[sizeof(out_mac)], pkt, caplen);

	if (0 > pcap_inject(out_pcap, out_buf, caplen)) {
		fprintf(stderr, "failed to inject packet onto %s: %s\n",
			out_addr, pcap_geterr(out_pcap));
		stop(EX_IOERR);
	}
}

/* forward watch hits in a pcap stream */
static void
out_whit_pcap(axa_p_whit_t *whit, size_t whit_len)
{
	struct timeval tv;
	uint8_t *pkt;
	size_t len, caplen;
	struct timespec ts;
	nmsg_message_t msg;
	uint vid, msgtype;
	const char *vid_str, *msgtype_str;
	const Nmsg__Base__Packet *packet;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	pkt = NULL;
	caplen = 0;
	len = 0;
	switch ((axa_p_whit_enum_t)whit->hdr.type) {
	case AXA_P_WHIT_IP:
		if (whit_len <= sizeof(whit->ip)) {
			fprintf(stderr, "truncated IP packet\n");
			stop(EX_IOERR);
		}
		tv.tv_sec = AXA_P2H32(whit->ip.hdr.ts.tv_sec);
		tv.tv_usec = AXA_P2H32(whit->ip.hdr.ts.tv_usec);
		pkt = whit->ip.b;
		caplen = whit_len - sizeof(whit->ip.hdr);
		len = whit->ip.hdr.orig_len;
		break;

	case AXA_P_WHIT_NMSG:
		whit2nmsg(&msg, whit, whit_len);
		vid = nmsg_message_get_vid(msg);
		msgtype = nmsg_message_get_msgtype(msg);
		if (vid != NMSG_VENDOR_BASE_ID
		    || msgtype != NMSG_VENDOR_BASE_PACKET_ID) {
			if (!out_error_ok()) {
				vid_str = nmsg_msgmod_vid_to_vname(vid);
				msgtype_str = nmsg_msgmod_msgtype_to_mname(vid,
							msgtype);
				out_error("cannot forward nmsg %s %s"
					  " messages via pcap",
					  vid_str, msgtype_str);
				return;
			}
		}

		/* forward the IP packets in BASE_PACKET */
		packet = (Nmsg__Base__Packet *)nmsg_message_get_payload(msg);
		if (packet == NULL)
			break;
		if (packet->payload_type != NMSG__BASE__PACKET_TYPE__IP)
			break;
		nmsg_message_get_time(msg, &ts);
		tv.tv_sec = ts.tv_sec;
		tv.tv_usec = ts.tv_nsec / 1000;
		pkt = packet->payload.data;
		caplen = packet->payload.len;
		len = packet->payload.len;
		break;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		out_error("cannot forward watch hits type #%d", whit->hdr.type);
		return;
#pragma clang diagnostic pop
	}

	if (out_pcap_dumper != NULL)
		out_ip_pcap_file(pkt, caplen, len, &tv);
	else
		out_ip_pcap_inject(pkt, caplen);
}

/* Forward from the SRA server to the output */
static void
sra_forward(void)
{
	axa_p_whit_t *whit;
	size_t whit_len;
	char buf[1024];
	axa_emsg_t emsg;

	switch (axa_p_recv(&emsg, client.in_sock, &client.recv_hdr,
			   &client.recv_body, &client.recv_len,
			   client.addr,
			   AXA_P_FROM_SRA, &client.alive)) {
	case AXA_P_RECV_RESULT_INCOM:
		return;
	case AXA_P_RECV_RESULT_ERR:
		disconnect("%s\n", emsg.c);
		return;
	case AXA_P_RECV_RESULT_DONE:
		break;
	default:
		AXA_FAIL("impossible axa_p_recv() result");
	}

	switch ((axa_p_op_t)client.recv_hdr.op) {
	case AXA_P_OP_NOP:
		print_nop();
		break;

	case AXA_P_OP_ERROR:
		print_error();
		axa_client_close(&client);
		out_flush();
		axa_client_backoff(&client);
		return;

	case AXA_P_OP_MISSED:
		print_missed();
		break;

	case AXA_P_OP_WHIT:
		whit = &client.recv_body->whit;
		whit_len = client.recv_len - sizeof(client.recv_hdr);
		if (out_nmsg_output != NULL) {
			out_whit_nmsg(whit, whit_len);
		} else {
			AXA_ASSERT(out_pcap != NULL);
			out_whit_pcap(whit, whit_len);
		}
		break;

	case AXA_P_OP_OK:
	case AXA_P_OP_HELLO:
	case AXA_P_OP_AHIT:
	case AXA_P_OP_WLIST:
	case AXA_P_OP_ALIST:
	case AXA_P_OP_OPT:
	case AXA_P_OP_CLIST:
		fprintf(stderr, "unexpected %s\n",
			axa_p_to_str(buf, sizeof(buf), false,
				     &client.recv_hdr,
				     client.recv_body));
		break;

	case AXA_P_OP_USER:
	case AXA_P_OP_JOIN:
	case AXA_P_OP_PAUSE:
	case AXA_P_OP_GO:
	case AXA_P_OP_WATCH:
	case AXA_P_OP_WGET:
	case AXA_P_OP_ANOM:
	case AXA_P_OP_AGET:
	case AXA_P_OP_STOP:
	case AXA_P_OP_ALL_STOP:
	case AXA_P_OP_CHANNEL:
	case AXA_P_OP_CGET:
	case AXA_P_OP_ACCT:
	default:
		AXA_FAIL("impossible SRA op of %d from %s",
			 client.recv_hdr.op, client.addr);
	}

	axa_client_flush(&client);
}

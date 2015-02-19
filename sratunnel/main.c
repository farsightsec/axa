/*
 * Tunnel SIE data from an SRA or RAD server.
 *
 *  Copyright (c) 2014-2015 by Farsight Security, Inc.
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

#include <config.h>
#include <axa/client.h>
#include <axa/axa_endian.h>
#include <axa/fields.h>
#include <axa/open_nmsg_out.h>

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
#include <sysexits.h>
#include <sys/stat.h>
#include <unistd.h>


static uint axa_debug;

typedef struct arg arg_t;
struct arg {
	arg_t		*next;
	const char	*c;
};
static arg_t *chs = NULL;
static arg_t *watches = NULL;
static arg_t *anomalies = NULL;
static int trace = 0;
static axa_cnt_t rlimit = 0;

static const char *srvr_addr;

static axa_client_t client;		/* Connection to the server. */

static bool counting = false;
static int count, initial_count;

static bool out_bar_on = false;
static const char *out_bar_strs[] = {
	"|\b", "/\b", "-\b", "\\\b", "|\b", "/\b", "-\b", "\\\b"
};
static uint out_bar_idx;
#define PROGESS_MS (1000/AXA_DIM(out_bar_strs))	/* 2 revolutions/second */
static struct timeval out_bar_time;

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
static int out_pcap_datalink;
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

typedef enum {SRA, RAD} axa_mode_t;
static axa_mode_t mode;



static void sigterm(int sig);
static void stop(int s) AXA_NORETURN;
static void disconnect(bool complain, const char *p, ...) AXA_PF(2,3);
static bool out_open(void);
static void out_close(void);
static void out_flush(void);
static void srvr_connect(void);
static void forward(void);
static bool srvr_send(axa_tag_t tag, axa_p_op_t op,
		      const void *b, size_t b_len);


static void AXA_NORETURN
usage(const char *msg)
{
	const char *cmn = ("[-VdtOR] [-C count] [-r rate-limit]"
				 " [-E ciphers] [-S certs]\n");
	const char *sra =("    -s [user@]SRA-server -w watch -c channel"
				 " -o out-addr");
	const char *rad =("    -s [user@]RAD-server -w watch"
				  " -a anomaly -o out-addr");

	if (msg != NULL)
		axa_error_msg("%s", msg);
	axa_error_msg("%s%s", cmn, mode == RAD ? rad : sra);
	exit(EX_USAGE);
}

int
main(int argc, char **argv)
{
	arg_t *arg;
	struct timeval now;
	time_t ms;
	nmsg_res res;
	axa_emsg_t emsg;
	char *p;
	const char *cp;
	int i;

	axa_set_me(argv[0]);
	AXA_ASSERT(axa_parse_log_opt(&emsg, "trace,off,stdout"));
	AXA_ASSERT(axa_parse_log_opt(&emsg, "error,off,stderr"));
	axa_syslog_init();
	axa_clean_stdio();
	axa_set_core();
	axa_client_backoff_reset(&client);
	axa_client_init(&client);

	if (strcmp(axa_prog_name, "radtunnel") == 0)
		mode = RAD;

	version = false;
	while ((i = getopt(argc, argv, "VdtORC:r:E:S:o:s:c:w:a:")) != -1) {
		switch (i) {
		case 'V':
			version = true;
			break;

		case 'd':
			++axa_debug;
			break;

		case 't':
			++trace;
			break;

		case 'O':
			out_bar_on = true;
			break;

		case 'o':
			out_addr = optarg;
			break;

		case 'R':
			mode = RAD;
			break;

		case 'C':
			count = strtoul(optarg, &p, 10);
			if (*optarg == '\0'
			    || *p != '\0'
			    || count < 1) {
				axa_error_msg("invalid \"-C %s\"", optarg);
				exit(EX_USAGE);
			}
			initial_count = count;
			counting = true;
			break;

		case 'r':
			rlimit = strtoul(optarg, &p, 10);
			if (*optarg == '\0'
			    || *p != '\0'
			    || rlimit < 1 || rlimit > AXA_RLIMIT_MAX) {
				axa_error_msg("invalid \"-r %s\"", optarg);
				exit(EX_USAGE);
			}
			break;

		case 'E':
			if (axa_tls_cipher_list(&emsg, optarg) == NULL)
				axa_error_msg("%s", emsg.c);
			break;

		case 'S':
			if (!axa_tls_certs_dir(&emsg, optarg))
				axa_error_msg("%s", emsg.c);
			break;

		case 's':
			srvr_addr = optarg;
			break;

		case 'c':
			arg = AXA_SALLOC(arg_t);
			arg->c = optarg;
			arg->next = chs;
			chs = arg;
			break;

		case 'w':
			arg = AXA_SALLOC(arg_t);
			arg->c = optarg;
			arg->next = watches;
			watches = arg;
			break;

		case 'a':
			arg = AXA_SALLOC(arg_t);
			arg->c = optarg;
			arg->next = anomalies;
			anomalies = arg;
			break;

		default:
			usage(NULL);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage(argv[0]);

	if (version) {
		axa_trace_msg(AXA_PVERS_STR" AXA protocol %d", AXA_P_PVERS);
		if (srvr_addr == NULL && out_addr == NULL
		    && chs == NULL && watches == NULL
		    && anomalies == NULL)
			exit(0);
	}
	if (srvr_addr == NULL)
		usage("server not specified with -s");
	if (out_addr == NULL)
		usage("output not specifed with -o");
	if (watches == NULL)
		usage("no watches specified with -w");
	if (mode == RAD) {
		if (anomalies == NULL)
			usage("anomalies specified with -a");
		if (chs != NULL) {
			axa_error_msg("\"-c %s\" not allowed with -R", chs->c);
			while ((arg = chs) != NULL) {
				chs = arg->next;
				free(arg);
			}
		}
	} else {
		if (anomalies != NULL) {
			axa_error_msg("\"-a %s\" not allowed without -R",
				      anomalies->c);
			while ((arg = anomalies) != NULL) {
				anomalies = arg->next;
				free(arg);
			}
		}
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, sigterm);
	signal(SIGTERM, sigterm);
	signal(SIGINT, sigterm);
#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif

	if (!out_open())
		exit(EX_IOERR);

	AXA_DEBUG_TO_NMSG(axa_debug);
	res = nmsg_init();
	if (res != nmsg_res_success) {
		axa_error_msg("nmsg_init(): %s", nmsg_res_lookup(res));
		exit(EX_SOFTWARE);
	}
	nmsg_input = nmsg_input_open_null();
	AXA_ASSERT(nmsg_input != NULL);

	/*
	 * Continually reconnect to the SRA or RAD server and forward SIE data.
	 */
	first_time = true;
	for (;;) {
		if (terminated != 0)
			stop(terminated);

		/* (Re)connect to the server if it is time. */
		if (!AXA_CLIENT_CONNECTED(&client)) {
			ms = axa_client_again(&client, &now);
			if (ms <= 0) {
				srvr_connect();
			} else {
				if (axa_debug != 0
				    && (ms >= 100
					|| axa_debug >= AXA_DEBUG_TRACE))
					axa_trace_msg("delaying %.1f"
						      " seconds to re-connect",
						      ms/1000.0);
				usleep(ms*1000);
			}
			continue;
		}

		/* Flush the output buffer after silence. */
		gettimeofday(&now, NULL);
		if (time_out_flush.tv_sec != 0) {
			ms = (OUT_FLUSH_MS - axa_elapsed_ms(&now,
							&time_out_flush));
			if (ms <= 0) {
				out_flush();
				continue;
			}
		}

		switch (axa_io_wait(&emsg, &client.io, OUT_FLUSH_MS,
				    true, true)) {
		case AXA_IO_ERR:
			disconnect(true, "%s", emsg.c);
			break;
		case AXA_IO_TUNERR:
			for (;;) {
				cp = axa_io_tunerr(&client.io);
				if (cp == NULL)
					break;
				axa_error_msg("%s", cp);
			}
			break;
		case AXA_IO_BUSY:
			break;
		case AXA_IO_KEEPALIVE:
			srvr_send(AXA_TAG_NONE, AXA_P_OP_NOP, NULL, 0);
			continue;
		case AXA_IO_OK:
			/* Process a message from the server. */
			forward();
			break;
		default:
			AXA_FAIL("impossible axa_client_recv() result");
		}
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

	/* Free everything when we quit to check for memory leaks */

	axa_client_close(&client);
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
	while ((arg = anomalies) != NULL) {
		anomalies = arg->next;
		free(arg);
	}

	axa_io_cleanup();

	exit(s);
}

static void AXA_PF(2,3)
disconnect(bool complain, const char *p, ...)
{
	va_list args;

	if (complain) {
		va_start(args, p);
		axa_verror_msg(p, args);
		va_end(args);
	}

	out_flush();
	axa_client_backoff(&client);
}

static void
out_close(void)
{
	out_flush();

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
				axa_error_msg("write(%s): %s",
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
			axa_error_msg("nmsg_output_flush(forward): %s",
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
			axa_error_msg("stat(%s): %s", addr, strerror(errno));
			return (false);
		}
		have_file = false;
		have_fifo = false;
	}

	if (want_fifo && !have_fifo) {
		if (have_file) {
			axa_error_msg("\"%s\" exists but is not a FIFO", addr);
			return (false);
		}
		if (0 > mkfifo(addr, 0600)) {
			axa_error_msg("mkfifo(%s): %s", addr, strerror(errno));
			return (false);
		}
		have_fifo = true;
	}

	/* Create the stdio FILE manually to avoid blocking in the
	 * libpcap fopen() when the file is a pre-existing FIFO. */
	out_fd = open(addr, O_RDWR|O_CREAT|O_TRUNC|O_NONBLOCK|O_CLOEXEC, 0666);
	if (out_fd < 0) {
		axa_error_msg("open(%s): %s", addr, strerror(errno));
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
				axa_error_msg("read(%s): %s",
					      addr, strerror(errno));
				return (false);
			}
			if (rlen == 0)
				break;
			if (++n >= (1024*1024)/sizeof(out_buf)) {
				axa_error_msg("\"%s\""
					      " seems to be an active fifo",
					      addr);
				return (false);
			}
		}
	}

	f = fdopen(out_fd, "w");
	if (f == NULL) {
		axa_error_msg("fdopen(%s): %s", addr, strerror(errno));
		return (false);
	}
	out_pcap = pcap_open_dead(DLT_RAW, AXA_P_WHIT_IP_MAX);
	if (out_pcap == NULL) {
		axa_error_msg("pcap_open_dead() failed");
		return (false);
	}
	out_pcap_dumper = pcap_dump_fopen(out_pcap, f);
	if (out_pcap_dumper == NULL) {
		axa_error_msg("pcap_dump_open(%s): %s",
			      addr, pcap_geterr(out_pcap));
		return (false);
	}

	/* Cajole the pcap library into writing its header, but write the
	 * packets themselves to allow non-blocking output to tcpdump. */
	if (0 > pcap_dump_flush(out_pcap_dumper)) {
		axa_error_msg("pcap_dump_flush(forward): %s",
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
	const struct ether_addr *eaddr;
	const char *p;
	int i;

	memset(&out_mac, 0, sizeof(out_mac));
	p = strchr(ifname, '/');
	memset(ether, 0, sizeof(ether));
	if (p != NULL) {
		memcpy(ether, ifname, min(sizeof(ether), (size_t)(p-ifname)));
		ifname = p+1;
	}

	out_pcap = pcap_create(ifname, errbuf);
	if (out_pcap == NULL) {
		axa_error_msg("pcap_create(%s): %s", ifname, errbuf);
		return (false);
	}
	i = pcap_activate(out_pcap);
	if (i != 0) {
		axa_error_msg("pcap_activate(%s): %s",
			      ifname, pcap_geterr(out_pcap));
		pcap_close(out_pcap);

		out_pcap = NULL;
		return (false);
	}
	out_pcap_datalink = pcap_datalink(out_pcap);
	switch (out_pcap_datalink) {
	case DLT_EN10MB:
		if (ether[0] != '\0') {
			/* ether_aton_r() is not available on all systems,
			 * and ether_aton() is safe here. */
			eaddr = ether_aton(ether);
			if (eaddr != NULL) {
				out_mac.dst = *eaddr;
			} else if (ether_hostton(ether, &out_mac.dst) != 0) {
				axa_error_msg("cannot convert \"%s\""
					      " to an address;"
					      " using 0:0:0:0:0:0",
					  ether);
				memset(&out_mac, 0, sizeof(out_mac));
			}
		}
		out_mac.etype = htons(0x800);
		memcpy(out_buf, &out_mac, sizeof(out_mac));
		out_buf_base = sizeof(out_mac);
		break;
	case DLT_NULL:
	case DLT_LOOP:
		if (ether[0] != '\0')
			axa_error_msg("ignoring MAC address \"%s\""
				      " for loopback interface %s",
				      ether, ifname);
		out_buf_base = sizeof(uint32_t);
		break;
	default:
		axa_error_msg("cannot output to %s"
			      " with unknown datalink type %d",
			      ifname, out_pcap_datalink);
		pcap_close(out_pcap);
		return (false);
	}

	return (true);
}

static bool
out_open(void)
{
	axa_emsg_t emsg;

	if (AXA_CLITCMP(out_addr, "pcap:"))
		return (out_cmd_pcap_file(strchr(out_addr, ':')+1, false));

	if (AXA_CLITCMP(out_addr, "pcap-fifo:"))
		return (out_cmd_pcap_file(strchr(out_addr, ':')+1, true));

	if (AXA_CLITCMP(out_addr, "pcap-if:"))
		return (out_cmd_pcap_if(strchr(out_addr, ':')+1));

	if (!AXA_CLITCMP(out_addr, "nmsg:")) {
		axa_error_msg("unrecognized output type in \"-o %s\"",
			      out_addr);
		return (false);
	}

	if (0 >= axa_open_nmsg_out(&emsg, &out_nmsg_output, &out_sock_type,
				   strchr(out_addr, ':')+1)) {
		axa_error_msg("%s", emsg.c);
		return (false);
	}
	return (true);
}

static void
print_op(bool always, bool sent, const axa_p_hdr_t *hdr, const void *body)
{
	char buf[AXA_P_STRLEN];

	if (always || axa_debug >= AXA_DEBUG_TRACE)
		axa_trace_msg("%s %s",
			      sent ? "send" : "recv",
			      axa_p_to_str(buf, sizeof(buf), true, hdr, body));
}

static void
print_bad_op(const char *adj)
{
	char buf[AXA_P_STRLEN];

	axa_error_msg("recv %s%s", adj,
		      axa_p_to_str(buf, sizeof(buf), true,
				   &client.io.recv_hdr, client.io.recv_body));
}

static void
print_trace(void)
{
	char buf[AXA_P_STRLEN];

	if (axa_debug > 0 || trace > 0)
		axa_trace_msg("%s", axa_p_to_str(buf,
						 sizeof(buf), false,
						 &client.io.recv_hdr,
						 client.io.recv_body));
}

static void
print_missed(void)
{
	char buf[AXA_P_STRLEN];

	if (axa_debug == 0)
		return;

	axa_p_to_str(buf, sizeof(buf), true,
		     &client.io.recv_hdr,
		     client.io.recv_body);
	axa_trace_msg("%s\n",
		      axa_p_to_str(buf, sizeof(buf), true,
				   &client.io.recv_hdr, client.io.recv_body));
}

/* Send an AXA message to the server */
static bool
srvr_send(axa_tag_t tag, axa_p_op_t op, const void *body, size_t body_len)
{
	axa_p_hdr_t hdr;
	char pbuf[AXA_P_STRLEN];
	axa_emsg_t emsg;

	if (axa_client_send(&emsg, &client, tag, op, &hdr, body, body_len)) {
		print_op(false, true, &hdr, body);
		return (true);
	}

	disconnect(first_time || axa_debug != 0,
		   "sending %s failed: %s",
		   axa_p_to_str(pbuf, sizeof(pbuf), true, &hdr, body),
		   emsg.c);
	return (false);
}

/* Wait for a response from the server. */
static bool				/* false=give up and re-connect */
srvr_wait_resp(axa_p_op_t resp_op,	/* look for this response */
	       axa_p_op_t orig_op)	/* to this */
{
	bool result, done;
	const char *cp;
	axa_emsg_t emsg;

	result = false;
	done = false;
	do {
		if (terminated != 0)
			stop(terminated);

		switch (axa_input(&emsg, &client.io, INT_MAX)) {
		case AXA_IO_ERR:
			if (first_time || axa_debug != 0)
				axa_error_msg("%s", emsg.c);
			goto out;
		case AXA_IO_TUNERR:
			for (;;) {
				cp = axa_io_tunerr(&client.io);
				if (cp == NULL)
					break;
				axa_error_msg("%s", cp);
			}
			continue;
		case AXA_IO_BUSY:
			continue;
		case AXA_IO_KEEPALIVE:
			if (!srvr_send(AXA_TAG_NONE, AXA_P_OP_NOP, NULL, 0))
				return (false);
			continue;
		case AXA_IO_OK:
			/* Process a message from the server. */
			break;
		default:
			AXA_FAIL("impossible axa_client_recv() result");
		}

		switch ((axa_p_op_t)client.io.recv_hdr.op) {
		case AXA_P_OP_NOP:
			print_op(false, false,
				 &client.io.recv_hdr, client.io.recv_body);
			break;

		case AXA_P_OP_HELLO:
			if (!axa_client_hello(&emsg, &client, NULL)) {
				axa_error_msg("%s", emsg.c);
			} else {
				print_op(false, false,
					 &client.io.recv_hdr,
					 client.io.recv_body);
			}
			break;

		case AXA_P_OP_OPT:
			if (resp_op == client.io.recv_hdr.op) {
				print_op(false, false,
					 &client.io.recv_hdr,
					 client.io.recv_body);
				result = true;
			} else {
				print_bad_op("unexpected ");
			}
			done = true;
			break;

		case AXA_P_OP_OK:
			if (resp_op == client.io.recv_hdr.op
			    && orig_op == client.io.recv_body->result.orig_op) {
				print_op(false, false,
					 &client.io.recv_hdr,
					 client.io.recv_body);
				result = true;
				done = true;
			} else if (client.io.recv_body->result.orig_op
				   == AXA_P_OP_OK) {
				print_trace();
			} else {
				print_bad_op("unexpected ");
			}
			break;

		case AXA_P_OP_ERROR:
			print_op(first_time, false,
				 &client.io.recv_hdr, client.io.recv_body);
			done = true;
			break;

		case AXA_P_OP_MISSED:
		case AXA_P_OP_MISSED_RAD:
			print_missed();
			break;

		case AXA_P_OP_WHIT:
		case AXA_P_OP_AHIT:
		case AXA_P_OP_WLIST:
		case AXA_P_OP_ALIST:
		case AXA_P_OP_CLIST:
			print_bad_op("unexpected ");
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
			AXA_FAIL("impossible AXA op of %d from %s",
				 client.io.recv_hdr.op, client.io.label);
		}

		axa_recv_flush(&client.io);
	} while (!done);

out:
	if (!result) {
		/* Disconnect for now if we failed to get the right response. */
		out_flush();
		axa_client_backoff(&client);
	}
	return (result);
}

/* Send an AXA command to the server and wait for the response. */
static bool				/* false=give up and re-connect */
srvr_cmd(axa_tag_t tag, axa_p_op_t op, const void *b, size_t b_len,
	 axa_p_op_t resp_op)
{
	if (!srvr_send(tag, op, b, b_len)) {
		axa_client_backoff(&client);
		return (false);
	}

	return (srvr_wait_resp(resp_op, op));
}

/* (Re)connect to the server */
static void
srvr_connect(void)
{
	arg_t *arg;
	axa_p_opt_t opt;
	axa_p_watch_t watch;
	size_t watch_len;
	axa_p_channel_t channel;
	axa_p_anom_t anom;
	size_t anom_len;
	axa_emsg_t emsg;
	bool res;

	if (axa_debug != 0)
		axa_trace_msg("connecting to %s", srvr_addr);
	switch (axa_client_open(&emsg, &client, srvr_addr, mode == RAD,
				axa_debug > AXA_DEBUG_TRACE,
				256*1024, false)) {
	case AXA_CONNECT_ERR:
		if (axa_debug != 0 || first_time)
			axa_error_msg("%s", emsg.c);
		exit(EX_USAGE);
	case AXA_CONNECT_TEMP:
		disconnect(axa_debug != 0 || first_time,
			   "%s", emsg.c);
		return;			/* Try again after a non-fatal error. */
	case AXA_CONNECT_DONE:
		break;
	case AXA_CONNECT_INCOM:
		AXA_FAIL("impossible result from axa_client_open");
	case AXA_CONNECT_NOP:
		if (axa_debug >= AXA_DEBUG_TRACE)
			axa_trace_msg("send %s", emsg.c);
		break;
	case AXA_CONNECT_USER:
		if (axa_debug >= AXA_DEBUG_TRACE)
			axa_trace_msg("send %s", emsg.c);
		if (!srvr_wait_resp(AXA_P_OP_OK, AXA_P_OP_USER))
			return;
		break;
	}

	/* Immediately start server tracing to log the tunnel commands. */
	if (trace != 0) {
		memset(&opt, 0, sizeof(opt));
		opt.type = AXA_P_OPT_TRACE;
		opt.u.trace = AXA_H2P32(trace);
		if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_OPT, &opt,
			      sizeof(opt) - sizeof(opt.u)
			      + sizeof(opt.u.trace),
			      AXA_P_OP_OK))
			return;
	}

	/* Set the rate limit. */
	if (rlimit != 0) {
		memset(&opt, 0, sizeof(opt));
		opt.type = AXA_P_OPT_RLIMIT;
		opt.u.rlimit.max_pkts_per_sec = AXA_H2P64(rlimit);
		opt.u.rlimit.report_secs = AXA_H2P64(AXA_RLIMIT_NA);
		opt.u.rlimit.cur_pkts_per_sec = AXA_H2P64(AXA_RLIMIT_NA);
		if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_OPT, &opt,
			      sizeof(opt) - sizeof(opt.u)
			      + sizeof(opt.u.rlimit),
			      AXA_P_OP_OPT))
			return;
	}

	/* Block watch hits until we are ready. */
	if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_PAUSE, NULL, 0, AXA_P_OP_OK))
		return;

	/* Start the watches. */
	cur_tag = 1;
	for (arg = watches; arg != NULL; arg = arg->next) {
		if (mode == SRA)
			res = axa_parse_watch(&emsg, &watch, &watch_len,
					      arg->c);
		else
			res = axa_parse_rad_watch(&emsg, &watch, &watch_len,
						  arg->c);
		if (!res) {
			if (emsg.c[0] == '\0') {
				axa_error_msg("unrecognized \"-w %s\"", arg->c);
			} else {
				axa_error_msg("\"-w %s\": %s", arg->c, emsg.c);
			}
			exit(EX_USAGE);
		}

		if (!srvr_cmd(cur_tag, AXA_P_OP_WATCH, &watch, watch_len,
			      AXA_P_OP_OK))
			return;
		if (mode == SRA)
			++cur_tag;
	}

	/* Turn on the channels after after the watches. */
	for (arg = chs; arg != NULL; arg = arg->next) {
		memset(&channel, 0, sizeof(channel));
		if (!axa_parse_ch(&emsg, &channel.ch, arg->c, strlen(arg->c),
				  true, true)) {
			axa_error_msg("\"-c %s\": %s", arg->c, emsg.c);
			exit(EX_USAGE);
		}

		channel.on = 1;
		if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_CHANNEL,
			      &channel, sizeof(channel), AXA_P_OP_OK))
			return;
	}

	/* Turn on the anomaly detectors. */
	for (arg = anomalies; arg != NULL; arg = arg->next) {
		if (!axa_parse_anom(&emsg, &anom, &anom_len, arg->c)) {
			if (emsg.c[0] == '\0') {
				axa_error_msg("unrecognized \"-a %s\"", arg->c);
			} else {
				axa_error_msg("\"-a %s\": %s", arg->c, emsg.c);
			}
			exit(EX_USAGE);
		}

		if (!srvr_cmd(cur_tag, AXA_P_OP_ANOM, &anom, anom_len,
			      AXA_P_OP_OK))
			return;
	}

	if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_GO, NULL, 0, AXA_P_OP_OK))
		return;


	/* Reset connection back-off after last watch has been accepted. */
	axa_client_backoff_reset(&client);
}

/* Create nmsg message from incoming watch hit containing a nmsg message */
static void
whit2nmsg(nmsg_message_t *msgp, axa_p_whit_t *whit, size_t whit_len)
{
	axa_emsg_t emsg;

	if (!axa_whit2nmsg(&emsg, nmsg_input, msgp, whit, whit_len)) {
		axa_error_msg("%s", emsg.c);
		stop(EX_IOERR);
	}
}

static bool				/* false=skip the complaint */
out_error_ok(void)
{
	struct timeval now;

	/* allow a new complaint every 5 seconds */
	gettimeofday(&now, NULL);
	 if (5000 > axa_elapsed_ms(&now, &out_complaint_last))
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
	axa_verror_msg(p, args);
	va_end(args);

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
		if (AXA_P2H32(whit->ip.hdr.ip_len) != len)
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
		ts.tv_sec = AXA_P2H32(whit->ip.hdr.tv.tv_sec);
		ts.tv_nsec = AXA_P2H32(whit->ip.hdr.tv.tv_usec) * 1000;
		nmsg_message_set_time(msg, &ts);
		break;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		out_error("cannot forward type #%d messages as nmsg messages",
			  whit->hdr.type);
		return;
#pragma clang diagnostic pop
	}

	res = nmsg_output_write(out_nmsg_output, msg);

	/* Stop on non-UDP errors. */
	if (res != nmsg_res_success
	    && (out_sock_type != SOCK_DGRAM
		|| res != nmsg_res_errno
		|| !AXA_IGNORED_UDP_ERRNO(errno))) {
		axa_error_msg("nmsg_output_write(): %s", nmsg_res_lookup(res));
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
	uint t;
	uint32_t loopback_hdr;

	AXA_ASSERT(caplen < sizeof(out_buf) - out_buf_base);

	if (out_pcap_datalink == DLT_NULL
	    || out_pcap_datalink == DLT_LOOP) {
		AXA_ASSERT(caplen >= 20);   /* Require at least an IP header. */
		t = *pkt >> 4;
		switch (t) {
		case 4:
			loopback_hdr = PF_INET;
			break;
		case 6:
			loopback_hdr = PF_INET6;
			break;
		default:
			axa_error_msg("cannot inject packet onto %s"
				      " with unknown IP protocol version %d",
				      out_addr, t);
			return;
		}
		if (out_pcap_datalink == DLT_LOOP)
			loopback_hdr = htonl(loopback_hdr);
		memcpy(out_buf, &loopback_hdr, sizeof(loopback_hdr));
	}

	memcpy(&out_buf[out_buf_base], pkt, caplen);
	if (0 > pcap_inject(out_pcap, out_buf, caplen+out_buf_base)) {

		/*
		 * As of June, 2014, there is a bug in pcap_inject()
		 * on Freebsd that breaks this.  Search for the
		 * mailing list thread between Guy Harris and Fernando Gont
		 * about "pcap_inject() on loopback (FreeBSD)"
		 */
		axa_error_msg("failed to inject packet onto %s: %s",
			      out_addr, pcap_geterr(out_pcap));
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
			axa_error_msg("truncated IP packet");
			stop(EX_IOERR);
		}
		tv.tv_sec = AXA_P2H32(whit->ip.hdr.tv.tv_sec);
		tv.tv_usec = AXA_P2H32(whit->ip.hdr.tv.tv_usec);
		pkt = whit->ip.b;
		caplen = whit_len - sizeof(whit->ip.hdr);
		len = AXA_P2H32(whit->ip.hdr.ip_len);
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
		out_error("cannot forward watch hits type #%d",
			  whit->hdr.type);
		return;
#pragma clang diagnostic pop
	}

	if (out_pcap_dumper != NULL)
		out_ip_pcap_file(pkt, caplen, len, &tv);
	else
		out_ip_pcap_inject(pkt, caplen);
}

static void
forward_hit(axa_p_whit_t *whit, size_t whit_len)
{
	struct timeval now;
	time_t ms;

	if (out_nmsg_output != NULL) {
		out_whit_nmsg(whit, whit_len);
	} else {
		AXA_ASSERT(out_pcap != NULL);
		out_whit_pcap(whit, whit_len);
	}
	if (out_bar_on) {
		gettimeofday(&now, NULL);
		ms = axa_elapsed_ms(&now, &out_bar_time);
		if (ms >= PROGESS_MS) {
			fflush(stderr);
			fputs(out_bar_strs[out_bar_idx], stdout);
			fflush(stdout);
			++out_bar_idx;
			out_bar_idx %= AXA_DIM(out_bar_strs);
			out_bar_time = now;
		}
	}
	if (counting && --count <= 0) {
		if (axa_debug != 0)
			axa_trace_msg("forwarded %d messages", initial_count);
		stop(0);
	}
}

/* Forward from the server to the output */
static void
forward(void)
{
	axa_emsg_t emsg;

	switch (axa_recv_buf(&emsg, &client.io)) {
	case AXA_IO_OK:
		break;
	case AXA_IO_ERR:
		disconnect(true, "%s", emsg.c);
		return;
	case AXA_IO_BUSY:
		return;			/* wait for the rest */
	case AXA_IO_TUNERR:
	case AXA_IO_KEEPALIVE:
		AXA_FAIL("impossible axa_recv_buf() result");
	}

	switch ((axa_p_op_t)client.io.recv_hdr.op) {
	case AXA_P_OP_NOP:
		print_op(false, false,
			 &client.io.recv_hdr, client.io.recv_body);
		break;

	case AXA_P_OP_ERROR:
		print_bad_op("");
		disconnect(false, " ");
		return;

	case AXA_P_OP_MISSED:
	case AXA_P_OP_MISSED_RAD:
		print_missed();
		break;

	case AXA_P_OP_WHIT:
		print_op(false, false,
			 &client.io.recv_hdr, client.io.recv_body);
		forward_hit(&client.io.recv_body->whit,
			    client.io.recv_body_len
			    - sizeof(client.io.recv_hdr));
		break;

	case AXA_P_OP_AHIT:
		print_op(false, false,
			 &client.io.recv_hdr, client.io.recv_body);
		forward_hit(&client.io.recv_body->ahit.whit,
			    client.io.recv_body_len
			    - sizeof(client.io.recv_hdr)
			    - (sizeof(client.io.recv_body->ahit)
			       - sizeof(client.io.recv_body
					->ahit.whit)));
		break;

	case AXA_P_OP_OK:
		print_trace();
		break;

	case AXA_P_OP_HELLO:
	case AXA_P_OP_WLIST:
	case AXA_P_OP_ALIST:
	case AXA_P_OP_OPT:
	case AXA_P_OP_CLIST:
		print_bad_op("unexpected ");
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
		AXA_FAIL("impossible AXA op of %d from %s",
			 client.io.recv_hdr.op, client.io.label);
	}

	axa_recv_flush(&client.io);
}

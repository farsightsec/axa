/*
 * Tunnel SIE data from an SRA or RAD server.
 *
 *  Copyright (c) 2014-2017 by Farsight Security, Inc.
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

#include "sratunnel.h"

/* extern: main.c */
extern uint axa_debug;
extern nmsg_input_t nmsg_input;
extern const char *out_addr;

/* global */
nmsg_output_t out_nmsg_output;		/* NSMG output object */
pcap_t *out_pcap;			/* pcap output object */
bool nmsg_zlib = false;			/* NMSG zlib container compression */

/* private */
static struct timeval out_complaint_last;
static bool out_error_first_time = true;
static bool out_complaint_skipped;
static int out_sock_type;
static struct timeval time_out_flush;
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
static nmsg_msgmod_t out_nmsg_mod = NULL;
static void *out_nmsg_clos;
static bool out_nmsg_mod_checked = false;

void
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

void
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

bool
out_open(bool output_buffering)
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
				   strchr(out_addr, ':')+1, output_buffering)) {
		axa_error_msg("%s", emsg.c);
		return (false);
	}
	if (nmsg_zlib)
		nmsg_output_set_zlibout(out_nmsg_output, true);
	return (true);
}

/* Create nmsg message from incoming watch hit containing a nmsg message */
static axa_w2n_res_t
whit2nmsg(nmsg_message_t *msgp, axa_p_whit_t *whit, size_t whit_len)
{
	axa_emsg_t emsg;
	axa_w2n_res_t res;

	res = axa_whit2nmsg(&emsg, nmsg_input, msgp, whit, whit_len);
	switch (res) {
		case AXA_W2N_RES_FAIL:
			axa_error_msg("%s", emsg.c);
			stop(EX_IOERR);
		case AXA_W2N_RES_SUCCESS:
		case AXA_W2N_RES_FRAGMENT:
			break;
	}
	return (res);
}

static bool				/* false=skip the complaint */
out_error_ok(void)
{
	struct timeval now;

	/* allow first error message */
	if (out_error_first_time) {
		out_error_first_time = false;
		gettimeofday(&out_complaint_last, NULL);
		return (true);
	}

	/* from here on out, only allow a new complaint every 5 seconds */
	gettimeofday(&now, NULL);

	if (5000 > axa_elapsed_ms(&now, &out_complaint_last)) {
		/* count skipped complaints */
		out_complaint_skipped = true;
		return (false);
	}

	return (true);
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
void
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
		/* pass nmsg messages along, but ignore fragments */
		if (whit2nmsg(&msg, whit, whit_len) == AXA_W2N_RES_FRAGMENT) {
			if (axa_debug != 0)
				axa_trace_msg("ignoring NMSG fragment from "
						AXA_OP_CH_PREFIX"%d",
						AXA_P2H_CH(whit->hdr.ch));
			return;
		}
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

	if (pkt == NULL) {
		out_error("NULL packet; nothing to do");
		return;
	}

	if (caplen + sizeof(sf_hdr) > sizeof(out_buf) - out_buf_len
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

	if (pkt == NULL) {
		axa_error_msg("NULL packet; nothing to do");
		return;
	}

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
void
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
		/* pass nmsg messages along, but ignore fragments */
		if (whit2nmsg(&msg, whit, whit_len) == AXA_W2N_RES_FRAGMENT) {
			if (axa_debug != 0)
				axa_trace_msg("ignoring NMSG fragment from "
						AXA_OP_CH_PREFIX"%d",
						AXA_P2H_CH(whit->hdr.ch));
			return;
		}
		vid = nmsg_message_get_vid(msg);
		msgtype = nmsg_message_get_msgtype(msg);
		if (vid != NMSG_VENDOR_BASE_ID
		    || msgtype != NMSG_VENDOR_BASE_PACKET_ID) {
			vid_str = nmsg_msgmod_vid_to_vname(vid);
			msgtype_str = nmsg_msgmod_msgtype_to_mname(vid,
						msgtype);
			out_error("cannot forward nmsg %s %s"
				  " messages via pcap",
				  vid_str, msgtype_str);
			return;
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

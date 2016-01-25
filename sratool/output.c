/*
 * SIE Remote Access (SRA) ASCII tool
 *
 *  Copyright (c) 2014-2016 by Farsight Security, Inc.
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

#include "sratool.h"

/* extern: main.c */
extern uint axa_debug;
extern axa_emsg_t emsg;

/* global */
int out_fd;				/* pcap output fd */
nmsg_output_t out_nmsg_output;		/* NMSG output object */
pcap_t *out_pcap;			/* pcap output object */
pcap_dumper_t *out_pcap_dumper;		/* pcap dump file output object */
int out_pcap_datalink;			/* link-layer header type */
int output_count;			/* limit forwarded packets */
int output_count_total;			/* total packets to output */
bool output_counting;			/* true if counting output packets */
int output_errno;			/* output device errno */
int out_sock_type;			/* output socket, DGRAM or STREAM */
static struct timeval time_out_flush;	/* timestamp of last output flush */
#define OUT_FLUSH_MS	100		/* flush output this often */
static struct timeval out_complaint_last; /* timestamp of last complaint */
static bool out_complaint_skipped;	/* true if we missed some complaints */
uint8_t out_buf[AXA_P_WHIT_IP_MAX*4];	/* payloads to be output go here */
size_t out_buf_base;			/* base output size */
size_t out_buf_len;			/* sizeof data to be output */
bool out_on;				/* true == output forwarding is on */
bool out_on_nmsg;			/* true == output dest is nmsg */
bool nmsg_zlib = false;			/* true == nmsg zlib compression on */
char *out_addr;				/* output/forwarding destination */

/* private */
static void *out_nmsg_clos;
static struct timeval output_errno_time;
static nmsg_msgmod_t out_nmsg_mod = NULL;
static bool out_nmsg_mod_checked = false;

/* Flush the output forwarding buffer if it is time or say how long until it
 * will be time.
 */
time_t
out_flush_ck(const struct timeval *now, time_t delay)
{
	time_t ms;
	struct timeval now0;

	if (time_out_flush.tv_sec == 0)
		return (delay);

	if (now == NULL) {
		gettimeofday(&now0, NULL);
		now = &now0;
	}

	ms = OUT_FLUSH_MS - axa_elapsed_ms(now, &time_out_flush);
	if (ms > 0)
		return (max(delay, ms));

	out_flush();
	return (delay);
}

void
out_flush(void)
{
	nmsg_res res;
	ssize_t wlen;

	if (time_out_flush.tv_sec == 0)
		return;

	if (out_buf_len != 0) {
		wlen = write(out_fd, &out_buf[out_buf_base],
			     out_buf_len - out_buf_base);
		if (wlen < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK
			    && errno != EINTR) {
				error_msg("write(%s): %s",
					  out_addr, strerror(errno));
				out_close(true);
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
			error_msg("nmsg_output_flush(forward): %s",
				  nmsg_res_lookup(res));
			out_close(true);
		}
	}

	time_out_flush.tv_sec = 0;
}

void
out_close(bool announce)
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

	if (out_addr != NULL) {
		if (announce) {
			clear_prompt();
			printf("stop forwarding to %s\n", out_addr);
		}
		free(out_addr);
		out_addr = NULL;
	}

	out_buf_base = out_buf_len = 0;
	time_out_flush.tv_sec = 0;
	out_nmsg_mod = NULL;
	out_nmsg_mod_checked = false;
	out_complaint_last.tv_sec = 0;
	out_complaint_skipped = false;

	out_on = false;
	out_on_nmsg = false;
	nmsg_zlib = false;
}

bool
out_error_ok(void)
{
	struct timeval now;
	time_t ms;

	gettimeofday(&now, NULL);
	ms = axa_elapsed_ms(&now, &out_complaint_last);

	/* allow a new complaint every 5 seconds */
	 if (ms > 5000)
		 return (true);

	 /* count skipped complaints */
	 out_complaint_skipped = true;
	 return (false);
}

void AXA_PF(1,2)
out_error(const char *p, ...)
{
	va_list args;

	if (!out_error_ok())
		return;

	clear_prompt();
	if (out_complaint_skipped) {
		error_msg("...");
		out_complaint_skipped = false;
	}
	va_start(args, p);
	axa_verror_msg(p, args);
	va_end(args);

	gettimeofday(&out_complaint_last, NULL);
}

/* forward watch hits as NMSG messages */
bool
out_whit_nmsg(axa_p_whit_t *whit, size_t whit_len)
{
	nmsg_message_t msg;
	struct timespec ts;
	static const union {
		uint    e;
		uint8_t	c[0];
	} pkt_enum = { .e = NMSG__BASE__PACKET_TYPE__IP };
	size_t len;
	struct timeval now;
	nmsg_res res;
	bool result;

	switch ((axa_p_whit_enum_t)whit->hdr.type) {
	case AXA_P_WHIT_NMSG:
		/* pass NMSG messages along */
		if (whit2nmsg(&msg, whit, whit_len) == AXA_W2N_RES_FRAGMENT) {
			if (axa_debug != 0)
				printf("ignoring NMSG fragment from "
						AXA_OP_CH_PREFIX"%d",
						AXA_P2H_CH(whit->hdr.ch));
			return (false);
		}
		if (msg == NULL)
			return (false);
		break;

	case AXA_P_WHIT_IP:
		/* Convert raw IP packets to nmsg BASE_PACKET */
		len = whit_len - sizeof(whit->ip.hdr);
		if (AXA_P2H32(whit->ip.hdr.ip_len) != len)
			return (false);	/* Ignore incomplete packets. */

		if (!out_nmsg_mod_checked) {
			out_nmsg_mod_checked = true;
			out_nmsg_mod = nmsg_msgmod_lookup(NMSG_VENDOR_BASE_ID,
						NMSG_VENDOR_BASE_PACKET_ID);
			if (out_nmsg_mod == NULL) {
				out_error("cannot get BASE_PACKET module");
				return (false);
			}
			res = nmsg_msgmod_init(out_nmsg_mod, &out_nmsg_clos);
			if (res != nmsg_res_success) {
				out_error("cannot init BASE_PACKET module");
				out_nmsg_mod = NULL;
				return (false);
			}
		}
		if (out_nmsg_mod == NULL) {
			out_error("cannot forward IP as NMSG messages"
				  " without PACKET nmsg_msgmod");
			return (false);
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
		out_error("cannot forward SRA #%d messages as NMSG messages",
			  whit->hdr.type);
		return (false);
#pragma clang diagnostic pop
	}

	res = nmsg_output_write(out_nmsg_output, msg);
	if (res == nmsg_res_success) {
		result = true;
	} else {
		result = false;

		gettimeofday(&now, NULL);
		if (out_sock_type != SOCK_DGRAM
		    || res != nmsg_res_errno
		    || !AXA_IGNORED_UDP_ERRNO(errno)) {
			/* Stop on non-UDP errors. */
			clear_prompt();
			error_msg("nmsg_output_write(): %s",
				  nmsg_res_lookup(res));
			out_close(false);
			disconnect(true);
		} else if (output_errno != errno
			   || 60*1000 <= axa_elapsed_ms(&now,
							&output_errno_time)
			   || axa_debug >= AXA_DEBUG_TRACE) {
			/* Report occassional identical UDP errors. */
			output_errno = errno;
			gettimeofday(&output_errno_time, NULL);
			clear_prompt();
			error_msg("nmsg_output_write(): %s",
				  strerror(output_errno));
		}
	}

	nmsg_message_destroy(&msg);
	if (time_out_flush.tv_sec == 0)
		gettimeofday(&time_out_flush, NULL);

	return (result);
}

void
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

void
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
			error_msg("cannot inject packet onto %s"
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
		 * on FreeBSD that breaks this.  Search for the
		 * mailing list thread between Guy Harris and Fernando Gont
		 * about "pcap_inject() on loopback (FreeBSD)"
		 */
		error_msg("failed to inject packet onto %s: %s",
			  out_addr, pcap_geterr(out_pcap));
	}
}

/* forward watch hits in a pcap stream */
bool
out_whit_pcap(axa_p_whit_t *whit, size_t whit_len)
{
	struct timeval tv;
	uint8_t *pkt;
	size_t len, caplen;
	struct timespec ts;
	nmsg_message_t msg;
	uint vid, msgtype;
	const Nmsg__Base__Packet *packet;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	pkt = NULL;
	caplen = 0;
	len = 0;
	switch ((axa_p_whit_enum_t)whit->hdr.type) {
	case AXA_P_WHIT_IP:
		if (whit_len <= sizeof(whit->ip)) {
			clear_prompt();
			error_msg("truncated IP packet");
			disconnect(true);
			return (false);
		}
		tv.tv_sec = AXA_P2H32(whit->ip.hdr.tv.tv_sec);
		tv.tv_usec = AXA_P2H32(whit->ip.hdr.tv.tv_usec);
		pkt = whit->ip.b;
		caplen = whit_len - sizeof(whit->ip.hdr);
		len = AXA_P2H32(whit->ip.hdr.ip_len);
		break;

	case AXA_P_WHIT_NMSG:
		if (whit2nmsg(&msg, whit, whit_len) == AXA_W2N_RES_FRAGMENT) {
			if (axa_debug != 0)
				printf("ignoring NMSG fragment from "
						AXA_OP_CH_PREFIX"%d",
						AXA_P2H_CH(whit->hdr.ch));
			return (false);
		}
		if (msg == NULL)
			return (false);
		vid = nmsg_message_get_vid(msg);
		msgtype = nmsg_message_get_msgtype(msg);
		if (vid != NMSG_VENDOR_BASE_ID
		    || msgtype != NMSG_VENDOR_BASE_PACKET_ID) {
			if (!out_error_ok()) {
				out_error("cannot forward nmsg %s %s"
					  " messages via pcap",
					  nmsg_msgmod_vid_to_vname(vid),
					  nmsg_msgmod_msgtype_to_mname(vid,
							msgtype));
			}
			return (false);
		}

		/* decode IP packets in BASE_PACKET to make pcap packets */
		packet = (Nmsg__Base__Packet *)nmsg_message_get_payload(msg);
		if (packet == NULL
		    || packet->payload_type != NMSG__BASE__PACKET_TYPE__IP) {
			if (!out_error_ok()) {
				out_error("failed to forward nmsg %s %s"
					  " messages via pcap",
					  nmsg_msgmod_vid_to_vname(vid),
					  nmsg_msgmod_msgtype_to_mname(vid,
							msgtype));
			}
			return (false);
		}
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
		return (false);
#pragma clang diagnostic pop
	}

	if (out_pcap_dumper != NULL)
		out_ip_pcap_file(pkt, caplen, len, &tv);
	else
		out_ip_pcap_inject(pkt, caplen);
	return (true);
}

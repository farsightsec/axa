/*
 * Print a dark channel packet
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

#include "sratool.h"

#include <arpa/nameser.h>
#include <axa/axa_endian.h>

#include <errno.h>
#include <netinet/ip6.h>
#define __FAVOR_BSD			/* for Debian tcp.h and udp.h */
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
#endif


bool					/* false=failed to print it */
print_dns_pkt(const uint8_t *data, size_t data_len, const char *str)
{
	wdns_message_t m;
	wdns_rr_t *q;
	const char *rcode, *class, *rtype;
	char wdns_resbuf[AXA_WDNS_RES_STRLEN];
	char class_buf[10], rtype_buf[10], rcode_buf[6];
	char qname[NS_MAXDNAME];
	char *msg_str, *p;
	bool eol;
	wdns_res wres;

	fputs(NMSG_LEADER"DNS:", stdout);

	wres = wdns_parse_message(&m, data, data_len);
	if (wres != wdns_res_success) {
		printf("  wdns_parse_message(%s): %s\n", str,
		       axa_wdns_res(wres, wdns_resbuf, sizeof(wdns_resbuf)));
		return (false);
	}

	if (verbose != 0) {
		msg_str = wdns_message_to_str(&m);
		if (msg_str == NULL) {
			printf("  wdns_message_to_str(%s) failed\n", str);
		} else {
			fputs("\n", stdout);
			for (eol = true, p = msg_str; *p != '\0'; ++p) {
				if (eol) {
					eol = false;
					fputs(NMSG_LEADER2, stdout);
				}
				fputc(*p, stdout);
				if (*p == '\n')
					eol = true;
			}
			free(msg_str);
		}
		wdns_clear_message(&m);
		return (true);
	}

	rcode = wdns_rcode_to_str(WDNS_FLAGS_RCODE(m));
	if (rcode == NULL) {
		snprintf(rcode_buf, sizeof(rcode_buf),
			 "%d ", WDNS_FLAGS_RCODE(m));
		rcode = rcode_buf;
	}

	q = m.sections[0].rrs;
	if (q == NULL) {
		rtype = "?";
		class = "?";
		strlcpy(qname, "(empty QUESTION section)", sizeof(qname));
	} else {
		class = wdns_rrclass_to_str(q->rrclass);
		if (class == NULL) {
			snprintf(class_buf, sizeof(class_buf),
				 "CLASS %d", q->rrclass);
			class = class_buf;
		}
		rtype = axa_rtype_to_str(rtype_buf, sizeof(rtype_buf),
					 q->rrtype);
		axa_domain_to_str(q->name.data, q->name.len,
				  qname, sizeof(qname));
	}

	printf(" %s %s %s"
	       "  %s%s%s%s%s%s%s",
	       qname, class, rtype,
	       WDNS_FLAGS_QR(m) ? " qr" : "",
	       WDNS_FLAGS_AA(m) ? " aa" : "",
	       WDNS_FLAGS_TC(m) ? " tc" : "",
	       WDNS_FLAGS_RD(m) ? " rd" : "",
	       WDNS_FLAGS_RA(m) ? " ra" : "",
	       WDNS_FLAGS_AD(m) ? " ad" : "",
	       WDNS_FLAGS_CD(m) ? " cd" : "");

	if (WDNS_FLAGS_QR(m))
		printf("  %s"
		       "  %d ans, %d auth, %d add RRs",
		       rcode,
		       m.sections[1].n_rrs,
		       m.sections[2].n_rrs,
		       m.sections[3].n_rrs);
	fputc('\n', stdout);

	wdns_clear_message(&m);
	return (true);
}


static void AXA_PF(4,5)
add_str(char *buf, size_t buf_len, size_t *buf_pos, const char *p, ...)
{
	size_t len;
	int i;
	va_list args;

	if (*buf_pos >= buf_len)
		return;
	len = buf_len - *buf_pos;
	va_start(args, p);
	i = vsnprintf(&buf[*buf_pos], len, p, args);
	va_end(args);
	if (i < 0) {
		error_msg("vsnprintf(): %s", strerror(errno));
		*buf_pos = buf_len;
	} else if ((size_t)i > len) {
		strcpy(&buf[buf_len-4], "...");
		*buf_pos = buf_len;
	} else {
		*buf_pos += i;
	}
}

static bool
ck_ipdg(const char *protocol,
	size_t min_len, const void *ptr, size_t actual_len,
	const axa_p_whit_t *whit, char *err_buf, size_t err_buf_len)
{
	if (ptr == NULL) {
		if (err_buf == NULL)
			error_msg("missing %s header from "
				  AXA_OP_CH_PREFIX"%d",
				  protocol, AXA_P2H_CH(whit->hdr.ch));
		else
			snprintf(err_buf, err_buf_len,
				 " missing %s header from "
				 AXA_OP_CH_PREFIX"%d",
				 protocol, AXA_P2H_CH(whit->hdr.ch));
		return (false);
	}
	if (actual_len < min_len) {
		if (err_buf == NULL)
			error_msg("truncated %s header of "
				  "%zd bytes from "AXA_OP_CH_PREFIX"%d",
				  protocol, actual_len,
				  AXA_P2H_CH(whit->hdr.ch));
		else
			snprintf(err_buf, err_buf_len,
				 " truncated %s header of %zd bytes from "
				 AXA_OP_CH_PREFIX"%d",
				 protocol, actual_len,
				 AXA_P2H_CH(whit->hdr.ch));
		return (false);
	}
	return (true);
}

static void
print_src_dst(char *srcip, size_t srcip_len, char *dstip, size_t dstip_len,
	      const axa_socku_t *src_su, const axa_socku_t *dst_su,
	      uint ttl, const char *info)
{
	/* Separate port numbers with '.' for consistency with nmsg
	 * presentation form and ignore the nmsgtool preference for '/'
	 * for channels or confusion with CIDR blocks. */
	printf(" %20s > %-20s IP TTL=%d %s\n",
	       axa_su_to_str(srcip, srcip_len, '.', src_su),
	       axa_su_to_str(dstip, dstip_len, '.', dst_su),
	       ttl, info);
}

#define ADD_INFO(...) add_str(info, sizeof(info), &info_pos, __VA_ARGS__)
#define ADD_CHARS(...) add_str(chars, sizeof(chars), &chars_pos, __VA_ARGS__)

void
print_raw(const uint8_t *pkt, size_t pkt_len)
{
	char info[64];
	size_t info_pos;
	char chars[18];
	size_t chars_pos;
	uint pay_pos;
	u_char c;

	info_pos = 0;
	chars_pos = 0;
	for (pay_pos = 0; pay_pos < pkt_len; ++pay_pos) {
		if (info_pos == 0) {
			if (pay_pos > 256) {
				fputs(NMSG_LEADER2"...\n", stdout);
				break;
			}
			ADD_INFO("%7d:", pay_pos);
		}
		c = pkt[pay_pos];
		ADD_INFO(" %02x", c);
		if (c >= '!' && c <= '~')
			ADD_CHARS("%c", c);
		else
			ADD_CHARS(".");
		if (chars_pos == 8) {
			ADD_INFO(" ");
			ADD_CHARS(" ");
		} else if (chars_pos == 17) {
			printf("%55s  %s\n", info, chars);
			info_pos = 0;
			chars_pos = 0;
		}
	}
	if (info_pos != 0)
		printf("%-57s  %s\n", info, chars);
}

void
print_raw_ip(const uint8_t *pkt_data, size_t caplen,
	     const axa_p_whit_t *whit)
{
	struct nmsg_ipdg dg;
	struct ip ip_hdr;
	uint ttl;
	struct ip6_hdr ip6_hdr;
	struct tcphdr tcp_hdr;
	struct udphdr udp_hdr;
	uint uh_ulen;
	char err_buf[80];
	char info[64];
	size_t info_pos;
	char dstip[INET6_ADDRSTRLEN], srcip[INET6_ADDRSTRLEN];
	axa_socku_t dst_su, src_su;
	nmsg_res res;


	clear_prompt();

	memset(&dg, 0, sizeof(dg));
	res = nmsg_ipdg_parse_pcap_raw(&dg, DLT_RAW, pkt_data, caplen);
	if (res != nmsg_res_success && dg.len_network == 0) {
		/* Postpone dealing with whine from nmsg_ipdg_parse_pcap_raw()
		 * if it got something. */
		fputs(" unknown packet\n", stdout);
		if (verbose > 1)
			print_raw(pkt_data, caplen);
		return;
	}

	switch (dg.proto_network) {
	case AF_INET:
		if (!ck_ipdg("IP", sizeof(ip_hdr),
			     dg.network, dg.len_network, whit, NULL, 0))
			return;
		memcpy(&ip_hdr, dg.network, sizeof(ip_hdr));
		axa_ip_to_su(&dst_su, &ip_hdr.ip_dst, AF_INET);
		axa_ip_to_su(&src_su, &ip_hdr.ip_src, AF_INET);
		ttl = ip_hdr.ip_ttl;
		break;
	case AF_INET6:
		if (!ck_ipdg("IPv6", sizeof(ip6_hdr),
			     dg.network, dg.len_network, whit, NULL, 0))
			return;
		memcpy(&ip6_hdr, dg.network, sizeof(ip6_hdr));
		axa_ip_to_su(&dst_su, &ip6_hdr.ip6_dst, AF_INET6);
		axa_ip_to_su(&src_su, &ip6_hdr.ip6_src, AF_INET6);
		ttl = ip6_hdr.ip6_hlim;
		break;
	default:
		printf(" unknown AF %d\n", dg.proto_network);
		if (verbose > 1)
			print_raw(dg.network, dg.len_network);
		return;
	}

	info_pos = 0;
	switch (dg.proto_transport) {
	case IPPROTO_ICMP:
		ADD_INFO("ICMP");
		if (dg.transport == NULL)
			ADD_INFO(" later fragment");
		else
			ADD_INFO(" %d bytes", ntohs(ip_hdr.ip_len));
		print_src_dst(srcip, sizeof(srcip), dstip, sizeof(dstip),
			      &src_su, &dst_su, ttl, info);
		break;

	case IPPROTO_ICMPV6:
		ADD_INFO("ICMPv6");
		if (dg.transport == NULL)
			ADD_INFO(" later fragment");
		print_src_dst(srcip, sizeof(srcip), dstip, sizeof(dstip),
			      &src_su, &dst_su, ttl, info);
		break;

	case IPPROTO_TCP:
		ADD_INFO("TCP");
		if (dg.transport == NULL) {
			ADD_INFO(" later fragment");
		} else if (!ck_ipdg("TCP", sizeof(tcp_hdr),
				    dg.transport, dg.len_transport,
				    whit, err_buf, sizeof(err_buf))) {
			add_str(info, sizeof(info), &info_pos,
				"\n%s\n", err_buf);
		} else {
			memcpy(&tcp_hdr, dg.transport, sizeof(tcp_hdr));
			AXA_SU_PORT(&dst_su) = tcp_hdr.th_dport;
			AXA_SU_PORT(&src_su) = tcp_hdr.th_sport;
			if ((tcp_hdr.th_flags & TH_FIN) != 0)
				ADD_INFO(" FIN");
			if ((tcp_hdr.th_flags & TH_SYN) != 0)
				ADD_INFO(" SYN");
			if ((tcp_hdr.th_flags & TH_ACK) != 0)
				ADD_INFO(" ACK");
			if ((tcp_hdr.th_flags & TH_RST) != 0)
				ADD_INFO(" RST");
		}
		print_src_dst(srcip, sizeof(srcip), dstip, sizeof(dstip),
			      &src_su, &dst_su, ttl, info);
		break;

	case IPPROTO_UDP:
		ADD_INFO("UDP");
		if (dg.transport == NULL) {
			ADD_INFO(" later fragment");
			uh_ulen = 0;
		} else if (!ck_ipdg("UDP", sizeof(udp_hdr),
				    dg.transport, dg.len_transport,
				    whit, err_buf, sizeof(err_buf))) {
			add_str(info, sizeof(info), &info_pos,
				"\n%s\n", err_buf);
			uh_ulen = 0;
		} else {
			memcpy(&udp_hdr, dg.transport, sizeof(udp_hdr));
			AXA_SU_PORT(&dst_su) = udp_hdr.uh_dport;
			AXA_SU_PORT(&src_su) = udp_hdr.uh_sport;
			uh_ulen = ntohs(udp_hdr.uh_ulen);
			ADD_INFO(" %d bytes", uh_ulen);
			if (uh_ulen != dg.len_payload+sizeof(udp_hdr))
				ADD_INFO("  fragment");
		}
		print_src_dst(srcip, sizeof(srcip), dstip, sizeof(dstip),
			      &src_su, &dst_su, ttl, info);

		/* Try to print DNS if is plausible and DNS printing works. */
		if (dg.transport != NULL
		    && (AXA_SU_PORT(&dst_su) == htons(53)
			|| AXA_SU_PORT(&src_su) == htons(53))
		    && uh_ulen == dg.len_payload+sizeof(udp_hdr)
		    && print_dns_pkt(dg.payload, dg.len_payload, ""))
			return;
		break;

	default:
		snprintf(info, sizeof(info), " IP protocol %d",
			 dg.proto_transport);
		print_src_dst(srcip, sizeof(srcip), dstip, sizeof(dstip),
			      &src_su, &dst_su, ttl, info);
		break;
	}

	if (verbose > 1)
		print_raw(dg.payload, dg.len_payload);
}

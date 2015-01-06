/*
 * Print a dark channel packet
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

void
print_raw(const uint8_t *pkt, size_t pkt_len)
{
	char info_buf[64], *info;
	char chars_buf[18], *chars;
	size_t info_len, chars_len;
	uint pay_pos;
	u_char c;

	info = info_buf;
	info_len = sizeof(info_buf);
	chars = chars_buf;
	chars_len = sizeof(chars_buf);
	for (pay_pos = 0; pay_pos < pkt_len; ++pay_pos) {
		if (info_len == sizeof(info_buf)) {
			if (pay_pos > 256) {
				fputs(NMSG_LEADER2"...\n", stdout);
				break;
			}
			axa_buf_print(&info, &info_len, "%7d:", pay_pos);
		}
		c = pkt[pay_pos];
		axa_buf_print(&info, &info_len, " %02x", c);
		if (c >= '!' && c <= '~')
			axa_buf_print(&chars, &chars_len, "%c", c);
		else
			axa_buf_print(&chars, &chars_len, ".");
		if (chars_len == sizeof(chars_buf) - 8) {
			axa_buf_print(&info, &info_len, " ");
			axa_buf_print(&chars, &chars_len, " ");
		} else if (chars_len == sizeof(chars_buf) - 17) {
			printf("%55s  %s\n", info_buf, chars_buf);
			info = info_buf;
			info_len = sizeof(info_buf);
			chars = chars_buf;
			chars_len = sizeof(chars_buf);
		}
	}
	if (info_len != sizeof(info_buf))
		printf("%-57s  %s\n", info_buf, chars_buf);
}

void
print_raw_ip(const uint8_t *pkt_data, size_t caplen, axa_p_ch_t ch)
{
	axa_socku_t dst_su, src_su;
	char dst[AXA_SU_TO_STR_LEN], src[AXA_SU_TO_STR_LEN];
	char info[80];

	clear_prompt();

	if (axa_ipdg_parse(pkt_data, caplen, ch, &dst_su, &src_su,
			    info, sizeof(info))) {
		printf(" %20s > %-20s %s\n",
		       axa_su_to_str(src, sizeof(src), '.', &src_su),
		       axa_su_to_str(dst, sizeof(dst), '.', &dst_su),
		       info);
	} else {
		printf(" %s\n", info);
	}

	if (verbose > 1)
		print_raw(pkt_data, caplen);
}

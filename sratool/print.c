/*
 * Print various SIE messages
 *
 *  Copyright (c) 2014-2018 by Farsight Security, Inc.
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

/* extern: cmd.c */
extern EditLine *el_e;
extern axa_mode_t mode;
extern struct timeval no_reprompt;

/* extern: infile.c */
extern int in_file_cur;

/* extern: main.c */
extern axa_emsg_t emsg;
extern uint axa_debug;
extern int packet_count;
extern bool packet_counting;
extern int packet_count_total;
extern nmsg_input_t nmsg_input;

/* extern: output.c */
extern bool out_on;
extern char *out_addr;
extern pcap_t *out_pcap;
extern int output_count;
extern bool output_counting;
extern int output_count_total;
extern nmsg_output_t out_nmsg_output;

/* extern: server.c */
extern axa_client_t client;

/* private */
static uint out_bar_idx;
static struct timeval out_bar_time;
static const char *out_bar_strs[] = {
	"|\b", "/\b", "-\b", "\\\b", "|\b", "/\b", "-\b", "\\\b"
};
#define PROGRESS_MS (1000/AXA_DIM(out_bar_strs)) /* 2 revolutions/second */

bool					/* false=failed to print it */
print_dns_pkt(const uint8_t *data, size_t data_len, const char *str)
{
	wdns_message_t m;
	wdns_rr_t *q;
	const char *rcode, *class, *rtype;
	char wdns_resbuf[AXA_WDNS_RES_STRLEN];
	char class_buf[18], rtype_buf[10], rcode_buf[12];
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

static bool
get_nmsg_field(const nmsg_message_t msg, const char *fname,
	       axa_nmsg_idx_t val_idx, void **data, size_t *data_len,
	       char *ebuf, size_t ebuf_size)
{
	nmsg_res res;

	res = nmsg_message_get_field(msg, fname, val_idx, data, data_len);
	if (res == nmsg_res_success)
		return (true);

	snprintf(ebuf, ebuf_size, "nmsg_message_get_field(%s): %s",
		 fname, nmsg_res_lookup(res));
	*data = ebuf;
	*data_len = strlen(ebuf);
	return (false);
}

static bool				/* false=returning error message */
get_nmsg_field_by_idx(const nmsg_message_t msg, axa_nmsg_idx_t field_idx,
		      axa_nmsg_idx_t val_idx, void **data, size_t *data_len,
		      char *ebuf, size_t ebuf_size)
{
	nmsg_res res;

	res = nmsg_message_get_field_by_idx(msg, field_idx, val_idx,
					    data, data_len);
	if (res == nmsg_res_success)
		return (true);

	snprintf(ebuf, ebuf_size, "nmsg_message_get_field(%d): %s",
		 field_idx, nmsg_res_lookup(res));
	*data = ebuf;
	*data_len = strlen(ebuf);
	return (false);
}

static bool
enum_value_to_name(const nmsg_message_t msg, const char *fname, uint value,
		   const char **type_str, char *ebuf, size_t ebuf_size)
{
	nmsg_res res;

	res = nmsg_message_enum_value_to_name(msg, fname, value, type_str);
	if (res == nmsg_res_success)
		return (true);

	if (ebuf_size > 0) {
		snprintf(ebuf, ebuf_size,
			 "nmsg_message_enum_value_to_name(%s): %s",
			 fname, nmsg_res_lookup(res));
		*type_str = ebuf;
	} else {
		*type_str = NULL;
	}
	return (false);
}

static bool
fname_enum_to_name(const nmsg_message_t msg, const char *fname,
		   const char **type_str, char *ebuf, size_t ebuf_size)
{
	void *data;
	size_t data_len;
	uint value;
	nmsg_res res;

	if (!get_nmsg_field(msg, fname, 0, &data, &data_len,
			    ebuf, ebuf_size)) {
		*type_str = data;
		return (false);
	}
	if (data_len != sizeof(value)) {
		*type_str = "wrong enum len from nmsg_message_get_field()";
		return (false);
	}
	memcpy(&value, data, sizeof(value));
	res = nmsg_message_enum_value_to_name(msg, fname, value, type_str);
	if (res == nmsg_res_success)
		return (true);
	*type_str = ebuf;
	return (false);
}

static bool
data_to_ip(char *buf, size_t buf_len,
	   const void *data, size_t data_len, const char *tag)
{
	axa_socku_t su;

	if (!axa_data_to_su(&su, data, data_len)) {
		snprintf(buf, buf_len, "%s IP length=%zd", tag, data_len);
		return (false);
	}
	axa_su_to_str(buf, buf_len, '.', &su);
	return (true);
}

static bool
fname_to_ip(char *buf, size_t buf_len, const nmsg_message_t msg,
	    const char *fname, axa_nmsg_idx_t val_idx)
{
	void *data;
	size_t data_len;

	if (!get_nmsg_field(msg, fname, val_idx, &data, &data_len,
			    buf, buf_len))
		return (buf);
	return (data_to_ip(buf, buf_len, data, data_len, fname));
}

static void
print_verbose_nmsg(const nmsg_message_t msg, const char *eq, const char *val)
{
	char *pres_data;
	const char *line, *eol;
	nmsg_res res;

	printf("%s%s\n", eq, val);

	res = nmsg_message_to_pres(msg, &pres_data, "\n");
	if (res != nmsg_res_success) {
		printf(NMSG_LEADER"<UNKNOWN NMSG %u:%u>\n",
		       nmsg_message_get_vid(msg),
		       nmsg_message_get_msgtype(msg));
		return;
	}

	for (line = pres_data; *line != '\0'; line = eol) {
		eol = strchr(line, '\n');
		AXA_ASSERT(eol != NULL);
		++eol;
		fputs(NMSG_LEADER, stdout);
		fwrite(line, eol-line, 1, stdout);
	}
	free(pres_data);
}

typedef struct {
	char		*buf0;
	size_t		buf0_len;
	char		*buf;
	size_t		buf_len;
	nmsg_message_t	msg;
	const char	*rdata_name;
} rdata_ctxt_t;

static void
rdata_error(void *ctxt0, const char *p, va_list args)
{
	rdata_ctxt_t *ctxt = ctxt0;

	vsnprintf(ctxt->buf0, ctxt->buf0_len, p, args);
	ctxt->buf_len = 0;
}

static bool
rdata_buf_alloc(rdata_ctxt_t *ctxt)
{
	size_t len;

	len = strlen(ctxt->buf);
	ctxt->buf += len;
	ctxt->buf_len -= len;
	return (ctxt->buf_len > 0);
}

static bool
rdata_buf_cat(rdata_ctxt_t *ctxt, const char *str)
{
	strlcpy(ctxt->buf, str, ctxt->buf_len);
	return (rdata_buf_alloc(ctxt));
}

static bool
rdata_ip_to_buf(void *ctxt0, const uint8_t *ip, size_t ip_len,
		const char *str AXA_UNUSED)
{
	rdata_ctxt_t *ctxt = ctxt0;
	axa_socku_t su;

	if (!rdata_buf_cat(ctxt, " "))
		return (false);

	if (!axa_data_to_su(&su, ip, ip_len)) {
		snprintf(ctxt->buf0, ctxt->buf0_len, "%s IP length=%zd",
			 ctxt->rdata_name, ip_len);
		ctxt->buf_len = 0;
		return (false);
	}
	axa_su_to_str(ctxt->buf, ctxt->buf_len, '.', &su);
	return (rdata_buf_alloc(ctxt));
}

static bool
rdata_domain_to_buf(void *ctxt0, const uint8_t *name, size_t name_len,
		    axa_walk_dom_t dtype AXA_UNUSED,
		    uint rtype AXA_UNUSED,
		    const char *str AXA_UNUSED)
{
	rdata_ctxt_t *ctxt = ctxt0;
	char wname[NS_MAXDNAME];

	if (!rdata_buf_cat(ctxt, " "))
		return (false);

	axa_domain_to_str(name, name_len, wname, sizeof(wname));
	strlcpy(ctxt->buf, wname, ctxt->buf_len);
	return (rdata_buf_alloc(ctxt));
}

static axa_walk_ops_t rdata_ops = {
	.error = rdata_error,
	.ip = rdata_ip_to_buf,
	.domain = rdata_domain_to_buf,
};

#define RDATA_BUF_LEN (32+NS_MAXDNAME+1+NS_MAXDNAME)
static const char *
rdata_to_buf(char *buf, size_t buf_len,
	     const char *rdata_name, uint32_t rtype,
	     uint8_t *rdata, size_t rdata_len)
{
	rdata_ctxt_t ctxt;

	ctxt.buf0 = buf;
	ctxt.buf0_len = buf_len;
	ctxt.buf = buf;
	ctxt.buf_len = buf_len;
	ctxt.rdata_name = rdata_name;

	axa_rtype_to_str(ctxt.buf, ctxt.buf_len, rtype);
	if (!rdata_buf_alloc(&ctxt))
		return (buf);

	axa_walk_rdata(&ctxt, &rdata_ops, NULL, 0, NULL, rdata+rdata_len,
		       rdata, rdata_len, rtype, "");

	return (buf);
}

/* Get a string for rdata specified by
 *	rdata_name=nmsg field name for the data itself
 *	rtype_idx=nmsg field index for the rtype of the data */
static const char *
rdata_nmsg_to_buf(char *buf, size_t buf_len, const nmsg_message_t msg,
		  const axa_nmsg_field_t *field, axa_nmsg_idx_t val_idx)
{
	uint32_t rtype;
	void *data;
	size_t data_len;

	/* Get the rdata type */
	if (!axa_get_helper(&emsg, msg, &field->rtype, 0,
			    &rtype, NULL, sizeof(rtype), sizeof(rtype), NULL)) {
		strlcpy(buf, emsg.c, buf_len);
		return (buf);
	}

	/* get the rdata itself */
	if (!get_nmsg_field_by_idx(msg, field->idx, val_idx, &data, &data_len,
				   buf, buf_len))
		return (buf);

	return (rdata_to_buf(buf, buf_len, field->name, rtype, data, data_len));
}

static void
print_nmsg_base_dnsqr(const nmsg_message_t msg, const char *eq, const char *val,
		      const axa_p_whit_t *whit)
{
	const Nmsg__Base__DnsQR *dnsqr;
	char ebuf[80];
	const char *type_str;

	if (verbose != 0) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	dnsqr = (Nmsg__Base__DnsQR *)nmsg_message_get_payload(msg);
	if (dnsqr == NULL) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	/* Punt on odd messages */
	if (dnsqr->n_query_packet == 0 && dnsqr->n_response_packet == 0) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}
	if (dnsqr->type != NMSG__BASE__DNS_QRTYPE__UDP_QUERY_ONLY
	    && dnsqr->type != NMSG__BASE__DNS_QRTYPE__UDP_RESPONSE_ONLY
	    && dnsqr->type != NMSG__BASE__DNS_QRTYPE__UDP_QUERY_RESPONSE
	    && dnsqr->type != NMSG__BASE__DNS_QRTYPE__UDP_UNSOLICITED_RESPONSE
	    && dnsqr->type != NMSG__BASE__DNS_QRTYPE__UDP_UNANSWERED_QUERY) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	if (!enum_value_to_name(msg, "type", dnsqr->type, &type_str,
				ebuf, sizeof(ebuf))) {
		if (verbose > 1)
			printf("%s\n", ebuf);
		print_verbose_nmsg(msg, eq, val);
		return;
	}
	printf("%s%s  %s\n", eq, val, type_str);
	/* The query should be in the response,
	 * so print the query only without a response. */
	if (dnsqr->n_response_packet == 0) {
		print_raw_ip(dnsqr->query_packet[0].data,
			     dnsqr->query_packet[0].len,
			     AXA_P2H_CH(whit->hdr.ch));
	} else {
		print_raw_ip(dnsqr->response_packet[0].data,
			     dnsqr->response_packet[0].len,
			     AXA_P2H_CH(whit->hdr.ch));
	}
}

static void
print_sie_dnsdedupe(const nmsg_message_t msg, const axa_nmsg_field_t *field,
		    const char *eq, const char *val)
{
	const char *type_str;
	const Nmsg__Sie__DnsDedupe *dnsdedupe;
	char ebuf[80];
	char response_ip_buf[INET6_ADDRSTRLEN];
	char rdata_buf[RDATA_BUF_LEN];
	char rrname_buf[NS_MAXDNAME];
	bool need_nl;

	if (verbose != 0) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	dnsdedupe = (Nmsg__Sie__DnsDedupe *)nmsg_message_get_payload(msg);

	if (!dnsdedupe->has_type) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}
	if (!enum_value_to_name(msg, "type", dnsdedupe->type, &type_str,
				ebuf, sizeof(ebuf))) {
		if (verbose > 1)
			printf("%s\n", ebuf);
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	printf("%s%s  %s\n", eq, val, type_str);

	/* Print the response IP only if we did not print it as the trigger. */
	need_nl = false;
	if ((field == NULL || strcmp(field->name, "response_ip") != 0)
	    && dnsdedupe->has_response_ip) {
		data_to_ip(response_ip_buf, sizeof(response_ip_buf),
			   dnsdedupe->response_ip.data,
			   dnsdedupe->response_ip.len, "response_ip");
		printf(NMSG_LEADER"response_ip=%s", response_ip_buf);
		need_nl = true;
	}
	/* Print the rdata only if we will not print the response packet,
	 * we did not print it as the trigger,
	 * and we can. */
	if (!dnsdedupe->has_response
	    && (field == NULL || strcmp(field->name, "rdata") != 0)
	    && dnsdedupe->n_rdata >= 1 && dnsdedupe->has_rrtype) {
                /* handle strange case of null rdata contents */
                if (dnsdedupe->rdata->len == 0
                    || dnsdedupe->rdata->data == NULL)
                    printf(NMSG_LEADER"rdata=");
                else
                    printf(NMSG_LEADER"rdata=%s",
		       rdata_to_buf(rdata_buf, sizeof(rdata_buf),
				    "rdata", dnsdedupe->rrtype,
				    dnsdedupe->rdata->data,
				    dnsdedupe->rdata->len));
		need_nl = true;
	}
	/* Print the domain name only if we will not print the response packet,
	 * we did not print it as the trigger,
	 * and we can. */
	if (!dnsdedupe->has_response
	    && (field == NULL || strcmp(field->name, "rrname") != 0)
	    && dnsdedupe->has_rrname) {
		axa_domain_to_str(dnsdedupe->rrname.data, dnsdedupe->rrname.len,
				  rrname_buf, sizeof(rrname_buf));
		printf(NMSG_LEADER"rrname=%s", rrname_buf);
		need_nl = true;
	}
	if (need_nl)
		fputc('\n', stdout);

	if (dnsdedupe->has_response)
		print_dns_pkt(dnsdedupe->response.data,
			      dnsdedupe->response.len, "response");
}

static void
print_sie_newdomain(const nmsg_message_t msg,
		    const axa_nmsg_field_t *field AXA_UNUSED,
		    const char *eq, const char *val)
{
	const Nmsg__Sie__NewDomain *newdomain;
	char rrname_buf[NS_MAXDNAME];
	char domain_buf[NS_MAXDNAME];
	char rtype_buf[10];

	if (verbose != 0) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	newdomain = (Nmsg__Sie__NewDomain *)nmsg_message_get_payload(msg);

	axa_domain_to_str(newdomain->rrname.data, newdomain->rrname.len,
			  rrname_buf, sizeof(rrname_buf));
	axa_rtype_to_str(rtype_buf, sizeof(rtype_buf), newdomain->rrtype);
	if (newdomain->domain.data)
		axa_domain_to_str(newdomain->domain.data, newdomain->domain.len,
				domain_buf, sizeof(domain_buf));
	printf("%s%s\n %s/%s: %s\n",
	       eq, val, rrname_buf, rtype_buf,
           newdomain->domain.data ? domain_buf : rrname_buf);
}

static void
print_nmsg_base_http(const nmsg_message_t msg, const axa_nmsg_field_t *field,
		     const char *eq, const char *val)
{
	char buf[NS_MAXDNAME];
	bool need_nl;

	if (verbose != 0) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	/* Print the triggering field name and its value. */
	printf("%s%s\n", eq, val);
	need_nl = false;

	/* Print the source and destination fields if not just now printed. */
	if (field == NULL || strcmp(field->name, "srcip") != 0) {
		fname_to_ip(buf, sizeof(buf), msg, "srcip", 0);
		printf(NMSG_LEADER"srcip=%s", buf);
		need_nl = true;
	}
	if (field == NULL || strcmp(field->name, "dstip") != 0) {
		fname_to_ip(buf, sizeof(buf), msg, "dstip", 0);
		printf(NMSG_LEADER"dstip=%s", buf);
		need_nl = true;
	}
	if (need_nl)
		fputc('\n', stdout);
}

static void
print_text(const char *text, size_t text_len)
{
	int lines;
	size_t line_len, skip;

	lines = 0;
	while (text_len > 0) {
		if (++lines >= 6) {
			fputs(NMSG_LEADER2"...\n", stdout);
			return;
		}
		line_len = 76;
		if (line_len > text_len) {
			line_len = text_len;
			skip = 0;
		} else {
			for (;;) {
				if (line_len < 60) {
					line_len = 76;
					skip = 0;
					break;
				}
				if (text[line_len] == ' '
				    || text[line_len] == '\t') {
					skip = 1;
					break;
				}
				--line_len;
			}
		}
		printf(NMSG_LEADER2"%.*s\n", (int)line_len, text);
		text += line_len+skip;
		text_len -= line_len+skip;
	}
}

static void
print_nmsg_base_encode(const nmsg_message_t msg,
		       const char *eq, const char *val)
{
	void *data;
	size_t data_len;
	const char *type_str;
	char ebuf[80];
	bool ok;

	ok = fname_enum_to_name(msg, "type", &type_str, ebuf, sizeof(ebuf));
	printf("%s%s  %s\n", eq, val, type_str);
	if (!ok)
		return;

	if (!get_nmsg_field(msg, "payload", 0,
			    &data, &data_len, ebuf, sizeof(ebuf))) {
		printf(NMSG_LEADER"%s\n", ebuf);
		return;
	}

	if (strcmp(type_str, "JSON") == 0) {
		print_text(data, data_len);
	} else if (strcmp(type_str, "TEXT") == 0
		   || strcmp(type_str, "YAML") == 0
		   || strcmp(type_str, "XML") == 0) {
		if (verbose == 0)
			return;
		print_text(data, data_len);
	} else {
		/* MessagePack seems to be binary */
		if (verbose == 0)
			return;
		print_raw(data, data_len);
	}
}

static void
print_nmsg_base_packet(const nmsg_message_t msg, const axa_p_whit_t *whit,
		       const char *eq, const char *val)
{
	void *data;
	size_t data_len;
	const char *type_str;
	char ebuf[80];
	bool ok;

	ok = fname_enum_to_name(msg, "payload_type",
				&type_str, ebuf, sizeof(ebuf));
	if (!ok) {
		printf("%s%s  %s\n", eq, val, type_str);
		return;
	}
	if (!get_nmsg_field(msg, "payload", 0,
			       &data, &data_len, ebuf, sizeof(ebuf))) {
		printf("%s%s  %s\n", eq, val, type_str);
		printf(NMSG_LEADER"%s\n", (char *)data);
		return;
	}

	printf("%s%s\n", eq, val);
	print_raw_ip(data, data_len, AXA_P2H_CH(whit->hdr.ch));
}

/*
 * Convert field index to field name and value string.
 */
static void
get_nm_eq_val(const nmsg_message_t msg, const axa_p_whit_t *whit,
	      const axa_nmsg_field_t **fieldp,
	      const char **nm, const char **eq, const char **val,
	      char *buf, size_t buf_len)
{
	const axa_nmsg_field_t *field;
	axa_nmsg_idx_t field_idx;
	void *data;
	size_t data_len;
	size_t n;

	field_idx = AXA_P2H_IDX(whit->nmsg.hdr.field_idx);
	if (field_idx == AXA_NMSG_IDX_ERROR) {
		strlcpy(buf, "ERROR", buf_len);
		*nm = buf;
		*eq = "";
		*val = "";
		*fieldp = NULL;
		return;
	} else if (field_idx == AXA_NMSG_IDX_DARK) {
		*nm = "";
		*eq = "";
		*val = "";
		*fieldp = NULL;
		return;
	} else if (field_idx >= AXA_NMSG_IDX_RSVD) {
		strlcpy(buf, "? unrecognized message", buf_len);
		*nm = buf;
		*eq = "";
		*val = "";
		*fieldp = NULL;
		return;
	}

	field = axa_msg_fields(msg);
	if (field == NULL) {
		strlcpy(buf, "? unrecognized message", buf_len);
		*nm = buf;
		*eq = "";
		*val = "";
		*fieldp = NULL;
		return;
	}
	for (;;) {
		if (field->idx == field_idx)
			break;
		field = field->next;
		if (field == NULL) {
			strlcpy(buf, "? unrecognized field", buf_len);
			*nm = buf;
			*eq = "";
			*val = "";
			return;
		}
	}
	*fieldp = field;

	switch (field->fc) {
	case AXA_FC_IP:
		*nm = field->name;
		*eq = "=";
		fname_to_ip(buf, buf_len, msg, field->name,
			    AXA_P2H_IDX(whit->nmsg.hdr.val_idx));
		*val = buf;
		break;

	case AXA_FC_DOM:
		*nm = field->name;
		*eq = "=";
		if (get_nmsg_field_by_idx(msg, field_idx,
					   AXA_P2H_IDX(whit->nmsg.hdr.val_idx),
					   &data, &data_len, buf, buf_len))
			axa_domain_to_str(data, data_len, buf, buf_len);
		*val = buf;
		break;

	case AXA_FC_IP_ASCII:
	case AXA_FC_DOM_ASCII:
	case AXA_FC_HOST:
		*nm = field->name;
		*eq = "=";
		if (get_nmsg_field_by_idx(msg, field_idx,
					  AXA_P2H_IDX(whit->nmsg.hdr.val_idx),
					  &data, &data_len, buf, buf_len)) {
			n = min(buf_len-1, data_len);
			memcpy(buf, data, n);
			buf[n] = '\0';
		}
		*val = buf;
		break;

	case AXA_FC_RDATA:
		*nm = field->name;
		*eq = "=";
		*val = rdata_nmsg_to_buf(buf, buf_len, msg, field,
					 AXA_P2H_IDX(whit->nmsg.hdr.val_idx));
		break;

	case AXA_FC_DNS:
	case AXA_FC_JSON:
	case AXA_FC_IP_DGRAM:
		*nm = field->name;
		*eq = "";
		*val = "";
		break;

	case AXA_FC_UNKNOWN:
		*nm = field->name;
		snprintf(buf, buf_len, " ? unknown field");
		*eq = buf;
		*val = "";
		break;

#pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		*nm = field->name;
		snprintf(buf, buf_len, " ? strange field #%d", field->fc);
		*eq = buf;
		*val = "";
		break;
#pragma clang diagnostic pop
	}
}

/* Create nmsg message from incoming watch hit containing a nmsg message */
axa_w2n_res_t
whit2nmsg(nmsg_message_t *msgp, axa_p_whit_t *whit, size_t whit_len)
{
	axa_w2n_res_t res;

	res = axa_whit2nmsg(&emsg, nmsg_input, msgp, whit, whit_len);
	switch (res) {
		case AXA_W2N_RES_FAIL:
			clear_prompt();
			error_msg("%s", emsg.c);
			disconnect(true);
		case AXA_W2N_RES_SUCCESS:
		case AXA_W2N_RES_FRAGMENT:
			break;
	}
	return (res);
}

static void
print_nmsg(axa_p_whit_t *whit, size_t whit_len,
	   const char *title_sep, const char *title)
{
	axa_nmsg_idx_t vid, type;
	char tag_buf[AXA_TAG_STRLEN];
	const axa_nmsg_field_t *field;
	char vendor_buf[12], mname_buf[12], field_buf[RDATA_BUF_LEN];
	const char *vendor, *mname, *nm, *eq, *val;
	char group[40];
	const char *cp;
	nmsg_message_t msg;
	uint n;

	if (whit2nmsg(&msg, whit, whit_len) == AXA_W2N_RES_FRAGMENT) {
		if (axa_debug != 0)
			printf("ignoring NMSG fragment from "
					AXA_OP_CH_PREFIX"%d",
					AXA_P2H_CH(whit->hdr.ch));
		return;
	}
	if (msg == NULL)
		return;

	/* Convert binary vendor ID, message type, and field index to
	 * vendor name, message type string, field name, and field value. */
	vid = AXA_P2H_IDX(whit->nmsg.hdr.vid);
	type = AXA_P2H_IDX(whit->nmsg.hdr.type);
	vendor = nmsg_msgmod_vid_to_vname(vid);
	if (vendor == NULL) {
		snprintf(vendor_buf, sizeof(vendor_buf), "ID #%d", vid);
		vendor = vendor_buf;
	}
	mname = nmsg_msgmod_msgtype_to_mname(vid, type);
	if (mname == NULL) {
		snprintf(mname_buf, sizeof(mname_buf), "#%d", type);
		mname = mname_buf;
	}
	field = NULL;			/* silence gcc warning */
	get_nm_eq_val(msg, whit, &field, &nm, &eq, &val,
		      field_buf, sizeof(field_buf));

	cp = NULL;
	n = nmsg_message_get_group(msg);
	if (n != 0)
		cp = nmsg_alias_by_key(nmsg_alias_group, n);
	if (cp == NULL)
		group[0] = '\0';
	else
		snprintf(group, sizeof(group), " %s", cp);

	/* Print what we have so far,
	 * except the value which might be redundant */
	clear_prompt();
	printf("%s%s%s "AXA_OP_CH_PREFIX"%d  %s %s%s %s",
	       axa_tag_to_str(tag_buf, sizeof(tag_buf),
			      AXA_P2H_TAG(client.io.recv_hdr.tag)),
	       title_sep, title,
	       AXA_P2H_CH(whit->hdr.ch), vendor, mname, group, nm);

	switch (vid) {
	case NMSG_VENDOR_BASE_ID:
		switch (type) {
		case NMSG_VENDOR_BASE_DNSQR_ID:
			print_nmsg_base_dnsqr(msg, eq, val, whit);
			break;
		case NMSG_VENDOR_BASE_HTTP_ID:
			print_nmsg_base_http(msg, field, eq, val);
			break;
		case NMSG_VENDOR_BASE_ENCODE_ID:
			print_nmsg_base_encode(msg, eq, val);
			break;
		case NMSG_VENDOR_BASE_PACKET_ID:
			print_nmsg_base_packet(msg, whit, eq, val);
			break;
		default:
			print_verbose_nmsg(msg, eq, val);
			break;
		}
		break;

	case NMSG_VENDOR_SIE_ID:
		switch (type) {
		case NMSG_VENDOR_SIE_DNSDEDUPE_ID:
			print_sie_dnsdedupe(msg, field, eq, val);
			break;
		case NMSG_VENDOR_SIE_NEWDOMAIN_ID:
			print_sie_newdomain(msg, field, eq, val);
			break;
		default:
			print_verbose_nmsg(msg, eq, val);
			break;
		}
		break;

	default:
		print_verbose_nmsg(msg, eq, val);
		break;
	}

	nmsg_message_destroy(&msg);
}

void
print_whit(axa_p_whit_t *whit, size_t whit_len,
	   const char *title_sep, const char *title)
{
	struct timeval now;
	time_t ms;
	char tag_buf[AXA_TAG_STRLEN];
	bool fwded;

	/* Forward binary packets if necessary. */
	if (out_on) {
		if (out_nmsg_output != NULL) {
			fwded = out_whit_nmsg(whit, whit_len);
		} else {
			AXA_ASSERT(out_pcap != NULL);
			fwded = out_whit_pcap(whit, whit_len);
		}
		if (fwded && --output_count == 0 && output_counting) {
			clear_prompt();
			printf("output %d packets to %s finished\n",
			       output_count_total, out_addr);
			out_close(true);
		}
	}

	if (--packet_count < 0 && packet_counting) {
		clear_prompt();
		if (packet_count == -1) {
			fputs("\npacket count limit exceeded\n", stdout);
		} else if (in_file_cur == 0 && el_e != NULL) {
			gettimeofday(&now, NULL);
			ms = axa_elapsed_ms(&now, &out_bar_time);
			if (ms >= PROGRESS_MS) {
				fputs(out_bar_strs[out_bar_idx], stdout);
				fflush(stdout);
				no_reprompt = now;
				++out_bar_idx;
				out_bar_idx %= AXA_DIM(out_bar_strs);
				out_bar_time = now;
			}
		}
		return;
	}

	clear_prompt();
	switch ((axa_p_whit_enum_t)whit->hdr.type) {
	case AXA_P_WHIT_NMSG:
		print_nmsg(whit, whit_len, title_sep, title);
		return;
	case AXA_P_WHIT_IP:
		if (whit_len <= sizeof(whit->ip)) {
			error_msg("truncated IP packet");
			disconnect(true);
			return;
		}

		printf("%s%s%s "AXA_OP_CH_PREFIX"%d\n",
		       axa_tag_to_str(tag_buf, sizeof(tag_buf),
				      AXA_P2H_TAG(client.io.recv_hdr.tag)),
		       title_sep, title,
		       AXA_P2H_CH(whit->hdr.ch));
		print_raw_ip(whit->ip.b, whit_len - sizeof(whit->ip.hdr),
			     AXA_P2H_CH(whit->hdr.ch));
		return;
	}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	error_msg("unrecognized message type %d", whit->hdr.type);
	disconnect(true);
#pragma clang diagnostic pop
}

void
print_ahit(void)
{
	print_whit(&client.io.recv_body->ahit.whit,
		   client.io.recv_hdr.len
		   - (sizeof(client.io.recv_hdr)
		      + sizeof(client.io.recv_body->ahit)
		      - sizeof(client.io.recv_body->ahit.whit)),
		   " ", client.io.recv_body->ahit.an.c);
}

void
print_channel(void)
{
	const axa_p_clist_t *clist;
	axa_p_ch_buf_t buf;

	clear_prompt();
	clist = &client.io.recv_body->clist;
	snprintf(buf.c, sizeof(buf),
		 AXA_OP_CH_PREFIX"%d", AXA_P2H_CH(clist->ch));
	printf(" %8s %3s %s\n",
	       buf.c, clist->on != 0 ? "on" : "off", clist->spec.c);
}

void
wlist_alist(void)
{
	axa_tag_t list_tag;
	char hdr_tag_buf[AXA_TAG_STRLEN];
	char list_tag_buf[AXA_TAG_STRLEN];
	char buf[AXA_P_STRLEN];

	if (client.io.recv_hdr.op == AXA_P_OP_WLIST)
		list_tag = client.io.recv_body->wlist.cur_tag;
	else
		list_tag = client.io.recv_body->alist.cur_tag;
	axa_tag_to_str(list_tag_buf, sizeof(list_tag_buf),
		       AXA_P2H_TAG(list_tag));

	clear_prompt();
	if (client.io.recv_hdr.tag != AXA_P2H_TAG(AXA_TAG_NONE)
	    && client.io.recv_hdr.tag != list_tag)
		printf("     nearest %s to %s is %s\n",
		       mode == RAD ? "anomaly" : "watch",
		       axa_tag_to_str(hdr_tag_buf, sizeof(hdr_tag_buf),
				      client.io.recv_hdr.tag),
		       list_tag_buf);

	printf("%7s %s\n",
	       list_tag_buf, axa_p_to_str(buf, sizeof(buf), false,
					  &client.io.recv_hdr,
					  client.io.recv_body));
}

void
count_print(bool always)
{
	if (always && !packet_counting)
		printf("    packet printing not limited by count\n"
				"        %d packets recently printed\n",
				0 - packet_count);
	else if (packet_count < 0)
		printf("    packet printing stopped by count %d packets ago\n",
				0 - packet_count);
	else
		printf("    %d packets remaining to print of %d total\n",
				packet_count, packet_count_total);

	if (!out_on)
		return;
	if (!output_counting)
		printf("    packet output or forwarding not limited by count\n"
				"        %d packets recently output\n",
				0 - output_count);
	else if (output_count < 0)
		printf("    packet output or forwarding stopped by count"
				" %d packets ago\n",
				0 - output_count);
	else
		printf("    %d packets remaining to output or forward of"
				" %d total\n",
				output_count, output_count_total);
}

static void
print_stats_sys(_axa_p_stats_sys_t *sys)
{
	int j, ch_cnt;
	struct timeval tv;
	const char *server_type;
	uint32_t user_cnt;
	axa_ch_mask_t mask;

	if (sys->type != _AXA_P_STATS_TYPE_SYS) {
		printf("expected system/server stats, got type \"%d\"\n",
				sys->type);
		return;
	}

	/* UINT32_MAX or UINT64_MAX == server error in gathering stat */
	if (sys->uptime == UINT32_MAX) {
		printf("    server uptime   : unavailable\n");
	}
	else {
		gettimeofday(&tv, NULL);
		tv.tv_sec -= AXA_P2H32(sys->uptime);
		printf("    server uptime   : %s\n", convert_timeval(&tv));
	}
	if (sys->load[0] == UINT32_MAX && sys->load[1] == UINT32_MAX &&
			sys->load[2] == UINT32_MAX) {
		printf("    server load     : unavailable\n");
	}
	else {
		printf("    server load     : %.2f %.2f %.2f\n",
				AXA_P2H32(sys->load[0]) * .0001,
				AXA_P2H32(sys->load[1]) * .0001,
				AXA_P2H32(sys->load[2]) * .0001);
	}

	server_type = sys->server_type == _AXA_STATS_SRVR_TYPE_SRA
		? "sra" : "rad";
	printf("    %s sys\n", server_type);
	if (sys->cpu_usage == UINT32_MAX) {
		printf("      CPU usage     : unavailable\n");
	}
	else {
		printf("      CPU usage     : %.2f%%\n",
				AXA_P2H32(sys->cpu_usage) * .0001);
	}
	if (sys->starttime == UINT32_MAX) {
		printf("      uptime        : unavailable\n");
	}
	else {
		gettimeofday(&tv, NULL);
		tv.tv_sec -= (AXA_P2H32(sys->uptime) -
				AXA_P2H32(sys->starttime));
		printf("      uptime        : %s\n", convert_timeval(&tv));
	}
	if (sys->vmsize == UINT64_MAX) {
		printf("      VM size       : unavailable\n");
	}
	else {
		printf("      VM size       : %"PRIu64"m\n",
				AXA_P2H64(sys->vmsize) / (1024 * 1024));
	}
	if (sys->vmrss == UINT64_MAX) {
		printf("      VM RSS        : unavailable\n");
	}
	else {
		printf("      VM RSS        : %"PRIu64"kb\n",
				AXA_P2H64(sys->vmrss) / 1024);
	}
	if (sys->thread_cnt == UINT32_MAX) {
		printf("      thread cnt    : unavailable\n");
	}
	else {
		printf("      thread cnt    : %"PRIu32"\n",
				AXA_P2H32(sys->thread_cnt));
	}
	if (sys->server_type != _AXA_STATS_SRVR_TYPE_RAD) {
		/* radd doesn't run as root so it can't read
		 * /proc/[pid]/fdinfo or /proc/[pid]/io
		 */
		printf("    open file descriptors\n");
		if (sys->fd_sockets == UINT32_MAX) {
			printf("      socket        : unavailable\n");
		}
		else {
			printf("      socket        : %"PRIu32"\n",
					AXA_P2H32(sys->fd_sockets));
		}
		if (sys->fd_pipes == UINT32_MAX) {
			printf("      pipe          : unavailable\n");
		}
		else {
			printf("      pipe          : %"PRIu32"\n",
					AXA_P2H32(sys->fd_pipes));
		}
		if (sys->fd_anon_inodes == UINT32_MAX) {
			printf("      anon_inode    : unavailable\n");
		}
		else {
			printf("      anon_inode    : %"PRIu32"\n",
					AXA_P2H32(sys->fd_anon_inodes));
		}
		if (sys->fd_other == UINT32_MAX) {
			printf("      other         : unavailable\n");
		}
		else {
			printf("      other         : %"PRIu32"\n",
					AXA_P2H32(sys->fd_other));
		}
		if (sys->rchar == UINT64_MAX) {
			printf("    rchar           : unavailable\n");
		}
		else {
			printf("    rchar           : %"PRIu64"\n",
					AXA_P2H64(sys->rchar));
		}
		if (sys->wchar == UINT64_MAX) {
			printf("    wchar           : unavailable\n");
		}
		else {
			printf("    wchar           : %"PRIu64"\n",
					AXA_P2H64(sys->wchar));
		}
	}
	user_cnt = AXA_P2H32(sys->user_cnt);
	printf("    users           : %d\n", user_cnt);

	if (sys->server_type == _AXA_STATS_SRVR_TYPE_SRA) {
		printf("    watches\n");
		printf("      ipv4 watches  : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.ipv4_cnt));
		printf("      ipv6 watches  : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.ipv6_cnt));
		printf("      dns watches   : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.dns_cnt));
		printf("      ch watches    : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.ch_cnt));
		printf("      err watches   : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.err_cnt));
		printf("      total watches : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.ipv4_cnt) +
			AXA_P2H32(sys->srvr.sra.watches.ipv6_cnt) +
			AXA_P2H32(sys->srvr.sra.watches.dns_cnt) +
			AXA_P2H32(sys->srvr.sra.watches.ch_cnt) +
			AXA_P2H32(sys->srvr.sra.watches.err_cnt));
		printf("    channels        : ");
		mask = sys->srvr.sra.ch_mask;
		for (j = ch_cnt = 0; j <= AXA_NMSG_CH_MAX; j++) {
			if (axa_get_bitwords(
				mask.m, j)) {
					printf("%u ", j);
					ch_cnt++;
			}
		}
		if (ch_cnt == 0)
			printf("none");
		printf("\n");
	}
	else /* AXA_STATS_SRVR_TYPE_RAD */ {
		printf("      anomalies     : %u\n",
			AXA_P2H32(sys->srvr.rad.an_cnt));
	}
}

static void
print_stats_user_an(_axa_p_stats_user_rad_an_t *an_obj)
{
	int j, ch_cnt;
	char ru_buf[sizeof("unlimited") + 4];
	axa_ch_mask_t mask;

	printf("        anomaly     : %s\n", an_obj->name);
	printf("        options     : %s\n", an_obj->opt);

	memset(&ru_buf, 0, sizeof (ru_buf));

	if (an_obj->ru_original == INT_MAX)
		strlcpy(ru_buf, "unlimited", sizeof(ru_buf));
	else
		snprintf(ru_buf, sizeof (ru_buf) - 1, "%d",
				an_obj->ru_original);
	printf("        RU (orig)   : %s\n", ru_buf);
	if (an_obj->ru_current == INT_MAX)
		strlcpy(ru_buf, "unlimited", sizeof(ru_buf));
	else
		snprintf(ru_buf, sizeof (ru_buf) - 1, "%d",
				an_obj->ru_current);
	printf("        RU (cur)    : %s\n", ru_buf);
	printf("        RU (cost)   : %d\n", AXA_P2H32(an_obj->ru_cost));
	printf("        channels    : ");
	mask = an_obj->ch_mask;
	for (j = ch_cnt = 0; j <= AXA_NMSG_CH_MAX; j++) {
		if (axa_get_bitwords(mask.m, j)) {
				printf("%d ", j);
				ch_cnt++;
		}
	}
	if (ch_cnt == 0)
		printf("none");
	printf("\n\n");
}

static int
print_stats_user(_axa_p_stats_user_t *user)
{
	uint8_t *p;
	time_t t;
	int j, ch_cnt, bytes_printed = 0, an_objs_cnt;
	struct timeval connected_since, last_cnt_update;
	struct tm *tm_info;
	const char *io_type;
	char time_buf[30];
	char addr_str[INET6_ADDRSTRLEN];
	axa_ch_mask_t mask;

	if (user->type != _AXA_P_STATS_TYPE_USER) {
		printf("expected user object, got type \"%d\"\n", user->type);
		return (0);
	}

	printf("\n    user            : %s (%s)\n", user->user.name,
			user->is_admin == 1 ? "admin" : "non-admin");
	switch (user->addr_type)
	{
		case AXA_AF_INET:
			inet_ntop(AF_INET, &user->ip.ipv4, addr_str,
					sizeof(addr_str));
			break;
		case AXA_AF_INET6:
			inet_ntop(AF_INET6, &user->ip.ipv6, addr_str,
					sizeof(addr_str));
			break;
		case AXA_AF_UNKNOWN:
			strlcpy(addr_str, "unknown", sizeof(addr_str));
			break;
	}
	printf("      from          : %s\n", addr_str);
	printf("      serial number : %u\n", AXA_P2H32(user->sn));
	connected_since.tv_sec = user->connected_since.tv_sec;
	connected_since.tv_usec = user->connected_since.tv_usec;
	t = AXA_P2H32(connected_since.tv_sec);
	tm_info = gmtime(&t);
		strftime(time_buf, sizeof (time_buf),
				"%Y-%m-%dT%H:%M:%SZ", tm_info);
	printf("      since         : %s (%s)\n", time_buf,
			convert_timeval(&connected_since));

	switch (user->io_type) {
		case AXA_IO_TYPE_UNIX:
			io_type = AXA_IO_TYPE_UNIX_STR;
			break;
		case AXA_IO_TYPE_TCP:
			io_type = AXA_IO_TYPE_TCP_STR;
			break;
		case AXA_IO_TYPE_APIKEY:
			io_type = AXA_IO_TYPE_APIKEY_STR;
			break;
		case AXA_IO_TYPE_UNKN:
		default:
			io_type = "unknown";
			break;
	}
	printf("      transport     : %s\n", io_type);
	switch (mode) {
		case SRA:
			printf("      channels      : ");
			mask = user->srvr.sra.ch_mask;
			for (j = ch_cnt = 0; j <= AXA_NMSG_CH_MAX; j++) {
				if (axa_get_bitwords(
					mask.m, j)) {
						printf("%d ", j);
						ch_cnt++;
				}
			}
			if (ch_cnt == 0)
				printf("none");
			printf("\n");
			printf("      ipv4 watches  : %d\n",
				AXA_P2H32(
					user->srvr.sra.watches.ipv4_cnt));
			printf("      ipv6 watches  : %d\n",
				AXA_P2H32(
					user->srvr.sra.watches.ipv6_cnt));
			printf("      dns watches   : %d\n",
				AXA_P2H32(
					user->srvr.sra.watches.dns_cnt));
			printf("      ch watches    : %d\n",
				AXA_P2H32(
					user->srvr.sra.watches.ch_cnt));
			printf("      err watches   : %d\n",
				AXA_P2H32(
					user->srvr.sra.watches.err_cnt));
			break;
		case RAD:
			printf("      anomalies     : %d\n",
				AXA_P2H32(user->srvr.rad.an_obj_cnt));
			break;
		case BOTH:
			break;
	}
	printf("      rate-limiting : ");
	if (AXA_P2H64(user->ratelimit) == AXA_RLIMIT_OFF)
		printf("off\n");
	else
		printf("%"PRIu64"\n", AXA_P2H64(user->ratelimit));
	printf("      sampling      : %.2f%%\n",
			AXA_P2H64(user->sample) * .0001);

	if (mode == RAD && user->srvr.rad.an_obj_cnt > 0) {
		if (user->srvr.rad.an_obj_cnt >
			_AXA_STATS_MAX_USER_RAD_AN_OBJS) {
			printf("invalid rad anomaly object count: %u",
					user->srvr.rad.an_obj_cnt);
			return (bytes_printed);
		}

		printf("      loaded modules\n");
		p = (uint8_t *)user + sizeof (_axa_p_stats_user_t);
		for (an_objs_cnt = user->srvr.rad.an_obj_cnt; an_objs_cnt;
				an_objs_cnt--) {
			print_stats_user_an((_axa_p_stats_user_rad_an_t *)p);
			bytes_printed += sizeof(_axa_p_stats_user_rad_an_t);
			p += sizeof(_axa_p_stats_user_rad_an_t);
		}
	}

	printf("      packet counters\n");
	last_cnt_update.tv_sec = user->last_cnt_update.tv_sec;
	last_cnt_update.tv_usec = user->last_cnt_update.tv_usec;
	t = AXA_P2H32(last_cnt_update.tv_sec);
	tm_info = gmtime(&t);
	strftime(time_buf, sizeof (time_buf), "%Y-%m-%dT%H:%M:%SZ", tm_info);
	printf("      last updated  : %s (%s)\n", time_buf,
			convert_timeval(&last_cnt_update));
	printf("        filtered    : %"PRIu64"\n",
			AXA_P2H64(user->filtered));
	printf("        missed      : %"PRIu64"\n",
			AXA_P2H64(user->missed));
	printf("        collected   : %"PRIu64"\n",
			AXA_P2H64(user->collected));
	printf("        sent        : %"PRIu64"\n",
			AXA_P2H64(user->sent));
	printf("        rlimit      : %"PRIu64"\n",
			AXA_P2H64(user->rlimit));
	printf("        congested   : %"PRIu64"\n",
			AXA_P2H64(user->congested));

	bytes_printed += sizeof (_axa_p_stats_user_t);
	return (bytes_printed);
}

void
print_stats(_axa_p_stats_rsp_t *stats, uint32_t len)
{
	uint16_t user_objs_cnt;
	uint8_t *p;
	int q = 0;

	if (stats->version != _AXA_STATS_VERSION_ONE) {
		printf("server returned unknown stats protocol version %d\n",
				stats->version);
		return;
	}

	if (axa_debug != 0) {
		printf("    stats_len       : %ub\n", AXA_P2H32(len));
	}

	switch (stats->result) {
		case AXA_P_STATS_R_SUCCESS:
			printf("    success\n");
			break;
		case AXA_P_STATS_R_FAIL_NF:
			printf("    failed, user/sn not found\n");
			return;
		case AXA_P_STATS_R_FAIL_UNK:
			printf("    failed, unknown reason\n");
			return;
		default:
			printf("    unknown result code\n");
			return;
	}

	if (stats->sys_objs_cnt > 1) {
		printf("invalid stats response: too many sys objects (%u > 1)\n", stats->sys_objs_cnt);
		return;
	}

	if (stats->user_objs_cnt > _AXA_STATS_MAX_USER_OBJS) {
		printf("invalid stats response: too many user objects (%u > %u)\n", stats->user_objs_cnt, _AXA_STATS_MAX_USER_OBJS);
		return;
	}

	p = (uint8_t *)stats + sizeof(_axa_p_stats_rsp_t);
	if (stats->sys_objs_cnt == 1)
		print_stats_sys((_axa_p_stats_sys_t *)p);

	p += (stats->sys_objs_cnt * sizeof (_axa_p_stats_sys_t));
	for (user_objs_cnt = stats->user_objs_cnt; user_objs_cnt;
			user_objs_cnt--) {
		q = print_stats_user((_axa_p_stats_user_t *)p);
		p += q;
	}
}

void
print_kill(_axa_p_kill_t *kill, size_t len AXA_UNUSED)
{
	switch (kill->result) {
		case AXA_P_KILL_R_SUCCESS:
			printf("    success\n");
			break;
		case AXA_P_KILL_R_FAIL_NF:
			printf("    failed, %s not found\n",
					kill->mode == AXA_P_KILL_M_SN ?
					"serial number" : "user");
			break;
		case AXA_P_KILL_R_FAIL_UNK:
			printf("    failed, unknown reason\n");
			break;
	}
}

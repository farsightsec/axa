/*
 * AXA protocol utilities
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

#include <axa/axa_endian.h>
#include <axa/wire.h>

#include <nmsg.h>
#include <wdns.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <limits.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#define __FAVOR_BSD			/* for Debian tcp.h and udp.h */
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
#include <time.h>			/* for localtime() and strftime() */
#endif
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>


/* Point to the value string after "ip=", "dns=", or "ch=".
 * Allow whitespace around '=' or instead of '='.
 */
static const char *
get_value(const char *arg,
	  const char *type, size_t type_len)	/* "ip", "dns", or "ch" */
{
	size_t sep_len;

	if (strncasecmp(arg, type, type_len) != 0)
		return (NULL);
	arg += strlen(type);
	sep_len = strspn(arg, AXA_WHITESPACE);
	arg += sep_len;
	if (*arg == '=') {
		++arg;
		arg += strspn(arg, AXA_WHITESPACE);
	} else if (sep_len == 0) {
		return (NULL);
	}
	return (arg);
}

/*
 * Parse an AXA watch definition.
 *	false=problem
 *	    with emsg->c a relevant error message except when the watch
 *	    makes no sense.  In that case, emsg->c[0] == '\0'.
 */
bool
axa_parse_watch(axa_emsg_t *emsg,
		axa_p_watch_t *watch,	/* parsed result */
		size_t *watch_len,
		const char *arg)	/* null terminated input */
{
	const char *value;
	int prefix;
	axa_socku_t su;
	axa_p_ch_t ch;
	wdns_name_t name;

	memset(watch, 0, sizeof(*watch));
	*watch_len = sizeof(*watch) - sizeof(watch->pat);

	if ((value = get_value(arg, "ip", sizeof("ip")-1)) != NULL) {
		if (*value == '\0') {
			axa_pemsg(emsg, "missing IP address");
			return (false);
		}
		prefix = axa_str_to_cidr(emsg, &su, value);
		if (prefix <= 0)
			return (false);
		watch->prefix = prefix;
		if (su.sa.sa_family == AF_INET) {
			watch->type = AXA_P_WATCH_IPV4;
			if (watch->prefix < 32)
				watch->flags |= AXA_P_WATCH_FG_WILD;
			watch->pat.addr = su.ipv4.sin_addr;
			/* Be conservative in what we send by not trimming
			 * the address. */
			*watch_len += sizeof(watch->pat.addr);
		} else {
			watch->type = AXA_P_WATCH_IPV6;
			if (watch->prefix < 128)
				watch->flags |= AXA_P_WATCH_FG_WILD;
			watch->pat.addr6 = su.ipv6.sin6_addr;
			/* Be conservative in what we send by not trimming
			 * the address. */
			*watch_len += sizeof(watch->pat.addr6);
		}
		return (true);
	}

	if ((value = get_value(arg, "dns", sizeof("dns")-1)) != NULL) {
		watch->type = AXA_P_WATCH_DNS;
		if (*value == '*') {
			watch->flags |= AXA_P_WATCH_FG_WILD;
			if (*++value == '.' && value[1] != '\0')
				++value;
		}
		if (*value == '\0') {
			axa_pemsg(emsg, "missing domain name");
			return (false);
		}
		name.data = NULL;
		if (wdns_str_to_name(value, &name) != wdns_res_success) {
			axa_pemsg(emsg, "invalid DNS name \"%s\"", value);
			return (false);
		}
		memcpy(watch->pat.dns, name.data, name.len);
		*watch_len += name.len;
		free(name.data);
		return (true);
	}

	if ((value = get_value(arg, AXA_OP_CH_PREFIX,
			       sizeof(AXA_OP_CH_PREFIX)-1)) != NULL) {
		if (*value == '\0') {
			axa_pemsg(emsg, "missing channel");
			return (false);
		}
		watch->type = AXA_P_WATCH_CH;
		if (!axa_parse_ch(emsg, &ch,
				  value, strlen(value), false, true))
			return (false);
		watch->pat.ch = AXA_H2P_CH(ch);
		*watch_len += sizeof(watch->pat.ch);
		return (true);
	}

	if (AXA_CLITCMP(arg, "errors")) {
		arg += sizeof("errors")-1;
		arg += strspn(arg, AXA_WHITESPACE);
		if (*arg == '\0') {
			watch->type = AXA_P_WATCH_ERRORS;
			return (true);
		}
	}
	if (AXA_CLITCMP(arg, "error")) {
		arg += sizeof("error")-1;
		arg += strspn(arg, AXA_WHITESPACE);
		if (*arg == '\0') {
			watch->type = AXA_P_WATCH_ERRORS;
			return (true);
		}
	}

	/* Let the caller handle nonsense watches */
	emsg->c[0] = '\0';
	return (false);
}

static bool
get_flag(axa_p_watch_t *watch, u_int bit,
	 char **strp, const char *flag, size_t flag_len)
{
	char *str;

	str = *strp;
	if (strncasecmp(str, flag, flag_len) != 0)
		return (false);
	str += flag_len;
	if (*str == ',') {
		++str;
	} else if (*str != ')') {
		return (false);
	}
	watch->flags |= bit;
	*strp = str;
	return (true);
}

/*
 * Parse an RAD watch definition.
 *	An empty emsg->c indicates an unrecognized type of watch.
 */
bool
axa_parse_rad_watch(axa_emsg_t *emsg,
		    axa_p_watch_t *watch,   /* parsed result */
		    size_t *watch_len,
		    const char *arg)	/* null terminated */
{
	char *str, *flags;

	str = axa_strdup(arg);
	flags = strchr(str, '(');
	if (flags != NULL)
		*flags++ = '\0';

	if (!axa_parse_watch(emsg, watch, watch_len, str)) {
		free(str);
		return (false);
	}

	switch ((axa_p_watch_type_t)watch->type) {
	case AXA_P_WATCH_IPV4:
	case AXA_P_WATCH_IPV6:
	case AXA_P_WATCH_DNS:
		break;
	case AXA_P_WATCH_CH:
		axa_pemsg(emsg, "channel watches not available");
		free(str);
		return (false);
	case AXA_P_WATCH_ERRORS:
		axa_pemsg(emsg, "error watches not available");
		free(str);
		return (false);
	default:
		AXA_FAIL("impossible message type");
	}

	if (flags != NULL && *flags != '\0') {
		do {
			if (get_flag(watch, AXA_P_WATCH_FG_SHARED,
				     &flags, AXA_P_WATCH_STR_SHARED,
				     sizeof(AXA_P_WATCH_STR_SHARED)-1))
				continue;
			axa_pemsg(emsg, "unrecognized flag \"(%s\"", flags);
			free(str);
			return (false);
		} while (strcmp(flags, ")") != 0);
	}
	free(str);
	return (true);
}

/* Parse an AXA anomaly detection module definition.
 *	false=problem
 *	    emsg->c is a relevant error message except when the watch
 *	    makes no sense.  In that case, emsg->c[0] == '\0'. */
bool
axa_parse_anom(axa_emsg_t *emsg,
	       axa_p_anom_t *anom,	/* parsed result */
	       size_t *anom_len,	/* parsed result length */
	       const char *arg)		/* null terminated input */
{
	const char *parms;
	size_t an_len, parms_len;

	memset(anom, 0, sizeof(*anom));

	/* require "name[ parameters]" */
	if (arg[0] == '\0') {
		axa_pemsg(emsg, "missing name");
		return (false);
	}
	parms = strpbrk(arg, AXA_WHITESPACE);
	if (parms == NULL) {
		an_len = strlen(arg);
		parms = arg+an_len;
	} else {
		an_len = parms - arg;
	}
	if (an_len >= sizeof(anom->an)) {
		axa_pemsg(emsg, "name \"%.*s\" too long",
			  (int)an_len, arg);
		return (false);
	}
	memcpy(&anom->an, arg, an_len);

	parms += strspn(parms, AXA_WHITESPACE);
	parms_len = strlen(parms)+1;
	if (parms_len >= sizeof(anom->parms)) {
		axa_pemsg(emsg, "parameters \"%s\" too long", parms);
		return (false);
	}
	memcpy(&anom->parms, parms, parms_len);
	*anom_len = sizeof(*anom) - sizeof(anom->parms) + parms_len;

	return (true);
}

const char *
axa_tag_to_str(char *buf, size_t buf_len,   /* should be AXA_TAG_STRLEN */
	       axa_tag_t tag)
{
	if (tag == AXA_TAG_NONE)
		strlcpy(buf, "*", buf_len);
	else
		snprintf(buf, buf_len, "%d", tag);
	return (buf);
}

const char *
axa_op_to_str(char *buf, size_t buflen,	/* should be AXA_P_OP_STRLEN */
	      axa_p_op_t op)
{
	switch (op) {
	case AXA_P_OP_HELLO:	strlcpy(buf, "HELLO",		buflen); break;
	case AXA_P_OP_NOP:	strlcpy(buf, "NOP",		buflen); break;
	case AXA_P_OP_OK:	strlcpy(buf, "OK",		buflen); break;
	case AXA_P_OP_ERROR:	strlcpy(buf, "ERROR",		buflen); break;
	case AXA_P_OP_WHIT:	strlcpy(buf, "WATCH HIT",	buflen); break;
	case AXA_P_OP_AHIT:	strlcpy(buf, "ANOMALY HIT",	buflen); break;
	case AXA_P_OP_MISSED:	strlcpy(buf, "MISSED",		buflen); break;
	case AXA_P_OP_WLIST:	strlcpy(buf, "WATCH LIST",	buflen); break;
	case AXA_P_OP_ALIST:	strlcpy(buf, "ANOMALY LIST",	buflen); break;
	case AXA_P_OP_CLIST:	strlcpy(buf, "CHANNEL LIST",	buflen); break;
	case AXA_P_OP_MISSED_RAD: strlcpy(buf, "RAD MISSED",	buflen); break;

	case AXA_P_OP_USER:	strlcpy(buf, "USER",		buflen); break;
	case AXA_P_OP_JOIN:	strlcpy(buf, "JOIN",		buflen); break;
	case AXA_P_OP_PAUSE:	strlcpy(buf, "PAUSE",		buflen); break;
	case AXA_P_OP_GO:	strlcpy(buf, "GO",		buflen); break;
	case AXA_P_OP_WATCH:	strlcpy(buf, "WATCH",		buflen); break;
	case AXA_P_OP_WGET:	strlcpy(buf, "WATCH GET",	buflen); break;
	case AXA_P_OP_ANOM:	strlcpy(buf, "ANOMALY",		buflen); break;
	case AXA_P_OP_AGET:	strlcpy(buf, "ANOMALY GET",	buflen); break;
	case AXA_P_OP_STOP:	strlcpy(buf, "STOP",		buflen); break;
	case AXA_P_OP_ALL_STOP:	strlcpy(buf, "ALL STOP",	buflen); break;
	case AXA_P_OP_CHANNEL:	strlcpy(buf, "CHANNEL ON/OFF",	buflen); break;
	case AXA_P_OP_CGET:	strlcpy(buf, "CHANNEL GET",	buflen); break;
	case AXA_P_OP_OPT:	strlcpy(buf, "OPTION",		buflen); break;
	case AXA_P_OP_ACCT:	strlcpy(buf, "ACCOUNTING",	buflen); break;
	case AXA_P_OP_RADU:	strlcpy(buf, "RAD UNITS GET",	buflen); break;
	case AXA_P_OP_MGMT_GET:	strlcpy(buf, "MGMT GET",	buflen); break;
	case AXA_P_OP_MGMT_GETRSP:strlcpy(buf, "MGMT GET RSP",	buflen); break;
	case _AXA_P_OP_KILL_REQ:strlcpy(buf, "KILL REQ",	buflen); break;
	case _AXA_P_OP_KILL_RSP:strlcpy(buf, "KILL RSP",	buflen); break;
	case _AXA_P_OP_STATS_REQ:strlcpy(buf,"STATS REQ",	buflen); break;
	case _AXA_P_OP_STATS_RSP:strlcpy(buf,"STATS RSP",	buflen); break;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		snprintf(buf, buflen, "unknown op #%d", op);
#pragma clang diagnostic pop
	}
	return (buf);
}

const char *
axa_opt_to_str(char *buf, size_t buflen, axa_p_opt_type_t opt)
{
	switch (opt) {
	case AXA_P_OPT_TRACE:	strlcpy(buf, "TRACE",	    buflen); break;
	case AXA_P_OPT_RLIMIT:	strlcpy(buf, "RATE LIMIT",  buflen); break;
	case AXA_P_OPT_SAMPLE:	strlcpy(buf, "SAMPLE",	    buflen); break;
	case AXA_P_OPT_SNDBUF:	strlcpy(buf, "SNDBUF",	    buflen); break;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		snprintf(buf, buflen, "unknown option type #%d", opt);
#pragma clang diagnostic pop
	}
	return (buf);
}

const char *
axa_tag_op_to_str(char *buf, size_t buf_len,
		  axa_tag_t tag, axa_p_op_t op)
{
	size_t tag_len;
	char *op_buf;

	axa_tag_to_str(buf, buf_len, tag);
	tag_len = strlen(buf);
	if (tag_len+1+1+1 >= buf_len)
		return (buf);
	buf_len -= tag_len+2;
	op_buf = buf + tag_len;
	*op_buf++ = ' ';
	axa_op_to_str(op_buf, buf_len - (tag_len+1), op);

	return (buf);
}

char *
axa_watch_ip_to_str(char *buf, size_t buf_len,
		int af, const void *addr, size_t alen, uint prefix)
{
	union {
		struct in_addr	ipv4;
		struct in6_addr	ipv6;
		uint8_t		b[0];
	} abuf;
	char ip_str[INET6_ADDRSTRLEN];
	char prefix_str[1+3+1];
	size_t cplen;

	if (af == AF_INET) {
		/* Watch IP address lengths are checked in input */
		if (prefix == 0 || prefix > 32) {
			snprintf(buf, buf_len,
				 "invalid IPv4 prefix of %d", prefix);
			return (buf);
		}
		if (prefix == 32) {
			prefix_str[0] = '\0';
		} else {
			snprintf(prefix_str, sizeof(prefix_str),
				 "/%d", prefix);
		}
	} else {
		if (prefix == 0 || prefix > 128) {
			snprintf(buf, buf_len,
				 "invalid IPv6 prefix of %d", prefix);
			return (buf);
		}
		if (prefix == 128) {
			prefix_str[0] = '\0';
		} else {
			snprintf(prefix_str, sizeof(prefix_str), "/%d", prefix);
		}
	}

	/* allow truncation to the prefix */
	memset(&abuf, 0, sizeof(abuf));
	cplen = alen;
	if (alen > sizeof(abuf))
		cplen = sizeof(abuf);
	memcpy(&abuf, addr, cplen);

	if (NULL == inet_ntop(af, &abuf, ip_str, sizeof(ip_str))) {
		snprintf(buf, buf_len,
			 "inet_ntop(%c): %s",
			 af == AF_INET ? '4' : '6', strerror(errno));
		return (buf);
	}
	snprintf(buf, buf_len, "IP=%s%s", ip_str, prefix_str);
	return (buf);
}

char *
axa_watch_to_str(char *buf, size_t buf_len,
		 const axa_p_watch_t *watch, size_t watch_len)
{
	char domain[NS_MAXDNAME];
	const char *star;
	ssize_t pat_len;

	pat_len = watch_len - (sizeof(*watch) - sizeof(watch->pat));
	AXA_ASSERT(pat_len >= 0);
	switch ((axa_p_watch_type_t)watch->type) {
	case AXA_P_WATCH_IPV4:
		axa_watch_ip_to_str(buf, buf_len, AF_INET,
				&watch->pat.addr, pat_len, watch->prefix);
		break;
	case AXA_P_WATCH_IPV6:
		axa_watch_ip_to_str(buf, buf_len, AF_INET6,
				&watch->pat.addr6, pat_len, watch->prefix);
		break;
	case AXA_P_WATCH_DNS:
		axa_domain_to_str(watch->pat.dns, pat_len,
				  domain, sizeof(domain));
		if ((watch->flags & AXA_P_WATCH_FG_WILD) == 0) {
			star = "";
		} else if (domain[0] == '.') {
				star = "*";
		} else {
			star = "*.";
		}
		snprintf(buf, buf_len, "dns=%s%s", star, domain);
		break;
	case AXA_P_WATCH_CH:
		snprintf(buf, buf_len,
			 AXA_OP_CH_PREFIX"="AXA_OP_CH_PREFIX"%d",
			 AXA_P2H_CH(watch->pat.ch));
		break;
	case AXA_P_WATCH_ERRORS:
		snprintf(buf, buf_len, "ERRORS");
		break;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		snprintf(buf, buf_len, "unknown watch type %d", watch->type);
		break;
#pragma clang diagnostic pop
	}

	if ((watch->flags & AXA_P_WATCH_FG_SHARED) != 0)
		strlcat(buf, "("AXA_P_WATCH_STR_SHARED")", buf_len);

	return (buf);
}

static void
watch_add_str(char **bufp, size_t *buf_lenp,
	      const char *op_sp, const axa_p_watch_t *watch, size_t watch_len)
{
	size_t len;

	axa_buf_print(bufp, buf_lenp, "%s", op_sp);
	axa_watch_to_str(*bufp, *buf_lenp, watch, watch_len);
	len = strlen(*bufp);
	*bufp += len;
	*buf_lenp -= len;
}

static void
whit_add_str(char **bufp, size_t *buf_lenp,
	     const char *op_sp, const axa_p_whit_t *whit, size_t whit_len)
{
	char ip_str[INET6_ADDRSTRLEN];

	if (whit->hdr.type == AXA_P_WHIT_NMSG) {
		axa_buf_print(bufp, buf_lenp, "%s"AXA_OP_CH_PREFIX"%d nmsg",
			      op_sp, whit->hdr.ch);
		return;
	}

	if (whit->hdr.type != AXA_P_WHIT_IP) {
		axa_buf_print(bufp, buf_lenp, "%s"AXA_OP_CH_PREFIX"%d ???",
			      op_sp, whit->hdr.ch);
		return;
	}

	if (whit_len >= sizeof(struct ip)
	    && (whit->ip.b[0] & 0xf0) == 0x40) {
		axa_watch_ip_to_str(ip_str, sizeof(ip_str), AF_INET,
				AXA_OFFSET(whit->ip.b, struct ip, ip_src),
				4, 32);
		axa_buf_print(bufp, buf_lenp, "%s"AXA_OP_CH_PREFIX"%d src %s",
			      op_sp, whit->hdr.ch, ip_str);

	} else if (whit_len >= sizeof(struct ip6_hdr)
	    && (whit->ip.b[0] & 0xf0) == 0x60) {
		axa_watch_ip_to_str(ip_str, sizeof(ip_str), AF_INET6,
				AXA_OFFSET(whit->ip.b, struct ip6_hdr, ip6_src),
				16, 128);
		axa_buf_print(bufp, buf_lenp, "%s"AXA_OP_CH_PREFIX"%d src %s",
			      op_sp, whit->hdr.ch, ip_str);

	} else {
		axa_buf_print(bufp, buf_lenp, "%s"AXA_OP_CH_PREFIX"%d ???",
			      op_sp, whit->hdr.ch);
	}
}

static void
rlimit_add_str(char **bufp, size_t *buf_lenp,
	       axa_cnt_t limit, axa_cnt_t cur, const char *str)
{
	/* buffers sized largest sane number of packets */
	char limit_buf[sizeof("9,999,999,999,999,999,999")];
	char cur_buf[sizeof("; current value=9,999,999,999,999,999,999")];
	const char *limit_str;

	limit = AXA_P2H64(limit);
	cur = AXA_P2H64(cur);
	if (cur == AXA_RLIMIT_NA) {
		if (limit == AXA_RLIMIT_NA)
			return;
		cur_buf[0] = '\0';
	} else {
		snprintf(cur_buf, sizeof(cur_buf),
			 "; current value=%"PRIu64, cur);
	}
	if (limit == AXA_RLIMIT_NA) {
		limit_str = "no change";
	} else if (limit == AXA_RLIMIT_OFF) {
		limit_str = "unlimited";
	} else {
		snprintf(limit_buf, sizeof(limit_buf), "%"PRIu64, limit);
		limit_str = limit_buf;
	}
	axa_buf_print(bufp, buf_lenp, "\n    %s per %s%s",
		      limit_str, str, cur_buf);
}

static void
missed_add_str(char **bufp, size_t *buf_lenp,
	       const char *op_nl, const axa_p_missed_t *missed)
{
	time_t epoch;
	char time_buf[32];

	epoch = AXA_P2H32(missed->last_report);
	strftime(time_buf, sizeof(time_buf), "%Y/%m/%d %T",
		 localtime(&epoch));

	axa_buf_print(bufp, buf_lenp,
		      "%s"
		      "    missed %"PRIu64" input packets,"
		      " dropped %"PRIu64" for congestion,\n"
		      "\tdropped %"PRIu64" for rate limit,"
		      " filtered %"PRIu64"\n"
		      "\tsince %s",
		      op_nl,
		      AXA_P2H64(missed->missed),
		      AXA_P2H64(missed->dropped),
		      AXA_P2H64(missed->rlimit),
		      AXA_P2H64(missed->filtered),
		      time_buf);
}

static void
missed_rad_add_str(char **bufp, size_t *buf_lenp,
		   const char *op_nl, const axa_p_missed_rad_t *missed)
{
	time_t epoch;
	char time_buf[32];

	epoch = AXA_P2H32(missed->last_report);
	strftime(time_buf, sizeof(time_buf), "%Y/%m/%d %T",
		 localtime(&epoch));

	axa_buf_print(bufp, buf_lenp,
		      "%s"
		      "    missed %"PRIu64" input packets at SRA server,"
		      " dropped %"PRIu64" for SRA->RAD congestion,\n"
		      "\tdropped %"PRIu64" for SRA->RAD rate limit,"
		      " filtered %"PRIu64" by SRA\n"
		      "\tdropped %"PRIu64" for RAD->client congestion,"
		      " dropped %"PRIu64" for RAD rate limit,\n"
		      "\tfiltered %"PRIu64" by RAD modules"
		      " since %s",
		      op_nl,
		      AXA_P2H64(missed->sra_missed),
		      AXA_P2H64(missed->sra_dropped),
		      AXA_P2H64(missed->sra_rlimit),
		      AXA_P2H64(missed->sra_filtered),
		      AXA_P2H64(missed->dropped),
		      AXA_P2H64(missed->rlimit),
		      AXA_P2H64(missed->filtered),
		      time_buf);
}

static bool				/* false=message added to err_buf */
ck_ipdg(const void *ptr, size_t actual_len, bool is_ip,
	char **err_buf, size_t *err_buf_len,
	const char *proto_nm, size_t min_len, axa_p_ch_t ch)
{
	if (ptr == NULL) {
		axa_buf_print(err_buf, err_buf_len,
			      "%smissing %s header from "
			      AXA_OP_CH_PREFIX"%d",
			      is_ip ? "" : "\n",
			      proto_nm, ch);
		return (false);
	}
	if (actual_len < min_len) {
		axa_buf_print(err_buf, err_buf_len,
			      "%struncated %s header of %zd bytes from "
			      AXA_OP_CH_PREFIX"%d",
			      is_ip ? "" : "\n",
			      proto_nm, actual_len, ch);
		return (false);
	}
	return (true);
}

/* Convert a raw IP datagram to a string. */
bool					/* true=dst and src set */
axa_ipdg_parse(const uint8_t *pkt_data, size_t caplen, axa_p_ch_t ch,
	       axa_socku_t *dst_su, axa_socku_t *src_su,
	       char *cmt, size_t cmt_len)
{
	struct nmsg_ipdg dg;
	struct ip ip_hdr;
	uint ttl;
	struct ip6_hdr ip6_hdr;
	struct tcphdr tcp_hdr;
	struct udphdr udp_hdr;
	uint uh_ulen;
	nmsg_res res;

	/* quell static analyzer complaints when dg.proto_network is AF_INET6 */
	ip_hdr.ip_len = 0;

	memset(dst_su, 0, sizeof(*dst_su));
	memset(src_su, 0, sizeof(*src_su));
	if (cmt_len > 0)
		*cmt = '\0';

	memset(&dg, 0, sizeof(dg));
	res = nmsg_ipdg_parse_pcap_raw(&dg, DLT_RAW, pkt_data, caplen);
	if (res != nmsg_res_success || dg.len_network == 0) {
		axa_buf_print(&cmt, &cmt_len, " unknown packet");
		return (false);
	}

	switch (dg.proto_network) {
	case AF_INET:
		if (!ck_ipdg(dg.network, dg.len_network, false,
			     &cmt, &cmt_len, "IP", sizeof(ip_hdr), ch))
			return (false);
		memcpy(&ip_hdr, dg.network, sizeof(ip_hdr));
		axa_ip_to_su(dst_su, &ip_hdr.ip_dst, AF_INET);
		axa_ip_to_su(src_su, &ip_hdr.ip_src, AF_INET);
		ttl = ip_hdr.ip_ttl;
		break;
	case AF_INET6:
		if (!ck_ipdg(dg.network, dg.len_network, false,
			     &cmt, &cmt_len, "IPv6", sizeof(ip6_hdr), ch))
			return (false);
		memcpy(&ip6_hdr, dg.network, sizeof(ip6_hdr));
		axa_ip_to_su(dst_su, &ip6_hdr.ip6_dst, AF_INET6);
		axa_ip_to_su(src_su, &ip6_hdr.ip6_src, AF_INET6);
		ttl = ip6_hdr.ip6_hlim;
		break;
	default:
		axa_buf_print(&cmt, &cmt_len, "unknown AF %d from "
			      AXA_OP_CH_PREFIX"%d",
			      dg.proto_network, AXA_P2H_CH(ch));
		return (false);
	}

	switch (dg.proto_transport) {
	case IPPROTO_ICMP:
		axa_buf_print(&cmt, &cmt_len, "TTL=%d ICMP", ttl);
		if (dg.transport == NULL)
			axa_buf_print(&cmt, &cmt_len, " later fragment");
		else
			axa_buf_print(&cmt, &cmt_len,
				      " %d bytes", ntohs(ip_hdr.ip_len));
		break;

	case IPPROTO_ICMPV6:
		axa_buf_print(&cmt, &cmt_len, "TTL=%d ICMPv6", ttl);
		if (dg.transport == NULL)
			axa_buf_print(&cmt, &cmt_len, " later fragment");
		break;

	case IPPROTO_TCP:
		axa_buf_print(&cmt, &cmt_len, "TTL=%d TCP", ttl);
		if (dg.transport == NULL) {
			axa_buf_print(&cmt, &cmt_len, " later fragment");
		} else if (ck_ipdg(dg.transport, dg.len_transport, true,
				    &cmt, &cmt_len, "TCP",
				    sizeof(tcp_hdr), ch )) {
			memcpy(&tcp_hdr, dg.transport, sizeof(tcp_hdr));
			AXA_SU_PORT(dst_su) = tcp_hdr.th_dport;
			AXA_SU_PORT(src_su) = tcp_hdr.th_sport;
			if ((tcp_hdr.th_flags & TH_FIN) != 0)
				axa_buf_print(&cmt, &cmt_len, " FIN");
			if ((tcp_hdr.th_flags & TH_SYN) != 0)
				axa_buf_print(&cmt, &cmt_len, " SYN");
			if ((tcp_hdr.th_flags & TH_ACK) != 0)
				axa_buf_print(&cmt, &cmt_len, " ACK");
			if ((tcp_hdr.th_flags & TH_RST) != 0)
				axa_buf_print(&cmt, &cmt_len, " RST");
		}
		break;

	case IPPROTO_UDP:
		axa_buf_print(&cmt, &cmt_len, "TTL=%d UDP", ttl);
		if (dg.transport == NULL) {
			axa_buf_print(&cmt, &cmt_len, " later fragment");
		} else if (ck_ipdg(dg.transport, dg.len_transport, true,
				    &cmt, &cmt_len, "UDP",
				    sizeof(udp_hdr), ch)) {
			memcpy(&udp_hdr, dg.transport, sizeof(udp_hdr));
			AXA_SU_PORT(dst_su) = udp_hdr.uh_dport;
			AXA_SU_PORT(src_su) = udp_hdr.uh_sport;
			uh_ulen = ntohs(udp_hdr.uh_ulen);
			axa_buf_print(&cmt, &cmt_len, " %d bytes", uh_ulen);
			if (uh_ulen != dg.len_payload+sizeof(udp_hdr))
				axa_buf_print(&cmt, &cmt_len, "  fragment");
		}
		break;

	default:
		axa_buf_print(&cmt, &cmt_len, " IP protocol %d",
			      dg.proto_transport);
		break;
	}

	return (true);
}

/* Convert some AXA protocol messages to strings. */
char *					/* input parameter buf0 */
axa_p_to_str(char *buf0, size_t buf_len,    /* should be AXA_P_STRLEN */
	     bool print_op,
	     const axa_p_hdr_t *hdr,	/* protocol byte order */
	     const axa_p_body_t *body)
{
	char tag_op_buf[AXA_TAG_STRLEN+AXA_P_OP_STRLEN];
	char *buf;
	char opt_buf[AXA_P_OP_STRLEN];
	const char *op_sp, *op_nl;
	uint32_t sample, bufsize;

	buf = buf0;
	buf[0] = '\0';
	if (print_op) {
		axa_buf_print(&buf, &buf_len, "%s",
			      axa_tag_op_to_str(tag_op_buf, sizeof(tag_op_buf),
						AXA_P2H_TAG(hdr->tag),
						hdr->op));
		op_sp = " ";
		op_nl = "\n";
	} else {
		op_sp = "";
		op_nl = "";
	}

	switch ((axa_p_op_t)hdr->op) {
	case AXA_P_OP_NOP:
		break;

	case AXA_P_OP_HELLO:
		axa_buf_print(&buf, &buf_len, "%s%s", op_sp, body->hello.str);
		break;

	case AXA_P_OP_OK:
	case AXA_P_OP_ERROR:
		if (body->result.orig_op == AXA_P_OP_OK
		    || body->result.orig_op == AXA_P_OP_NOP
		    || body->result.orig_op == AXA_P_OP_ERROR) {
			axa_buf_print(&buf, &buf_len, "%s%s",
				      op_sp, body->result.str);
		} else {
			axa_buf_print(&buf, &buf_len, "%s%s %s",
				      op_sp,
				      axa_op_to_str(tag_op_buf,
						    sizeof(tag_op_buf),
						    body->result.orig_op),
				      body->result.str);
		}
		break;

	case AXA_P_OP_MISSED:
		missed_add_str(&buf, &buf_len, op_nl, &body->missed);
		break;

	case AXA_P_OP_MISSED_RAD:
		missed_rad_add_str(&buf, &buf_len, op_nl, &body->missed_rad);
		break;

	case AXA_P_OP_WHIT:
		whit_add_str(&buf, &buf_len, op_sp, &body->whit,
			      (AXA_P2H32(hdr->len) - sizeof(*hdr)));
		break;

	case AXA_P_OP_WATCH:
		watch_add_str(&buf, &buf_len, op_sp, &body->watch,
			      (AXA_P2H32(hdr->len) - sizeof(*hdr)));
		break;

	case AXA_P_OP_ANOM:
		axa_buf_print(&buf, &buf_len, "%s%s", op_sp, body->anom.an.c);
		if (AXA_P2H32(hdr->len)-sizeof(*hdr) > sizeof(body->anom.an.c)
		    && body->anom.parms[0] != '\0')
			axa_buf_print(&buf, &buf_len, " %s", body->anom.parms);
		break;

	case AXA_P_OP_CHANNEL:
		if (body->channel.ch == AXA_P2H_CH(AXA_OP_CH_ALL)) {
			snprintf(buf, buf_len, "%s"AXA_OP_CH_ALLSTR" %s",
				 op_sp,
				 (body->channel.on != 0) ? "on" : "off");
		} else {
			snprintf(buf, buf_len, "%s"AXA_OP_CH_PREFIX"%d %s",
				 op_sp,
				 AXA_P2H_CH(body->channel.ch),
				 (body->channel.on != 0) ? "on" : "off");
		}
		break;

	case AXA_P_OP_WLIST:
		if (print_op)
			axa_buf_print(&buf, &buf_len, " %5s",
				      axa_tag_to_str(tag_op_buf,
						     sizeof(tag_op_buf),
						     AXA_P2H_TAG(body
							 ->wlist.cur_tag)));
		watch_add_str(&buf, &buf_len, op_sp, &body->wlist.w,
			      (AXA_P2H32(hdr->len) - sizeof(*hdr)
			       - (sizeof(body->wlist)
				  - sizeof(body->wlist.w))));
		break;

	case AXA_P_OP_AHIT:
		axa_buf_print(&buf, &buf_len, "%s%s ", op_sp, body->ahit.an.c);
		whit_add_str(&buf, &buf_len, op_sp, &body->ahit.whit,
			      (AXA_P2H32(hdr->len) - sizeof(*hdr)));
		break;

	case AXA_P_OP_ALIST:
		if (print_op)
			axa_buf_print(&buf, &buf_len, " %5s ",
				      axa_tag_to_str(tag_op_buf,
						     sizeof(tag_op_buf),
						     AXA_P2H_TAG(body
							 ->alist.cur_tag)));
		axa_buf_print(&buf, &buf_len, "%5s %s",
			      body->alist.anom.an.c,
			      body->alist.anom.parms);
		break;

	case AXA_P_OP_CLIST:
		break;

	case AXA_P_OP_USER:
		axa_buf_print(&buf, &buf_len, "%s'%s'",
			      op_sp, body->user.name);
		break;

	case AXA_P_OP_OPT:
		switch ((axa_p_opt_type_t)body->opt.type) {
		case AXA_P_OPT_TRACE:
			axa_buf_print(&buf, &buf_len, "%strace=%d", op_sp,
				      AXA_P2H32(body->opt.u.trace));
			break;
		case AXA_P_OPT_RLIMIT:
			axa_buf_print(&buf, &buf_len, "%s%s", op_sp,
				      axa_opt_to_str(opt_buf, sizeof(opt_buf),
						     body->opt.type));
			rlimit_add_str(&buf, &buf_len,
				       body->opt.u.rlimit.max_pkts_per_sec,
				       body->opt.u.rlimit.cur_pkts_per_sec,
				       "second");
			if (AXA_P2H64(body->opt.u.rlimit.report_secs)
			    == AXA_RLIMIT_OFF)
				axa_buf_print(&buf, &buf_len,
					      "    no regular reports");
			else if (AXA_P2H64(body->opt.u.rlimit.report_secs)
				 != AXA_RLIMIT_NA)
				axa_buf_print(&buf, &buf_len,
					      "\n    %"PRIu64
					      " seconds between reports",
					      AXA_P2H64(body->opt.u.
							rlimit.report_secs));
			break;
		case AXA_P_OPT_SAMPLE:
			sample = AXA_P2H32(body->opt.u.sample);
			if (sample == AXA_P_OPT_SAMPLE_REQ)
				axa_buf_print(&buf, &buf_len,
					      "%srequest sample rate",
					      op_sp);
			else
				axa_buf_print(&buf, &buf_len,
					      "%ssample %.2f%%",
					      op_sp,
					      sample
					      / (AXA_P_OPT_SAMPLE_SCALE*1.0));
			break;
		case AXA_P_OPT_SNDBUF:
			bufsize = AXA_P2H32(body->opt.u.bufsize);
			if (bufsize == AXA_P_OPT_SNDBUF_REQ)
				axa_buf_print(&buf, &buf_len,
					      "%srequest bufsize",
					      op_sp);
			else
				axa_buf_print(&buf, &buf_len, "%sbufsize=%d",
				      op_sp, bufsize);
			break;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
		default:
			if (print_op)
				axa_buf_print(&buf, &buf_len, " ");
			axa_buf_print(&buf, &buf_len,
				      "unrecognized type %d", body->opt.type);
			break;
#pragma clang diagnostic pop
		}
		break;

	case AXA_P_OP_JOIN:
	case AXA_P_OP_PAUSE:
	case AXA_P_OP_GO:
	case AXA_P_OP_WGET:
	case AXA_P_OP_AGET:
	case AXA_P_OP_STOP:
	case AXA_P_OP_ALL_STOP:
	case AXA_P_OP_CGET:
	case AXA_P_OP_ACCT:
	case AXA_P_OP_RADU:
	case AXA_P_OP_MGMT_GET:
	case AXA_P_OP_MGMT_GETRSP:
	case _AXA_P_OP_KILL_REQ:
	case _AXA_P_OP_KILL_RSP:
	case _AXA_P_OP_STATS_REQ:
	case _AXA_P_OP_STATS_RSP:
	default:
		break;
	}

	return (buf0);
}

/* Check the header of an AXA message. */
bool				/* false=bad */
axa_ck_hdr(axa_emsg_t *emsg, const axa_p_hdr_t *hdr,
       const char *label, axa_p_direction_t dir)
{
	size_t max_len, min_len;
	bool dir_ok;
	const char *dir1_str, *dir2_str;
	int tagged;			/* -1=never 0=sometimes 1=always */
	char op_buf[AXA_P_OP_STRLEN];
	axa_p_body_t *body;
	axa_tag_t tag;
	uint32_t len;

	body = NULL;
	len = AXA_P2H32(hdr->len);
	if (len < sizeof(*hdr)) {
		axa_pemsg(emsg, "AXA header length of %d is too small"
			  " from %s", len, label);
		return (false);
	}
	if (hdr->pvers < AXA_P_PVERS_MIN || hdr->pvers > AXA_P_PVERS_MAX) {
		axa_pemsg(emsg, "unknown protocol version #%d for %s from %s",
			  hdr->pvers,
			  axa_op_to_str(op_buf, sizeof(op_buf), hdr->op),
			  label);
		return (false);
	}
	len -= sizeof(*hdr);
	if (len > AXA_P_MAX_BODY_LEN) {
		axa_pemsg(emsg, "impossible body length %d from %s",
			  len, label);
		return (false);
	}

	switch ((axa_p_op_t)hdr->op) {
	case AXA_P_OP_NOP:
		max_len = min_len = 0;
		tagged = 0;
		dir_ok = true;
		break;
	case AXA_P_OP_HELLO:
		max_len = sizeof(body->hello);
		min_len = max_len - sizeof(body->hello.str);
		tagged = -1;
		dir_ok = true;
		break;
	case AXA_P_OP_OK:
	case AXA_P_OP_ERROR:
		max_len = sizeof(body->result);
		min_len = max_len - sizeof(body->result.str);
		tagged = 0;
		dir_ok = (dir == AXA_P_FROM_SRA || dir == AXA_P_FROM_RAD);
		break;
	case AXA_P_OP_MISSED:
		max_len = min_len = sizeof(body->missed);
		tagged = -1;
		dir_ok = (dir == AXA_P_FROM_SRA);
		break;
	case AXA_P_OP_MISSED_RAD:
		max_len = min_len = sizeof(body->missed_rad);
		tagged = -1;
		dir_ok = (dir == AXA_P_FROM_RAD);
		break;
	case AXA_P_OP_WHIT:
		min_len = AXA_WHIT_MIN_LEN;
		max_len = AXA_WHIT_MAX_LEN;
		tagged = 1;
		dir_ok = (dir == AXA_P_FROM_SRA || dir == AXA_P_FROM_RAD);
		break;
	case AXA_P_OP_WLIST:
		max_len = sizeof(body->wlist);
		min_len = max_len - sizeof(body->wlist.w.pat);
		tagged = 0;
		dir_ok = (dir == AXA_P_FROM_SRA || dir == AXA_P_FROM_RAD);
		break;
	case AXA_P_OP_AHIT:
		min_len = (sizeof(body->ahit) - sizeof(body->ahit.whit)
			   + AXA_WHIT_MIN_LEN);
		max_len = (sizeof(body->ahit) - sizeof(body->ahit.whit)
			   + AXA_WHIT_MAX_LEN);
		tagged = 1;
		dir_ok = (dir == AXA_P_FROM_RAD);
		break;
	case AXA_P_OP_ALIST:
		max_len = sizeof(body->alist);
		min_len = max_len - sizeof(body->alist.anom.parms);
		tagged = 0;
		dir_ok = (dir == AXA_P_FROM_RAD);
		break;
	case AXA_P_OP_CLIST:
		max_len = sizeof(body->clist);
		min_len = max_len;
		tagged = 0;
		dir_ok = (dir == AXA_P_FROM_SRA || dir == AXA_P_FROM_RAD);
		break;

	case AXA_P_OP_USER:
		max_len = min_len = sizeof(body->user);
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_JOIN:
		max_len = min_len = sizeof(body->join);
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_PAUSE:
	case AXA_P_OP_GO:
		max_len = min_len = 0;
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_WATCH:
		max_len = sizeof(body->watch);
		min_len = max_len - sizeof(body->watch.pat);
		tagged = 1;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_WGET:
		max_len = min_len = 0;
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_ANOM:
		max_len = sizeof(body->anom);
		min_len = max_len - sizeof(body->anom.parms);
		tagged = 1;
		dir_ok = (dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_AGET:
		max_len = min_len = 0;
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_STOP:
		max_len = min_len = 0;
		tagged = 1;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_ALL_STOP:
		max_len = min_len = 0;
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_CHANNEL:
		max_len = sizeof(axa_p_channel_t);
		min_len = max_len;
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA);
		break;
	case AXA_P_OP_CGET:
		max_len = min_len = 0;
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_OPT:
		min_len = sizeof(body->opt) - sizeof(body->opt.u);
		max_len = min_len + 1024;
		tagged = 0;
		dir_ok = true;
		break;
	case AXA_P_OP_ACCT:
		max_len = min_len = 0;
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_RADU:
		max_len = min_len = 0;
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_MGMT_GET:
		max_len = min_len = 0;
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case AXA_P_OP_MGMT_GETRSP:
		min_len = max_len =
			strlen("mgmt is deprecated, please upgrade and use \"stats\"");
		tagged = 0;
		dir_ok = (dir == AXA_P_FROM_SRA || dir == AXA_P_FROM_RAD);
		break;
	case _AXA_P_OP_KILL_REQ:
		max_len = min_len = sizeof(_axa_p_kill_t);
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case _AXA_P_OP_KILL_RSP:
		min_len = max_len = sizeof(_axa_p_kill_t);
		tagged = 0;
		dir_ok = (dir == AXA_P_FROM_SRA || dir == AXA_P_FROM_RAD);
		break;
	case _AXA_P_OP_STATS_REQ:
		max_len = min_len = sizeof(_axa_p_stats_req_t);
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
		break;
	case _AXA_P_OP_STATS_RSP:
		/* stats response header */
		min_len = sizeof(_axa_p_stats_rsp_t);
		/* stats response header + sys object + max user objs + max
		 * rad an objs */
		max_len = sizeof(_axa_p_stats_rsp_t) +
			sizeof(_axa_p_stats_sys_t) +
			(_AXA_STATS_MAX_USER_OBJS *
			 sizeof(_axa_p_stats_user_t)) +
			(_AXA_STATS_MAX_USER_OBJS *
			 ((_AXA_STATS_MAX_USER_RAD_AN_OBJS *
                         sizeof(_axa_p_stats_user_rad_an_t))));
		tagged = 0;
		dir_ok = (dir == AXA_P_FROM_SRA || dir == AXA_P_FROM_RAD);
		break;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		max_len = 0;
		min_len = INT_MAX;
		tagged = 1;
		dir_ok = false;
		break;
#pragma clang diagnostic pop
	}

	tag = AXA_P2H_TAG(hdr->tag);
	if (tagged == 1) {
		if (tag == AXA_TAG_NONE) {
			axa_pemsg(emsg, "missing tag for %s from %s",
				  axa_op_to_str(op_buf, sizeof(op_buf),
						hdr->op),
				  label);
			return (false);
		}
	} else if (tagged == -1) {
		if (tag != AXA_TAG_NONE) {
			axa_pemsg(emsg, "unexpected tag %d for %s from %s",
				  tag,
				  axa_op_to_str(op_buf, sizeof(op_buf),
						hdr->op),
				  label);
			return (false);
		}
	}

	if (!dir_ok) {
		switch (dir) {
		case AXA_P_TO_SRA:
			dir1_str = label;
			dir2_str = "SRA client";
			break;
		case AXA_P_FROM_SRA:
			dir1_str = "SRA";
			dir2_str = label;
			break;
		case AXA_P_TO_RAD:
			dir1_str = label;
			dir2_str = "RAD client";
			break;
		case AXA_P_FROM_RAD:
			dir1_str = "RAD";
			dir2_str = label;
			break;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
		default:
			dir1_str = "?";
			dir2_str = label;
			break;
#pragma clang diagnostic pop
		}
		axa_pemsg(emsg, "%s illegal from %s to %s",
			  axa_op_to_str(op_buf, sizeof(op_buf), hdr->op),
			  dir1_str, dir2_str);
		return (false);
	}

	if (len > max_len) {
		axa_pemsg(emsg, "length %d for %s from %s should be at most %zu",
			  len, axa_op_to_str(op_buf, sizeof(op_buf), hdr->op),
			  label, max_len);
		return (false);
	}
	if (len < min_len) {
		axa_pemsg(emsg, "length %d for %s from %s must be at least %zu",
			  len, axa_op_to_str(op_buf, sizeof(op_buf), hdr->op),
			  label, min_len);
		return (false);
	}

	return (true);
}

/* Check that an AXA message is null terminated. */
static bool
ck_field_null(axa_emsg_t *emsg, axa_p_op_t op, const void *field,
	      size_t field_len, const char *field_name)
{
	char op_buf[AXA_P_OP_STRLEN];

	if (field_len == 0) {
		axa_pemsg(emsg, "%s %s truncated",
			  axa_op_to_str(op_buf, sizeof(op_buf), op),
			  field_name);
		return (false);
	}
	if (((uint8_t *)field)[field_len-1] != '\0') {
		axa_pemsg(emsg, "%s %s not null terminated",
			  axa_op_to_str(op_buf, sizeof(op_buf), op),
			  field_name);
		return (false);
	}
	return (true);
}

/* Check a binary channel number. */
static bool
ck_ch(axa_emsg_t *emsg, axa_p_op_t op,
      axa_p_ch_t ch,			/* protocol byte order */
      bool all_ok)
{
	char op_buf[AXA_P_OP_STRLEN];

	ch = AXA_P2H_CH(ch);
	if (ch == AXA_OP_CH_ALL && all_ok)
		return (true);
	if (ch > AXA_OP_CH_MAX) {
		axa_pemsg(emsg, "%s "AXA_OP_CH_PREFIX"%d is an invalid channel",
			  axa_op_to_str(op_buf, sizeof(op_buf), op), ch);
		return (false);
	}
	return (true);
}

/* Check anomaly name */
static bool
ck_an(axa_emsg_t *emsg, axa_p_op_t op, const axa_p_an_t *an)
{
	char op_buf[AXA_P_OP_STRLEN];

	if (an->c[sizeof(an->c)-1] != '\0') {
		axa_pemsg(emsg, "%s \"%.*s\" name not null terminated",
			  axa_op_to_str(op_buf, sizeof(op_buf), op),
			  (int)sizeof(*an), an->c);
		return (false);
	}
	return (true);
}

/* Check anomaly specification. */
static bool
ck_anom(axa_emsg_t *emsg, axa_p_op_t op,
	const axa_p_anom_t *anom, size_t anom_len)
{
	size_t parms_len;

	parms_len = anom_len - sizeof(anom->an);
	return (ck_field_null(emsg, op, anom->an.c, sizeof(anom->an), "name")
		&& (parms_len == 0
		    || ck_field_null(emsg, op, anom->parms, parms_len,
				     "parameters")));
}

/* Check a watch in AXA_P_OP_WATCH or AXA_P_OP_WLIST. */
static bool
ck_watch(axa_emsg_t *emsg, axa_p_op_t op,
	 const axa_p_watch_t *w, size_t watch_len)
{
	char op_buf[AXA_P_OP_STRLEN];
	ssize_t pat_len;
	int name_len;

	if (w->pad != 0) {
		axa_pemsg(emsg, "%s bad watch byte %#x",
			  axa_op_to_str(op_buf, sizeof(op_buf), op),
			  w->pad);
		return (false);
	}
	if (0 != (w->flags & ~(AXA_P_WATCH_FG_WILD
			       | AXA_P_WATCH_FG_SHARED))) {
		axa_pemsg(emsg, "%s bad watch flags %#x",
			  axa_op_to_str(op_buf, sizeof(op_buf), op),
			  w->flags);
		return (false);
	}

	pat_len = watch_len - (sizeof(*w) - sizeof(w->pat));
	switch ((axa_p_watch_type_t)w->type) {
	case AXA_P_WATCH_IPV4:
		if (pat_len <= 0 || pat_len > (ssize_t)sizeof(w->pat.addr)) {
			axa_pemsg(emsg, "%s bad IPv4 length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  watch_len);
			return (false);
		}
		if (w->prefix == 0 || (w->prefix+7)/8 > pat_len) {
			axa_pemsg(emsg, "%s bad prefix length"
				  " %d for address length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  w->prefix, pat_len);
			return (false);
		}
		break;
	case AXA_P_WATCH_IPV6:
		if (pat_len <= 0 || pat_len > (ssize_t)sizeof(w->pat.addr6)) {
			axa_pemsg(emsg, "%s bad IPv6 length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  watch_len);
			return (false);
		}
		if (w->prefix == 0 || (w->prefix+7)/8 > pat_len) {
			axa_pemsg(emsg, "%s bad prefix length"
				  " %d for address length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  w->prefix, pat_len);
			return (false);
		}
		break;
	case AXA_P_WATCH_DNS:
		if (pat_len <= 0 || pat_len > (int)sizeof(w->pat.dns)) {
			axa_pemsg(emsg, "%s bad dns length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  watch_len);
			return (false);
		}
		name_len = 0;
		while (w->pat.dns[name_len] != 0) {
			name_len += 1+w->pat.dns[name_len];
			if (name_len > pat_len)
				break;
		}
		if (name_len+1 != pat_len) {
			axa_pemsg(emsg, "%s bad dns label lengths",
				  axa_op_to_str(op_buf, sizeof(op_buf), op));
			return (false);
		}
		break;
	case AXA_P_WATCH_CH:
		if (pat_len != sizeof(w->pat.ch)) {
			axa_pemsg(emsg, "%s bad channel watch length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  watch_len);
			return (false);
		}
		return (ck_ch(emsg, op, w->pat.ch, false));
	case AXA_P_WATCH_ERRORS:
		if (pat_len != 0) {
			axa_pemsg(emsg, "%s bad error watch length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  watch_len);
			return (false);
		}
		break;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		axa_pemsg(emsg, "%s unknown watch type %d",
			  axa_op_to_str(op_buf, sizeof(op_buf), op),
			  w->type);
		return (false);
#pragma clang diagnostic pop
	}

	return (true);
}

static bool
ck_whit(axa_emsg_t *emsg, axa_p_op_t op,
	const axa_p_whit_t *whit, size_t whit_len)
{
	char op_buf[AXA_P_OP_STRLEN];

	if (!ck_ch(emsg, op, whit->hdr.ch, false))
		return (false);

	if (whit->hdr.type == AXA_P_WHIT_NMSG) {
		if (whit_len < sizeof(axa_p_whit_nmsg_t)) {
			axa_pemsg(emsg, "%s bad nmsg watch hit length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  whit_len);
			return (false);
		}

	} else if (whit->hdr.type == AXA_P_WHIT_IP) {
		if (whit_len < sizeof(axa_p_whit_ip_t)) {
			axa_pemsg(emsg, "%s bad IP watch hit length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  whit_len);
			return (false);
		}

	} else {
		axa_pemsg(emsg, "%s bad watch hit type %d",
			  axa_op_to_str(op_buf, sizeof(op_buf), op),
			  whit->hdr.type);
		return (false);
	}

	return (true);
}

static bool
ck_opt(axa_emsg_t *emsg, axa_p_op_t op, const axa_p_opt_t *opt, size_t opt_len)
{
	size_t val_len;
	char op_buf[AXA_P_OP_STRLEN];
	char opt_buf[AXA_P_OP_STRLEN];

	AXA_ASSERT(opt_len >= sizeof(axa_p_opt_t) - sizeof(opt->u));

	switch ((axa_p_opt_type_t)opt->type) {
	case AXA_P_OPT_TRACE:
		val_len = sizeof(opt->u.trace);
		break;
	case AXA_P_OPT_RLIMIT:
		val_len = sizeof(opt->u.rlimit);
		break;
	case AXA_P_OPT_SAMPLE:
		val_len = sizeof(opt->u.sample);
		break;
	case AXA_P_OPT_SNDBUF:
		val_len = sizeof(opt->u.bufsize);
		break;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		axa_pemsg(emsg, "%s %s",
			  axa_op_to_str(op_buf, sizeof(op_buf), op),
			  axa_opt_to_str(opt_buf, sizeof(opt_buf), opt->type));
		return (false);
#pragma clang diagnostic pop
	}

	if (val_len != opt_len - (sizeof(axa_p_opt_t) - sizeof(opt->u))) {
		axa_pemsg(emsg, "%s %s bad rate limit option length %zd",
			  axa_op_to_str(op_buf, sizeof(op_buf), op),
			  axa_opt_to_str(opt_buf, sizeof(opt_buf), opt->type),
			  opt_len);
		return (false);
	}

	return (true);
}

/*
 * Sanity check an AXA protocol body after the header has been checked.
 *	The header check has validated the body length.
 */
bool					/* false=bad */
axa_ck_body(axa_emsg_t *emsg, axa_p_op_t op, const axa_p_body_t *body,
	    size_t body_len)
{
	switch (op) {
	case AXA_P_OP_HELLO:
		return (ck_field_null(emsg, op, body->b, body_len, "version"));
	case AXA_P_OP_NOP:
		break;
	case AXA_P_OP_OK:
	case AXA_P_OP_ERROR:
		return (ck_field_null(emsg, op, body, body_len, "message"));
	case AXA_P_OP_MISSED:
	case AXA_P_OP_MISSED_RAD:
		break;
	case AXA_P_OP_WHIT:
		return (ck_whit(emsg, op, &body->whit, body_len));
	case AXA_P_OP_WLIST:
		return (ck_watch(emsg, op, &body->wlist.w,
				 body_len - (sizeof(body->wlist)
					     - sizeof(body->wlist.w))));
	case AXA_P_OP_AHIT:
		return (ck_an(emsg, op, &body->ahit.an)
			&& ck_ch(emsg, op, body->ahit.whit.hdr.ch, false));
	case AXA_P_OP_ALIST:
		return (ck_anom(emsg, op, &body->alist.anom,
				body_len - (sizeof(body->alist)
					    - sizeof(body->alist.anom))));
	case AXA_P_OP_CLIST:
		if (!ck_ch(emsg, op, body->clist.ch, false))
			return (false);
		return (ck_field_null(emsg, op, body, body_len, "channel"));


	case AXA_P_OP_USER:
		return (ck_field_null(emsg, op, body, body_len, "user name"));
	case AXA_P_OP_JOIN:
	case AXA_P_OP_PAUSE:
	case AXA_P_OP_GO:
		break;
	case AXA_P_OP_WATCH:
		return (ck_watch(emsg, op, &body->watch, body_len));
	case AXA_P_OP_WGET:
		break;
	case AXA_P_OP_ANOM:
		return (ck_anom(emsg, op, &body->anom, body_len));
	case AXA_P_OP_AGET:
	case AXA_P_OP_STOP:
	case AXA_P_OP_ALL_STOP:
		break;
	case AXA_P_OP_CHANNEL:
		return (ck_ch(emsg, op, body->channel.ch, true));
	case AXA_P_OP_CGET:
		break;
	case AXA_P_OP_OPT:
		return (ck_opt(emsg, op, &body->opt, body_len));
	case AXA_P_OP_ACCT:
		break;
	case AXA_P_OP_RADU:
		break;
	case AXA_P_OP_MGMT_GET:
		break;
	case AXA_P_OP_MGMT_GETRSP:
		break;
	case _AXA_P_OP_KILL_REQ:
		/* TODO */
		break;
	case _AXA_P_OP_KILL_RSP:
		/* TODO */
		break;
	case _AXA_P_OP_STATS_REQ:
		/* TODO */
		break;
	case _AXA_P_OP_STATS_RSP:
		/* TODO */
		break;
	}

	return (true);
}

axa_io_type_t
axa_io_type_parse(const char **addrp)
{
	axa_io_type_t result;
	const char *addr;
	int i;

	addr = *addrp;
	addr += strspn(addr, AXA_WHITESPACE);

	if (AXA_CLITCMP(addr, AXA_IO_TYPE_UNIX_STR":")) {
		addr += sizeof(AXA_IO_TYPE_UNIX_STR":")-1;
		result = AXA_IO_TYPE_UNIX;

	} else if (AXA_CLITCMP(addr, AXA_IO_TYPE_TCP_STR":")) {
		addr += sizeof(AXA_IO_TYPE_TCP_STR":")-1;
		result = AXA_IO_TYPE_TCP;

	} else if (AXA_CLITCMP(addr, AXA_IO_TYPE_TLS_STR":")) {
		addr += sizeof(AXA_IO_TYPE_TLS_STR":")-1;
		result = AXA_IO_TYPE_TLS;

	} else if (AXA_CLITCMP(addr, AXA_IO_TYPE_SSH_STR":")) {
		addr += sizeof(AXA_IO_TYPE_SSH_STR":")-1;
		result = AXA_IO_TYPE_SSH;

	} else if (AXA_CLITCMP(addr, AXA_IO_TYPE_SSH_STR)
		   && 0 != (i = strspn(addr+sizeof(AXA_IO_TYPE_SSH_STR)-1,
				       AXA_WHITESPACE))) {
		/* allow "ssh " for upward compatibility with old sratool */
		addr += sizeof(AXA_IO_TYPE_SSH_STR)-1 + i;
		result = AXA_IO_TYPE_SSH;

	} else if (AXA_CLITCMP(addr, AXA_IO_TYPE_APIKEY_STR":")) {
		addr += sizeof(AXA_IO_TYPE_APIKEY_STR":")-1;
		result = AXA_IO_TYPE_APIKEY;

	} else {
		return (AXA_IO_TYPE_UNKN);
	}

	*addrp = addr;
	return (result);
}

/* I/O type to string */
const char *
axa_io_type_to_str(axa_io_type_t type)
{
	switch (type) {
	case AXA_IO_TYPE_UNKN:
	default:
		return ("?");
	case AXA_IO_TYPE_UNIX:
		return (AXA_IO_TYPE_UNIX_STR);
	case AXA_IO_TYPE_TCP:
		return (AXA_IO_TYPE_TCP_STR);
	case AXA_IO_TYPE_SSH:
		return (AXA_IO_TYPE_SSH_STR);
	case AXA_IO_TYPE_TLS:
		return (AXA_IO_TYPE_TLS_STR);
	case AXA_IO_TYPE_APIKEY:
		return (AXA_IO_TYPE_APIKEY_STR);
	}
}

void
axa_io_init(axa_io_t *io)
{
	memset(io, 0, sizeof(*io));
	io->su.sa.sa_family = -1;
	io->i_fd = -1;
	io->o_fd = -1;
	io->tun_fd = -1;
	io->tun_pid = -1;
	io->pvers = AXA_P_PVERS;
}

void
axa_recv_flush(axa_io_t *io)
{
	if (io->recv_body != NULL) {
		free(io->recv_body);
		io->recv_body = NULL;
	}
	io->recv_body_len = 0;
}

static void
ck_close(int fd, const char *label)
{
	if (0 > close(fd)) {
		/* This should not happen. */
		axa_trace_msg("close(%s): %s", label, strerror(errno));
	}
}

void
axa_io_close(axa_io_t *io)
{
	int wstatus;

	switch (io->type) {
		case AXA_IO_TYPE_APIKEY:
			axa_apikey_stop(io);
			break;
		case AXA_IO_TYPE_TLS:
			axa_tls_stop(io);
			break;
		case AXA_IO_TYPE_UNIX:
		case AXA_IO_TYPE_UNKN:
		case AXA_IO_TYPE_SSH:
		case AXA_IO_TYPE_TCP:
		default:
			break;
	}

	if (io->i_fd >= 0 && io->i_fd != io->o_fd)
		ck_close(io->i_fd, "io->i_fd");
	if (io->o_fd >= 0)
		ck_close(io->o_fd, "io->o_fd");

	if (io->tun_fd >= 0)
		ck_close(io->tun_fd, "io->tun_fd");

	if (io->tun_pid != -1) {
		kill(io->tun_pid, SIGKILL);
		waitpid(io->tun_pid, &wstatus, 0);
	}

	axa_recv_flush(io);
	if (io->recv_buf != NULL)
		free(io->recv_buf);

	if (io->tun_buf != NULL)
		free(io->tun_buf);

	if (io->send_buf != NULL)
		free(io->send_buf);

	if (io->addr != NULL)
		free(io->addr);
	if (io->label != NULL)
		free(io->label);

	if (io->cert_file != NULL)
		free(io->cert_file);
	if (io->key_file != NULL)
		free(io->key_file);
	if (io->tls_info != NULL)
		free(io->tls_info);

	/* Clear the FDs, PID, buffer pointers, etc. */
	axa_io_init(io);
}

static axa_p_direction_t
which_direction(const axa_io_t *io, bool send)
{
	bool to_srvr;
	axa_p_direction_t result;

	to_srvr = ((send && io->is_client)
		   || (!send && !io->is_client));
	if (io->is_rad) {
		result = to_srvr ? AXA_P_TO_RAD : AXA_P_FROM_RAD;
	} else {
		result = to_srvr ? AXA_P_TO_SRA : AXA_P_FROM_SRA;
	}

	return (result);
}

/* Make an error message for a bad AXA message header that looks like
 * an SSH message of the day.. */
static void
motd_hdr(axa_emsg_t *emsg, axa_io_t *io)
{
	ssize_t i;

	if (io->type != AXA_IO_TYPE_SSH)
		return;

	/* Did we receive the header in a single read? */
	if (io->recv_start != &io->recv_buf[sizeof(axa_p_hdr_t)]) {
		/* No, so do not disturb the existing error message. */
		return;
	}

	/* Yes, so find the first non-ASCII byte. */
	for (i = 0; i < io->recv_bytes; ++i) {
		if (io->recv_start[i] < ' '
		    || io->recv_start[i] > '~')
			break;
	}

	/* Assume it is a message of the day via SSH if
	 * there is a bunch of ASCII ending with '\n' or '\r'. */
	if (i == io->recv_bytes
	    && (io->recv_start[i] == '\n'
		|| io->recv_start[i] != '\r'))
		axa_pemsg(emsg, "unexpected text \"%.*s\" from %s",
			  (int)i, io->recv_buf, io->label);
}

axa_io_result_t
axa_recv_buf(axa_emsg_t *emsg, axa_io_t *io)
{
#define BUF_SIZE (64*1024)
	ssize_t len, i;
	size_t hdr_len;
	uint8_t *tgt;
	axa_io_result_t io_result;

	/* Create unprocessed data buffer the first time. */
	if (io->recv_buf == NULL) {
		io->recv_buf_len = BUF_SIZE;
		io->recv_buf = axa_malloc(io->recv_buf_len);
		io->recv_bytes = 0;
	}

	if (io->recv_body_len == 0)
		memset(&io->recv_hdr, 0, sizeof(io->recv_hdr));

	for (;;) {
		/* Decide how many more bytes we need. */
		len = sizeof(io->recv_hdr) - io->recv_body_len;
		if (len > 0) {
			/* We do not yet have the entire header,
			 * and so we must not have a place for the body. */
			AXA_ASSERT(io->recv_body == NULL);

			tgt = (uint8_t *)&io->recv_hdr + io->recv_body_len;

		} else {
			/* We have at least all of the header.
			 * Check the header when we first have it. */
			if (len == 0
			    && !axa_ck_hdr(emsg, &io->recv_hdr, io->label,
				       which_direction(io, false))) {
				motd_hdr(emsg, io);
				return (AXA_IO_ERR);
			}

			/* Stop when we have a complete message. */
			hdr_len = AXA_P2H32(io->recv_hdr.len);
			if (hdr_len == io->recv_body_len) {
#if AXA_P_PVERS != 1
#error "write code to adjust other guy's AXA protocol to our version"
#endif
				if (!axa_ck_body(emsg, io->recv_hdr.op,
						 io->recv_body,
						 hdr_len-sizeof(io->recv_hdr)))
					return (AXA_IO_ERR);
				return (AXA_IO_OK);
			}

			/* Allocate the body only when needed. */
			if (io->recv_body == NULL)
				io->recv_body = axa_malloc(hdr_len
							- sizeof(io->recv_hdr));
			len = hdr_len - io->recv_body_len;
			tgt = ((uint8_t *)io->recv_body
			       + io->recv_body_len - sizeof(io->recv_hdr));
		}

		/* Read more data into the hidden buffer when we run out. */
		if (io->recv_bytes == 0) {
			io->recv_start = io->recv_buf;
			if (io->type == AXA_IO_TYPE_TLS ||
					io->type == AXA_IO_TYPE_APIKEY) {
				io_result = axa_tls_read(emsg, io);
				if (io_result != AXA_IO_OK)
					return (io_result);
			} else {
				for (;;) {
					i = read(io->i_fd, io->recv_buf,
						 io->recv_buf_len);
					if (i > 0) {
					    io->recv_bytes = i;
					    gettimeofday(&io->alive, NULL);
					    break;
					}

					if (i == 0) {
					    axa_pemsg(emsg, "read(%s): EOF",
						      io->label);
					    return (AXA_IO_ERR);
					}
					if (errno == EINTR)
					    continue;
					if (errno == EAGAIN
					    || errno == EWOULDBLOCK)
					    return (AXA_IO_BUSY);
					axa_pemsg(emsg, "read(%s): %s",
						  io->label, strerror(errno));
					return (AXA_IO_ERR);
				}
			}
		}

		/* Consume data in the buffer. */
		i = min(len, io->recv_bytes);
		memcpy(tgt, io->recv_start, i);
		io->recv_start += i;
		io->recv_bytes -= i;

		io->recv_body_len += i;
	}
}

/* Wait for something to to happen */
axa_io_result_t
axa_io_wait(axa_emsg_t *emsg, axa_io_t *io,
	    time_t wait_ms, bool keepalive, bool tun)
{
	struct timeval now;
	time_t ms;
	struct pollfd pollfds[3];
	int nfds, i_nfd, o_nfd, tun_nfd;
	int i;

	/* Stop waiting when it is time for a keepalive. */
	if (keepalive) {
		gettimeofday(&now, NULL);
		ms = (AXA_KEEPALIVE_MS - axa_elapsed_ms(&now, &io->alive));
		if (wait_ms > ms)
			wait_ms = ms;
	}
	if (wait_ms < 0)
		wait_ms = 0;

	memset(pollfds, 0, sizeof(pollfds));
	i_nfd = -1;
	o_nfd = -1;
	tun_nfd = -1;
	nfds = 0;

	if (io->i_fd >= 0 && io->i_events != 0) {
		pollfds[nfds].fd = io->i_fd;
		pollfds[nfds].events = io->i_events;
		i_nfd = nfds++;
	}

	if (io->o_fd >= 0 && io->o_events != 0) {
		pollfds[nfds].fd = io->o_fd;
		pollfds[nfds].events = io->o_events;
		o_nfd = nfds++;
	}

	/* Watch the stderr pipe from a tunnel such as ssh. */
	if (tun && io->tun_fd >= 0) {
		pollfds[nfds].fd = io->tun_fd;
		pollfds[nfds].events = AXA_POLL_IN;
		tun_nfd = nfds++;
	}

	i = poll(pollfds, nfds, wait_ms);
	if (i < 0 && errno != EINTR) {
		axa_pemsg(emsg, "poll(): %s", strerror(errno));
		return (AXA_IO_ERR);
	}
	if (i <= 0)
		return (AXA_IO_BUSY);

	if (tun_nfd >= 0 && pollfds[tun_nfd].revents != 0)
		return (AXA_IO_TUNERR);

	if ((i_nfd >= 0 && pollfds[i_nfd].revents != 0)
	    || (o_nfd >= 0 && pollfds[o_nfd].revents != 0))
		return (AXA_IO_OK);

	if (keepalive) {
		gettimeofday(&now, NULL);
		ms = (AXA_KEEPALIVE_MS - axa_elapsed_ms(&now, &io->alive));
		if (ms <= 0)
			return (AXA_IO_KEEPALIVE);
	}
	return (AXA_IO_BUSY);
}

/*  Wait for and read a complete AXA message from the server into
 * the client buffer. */
axa_io_result_t
axa_input(axa_emsg_t *emsg, axa_io_t *io, time_t wait_ms)
{
	axa_io_result_t result;

	for (;;) {
		if (!AXA_IO_OPENED(io)) {
			axa_pemsg(emsg, "not open");
			return (AXA_IO_ERR);
		}
		if (!AXA_IO_CONNECTED(io)) {
			axa_pemsg(emsg, "not connected");
			return (AXA_IO_ERR);
		}

		/* Read more from the peer when needed. */
		if (io->recv_buf == NULL || io->recv_bytes == 0) {
			result = axa_io_wait(emsg, io, wait_ms,
					     AXA_IO_CONNECTED(io), true);
			switch (result) {
			case AXA_IO_OK:
				break;
			case AXA_IO_ERR:
			case AXA_IO_TUNERR:
			case AXA_IO_KEEPALIVE:
			case AXA_IO_BUSY:
				return (result);
			}
		}

		result = axa_recv_buf(emsg, io);
		switch (result) {
		case AXA_IO_OK:
		case AXA_IO_ERR:
			return (result);
		case AXA_IO_BUSY:
			continue;	/* wait for the rest */
		case AXA_IO_TUNERR:	/* impossible */
		case AXA_IO_KEEPALIVE:	/* impossible */
			AXA_FAIL("impossible axa_recv_buf() result");
		}
	}
}

size_t
axa_make_hdr(axa_emsg_t *emsg, axa_p_hdr_t *hdr,
	     axa_p_pvers_t pvers, axa_tag_t tag, axa_p_op_t op,
	     size_t b1_len, size_t b2_len, axa_p_direction_t dir)
{
	size_t total;

	memset(hdr, 0, sizeof(axa_p_hdr_t));
	hdr->tag = AXA_H2P_TAG(tag);
	total = sizeof(*hdr) + b1_len + b2_len;
	hdr->len = AXA_H2P32(total);
	hdr->pvers = pvers;
	hdr->op = op;

	if (!axa_ck_hdr(emsg, hdr, "myself", dir))
		return (0);

	return (total);
}

/* Send an AXA request or response to the server or client.
 *	The message is in 0, 1, 2, or 3 parts.
 *	hdr is the optional AXA protocol header to be built
 *	b1 and b1_len specify an optional second part after the header
 *	b2 and b2_len specify the third part. */
axa_io_result_t
axa_send(axa_emsg_t *emsg, axa_io_t *io,
	 axa_tag_t tag, axa_p_op_t op, axa_p_hdr_t *hdr,
	 const void *b1, size_t b1_len,
	 const void *b2, size_t b2_len)
{
	axa_p_hdr_t hdr0;
	struct iovec iov[3];
	int iovcnt;
	ssize_t total, done;

#if AXA_P_PVERS != 1
	if (pvers != AXA_P_PVERS) {
#error "write code to adjust outgoing data to other guy's AXA protocol"
	}
#endif

	if (hdr == NULL)
		hdr = &hdr0;
	total = axa_make_hdr(emsg, hdr, io->pvers, tag, op,
			     b1_len, b2_len, which_direction(io, true));
	if (total == 0)
		return (AXA_IO_ERR);

	if (io->type == AXA_IO_TYPE_TLS || io->type == AXA_IO_TYPE_APIKEY) {
		/*
		 * For TLS, save all 3 parts in the overflow output buffer
		 * so that the AXA message can be sent as a single TLS
		 * transaction.  This is expensive, but only if you ignore
		 * the cost of TLS encryption.
		 */
		axa_send_save(io, 0, hdr, b1, b1_len, b2, b2_len);
		return (axa_tls_flush(emsg, io));
	}

	for (;;) {
		iov[0].iov_base = hdr;
		iov[0].iov_len = sizeof(*hdr);
		if (b1_len == 0) {
			iovcnt = 1;
		} else {
			iov[1].iov_base = (void *)b1;
			iov[1].iov_len = b1_len;
			if (b2_len == 0) {
				iovcnt = 2;
			} else {
				iov[2].iov_base = (void *)b2;
				iov[2].iov_len = b2_len;
				iovcnt = 3;
			}
		}

		done = writev(io->o_fd, iov, iovcnt);
		if (done > 0) {
			gettimeofday(&io->alive, NULL);
			break;
		}

		if (done < 0) {
			if (errno == EINTR) {
				/* ignore signals */
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* None sent, so give up and let
				 * the caller save or discard. */
				return (AXA_IO_BUSY);
			}

			axa_pemsg(emsg, "writev(%s): %s",
				  io->label, strerror(errno));
			return (AXA_IO_ERR);
		}
	}
	if (done < total)
		axa_send_save(io, done, hdr, b1, b1_len, b2, b2_len);

	return (AXA_IO_OK);
}

/* Add to the buffer of pending output data. */
void
axa_send_save(axa_io_t *io, size_t done, const axa_p_hdr_t *hdr,
	      const void *b1, size_t b1_len,
	      const void *b2, size_t b2_len)
{
	ssize_t avail_len, new_len;
	ssize_t undone, chunk;
	uint8_t *new_buf, *p;

	undone = sizeof(*hdr)+b1_len+b2_len - done;
	AXA_ASSERT(undone > 0);

	/* Expand the buffer if necessary */
	avail_len = io->send_buf_len - io->send_bytes;
	if (avail_len < undone) {
		new_len = (io->send_buf_len + undone + 1024 + 1023) & ~1024;
		new_buf = axa_malloc(new_len);

		/* Save previously saved data. */
		if (io->send_buf != NULL) {
			if (io->send_bytes != 0)
				memcpy(new_buf, io->send_start, io->send_bytes);
			free(io->send_buf);
		}
		io->send_buf = new_buf;;
		io->send_start = io->send_buf;
		io->send_buf_len = new_len;

	} else if (avail_len - (io->send_start - io->send_buf) < undone) {
		/* slide down previously pending data */
		if (io->send_bytes != 0)
			memmove(io->send_buf, io->send_start, io->send_bytes);
		io->send_start = io->send_buf;
	}

	/* Copy the unsent parts of the header and two chucks of body */
	p = io->send_start + io->send_bytes;
	io->send_bytes += undone;

	chunk = sizeof(*hdr) - done;
	if (chunk > 0) {
		/* Some or all of the header was not sent.
		 * Save the unsent part. */
		memcpy(p, (uint8_t *)hdr + done, chunk);
		p += chunk;
		done += chunk;
	}

	chunk = sizeof(*hdr)+b1_len - done;
	if (chunk > 0) {
		/* Some or all of the first chunk of body was not sent.
		 * Save the unsent part. */
		memcpy(p, ((uint8_t *)b1)+(b1_len-chunk), chunk);
		p += chunk;
		done += chunk;
	}

	chunk = sizeof(*hdr)+b1_len+b2_len - done;
	if (chunk > 0) {
		/* Some or all of the second chunk of body was not sent.
		 * Save the unsent part. */
		memcpy(p, ((uint8_t *)b2)+(b2_len-chunk), chunk);
	}
}

/* Flush pending output */
axa_io_result_t
axa_send_flush(axa_emsg_t *emsg, axa_io_t *io)
{
	ssize_t done;

	if (io->type == AXA_IO_TYPE_TLS || io->type == AXA_IO_TYPE_APIKEY)
		return (axa_tls_flush(emsg, io));

	/* Repeat other transports until nothing flows. */
	for (;;) {
		if (io->send_bytes == 0) {
			io->o_events = 0;
			return (AXA_IO_OK);
		}

		done = write(io->o_fd, io->send_start,
			     io->send_bytes);
		if (done < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				io->send_bytes = 0;
				axa_pemsg(emsg, "send(): %s",
					  strerror(errno));
				return (AXA_IO_ERR);
			}

			io->o_events = AXA_POLL_OUT;
			return (AXA_IO_BUSY);
		}
		io->send_start += done;
		io->send_bytes -= done;

		gettimeofday(&io->alive, NULL);
	}
}

/* Capture anything that the tunnel (eg. ssh) process says. */
const char *				/* NULL or \'0' terminated string */
axa_io_tunerr(axa_io_t *io)
{
	int i;
	char *p;

	/* Create the buffer the first time */
	if (io->tun_buf == NULL || io->tun_buf_size == 0) {
		AXA_ASSERT(io->tun_buf == NULL && io->tun_buf_size == 0);
		io->tun_buf_size = 120;
		io->tun_buf = axa_malloc(io->tun_buf_size);
	}

	for (;;) {
		/* Discard the previously returned line. */
		if (io->tun_buf_bol != 0) {
			i = io->tun_buf_len - io->tun_buf_bol;
			if (i > 0)
				memmove(io->tun_buf,
					&io->tun_buf[io->tun_buf_bol],
					i);
			io->tun_buf_len -= io->tun_buf_bol;
			io->tun_buf_bol = 0;
		}

		/* Hope to return the next line in the buffer. */
		if (io->tun_buf_len > 0) {
			i = min(io->tun_buf_len, io->tun_buf_size);
			p = memchr(io->tun_buf, '\n', i);
			if (p != NULL) {
				*p = '\0';
				io->tun_buf_bol = p+1 - io->tun_buf;

				/* trim '\r' */
				while (p > io->tun_buf && *--p == '\r')
					*p = '\0';
				/* Discard blank lines. */
				if (p == io->tun_buf)
					continue;
				return (io->tun_buf);
			}
		}

		/* Get more data, possibly completing a partial line. */
		i = io->tun_buf_size-1 - io->tun_buf_len;
		if (i > 0 && io->tun_fd >= 0) {
			i = read(io->tun_fd,
				 &io->tun_buf[io->tun_buf_len],
				 i);

			/* Return the 1st line in the new buffer load */
			if (i > 0) {
				io->tun_buf_len += i;
				io->tun_buf[io->tun_buf_len] = '\0';
				continue;
			}

			if (i < 0
			    && errno != EWOULDBLOCK && errno != EAGAIN) {
				/* Return error message at errors. */
				snprintf(io->tun_buf, io->tun_buf_size,
					 "read(tunerr): %s",
					 strerror(errno));
				io->tun_buf_len = strlen(io->tun_buf)+1;
				close(io->tun_fd);
				io->tun_fd = -1;

			} else if (i == 0) {
				close(io->tun_fd);
				io->tun_fd = -1;
			}
		}

		/* Return whatever we have. */
		io->tun_buf_bol = io->tun_buf_len;
		return ((io->tun_buf_len > 0) ? io->tun_buf : NULL);
	}
}

/* Clean up AXA I/O functions including freeing TLS data */
void
axa_io_cleanup(void)
{
	axa_tls_cleanup();
	axa_apikey_cleanup();
}

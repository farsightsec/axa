/*
 * AXA protocol utilities
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

#include <axa/axa_endian.h>
#include <axa/wire.h>

#include <wdns.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <limits.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
#include <time.h>			/* for localtime() and strftime() */
#endif
#include <sys/uio.h>
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

	str = strdup(arg);
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
	case AXA_P_OP_AHIT:	strlcpy(buf, "ANOMOLY HIT",	buflen); break;
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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		snprintf(buf, buflen, "unknown op #%d", op);
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

static char *
watch_ip_to_str(char *buf, size_t buf_len,
		int af, const void *addr, size_t alen, uint prefix)
{
	union {
		struct in_addr	ipv4;
		struct in6_addr	ipv6;
		uint8_t		b[0];
	} abuf;
	char ip_str[INET6_ADDRSTRLEN];
	char prefix_str[1+3+1];

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
	AXA_ASSERT(alen <= sizeof(abuf));
	memcpy(&abuf, addr, alen);

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
		watch_ip_to_str(buf, buf_len, AF_INET,
				&watch->pat.addr, pat_len, watch->prefix);
		break;
	case AXA_P_WATCH_IPV6:
		watch_ip_to_str(buf, buf_len, AF_INET6,
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
	      const axa_p_watch_t *watch, size_t watch_len)
{
	size_t len;

	axa_watch_to_str(*bufp, *buf_lenp, watch, watch_len);
	len = strlen(*bufp);
	*bufp += len;
	*buf_lenp -= len;
}

static void
whit_add_str(char **bufp, size_t *buf_lenp,
	    const axa_p_whit_t *whit, size_t whit_len)
{
	char ip_str[INET6_ADDRSTRLEN];

	if (whit->hdr.type == AXA_P_WHIT_NMSG) {
		axa_buf_print(bufp, buf_lenp, "ch%d nmsg", whit->hdr.ch);
		return;
	}

	if (whit->hdr.type != AXA_P_WHIT_IP) {
		axa_buf_print(bufp, buf_lenp, "ch%d ???", whit->hdr.ch);
		return;
	}

	if (whit_len >= sizeof(struct ip)
	    && (whit->ip.b[0] & 0xf0) == 0x40) {
		watch_ip_to_str(ip_str, sizeof(ip_str), AF_INET,
				AXA_OFFSET(whit->ip.b, struct ip, ip_src),
				4, 32);
		axa_buf_print(bufp, buf_lenp,
			      "ch%d src %s", whit->hdr.ch, ip_str);

	} else if (whit_len >= sizeof(struct ip6_hdr)
	    && (whit->ip.b[0] & 0xf0) == 0x60) {
		watch_ip_to_str(ip_str, sizeof(ip_str), AF_INET6,
				AXA_OFFSET(whit->ip.b, struct ip6_hdr, ip6_src),
				16, 128);
		axa_buf_print(bufp, buf_lenp,
			      "ch%d src %s", whit->hdr.ch, ip_str);

	} else {
		axa_buf_print(bufp, buf_lenp, "ch%d ???", whit->hdr.ch);
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
	       const axa_p_missed_t *missed)
{
	time_t epoch;
	char time_buf[32];

	epoch = AXA_P2H32(missed->last_report);
	strftime(time_buf, sizeof(time_buf), "%Y/%m/%d %T",
		 localtime(&epoch));

	axa_buf_print(bufp, buf_lenp,
		      "    missed %"PRIu64" input packets,"
		      " dropped %"PRIu64" for congestion,\n"
		      "\tdropped %"PRIu64" for rate limit,"
		      " filtered %"PRIu64"\n"
		      "\tsince %s",
		      AXA_P2H64(missed->missed),
		      AXA_P2H64(missed->dropped),
		      AXA_P2H64(missed->rlimit),
		      AXA_P2H64(missed->filtered),
		      time_buf);
}

static void
missed_rad_add_str(char **bufp, size_t *buf_lenp,
		   const axa_p_missed_rad_t *missed)
{
	time_t epoch;
	char time_buf[32];

	epoch = AXA_P2H32(missed->last_report);
	strftime(time_buf, sizeof(time_buf), "%Y/%m/%d %T",
		 localtime(&epoch));

	axa_buf_print(bufp, buf_lenp,
		      "    missed %"PRIu64" input packets at SRA server,"
		      " dropped %"PRIu64" for SRA->RAD congestion,\n"
		      "\tdropped %"PRIu64" for SRA->RAD rate limit,"
		      " filtered %"PRIu64" by SRA\n"
		      "\tdropped %"PRIu64" for RAD->client congestion,"
		      " dropped %"PRIu64" for RAD rate limit,\n"
		      "\tfiltered %"PRIu64" by RAD modules"
		      " since %s",
		      AXA_P2H64(missed->sra_missed),
		      AXA_P2H64(missed->sra_dropped),
		      AXA_P2H64(missed->sra_rlimit),
		      AXA_P2H64(missed->sra_filtered),
		      AXA_P2H64(missed->dropped),
		      AXA_P2H64(missed->rlimit),
		      AXA_P2H64(missed->filtered),
		      time_buf);
}

/* Convert som AXA protocol messages to strings. */
char *					/* input parameter buf0 */
axa_p_to_str(char *buf0, size_t buf_len,    /* should be AXA_P_STRLEN */
	     bool print_op,
	     const axa_p_hdr_t *hdr,	/* protocol byte order */
	     const axa_p_body_t *body)
{
	char tag_op_buf[AXA_TAG_STRLEN+AXA_P_OP_STRLEN];
	char *buf;

	buf = buf0;
	buf[0] = '\0';
	if (print_op)
		axa_buf_print(&buf, &buf_len, "%s",
			      axa_tag_op_to_str(tag_op_buf, sizeof(tag_op_buf),
						AXA_P2H_TAG(hdr->tag),
						hdr->op));

	switch ((axa_p_op_t)hdr->op) {
	case AXA_P_OP_NOP:
		break;

	case AXA_P_OP_HELLO:
		if (print_op)
			axa_buf_print(&buf, &buf_len, " ");
		axa_buf_print(&buf, &buf_len, "%s", body->hello.str);
		break;

	case AXA_P_OP_OK:
	case AXA_P_OP_ERROR:
		if (print_op)
			axa_buf_print(&buf, &buf_len, " ");
		if (body->result.orig_op == AXA_P_OP_OK
		    || body->result.orig_op == AXA_P_OP_NOP
		    || body->result.orig_op == AXA_P_OP_ERROR) {
			axa_buf_print(&buf, &buf_len, "%s",
				      body->result.str);
		} else {
			axa_buf_print(&buf, &buf_len, "%s %s",
				      axa_op_to_str(tag_op_buf,
						    sizeof(tag_op_buf),
						    body->result.orig_op),
				      body->result.str);
		}
		break;

	case AXA_P_OP_MISSED:
		if (print_op)
			axa_buf_print(&buf, &buf_len, "\n");
		missed_add_str(&buf, &buf_len, &body->missed);
		break;

	case AXA_P_OP_MISSED_RAD:
		if (print_op)
			axa_buf_print(&buf, &buf_len, "\n");
		missed_rad_add_str(&buf, &buf_len, &body->missed_rad);
		break;

	case AXA_P_OP_WHIT:
		if (print_op)
			axa_buf_print(&buf, &buf_len, " ");
		whit_add_str(&buf, &buf_len, &body->whit,
			      (AXA_P2H32(hdr->len) - sizeof(*hdr)));
		break;

	case AXA_P_OP_WATCH:
		if (print_op)
			axa_buf_print(&buf, &buf_len, " ");
		watch_add_str(&buf, &buf_len, &body->watch,
			      (AXA_P2H32(hdr->len) - sizeof(*hdr)));
		break;

	case AXA_P_OP_ANOM:
		if (print_op)
			axa_buf_print(&buf, &buf_len, " ");
		axa_buf_print(&buf, &buf_len, "%s", body->anom.an.c);
		if (AXA_P2H32(hdr->len)-sizeof(*hdr) > sizeof(body->anom.an.c)
		    && body->anom.parms[0] != '\0')
			axa_buf_print(&buf, &buf_len, " %s", body->anom.parms);
		break;

	case AXA_P_OP_CHANNEL:
		if (print_op)
			axa_buf_print(&buf, &buf_len, " ");
		if (body->channel.ch == AXA_P2H_CH(AXA_OP_CH_ALL)) {
			snprintf(buf, buf_len, AXA_OP_CH_ALLSTR" %s",
				 (body->channel.on != 0) ? "on" : "off");
		} else {
			snprintf(buf, buf_len, AXA_OP_CH_PREFIX"%d %s",
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
		watch_add_str(&buf, &buf_len, &body->wlist.w,
			      (AXA_P2H32(hdr->len) - sizeof(*hdr)
			       - (sizeof(body->wlist)
				  - sizeof(body->wlist.w))));
		break;

	case AXA_P_OP_AHIT:
		if (print_op)
			axa_buf_print(&buf, &buf_len, " ");
		axa_buf_print(&buf, &buf_len, "%s ", body->ahit.an.c);
		whit_add_str(&buf, &buf_len, &body->ahit.whit,
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
		if (print_op)
			axa_buf_print(&buf, &buf_len, " ");
		axa_buf_print(&buf, &buf_len, "'%s'", body->user.name);
		break;

	case AXA_P_OP_OPT:
		switch ((axa_p_opt_type_t)body->opt.type) {
		case AXA_P_OPT_TRACE:
			if (print_op)
				axa_buf_print(&buf, &buf_len, " TRACE ");
			axa_buf_print(&buf, &buf_len, "trace=%d",
				      body->opt.u.trace);
			break;
		case AXA_P_OPT_RLIMIT:
			if (print_op)
				axa_buf_print(&buf, &buf_len, " ");
			axa_buf_print(&buf, &buf_len, "RATE LIMITS");
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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
		default:
			if (print_op)
				axa_buf_print(&buf, &buf_len, " ");
			axa_buf_print(&buf, &buf_len,
				      "unrecogized type %d", body->opt.type);
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
	default:
		break;
	}

	return (buf0);
}

/* Check the header of an AXA message. */
static bool				/* false=bad */
ck_hdr(axa_emsg_t *emsg, const axa_p_hdr_t *hdr,
       const char *peer, axa_p_direction_t dir)
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
			  " from %s", len, peer);
		return (false);
	}
	if (hdr->pvers < AXA_P_PVERS_MIN || hdr->pvers > AXA_P_PVERS_MAX) {
		axa_pemsg(emsg, "unknown protocol version #%d for %s from %s",
			  hdr->pvers,
			  axa_op_to_str(op_buf, sizeof(op_buf), hdr->op),
			  peer);
		return (false);
	}
	len -= sizeof(*hdr);
	if (len > AXA_P_MAX_BODY_LEN) {
		axa_pemsg(emsg, "impossible body length %d from %s",
			  len, peer);
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
		max_len = sizeof(body->opt);
		min_len = max_len - (sizeof(body->opt.u)
				     - sizeof(body->opt.u.trace));
		tagged = 0;
		dir_ok = true;
		break;
	case AXA_P_OP_ACCT:
		max_len = min_len = 0;
		tagged = 0;
		dir_ok = (dir == AXA_P_TO_SRA || dir == AXA_P_TO_RAD);
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
				  peer);
			return (false);
		}
	} else if (tagged == -1) {
		if (tag != AXA_TAG_NONE) {
			axa_pemsg(emsg, "unexpected tag %d for %s from %s",
				  tag,
				  axa_op_to_str(op_buf, sizeof(op_buf),
						hdr->op),
				  peer);
			return (false);
		}
	}

	if (!dir_ok) {
		switch (dir) {
		case AXA_P_TO_SRA:
			dir1_str = peer;
			dir2_str = "SRA client";
			break;
		case AXA_P_FROM_SRA:
			dir1_str = "SRA";
			dir2_str = peer;
			break;
		case AXA_P_TO_RAD:
			dir1_str = peer;
			dir2_str = "RAD client";
			break;
		case AXA_P_FROM_RAD:
			dir1_str = "RAD";
			dir2_str = peer;
			break;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
		default:
			dir1_str = "?";
			dir2_str = peer;
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
			  peer, max_len);
		return (false);
	}
	if (len < min_len) {
		axa_pemsg(emsg, "length %d for %s from %s must be at least %zu",
			  len, axa_op_to_str(op_buf, sizeof(op_buf), hdr->op),
			  peer, min_len);
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

	AXA_ASSERT(opt_len >= sizeof(axa_p_opt_t) - sizeof(opt->u)
		   && opt_len <= sizeof(axa_p_opt_t ));
	val_len = opt_len - (sizeof(axa_p_opt_t) - sizeof(opt->u));

	switch ((axa_p_opt_type_t)opt->type) {
	case AXA_P_OPT_TRACE:
		if (val_len != sizeof(opt->u.trace)) {
			axa_pemsg(emsg, "%s bad trace option length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  opt_len);
			return (false);
		}
		break;
	case AXA_P_OPT_RLIMIT:
		if (val_len != sizeof(opt->u.rlimit)) {
			axa_pemsg(emsg, "%s bad rate limit option length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  opt_len);
			return (false);
		}
		break;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		axa_pemsg(emsg, "%s unrecognized option type %d",
			  axa_op_to_str(op_buf, sizeof(op_buf), op),
			  opt->type);
		return (false);
#pragma clang diagnostic pop
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
	}

	return (true);
}

axa_p_recv_result_t
axa_p_recv(axa_emsg_t *emsg, int s,
	   axa_p_hdr_t *hdr, axa_p_body_t **bodyp, size_t *recv_len,
	   axa_recv_buf_t *buf,
	   const char *peer, axa_p_direction_t dir, struct timeval *alive)
{
#define BUF_SIZE (64*1024)
	ssize_t len, i;
	size_t hdr_len;
	axa_p_body_t *body;
	uint8_t *tgt;

	AXA_ASSERT(peer != NULL);

	/* Create our hidden buffer the first time. */
	if (buf->data == NULL) {
		buf->buf_size = BUF_SIZE;
		buf->data = axa_malloc(buf->buf_size);
		buf->data_len = 0;
	}

	if (*recv_len == 0)
		memset(hdr, 0, sizeof(*hdr));
	body = *bodyp;

	for (;;) {
		/* Decide how many more bytes we need. */
		len = sizeof(*hdr) - *recv_len;
		if (len > 0) {
			/* We do not yet have the entire header,
			 * and so we must not have a place for the body. */
			AXA_ASSERT(body == NULL);

			tgt = (uint8_t *)hdr + *recv_len;

		} else {
			/* We have at least all of the header.
			 * Check the header when we first have it. */
			if (len == 0
			    && !ck_hdr(emsg, hdr, peer, dir)) {
				/* The AXA message header is bad.
				 * If it is all ASCII, and if much of the
				 * buffer read from the peer is ASCII, then
				 * report it as a likely message-of-the-day
				 * or other error. */
				if (buf->base == &buf->data[sizeof(*hdr)]) {
					len = buf->data_len+sizeof(*hdr);
					for (i = 0; i < len; ++i)
					    if (buf->data[i] < ' '
						|| buf->data[i] > '~')
						break;
					if (i == buf->data_len
					    || buf->data[i] == '\n')
					    axa_pemsg(emsg, "unexpected text"
						      " \"%.*s\" from %s",
						      (int)i, buf->data, peer);
				}
				return (AXA_P_RECV_ERR);
			}

			/* Stop when we have a complete message. */
			hdr_len = AXA_P2H32(hdr->len);
			if (hdr_len == *recv_len) {
#if AXA_P_PVERS != 1
#error "write code to adjust other guy's AXA protocol to our version"
#endif
				if (!axa_ck_body(emsg, hdr->op, body,
						 hdr_len - sizeof(*hdr)))
					return (AXA_P_RECV_ERR);
				return (AXA_P_RECV_DONE);
			}

			/* Allocate space for the body only when needed. */
			if (body == NULL) {
				body = axa_malloc(hdr_len - sizeof(*hdr));
				*bodyp = body;
			}
			len = hdr_len - *recv_len;
			tgt = (uint8_t *)body + *recv_len - sizeof(*hdr);
		}

		/* Read more data into the hidden buffer when we run out. */
		if (buf->data_len == 0) {
			for (;;) {
				buf->base = buf->data;
				i = read(s, buf->base, buf->buf_size);
				if (i > 0) {
					if (alive != NULL)
					    gettimeofday(alive, NULL);
					break;
				}

				if (i == 0) {
					axa_pemsg(emsg, "read(%s): EOF", peer);
					return (AXA_P_RECV_ERR);
				}
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return (AXA_P_RECV_INCOM);
				axa_pemsg(emsg, "read(%s): %s",
					  peer, strerror(errno));
				return (AXA_P_RECV_ERR);
			}
			buf->data_len = i;
		}

		/* Consume data in the buffer. */
		i = min(len, buf->data_len);
		memcpy(tgt, buf->base, i);
		buf->base += i;
		buf->data_len -= i;

		*recv_len += i;
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

	if (!ck_hdr(emsg, hdr, "myself", dir))
		return (0);

	return (total);
}

/* Send an SRA or RAD request or response to the server or client.
 *	The message is in 1, 2, or 3 parts.
 *	hdr is the AXA protocol header to be built
 *	b1 and b1_len specify an optional second part after the header
 *	b2 and b2_len specify the third part. */
axa_p_send_result_t
axa_p_send(axa_emsg_t *emsg, int s,
	   axa_p_pvers_t pvers, axa_tag_t tag, axa_p_op_t op,
	   axa_p_hdr_t *hdr,
	   const void *b1, size_t b1_len,
	   const void *b2, size_t b2_len,
	   size_t *donep,		/* put # of bytes sent here */
	   const char *peer,		/* peer name for error messages */
	   axa_p_direction_t dir,	/* to server or to client */
	   struct timeval *alive)
{
	axa_p_hdr_t hdr0;
	struct iovec iov[3];
	int iovcnt;
	size_t total;
	ssize_t done;

	AXA_ASSERT(peer != NULL);

#if AXA_P_PVERS != 1
	if (pvers != AXA_P_PVERS) {
#error "write code to adjust outgoing data to other guy's AXA protocol"
	}
#endif

	if (hdr == NULL)
		hdr = &hdr0;
	total = axa_make_hdr(emsg, hdr, pvers, tag, op, b1_len, b2_len, dir);
	if (total == 0)
		return (AXA_P_SEND_BAD);

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

	gettimeofday(alive, NULL);

	done = writev(s, iov, iovcnt);
	if (done < 0) {
		if (donep != NULL)
			*donep = 0;
		axa_pemsg(emsg, "writev(%s): %s", peer, strerror(errno));
		if (errno == EAGAIN || errno == EWOULDBLOCK
		    || errno == ENOBUFS || errno == EINTR)
			return (AXA_P_SEND_BUSY);
		return (AXA_P_SEND_BAD);
	}

	if (donep != NULL)
		*donep = done;
	if (done == (ssize_t)total)
		return (AXA_P_SEND_OK);	/* All of the message was sent. */

	/* Part of the message was sent.
	 * The caller must figure out how much of the header and
	 * each part was sent and save the unsent data. */
	return (AXA_P_SEND_BUSY);
}

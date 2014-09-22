/*
 * AXA protocol utilities
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

#include <axa/axa_endian.h>
#include <axa/wire.h>

#include <wdns.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		AXA_FAIL("impossible message type");
#pragma clang diagnostic pop
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
	       size_t *anom_len,	/* its length */
	       const char *arg)		/* null terminated input */
{
	const char *parms;
	size_t an_len, parms_len;

	memset(anom, 0, sizeof(*anom));

	/* look for "name [parameters]" */
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

char *
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

char *
axa_tag_to_str(char *buf, size_t buf_len,   /* should be AXA_TAG_STRLEN */
	       axa_tag_t tag)
{
	if (tag == AXA_TAG_NONE)
		strlcpy(buf, "*", buf_len);
	else
		snprintf(buf, buf_len, "%d", tag);
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
rlimit_to_str(char **bufp, size_t *buf_lenp,
	      axa_rlimit_t limit, axa_rlimit_t cur, const char *str)
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

/* Convert som AXA protocol messages to strings. */
char *
axa_p_to_str(char *buf0, size_t buf_len,    /* should be AXA_P_STRLEN */
	     bool print_op,
	     const axa_p_hdr_t *hdr, const axa_p_body_t *body)
{
	char tag_buf[AXA_TAG_STRLEN];
	char op_buf[AXA_P_OP_STRLEN];
	const axa_p_watch_t *watch;
	char *buf;

	buf = buf0;
	buf[0] = '\0';
	if (print_op)
		axa_buf_print(&buf, &buf_len, "%s %s ",
			      axa_tag_to_str(tag_buf, sizeof(tag_buf),
					     AXA_P2H_TAG(hdr->tag)),
			      axa_op_to_str(op_buf, sizeof(op_buf), hdr->op));

	switch ((axa_p_op_t)hdr->op) {
	case AXA_P_OP_NOP:
		break;

	case AXA_P_OP_HELLO:
		axa_buf_print(&buf, &buf_len, "%s", body->hello.str);
		break;

	case AXA_P_OP_OK:
	case AXA_P_OP_ERROR:
		if (body->result.op == AXA_P_OP_OK
		    || body->result.op == AXA_P_OP_NOP
		    || body->result.op == AXA_P_OP_ERROR) {
			axa_buf_print(&buf, &buf_len, "%s",
				      body->result.str);
		} else {
			axa_buf_print(&buf, &buf_len, "%s %s",
				      axa_op_to_str(op_buf, sizeof(op_buf),
						    body->result.op),
				      body->result.str);
		}
		break;

	case AXA_P_OP_MISSED:
		break;

	case AXA_P_OP_WHIT:
		break;			/* The tag is enough. */

	case AXA_P_OP_WATCH:
		watch = &body->watch;
		watch_add_str(&buf, &buf_len, watch,
			      (AXA_P2H32(hdr->len) - sizeof(*hdr)));
		break;

	case AXA_P_OP_ANOM:
		if (AXA_P2H32(hdr->len)-sizeof(*hdr) == sizeof(body->anom.an.c))
			snprintf(buf, buf_len, "\"%s\"",
				 body->anom.an.c);
		else
			snprintf(buf, buf_len, "\"%s\" \"%s\"",
				 body->anom.an.c, body->anom.parms);
		break;

	case AXA_P_OP_CHANNEL:
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
		if (hdr->tag != AXA_P2H_TAG(AXA_TAG_NONE) &&
		    hdr->tag != body->wlist.cur_tag)
			axa_buf_print(&buf, &buf_len,
				      "    nearest WATCH to %d is %d\n",
				      AXA_P2H_TAG(hdr->tag),
				      AXA_P2H_TAG(body->wlist.cur_tag));
		axa_buf_print(&buf, &buf_len, "  %5s ",
			      axa_tag_to_str(tag_buf, sizeof(tag_buf),
					     AXA_P2H_TAG(body->wlist.cur_tag)));
		watch_add_str(&buf, &buf_len, &body->wlist.w,
			      (AXA_P2H32(hdr->len) - sizeof(*hdr)
			       - (sizeof(body->wlist)
				  - sizeof(body->wlist.w))));
		break;

	case AXA_P_OP_AHIT:
		snprintf(buf, buf_len, "\"%s\"", body->ahit.an.c);
		break;

	case AXA_P_OP_ALIST:
		if (hdr->tag != AXA_P2H_TAG(AXA_TAG_NONE)
		    && hdr->tag != body->alist.cur_tag)
			axa_buf_print(&buf, &buf_len,
				      "    nearest ANOMALY to %d is %d\n",
				      AXA_P2H_TAG(hdr->tag),
				      AXA_P2H_TAG(body->alist.cur_tag));
		axa_buf_print(&buf, &buf_len, "  %5s %5s %s",
			      axa_tag_to_str(tag_buf, sizeof(tag_buf),
					     AXA_P2H_TAG(body->alist.cur_tag)),
			      body->alist.anom.an.c,
			      body->alist.anom.parms);
		break;

	case AXA_P_OP_CLIST:
		break;

	case AXA_P_OP_USER:
		axa_buf_print(&buf, &buf_len, "'%s'", body->user.name);
		break;

	case AXA_P_OP_OPT:
		switch ((axa_p_opt_type_t)body->opt.type) {
		case AXA_P_OPT_DEBUG:
			axa_buf_print(&buf, &buf_len, "debug=%d",
				      body->opt.u.debug);
			break;
		case AXA_P_OPT_RLIMIT:
			axa_buf_print(&buf, &buf_len, "RATE LIMITS");
			rlimit_to_str(&buf, &buf_len,
				      body->opt.u.rlimit.max_pkts_per_sec,
				      body->opt.u.rlimit.cur_pkts_per_sec,
				      "second");
			if (AXA_P2H64(body->opt.u.rlimit.report_secs)
			    == AXA_RLIMIT_OFF)
				axa_buf_print(&buf, &buf_len,
					      "\n    no regular reports");
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
	const char *dir_str;
	int tagged;			/* -1=never 0=sometimes 1=always */
	char op_buf[AXA_P_OP_STRLEN];
	axa_p_body_t *body;
	axa_tag_t tag;
	uint32_t len;

	body = NULL;
	len = AXA_P2H32(hdr->len);
	if (len < sizeof(*hdr)) {
		axa_pemsg(emsg, "SRA header length of %d is too small", len);
		return (false);
	}
	if (hdr->pvers < AXA_P_PVERS_MIN || hdr->pvers > AXA_P_PVERS_MAX) {
		axa_pemsg(emsg, "unknown protocol version #%d from %s",
			  hdr->pvers, peer);
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
		dir_ok = (dir == AXA_P_FROM_SRA || dir == AXA_P_FROM_RAD);
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
				     - sizeof(body->opt.u.debug));
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
		case AXA_P_TO_SRA:	dir_str = "SRA client"; break;
		case AXA_P_FROM_SRA:	dir_str = "SRA"; break;
		case AXA_P_TO_RAD:	dir_str = "RAD client"; break;
		case AXA_P_FROM_RAD:	dir_str = "RAD"; break;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
		default:		dir_str = "?"; break;
#pragma clang diagnostic pop
		}
		axa_pemsg(emsg, "illegal from %s %s", dir_str, peer);
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

	if (an->c[sizeof(an)-1] != '\0') {
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
			axa_pemsg(emsg, "%s bad IP watch length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  watch_len);
			return (false);
		}
		if (w->prefix == 0 || (w->prefix+7)/8 > pat_len) {
			axa_pemsg(emsg, "%s bad IP prefix length"
				  " %d for address length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  w->prefix, pat_len);
			return (false);
		}
		break;
	case AXA_P_WATCH_IPV6:
		if (pat_len <= 0 || pat_len > (ssize_t)sizeof(w->pat.addr6)) {
			axa_pemsg(emsg, "%s bad IP watch length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  watch_len);
			return (false);
		}
		if (w->prefix == 0 || (w->prefix+7)/8 > pat_len) {
			axa_pemsg(emsg, "%s bad IP prefix length"
				  " %d for address length %zd",
				  axa_op_to_str(op_buf, sizeof(op_buf), op),
				  w->prefix, pat_len);
			return (false);
		}
		break;
	case AXA_P_WATCH_DNS:
		if (pat_len <= 0 || pat_len > (int)sizeof(w->pat.dns)) {
			axa_pemsg(emsg, "%s bad dns watch length %zd",
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
			axa_pemsg(emsg, "%s bad dns watch label lengths",
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
ck_opt(axa_emsg_t *emsg, axa_p_op_t op, const axa_p_opt_t *opt, size_t opt_len)
{
	size_t val_len;
	char op_buf[AXA_P_OP_STRLEN];

	AXA_ASSERT(opt_len >= sizeof(axa_p_opt_t) - sizeof(opt->u)
		   && opt_len <= sizeof(axa_p_opt_t ));
	val_len = opt_len - (sizeof(axa_p_opt_t) - sizeof(opt->u));

	switch ((axa_p_opt_type_t)opt->type) {
	case AXA_P_OPT_DEBUG:
		if (val_len != sizeof(opt->u.debug)) {
			axa_pemsg(emsg, "%s bad debug option length %zd",
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
		break;
	case AXA_P_OP_WHIT:
		return (ck_ch(emsg, op, body->whit.hdr.ch, false));
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

static ssize_t				/* -1=error 0=EWOULDBLOCK */
recv_read(axa_emsg_t *emsg, int s, void *buf, size_t len,
	  const char *peer, struct timeval *alive)
{
	int i;

	for (;;) {
		i = read(s, buf, len);
		if (i > 0) {
			if (alive != NULL)
				gettimeofday(alive, NULL);
			return (i);
		}

		if (i == 0) {
			axa_pemsg(emsg, "read(%s): EOF", peer);
			return (-1);
		}
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return (0);
		axa_pemsg(emsg, "read(%s): %s", peer, strerror(errno));
		return (-1);
	}
}

/*
 *  Receive an AXA request or response into a fixed header buffer and
 *      a dynamic body buffer.
 * This function stalls until something is read, so use poll() or select()
 *	before calling it.
 * On entry,
 *	hdr points to a buffer for the AXA protocol header
 *	bodyp is a pointer to a pointer to a buffer that will be allocated
 *	    and filled with the next AXA protocol message.  This buffer must
 *	    be freed by the caller, perhaps with axa_client_flush().
 *	recv_len is the number of bytes previously received by this function.
 *	buf is optional for reducing read() system calls.
 *	peer is a string describing the peer such as its IP address and port #
 *	direction specifies whether this is working for an AXA server or client
 *	alive is used to trigger AXA protocol keepalives
 * On exit,
 *	AXA_P_RECV_RESULT_ERR	fatal error or EOF
 *	AXA_P_RECV_RESULT_INCOM	try again after select() with the same args
 *	AXA_P_RECV_RESULT_DONE	complete message received in *bodyp
 *	recv_len=sizeof(*hdr)+bytes in *bodyp
 */
axa_p_recv_result_t
axa_p_recv(axa_emsg_t *emsg, int s,
	   axa_p_hdr_t *hdr, axa_p_body_t **bodyp, size_t *recv_len,
	   axa_recv_buf_t *buf,
	   const char *peer, axa_p_direction_t dir, struct timeval *alive)
{
#define BUF_SIZE (8*1024)
	ssize_t len, i;
	size_t hdr_len;
	axa_p_body_t *body;
	uint8_t *tgt;

	AXA_ASSERT(peer != NULL);

	if (*recv_len == 0)
		memset(hdr, 0, sizeof(*hdr));

	body = *bodyp;
	for (;;) {
		/*
		 * Decide how much we need and where to put it.
		 */
		len = sizeof(*hdr) - *recv_len;
		if (len > 0) {
			/* We do not yet have the entire header,
			 * and so we must not have a buffer for the body. */
			AXA_ASSERT(body == NULL);
			tgt = (uint8_t *)hdr + *recv_len;

		} else {
			/* We have at least all of the header.
			 * Check the header when we first have it. */
			if (len == 0
			    && !ck_hdr(emsg, hdr, peer, dir))
				return (AXA_P_RECV_RESULT_ERR);

			/* Stop when we have a complete message. */
			hdr_len = AXA_P2H32(hdr->len);
			if (hdr_len == *recv_len) {
				if (!axa_ck_body(emsg, hdr->op, body,
						 hdr_len - sizeof(*hdr)))
					return (AXA_P_RECV_RESULT_ERR);
				return (AXA_P_RECV_RESULT_DONE);
			}

			if (body == NULL) {
				body = malloc(hdr_len - sizeof(*hdr));
				AXA_ASSERT(body != NULL);
				*bodyp = body;
			}
			len = hdr_len - *recv_len;
			tgt = (uint8_t *)body + *recv_len - sizeof(*hdr);
		}

		if (buf != NULL) {
			if (buf->data == NULL) {
				buf->buf_size = BUF_SIZE;
				buf->data = malloc(buf->buf_size);
				AXA_ASSERT(buf->data != NULL);
				buf->data_len = 0;
			}

			/* Get more data when we run out. */
			if (buf->data_len == 0) {
				/* If we have enough of an AXA protocol header
				 * to know the size of the message,
				 * then read only that much.
				 * This ensures that pause occassionally.
				 * When we have the whole header, we could
				 * read() directly into to final buffer,
				 * but that is a rare case. */
				if (body != NULL)
					i = len;
				else
					i = buf->buf_size;
				i = recv_read(emsg, s, buf->data, i,
					      peer, alive);
				if (i < 0)
					return (AXA_P_RECV_RESULT_ERR);
				if (i == 0)
					return (AXA_P_RECV_RESULT_INCOM);
				buf->data_len = i;
				buf->base = buf->data;
			}

			i = min(len, buf->data_len);
			memcpy(tgt, buf->base, i);
			buf->base += i;
			buf->data_len -= i;

		} else {
			i = recv_read(emsg, s, tgt, len, peer, alive);
			if (i < 0)
				return (AXA_P_RECV_RESULT_ERR);
			if (i == 0)
				return (AXA_P_RECV_RESULT_INCOM);
		}

		*recv_len += i;
	}
}

size_t
axa_make_hdr(axa_p_hdr_t *hdr,
	     axa_p_pvers_t pvers, axa_tag_t tag, axa_p_op_t op,
	     size_t b1_len, size_t b2_len, axa_p_direction_t dir)
{
	size_t total;
	axa_emsg_t emsg;

	total = sizeof(*hdr) + b1_len + b2_len;
	memset(hdr, 0, sizeof(axa_p_hdr_t));
	hdr->tag = AXA_H2P_TAG(tag);
	hdr->len = AXA_H2P32(total);
	hdr->pvers = pvers;
	hdr->op = op;
	AXA_ASSERT_MSG(ck_hdr(&emsg, hdr, "myself", dir), "%s", emsg.c);

	return (total);
}

/* Send an SRA or RAD request or response to the client or the server.
 *	The message is in 1, 2, or 3 parts.
 *	hdr always points to the AXA protocol header to build
 *	b1 and b1_len specify an optional second part
 *	b2 and b2_len specify the third part. */
axa_p_send_result_t
axa_p_send(axa_emsg_t *emsg, int s,
	   axa_p_pvers_t pvers, axa_tag_t tag, axa_p_op_t op,
	   axa_p_hdr_t *hdr,
	   const void *b1, size_t b1_len,   /* rest of AXA message to send */
	   const void *b2, size_t b2_len,
	   size_t *donep,		/* put # of bytes sent here */
	   const char *peer,		/* peer name for error messages */
	   axa_p_direction_t dir,	/* to server or to client */
	   struct timeval *alive)
{
	struct iovec iov[3];
	int iovcnt;
	size_t total;
	ssize_t done;

	AXA_ASSERT(peer != NULL);

	total = axa_make_hdr(hdr, pvers, tag, op, b1_len, b2_len, dir);

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
		*donep = 0;
		axa_pemsg(emsg, "writev(%s): %s", peer, strerror(errno));
		if (errno == EAGAIN || errno == EWOULDBLOCK
		    || errno == ENOBUFS || errno == EINTR)
			return (AXA_P_SEND_BUSY);
		return (AXA_P_SEND_BAD);
	}

	*donep = done;
	if (done == (ssize_t)total)
		return (AXA_P_SEND_OK);	/* All of the message was sent. */

	/* Part of the message was sent.
	 * The caller must figure out how much of the header and
	 * each part was sent and save the unsent data. */
	return (AXA_P_SEND_BUSY);
}

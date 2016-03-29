/*
 * Advanced Exchange Access (AXA) semanatics for DNS packets and fields.
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

#include <axa/fields.h>
#include <axa/dns_walk.h>

#include <nmsg/message.h>

#include <string.h>
#include <arpa/nameser.h>


static void AXA_PF(3,6)
error(void *ctxt, axa_walk_ops_t *ops,
      const char *pat,			/* error message pattern */
      const char *prep,			/* preposition such as "before" */
      axa_walks_t *s,			/* section name */
      ...)
{
	char pat_buf[80];
	va_list args;

	if (*s != '\0') {
		snprintf(pat_buf, sizeof(pat_buf),
			 "%s %s %s", pat, prep, s);
		pat = pat_buf;
	}

	va_start(args, s);
	ops->error(ctxt, pat, args);
	va_end(args);
}

static inline bool
skip(uint n, void *ctxt, axa_walk_ops_t *ops,
     axa_walkb_t **pp,			/* advance that pointer */
     axa_walkb_t *pkt_lim,		/* but not up to here */
     axa_walks_t *s)			/* section name */
{
	axa_walkb_t *p;

	p = *pp+n;
	if (p > pkt_lim) {
		error(ctxt, ops, "DNS data truncated", "before", s);
		return (false);
	}
	*pp = p;
	return (true);
}

#define BAD_UNPACK16 ((uint)-1)
static uint
unpack16(void *ctxt, axa_walk_ops_t *ops,
	 axa_walkb_t **pp, axa_walkb_t *pkt_lim, axa_walks_t *s)
{
	axa_walkb_t *p;
	uint w;

	p = *pp;
	if (p+2 > pkt_lim) {
		error(ctxt, ops, "DNS data truncated", "before", s);
		return (BAD_UNPACK16);
	}
	w = *p++;
	w = (w<<8) | *p++;
	*pp = p;
	return (w);
}

static bool				/* false=stop parsing */
get_domain(void *ctxt, axa_walk_ops_t *ops,
	   uint8_t *name,
	   size_t name_limit,
	   size_t *name_lenp,
	   axa_walkb_t *pkt_base,	/* 0 or DNS pkt start to decompress */
	   axa_walkb_t **pp,		/* pointer to current position */
	   axa_walkb_t *pkt_lim,	/* end+1 of DNS pkt */
	   axa_walks_t *s)		/* DNS section name */
{
	axa_walkb_t *p, *p2;
	ssize_t checked, label_len, name_len, offset;

	p = *pp;
	name_len = 0;
	checked = 0;
	do {
		label_len = *p;

		switch (label_len & 0xc0) {
		case 0:
		case 0x40:		/* EDNS0 extended label type */
			break;

		case 0x80:
			error(ctxt, ops, "invalid DNS label character %#zx",
			      "in", s, label_len);
			return (false);

		case 0xc0:
			if (pkt_base == NULL) {
				/* We cannot decompress in isolated rdata. */
				error(ctxt, ops, "illegal DNS compression",
				      "in", s);
				return (false);
			}
			if (p+2 > pkt_lim) {
				error(ctxt, ops,
				      "DNS compressed label truncated",
				      "in", s);
				return (false);
			}
			offset = ((label_len & 0x3f)<< 8) + *++p;
			p2 = pkt_base + offset;
			if (p2 >= pkt_lim) {
				error(ctxt, ops,
				      "DNS label compression truncated",
				      "in", s);
				return (false);
			}
			/* Check for loops in the compressed name;
			 * if we've looked at the whole message,
			 * there must be a loop. */
			checked += 2;
			if (name_len + checked > pkt_lim - pkt_base) {
				error(ctxt, ops,
				      "DNS label compression loop", "in", s);
				return (false);
			}
			if (pp != NULL) {
				*pp = p+1;
				pp = NULL;
			}
			p = p2;
			continue;
		}

		if (name_len+label_len > (ssize_t)name_limit) {
			error(ctxt, ops, "run-on DNS label", "in", s);
			return (false);
		}
		if (p + ++label_len > pkt_lim) {
			error(ctxt, ops, "DNS domain truncated", "in", s);
			return (false);
		}
		memcpy(&name[name_len], p, label_len);
		name_len += label_len;
		p += label_len;
	} while (label_len > 1);
	if (pp != NULL)
		*pp = p;

	*name_lenp = name_len;
	return (true);
}

static bool
walk_ip(void *ctxt, axa_walk_ops_t *ops,
	axa_walkb_t **pp, size_t rdlength, uint rtype, size_t len,
	axa_walks_t *s)
{
	char tbuf[16];
	axa_walkb_t *p;

	/* The caller has alredy checked that rdlength bytes are available. */
	p = *pp;
	*pp += rdlength;
	if (rdlength != len) {
		error(ctxt, ops, "%s rdata rdlength %zd != expected %zd", "in",
		      s, axa_rtype_to_str(tbuf, sizeof(tbuf), rtype),
		      rdlength, len);
		return (true);
	}
	if (ops->ip == NULL)
		return (true);
	return (ops->ip(ctxt, p, len, s));
}

static bool				/* false=stop parsing */
walk_domain(void *ctxt, axa_walk_ops_t *ops,
	    axa_walkb_t *pkt_base,	/* 0 or DNS pkt start to decompress */
	    axa_walkb_t **pp,		/* pointer to current position */
	    axa_walkb_t *pkt_lim,	/* end+1 of DNS pkt */
	    axa_walk_dom_t dtype,	/* stray, owner, or in rdata */
	    uint rtype,			/* of owned or containing rdata */
	    axa_walks_t *s)		/* DNS section name */
{
	uint8_t name[AXA_P_DOMAIN_LEN];
	size_t name_len;

	if (!get_domain(ctxt, ops, name, sizeof(name), &name_len,
			pkt_base, pp, pkt_lim, s))
		return (false);

	if (ops->domain == NULL)
		return (true);
	return (ops->domain(ctxt, name, name_len, dtype, rtype, s));
}

/* Come here with an owner name and its rdata.
 * This function can be ops->rdata or called by ops->rdata. */
bool					/* false=stop parsing */
axa_walk_rdata(void *ctxt, axa_walk_ops_t *ops,
	       axa_walkb_t *oname,
	       size_t oname_len,
	       axa_walkb_t *pkt_base,   /* NULL or DNS pkt to decompress */
	       axa_walkb_t *pkt_lim,    /* end+1 of DNS pkt */
	       axa_walkb_t *rdata,	/* rdata to walk or parse */
	       size_t rdlength,		/* length of rdata */
	       uint rtype,
	       axa_walks_t *s)		/* DNS section name */
{
	axa_walkb_t *eod;
	char rbuf[16];

	if (ops->domain != NULL && oname != NULL
	    && !ops->domain(ctxt, oname, oname_len,
			    AXA_WALK_DOM_OWNER, rtype, s))
		return (false);		/* stop on an error or known answer */

	eod = rdata+rdlength;

	switch (rtype) {
	case ns_t_cname:
	case ns_t_mb:
	case ns_t_mg:
	case ns_t_mr:
	case ns_t_ns:
	case ns_t_ptr:
	case ns_t_dname:
		if (!walk_domain(ctxt, ops, pkt_base, &rdata, pkt_lim,
				 AXA_WALK_DOM_RDATA1, rtype, s))
			return (false);
		break;
	case ns_t_soa:
		if (!walk_domain(ctxt, ops, pkt_base, &rdata, pkt_lim,
				 AXA_WALK_DOM_RDATA1, rtype, s)
		    || !walk_domain(ctxt, ops, pkt_base, &rdata, pkt_lim,
				    AXA_WALK_DOM_RDATA2, rtype, s)
		    || !skip(4*5, ctxt, ops, &rdata, pkt_lim, s))
			return (false);
		break;
	case ns_t_mx:
	case ns_t_afsdb:
	case ns_t_rt:
		if (!skip(2, ctxt, ops, &rdata, pkt_lim, s)
		    || !walk_domain(ctxt, ops, pkt_base, &rdata, pkt_lim,
				    AXA_WALK_DOM_RDATA1, rtype, s))
			return (false);
		break;
	case ns_t_px:
		if (!skip(2, ctxt, ops, &rdata, pkt_lim, s)
		    || !walk_domain(ctxt, ops, pkt_base, &rdata, pkt_lim,
				    AXA_WALK_DOM_RDATA1, rtype, s)
		    || !walk_domain(ctxt, ops, pkt_base, &rdata, pkt_lim,
				    AXA_WALK_DOM_RDATA2, rtype, s))
			return (false);
		break;
	case ns_t_srv:
		if (!skip(2*3, ctxt, ops, &rdata, pkt_lim, s)
		    || !walk_domain(ctxt, ops, pkt_base, &rdata, pkt_lim,
				    AXA_WALK_DOM_RDATA1, rtype, s))
			return (false);
		break;
	case ns_t_minfo:
	case ns_t_rp:
		if (!walk_domain(ctxt, ops, pkt_base, &rdata, pkt_lim,
				 AXA_WALK_DOM_RDATA1, rtype, s)
		    || !walk_domain(ctxt, ops, pkt_base, &rdata, pkt_lim,
				    AXA_WALK_DOM_RDATA2, rtype, s))
			return (false);
		break;
	case ns_t_a:
		if (!walk_ip(ctxt, ops, &rdata, rdlength, rtype, 4, s))
			return (false);
		break;
	case ns_t_aaaa:
		if (!walk_ip(ctxt, ops, &rdata, rdlength, rtype, 16, s))
			return (false);
		break;
	default:
		if (!skip(rdlength, ctxt, ops, &rdata, pkt_lim, s))
			return (false);
	}

	if (rdata != eod) {
		error(ctxt, ops, "DNS rdlength %zd for %s long by %d", "in", s,
		      rdlength, axa_rtype_to_str(rbuf, sizeof(rbuf), rtype),
		      (int)(eod - rdata));
		return (false);
	}
	return (true);
}

bool					/* false=stop parsing */
axa_skip_rdata(void *ctxt, axa_walk_ops_t *ops,
	       axa_walkb_t *oname AXA_UNUSED,
	       size_t oname_len AXA_UNUSED,
	       axa_walkb_t *pkt_base AXA_UNUSED,
	       axa_walkb_t *pkt_lim,
	       axa_walkb_t *rdata,
	       size_t rdlength,
	       uint rtype,
	       axa_walks_t *s)
{
	axa_walkb_t *eod;
	char rbuf[16];

	eod = rdata+rdlength;

	if (!skip(rdlength, ctxt, ops, &rdata, pkt_lim, s))
		return (false);

	if (rdata != eod) {
		error(ctxt, ops, "DNS rdlength %zd for %s long by %d", "in", s,
		      rdlength, axa_rtype_to_str(rbuf, sizeof(rbuf), rtype),
		      (int)(eod - rdata));
		return (false);
	}
	return (true);
}

static bool				/* false=stop walking and parsing */
walk_rr(void *ctxt, axa_walk_ops_t *ops,
	axa_walkb_t *pkt_base,		/* 0 or DNS pkt start to decompress */
	axa_walkb_t **pp,		/* pointer to current position */
	axa_walkb_t *pkt_lim,		/* end+1 of DNS pkt */
	bool question,			/* in the question section */
	axa_walks_t *s)			/* name of the section */
{
	uint type, class, rdlength;
	uint8_t oname[AXA_P_DOMAIN_LEN];
	size_t oname_len;
	axa_walk_rdata_t *rdata;

	/* Get the owner name that starts the Resource Record. */
	if (!get_domain(ctxt, ops, oname, sizeof(oname), &oname_len,
			pkt_base, pp, pkt_lim, s))
		return (false);

	type = unpack16(ctxt, ops, pp, pkt_lim, s);
	if (type >= BAD_UNPACK16)
		return (false);
	class = unpack16(ctxt, ops, pp, pkt_lim, s);
	if (class >= BAD_UNPACK16)
		return (false);

	/* QUESTION sections contain no rdata. */
	if (question) {
		if (ops->domain == NULL)
			return (true);
		return (ops->domain(ctxt, oname, oname_len,
				    AXA_WALK_DOM_QUESTION, -1, s));
	}

	if (!skip(4, ctxt, ops, pp, pkt_lim, s))    /* skip TTL */
		return (false);
	rdlength = unpack16(ctxt, ops, pp, pkt_lim, s);
	if (rdlength >= BAD_UNPACK16)
		return (false);
	if (*pp+rdlength > pkt_lim) {
		char tbuf[16];

		error(ctxt, ops, "DNS %s RR truncated by %d bytes", "in", s,
		      axa_rtype_to_str(tbuf, sizeof(tbuf), type),
		      (int)(*pp+rdlength - pkt_lim));
		return (false);
	}

	rdata = ops->rdata;
	if (rdata == NULL)
		rdata = axa_walk_rdata;
	if (!rdata(ctxt, ops, oname, oname_len,
		  pkt_base, pkt_lim, *pp, rdlength, type, s))
		return (false);

	*pp += rdlength;
	return (true);
}

static bool				/* false=stop parsing */
walk_section(void *ctxt, axa_walk_ops_t *ops,
	     axa_walkb_t *pkt_base,
	     axa_walkb_t **pp,
	     axa_walkb_t *pkt_lim,
	     uint num_rrs, bool question, axa_walks_t *s)
{
	uint n;

	if (question && num_rrs == 0) {
		error(ctxt, ops, "no RRs", "in", s);
		return (true);
	}
	for (n = 0; n <num_rrs; ++n) {
		if (*pp >= pkt_lim) {
			error(ctxt, ops, "%d instead of %d RRs", "in", s,
			      n, num_rrs);
			break;
		}
		if (!walk_rr(ctxt, ops, pkt_base, pp, pkt_lim, question, s))
			return (false);
	}
	return (true);
}

void
axa_walk_dns(void *ctxt, axa_walk_ops_t *ops,
	     axa_walkb_t *pkt_base, size_t pkt_len)
{
	axa_walkb_t *pkt, *pkt_lim;
	uint rcode, qdcount, ancount, nscount, arcount;

	pkt = pkt_base;
	pkt_lim = pkt_base + pkt_len;

	/* skip ID */
	if (!skip(2, ctxt, ops, &pkt, pkt_lim, "header"))
		return;

	rcode = unpack16(ctxt, ops, &pkt, pkt_lim, "header");
	if (rcode >= BAD_UNPACK16)
		return;
	/* do not try to parse FORMERRs */
	if ((rcode & 0xf)== ns_r_formerr)
		return;

	/* get numbers of RRs */
	qdcount = unpack16(ctxt, ops, &pkt, pkt_lim, "header");
	if (qdcount >= BAD_UNPACK16)
		return;
	ancount = unpack16(ctxt, ops, &pkt, pkt_lim, "header");
	if (ancount >= BAD_UNPACK16)
		return;
	nscount = unpack16(ctxt, ops, &pkt, pkt_lim, "header");
	if (nscount >= BAD_UNPACK16)
		return;
	arcount = unpack16(ctxt, ops, &pkt, pkt_lim, "header");
	if (arcount >= BAD_UNPACK16)
		return;

	/* filter the RRs in each section */
	if (!walk_section(ctxt, ops, pkt_base, &pkt, pkt_lim, qdcount,
			  true, "QUESTION section"))
		return;
	if (!walk_section(ctxt, ops, pkt_base, &pkt, pkt_lim, ancount,
			  false, "ANSWER section"))
		return;
	if (!walk_section(ctxt, ops, pkt_base, &pkt, pkt_lim, nscount,
			  false, "AUTHORITY section"))
		return;
	if (!walk_section(ctxt, ops, pkt_base, &pkt, pkt_lim, arcount,
			  false, "ADDITIONAL section"))
		return;
}

/*
 * Advanced Exchange Access (AXA) semanatics for DNS packets and fields
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

#ifndef AXA_DNS_WALK_H
#define AXA_DNS_WALK_H

/*! \file dns_walk.h
 *  \brief semantics for DNS packets and fields
 *
 *  This file contains DNS-related datatypes and function declarations.
 */

#include <axa/axa.h>

/** DNS objects */
typedef const uint8_t axa_walkb_t;
/** DNS section name */
typedef const char axa_walks_t;		

/** domain types */
typedef enum {
	AXA_WALK_DOM_UNK,		    /**< stray domain name */
	AXA_WALK_DOM_QUESTION,		/**< DNS question */
	AXA_WALK_DOM_OWNER,		    /**< rdata owner domain */
	AXA_WALK_DOM_RDATA1,		/**< 1st domain in rdata */
	AXA_WALK_DOM_RDATA2,		/**< 2nd domain in rdata */
} axa_walk_dom_t;

typedef const struct axa_walk_ops axa_walk_ops_t;

/**
 *  Notice an error
 *
 *  \param[in] ctxt
 *  \param[in] p
 *  \param[in] args
 */
typedef void (axa_walk_error_t)(void *ctxt, const char *p, va_list args);


/**
 *  Walk an IP
 *
 *  \param[in] ctxt
 *  \param[in] ip
 *  \param[in] ip_len
 *  \param[in] s
 *
 *  \retval true
 *  \retval false stop walking and parsing for all of the following
 */
typedef bool (axa_walk_ip_t)(void *ctxt,
			     const axa_walkb_t *ip, size_t ip_len,
			     axa_walks_t *s);

/**
 *  Walk a domain
 *
 *  \param[in] ctxt
 *  \param[in] name
 *  \param[in] name_len
 *  \param[in] dtype
 *  \param[in] rtype
 *  \param[in] s
 *
 *  \retval true
 *  \retval false stop walking and parsing for all of the following
 */
typedef bool (axa_walk_domain_t)(void *ctxt,
				 axa_walkb_t *name,
				 size_t name_len,
				 axa_walk_dom_t dtype,
				 uint rtype,	/* owned or containing rdata */
				 axa_walks_t *s);   /* section name */

/**
 *
 *  Come here with an owner name and its rdata.
 *  This function can be ops->rdata or called by ops->rdata.
 *
 *  \param[in] ctxt
 *  \param[in] ops
 *  \param[in] oname owner name (if known)
 *  \param[in] oname_len length of owner name
 *  \param[in] pkt_base NULL or DNS packet to decompress
 *  \param[in] rdata rdata to walk or parse
 *  \param[in] pkt_lim end + 1 of DNS packet
 *  \param[in] rtype
 *  \param[in] rdlength rdata length
 *  \param[in] s section name
 *
 *  \retval true
 *  \retval false stop parsing
 */
typedef bool (axa_walk_rdata_t)(void *ctxt,
				axa_walk_ops_t *ops,
				axa_walkb_t *oname, /* owner name if known */
				size_t oname_len,
				axa_walkb_t *pkt_base,
				axa_walkb_t *rdata,
				axa_walkb_t *pkt_lim,
				uint rtype,
				size_t rdlength,    /* rdata length */
				axa_walks_t *s);    /* section name */

/** AXA walk ops */
struct axa_walk_ops {
	axa_walk_error_t	*error;     /**< walk_error() */
	axa_walk_ip_t		*ip;        /**< walk_ip() */
	axa_walk_domain_t	*domain;    /**< walk_domain() */
	axa_walk_rdata_t	*rdata;     /**< walk_rdata() */
};

/** */
extern axa_walk_rdata_t axa_walk_rdata;
/** */
extern axa_walk_rdata_t axa_skip_rdata;

/**
 *
 *
 *  \param[in] ctxt
 *  \param[in] ops
 *  \param[in] pkt_base
 *  \param[in] pkt_len
 */
extern void axa_walk_dns(void *ctxt, axa_walk_ops_t *ops,
			 axa_walkb_t *pkt_base, size_t pkt_len);

#endif /* AXA_DNS_WALK_H */

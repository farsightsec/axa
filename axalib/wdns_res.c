/*
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


#include <axa/fields.h>

#include <wdns.h>

#include <string.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
#endif

/* This must be replaced by or supplemented with the
 * new function in the wdns library. */

/* Return a value that can be used as an arg to printf()
 * and set the buffer in case it is used. */
const char *
axa_wdns_res(unsigned int wres,
	     char *buf, size_t buf_len)	/* AXA_WDNS_RES_STRLEN */
{
	const char *str;

	switch (wres) {
	case wdns_res_success:
		str = "success";
		break;
	case wdns_res_failure:
		str = "failure";
		break;
	case wdns_res_invalid_compression_pointer:
		str = "invalid compression pointer";
		break;
	case wdns_res_invalid_length_octet:
		str = "invalid length octet";
		break;
	case wdns_res_invalid_opcode:
		str = "invalid opcode";
		break;
	case wdns_res_invalid_rcode:
		str = "invalid rcode";
		break;
	case wdns_res_len:
		str = "len";
		break;
	case wdns_res_malloc:
		str = "malloc";
		break;
	case wdns_res_name_len:
		str = "name len";
		break;
	case wdns_res_name_overflow:
		str = "name overflow";
		break;
	case wdns_res_out_of_bounds:
		str = "out of bounds";
		break;
	case wdns_res_overflow:
		str = "overflow";
		break;
	case wdns_res_parse_error:
		str = "parse error";
		break;
	case wdns_res_qdcount:
		str = "qdcount";
		break;
	case wdns_res_unknown_opcode:
		str = "unknown opcode";
		break;
	case wdns_res_unknown_rcode:
		str = "unknown rcode";
		break;
	default:
		snprintf(buf, buf_len, "wdns result #%d", wres);
		return (buf);
	}

	strlcpy(buf, str, buf_len);
	return (str);
}

/*
 * Parse "chN"
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

#include <axa/protocol.h>

#include <stdlib.h>
#include <string.h>

bool					/* false=bad */
axa_parse_ch(axa_emsg_t *emsg,
	     axa_p_ch_t *chp,		/* put channel number here */
	     const char *s, size_t s_len,
	     bool all_ok,		/* "all" is allowed */
	     bool number_ok)		/* recognize "202" as "ch202" */
{
	axa_p_ch_buf_t buf;
	u_long l;
	char *p;

	if (s_len == 0) {
		if (emsg != NULL)
			axa_pemsg(emsg, "invalid channel \"\"");
		return (false);
	} else if (s_len >= sizeof(buf)) {
		if (emsg != NULL)
			axa_pemsg(emsg, "invalid channel \"%.*s...\"",
				  (int)sizeof(buf), s);
		return (false);
	}

	memcpy(&buf, s, s_len);
	buf.c[s_len] = '\0';
	s = buf.c;

	if (all_ok && strcasecmp(s, AXA_OP_CH_ALLSTR) == 0) {
		if (chp != NULL)
			*chp = AXA_OP_CH_ALL;
		return (true);
	}

	if (AXA_CLITCMP(s, AXA_OP_CH_PREFIX)) {
		s += sizeof(AXA_OP_CH_PREFIX)-1;
	} else if (!number_ok) {
		if (emsg != NULL)
			axa_pemsg(emsg, "invalid channel \"%s\"", buf.c);
		return (false);
	}

	l = strtoul(s, &p, 10);
	if ((*p != '\0' && strspn(p, AXA_WHITESPACE) != strlen(p))
	    || l > AXA_OP_CH_MAX) {
		if (emsg != NULL)
			axa_pemsg(emsg, "invalid channel \"%s\"", buf.c);
		return (false);
	}

	if (chp != NULL)
		*chp = l;
	return (true);
}


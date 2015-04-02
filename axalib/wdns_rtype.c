/*
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


#include <axa/fields.h>

#include <wdns.h>

#include <string.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
#endif


/* This should be revisited when (and if) wdns_rrtype_to_str() changes. */

const char *
axa_rtype_to_str(char *buf, size_t buf_len, unsigned int rtype)
{
	const char *result;

	result = wdns_rrtype_to_str(rtype);
	if (result != NULL)
		strlcpy(buf, result, buf_len);
	else
		snprintf(buf, buf_len, "TYPE%d", rtype);
	return (buf);
}

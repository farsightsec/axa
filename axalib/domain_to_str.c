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

#include <axa/axa.h>

#include <wdns.h>

const char *
axa_domain_to_str(const uint8_t *src, size_t src_len,
		  char *dst)		/* must be at least NS_MAXDNAME */
{
	size_t len;

	len = wdns_domain_to_str(src, src_len, dst);

	/* trim trailing '.' except from root */
	if (len > 2)
		dst[len -2] = '\0';

	return (dst);
}

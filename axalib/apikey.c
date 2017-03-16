/*
 * apikey functions
 *
 *  Copyright (c) 2015-2017 by Farsight Security, Inc.
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

#include <config.h>
#include <axa/wire.h>
#ifdef __linux
#include <bsd/string.h>                 /* for strlcpy() */
#endif

/*
 * Parse apikey specification.
 */
bool
axa_apikey_parse(axa_emsg_t *emsg, char **addrp, axa_p_user_t *u, const char *spec)
{
	char *p, *spec_copy, *apikey_p;
	const char *at;

	at = strchr(spec, '@');

	if (at == NULL) {
		axa_pemsg(emsg, "\"apikey:%s\" has no server specification",
				spec);
		return (false);
	}
	if (at == spec) {
		axa_pemsg(emsg, "\"apikey:%s\" has no apikey", spec);
		return (false);
	}
	spec_copy = axa_strdup(spec);
	p = spec_copy;
	apikey_p = strsep(&p, "@");

	strlcpy(u->name, apikey_p, sizeof(u->name));

	*addrp = axa_strdup(at + 1);
	free(spec_copy);
	return (true);
}

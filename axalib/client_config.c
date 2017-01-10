/*
 * Advanced Exchange Access (AXA) parser for client config
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

#include <config.h>
#include <axa/client_config.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <regex.h>
#ifdef __linux
#include <bsd/string.h>                 /* for strlcpy() */
#endif

/* add an alias to the global alias array */
void _alias_add(char *alias, char *connect);
/* parse a config entry */
bool _config_entry_parse(const char *line0);
/* check an alias line */
bool _alias_check(const char *line0);

/* global client config data */
axa_client_config_t axa_client_config;

/* config entry regex */
/* The format of an entry is 'type:foo=bar' where type, foo, and bar are
 * 1-63 alphanumeric characters. */
const char *alias_re_s = "^[a-zA-Z0-9-]{1,63}:[a-zA-Z0-9-]{1,63}=[a-zA-Z0-9-]{1,63}";
regex_t alias_re;


void
axa_unload_client_config(void)
{
	axa_alias_t *p, *q;

	for (p = axa_client_config.aliases; p; p = q->next) {
		q = p;
		free(p);
	}

	axa_client_config.aliases = NULL;
	axa_client_config.aliases_tail = NULL;
}

void
_alias_add(char *alias, char *connect)
{
	if (axa_client_config.aliases == NULL) {
		axa_client_config.aliases = AXA_SALLOC(axa_alias_t);
		strlcpy(axa_client_config.aliases->a, alias,
				sizeof(axa_client_config.aliases->a));
		strlcpy(axa_client_config.aliases->c, connect,
				sizeof(axa_client_config.aliases->c));
		axa_client_config.aliases->next = NULL;
		axa_client_config.aliases_tail =
			axa_client_config.aliases;
	}
	else {
		axa_client_config.aliases_tail->next = AXA_SALLOC(axa_alias_t);
		strlcpy(axa_client_config.aliases_tail->next->a, alias,
				sizeof(axa_client_config.aliases->next->a));
		strlcpy(axa_client_config.aliases_tail->next->c, connect,
				sizeof(axa_client_config.aliases->next->c));
		axa_client_config.aliases_tail->next->next = NULL;
		axa_client_config.aliases_tail =
			axa_client_config.aliases_tail->next;
	}
}

/* check alias line against regex and add to global alias array */
bool
_config_entry_parse(const char *line0)
{
	char *p, *line, *type_str, *alias_str;

	if (regexec(&alias_re, line0, 0, NULL, 0) != 0) {
		return (false);
	}

	line = axa_strdup(line0);
	p = line;
	type_str = strsep(&p, ":");
	if (strncmp(type_str, "alias", 5) == 0) {
		alias_str = strsep(&p, "=");

		_alias_add(alias_str, p);
	}
	/* ... */
	free(line);

	return (true);
}

/*
 * Read AXA client config file.
 */
void
axa_load_client_config(const char *config_file0)
{
	FILE *f;
	char *line_buf, *p, *config_file;
	uint line_num;
	size_t line_buf_size;
	const char *line0;

	axa_unload_client_config();

	/*
	 * Use a specified file, or default to $HOME/.axa/config,
	 */
	if (config_file0 != NULL && *config_file0 != '\0') {
		config_file = axa_strdup(config_file0);
		f = fopen(config_file, "r");
	} else {
		f = NULL;
		p = getenv("HOME");
		if (p == NULL) {
			config_file = NULL;
		} else {
			axa_asprintf(&config_file, "%s/.axa/%s", p, "config");
			f = fopen(config_file, "r");
		}
	}
	if (f == NULL) {
		axa_error_msg("cannot open \"%s\": %s",
			      config_file, strerror(errno));
		free(config_file);
		return;
	}

	/* alias section */
	if (regcomp(&alias_re, alias_re_s, REG_EXTENDED | REG_NOSUB) != 0) {
		axa_error_msg("invalid alias regex \"%s\"", alias_re_s);
		goto done;
	}

	line_buf = NULL;
	line_buf_size = 0;
	line_num = 0;
	/* Parse config file, line by line. A parsing error will throw an
	 * error message and control will continue to the next line. */
	for (;;) {
		line0 = axa_fgetln(f, config_file, &line_num, &line_buf,
				&line_buf_size);
		if (line0 == NULL) {
			/* no more entries, all done */
			break;
		}

		if (_config_entry_parse(line0) == false) {
			axa_error_msg("invalid \"%s\" in line %d of"
					"\"%s\"", line0, line_num,
					config_file);
			continue;
		}
	}
done:
	regfree(&alias_re);
	free(config_file);
	fclose(f);
}

const char *
axa_client_config_alias_chk(const char *alias)
{
	axa_alias_t *p;
	char *ret;

	ret = NULL;
	for (p = axa_client_config.aliases; p; p = p->next) {
		if (strncmp(p->a, alias, sizeof(p->a)) == 0) {
			ret = p->c;
		}
	}

	return (ret);
}

void
axa_client_config_alias_print()
{
	axa_alias_t *p;

	for (p = axa_client_config.aliases; p; p = p->next) {
		printf("%s\t-->\t%s\n", p->a, p->c);
	}
}

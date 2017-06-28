/*
 * Advanced Exchange Access (AXA) client config parsing
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

#ifndef AXA_CLIENT_CONFIG_H
#define AXA_CLIENT_CONFIG_H

/**
 *  \defgroup axa_client_config axa_client_config
 *
 *
 * @{
 */

#include <axa/protocol.h>
#include <axa/axa.h>

#define AXA_ALIAS_STRLEN	64
#define AXA_CONNECT_STRLEN	1024
/* connection alias */
struct axa_alias {
	char a[AXA_ALIAS_STRLEN];	/* alias "shortcut" string */
	char c[AXA_CONNECT_STRLEN];	/* server connection string */
	struct axa_alias *next;		/* next alias */
};
typedef struct axa_alias axa_alias_t;

/* Holds client-side configuration data */
typedef struct {
	axa_alias_t *aliases;		/* connection alias chain */
	axa_alias_t *aliases_tail;	/* end of list */
} axa_client_config_t;

/**
 *  Unload client config and free all associated memory.
 */
void axa_unload_client_config(void);

/**
 *  Load client config.
 *
 *  \param[out] emsg error message if something went wrong
 *  \param[in] config_file0 canonical name of config file
 *
 *  \retval true if file was successfully opened and parsed
 *  \retval false if there was an error, emsg will contain the reason
 */
bool axa_load_client_config(axa_emsg_t *emsg, const char *config_file0);

/**
 *  Check for a connection alias.
 *
 *  \param[in] alias name of alias to look for in connection alias list
 *
 *  \return if alias exists a pointer to a fully qualified server connection
    string or NULL if it does not
 */
const char *axa_client_config_alias_chk(const char *alias);

/**
 *  Print alias list to stdout.
 */
void axa_client_config_alias_print(void);

#endif /* AXA_CLIENT_CONFIG_H */

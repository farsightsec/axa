/*
 * Advanced Exchange Access (AXA) protocol definitions
 *
 *  Copyright (c) 2014-2016 by Farsight Security, Inc.
 *
 * This file is used outside the AXA programs.
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

#ifndef AXA_JSON_H
#define AXA_JSON_H

/**
 * \defgroup axa_json axa_json
 *
 * `axa_json` contains the AXA protocol JSON serialization.
 *
 * This module generates JSON-formatted strings for any
 * AXA protocol message.
 *
 */

#include <stddef.h>

#include <axa/protocol.h>
#include <nmsg.h>

typedef enum {
	AXA_JSON_RES_SUCCESS,
	AXA_JSON_RES_FAILURE,
	AXA_JSON_RES_MEMFAIL,
	AXA_JSON_RES_NOTIMPL
} axa_json_res_t;

/**
 * Convert a protocol body to JSON.
 *
 * \param[out] emsg if something goes wrong, this will contain the reason
 * \param[in] nmsg_input a nmsg null_input that is used to deserialize watch hits
 * \param[in] hdr axa protocol header structure
 * \param[in] body axa protocol body structure
 * \param[in] body_len number of bytes in body
 * \param[out] out handle to char* that is assigned on success.  must be freed by caller
 */
axa_json_res_t
axa_body_to_json(axa_emsg_t *, nmsg_input_t nmsg_input, axa_p_hdr_t *hdr, axa_p_body_t *body, size_t body_len, char **out);

#endif /* AXA_JSON_H */

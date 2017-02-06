/*
 * Copyright (c) 2009-2017 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef AXA_STRBUF_H
#define AXA_STRBUF_H

#include <stddef.h>

/*! \file axa/strbuf.h
 * \brief String buffers
 *
 * Dynamically sized strings that may be appended to or reset.
 */

/** String buffer. */
struct axa_strbuf {
	char	*pos;	/*%< end of string */
	char	*data;	/*%< buffer for string data */
	size_t	bufsz;	/*%< size of data allocation */
};

typedef enum {
	AXA_STRBUF_SUCCESS,
	AXA_STRBUF_FAILURE,
	AXA_STRBUF_MEMFAIL
} axa_strbuf_res_t;

/**
 * Initialize a string buffer.
 *
 * \return Initialized string buffer, or NULL on memory allocation failure.
 */
struct axa_strbuf *axa_strbuf_init(void);

/**
 * Destroy all resources associated with a string buffer.
 *
 * \param[in] sb pointer to string buffer.
 */
void axa_strbuf_destroy(struct axa_strbuf **sb);

/**
 * Append to a string buffer.
 *
 * \param[in] sb string buffer.
 *
 * \param[in] fmt format string to be passed to vsnprintf.
 *
 * \param[in] ... arguments to vsnprintf.
 *
 * \return #axa_strbuf_res_t_success
 * \return #axa_strbuf_res_t_memfail
 * \return #axa_strbuf_res_t_failure
 */
axa_strbuf_res_t axa_strbuf_append(struct axa_strbuf *sb, const char *fmt, ...);

/**
 * Reset a string buffer.
 *
 * Resets the size of the internal buffer to the default size, but does not
 * clear the contents of the buffer.
 *
 * \param[in] sb string buffer.
 *
 * \return #axa_strbuf_res_t_success
 * \return #axa_strbuf_res_t_memfail
 */
axa_strbuf_res_t axa_strbuf_reset(struct axa_strbuf *sb);

/**
 * Find the length of the used portion of the string buffer.
 *
 * \param[in] sb string buffer.
 *
 * \return Number of bytes consumed by the string.
 */
size_t axa_strbuf_len(struct axa_strbuf *sb);

/**
 * Clip the string buffer.  If n_elems is greater than len(sb) this
 * is a noop.
 *
 * \param[in] sb string buffer.
 * \param[in] n_elems the new size of the string
 */
void axa_strbuf_clip(struct axa_strbuf *sb, size_t n_elems);

#endif /* AXA_STRBUF_H */

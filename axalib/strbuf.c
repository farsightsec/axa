/*
 * Copyright (c) 2009, 2012 by Farsight Security, Inc.
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

/* Import. */

#include <axa/axa.h>
#include <axa/strbuf.h>

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

/* Macros. */

#define DEFAULT_STRBUF_ALLOC_SZ		1024

/* Export. */

struct axa_strbuf *
axa_strbuf_init(void) {
	struct axa_strbuf *sb;

	sb = calloc(1, sizeof(*sb));

	return (sb);
}

void
axa_strbuf_destroy(struct axa_strbuf **sb) {
	free((*sb)->data);
	free(*sb);
	*sb = NULL;
}

axa_strbuf_res_t
axa_strbuf_append(struct axa_strbuf *sb, const char *fmt, ...) {
	ssize_t avail, needed;
	int status;
	va_list args, args_copy;
	void *ptr;

	/* allocate a data buffer if necessary */
	if (sb->data == NULL) {
		sb->pos = sb->data = malloc(DEFAULT_STRBUF_ALLOC_SZ);
		if (sb->data == NULL)
			return (AXA_STRBUF_MEMFAIL);
		sb->bufsz = DEFAULT_STRBUF_ALLOC_SZ;
	}

	/* determine how many bytes are needed */
	va_start(args, fmt);
	va_copy(args_copy, args);
	needed = vsnprintf(NULL, 0, fmt, args_copy) + 1;
	va_end(args_copy);
	if (needed < 0) {
		free(sb->data);
		sb->pos = sb->data = NULL;
		sb->bufsz = 0;
		return (AXA_STRBUF_FAILURE);
	}

	/* determine how many bytes of buffer space are available */
	avail = sb->bufsz - (sb->pos - sb->data);
	AXA_ASSERT(avail >= 0);

	/* increase buffer size if necessary */
	if (needed > avail) {
		size_t offset;
		ssize_t new_bufsz = 2 * sb->bufsz;

		offset = sb->pos - sb->data;

		while (new_bufsz - (ssize_t) sb->bufsz < needed)
			new_bufsz *= 2;
		AXA_ASSERT(sb->bufsz > 0);
		ptr = realloc(sb->data, new_bufsz);
		if (ptr == NULL) {
			free(sb->data);
			sb->pos = sb->data = NULL;
			sb->bufsz = 0;
			return (AXA_STRBUF_MEMFAIL);
		}
		sb->data = ptr;
		sb->pos = sb->data + offset;
		sb->bufsz = new_bufsz;
	}

	/* print to the end of the strbuf */
	status = vsnprintf(sb->pos, needed + 1, fmt, args);
	if (status >= 0)
		sb->pos += status;
	else {
		free(sb->data);
		sb->pos = sb->data = NULL;
		sb->bufsz = 0;
		return (AXA_STRBUF_FAILURE);
	}

	return (AXA_STRBUF_SUCCESS);
}

size_t
axa_strbuf_len(struct axa_strbuf *sb) {
	AXA_ASSERT(sb->pos >= sb->data);
	AXA_ASSERT(sb->pos - sb->data <= (ssize_t) sb->bufsz);
	return (sb->pos - sb->data);
}

void
axa_strbuf_clip(struct axa_strbuf *sb, size_t n_elems)
{
	if (n_elems < axa_strbuf_len(sb)) {
		sb->pos = &(sb->data[n_elems]);
		*(sb->pos) = 0;
	}
}

axa_strbuf_res_t
axa_strbuf_reset(struct axa_strbuf *sb) {
	void *ptr;
	
	ptr = realloc(sb->data, DEFAULT_STRBUF_ALLOC_SZ);
	if (ptr == NULL) {
		free(sb->data);
		sb->pos = sb->data = NULL;
		sb->bufsz = 0;
		return (AXA_STRBUF_MEMFAIL);
	}
	sb->pos = sb->data = ptr;
	sb->bufsz = DEFAULT_STRBUF_ALLOC_SZ;

	return (AXA_STRBUF_SUCCESS);
}

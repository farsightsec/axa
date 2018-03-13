/*
 * Advanced Exchange Access (AXA) yajl shortcut macros
 *
 *  Copyright (c) 2018 by Farsight Security, Inc.
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

#ifndef AXA_YAJL_SHORTCUTS_H
#define AXA_YAJL_SHORTCUTS_H

#define add_yajl_map(g) do {                                            \
	yajl_gen_status g_status;                                       \
	g_status = yajl_gen_map_open(g);                                \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                     \
} while (0)

#define close_yajl_map(g) do {                                          \
	yajl_gen_status g_status;                                       \
	g_status = yajl_gen_map_close(g);                             	\
	AXA_ASSERT(g_status == yajl_gen_status_ok);                   	\
} while (0)

#define add_yajl_array(g) do {                                          \
	yajl_gen_status g_status;                                       \
	g_status = yajl_gen_array_open(g);                              \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                     \
} while (0)

#define close_yajl_array(g) do {                                        \
	yajl_gen_status g_status;                                       \
	g_status = yajl_gen_array_close(g);                             \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                     \
} while (0)

#define add_yajl_null(g) do {                                           \
	yajl_gen_status g_status;                                       \
	g_status = yajl_gen_null(g);                                    \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                 	\
} while (0)

#define add_yajl_bool(g, b) do {                                        \
	yajl_gen_status g_status;                                       \
	g_status = yajl_gen_bool(g, b);                                 \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                     \
} while (0)

#define add_yajl_string_len(g, s, l) do {                               \
	yajl_gen_status g_status;                                       \
	g_status = yajl_gen_string(g, (const unsigned  char *) s, l);   \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                    	\
} while (0)

#define add_yajl_string(g, s) add_yajl_string_len((g), (s), strlen((s)))

#define add_yajl_integer(g, i) do {                                 	\
	yajl_gen_status g_status;                                       \
	g_status = yajl_gen_integer(g, i);                              \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                     \
} while (0)

#define add_yajl_number_sb(g, sb) do {                                  \
	yajl_gen_status g_status;                                       \
	g_status = yajl_gen_number(g, (const char *)sb->data,		\
			strlen(sb->data));				\
	AXA_ASSERT (g_status == yajl_gen_status_ok);                    \
} while (0)

#define add_yajl_number(g, sb, i) do {                                  \
	yajl_gen_status g_status;                                       \
	axa_strbuf_reset(sb);                                           \
	axa_strbuf_append(sb, "%" PRIu64, (i));                         \
	g_status = yajl_gen_number(g, (const char *)sb->data,		\
			strlen(sb->data)); 				\
	AXA_ASSERT (g_status == yajl_gen_status_ok);                    \
} while (0)

#endif /* AXA_YAJL_SHORTCUTS_H */

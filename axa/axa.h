/*
 * general Advanced Exchange Access (AXA) definitions
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

#ifndef AXA_AXA_H
#define AXA_AXA_H

#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#ifdef __linux
#include <bsd/libutil.h>
#else					/* FreeBSD */
#include <sys/param.h>
#include <libutil.h>
#endif


#define AXA_DIM(_a)    ((int)((sizeof(_a) / sizeof((_a)[0]))))
#define AXA_LAST(_a)    (&(_a)[AXA_DIM(_a)-1])

#define AXA_OFFSET(_p,_s,_t)  ((uint8_t *)(_p)				\
			       + ((uint8_t *)&((_s *)0)->_t  - (uint8_t *)0))

/* ctype() is now a slow mess that does not give constant results on all
 * systems */
#define AXA_IS_WHITE(c) ({char _c = (c); _c == ' ' || _c == '\t'	\
				      || _c == '\r' || _c == '\n';})
#define AXA_WHITESPACE	" \t\n\r"
#define AXA_IS_UPPER(c) ({char _c = (c); _c >= 'A' && _c <= 'Z';})
#define AXA_IS_LOWER(c) ({char _c = (c); _c >= 'a' && _c <= 'z';})
#define AXA_IS_DIGIT(c) ({char _c = (c); _c >= '0' && _c <= '9';})
#define AXA_TO_LOWER(c) ({char _l = (c); AXA_IS_UPPER(_l) ? (_l+'a'-'A') : _l;})
#define AXA_TO_UPPER(c) ({char _u = (c); AXA_IS_LOWER(_u) ? (_u-'a'-'A') : _u;})

#define AXA_UNUSED	__attribute__((unused))
#define AXA_PF(f,l)	__attribute__((format(printf,f,l)))
#define	AXA_NORETURN    __attribute__((__noreturn__))


#undef min
#define min(a,b) ({int _a = (a), _b = (b); _a < _b ? _a : _b; })
#undef max
#define max(a,b) ({int _a = (a), _b = (b); _a > _b ? _a : _b; })

/* for declarations where ({}) is not allowed and side effects can't happen */
#define dcl_max(a,b) ((a) >= (b) ? (a) : (b))


#define AXA_CLITCMP(b,_s)  (strncasecmp((b), (_s), sizeof(_s)-1) == 0)

typedef int32_t		axa_ref_cnt_t;
#define AXA_INC_REF(c)	AXA_ASSERT(++(c) > 0)
#define AXA_DEC_REF(c)	AXA_ASSERT(--(c) >= 0)


/* domain_to_str.c */
extern const char *axa_domain_to_str(const uint8_t *src, size_t src_len,
				     char *dst);    /* at least NS_MAXDNAME */

/* emsg.c */
extern void *axa_zalloc(size_t s);
extern char *axa_strdup(const char *s);
extern void axa_asprintf(char **bufp, const char *p, ...) AXA_PF(2,3);
extern void axa_set_core(void);
typedef struct axa_emsg {
	char	c[120];
} axa_emsg_t;
extern uint axa_debug;
#define AXA_DEBUG_TRACE	    3		/* show trace messages */
#define AXA_DEBUG_NMSG	    4
#define AXA_DEBUG_MAX	    10
#define AXA_DEBUG_TO_NMSG() nmsg_set_debug(axa_debug <= AXA_DEBUG_NMSG	\
					   ? 0 :axa_debug - AXA_DEBUG_NMSG)
extern void axa_set_me(const char *me);
extern bool axa_parse_log_opt(const char *arg);
extern void axa_syslog_init(void);
extern bool axa_buf_print(char **bufp, size_t *buf_lenp, bool ellipsis,
			  const char *p, ...) AXA_PF(4,5);
extern void axa_clean_stdio(void);
extern void axa_vpemsg(axa_emsg_t *emsg, const char *msg, va_list args);
extern void axa_pemsg(axa_emsg_t *emsg, const char *msg, ...) AXA_PF(2,3);
extern void axa_verror_msg(const char *p, va_list args);
extern void axa_error_msg(const char *p, ...) AXA_PF(1,2);
extern void axa_io_error(const char *op, const char *src, ssize_t len);
extern void axa_vtrace_msg(const char *p, va_list args);
extern void axa_trace_msg(const char *p, ...) AXA_PF(1,2);
extern void axa_vfatal_msg(int ex_code, const char *p, va_list) AXA_NORETURN;
extern void axa_fatal_msg(int ex_code,
			  const char *p, ...) AXA_PF(2,3) AXA_NORETURN;
extern void axa_accounting_rcd(const char *p, ...) AXA_PF(1,2);
extern void axa_pidfile(const char *rundir, const char *pidfile);
extern char axa_prog_name[];
extern struct pidfh *axa_pidfh;

extern char *axa_fgetln(FILE *f, const char *file_name, uint *line_num,
			char **bufp, size_t *buf_sizep);
extern const char *axa_strip_white(const char *str, size_t *lenp);
extern ssize_t axa_get_token(char *token, size_t token_len,
			     const char **stringp, const char *seps);

#define AXA_ASSERT_MSG(c,...) ((c) ? 0 : axa_fatal_msg(0, __VA_ARGS__))
#define AXA_ASSERT(c) AXA_ASSERT_MSG((c), "\""#c"\" is false")
#define AXA_FAIL(...) axa_fatal_msg(0, __VA_ARGS__)


/* hash_divisor.c */
extern uint32_t axa_hash_divisor(uint32_t initial, bool smaller);

/* parse_ch.c */
extern bool axa_parse_ch(axa_emsg_t *emsg, uint16_t *chp,
			 const char *str, size_t str_len,
			 bool all_ok, bool number_ok);

/* time.c */
extern time_t axa_tv_diff2ms(const struct timeval *tv1,
			     const struct timeval *tv2);
extern time_t axa_elapsed_ms(const struct timeval *now, struct timeval *then);



#endif /* AXA_AXA_H */

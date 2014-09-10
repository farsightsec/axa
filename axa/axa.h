/** General Advanced Exchange Access (AXA) definitions
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

#include <inttypes.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>


/**
 *  Return the number of elements in an array
 *  \param[in] _a the array to size up
 *
 *  \return the size of the array an int instead of size_t
 */
#define AXA_DIM(_a)    ((int)((sizeof(_a) / sizeof((_a)[0]))))
/**
 *  Return a pointer to the last item of an array
 *  \param[in] _a the array containing the item
 *
 *  \return a pointer to the last item
 */
#define AXA_LAST(_a)    (&(_a)[AXA_DIM(_a)-1])

#define AXA_OFFSET(_p,_s,_t)  ((uint8_t *)(_p)				\
			       + ((uint8_t *)&((_s *)0)->_t  - (uint8_t *)0))

/*
 * Ignore locales to get consistent results on all systems,
 * and because the AXA control files are ASCII.
 */
#define AXA_IS_WHITE(c) ({char _c = (c); _c == ' ' || _c == '\t'	\
				      || _c == '\r' || _c == '\n';})
#define AXA_WHITESPACE	" \t\n\r"
#define AXA_IS_UPPER(c) ({char _c = (c); _c >= 'A' && _c <= 'Z';})
#define AXA_IS_LOWER(c) ({char _c = (c); _c >= 'a' && _c <= 'z';})
#define AXA_IS_DIGIT(c) ({char _c = (c); _c >= '0' && _c <= '9';})
#define AXA_TO_LOWER(c) ({char _l = (c); AXA_IS_UPPER(_l) ? (_l+'a'-'A') : _l;})
#define AXA_TO_UPPER(c) ({char _u = (c); AXA_IS_LOWER(_u) ? (_u-'a'-'A') : _u;})

/* Tell the compiler not to complain about an unused parameter. */
#define AXA_UNUSED	__attribute__((unused))

/*
 * Tell the compiler to check an actual format string against the
 * the other actual parameters.
 * f: the number of the "format string" parameter
 * l: the number of the first variadic parameter
 */
#define AXA_PF(f,l)	__attribute__((format(printf,f,l)))

/* Tell the compiler that this function will never return  */
#define	AXA_NORETURN    __attribute__((__noreturn__))


#undef min
#define min(a,b) ({typeof(a) _a = (a); typeof(b)_b = (b); _a < _b ? _a : _b; })
#undef max
#define max(a,b) ({typeof(a) _a = (a); typeof(b) _b = (b); _a > _b ? _a : _b; })

/* for declarations where ({}) is not allowed and side effects can't happen */
#define dcl_max(a,b) ((a) >= (b) ? (a) : (b))

/**
 *  Case compare two NULL terminated strings, comparing at most sizeof(_s - 1)
 *  characters.
 *  \param[in] _b const char * first, not necessarily null terminated string
 *	to compare
 *  \param[in] _s const char * null terminated second string to compare
 *
 *  \return same semantics as strncasecmp()
 */
#define AXA_CLITCMP(_b,_s)  (strncasecmp((_b), (_s), sizeof(_s)-1) == 0)

typedef int32_t		axa_ref_cnt_t;
#define AXA_INC_REF(c)	AXA_ASSERT(__sync_add_and_fetch(&(c), 1) > 0)
#define AXA_DEC_REF(c)	AXA_ASSERT(__sync_sub_and_fetch(&(c), 1) >= 0)

/* domain_to_str.c */
/**
 *  Convert a domain name to a canonical string. Sane wrapper for
 *  wdns_domain_to_str(). dst_len must be >=NS_MAXDNAME because
 *  wdns_domain_to_str() does not check.
 *  \param[in] src domain name in wire format
 *  \param[in] src_len length of domain name in bytes
 *  \param[out] dst caller-alloc'd string buffer, should be of size NS_MAXDNAME
 *  \param[in] dst_len size of the dst buffer
 *
 *  \return the value of dst
 */
extern const char *axa_domain_to_str(const uint8_t *src, size_t src_len,
				     char *dst, size_t dst_len);

/* emsg.c */
/**
 *  A calloc() wrapper that crashes immediately (via AXA_ASSERT) on malloc
 *  failures. The memory region will be zero-filled.
 *  \param[in] s size of memory to allocate
 *
 *  \return pointer to the allocated memory
 */
extern void *axa_zalloc(size_t s);
#define AXA_SALLOC(t) ((t *)axa_zalloc(sizeof(t)))

/**
 *  A strdup() wrapper that crashes immediately (via AXA_ASSERT) on a strdup()
 *  failure (which should be ENOMEM). You should free the memory referenced by
 *  the string this function returns.
 *  \param[in] s the string to duplicate
 *
 *  \return pointer to the duplicated string
 */
extern char *axa_strdup(const char *s);

/**
 *  A vasprintf() wrapper that crashes immediately (via AXA_ASSERT) on
 *  vasprintf failures. When you're done with it, bufp should be subsequently
 *  freed.
 *  \param[out] bufp a pointer to the newly minted and formated string
 *  \param[in] p the format string
 *  \param[in] args a var args list
 */
extern void axa_vasprintf(char **bufp, const char *p, va_list args);

/**
 *  An asprintf() wrapper that crashes immediately (via AXA_ASSERT) on
 *  asprintf failures. When you're done with it, bufp should be subsequently
 *  freed.
 *  \param[out] bufp a pointer to the newly minted and formated string
 *  \param[in] p the format string
 *  \param[in] ... a var args list
 */
extern void axa_asprintf(char **bufp, const char *p, ...) AXA_PF(2,3);

/**
 *  Try to enable core files. Wraps getrlimit() and setrlimit().
 */
extern void axa_set_core(void);


typedef struct axa_emsg {
	char	c[120];
} axa_emsg_t;
extern uint axa_debug;
#define axa_debug_
#define AXA_DEBUG_WATCH	2		/* watches, anomalies, & channels */
#define AXA_DEBUG_TRACE	3		/* SRA messages */
#define AXA_DEBUG_NMSG	4
#define AXA_DEBUG_TO_NMSG() nmsg_set_debug(axa_debug <= AXA_DEBUG_NMSG	\
					   ? 0 : axa_debug - AXA_DEBUG_NMSG)
#define AXA_DEBUG_MAX	10

/**
 *  Set the global program name, the syslog logging stuff needs this to be
 *  called first.
 *  \param[in] me (argv[0])
 */
extern void axa_set_me(const char *me);

extern char axa_prog_name[];

/**
 *  Parse log options string
 *  \param[in] arg CSV string with the following options:
 *      {trace|error|acct},{off|FACILITY.LEVEL}[,{none,stderr,stdout}]
 *
 *  \return true if string groks, false if not
 */
extern bool axa_parse_log_opt(const char *arg);

/**
 *  Initialize the axa syslog interface
 */
extern void axa_syslog_init(void);

/**
 *  Add text to an error or other message buffer.
 *  If we run out of room, add "...".
 *  \param[in, out] bufp in: the orignal string, out: the concatenated strings
 *  \param[in, out] bufp_len in: the length of bufp string, out: new length
 *  \param[in] p the format string to copy over
 *  \param[in] ... va_args business
 */
extern void axa_buf_print(char **bufp, size_t *buf_lenp,
			  const char *p, ...) AXA_PF(3,4);

/**
 *  Prevent surprises from uses of stdio FDs by ensuring that the FDs are open.
 */
extern void axa_clean_stdio(void);

/**
 *  Generate an erorr message string in a buffer, if we have a buffer.
 *  Log or print the message if there is no buffer
 *  \param[out] emsg the error message buffer -- error message will end up here
 *  \param[in] msg message
 *  \param[in] args arguments to p
 */
extern void axa_vpemsg(axa_emsg_t *emsg, const char *msg, va_list args);

/**
 *  axa_vpemsg() wrapper using the variadic stdarg macros (va_start(),
 *  va_end()).
 *  \param[out] emsg the error message buffer -- error message will end up here
 *  \param[in] msg message
 *  \param[in] ... variable length argument list
 */
extern void axa_pemsg(axa_emsg_t *emsg, const char *msg, ...) AXA_PF(2,3);
typedef enum {
	AXA_SYSLOG_TRACE=0,
	AXA_SYSLOG_ERROR=1,
	AXA_SYSLOG_ACCT=2
} axa_syslog_type_t;

/**
 *  Log an axa message. Depending on type, this function could write to stdout
 *  stderr, and/or to syslog.
 *  \param[in] type one of #axa_syslog_type_t
 *  \param[in] fatal if true and fatal verbiage will be prepended to message
 *  \param[in] p message
 *  \param[in] args variadic argument list
 */
extern void axa_vlog_msg(axa_syslog_type_t type, bool fatal,
			 const char *p, va_list args);

/**
 *  Log an error message.  This is a wrapper for axa_vlog_msg with
 *	type of AXA_SYSLOG_ERROR with fatal == false.
 *  \param[in] p message
 *  \param[in] args variadic argument list
 */
extern void axa_verror_msg(const char *p, va_list args);

/**
 *  Log an error message and crash.  This is a variadic wrapper for
 *	axa_vlog_msg with type of AXA_SYSLOG_ERROR with fatal == false.
 *  \param[in] p message
 *  \param[in] ... variable length argument list
 */
extern void axa_error_msg(const char *p, ...) AXA_PF(1,2);

/**
 *  Log an error message for an I/O function that has returned either
 *	a negative read or write length or the wrong length..  Complain
 *	about a non-negative length or decode errno for a negative length.
 *  \param[in] p message
 *  \param[in] ... variable length argument list
 */
extern void axa_io_error(const char *op, const char *src, ssize_t len);

/**
 *  Log a trace message in the tracing syslog stream as opposed to the
 *	error syslog stream.
 *  \param[in] p message
 *  \param[in] args variadic argument list
 */
extern void axa_vtrace_msg(const char *p, va_list args);

/**
 *  Log a trace message in the tracing syslog stream as opposed to the
 *	error syslog stream.
 *  \param[in] p message
 *  \param[in] ... variable length argument list
 */
extern void axa_trace_msg(const char *p, ...) AXA_PF(1,2);

/**
 *  Log a serious error message and either exit with a specified exit code
 *	or crash if the exit code is EX_SOFTWARE.
 *  \param[in] ex_code exit code
 *  \param[in] p message
 *  \param[in] args variadic argument list
 */
extern void axa_vfatal_msg(int ex_code, const char *p, va_list) AXA_NORETURN;

/**
 *  Log a serious error message and either exit with a specified exit code
 *	or crash if the exit code is EX_SOFTWARE.
 *  \param[in] ex_code exit code
 *  \param[in] p our last words
 *  \param[in] ... va_args business
 */
extern void axa_fatal_msg(int ex_code,
			  const char *p, ...) AXA_PF(2,3) AXA_NORETURN;

/**
 *  Get a logical line from a stdio stream, with leading and trailing
 *  whitespace trimmed and "\\\n" deleted as a continuation.
 *  If the buffer is NULL or it is not big enough, it is freed and a new
 *  buffer is allocated. This must be freed after the last use of this
 *  function.
 *
 *  Except at error or EOF, the start of the next line is returned,
 *  which might not be at the start of the buffer.
 *  \param[in] f the file to read from (for error reporting)
 *  \param[in] file_name name of the file (for error reporting)
 *  \param[in,out] line_num line number of file, will be progressively updated
 *  \param[in,out] bufp buffer to store line, can be NULL
 *  \param[in,out] bufp_size
 *
 *  \return The return value is NULL and emsg->c[0]=='\0' at EOF or NULL and
 *  emsg->c[0]!='\0' after an error.
 */
extern char *axa_fgetln(FILE *f, const char *file_name, uint *line_num,
			char **bufp, size_t *buf_sizep);

/**
 *  Strip leading and trailing white space.
 *  \param[in,out] str in: string to cleanse, out: cleansed string
 *  \param[in,out] lenp in: length of the string, out: new length
 *
 *  \return the string cleansed of whitespace
 */
extern const char *axa_strip_white(const char *str, size_t *lenp);

/**
 *  Copy the next token from a string to a buffer and return the
 *  size of the string put into the buffer.
 *  Honor quotes and backslash.
 *  The caller must skip leading token separators (e.g. blanks) if necessary.
 *  When the separators include whitespace and whitespace ends the token,
 *  then all trailing whitespace is skipped
 *  \param[in,out] token token goes here
 *  \param[in,out] token_len length of the token
 *  \param[in,out] stringp input string
 *  \param[in,out] seps string of token separators
 *
 *  \return the size of the string, -1 on error
 */
extern ssize_t axa_get_token(char *token, size_t token_len,
			     const char **stringp, const char *seps);

#define AXA_ASSERT_MSG(c,...) ((c) ? 0 : axa_fatal_msg(0, __VA_ARGS__))
#define AXA_ASSERT(c) AXA_ASSERT_MSG((c), "\""#c"\" is false")
#define AXA_FAIL(...) axa_fatal_msg(0, __VA_ARGS__)


/* hash_divisor.c */
/**
 *  Get a modulus for a hash function that is tolerably likely to be
 *  relatively prime to most inputs.  We get a prime for initial values
 *  not larger than the square of the last prime.  We often get a prime
 *  after that.
 *  This works well in practice for hash tables up to at least 100
 *  times the square of the last prime and better than a multiplicative hash.
 *  \param[in] initial is the starting point for searching for number with no
 *  small divisors. That is usually the previous size of an expanding hashtable
 *  or the initial guess for a new hash table.
 *  \param[in] smaller false if  you want a prime larger than the initial
 *  value but somet.
 *
 *  \return the modulus
 */
extern uint32_t axa_hash_divisor(uint32_t initial, bool smaller);

/* parse_ch.c */
extern bool axa_parse_ch(axa_emsg_t *emsg, uint16_t *chp,
			 const char *str, size_t str_len,
			 bool all_ok, bool number_ok);

/* time.c */
/**
 *  Compute (tv1 - tv2) in milliseconds, but clamped to FOREVER_SECS.
 *  \param[in] tv1 const struct timeval * to first time value
 *  \param[in] tv2 const struct timeval * to second time value
 *  \return the difference between the two tv_sec values, in ms
 */
extern time_t axa_tv_diff2ms(const struct timeval *tv1,
			     const struct timeval *tv2);

/**
 *  Compute elapsed time between two timevals, in milliseconds -- if the
 *  value would be negative, return 0.
 *  \param[in] now const struct timeval * to first time value
 *  \param[in] then const struct timeval * to second time value
 *  \return the difference between the two tv_sec values, in ms
 */
extern time_t axa_elapsed_ms(const struct timeval *now, struct timeval *then);


#endif /* AXA_AXA_H */

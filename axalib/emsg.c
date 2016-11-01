/*
 * Error message and syslog output.
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

#include <axa/axa.h>

#include <syslog.h>
#include <errno.h>
#include <paths.h>
#include <sysexits.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
#endif
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>



static struct {
	int	priority;		/* syslog(3) facility|level */
	bool	set;
	bool	on;
	bool	out_stdout;		/* send messages to stdout */
	bool	out_stderr;		/* send messages to stderr */
} ss[3];				/* AXA_SYSLOG_{TRACE,ERROR,ACCT} */

static bool syslog_set;
static bool syslog_open;

char axa_prog_name[256];


/* Crash immediately on malloc failures. */
void *
axa_malloc(size_t s)
{
	void *p;

	p = malloc(s);
	AXA_ASSERT(p != NULL);
	return (p);
}

void *
axa_zalloc(size_t s)
{
	void *p;

	p = calloc(1, s);
	AXA_ASSERT(p != NULL);
	return (p);
}

char *
axa_strdup(const char *s)
{
	char *p;

	p = strdup(s);
	AXA_ASSERT(p != NULL);
	return (p);
}

char *
axa_strndup(const char *s, size_t len)
{
	char *p;

	p = strndup(s, len);
	AXA_ASSERT(p != NULL);
	return (p);
}

void
axa_vasprintf(char **bufp, const char *p, va_list args)
{
	int i;

	i = vasprintf(bufp, p,  args);
	AXA_ASSERT(i >= 0);
}

void AXA_PF(2,3)
axa_asprintf(char **bufp, const char *p, ...)
{
	va_list args;

	va_start(args, p);
	axa_vasprintf(bufp, p,  args);
	va_end(args);
}

/* Try to enable core files. */
void
axa_set_core(void)
{
	struct rlimit rl;

	if (0 > getrlimit(RLIMIT_CORE, &rl)) {
		axa_error_msg("getrlimit(RLIMIT_CORE): %s\n",
			strerror(errno));
		return;
	}
	if (rl.rlim_cur != 0)
		return;
	if (rl.rlim_max < 10*1024) {
		axa_error_msg("getrlimit(RLIMIT_CORE) max = %ld\n",
			(long)rl.rlim_max);
	}
	rl.rlim_cur = RLIM_INFINITY;
	if (0 > setrlimit(RLIMIT_CORE, &rl)) {
		axa_error_msg("setrlimit(RLIMIT_CORE %ld %ld): %s\n",
			(long)rl.rlim_cur, (long)rl.rlim_max, strerror(errno));
		return;
	}
}

void
axa_set_me(const char *me)
{
	const char *p;

	p = strrchr(me, '/');
	if (p != NULL)
		me = p+1;
	strlcpy(axa_prog_name, me, sizeof(axa_prog_name));
	if (syslog_open)
		axa_syslog_init();
}

static int
parse_syslog_level(const char *level)
{
	static struct {
		const char *str;
		int level;
	} level_tbl[] = {
		{"LOG_EMERG",	LOG_EMERG},
		{"LOG_ALERT",	LOG_ALERT},
		{"LOG_CRIT",	LOG_CRIT},
		{"LOG_ERR",	LOG_ERR},
		{"LOG_WARNING",	LOG_WARNING},
		{"LOG_NOTICE",	LOG_NOTICE},
		{"LOG_INFO",	LOG_INFO},
		{"LOG_DEBUG",	LOG_DEBUG},
	};
	int i;

	for (i = 0; i < AXA_DIM(level_tbl); ++i) {
		if (strcasecmp(level, level_tbl[i].str) == 0)
			return (level_tbl[i].level);
	}
	return (-1);
}

static int
parse_syslog_facility(const char *facility)
{
	static struct {
	    const char *str;
	    int facility;
	} facility_tbl[] = {
		{"LOG_AUTH",	LOG_AUTH},
#ifdef LOG_AUTHPRIV
		{"LOG_AUTHPRIV",LOG_AUTHPRIV},
#endif
		{"LOG_CRON",	LOG_CRON},
		{"LOG_DAEMON",	LOG_DAEMON},
#ifdef LOG_FTP
		{"LOG_FTP",	LOG_FTP},
#endif
		{"LOG_KERN",	LOG_KERN},
		{"LOG_LPR",	LOG_LPR},
		{"LOG_MAIL",	LOG_MAIL},
		{"LOG_NEWS",	LOG_NEWS},
		{"LOG_USER",	LOG_USER},
		{"LOG_UUCP",	LOG_UUCP},
		{"LOG_LOCAL0",	LOG_LOCAL0},
		{"LOG_LOCAL1",	LOG_LOCAL1},
		{"LOG_LOCAL2",	LOG_LOCAL2},
		{"LOG_LOCAL3",	LOG_LOCAL3},
		{"LOG_LOCAL4",	LOG_LOCAL4},
		{"LOG_LOCAL5",	LOG_LOCAL5},
		{"LOG_LOCAL6",	LOG_LOCAL6},
		{"LOG_LOCAL7",	LOG_LOCAL7},
	};
	int i;

	for (i = 0; i < AXA_DIM(facility_tbl); ++i) {
		if (strcasecmp(facility, facility_tbl[i].str) == 0)
			return (facility_tbl[i].facility);
	}
	return (-1);
}

/*
 * Parse
 *	{trace|error|acct},{off|FACILITY.LEVEL}[,{none,stderr,stdout}]
 */
bool
axa_parse_log_opt(axa_emsg_t *emsg, const char *arg)
{
	char type_buf[32], syslog_buf[32], syslog1_buf[32];
	const char *arg1, *syslog2_str;
	int facility, level;
	axa_syslog_type_t type;
	bool on, out_stdout, out_stderr;

	arg1 = arg;
	axa_get_token(type_buf, sizeof(type_buf), &arg1, ",");
	if (strcasecmp(type_buf, "trace") == 0) {
		type = AXA_SYSLOG_TRACE;
	} else if (strcasecmp(type_buf, "error") == 0) {
		type = AXA_SYSLOG_ERROR;
	} else if (strcasecmp(type_buf, "acct") == 0) {
		type = AXA_SYSLOG_ACCT;
	} else {
		axa_pemsg(emsg, "\"%s\" in \"-L %s\""
			  " is neither \"trace\", \"error\", nor \"acct\"",
			  type_buf, arg);
		return (false);
	}

	axa_get_token(syslog_buf, sizeof(syslog_buf), &arg1, ",");
	if (strcasecmp(syslog_buf, "off") == 0) {
		on = false;
		facility = 0;
		level = 0;
	} else {
		syslog2_str = syslog_buf;
		axa_get_token(syslog1_buf, sizeof(syslog1_buf),
			      &syslog2_str, ".");

		facility = parse_syslog_facility(syslog1_buf);
		level = parse_syslog_level(syslog2_str);
		if (facility < 0 && level < 0) {
			/* Recognize both LEVEL.FACILITY and FACILITY.LEVEL */
			facility = parse_syslog_facility(syslog2_str);
			level = parse_syslog_level(syslog1_buf);
		}
		if (facility < 0) {
			axa_pemsg(emsg,
				  "unrecognized syslog facility in \"%s\"",
				  arg);
			return (false);
		}
		if (level < 0) {
			axa_pemsg(emsg, "unrecognized syslog level in \"%s\"",
				      arg);
			return (false);
		}
		on = true;
	}

	if (arg1[0] == '\0' || AXA_CLITCMP(arg1, "stderr")) {
		out_stdout = false;
		out_stderr = true;
	} else if (AXA_CLITCMP(arg1, "off") || AXA_CLITCMP(arg1, "none")) {
		out_stdout = false;
		out_stderr = false;
	} else if (AXA_CLITCMP(arg1, "stdout")) {
		out_stdout = true;
		out_stderr = false;
	} else {
		axa_pemsg(emsg, "\"%s\" in \"-L %s\" is neither"
			  " NONE, STDERR, nor STDOUT",
			  arg1, arg);
		return (false);
	}

	ss[type].on = on;
	ss[type].priority = facility | level;
	ss[type].out_stdout = out_stdout;
	ss[type].out_stderr = out_stderr;

	if (ss[type].set)
		axa_error_msg("warning: \"-L %s,...\" already set", type_buf);
	ss[type].set = true;

	return (true);
}

/*
 * Initialize AXA default logging.
 *	axa_parse_log_opt() can override these values.
 */
static void
set_syslog(void)
{
	axa_emsg_t emsg;

	if (syslog_set)
		return;

	if (!ss[AXA_SYSLOG_TRACE].set) {
		AXA_ASSERT(axa_parse_log_opt(&emsg,
					     "trace,LOG_DEBUG.LOG_DAEMON"));
		ss[AXA_SYSLOG_TRACE].set = false;
	}
	if (!ss[AXA_SYSLOG_ERROR].set) {
		/* transposed facility and level to check axa_parse_log_opt() */
		AXA_ASSERT(axa_parse_log_opt(&emsg,
					     "error,LOG_DAEMON.LOG_ERR"));
		ss[AXA_SYSLOG_ERROR].set = false;
	}
	if (!ss[AXA_SYSLOG_ACCT].set) {
		AXA_ASSERT(axa_parse_log_opt(&emsg,
					     "acct,LOG_NOTICE.LOG_AUTH,none"));
		ss[AXA_SYSLOG_ACCT].set = false;
	}
	syslog_set = true;
}

void
axa_syslog_init(void)
{
	set_syslog();
	if (axa_prog_name[0] != '\0') {
		if (syslog_open)
			closelog();
		openlog(axa_prog_name, LOG_PID, LOG_DAEMON);
		syslog_open = true;
	}
}

static void
clean_stdfd(int stdfd)
{
	struct stat sb;
	int fd;

	if (0 > fstat(stdfd, &sb) && errno == EBADF) {
		fd = open(_PATH_DEVNULL, 0, O_RDWR | O_CLOEXEC);
		if (fd < 0)		/* ignore errors we can't help */
			return;
		if (fd != stdfd) {
			dup2(fd, stdfd);
			close(fd);
		}
	}
}

/*
 * Add text to an error or other message buffer.
 *	If we run out of room, add "...". */
void AXA_PF(3,4)
axa_buf_print(char **bufp, size_t *buf_lenp, const char *p, ...)
{
	size_t buf_len, len;
	va_list args;

	buf_len = *buf_lenp;
	if (buf_len < sizeof("...")) {
		if (buf_len != 0) {
			strlcpy(*bufp, "...", buf_len);
			*bufp += buf_len-1;
			*buf_lenp = 1;
		}
		return;
	}

	va_start(args, p);
	len = vsnprintf(*bufp, *buf_lenp, p,  args);
	va_end(args);
	if (len+sizeof("...") > buf_len) {
		strcpy(*bufp+buf_len-sizeof("..."), "...");
		*bufp += buf_len-1;
		*buf_lenp = 1;
	} else {
		*buf_lenp -= len;
		*bufp += len;
	}
}


/* Prevent surprises from uses of stdio FDs by ensuring that the FDs are open */
void
axa_clean_stdio(void)
{
	clean_stdfd(STDIN_FILENO);
	clean_stdfd(STDOUT_FILENO);
	clean_stdfd(STDERR_FILENO);
}

void
axa_vlog_msg(axa_syslog_type_t type, bool fatal, const char *p, va_list args)
{
	char buf[512], *bufp;
	size_t buf_len, n;
	FILE *stdio;
#	define FMSG "; fatal error"

	/*
	 * This function cannot use axa_vasprintf() and other axa_*()
	 * functions that would themselves call this function.
	 */

	bufp = buf;
	buf_len = sizeof(buf);
	if (fatal)
		buf_len -= sizeof(FMSG)-1;

	n = vsnprintf(bufp, buf_len, p, args);

	if (n >= buf_len)
		n = buf_len-1;
	if (n != 0 && buf[n-1] == '\n')
		buf[--n] = '\0';
	if (n == 0) {
		strlcat(bufp, "(empty error message)", buf_len);
		n = sizeof("(empty error message)")-1;
	}
	if (n >= buf_len)
		strcpy(&buf[buf_len-sizeof("...")], "...");
	if (fatal)
		strlcat(buf, FMSG, sizeof(buf));

	/* keep stderr and stdout straight despite syslog output
	 * to stdout or stderr */
	fflush(stdout);
	fflush(stderr);

	set_syslog();

	if (ss[type].out_stderr)
		stdio = stderr;
	else if (ss[type].out_stdout)
		stdio = stdout;
	else
		stdio = NULL;
	if (stdio != NULL)
		fprintf(stdio, "%s\n", buf);

	if (ss[type].on)
		syslog(ss[type].priority, "%s", buf);

	/* Error messges also go to the trace stream. */
	if (type == AXA_SYSLOG_ERROR && ss[AXA_SYSLOG_TRACE].on
	    && ss[AXA_SYSLOG_TRACE].priority != ss[AXA_SYSLOG_ERROR].priority)
		syslog(ss[AXA_SYSLOG_TRACE].priority, "%s", buf);

	fflush(stdout);
	fflush(stderr);
}

/*
 * Generate an error message string in a buffer, if we have a buffer.
 * Log or print the message if there is no buffer
 */
void
axa_vpemsg(axa_emsg_t *emsg, const char *p, va_list args)
{
	if (emsg == NULL) {
		axa_vlog_msg(AXA_SYSLOG_ERROR, false, p, args);
	} else {
		vsnprintf(emsg->c, sizeof(axa_emsg_t), p, args);
	}
}

void AXA_PF(2,3)
axa_pemsg(axa_emsg_t *emsg, const char *p, ...)
{
	va_list args;

	va_start(args, p);
	axa_vpemsg(emsg, p, args);
	va_end(args);
}

void
axa_verror_msg(const char *p, va_list args)
{
	axa_vlog_msg(AXA_SYSLOG_ERROR, false, p, args);
}

void AXA_PF(1,2)
axa_error_msg(const char *p, ...)
{
	va_list args;

	va_start(args, p);
	axa_vlog_msg(AXA_SYSLOG_ERROR, false, p, args);
	va_end(args);
}

void
axa_io_error(const char *op, const char *src, ssize_t len)
{
	if (len >= 0) {
		axa_error_msg("%s(%s)=%zd", op, src, len);
	} else {
		axa_error_msg("%s(%s): %s", op, src, strerror(errno));
	}
}

void
axa_vtrace_msg(const char *p, va_list args)
{
	axa_vlog_msg(AXA_SYSLOG_TRACE, false, p, args);
}

void AXA_PF(1,2)
axa_trace_msg(const char *p, ...)
{
	va_list args;

	va_start(args, p);
	axa_vlog_msg(AXA_SYSLOG_TRACE, false, p, args);
	va_end(args);
}

void AXA_NORETURN
axa_vfatal_msg(int ex_code, const char *p, va_list args)
{
	axa_vlog_msg(AXA_SYSLOG_ERROR, true, p, args);

	if (ex_code == 0 || ex_code == EX_SOFTWARE)
		abort();
	exit(ex_code);
}

/*
 * Things are so sick that we must bail out.
 */
void AXA_PF(2,3) AXA_NORETURN
axa_fatal_msg(int ex_code, const char *p, ...)
{
	va_list args;

	va_start(args, p);
	axa_vfatal_msg(ex_code, p, args);
}

/*
 * Get a logical line from a stdio stream, with leading and trailing
 * whitespace trimmed and "\\\n" deleted as a continuation.
 *	The file name and line number must be provided for error messages.
 *	The line number is updated.
 *	The buffer can be NULL.
 *	If the buffer is NULL or it is not big enough, it is freed and a new
 *	    buffer is allocated.
 *	The must be freed after the last use of this function.
 *	Except at error or EOF, the start of the next line is returned,
 *	    which might not be at the start of the buffer.
 *	The return value is NULL and emsg->c[0]=='\0' at EOF.
 *	The return value is NULL and emsg->c[0]!='\0' after an error.
 */
char *
axa_fgetln(FILE *f,			/* source */
	   const char *file_name,	/* for error messages */
	   uint *line_num,
	   char **bufp,			/* destination must be freed */
	   size_t *buf_sizep)
{
	char *buf, *p, *line;
	size_t buf_size, len, delta;

	if (*bufp == NULL) {
		AXA_ASSERT(*buf_sizep == 0);
		buf = axa_malloc(*buf_sizep = 81);
		*bufp = buf;
	}
	for (;;) {
		buf = *bufp;
		buf_size = *buf_sizep;
		for (;;) {
			if (buf_size < 80) {
				delta = (*buf_sizep/81+2)*81 - buf_size;
				p = axa_malloc(*buf_sizep + delta);
				len = buf - *bufp;
				if (len > 0)
					memcpy(p, *bufp, len);
				*buf_sizep += delta;
				buf_size += delta;
				free(*bufp);
				*bufp = p;
				buf = p+len;
			}

			if (fgets(buf, buf_size, f) == NULL) {
				*buf = '\0';
				if (ferror(f) != 0) {
					axa_error_msg("fgets(%s): \"%s\"",
						      file_name,
						      strerror(errno));
					return (NULL);
				}
				break;
			}

			/* Expand the buffer and get more if the buffer
			 * was too small for the line */
			len = strlen(buf);
			if (len >= buf_size-1 && buf[len-1] != '\n') {
				buf_size -= len;
				buf += len;
				continue;
			}

			++*line_num;

			/* trim trailing '\n' and check for continuation */
			while (len >0
			       && (buf[len-1] == '\n' || buf[len-1] == '\r')) {
				buf[--len] = '\0';
			}
			if (len == 0
			    || ( buf[--len] != '\\' || len >= 10*1024))
				break;
			buf[len]= '\0';
			buf_size -= len;
			buf += len;
		}

		/* Trim leading blanks and comments */
		line = *bufp+strspn(*bufp, AXA_WHITESPACE);
		p = strpbrk(line, "\r\n#");
		if (p != NULL)
			*p = '\0';

		/* skip blank lines */
		if (*line != '\0')
			return (line);
		if (feof(f))
			return (NULL);
	}
}

/*
 * Strip leading and trailing white space.
 */
const char *
axa_strip_white(const char *str, size_t *lenp)
{
	const char *end;
	char c;

	str += strspn(str, AXA_WHITESPACE);
	end = str+strlen(str);
	while (end > str) {
		c = *(end-1);
		if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
			break;
		--end;
	}
	*lenp = end-str;
	return (str);
}

/* Copy the next token from a string to a buffer and return the
 * size of the string put into the buffer.
 * Honor quotes and backslash.
 * The caller must skip leading token separators (e.g. blanks) if necessary.
 * When the separators include whitespace and whitespace ends the token,
 *	then all trailing whitespace is skipped */
ssize_t					/* # of bytes or <0 for failure */
axa_get_token(char *buf,		/* put the token here */
	      size_t buf_len,
	      const char **stringp,	/* input string pointer */
	      const char *seps)		/* string of token separators */
{
	int token_len;
	bool quot_ok, esc_ok;
	const char *string;
	char c, quote;

	token_len = 0;

	/* Quietly skip without a buffer but fail with a zero-length buffer. */
	if (buf_len == 0 && buf != NULL)
		return (-1);

	quot_ok = (strpbrk(seps, "\"'") == NULL);
	esc_ok = (strchr(seps, '\\') == NULL);
	string = *stringp;

	for (;;) {
		c = *string;
		if (c == '\0') {
			if (buf != NULL)
				*buf = '\0';
			*stringp = string;
			return (token_len);
		}
		if (quot_ok && strchr("\"'",c ) != NULL) {
			quote = c;
			while ((c = *++string) != quote) {
				if (c == '\0') {
					if (buf != NULL)
					    *buf = '\0';
					*stringp = string;
					return (token_len);
				}
				++token_len;

				if (buf == NULL)
					continue;
				if (--buf_len == 0) {
					*buf = '\0';
					*stringp = string;
					return (-1);
				}
				*buf++ = c;
			}
			++string;
			continue;
		}

		++string;
		if (c == '\\' && esc_ok) {
			c = *string++;
		} else if (strchr(seps, c) != NULL) {
			/* We found a separator.  Eat it and stop.
			 * If it is whitespace, then eat all trailing
			 * whitespace. */
			if (strchr(AXA_WHITESPACE, c) != NULL)
				string += strspn(string, AXA_WHITESPACE);

			if (buf != NULL)
				*buf = '\0';
			*stringp = string;
			return (token_len);
		}
		++token_len;

		if (buf == NULL)
			continue;
		if (--buf_len == 0) {
			*buf = '\0';
			*stringp = string;
			return (-1);
		}
		*buf++ = c;
	}
}

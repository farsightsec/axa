/*
 * Error message and syslog output.
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

uint axa_debug;



typedef enum {SS_TRACE=0, SS_ERROR=1, SS_ACCT=2} ss_type_t;
static struct {
	int	priority;
	bool	set;
	bool	on;
} ss[3];

char axa_prog_name[256] = "?";
static char prog_name_msg[sizeof(axa_prog_name)+sizeof(": ")];
struct pidfh *axa_pidfh = NULL;


/* Crash immediately on malloc failures. */
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

void AXA_PF(2,3)
axa_asprintf(char **bufp, const char *p, ...)
{
	va_list args;
	int i;

	va_start(args, p);
	i = vasprintf(bufp, p,  args);
	va_end(args);
	AXA_ASSERT(i >= 0);
}

/*
 * Try to enable core files.
 */
void
axa_set_core(void)
{
	struct rlimit rl;

	if (0 > getrlimit(RLIMIT_CORE, &rl)) {
		fprintf(stderr, "getrlimit(RLIMIT_CORE): %s\n",
			strerror(errno));
		return;
	}
	if (rl.rlim_cur != 0)
		return;
	if (rl.rlim_max < 10*1024) {
		fprintf(stderr, "getrlimit(RLIMIT_CORE) max = %ld\n",
			(long)rl.rlim_max);
	}
	rl.rlim_cur = min(rl.rlim_max, 512*1024*1024);
	if (0 > setrlimit(RLIMIT_CORE, &rl)) {
		fprintf(stderr, "setrlimit(RLIMIT_CORE %ld %ld): %s\n",
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
	snprintf(prog_name_msg, sizeof(prog_name_msg), "%s: ", me);
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
 *	{trace|error|acct},{off|FACILITY.LEVEL}
 */
bool
axa_parse_log_opt(const char *arg)
{
	char type_buf[sizeof("error")];
	char facility_buf[32];
	const char *level_str, *facility_str, *str;
	int facility, level;
	ss_type_t type;

	level_str = arg;
	axa_get_token(type_buf, sizeof(type_buf), &level_str, ",");
	if (strcasecmp(type_buf, "trace") == 0) {
		type = SS_TRACE;
	} else if (strcasecmp(type_buf, "error") == 0) {
		type = SS_ERROR;
	} else if (strcasecmp(type_buf, "acct") == 0) {
		type = SS_ACCT;
	} else {
		axa_error_msg("\"%s\" in \"-L %s\""
			      " is neither \"trace\", \"error\", nor \"acct\"",
			      type_buf, arg);
		return (false);
	}

	if (strcasecmp(level_str, "off") == 0) {
		ss[type].on = false;
	} else {
		facility_str = facility_buf;
		if (0 > axa_get_token(facility_buf, sizeof(facility_buf),
				      &level_str, ".,")
		    || facility_str[0] == '\0') {
			axa_error_msg("missing or bad facility in \"-L %s\"",
				      arg);
			return (false);
		}

		if (level_str == NULL) {
			axa_error_msg("missing syslog level in \"-L %s\"",
				      arg);
			return (false);
		}

		/* recognize both level.facility and facility.level */
		facility = parse_syslog_facility(facility_str);
		level = parse_syslog_level(level_str);
		if (facility < 0 && level < 0
		    && (parse_syslog_level(facility_str) >= 0
			|| parse_syslog_facility(level_str) >= 0)) {
			str = facility_str;
			facility_str = level_str;
			level_str = str;
			facility = parse_syslog_facility(facility_str);
			level = parse_syslog_level(level_str);
		}
		if (facility < 0) {
			axa_error_msg("unrecognized syslog facility in \"%s\"",
				      arg);
			return (false);
		}
		if (level < 0) {
			axa_error_msg("unrecognized syslog level in \"%s\"",
				      arg);
			return (false);
		}

		ss[type].on = true;
		ss[type].priority = facility | level;
	}

	if (ss[type].set)
		axa_error_msg("warning: \"-L %s,...\" already set", type_buf);
	ss[type].set = true;

	return (true);
}

void
axa_syslog_init(void)
{
	AXA_ASSERT_MSG(prog_name_msg[0] != '\0', "axa_set_me() not yet called");

	openlog(axa_prog_name, LOG_PID | LOG_NOWAIT, LOG_DAEMON);
	if (!ss[SS_TRACE].set) {
		axa_parse_log_opt("trace,LOG_DEBUG,LOG_DAEMON");
		ss[SS_TRACE].set = false;
	}
	if (!ss[SS_ERROR].set) {
		/* transposed facility and level to check axa_parse_log_opt() */
		axa_parse_log_opt("error,LOG_DAEMON,LOG_ERR");
		ss[SS_ERROR].set = false;
	}
	if (!ss[SS_ACCT].set) {
		axa_parse_log_opt("acct,LOG_NOTICE,LOG_AUTH");
		ss[SS_ACCT].set = false;
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

/* Add text to an error or other message buffer */
bool AXA_PF(4,5)			/* false=no more room */
axa_buf_print(char **bufp, size_t *buf_lenp, bool ellipsis, const char *p, ...)
{
	size_t len;
	va_list args;

	if (*buf_lenp == 0)
		return (false);

	va_start(args, p);
	len = vsnprintf(*bufp, *buf_lenp, p,  args);
	va_end(args);
	if ((ellipsis ? len+sizeof("...") : (len+1)) >= *buf_lenp) {
		if (ellipsis && *buf_lenp >= sizeof("..."))
			strcpy(*bufp+*buf_lenp-sizeof("..."), "...");
		*buf_lenp = 0;
		return (false);
	}
	*buf_lenp -= len;
	*bufp += len;
	return (true);
}


/* Prevent surprises from uses of stdio FDs by ensuring that the FDs are open */
void
axa_clean_stdio(void)
{
	clean_stdfd(STDIN_FILENO);
	clean_stdfd(STDOUT_FILENO);
	clean_stdfd(STDERR_FILENO);
}

static void
vlog_msg(ss_type_t type, bool fatal, const char *p, va_list args)
{
	char buf[512], *bufp;
	size_t buf_len, n;
#	define FMSG "; fatal error"

	bufp = buf;
	buf_len = sizeof(buf);
	if (fatal)
		buf_len -= sizeof(FMSG)-1;

	n = vsnprintf(bufp, buf_len, p, args);
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
	buf_len = strlen(buf);

	if (type != SS_ACCT) {
		fflush(stdout);		/* keep stderr and stdout straight */
		if (prog_name_msg[0] != '\0')
			fputs(prog_name_msg, stderr);
		fwrite(buf, buf_len, 1, stderr);
		fputc('\n', stderr);
	}

	if (ss[type].on)
		syslog(ss[type].priority, "%s", buf);

	/* keep stderr and stdout straight despite syslog output
	 * to stdout or stderr */
	if (type == SS_ERROR)
		fflush(stderr);
}

/*
 * Generate an erorr message string in a buffer, if we have a buffer.
 * Log or print the message if there is no buffer
 */
void
axa_vpemsg(axa_emsg_t *emsg, const char *p, va_list args)
{
	if (emsg == NULL) {
		vlog_msg(SS_ERROR, false, p, args);
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
	vlog_msg(SS_ERROR, false, p, args);
}

void AXA_PF(1,2)
axa_error_msg(const char *p, ...)
{
	va_list args;

	va_start(args, p);
	vlog_msg(SS_ERROR, false, p, args);
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

/*
 * talk to stdout and to the system log
 */
void
axa_vtrace_msg(const char *p, va_list args)
{
	vlog_msg(SS_TRACE, false, p, args);
}

void AXA_PF(1,2)
axa_trace_msg(const char *p, ...)
{
	va_list args;

	va_start(args, p);
	vlog_msg(SS_TRACE, false, p, args);
	va_end(args);
}

/*
 * Things are so sick that we must bail out.
 */
void AXA_NORETURN
axa_vfatal_msg(int ex_code, const char *p, va_list args)
{
	vlog_msg(SS_ERROR, true, p, args);

	if (axa_pidfh != NULL)
		pidfile_remove(axa_pidfh);
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

/* Stash an account record */
void AXA_PF(1,2)
axa_accounting_rcd(const char *p, ...)
{
	va_list args;

	va_start(args, p);
	vlog_msg(SS_ACCT, false, p, args);
	va_end(args);
}

void
axa_pidfile(const char *rundir, const char *pidfile)
{
	char *path;
	pid_t old_pid;
	int i;

	path = NULL;
	if (pidfile != NULL && pidfile[0] == '/') {
		axa_pidfh = pidfile_open(pidfile, 0644, &old_pid);
	} else {
		i = asprintf(&path, "%s/%s.pid", rundir, axa_prog_name);
		AXA_ASSERT(0 <= i);
		axa_pidfh = pidfile_open(path, 0644, &old_pid);
	}

	if (axa_pidfh == NULL) {
		if (errno == EEXIST)
			axa_fatal_msg(EX_OSERR, "%s already running with PID %d",
				      axa_prog_name, old_pid);
		else
			axa_fatal_msg(EX_IOERR, "pidfile_open(%s): %s",
				      path == NULL ? pidfile : path,
				      strerror(errno));
	}
	if (path != NULL)
		free(path);
}

char *
axa_fgetln(FILE *f, const char *file_name, uint *line_num,
	   char **bufp, size_t *buf_sizep)
{
	char *buf, *p, *line;
	size_t buf_size, len, delta;

	if (*bufp == NULL) {
		AXA_ASSERT(*buf_sizep == 0);
		buf = malloc(*buf_sizep = 81);
		AXA_ASSERT(buf != NULL);
		*bufp = buf;
	}
	for (;;) {
		buf = *bufp;
		buf_size = *buf_sizep;
		for (;;) {
			if (buf_size < 80) {
				delta = (*buf_sizep/81+2)*81 - buf_size;
				p = malloc(*buf_sizep + delta);
				AXA_ASSERT(p != NULL);
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

		if (c == '\\' && esc_ok)
			c = *++string;
		++string;

		if (strchr(seps, c) != NULL) {
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

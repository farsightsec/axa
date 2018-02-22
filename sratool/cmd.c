/*
 * SIE Remote Access (SRA) ASCII tool
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

#include "sratool.h"

/* extern: infile.c */
extern in_files_t in_files[];
extern int in_file_cur;

/* extern: main.c */
extern uint verbose;
extern bool quiet;
extern bool out_on;
extern bool out_on_nmsg;
extern bool nmsg_zlib;
extern axa_client_t client;
extern uint axa_debug;
extern axa_emsg_t emsg;
extern int packet_count;
extern int packet_count_total;
extern bool packet_counting;

/* extern: output.c */
extern int out_fd;
extern pcap_t *out_pcap;
extern int out_pcap_datalink;
extern int8_t *out_buf;
extern size_t out_buf_base;
extern int output_count;
extern int output_count_total;
extern bool output_counting;
extern bool output_buffering;
extern bool out_on;
extern char *out_addr;
extern int output_errno;
extern int out_sock_type;
extern nmsg_output_t out_nmsg_output;
extern pcap_dumper_t *out_pcap_dumper;

/* extern: signal.c */
extern bool interrupted;
extern bool terminated;

/* global */
bool eclose = false;            	/* disconnect on error */
History *el_history;			/* command history */
HistEvent el_event;			/* command history event */
char *history_savefile = NULL;		/* fq path to history savefile */
EditLine *el_e = NULL;			/* editline context */
struct timeval cmd_input;		/* timestamp of last input from user */
bool no_prompt = false;			/* true == sra> or rad> prompt */
struct timeval no_reprompt;		/* server has been active recently */
struct timeval prompt_cleared;		/* !=0 if prompt & user input erased */
struct timeval last_output;		/* timestamp of last output to user */
size_t prompt_len;			/* length of visible prompt */
cmd_t version_cmd;			/* version command exported to main */
axa_mode_t mode;			/* sratool or radtool */

/* private */
static int out_cmd_pcap_if(const char *ifname);
static int out_cmd_pcap_file(const char *addr, bool want_fifo);

static struct timeval connect_time;
static struct {
	struct ether_addr   dst;
	struct ether_addr   src;
	uint16_t            etype;
} out_mac;

/* commands */
static cmd_t help_cmd;
static cmd_t exit_cmd;
static cmd_t error_mode_cmd;
static cmd_t debug_cmd;
static cmd_t verbose_cmd;
static cmd_t source_cmd;
static cmd_t disconnect_cmd;
static cmd_t connect_cmd;
static cmd_t count_cmd;
static cmd_t ciphers_cmd;
static cmd_t out_cmd;
static cmd_t nop_cmd;
static cmd_t mode_cmd;
static cmd_t sra_mode_cmd;
static cmd_t rad_mode_cmd;
static cmd_t user_cmd;
static cmd_t sra_watch_cmd;
static cmd_t rad_watch_cmd;
static cmd_t list_cmd;
static cmd_t delete_cmd;
static cmd_t channel_cmd;
static cmd_t anom_cmd;
static cmd_t rlimits_cmd;
static cmd_t sample_cmd;
static cmd_t sndbuf_cmd;
static cmd_t acct_cmd;
static cmd_t pause_cmd;
static cmd_t trace_cmd;
static cmd_t go_cmd;
static cmd_t sleep_cmd;
static cmd_t radunit_cmd;
static cmd_t nmsg_zlib_cmd;
static cmd_t stats_req_cmd;
static cmd_t kill_cmd;
static cmd_t alias_cmd;
static cmd_t buffer_cmd;

typedef enum {
	NO,
	MB,
	YES
} ternary_t;

/* -1 = display help message, 0 = command failed, 1 = success */
struct cmd_tbl_entry {
	const char	*cmd;		/* common name of cmd */
	cmd_t		(*fnc);		/* function that runs cmd */
	axa_mode_t	mode;		/* SRA|RAD|BOTH */
	ternary_t	need_args;	/* YES|NO|MB (maybe) */
	bool		need_sock;	/* server connection req'd? YES|NO */
	const char	*help_str;	/* one-liner synopsis */
	const char	*usage_str;	/* detailed usage */
};

const cmd_tbl_entry_t cmds_tbl[] = {
{"?",			help_cmd,		BOTH, MB, NO,
    "? [cmd]",
    "List all commands or get more information about a command."
},
{"accounting",		acct_cmd,		BOTH, NO, YES,
    "accounting",
    "Ask the server to report total message counts."
},
{"alias",		alias_cmd,		BOTH, NO, NO,
    "alias",
    "List available connection aliases."
},
{"anomaly",		anom_cmd,		RAD, YES, YES,
    "tag anomaly name [parameters]",
    "Start the named anomaly detector module.\n"
    " \"Tag\" is the number labeling the module."
},
{"buffering",		buffer_cmd,		BOTH, NO, NO,
    "nmsg output buffering",
    "Toggle nmsg container buffering.\nFor this option to have any"
    " effect, output mode must be enabled in nmsg socket mode. "
    "When enabled, (by default) nmsg containers will fill with payloads"
    " before being emitted. When disabled, nmsg payloads will be emitted as"
    " rapidly as possible.\n"
    "Note, for this command to take effect, it must be set before using"
    " the 'forward' command."
},
{"ciphers",		ciphers_cmd,		BOTH, MB, NO,
    "ciphers [cipher-list]",
    "Specify the ciphers to be used with future connections."
    "  Disconnect the current connection if it uses TLS."
},
{"channels",		channel_cmd,		SRA, YES, YES,
    "channel {list | {on | off} {all | chN}}",
    "List available SRA channels or enable or disable"
    " one or all SIE channels."
},
{"connect",		connect_cmd,		BOTH, MB, NO,
    "connect [server]",
    "Show the current connection"
    " or connect with 'tcp:user@host,port',"
    " 'unix:[user@]/socket'] through a UNIX domain socket,"
    " 'ssh:[user@]host' via SSH"
    " or with 'tls:user@host,port."
},
{"count",		count_cmd,		BOTH, MB, NO,
    "count [#packets | off]",
    "Set terminal output to stop displaying packets after a"
    " number of packets (including immediately with a number of 0),"
    " show the currently remaining count,"
    " or turn off the packet count limit."
},
{"debug",		debug_cmd,		BOTH, MB, NO,
    "debug [on | off | quiet | N]",
    "increases, decreases, or shows the level of debugging and tracing messages"
    " that is also controlled by -d."
    "  \"Debug quiet\" turns off reports of successful AXA commands."
},
{"delete",		delete_cmd,		BOTH,MB, YES,
    "delete",
    "Delete a watch or anomaly."
},
{"delete watches",	delete_cmd,		SRA, MB, YES,
    "[tag] delete watches [all]",
    "With a tag, stop or delete the specified watch.\n"
    " With \"all\", delete all watches"
},
{"delete anomaly",	delete_cmd,		RAD, MB, YES,
    "[tag] delete anomaly [all]",
    "Delete an anomaly detector module specified by tag"
    " or all anomaly detector modules."
},
{"disconnect",		disconnect_cmd,		BOTH, NO, NO,
    "disconnect",
    "Disconnect from the server."
},
{"error mode",		error_mode_cmd,		BOTH, MB, NO,
    "error mode [disconnect | off]",
    "\"error mode disconnect\" disconnects from the server and exits"
    " when the server reports an error or the connection breaks."
    " In the default mode, \"error mode off\", errors are only reported."
},
{"exit",		exit_cmd,		BOTH, NO, NO,
    "exit",
    "Quit the program."
},
{"forward",		out_cmd,		BOTH, MB, NO,
    "forward [off | nmsg:[tcp:|udp:]host,port [count] | nmsg:file:path [count]\n"
    "      | pcap[-fifo]:file [count] | pcap-if:[dst/]ifname] [count]",
    "Start, stop or show the state of forwarding packets received from"
    " the server."
    "  Received NMSG messages and IP packets can be"
    " forwarded as NMSG messages to a TCP or UDP port."
    "  Received IP packets can be forwarded as a pcap stream"
    " to a file, to a FIFO created separately with `mkfifo`,"
    " or in Ethernet frames on a named network interface to a 48-bit address"
    " (default 0)."
    "  Stop forwarding after count messages."
},
{"get",			list_cmd,		RAD, NO, YES,
    "[tag] get",
    "With a tag, list the set of watches and anomaly detection modules with"
    " that tag."
    " Without a tag, list all active as well as available anomaly detection"
    " modules."
},
{"get channels",	list_cmd,		SRA, MB, YES,
    "get channels",
    "List all SIE channels available to the user on the SRA server."
},
{"get watches",		list_cmd,		SRA, MB, YES,
    "[tag] get watches",
    "With a tag, list the specified watch."
    "  List all watches without a tag."
},
{"go",			go_cmd,			BOTH, NO, YES,
    "go",
    "Tell the server to resume sending data."
},
{"help",		help_cmd,		BOTH, MB, NO,
    "help [cmd]",
    "List all commands or get more information about a command."
},
{"kill",		kill_cmd,		BOTH, YES, YES,
    "kill user_name | serial_number",
    "Kill off user session (admin users only). If serial number is specified"
    " kill a single session; if user name is specified, kill all sessions"
    " belonging to that user."
},
{"list channels",	list_cmd,		SRA, MB, YES,
    "list channels",
    "List all SIE channels available to the user on the SRA server."
},
{"list",		list_cmd,		RAD, NO, YES,
    "[tag] list",
    "With a tag, list the set of watches and anomaly detection modules with"
    " that tag."
    " Without a tag, list all active as well as available anomaly detection"
    " modules."
},
{"list watches",	list_cmd,		SRA, MB, YES,
    "[tag] list watches",
    "With a tag, list the specified watch."
    "  List all watches without a tag."
},
{"stats",		stats_req_cmd,		BOTH, MB, YES,
    "stats [all | user_name | serial_number]",
    "Get current system, server, and user statistics (admin users only)."
    " If no argument is provided, return a top-level summary containing"
    " system and server statistics."
    " If a user name or serial number is provided, proceed summary with"
    " information on all current sessions for that user."
    " If the keyword \"all\" is specified, proceed summary with information"
    " on all current sessions for all logged in users."
},
{"mode",		mode_cmd,		BOTH, MB, NO,
    "mode [SRA | RAD]",
    "Show the current command mode or"
    " expect to connect to an SRA or RAD server. Mode cannot be changed"
    " while connected to server."
},
{"nop",			nop_cmd,		BOTH, NO,YES,
    "nop",
    "Send a command to the server that does nothing but test the connection"
},
{"pause",		pause_cmd,		BOTH, NO, YES,
    "pause",
    "Tell the server to stop sending data."
},
{"quit",		exit_cmd,		BOTH, NO, NO,
    "quit",
    "Quit the program."
},
{"radd",		rad_mode_cmd,		BOTH, MB, NO,
    "radd",
    "Change to RAD mode (must not be connected to a server)."
},
{"rate limits",		rlimits_cmd,		BOTH, MB, YES,
    "rate limits [-|MAX|per-sec] [-|NEVER|report-secs]",
    "Ask the server to report its rate limits"
    " or to set rate limits and the interval between rate limit reports."
},
{"runits",		radunit_cmd,		RAD, NO, YES,
    "runits",
    "Ask the server for my RAD Unit balance."
},
{"sample",		sample_cmd,		BOTH, MB, YES,
    "sample [percent]",
    "Ask the server to report its current output sampling rate"
    " or to set its sampling rate."
},
{"sleep",		sleep_cmd,		BOTH, YES, NO,
    "sleep x.y",
    "Stop accepting commands or displaying server output for a while."
},
{"source",		source_cmd,		BOTH, YES, NO,
    "source filename",
    "Read and execute commands commands from a file."
},
{"status",		connect_cmd,		BOTH, NO, NO,
    "status",
    "get server status"
},
{"srad",		sra_mode_cmd,		BOTH, MB, NO,
    "srad",
    "Change to RAD mode (must not be connected to a server)."
},
{"stop",		delete_cmd,		BOTH, MB, YES,
    "stop",
    "Stop watches or anomalies."
},
{"watch",		rad_watch_cmd,		RAD, MB, YES,
    "tag watch {ip=IP[/n] | dns=[*.]dom}",
    "Tell the RAD server about address and domains of interest."
},
{"watch",		sra_watch_cmd,		SRA, MB, YES,
    "tag watch {ip=IP[/n] | dns=[*.]dom | ch=chN | errors}",
    "Tell the SRA server to send nmsg messages or IP packets that are to,"
    " from, or contain the specified IP addresses,"
    " that contain the specified domain name,"
    " that arrived at the server on the specified SIE channel,"
    " or are SIE messages that could not be decoded."
    " The \"tag\" is the integer labeling the watch."
},
{"trace",		trace_cmd,		BOTH, YES, YES,
    "trace N",
    "Set server trace level."
},
{"user",		user_cmd,		BOTH, YES, YES,
    "user name",
    "Send the user name required by the server on a TCP/IP connection or"
    " a UNIX domain socket.\n"
    " TLS/SSH connections do not use this command but use the"
    " name negotiated with the tls or ssh protocol."
},
{"verbose",		verbose_cmd,		BOTH, MB, NO,
    "verbose [on | off | N]",
    "controls the length of SIE message and IP packet descriptions."
    "  The default, \"verbose off\", generally displays one line summaries."
},
{"version",		version_cmd,		BOTH, NO, NO,
    "version",
    "shows the software and protocol version."
},
{"window",		sndbuf_cmd,		BOTH, MB, YES,
    "window [bytes]",
    "Ask the server to report its current TCP output buffer size on TLS and"
    " TCP connections or to set its output buffer size."
},
{"zlib",		nmsg_zlib_cmd,		BOTH, NO, NO,
    "zlib",
    "Toggle nmsg container compression.\nFor this option to have any"
    " effect, output mode must be enabled in nmsg file or socket mode."
},
};


const char *
el_prompt(EditLine *e AXA_UNUSED)
{
	static const char null_prompt[] = "";
	static const char rad_std_prompt[] = "rad> ";
	static const char sra_std_prompt[] = "sra> ";
	static const char rad_out_prompt[] = "output-rad> ";
	static const char sra_out_prompt[] = "output-sra> ";
	const char *prompt;

	if (interrupted)
		return (null_prompt);

	if (no_prompt)
		prompt = null_prompt;
	else if (out_on)
		prompt = mode == RAD ? rad_out_prompt : sra_out_prompt;
	else
		prompt = mode == RAD ? rad_std_prompt : sra_std_prompt;

	prompt_cleared.tv_sec = 0;
	no_reprompt.tv_sec = 0;
	prompt_len = strlen(prompt);
	return (prompt);
}

static int
get_cols(void)
{
	int cols = 0;

#ifdef TIOCGWINSZ
	if (cols == 0) {
		struct winsize ws;

		if (ioctl(el->el_infd, TIOCGWINSZ, (void *)&ws) != -1)
			col = ws.ws_col
	}
#endif
#ifdef TIOCGSIZE
	if (cols == 0) {
		struct ttysize ts;
		if (ioctl(el->el_infd, TIOCGSIZE, (void *)&ts) != -1)
			cols = ts.ts_cols;
	}
#endif

	if (cols == 0)
		cols = 80;

	return (cols);
}

/* Clear the prompt and any partial command to make room output from the
 * server. The history library will eventually be told to restore it. */
void
clear_prompt(void)
{
	const LineInfo *li;
	int cols, llen, i;

	cmd_input.tv_sec = 0;
	gettimeofday(&last_output, NULL);

	if (el_e == NULL)
		return;

	fflush(stderr);
	fflush(stdout);

	if (prompt_cleared.tv_sec == 0 && prompt_len != 0) {
		/* We do not catch SIGWINCH,
		 * and so must always get the screen (line) size. */
		cols = get_cols();

		/* get user's partial command */
		li = el_line(el_e);
		llen = li->lastchar - li->buffer;
		llen += prompt_len;

		if (llen > 0) {
			/* Erase the prompt and the user's command.
			 * '\b' generally does not wrap to the previous line,
			 * so mess around with the window size. */
			for (i = (li->cursor - li->buffer + prompt_len)/cols;
			     i > 0;
			     --i) {
				el_set(el_e, EL_ECHOTC, "up", NULL);
			}
			fputc('\r', stdout);
			/* Cover everything with blanks. */
			for (i = llen; i > 0; --i)
				fputc(' ', stdout);
			/* Back to the start of the (first) line. */
			for (i = llen/cols; i > 0; --i) {
				el_set(el_e, EL_ECHOTC, "up", NULL);
			}
		}
		fputc('\r', stdout);
		fflush(stdout);
	}

	prompt_len = 0;
	prompt_cleared = last_output;
}

/* Restore the prompt */
void
reprompt(void)
{
	prompt_cleared.tv_sec = 0;
	no_reprompt.tv_sec = 0;
	el_set(el_e, EL_REFRESH);
}

void
error_help_cmd(axa_tag_t tag, const char *arg)
{
	error_close(true);
	help_cmd(tag, arg, NULL);
}

void
history_get_savefile(void)
{
	int n;
	struct passwd *pw;
	const char *histfile_name  = ".sratool_history";
	static char buf[MAXPATHLEN + 1];

	pw = getpwuid(getuid());
	if (pw == NULL)
		return;

	n = snprintf(buf, sizeof(buf), "%s", pw->pw_dir);
	snprintf(buf + n, sizeof(buf) - n, "/%s", histfile_name);

	history_savefile = buf;
}


/* Compare command names ignoring case. */
static const char *			/* NULL or mismatch in user string */
cmd_cmp(const char *user,		/* from the user */
	const char *op,			/* from command table entry */
	bool *iss)			/* mere initial substring match */
{
	char op_c, user_c;
	int len;

	if (iss != NULL)
		*iss = false;

	len = 0;
	for (;;) {
		op_c = AXA_TO_LOWER(*op);

		user_c = AXA_TO_LOWER(*user);
		if (user_c == '\t')
			user_c = ' ';

		if (op_c != user_c) {
			/* compress bursts of blanks */
			if (user_c == ' ' && len != 0 && *(op-1) == ' ') {
				++user;
				continue;
			}

			/* Treat an initial substring match without an arg
			 * as a complete match. */
			if (user_c == '\0') {
				if (iss != NULL)
					*iss = true;
				return (NULL);
			}
			return (user);
		}

		/* stop at an exact match */
		if (op_c == '\0')
			return (NULL);

		++op;
		++user;
		++len;
	}
}

/* Look for (the start of) a word. */
static bool
word_cmp(const char **argp, const char *tgt)
{
	const char *arg1, *arg2;
	int i;

	arg1 = *argp;
	arg1 += strspn(arg1, AXA_WHITESPACE);

	if (arg1[0] == '\0')
		return (false);

	arg2 = cmd_cmp(arg1, tgt, NULL);
	if (arg2 == arg1)
		return (false);
	if (arg2 == NULL) {
		*argp = arg1 + strlen(arg1);
		return (true);
	}
	i = strspn(arg2, AXA_WHITESPACE);
	if (i != 0) {
		*argp = arg2+i;
		return (true);
	}
	return (false);
}

static bool
run_cmd(axa_tag_t tag, const char *op, const char *arg,
	const cmd_tbl_entry_t *ce)
{
	int i;

	if (ce->need_sock && !AXA_CLIENT_OPENED(&client)) {
		error_msg("\"%s\" requires a connection to a server", op);
		return (0);
	}

	if ((ce->need_args == YES && *arg == '\0')
	    || (ce->need_args == NO && *arg != '\0')) {
		error_help_cmd(tag, op);
		return (false);
	}

	i = ce->fnc(tag, arg, ce);
	if (i > 0)
		return (true);

	if (i < 0)
		error_help_cmd(tag, op);
	else
		error_close(true);
	return (false);
}

static bool				/* true=ok false=bad command */
cmd(axa_tag_t tag, const char *op)
{
	const char *arg, *best_argp = NULL;
	int j;
	const cmd_tbl_entry_t *ce, *ce1, *best_ce = NULL;
	bool iss;
	int num_iss;

	/* Look for the string as a command and execute it if we find it. */
	ce1 = NULL;
	num_iss = 0;
	for (ce = cmds_tbl; ce <= AXA_LAST(cmds_tbl); ++ce) {
		if (ce->mode != mode && ce->mode != BOTH)
			continue;
		arg = cmd_cmp(op, ce->cmd, &iss);
		if (arg == op)
			continue;

		/* If the command table entry and the command completely
		 * matched, then infer a null argument. */
		if (arg == NULL) {
			if (iss) {
				++num_iss;

				/* Continue searching after
				 * the 1st initial substring match,
				 * a duplicate initial substring match,
				 * or a synonym initial substring match. */
				if (ce1 == NULL) {
					ce1 = ce;
					continue;
				}
				if (ce1->fnc == ce->fnc)
					continue;
				if (ce->help_str == NULL)
					continue;
				error_help_cmd(tag, op);
				return (false);
			}
			if (ce->need_args != YES)
				return (run_cmd(tag, op, "", ce));
			error_help_cmd(tag, op);
			return (false);
		}
		/* If the command table entry is an initial substring of
		 * the user's command, then the rest of the command must
		 * start with white space. */
		j = strspn(arg, AXA_WHITESPACE);
		if (j == 0) {
			/* Handle blanks part of the command and before
			 * the mismatch. */
			j = strspn(--arg, AXA_WHITESPACE);
		}
		/* Trim blanks & use the rest of the string as the argument. */
		if (j != 0) {
			if (ce->need_args == NO) {
				/* arg not allowed */
				error_help_cmd(tag, op);
				return (false);
			}

			if (best_ce) {
				error_help_cmd(tag, op);
				return (false);
			}

			best_argp = arg+j;
			best_ce = ce;
			continue;
		}
	}

	if (best_ce)
		return (run_cmd(tag, op, best_argp, best_ce));

	/* run an unambiguous partial command */
	if (ce1 != NULL && (ce1->help_str != NULL || num_iss <= 1))
		return (run_cmd(tag, op, "", ce1));

	if (op[0] == '?') {
		help_cmd(tag, op+1, NULL);
		return (true);
	}
	error_msg("unrecognized command \"%s\"", op);
	return (false);
}

/*
 * Get an leading tag on a command
 */
static axa_tag_t
cmd_tag(const char **cur_cmdp)
{
	axa_tag_t tag;
	const char *cur_cmd;
	char *p;

	cur_cmd = *cur_cmdp;
	if (cur_cmd[0] == '*' && AXA_IS_WHITE(cur_cmd[1])) {
		tag = AXA_TAG_NONE;
		cur_cmd += 2;
	} else {
		tag = strtoul(cur_cmd, &p, 10);
		if (tag == AXA_TAG_NONE || !AXA_IS_WHITE(*p)) {
			tag = AXA_TAG_NONE;
		} else {
			cur_cmd = p;
		}
	}
	cur_cmd += strspn(cur_cmd, AXA_WHITESPACE);
	*cur_cmdp = cur_cmd;
	return (tag);
}


static size_t
help_cmd_snprint(char *buf, size_t buf_len, const cmd_tbl_entry_t *help_ce)
{
	if (help_ce->help_str == NULL)
		return (0);

	snprintf(buf, buf_len, " %s", help_ce->help_str);
	return (strlen(buf));
}

static void
help_usage_print(const cmd_tbl_entry_t *ce)
{
	const char *bol, *p, *eol;

	if (ce == NULL)
		return;
	bol = ce->usage_str;
	if (bol == NULL)
		return;

	while (*bol != '\0') {
		while (*bol == ' ' || *bol == '\n')
			++bol;
		eol = bol;
		p = bol;
		for (;;) {
			if (*p == ' ' || *p == '\n' || *p == '\0') {
				if (p - bol >= 64)
					break;
				eol = p;
				if (*p == '\0' || *p == '\n')
					break;
			}
			++p;
		}
		if (*bol != '\0')
			printf("%8s%.*s\n", "", (int)(eol-bol), bol);
		bol = eol;
	}
}

int
help_cmd(axa_tag_t tag AXA_UNUSED, const char *arg,
	 const cmd_tbl_entry_t *ce0 AXA_UNUSED)
{
	bool iss;
	int found;			/* 0=partial ISS, 1=iss, 2=exact */
	int found_len;			/* best partial ISS */
	bool stealth;			/* true=hidden command is only match */
	const cmd_tbl_entry_t *ce;
	const cmd_tbl_entry_t *help_ce, *usage_ce;
	int num_help;
	char buf[160];
	size_t hlen;
	const char *p;

	/* Ignore a tag. */
	cmd_tag(&arg);

	/* See if the string matches one or more commands. */
	found = -1;
	found_len = -1;
	stealth = true;
	if (arg != NULL && *arg != '\0') {
		for (ce = cmds_tbl; ce <= AXA_LAST(cmds_tbl); ++ce) {
			if (ce->mode != mode && ce->mode != BOTH)
				continue;
			p = cmd_cmp(arg, ce->cmd, &iss);
			if (p == NULL) {
				if (!iss) {
					/* complete match */
					found = 2;
				} else if (found < 1) {
					/* target is initial substring of
					 * command; note if it is best so far */
					found = 1;
				}
				if (ce->help_str != NULL)
					stealth = false;
			} else if (p != arg && found <= 0) {
				/* target has an initial substring that
				 * matches initial substring of command */
				found = 0;
				found_len = max(found_len, p-arg);
			}
		}
	}
	/* If we found something, show it */
	if (found > 0) {
		help_ce = NULL;
		usage_ce = NULL;
		num_help = 0;
		for (ce = cmds_tbl; ce <= AXA_LAST(cmds_tbl); ++ce) {
			if (ce->mode != mode && ce->mode != BOTH)
				continue;
			if (ce->help_str != NULL) {
				/* Show help for a matching synonym. */
				help_ce = ce;
			} else if (!stealth) {
			/* don't show hidden command if we have better */
				continue;
			}
			if (help_ce == NULL)
				continue;
			p = cmd_cmp(arg, ce->cmd, &iss);
			/* don't show a command that does not match at all */
			if (p == arg)
				continue;
			/* don't show commands that share initial substring
			 * with target if we have better */
			if (p != NULL && found > 0)
				continue;

			/* show commands for which the target is an initial
			 * substring only if we do not have better */
			if (found > 1 && iss)
				continue;
			if (p != NULL && found_len > p-arg)
				continue;

			help_cmd_snprint(buf, sizeof(buf), help_ce);
			printf(" %s%s\n", "", buf);
			++num_help;
			usage_ce = help_ce;\
			help_ce = NULL;
		}
		if (num_help == 1)
			help_usage_print(usage_ce);
		return (1);
	} else if (arg && strlen(arg)) {
		printf("No matching help topic could be found\n");
		return (1);
	}

	/* talk about all of the commands */
	printf("  %s AXA protocol %d\n", axa_get_version(), AXA_P_PVERS);

	for (ce = cmds_tbl; ce <= AXA_LAST(cmds_tbl); ++ce) {
		if (ce->mode != mode && ce->mode != BOTH)
			continue;
		hlen = help_cmd_snprint(buf, sizeof(buf), ce);
		if (hlen == 0)
			continue;
		printf("    %s\n", buf);
	}
	fputc('\n', stdout);

	return (1);
}

static int AXA_NORETURN
exit_cmd(axa_tag_t tag AXA_UNUSED, const char *arg AXA_UNUSED,
	 const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	stop(EX_OK);
}

static int
error_mode_cmd(axa_tag_t tag AXA_UNUSED, const char *arg,
	       const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	const char *setting;

	setting = arg;
	word_cmp(&setting, "mode");
	if (setting[0] != '\0') {
		if (word_cmp(&setting, "off")) {
			eclose = false;
		} else if (word_cmp(&setting, "disconnect")
			   || word_cmp(&setting, "on")
			   || word_cmp(&setting, "close")) {
			eclose = true;
		} else {
			return (-1);
		}
	}
	if (verbose > 0 || arg[0] == '\0') {
		if (eclose)
			printf("    error mode disconnect\n");
		else
			printf("    error mode off\n");
	}
	return (1);
}

static int
debug_cmd(axa_tag_t tag AXA_UNUSED, const char *arg,
	  const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	const char *setting;
	u_long l;
	char *p;

	setting = arg;
	if (setting[0] != '\0') {
		if (word_cmp(&setting, "quiet")) {
			axa_debug = 0;
			quiet = true;
		} else if (word_cmp(&setting, "off")) {
			axa_debug = 0;
			quiet = false;
		} else if (word_cmp(&setting, "on")) {
			quiet = false;
			++axa_debug;
		} else {
			l = strtoul(setting, &p, 10);
			if (*p != '\0')
				return (-1);
			axa_debug = l <= AXA_DEBUG_MAX ? l :
				AXA_DEBUG_MAX;
			quiet = false;
		}
		AXA_DEBUG_TO_NMSG(axa_debug);
	}
	if (axa_debug > 1 || arg[0] == '\0') {
		if (axa_debug == 0) {
			if (quiet)
				printf("    debug quiet\n");
			else
				printf("    debug off\n");
		} else if (axa_debug == 1) {
			printf("    debug on\n");
		} else {
			printf("    debug on+%d\n", axa_debug-1);
		}
	}
	return (1);
}

static int
verbose_cmd(axa_tag_t tag AXA_UNUSED, const char *arg,
	    const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	const char *setting;
	u_long l;
	char *p;

	setting = arg;
	if (setting[0] != '\0') {
		if (word_cmp(&setting, "off")) {
			verbose = 0;
		} else if (word_cmp(&setting, "on")) {
			++verbose;
		} else {
			l = strtoul(setting, &p, 10);
			if (*p != '\0')
				return (-1);
			verbose = l;
		}
	}
	if (verbose > 1 || arg[0] == '\0') {
		if (verbose == 0)
			printf("    verbose off\n");
		else if (verbose == 1)
			printf("    verbose on\n");
		else
			printf("    verbose on+%d\n", verbose-1);
	}
	return (1);
}

int
version_cmd(axa_tag_t tag AXA_UNUSED, const char *arg  AXA_UNUSED,
	    const cmd_tbl_entry_t *ce AXA_UNUSED)
{
#if AXA_P_PVERS_MIN != AXA_P_PVERS_MAX
	printf("%s built using AXA library %s, AXA protocol %d in %d to %d\n",
	       axa_prog_name, axa_get_version(),
	       AXA_P_PVERS, AXA_P_PVERS_MIN, AXA_P_PVERS_MAX);
#else
	printf("%s built using AXA library: %s, AXA protocol: %d\n",
	       axa_prog_name, axa_get_version(), AXA_P_PVERS);
#endif
	return (1);
}

static int
source_cmd(axa_tag_t tag AXA_UNUSED, const char *arg,
	   const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	if (in_file_cur >= MAX_IN_FILES-1) {
		error_msg("\"source\" nesting too deep");
		return (0);
	}

	in_files[in_file_cur+1].lineno = 0;
	in_files[in_file_cur+1].f = fopen(arg, "r");
	if (in_files[in_file_cur+1].f == NULL) {
		error_msg("fopen(%s): %s", arg, strerror(errno));
		return (0);
	}
	in_files[in_file_cur+1].name = axa_strdup(arg);
	++in_file_cur;

	return (1);
}

static int
disconnect_cmd(axa_tag_t tag AXA_UNUSED, const char *arg AXA_UNUSED,
	       const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	if (!AXA_CLIENT_OPENED(&client)) {
		fputs("not connected to a server\n", stdout);
	} else {
		disconnect(true);
	}
	return (1);
}

static int
alias_cmd(axa_tag_t tag AXA_UNUSED, const char *arg0 AXA_UNUSED,
	    const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	/* Check for config-file-specified alias first. */
	axa_client_config_alias_print();

	return (1);
}


static int
connect_cmd(axa_tag_t tag AXA_UNUSED, const char *arg0,
	    const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	const char *arg;

	if (arg0[0] == '\0') {
		if (!AXA_CLIENT_OPENED(&client)) {
			fputs("not connected to a server\n", stdout);
		} else if (client.hello == NULL) {
			printf("connecting to %s\n", client.io.label);
		} else {
			printf("connected to \"%s\"\n    %s\n",
			       client.hello, client.io.label);
			printf("    connected for: %s\n",
				convert_timeval(&connect_time));
			if (client.io.tls_info != NULL)
				printf("    %s\n", client.io.tls_info);
			count_print(false);
			if (mode == RAD)
				return (srvr_send(tag, AXA_P_OP_RADU, NULL, 0));
		}
		return (1);
	}

	/* Check for config-file-specified alias first. */
	arg = axa_client_config_alias_chk(arg0);
	arg = arg ? arg : arg0;

	if (AXA_CLIENT_OPENED(&client))
		disconnect(false);

	axa_client_backoff_reset(&client);
	switch (axa_client_open(&emsg, &client, arg, mode == RAD,
				axa_debug > AXA_DEBUG_TRACE,
				256*1024, true)) {
	case AXA_CONNECT_ERR:
	case AXA_CONNECT_TEMP:
		error_msg("%s", emsg.c);
		return (0);
	case AXA_CONNECT_DONE:
		break;
	case AXA_CONNECT_NOP:
	case AXA_CONNECT_USER:
		if (axa_debug >= AXA_DEBUG_TRACE) {
			clear_prompt();
			printf("send %s\n", emsg.c);
		}
		break;
	case AXA_CONNECT_INCOM:
		/* Wait here until the connection is complete or fails,
		 * because user commands that would send AXA messages will
		 * fail before the connection is complete. */
		while (AXA_CLIENT_OPENED(&client)
		       && !AXA_CLIENT_CONNECTED(&client)) {
			if (interrupted) {
				disconnect(true);
				return (1);
			}
			io_wait(false, true, INT_MAX);
		}
	}

	if (packet_counting)
		packet_count = packet_count_total;

	gettimeofday(&connect_time, NULL);
	return (1);
}

static int
out_cmd_pcap_if(const char *ifname)
{
	char ether[32];
	char errbuf[PCAP_ERRBUF_SIZE];
	const struct ether_addr *eaddr;
	const char *p;
	int i;

	memset(&out_mac, 0, sizeof(out_mac));
	p = strchr(ifname, '/');
	memset(ether, 0, sizeof(ether));
	if (p != NULL) {
		memcpy(ether, ifname, min(sizeof(ether), (size_t)(p-ifname)));
		ifname = p+1;
	}

	out_pcap = pcap_create(ifname, errbuf);
	if (out_pcap == NULL) {
		error_msg("pcap_create(%s): %s", ifname, errbuf);
		return (0);
	}
	i = pcap_activate(out_pcap);
	if (i != 0) {
		error_msg("pcap_activate(%s): %s",
			  ifname, pcap_geterr(out_pcap));
		pcap_close(out_pcap);

		out_pcap = NULL;
		return (0);
	}
	out_pcap_datalink = pcap_datalink(out_pcap);
	switch (out_pcap_datalink) {
	case DLT_EN10MB:
		if (ether[0] != '\0') {
			/* ether_aton_r() is not available on all systems,
			 * and ether_aton() is safe here. */
			eaddr = ether_aton(ether);
			if (eaddr != NULL) {
				out_mac.dst = *eaddr;
			} else if (ether_hostton(ether, &out_mac.dst) != 0) {
				error_msg("cannot convert \"%s\""
					  " to an address; using 0:0:0:0:0:0",
					  ether);
				memset(&out_mac, 0, sizeof(out_mac));
			}
		}
		out_mac.etype = htons(0x800);
		memcpy(out_buf, &out_mac, sizeof(out_mac));
		out_buf_base = sizeof(out_mac);
		break;
	case DLT_NULL:
	case DLT_LOOP:
		if (ether[0] != '\0')
			error_msg("ignoring MAC address \"%s\""
				  " for loopback interface %s",
				  ether, ifname);
		out_buf_base = sizeof(uint32_t);
		break;
	default:
		error_msg("cannot output to %s"
			  " with unknown datalink type %d",
			  ifname, out_pcap_datalink);
		pcap_close(out_pcap);
		return (0);
	}

	return (1);
}

static int
out_cmd(axa_tag_t tag AXA_UNUSED, const char *arg,
	const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	u_long l;
	char *count, *p;
	int result;

	if (arg[0] == '\0') {
		if (!out_on) {
			fputs("not forwarding messages\n", stdout);
		} else if (output_counting) {
			printf("forwarding %d of total %d messages to %s\n",
			       output_count, output_count_total, out_addr);
		} else {
			printf("forwarding messages to %s\n", out_addr);
		}
		if (out_on_nmsg == true)
			printf("output buffering is %s\n",
				output_buffering == true ? "on" : "off");
		return (1);
	}

	out_close(verbose > 0);

	if (word_cmp(&arg, "off") || word_cmp(&arg, "stop"))
		return (1);

	out_addr = axa_strdup(arg);

	count = strpbrk(out_addr, AXA_WHITESPACE);
	if (count != NULL) {
		*count++ = '\0';
		count += strspn(count, AXA_WHITESPACE);
		l = strtoul(count, &p, 10);
		if (p == count) {
			out_close(false);
			return (-1);
		}
		p += strspn(p, AXA_WHITESPACE);
		if (*p != '\0') {
			out_close(false);
			return (-1);
		}
		output_counting = true;
		output_count = l;
		output_count_total = l;
	}
	output_errno = -1;

	if (AXA_CLITCMP(out_addr, "pcap:")) {
		result = out_cmd_pcap_file(strchr(out_addr, ':')+1, false);
	} else	if (AXA_CLITCMP(out_addr, "pcap-fifo:")) {
		result = out_cmd_pcap_file(strchr(out_addr, ':')+1, true);
	} else	if (AXA_CLITCMP(out_addr, "pcap-if:")) {
		result = out_cmd_pcap_if(strchr(out_addr, ':')+1);
	} else if (AXA_CLITCMP(out_addr, "nmsg:")) {
		result = axa_open_nmsg_out(&emsg, &out_nmsg_output,
					   &out_sock_type,
					   strchr(out_addr, ':')+1,
					   output_buffering);
		if (result <= 0)
			error_msg("%s", emsg.c);
		out_on_nmsg = true;
	} else {
		result = -1;
	}

	if (result > 0) {
		out_on = true;
	} else {
		out_close(false);
	}
	return (result);
}

static int
count_cmd(axa_tag_t tag AXA_UNUSED, const char *arg,
	  const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	u_long l;
	char *p;

	if (arg[0] != '\0') {
		if (word_cmp(&arg, "off")) {
			if (packet_counting) {
				packet_counting = false;
				packet_count = 0;
				packet_count_total = 0;
			}
		} else {
			l = strtoul(arg, &p, 10);
			if (p == arg)
				return (-1);
			p += strspn(p, AXA_WHITESPACE);
			if (*p != '\0')
				return (-1);
			packet_counting = true;
			packet_count = l;
			packet_count_total = l;
		}
		return (1);
	}

	count_print(true);
	return (1);
}

static int
ciphers_cmd(axa_tag_t tag AXA_UNUSED, const char *arg,
	   const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	const char *cipher;

	if (arg[0] == '\0') {
		cipher = axa_tls_cipher_list(&emsg, NULL);
		if (cipher == NULL || *cipher == '\0')
			printf("next TLS cipher: \"\"\n");
		else
			printf("next TLS cipher: %s\n",
			       cipher);
		if (client.io.tls_info != NULL)
			printf("    current: %s\n",
			       client.io.tls_info);

	} else if (axa_tls_cipher_list(&emsg, arg) == NULL) {
		error_msg("%s", emsg.c);
		return (0);
	}
	return (1);
}

static int
nop_cmd(axa_tag_t tag, const char *arg AXA_UNUSED,
	const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	return (srvr_send(tag, AXA_P_OP_NOP, NULL, 0));
}

static int
mode_cmd(axa_tag_t tag AXA_UNUSED, const char *arg,
	 const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	const char *setting;

	setting = arg;
	if (setting[0] != '\0') {
		if (word_cmp(&setting, "sra")) {
            if (mode == RAD && AXA_CLIENT_CONNECTED(&client)) {
                printf("  can't change mode while connected to server\n");
                return (-1);
            }
			mode = SRA;
		} else if (word_cmp(&setting, "rad")) {
            if (mode == SRA && AXA_CLIENT_CONNECTED(&client)) {
                printf("  can't change mode while connected to server\n");
                return (-1);
            }
			mode = RAD;
		} else {
			return (-1);
		}
	}

	if (verbose > 0 || arg[0] == '\0') {
		switch (mode) {
		case SRA:
			printf("    SRA mode\n");
			break;
		case RAD:
			printf("    RAD mode\n");
			break;
		case BOTH:
		default:
			AXA_FAIL("impossible mode");
		}
	}
	return (1);
}

static int
sra_mode_cmd(axa_tag_t tag, const char *arg,
	     const cmd_tbl_entry_t *ce)
{
	word_cmp(&arg, "mode");
	if (arg[0] != '\0')
		return (-1);
	return (mode_cmd(tag, "sra", ce));
}

static int
rad_mode_cmd(axa_tag_t tag, const char *arg,
	     const cmd_tbl_entry_t *ce)
{
	word_cmp(&arg, "mode");
	if (arg[0] != '\0')
		return (-1);
	return (mode_cmd(tag, "rad", ce));
}

static int
user_cmd(axa_tag_t tag, const char *arg,
	 const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	axa_p_user_t user;

	if (strlen(arg) >= sizeof(user.name)) {
		error_msg("user name \"%s\" is too long", arg);
		return (0);
	}
	strncpy(user.name, arg, sizeof(user.name));
	return (srvr_send(tag, AXA_P_OP_USER, &user, sizeof(user)));
}

static int
sra_watch_cmd(axa_tag_t tag, const char *arg,
	      const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	axa_p_watch_t watch;
	size_t watch_len;

	if (arg[0] == '\0' || word_cmp(&arg, "get") || word_cmp(&arg, "list"))
		return (srvr_send(tag, AXA_P_OP_WGET, NULL, 0));

	if (tag == AXA_TAG_NONE) {
		error_msg("\"watch\" requires a tag");
		return (0);
	}

	if (axa_parse_watch(&emsg, &watch, &watch_len, arg))
		return (srvr_send(tag, AXA_P_OP_WATCH, &watch, watch_len));

	if (emsg.c[0] == '\0')
		return (-1);
	error_msg("%s", emsg.c);
	return (0);
}

static int
rad_watch_cmd(axa_tag_t tag, const char *arg,
	      const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	axa_p_watch_t watch;
	size_t watch_len;

	if (tag == AXA_TAG_NONE) {
		error_msg("\"watch\" requires a tag");
		return (0);
	}

	if (axa_parse_rad_watch(&emsg, &watch, &watch_len, arg))
		return (srvr_send(tag, AXA_P_OP_WATCH, &watch, watch_len));

	if (emsg.c[0] == '\0')
		return (-1);
	error_msg("%s", emsg.c);
	return (0);
}

static int
list_cmd(axa_tag_t tag, const char *arg, const cmd_tbl_entry_t *ce)
{
	if (mode == RAD) {
		return (srvr_send(tag, AXA_P_OP_AGET, NULL, 0));
	}

	if (word_cmp(&arg, "watches")
	    || (arg[0] == '\0'
		&& ce != NULL && strcmp(ce->cmd, "list watches") == 0))
		return (srvr_send(tag, AXA_P_OP_WGET, NULL, 0));
	if (word_cmp(&arg, "channels")
	    || (arg[0] == '\0'
		&& ce != NULL && (strcmp(ce->cmd, "list channels") == 0
		|| strcmp(ce->cmd, "get channels") == 0)))
		return (srvr_send(tag, AXA_P_OP_CGET, NULL, 0));

	return (-1);
}

static int
delete_cmd(axa_tag_t tag, const char *arg,
	   const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	if (mode == SRA) {
		(void)word_cmp(&arg, "watches");
	} else {
		/* ignore "anomaly" but take "a" to mean "all" and so
		 * do not match "a" as if it were "anomaly". */
		if (strcasecmp(arg, "a") != 0)
			(void)(word_cmp(&arg, "anomaly"));
	}
	if (word_cmp(&arg, "all"))
		return (srvr_send(tag, AXA_P_OP_ALL_STOP, NULL, 0));
	if (*arg == '\0') {
		if (tag == AXA_TAG_NONE)
			return (srvr_send(tag, AXA_P_OP_ALL_STOP, NULL, 0));
		return (srvr_send(tag, AXA_P_OP_STOP, NULL, 0));
	}
	return (-1);
}

static int
channel_on_off(axa_tag_t tag, const char *arg, bool on)
{
	axa_p_channel_t channel;
	axa_p_ch_t ch;

	ch = 0;
	memset(&channel, 0, sizeof(channel));
	if (!axa_parse_ch(&emsg, &ch, arg, strlen(arg), true, true)) {
		error_msg("%s", emsg.c);
		return (0);
	}
	channel.ch = ch;
	channel.ch = AXA_H2P_CH(channel.ch);
	channel.on = on ? 1 : 0;
	return (srvr_send(tag, AXA_P_OP_CHANNEL, &channel, sizeof(channel)));
}

static int
channel_cmd(axa_tag_t tag, const char *arg,
       const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	axa_p_ch_buf_t arg1_buf, arg2_buf;
	const char *arg1, *arg2;

	if (arg[0] == '\0' || word_cmp(&arg, "get") || word_cmp(&arg, "list"))
		return (srvr_send(tag, AXA_P_OP_CGET, NULL, 0));

	memset(&arg1_buf, 0, sizeof(arg1_buf));
	memset(&arg2_buf, 0, sizeof(arg2_buf));
	if (0 > axa_get_token(arg1_buf.c, sizeof(arg1_buf),
			      &arg, AXA_WHITESPACE)
	    || 0 > axa_get_token(arg2_buf.c, sizeof(arg2_buf),
				 &arg, AXA_WHITESPACE)
	    || *arg != '\0')
		return (-1);
	arg1 = arg1_buf.c;
	arg2 = arg2_buf.c;

	if (word_cmp(&arg1, "off") || word_cmp(&arg1, "stop"))
		return (channel_on_off(tag, arg2, false));
	if (word_cmp(&arg1, "on"))
		return (channel_on_off(tag, arg2, true));

	if (word_cmp(&arg2, "off") || word_cmp(&arg2, "stop"))
		return (channel_on_off(tag, arg1, false));
	if (word_cmp(&arg2, "on"))
		return (channel_on_off(tag, arg1, true));

	return (-1);
}

static int
anom_cmd(axa_tag_t tag, const char *arg,
       const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	axa_p_anom_t anom;
	size_t anom_len;

	if (tag == AXA_TAG_NONE) {
		error_msg("\"anomaly\" requires a tag");
		return (0);
	}

	if (axa_parse_anom(&emsg, &anom, &anom_len, arg))
		return (srvr_send(tag, AXA_P_OP_ANOM, &anom, anom_len));

	if (emsg.c[0] == '\0')
		return (-1);
	return (0);
}

static bool				/* false=bad value */
get_rlimit(axa_cnt_t *rlimit, const char *word)
{
	unsigned long n;
	char *p;

	if (*word == '\0' || strcmp("-", word) == 0) {
		*rlimit = AXA_H2P64(AXA_RLIMIT_NA);
		return (true);
	}
	if (word_cmp(&word, "MAXIMUM") || word_cmp(&word, "NEVER")
	    || word_cmp(&word, "OFF") || word_cmp(&word, "NONE")) {
		*rlimit = AXA_H2P64(AXA_RLIMIT_OFF);
		return (true);
	}
	n = strtoul(word, &p, 10);
	if (*p != '\0' || n < 1 || n > AXA_RLIMIT_MAX)
		return (false);

	*rlimit = AXA_H2P64(n);
	return (true);
}

static int
rlimits_cmd(axa_tag_t tag, const char *arg,
	    const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	char sec_buf[32];
	char report_secs_buf[32];
	axa_p_opt_t opt;
	axa_cnt_t rlimit;

	rlimit = 0;
	memset(&opt, 0, sizeof(opt));
	opt.type = AXA_P_OPT_RLIMIT;

	/* Ignore " limits" if present. */
	word_cmp(&arg, "limits");

	if (0 > axa_get_token(sec_buf, sizeof(sec_buf),
			      &arg, AXA_WHITESPACE)
	    || 0 > axa_get_token(report_secs_buf, sizeof(report_secs_buf),
				 &arg, AXA_WHITESPACE)
	    || *arg != '\0')
		return (-1);

	if (!get_rlimit(&rlimit, sec_buf))
		return (-1);
	else
		opt.u.rlimit.max_pkts_per_sec = rlimit;
	if (!get_rlimit(&rlimit, report_secs_buf))
		return (-1);
	else
		opt.u.rlimit.report_secs = rlimit;

	opt.u.rlimit.cur_pkts_per_sec = AXA_RLIMIT_NA;
	return (srvr_send(tag, AXA_P_OP_OPT, &opt,
			  sizeof(opt) - sizeof(opt.u) + sizeof(opt.u.rlimit)));
}

static int
sample_cmd(axa_tag_t tag, const char *arg,
	   const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	axa_p_opt_t opt;
	double d;
	char *p;

	memset(&opt, 0, sizeof(opt));
	opt.type = AXA_P_OPT_SAMPLE;

	if (*arg == '\0') {
		opt.u.sample = AXA_H2P32(AXA_P_OPT_SAMPLE_REQ);

	} else {
		d = strtod(arg, &p);
		if (*p != '\0' && *p != '%' && p[1] != '\0')
			return (-1);
		if (d <= 0.0 || d > 100.0) {
			error_msg("\"%s\" is an invalid sampling rate", arg);
			return (0);
		}
		opt.u.sample = AXA_H2P32(d * AXA_P_OPT_SAMPLE_SCALE);
	}

	return (srvr_send(tag, AXA_P_OP_OPT, &opt,
			  sizeof(opt) - sizeof(opt.u) + sizeof(opt.u.sample)));
}

static int
sndbuf_cmd(axa_tag_t tag, const char *arg,
	   const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	axa_p_opt_t opt;
	char *p;

	memset(&opt, 0, sizeof(opt));
	opt.type = AXA_P_OPT_SNDBUF;

	if (client.io.type != AXA_IO_TYPE_TCP
	    && client.io.type != AXA_IO_TYPE_TLS) {
		error_msg("cannot change the buffer size on %s connections",
			  axa_io_type_to_str(client.io.type));
		return (0);
	}

	if (*arg == '\0') {
		opt.u.bufsize = AXA_H2P32(AXA_P_OPT_SNDBUF_REQ);

	} else {
		opt.u.bufsize = strtoul(arg, &p, 0);
		if (*p != '\0')
			return (-1);
		if (opt.u.bufsize < AXA_P_OPT_SNDBUF_MIN) {
			error_msg("invalid output window size of %s", arg);
			return (0);
		}
		opt.u.bufsize = AXA_H2P32(opt.u.bufsize);
	}

	return (srvr_send(tag, AXA_P_OP_OPT, &opt,
			  sizeof(opt) - sizeof(opt.u) + sizeof(opt.u.bufsize)));
}

static int
pause_cmd(axa_tag_t tag, const char *arg AXA_UNUSED,
	  const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	return (srvr_send(tag, AXA_P_OP_PAUSE, NULL, 0));
}

static int
go_cmd(axa_tag_t tag, const char *arg AXA_UNUSED,
       const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	return (srvr_send(tag, AXA_P_OP_GO, NULL, 0));
}

static int
sleep_cmd(axa_tag_t tag AXA_UNUSED, const char *arg,
	  const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	double s;
	char *p;

	s = strtod(arg, &p);
	if (*p != '\0' || s < 0.001 || s > 1000)
		return (-1);
	io_wait(false, false, s*1000.0);
	return (1);
}

static int
trace_cmd(axa_tag_t tag, const char *arg,
	  const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	axa_p_opt_t opt;
	u_long l;
	char *p;

	l = strtoul(arg, &p, 10);
	if (*p != '\0') {
		if (strcasecmp(arg, "off") == 0)
			l = 0;
		else if (strcasecmp(arg, "on") == 0)
			l = AXA_DEBUG_TRACE;
		else
			return (-1);
	}
	memset(&opt, 0, sizeof(opt));
	opt.type = AXA_P_OPT_TRACE;
	opt.u.trace = AXA_H2P32(l);
	return (srvr_send(tag, AXA_P_OP_OPT, &opt,
			  sizeof(opt) - sizeof(opt.u) + sizeof(opt.u.trace)));
}

static int
acct_cmd(axa_tag_t tag, const char *arg AXA_UNUSED,
	 const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	return (srvr_send(tag, AXA_P_OP_ACCT, NULL, 0));
}

static int
radunit_cmd(axa_tag_t tag, const char *arg AXA_UNUSED,
	 const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	return (srvr_send(tag, AXA_P_OP_RADU, NULL, 0));
}

static int
nmsg_zlib_cmd(axa_tag_t tag AXA_UNUSED, const char *arg AXA_UNUSED,
	 const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	if (out_on == false) {
	printf("    output mode not enabled\n");
		return (0);
	}
	if (out_on_nmsg == false) {
		printf("    output mode not emitting nmsgs\n");
		return (0);
	}
	if (nmsg_zlib == false) {
		nmsg_zlib = true;
		nmsg_output_set_zlibout(out_nmsg_output, true);
		printf("    enabled\n");
	}
	else if (nmsg_zlib == true) {
		nmsg_zlib = false;
		nmsg_output_set_zlibout(out_nmsg_output, false);
		printf("    disabled\n");
	}
	return (1);
}

static int
stats_req_cmd(axa_tag_t tag, const char *arg,
		const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	char *p;
	uint32_t sn;
	_axa_p_stats_req_t stats_req;

	memset(&stats_req, 0, sizeof (stats_req));

	stats_req.version = _AXA_STATS_VERSION;

	/* no argument == summary */
	if (*arg == '\0') {
		printf("    sending stats summary request to server\n");
		stats_req.type = AXA_P_STATS_M_M_SUM;
	}
	/* all == everything */
	else if (word_cmp(&arg,"all")) {
		printf("    sending stats all request to server\n");
		stats_req.type = AXA_P_STATS_M_M_ALL;
	}
	/* username or serial number */
	else {
		sn = strtoul(arg, &p, 0);
		if (*p != '\0') {
			printf("    sending stats request to server for"
				" user \"%s\"\n", arg);
			strlcpy(stats_req.user.name, arg,
					sizeof(stats_req.user.name));
			stats_req.type = AXA_P_STATS_M_M_U;
		}
		else {
			stats_req.sn = AXA_H2P32(sn);
			stats_req.type = AXA_P_STATS_M_M_SN;
			printf("    sending stats request to server for"
					" serial number \"%u\"\n",
					stats_req.sn);
		}
	}
	return (srvr_send(tag, _AXA_P_OP_STATS_REQ, &stats_req,
				sizeof (stats_req)));
}

static int
kill_cmd(axa_tag_t tag, const char *arg,
	 const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	char *p;
	uint32_t sn;
	_axa_p_kill_t kill;

	if (*arg == '\0') {
		error_msg("kill command requires a valid user name or"
				" serial number");
		return (0);
	}

	memset(&kill, 0, sizeof (kill));
	sn = strtoul(arg, &p, 0);
	if (*p != '\0') {
		printf("    sending kill request to server"
				" (kill all sessions belonging to %s)...\n",
				arg);
		strlcpy(kill.user.name, arg, sizeof(kill.user.name));
		kill.mode = AXA_P_KILL_M_U;
	}
	else {
		printf("    sending kill request to server"
				" (kill session serial number %d)...\n", sn);
		kill.sn = AXA_H2P32(sn);
		kill.mode = AXA_P_KILL_M_SN;
	}

	return (srvr_send(tag, _AXA_P_OP_KILL_REQ, &kill, sizeof (kill)));
}

static int
out_cmd_pcap_file(const char *addr, bool want_fifo)
{
	FILE *f;
	struct stat sb;
	bool have_file, have_fifo;

	if (*addr == '\0')
		return (-1);

	if (0 <= stat(addr, &sb)) {
		have_file = true;
		have_fifo = S_ISFIFO(sb.st_mode);
	} else {
		if (errno != ENOENT) {
			error_msg("stat(%s): %s", addr, strerror(errno));
			return (0);
		}
		have_file = false;
		have_fifo = false;
	}

	if (want_fifo && !have_fifo) {
		if (have_file) {
			error_msg("\"%s\" exists but is not a FIFO", addr);
			return (0);
		}
		if (0 > mkfifo(addr, 0600)) {
			error_msg("mkfifo(%s): %s", addr, strerror(errno));
			return (0);
		}
		have_fifo = true;
	}

	/* Create the stdio FILE manually to avoid blocking in the
	 * libpcap fopen() when the file is a pre-existing FIFO. */
	out_fd = open(addr, O_RDWR|O_CREAT|O_TRUNC|O_NONBLOCK|O_CLOEXEC, 0666);
	if (out_fd < 0) {
		error_msg("open(%s): %s", addr, strerror(errno));
		return (0);
	}

	/* drain old bits from what might be a FIFO */
	if (have_fifo) {
		ssize_t rlen;
		size_t n;

		n = 0;
		for (;;) {
			rlen = read(out_fd, out_buf, sizeof(out_buf));
			if (rlen < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK
				    || errno == EINTR)
					break;
				error_msg("read(%s): %s",
					  addr, strerror(errno));
				close(out_fd);
				return (0);
			}
			if (rlen == 0)
				break;
			if (++n >= (1024*1024)/sizeof(out_buf)) {
				error_msg("\"%s\" seems to be an active fifo",
					  addr);
				close(out_fd);
				return (0);
			}
		}
	}

	f = fdopen(out_fd, "w");
	if (f == NULL) {
		error_msg("fdopen(%s): %s", addr, strerror(errno));
		close(out_fd);
		return (0);
	}
	out_pcap = pcap_open_dead(DLT_RAW, AXA_P_WHIT_IP_MAX);
	if (out_pcap == NULL) {
		error_msg("pcap_open_dead() failed");
		fclose(f);
		return (0);
	}
	out_pcap_dumper = pcap_dump_fopen(out_pcap, f);
	if (out_pcap_dumper == NULL) {
		error_msg("pcap_dump_open(%s): %s",
			  addr, pcap_geterr(out_pcap));
		fclose(f);
		return (0);
	}

	/* Cajole the pcap library into writing its header, but we will
	 * write the packets themselves to allow non-blocking output
	 * to tcpdump. */
	if (0 > pcap_dump_flush(out_pcap_dumper)) {
		error_msg("pcap_dump_flush(forward): %s",
			  pcap_geterr(out_pcap));
		out_close(false);
		return (0);
	}

	return (1);
}

static int
buffer_cmd(axa_tag_t tag AXA_UNUSED, const char *arg AXA_UNUSED,
	 const cmd_tbl_entry_t *ce AXA_UNUSED)
{
	if (out_on == false) {
		printf("    output mode not enabled\n");
		return (0);
	}
	if (out_on_nmsg == false) {
		printf("    output mode not emitting nmsgs\n");
		return (0);
	}
	if (output_buffering == false) {
		output_buffering = true;
		nmsg_output_set_buffered(out_nmsg_output, true);
		printf("    enabled\n");
	}
	else if (output_buffering == true) {
		output_buffering = false;
		nmsg_output_set_buffered(out_nmsg_output, false);
		printf("    disabled\n");
	}
	return (1);
}

bool				/* true=ok  false=bad command */
do_cmds(const char *str)
{
	char buf[2048];
	const char *cur;
	ssize_t cur_len;
	axa_tag_t tag;

	for (;;) {
		str += strspn(str, AXA_WHITESPACE";");
		if (*str == '#' || *str == '\0')
			return (true);

		/* Get the next tag, command, and args from the buffer. */
		cur_len = axa_get_token(buf, sizeof(buf), &str, ";\r\n");
		/* command too long */
		if (0 > cur_len)
			return (false);

		cur = buf;
		if (*cur == '#' || *cur == '\0')
			return (true);

		/* Trim trailing whitespace. */
		while (cur_len > 0
		       && strchr(AXA_WHITESPACE, buf[--cur_len]) != NULL) {
			buf[cur_len] = '\0';
		}

		tag = cmd_tag(&cur);

		/* Ignore null command with a tag. */
		if (*cur == '\0')
			continue;

		if (!cmd(tag, cur))
			return (false);
	}
}

int
#if LIBEDIT_IS_UNICODE
getcfn(EditLine *e AXA_UNUSED, wchar_t *buf)
#else
getcfn(EditLine *e AXA_UNUSED, char *buf)
#endif
{
	int i;
	char c = '\0';

	/* Wait until the user types something or a redisplay is faked */
	for (;;) {
		io_wait(true, false, INT_MAX);
		if (interrupted) {
			if (terminated)
				stop(1);
			/* Return with '\0' in the buffer to tell editline(3)
			 * to return immediately
			 * so that the interrupt can be acknowledged. */
			el_set(el_e, EL_UNBUFFERED, 1);
#if LIBEDIT_IS_UNICODE
			*buf = btowc('\0');
#else
			*buf = '\0';
#endif
			return (1);
		}

		/* After EOF from the input,
		 * wait until the server connection breaks
		 * or until we cannot output. */
		if (in_file_cur < 0) {
			if (!AXA_CLIENT_OPENED(&client))
				stop(EX_OK);
			continue;
		}

		AXA_ASSERT(in_file_cur == 0);
		/* Restore the prompt before echoing user's input. */
		if (prompt_cleared.tv_sec != 0)
			reprompt();
		i = read(STDIN_FILENO, &c, 1);
		if (i == 1) {
			gettimeofday(&cmd_input, NULL);
#if LIBEDIT_IS_UNICODE
			*buf = btowc(c);
#else
			*buf = c;
#endif
			return (1);
		}
		close(STDIN_FILENO);
		--in_file_cur;
	}
}

void AXA_NORETURN
usage(void)
{
	const char *sra = "SIE Remote Access Tool (sratool)\n";
	const char *rad = "Real-time Anomaly Detection Tool (radtool)\n";

	printf("%s", mode == SRA ? sra : rad);
	printf("(c) 2013-2017 Farsight Security, Inc.\n");
	printf("%s [options] [commands]\n", axa_prog_name);
	printf("[-c file]\t\tspecify commands file\n");
	printf("[-d]\t\t\tincrement debug level, -ddd > -dd > -d\n");
	printf("[-E ciphers]\t\tuse these TLS ciphers\n");
	printf("[-F file]\t\tspecify AXA fields file\n");
	printf("[-N]\t\t\tdisable command-line prompt\n");
	printf("[-S dir]\t\tspecify TLS certificates directory\n");
	printf("[-V]\t\t\tprint version and quit\n");
	printf("[commands]\t\tquoted string of commands to execute\n");
	exit(EX_USAGE);
}

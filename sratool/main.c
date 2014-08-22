/*
 * SIE Remote Access (SRA) ASCII tool
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

#include "sratool.h"
#include <axa/dns_walk.h>
#include <axa/client.h>

#include <nmsg/vendors.h>
#include <nmsg/sie/defs.h>
#include <nmsg/base/defs.h>
#include <nmsg/base/dnsqr.pb-c.h>
#include <nmsg/sie/newdomain.pb-c.h>
#include <nmsg/base/packet.pb-c.h>

#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#ifdef __linux
#include <netinet/ether.h>
#endif
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
#include <endian.h>
#else
#include <sys/endian.h>
#endif
#include <sysexits.h>
#include <sys/stat.h>
#include <unistd.h>

#include <histedit.h>


static int in_fds[10] = {STDIN_FILENO};
static int in_fd_cur = 0;
static int packet_count;
static bool packet_counting;

static nmsg_input_t nmsg_input;
static nmsg_output_t nmsg_pres;

/* Connection to the SRA server. */
static client_t client;

/* Output packets to this socket */
static bool out_on;
static char *out_addr;
static struct timeval time_out_flush;
#define OUT_FLUSH_MS	100
static struct timeval out_complaint_last;
static bool out_complaint_skipped;
static int out_sock_type;
static pcap_t *out_pcap;
static pcap_dumper_t *out_pcap_dumper;
static int out_fd;
static struct {
	struct ether_addr   dst;
	struct ether_addr   src;
	uint16_t	    etype;
} out_mac;
static uint8_t out_buf[AXA_P_WHIT_IP_MAX*4];
static size_t out_buf_base, out_buf_len;
static nmsg_output_t out_nmsg_output;
static nmsg_msgmod_t out_nmsg_mod = NULL;
static void *out_nmsg_clos;
static bool out_nmsg_mod_checked = false;


/* Use editline() instead of readline() to avoid GPL pollution. */
static History *el_history;
static HistEvent el_event;
static EditLine *el_e = NULL;
static const char *reprompt_str = "\x80";
static bool cmd_started = false;
static bool no_prompt = false;
static struct timeval prompt_cleared;
static struct timeval last_output;
static size_t prompt_len;
static bool interrupted = false;
static bool terminated = false;


static void sra_ssh_flush(void);
static bool do_cmds(const char *cmd_buf);
static void disconnect(bool announce);
static void out_close(bool announce);
static time_t out_flush_ck(const struct timeval *now, time_t delay);
static void out_flush(void);
static void read_srvr(void);
static int srvr_send(axa_tag_t tag, axa_p_op_t op,
		     const void *b, size_t b_len);

static axa_emsg_t emsg;

uint verbose = 0;

bool eclose = false;


static cmd_t help_cmd;
static cmd_t exit_cmd;
static cmd_t error_mode_cmd;
static cmd_t debug_cmd;
static cmd_t verbose_cmd;
static cmd_t version_cmd;
static cmd_t source_cmd;
static cmd_t disconnect_cmd;
static cmd_t connect_cmd;
static cmd_t count_cmd;
static cmd_t out_cmd;
static cmd_t nop_cmd;
static cmd_t mode_cmd;
static cmd_t sra_mode_cmd;
static cmd_t rad_mode_cmd;
static cmd_t user_cmd;
static cmd_t watch_cmd;
static cmd_t list_cmd;
static cmd_t delete_cmd;
static cmd_t ch_cmd;
static cmd_t an_cmd;
static cmd_t rlimits_cmd;
static cmd_t acct_cmd;
static cmd_t pause_cmd;
static cmd_t trace_cmd;
static cmd_t go_cmd;

typedef enum {NO, MB, YES} ternary_t;

typedef enum {SRA, RAD, BOTH} axa_mode_t;
static axa_mode_t protocol_mode;

/* -1=display help message, 0=command failed, 1=success */
typedef struct {
	const char	*cmd;
	cmd_t		(*fnc);
	axa_mode_t	mode;
	ternary_t	need_args;
	ternary_t	need_sock;
	const char	*help_str;
	const char	*usage_str;
} cmd_tbl_entry_t;

static const cmd_tbl_entry_t cmds_tbl[] = {
{"help",		help_cmd,		BOTH,MB, NO,
    "help [cmd]",
    NULL},
{"?",			help_cmd,		BOTH,MB, NO,
    NULL,
    NULL},
{"exit",		exit_cmd,		BOTH,NO, NO,
    "exit",
    NULL},
{"quit",		exit_cmd,		BOTH,NO, NO,
    NULL,
    NULL},
{"error mode",		error_mode_cmd,		BOTH,MB, NO,
    "error mode [disconnect | off]",
    "\"error mode disconnect\" disconnects from the server and exits"
    " when the server reports an error or the connection breaks."
    " In the default mode, \"error mode off\", errors are only reported."},
{"debug",		debug_cmd,		BOTH,MB, NO,
    "debug [on | off | N]",
    "increases or decreases the debugging and tracing messages"
    " that are also controlled by -d."},
{"verbose",		verbose_cmd,		BOTH,MB, NO,
    "verbose [on | off | N]",
    "controls the length of SIE message and IP packet descriptions."
    "The default, \"verbose off\", generally displays one line summaries."},
{"version",		version_cmd,		BOTH,NO, NO,
    "version",
    "shows the software and protocol version."},
{"source",		source_cmd,		BOTH,YES,NO,
    "source filename",
    "Read and execute commands commands from a file"},
{"disconnect",		disconnect_cmd,		BOTH,NO, YES,
    "disconnect",
    "Disconnect from the server"},
{"connect",		connect_cmd,		BOTH,MB, NO,
    "connect {host,port | /uds/socket | {ssh user@host [-zARG]}}",
    "Connect to a server at an IP address or UNIX domain socket or via SSH"},
{"count",		count_cmd,		BOTH,MB, NO,
    "count [#packets | off]",
    "Set terminal output to stop displaying packets after a"
    " number of packets (including immediately with a number of 0),"
    " show the currently remainint count,"
    " or turn off the packet count limit."},
{"mode",		mode_cmd,		BOTH,MB, MB,
    "mode [SRA | RAD]",
    "Show the current command mode or"
    " expect to connect to an SRA or RAD server."},
{"srad",		sra_mode_cmd,		BOTH,MB, MB,
    NULL,
    NULL},
{"radd",		rad_mode_cmd,		BOTH,MB, MB,
    NULL,
    NULL},
{"output",		out_cmd,		BOTH,MB, NO,
    "output [off | nmsg:[tcp:|udp:]host,port | pcap[-fifo]:file"
    "\n               | pcap-if:[dst/]ifname]",
    "Show the state of forwarding or start forwarding data received"
    " from the server.  Received msg messages and IP packets can be"
    " forwarded as nmsg messages to a TCP  or UDP port.  Received IP"
    " packets can be forwarded as a pcap stream to a file or a fifo"
    " created with `mkfio` or in Ethernet frames on a named network"
    " interface to a specified 48-bit address (default 0)."},
{"forward",		out_cmd,		BOTH,MB, NO,
    NULL,
    NULL},
{"fwd",			out_cmd,		BOTH,MB, NO,
    NULL,
    NULL},
{"nop",			nop_cmd,		BOTH,NO,YES,
    "nop",
    "Send a command to the server that does nothing but test the connection"},
{"user",		user_cmd,		BOTH,YES,YES,
    "user name",
    "Send the user name required by the server on a TCP/IP connection or"
    " a UNIX domain socket.\n"
    " SSH connections do not use this command but use the"
    " name negotiated with the ssh protocol."},
{"watch",		watch_cmd,		SRA, MB, YES,
    "tag watch {ip=IP[/n] | dns=[*.]dom | ch=chN | errors}",
    "Tell the SRA server to send nmsg messages or IP packets that are to,"
    " from, or contain the specified IP addresses,\n"
    " that contain the specified domain name,\n"
    " that arrived at the server on the specifed SIE channel,\n"
    " or are SIE messages that could not be decoded.\n"
    " The \"tag\" is the number labeling the watch"},
{"watches",		watch_cmd,		SRA, MB, YES,
    "[tag] watch list",
    "With a tag, list the specified watch.\n"
    " Without a tag, list all watches."},
{"list watches",	list_cmd,		SRA, MB, YES,
    "[tag] list watch",
    "With a tag, list the specified watch.  List all"
    " watches without a tag"},
{"get watches",		list_cmd,		SRA, MB, YES,
    NULL,
    NULL},
{"list channels",	list_cmd,		SRA, MB, YES,
    "list channels",
    "List all SIE channels available to the user on the SRA server."},
{"get channels",	list_cmd,		SRA, MB, YES,
    NULL,
    NULL},
{"list anomaly",	list_cmd,		RAD, MB, YES,
    "[tag] list anomaly",
    "List a specified or all available anomaly detection modules. "},
{"get anomaly",		list_cmd,		RAD, MB, YES,
    NULL,
    NULL},
{"delete watches",	delete_cmd,		SRA, MB, YES,
    "[tag] delete watch [all]",
    "With a tag, stop or delete the specified watch.\n"
    " With \"all\", delete all watches"},
{"delete anomaly",	delete_cmd,		RAD, MB, YES,
    "[tag] delete anomaly [all]",
    "Delete an anomaly detector module specified by tag"
    " or all anomaly detector modules."},
{"delete",		delete_cmd,		BOTH,MB, YES,
    NULL,
    NULL},
{"stop",		delete_cmd,		BOTH,MB, YES,
    NULL,
    NULL},
{"channels",		ch_cmd,			SRA, YES,YES,
    "channel {list | {on | off} {all | chN}}",
    "List available SRA channels or enable or disable"
    " one or all SIE channels."},
{"channels",		ch_cmd,			RAD, YES,YES,
    "channel list",
    "List available SRA channels."},
{"anomaly",		an_cmd,			RAD, YES,YES,
    "tag anomaly name [parameters]",
    "Start the named anomaly detector module.\n"
    " \"Tag\" is the number labeling the module."},
{"rate limits",		rlimits_cmd,		BOTH,MB, YES,
    "rate limits [- | MAX | per-sec] [- | MAX | per-day]"
    "\n                   [- | NEVER | report-secs]",
    "Ask the server to report its rate limits\n"
    " or set rate limits and the interval between rate limit reports."},
{"rlimits",		rlimits_cmd,		BOTH,MB, YES,
    NULL,
    NULL},
{"limits",		rlimits_cmd,		BOTH,MB, YES,
    NULL,
    NULL},
{"pause",		pause_cmd,		BOTH,NO, YES,
    "pause",
    "Tell the SRA server to stop sending data."},
{"go",			go_cmd,			BOTH,NO, YES,
    "go",
    "Tell the SRA server to resume sending data"},
{"trace",		trace_cmd,		BOTH,YES,YES,
    "trace N",
    "Set server trace level"},
{"accounting",		acct_cmd,		BOTH,NO, YES,
    "accounting",
    "Ask the server to report total message counts."},
{"acct",		acct_cmd,		BOTH,NO, YES,
    NULL,
    NULL},
};


static const char *
el_prompt(EditLine *e AXA_UNUSED)
{
	static const char null_prompt[] = "";
	static const char std_prompt[] = "> ";
	static const char out_prompt[] = "output > ";
	const char *prompt;

	if (interrupted)
		return (null_prompt);

	if (no_prompt)
		prompt = null_prompt;
	else if (out_on)
		prompt = out_prompt;
	else
		prompt = std_prompt;

	prompt_cleared.tv_sec = 0;
	prompt_len = strlen(prompt);
	return (prompt);
}

/* Clear the prompt and any partial command to make room output from the
 * server. The history library will eventually be told to restore it. */
void
clear_prompt(void)
{
	const LineInfo *li;
	int llen, i;

	cmd_started = false;
	gettimeofday(&last_output, NULL);

	if (el_e == NULL)
		return;

	if (prompt_cleared.tv_sec == 0) {
		/* user's partial command */
		li = el_line(el_e);
		llen = li->lastchar - li->buffer;
		llen += prompt_len;
		if (llen > 0) {
			/* Erase the prompt and the user's command using
			 * backspaces and blanks instead of '\r' in case
			 * they are longer than the screen width.
			 *
			 * First back up from the current cursor position to
			 * the prompt and then to the start of the prompt. */
			for (i = li->cursor - li->buffer + prompt_len;
			     i > 0;
			     --i)
				fputc('\b', stdout);
			/* Cover everything with blanks. */
			for (i = llen; i > 0; --i)
				fputc(' ', stdout);
			/* Back to the start of the (first) line. */
			for (i = llen; i > 0; --i)
				fputc('\b', stdout);
		}
		fputc('\r', stdout);	/* just in case */
	}
	fflush(stderr);
	fflush(stdout);
	gettimeofday(&prompt_cleared, NULL);
}

static void
sigint(int sig AXA_UNUSED)
{
	interrupted = true;
}

static void
sigterm(int sig AXA_UNUSED)
{
	interrupted = true;
	terminated = true;
}

static void AXA_NORETURN
stop(int status)
{
	if (el_e != NULL) {
		if (el_history)
			history_end(el_history);
		el_end(el_e);
	}
	fflush(stderr);
	fflush(stdout);
	disconnect(false);
	if (nmsg_input != NULL)
		nmsg_input_close(&nmsg_input);
	if (nmsg_pres != NULL)
		nmsg_output_close(&nmsg_pres);	/* this closes stdout */
	out_close(false);
	axa_unload_fields();

	exit(status);
}

static void
eclose_fnc(void)
{
	if (eclose && client.out_sock >= 0) {
		clear_prompt();
		printf("disconnecting from %s after error\n", client.addr);
		disconnect(false);
	}
}

void AXA_PF(1,2)
error_msg(const char *p, ...)
{
	va_list args;

	clear_prompt();

	va_start(args, p);
	vfprintf(stderr, p, args);
	va_end(args);
	fputc('\n', stderr);

	eclose_fnc();
}

static void error_help_cmd(axa_tag_t tag, const char *arg)
{
	eclose_fnc();
	help_cmd(tag, arg);
}

static int				/* 0 or 1 input chars in buf */
cmd_rdy(char *buf)
{
	struct timeval input_start, now;
	time_t poll_ms, cmd_ms, ms;
	struct pollfd pollfds[3];
	int nfds, i;

	gettimeofday(&input_start, NULL);
	for (;;) {
		if (in_fd_cur >= 0) {
			/* We will poll the primary input. */
			pollfds[0].fd = in_fds[in_fd_cur];
			pollfds[0].events = AXA_POLL_IN;
		} else {
			/* After EOF from the primary input,
			 * wait until the server connection breaks
			 * or until we cannot output. */
			if (client.in_sock < 0)
				stop(EX_OK);
			pollfds[0].fd = STDOUT_FILENO;
			pollfds[0].events = 0;
		}
		pollfds[0].revents = 0;
		nfds = 1;
		client.in_poll_nfd = -1;
		client.err_poll_nfd = -1;

		gettimeofday(&now, NULL);

		if (interrupted) {
			poll_ms = 0;

		} else if (client.in_sock < 0) {
			if (prompt_cleared.tv_sec != 0) {
				prompt_cleared.tv_sec = 0;
				*buf = reprompt_str[0];
				return (1);
			}
			/* Wait forever with only the user talking */
			poll_ms = INFTIM;

		} else {
			/* Send a NOP after the user stops typing,
			 * after we have not heard from the server
			 *	to see if the connection is broken,
			 * and at the start to declare our protocol version. */
			if (cmd_started)
				cmd_ms = axa_tv_diff2ms(&now, &input_start);
			else
				cmd_ms = INT_MAX;
			ms = axa_elapsed_ms(&now, &client.alive);
			if ((ms >= AXA_KEEPALIVE_MS || ms < 0)
			    && cmd_ms > 5*1000) {
				srvr_send(AXA_TAG_NONE, AXA_P_OP_NOP, NULL, 0);
				continue;
			}
			poll_ms = AXA_KEEPALIVE_MS - ms;
			if (poll_ms < 0)
				poll_ms = 100;

			/* Give the user 5 seconds without interruption
			 * to finish typing. */
			if (cmd_ms < 5*1000) {
				poll_ms = 5*1000 - cmd_ms;
			} else {
				/* Delay restoring the prompt until
				 * the server has been quiet 0.2 seconds. */
				if (prompt_cleared.tv_sec != 0) {
					ms = axa_elapsed_ms(&now,
							&prompt_cleared);
					if (ms > 200 || ms < 0) {
					    prompt_cleared.tv_sec = 0;
					    *buf = reprompt_str[0];
					    return (1);
					}
					ms = 200 - ms;
					if (poll_ms > ms)
					    poll_ms = ms;
				}

				pollfds[nfds].fd = client.in_sock;
				pollfds[nfds].events = AXA_POLL_IN;
				pollfds[nfds].revents = 0;
				client.in_poll_nfd = nfds++;

				/* Watch stderr from ssh. */
				if (client.err_sock >= 0) {
					pollfds[nfds].fd = client.err_sock;
					pollfds[nfds].events = AXA_POLL_IN;
					pollfds[nfds].revents = 0;
					client.err_poll_nfd = nfds++;
				}

				/* Flush the forwarding buffer
				 * when the SRA server goes quiet. */
				poll_ms = out_flush_ck(&now, poll_ms);
			}

			/* Flush piped output when quiet. */
			if (el_e == NULL && last_output.tv_sec != 0) {
				ms = axa_elapsed_ms(&now, &last_output);
				ms = 200 - ms;
				if (ms < 0)
					ms = 0;
				if (poll_ms > ms)
					poll_ms = ms;
			}
		}

		AXA_ASSERT(nfds <= AXA_DIM(pollfds));

		i = poll(pollfds, nfds, poll_ms);
		if (i < 0 && errno != EINTR)
			axa_fatal_msg(EX_OSERR, "poll(listen socket): %s",
				      strerror(errno));
		if (interrupted) {
			if (terminated || el_e == NULL)
				stop(1);
			*buf = '\0';
			el_set(el_e, EL_UNBUFFERED, 1);
			return (1);
		}
		out_flush_ck(NULL, 0);
		if (i <= 0) {
			/* Flush output to a pipe when quiet. */
			if (el_e == NULL && last_output.tv_sec != 0) {
				fflush(stderr);
				fflush(stdout);
				last_output.tv_sec = 0;
			}
			continue;
		}

		/* Always listen to the user before the server. */
		if (pollfds[0].revents != 0) {
			/* quit when both input and output die. */
			if (in_fd_cur < 0)
				stop(EX_OK);
			/* restore the prompt before echoing user's input */
			if (prompt_cleared.tv_sec != 0) {
				prompt_cleared.tv_sec = 0;
				*buf = reprompt_str[0];
				return (1);
			}
			return (0);
		}

		/* Repeat anything the ssh process says */
		if (client.err_poll_nfd >= 0
		    && pollfds[client.err_poll_nfd].revents != 0)
			sra_ssh_flush();

		/* Process messages from the server. */
		if (client.in_poll_nfd >= 0
		    && pollfds[client.in_poll_nfd].revents != 0)
			read_srvr();
	}
}

static int
getcfn(EditLine *e AXA_UNUSED, char *buf)
{
	int i;

	/* Wait until the user types something or a redisplay is faked */
	for (;;) {
		i = cmd_rdy(buf);
		if (i != 0)
			return (i);

		/* After EOF from the input,
		 * wait until the server connection breaks
		 * or until we cannot output. */
		if (in_fd_cur < 0) {
			if (client.in_sock < 0)
				stop(EX_OK);
			continue;
		}

		i = read(in_fds[in_fd_cur], buf, 1);
		if (i == 1) {
			cmd_started = true;
			return (1);
		}
		close(in_fds[in_fd_cur--]);
	}
}

static void AXA_NORETURN
usage(void)
{
	error_msg("[-VdN] [-F fields] [-c cfile] [commands]\n");
	exit(EX_USAGE);
}

int AXA_NORETURN
main(int argc, char **argv)
{
	const char *fields_file = FIELDS_FILE;
	char cmd_buf[500];
	bool version = false;
	const char *cfile = NULL;
	size_t n;
	nmsg_res res;
	char *p;
	int i;

	axa_set_me(argv[0]);
	axa_set_core();
	axa_client_init(&client);

	if (strcmp(axa_prog_name, "radtool") == 0)
		protocol_mode = RAD;

	if (isatty(STDIN_FILENO))
		el_e = el_init(axa_prog_name, stdin, stdout, stderr);
	if (el_e != NULL) {
		int mode;

		if (0 > el_get(el_e, EL_EDITMODE, &mode) || !mode) {
			el_end(el_e);
			el_e = NULL;
		}
	}
	if (el_e != NULL) {
		/* prefer emacs mode but let the user choose in .editrc */
		el_set(el_e, EL_EDITOR, "emacs");
		/* bind emacs search to ^R */
		el_set(el_e, EL_BIND, "\022", "em-inc-search-prev", NULL);
		el_source(el_e, NULL);
		el_history = history_init();
		history(el_history, &el_event, H_SETSIZE, 800);
		el_set(el_e, EL_HIST, history, el_history);
		el_set(el_e, EL_PROMPT, el_prompt);
		el_set(el_e, EL_SIGNAL, 1);
		el_set(el_e, EL_GETCFN, getcfn);
		el_set(el_e, EL_BIND, reprompt_str, "ed-redisplay", NULL);
	}

	while ((i = getopt(argc, argv, "VdNF:c:")) != -1) {
		switch (i) {
		case 'V':
			version = true;
			break;

		case 'd':
			++axa_debug;
			break;

		case 'N':
			no_prompt = true;
			break;

		case 'F':
			fields_file = optarg;
			break;

		case 'c':
			if (cfile != NULL)
				fprintf(stderr,
					"only one -c allowed;"
					" ignoring all but the last\n");
			cfile = optarg;
			break;

		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (version) {
		version_cmd(AXA_TAG_NONE, "");
		if (argc == 0)
			stop(EX_OK);
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, sigint);
	signal(SIGTERM, sigterm);
	signal(SIGHUP, sigterm);

	AXA_DEBUG_TO_NMSG();
	res = nmsg_init();
	if (res != nmsg_res_success)
		error_msg("nmsg_init(): %s", nmsg_res_lookup(res));
	nmsg_input = nmsg_input_open_null();
	AXA_ASSERT(nmsg_input != NULL);
	nmsg_pres = nmsg_output_open_pres(STDOUT_FILENO);

	axa_load_fields(fields_file);

	/* Answer commands from the control file. */
	if (cfile != NULL) {
		axa_asprintf(&p, "source %s", cfile);
		if (el_e != NULL)
			history(el_history, &el_event, H_ENTER, p);
		if (!do_cmds(p))
			fprintf(stderr, " initial \"-c %s\" failed\n", cfile);
		free(p);
	}

	/* Answer commands from the command line. */
	while (argc != 0) {
		if (el_e != NULL)
			history(el_history, &el_event, H_ENTER, *argv);
		if (!do_cmds(*argv)) {
			fputs(" initial commands aborted\n", stderr);
			break;
		}

		++argv;
		--argc;
	}

	/* Look for commands from stdin. */
	for (;;) {
		/* get a command line */
		cmd_started = false;
		fflush(stderr);
		fflush(stdout);
		if (el_e != NULL) {
			const char *cmd;
			int cmd_len;

			cmd = el_gets(el_e, &cmd_len);
			if (interrupted) {
				interrupted = false;
				el_set(el_e, EL_UNBUFFERED, 0);
				el_reset(el_e);
				fputs(" (int)\n", stdout);
				if (prompt_cleared.tv_sec != 0) {
					packet_counting = true;
					packet_count = 0;
				}
				continue;
			}
			if (cmd == NULL) {
				fputc('\n', stdout);
				stop(EX_OK);
			}

			/* save nontrivial lines not sourced from files */
			if (in_fd_cur == 0
			    && *(cmd+strspn(cmd, AXA_WHITESPACE)) != '\0')
				history(el_history, &el_event, H_ENTER, cmd);

			strlcpy(cmd_buf, cmd, sizeof(cmd_buf));

		} else {
			n = 0;
			for (;;) {
				getcfn(NULL, &cmd_buf[n]);
				if (cmd_buf[n] == reprompt_str[0])
					continue;
				if (cmd_buf[n++] == '\n'
				    || n >= sizeof(cmd_buf)-1)
					break;
			}
			cmd_buf[n] = '\0';
		}

		if (!do_cmds(cmd_buf)) {
			fputs(" ?\n", stderr);
			fflush(stdout);
		}
	}
}

/* Compare command names ignoring case. */
static const char *			/* NULL or mismatch in user string */
cmd_cmp(const char *user,		/* from the user */
	const char *op,			/* from command table entry */
	bool *iss)			/* exact initial substring match */
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

	if (ce->need_sock == YES && client.out_sock <0) {
		error_msg("\"%s\" requires a connection to a server",
			  ce->cmd);
		return (0);
	}

	i = ce->fnc(tag, arg);
	if (i > 0)
		return (true);

	eclose_fnc();
	if (i < 0)
		error_help_cmd(tag, op);
	return (false);
}

static bool				/* true=ok false=bad command */
cmd(axa_tag_t tag, const char *op)
{
	const char *arg;
	int j;
	const cmd_tbl_entry_t *ce, *ce1;
	bool iss;

	/* Look for the string as a command and execute it if we find it. */
	ce1 = NULL;
	for (ce = cmds_tbl; ce <= AXA_LAST(cmds_tbl); ++ce) {
		if (ce->mode != protocol_mode && ce->mode != BOTH)
			continue;
		arg = cmd_cmp(op, ce->cmd, &iss);
		if (arg == op)
			continue;

		/* If the command table entry and the command completely
		 * matched, then infer a null argument. */
		if (arg == NULL) {
			if (iss) {
				/* continue searching after the 1st or a
				 * duplicate initial substring match */
				if (ce1 == NULL || ce1->fnc == ce->fnc) {
					ce1 = ce;
					continue;
				}
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
		 * start with white space.
		 */
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
			return (run_cmd(tag, op, arg+j, ce));
		}
	}
	/* run an unambigious partial command */
	if (ce1 != NULL)
		return (run_cmd(tag, op, "", ce1));

	if (op[0] == '?') {
		help_cmd(tag, op+1);
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

static bool				/* true=ok  false=bad command */
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

static int
help_cmd(axa_tag_t tag AXA_UNUSED, const char *arg)
{
	bool iss;
	int found;			/* 0=partial ISS, 1=iss, 2=exact */
	int found_len;			/* best partial ISS */
	bool stealth;			/* true=hidden command is only match */
	const cmd_tbl_entry_t *ce;
	const cmd_tbl_entry_t *help_ce, *usage_ce;
	int num_help;
	char buf[120];
	size_t hlen, llen;
	const char *p;

	/* Ignore a tag. */
	cmd_tag(&arg);

	/* See if the string matches one or more commands. */
	found = -1;
	found_len = -1;
	stealth = true;
	if (arg != NULL && *arg != '\0') {
		for (ce = cmds_tbl; ce <= AXA_LAST(cmds_tbl); ++ce) {
			if (ce->mode != protocol_mode && ce->mode != BOTH)
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
	if (found >= 0) {
		help_ce = NULL;
		usage_ce = NULL;
		num_help = 0;
		for (ce = cmds_tbl; ce <= AXA_LAST(cmds_tbl); ++ce) {
			if (ce->mode != protocol_mode && ce->mode != BOTH)
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
	}

	/* talk about all of the commands */
	printf("  "AXA_PVERS_STR" AXA protocol %d\n", AXA_P_PVERS);

	llen = 0;
	for (ce = cmds_tbl; ce <= AXA_LAST(cmds_tbl); ++ce) {
		if (ce->mode != protocol_mode && ce->mode != BOTH)
			continue;
		hlen = help_cmd_snprint(buf, sizeof(buf), ce);
		if (hlen == 0)
			continue;
		if (llen != 0 &&  (llen > 35 || llen + hlen > 79)) {
			fputc('\n', stdout);
			llen = 0;
		}
		if (llen == 0) {
			llen = printf("     %-30s", buf);
		} else {
			printf("    %s\n", buf);
			llen = 0;
		}
	}
	if (llen != 0)
		fputc('\n', stdout);

	return (1);
}

static int AXA_NORETURN
exit_cmd(axa_tag_t tag AXA_UNUSED, const char *arg AXA_UNUSED)
{
	stop(EX_OK);
}

static int
error_mode_cmd(axa_tag_t tag AXA_UNUSED, const char *arg)
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
debug_cmd(axa_tag_t tag AXA_UNUSED, const char *arg)
{
	const char *setting;
	u_long l;
	char *p;

	setting = arg;
	if (setting[0] != '\0') {
		if (word_cmp(&setting, "off")) {
			axa_debug = 0;
		} else if (word_cmp(&setting, "on")) {
			++axa_debug;
		} else {
			l = strtoul(setting, &p, 10);
			if (*p != '\0')
				return (-1);
			axa_debug = l;
		}
		AXA_DEBUG_TO_NMSG();
	}
	if (axa_debug > 1 || arg[0] == '\0') {
		if (axa_debug == 0)
			printf("    debug off\n");
		else if (axa_debug == 1)
			printf("    debug on\n");
		else
			printf("    debug on+%d\n", axa_debug-1);
	}
	return (1);
}

static int
verbose_cmd(axa_tag_t tag AXA_UNUSED, const char *arg)
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

static int
version_cmd(axa_tag_t tag AXA_UNUSED, const char *arg  AXA_UNUSED)
{
	printf("%s "AXA_PVERS_STR" AXA protocol %d\n",
	       axa_prog_name, AXA_P_PVERS);
	return (1);
}

static int
source_cmd(axa_tag_t tag AXA_UNUSED, const char *arg)
{
	if (in_fd_cur+1 >= AXA_DIM(in_fds)) {
		error_msg("\"source\" nesting too deep");
		return (0);
	}

	in_fds[in_fd_cur+1] = open(arg, O_RDONLY | O_CLOEXEC);
	if (in_fds[in_fd_cur+1] < 0) {
		error_msg("open(%s): %s", arg, strerror(errno));
		return (0);
	}
	++in_fd_cur;
	return (1);
}

static void
disconnect(bool announce)
{
	axa_client_close(&client);

	sra_ssh_flush();

	if (announce) {
		clear_prompt();
		printf("disconnected\n");
	}
	out_close(announce && verbose > 0);
}

static int
disconnect_cmd(axa_tag_t tag AXA_UNUSED, const char *arg AXA_UNUSED)
{
	disconnect(true);
	return (1);
}

static int
connect_cmd(axa_tag_t tag AXA_UNUSED, const char *arg)
{
	if (arg[0] == '\0') {
		if (client.out_sock < 0) {
			fputs("not connected to a server\n", stdout);
		} else {
			printf("connected to %s\n", client.addr);
		}
		return (1);
	}

	if (client.out_sock >= 0)
		disconnect(false);

	client.retry.tv_sec = 0;
	client.backoff = 0;
	if (!axa_client_open(&emsg, &client, arg, axa_debug, false)) {
		error_msg("%s", emsg.c);
		return (0);
	}

	/* Send a NOP immediately to tell the server our version of
	 * the AXA protocol so that the server can say hello. */
	client.alive.tv_sec = 0;

	return (1);
}

static void
out_close(bool announce)
{
	if (out_pcap_dumper != NULL) {
		pcap_dump_close(out_pcap_dumper);
		out_pcap_dumper = NULL;
	}
	if (out_pcap != NULL) {
		pcap_close(out_pcap);
		out_pcap = NULL;
	}
	if (out_nmsg_output != NULL)
		nmsg_output_close(&out_nmsg_output);
	if (out_nmsg_mod != NULL) {
		nmsg_msgmod_fini(out_nmsg_mod, &out_nmsg_clos);
	}

	if (out_addr != NULL) {
		if (announce) {
			clear_prompt();
			printf("stop forwarding to %s\n", out_addr);
		}
		free(out_addr);
		out_addr = NULL;
	}

	out_buf_base = out_buf_len = 0;
	time_out_flush.tv_sec = 0;
	out_nmsg_mod = NULL;
	out_nmsg_mod_checked = false;
	out_complaint_last.tv_sec = 0;
	out_complaint_skipped = false;

	out_on = false;
}

/* Flush the output forwarding buffer if it is time
 * or say how long until it will be time. */
static time_t
out_flush_ck(const struct timeval *now, time_t delay)
{
	time_t ms;
	struct timeval now0;

	if (time_out_flush.tv_sec == 0)
		return (delay);

	if (now == NULL) {
		gettimeofday(&now0, NULL);
		now = &now0;
	}

	ms = axa_elapsed_ms(now, &time_out_flush);
	ms = OUT_FLUSH_MS - ms;
	if (ms > 0)
		return (max(delay, ms));

	out_flush();
	return (delay);
}

static void
out_flush(void)
{
	nmsg_res res;
	ssize_t wlen;

	if (time_out_flush.tv_sec == 0)
		return;

	if (out_buf_len != 0) {
		wlen = write(out_fd, &out_buf[out_buf_base],
			     out_buf_len - out_buf_base);
		if (wlen < 0) {
			if (errno != EAGAIN
			    && errno != EWOULDBLOCK
			    && errno != EINTR) {
				error_msg("write(%s): %s",
					  out_addr, strerror(errno));
				out_close(true);
			}
		} else {
			out_buf_base += wlen;
			if (out_buf_base >= out_buf_len)
				out_buf_base = out_buf_len = 0;
		}
	}

	if (out_nmsg_output != NULL) {
		res = nmsg_output_flush(out_nmsg_output);
		if (res != nmsg_res_success
		    &&  (out_sock_type != SOCK_DGRAM
			 || res != nmsg_res_errno
			 || !AXA_IGNORED_UDP_ERRNO(errno))) {
			error_msg("nmsg_output_flush(forward): %s",
				  nmsg_res_lookup(res));
			out_close(true);
		}
	}

	time_out_flush.tv_sec = 0;
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

	/* Cajole the pcap library into writing its header, but write the
	 * packets themselves to allow non-blocking output to tcpdump. */
	if (0 > pcap_dump_flush(out_pcap_dumper)) {
		error_msg("pcap_dump_flush(forward): %s",
			  pcap_geterr(out_pcap));
		out_close(false);
		return (0);
	}

	return (1);
}

static int
out_cmd_pcap_if(const char *ifname)
{
	char ether[32];
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *p;
	int i;

	memset(&out_mac, 0, sizeof(out_mac));
	p = strchr(ifname, '/');
	if (p != NULL) {
		memset(ether, 0, sizeof(ether));
		memcpy(ether, ifname, min(sizeof(ether), p-ifname));
		ifname = p+1;
		if (ether_aton_r(ether, &out_mac.dst) == NULL
		    && ether_hostton(ether, &out_mac.dst) != 0) {
			error_msg("cannot convert \"%s\" to a MAC address;"
				  " using 0", ether);
			memset(&out_mac, 0, sizeof(out_mac));
		}
	}
	out_mac.etype = htons(0x800);
	memcpy(out_buf, &out_mac, sizeof(out_mac));

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

	return (1);
}

static int
out_cmd(axa_tag_t tag AXA_UNUSED, const char *arg)
{
	const char *addr;
	struct addrinfo *ai;
	axa_socku_t su;
	int result;

	if (arg[0] == '\0') {
		if (!out_on) {
			fputs("not forwarding messages\n", stdout);
		} else {
			printf("forwarding messages to %s\n", out_addr);
		}
		return (1);
	}

	out_close(verbose > 0);

	if (word_cmp(&arg, "off") || word_cmp(&arg, "stop"))
		return (1);

	out_addr = axa_strdup(arg);

	if (AXA_CLITCMP(out_addr, "pcap:")) {
		result = out_cmd_pcap_file(out_addr + sizeof("pcap:")-1,
					   false);

	} else	if (AXA_CLITCMP(out_addr, "pcap-fifo:")) {
		result = out_cmd_pcap_file(out_addr + sizeof("pcap-fifo:")-1,
					   true);

	} else	if (AXA_CLITCMP(out_addr, "pcap-if:")) {
		result = out_cmd_pcap_if(out_addr + sizeof("pcap-if:")-1);

	} else if (AXA_CLITCMP(out_addr, "nmsg:")) {
		int s;

		addr = out_addr + sizeof("nmsg:")-1;
		if (AXA_CLITCMP(addr, "tcp:")) {
			addr += sizeof("tcp:")-1;
			out_sock_type = SOCK_STREAM;
		} else if (AXA_CLITCMP(addr, "udp:")) {
			addr += sizeof("udp:")-1;
			out_sock_type = SOCK_DGRAM;
		} else {
			out_sock_type = SOCK_DGRAM;
		}
		if (*addr == '\0')
			return (-1);

		if (!axa_get_srvr(&emsg, addr, false, &ai)) {
			error_msg("%s", emsg.c);
			return (0);
		}
		memset(&su, 0, sizeof(su));
		memcpy(&su.sa, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);

		s = socket(su.sa.sa_family, out_sock_type, 0);
		if (s < 0) {
			error_msg("socket(%s): %s", addr, strerror(errno));
			return (0);
		}

		if (0 > connect(s, &su.sa, AXA_SU_LEN(&su))) {
			error_msg("connect(%s): %s", addr, strerror(errno));
			close(s);
			return (0);
		}

		if (!axa_set_sock(&emsg, s, addr, false)) {
			error_msg("%s", emsg.c);
			close(s);
			return (0);
		}

		if (out_sock_type == SOCK_DGRAM) {
			out_nmsg_output = nmsg_output_open_sock(s,
							NMSG_WBUFSZ_ETHER);
			if (out_nmsg_output == NULL) {
				error_msg("nmsg_output_open_sock(%s): failed",
					  addr);
				close(s);
				return (0);
			}
		} else {
			out_nmsg_output = nmsg_output_open_file(s,
							NMSG_WBUFSZ_MAX);
			if (out_nmsg_output == NULL) {
				error_msg("nmsg_output_open_file(%s) failed",
					  addr);
				close(s);
				return (0);
			}
		}

		result = 1;

	} else {
		return (-1);
	}

	if (result > 0) {
		out_on = true;
	} else {
		out_close(false);
	}
	return (result);
}

static int
count_cmd(axa_tag_t tag AXA_UNUSED, const char *arg)
{
	u_long l;
	char *p;

	if (arg[0] != '\0') {
		if (word_cmp(&arg, "off")) {
			packet_counting = false;
		} else {
			l = strtoul(arg, &p, 10);
			if (p == arg)
				return (-1);
			p += strspn(p, AXA_WHITESPACE);
			if (*p != '\0')
				return (-1);
			packet_counting = true;
			packet_count = l;
		}
		return (1);
	}

	if (!packet_counting) {
		printf("    packet output not limited by count\n");
	} else if (packet_count < 0)
	printf("    packet output stopped by \"count\" %d packets ago\n",
	       0 - packet_count);
	else
		printf("    %d packets remaining\n", packet_count);
	return (1);
}

static int
nop_cmd(axa_tag_t tag, const char *arg AXA_UNUSED)
{
	return (srvr_send(tag, AXA_P_OP_NOP, NULL, 0));
}

static int
mode_cmd(axa_tag_t tag AXA_UNUSED, const char *arg)
{
	const char *setting;

	setting = arg;
	if (setting[0] != '\0') {
		if (word_cmp(&setting, "sra")) {
			if (protocol_mode != SRA) {
				disconnect(true);
				protocol_mode = SRA;
			}
		} else if (word_cmp(&setting, "rad")) {
			if (protocol_mode != RAD) {
				disconnect(true);
				protocol_mode = RAD;
			}
		} else {
			return (-1);
		}
	}

	if (verbose > 0 || arg[0] == '\0') {
		switch (protocol_mode) {
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
sra_mode_cmd(axa_tag_t tag, const char *arg)
{
	word_cmp(&arg, "mode");
	if (arg[0] != '\0')
		return (-1);
	return (mode_cmd(tag, "sra"));
}

static int
rad_mode_cmd(axa_tag_t tag, const char *arg)
{
	word_cmp(&arg, "mode");
	if (arg[0] != '\0')
		return (-1);
	return (mode_cmd(tag, "rad"));
}

static int
user_cmd(axa_tag_t tag, const char *arg)
{
	axa_p_user_t user;

	if (strlen(arg) >= sizeof(user.name)) {
		error_msg("user name \"%s\" too long", arg);
		return (0);
	}
	strncpy(user.name, arg, sizeof(user.name));
	return (srvr_send(tag, AXA_P_OP_USER, &user, sizeof(user)));
}

static int
watch_cmd(axa_tag_t tag, const char *arg)
{
	axa_p_watch_t watch;
	size_t watch_len;

	if (arg[0] == '\0' || word_cmp(&arg, "get") || word_cmp(&arg, "list"))
		return (srvr_send(tag, AXA_P_OP_WGET, NULL, 0));

	if (protocol_mode != SRA)
		return (-1);

	if (tag == AXA_TAG_NONE) {
		error_msg("\"watch\" requires a tag");
		return (0);
	}
	if (word_cmp(&arg, "errors")) {
		memset(&watch, 0, sizeof(watch));
		watch.type = AXA_P_WATCH_ERRORS;
		return (srvr_send(tag, AXA_P_OP_WATCH, &watch,
				  sizeof(watch)-sizeof(watch.pat)));
	}

	if (axa_parse_watch(&emsg, &watch, &watch_len, arg))
		return (srvr_send(tag, AXA_P_OP_WATCH, &watch, watch_len));

	if (emsg.c[0] == '\0')
		return (-1);
	error_msg("%s", emsg.c);
	return (0);
}

static int
list_cmd(axa_tag_t tag, const char *arg)
{
	if (word_cmp(&arg, "watches"))
		return (srvr_send(tag, AXA_P_OP_WGET, NULL, 0));
	if (word_cmp(&arg, "channels"))
		return (srvr_send(tag, AXA_P_OP_CGET, NULL, 0));
	if (protocol_mode == RAD && (word_cmp(&arg, "anomaly"))) {
		return (srvr_send(tag, AXA_P_OP_AGET, NULL, 0));
	}
	return (-1);
}

static int
delete_cmd(axa_tag_t tag, const char *arg)
{
	const char *label;

	if (protocol_mode == SRA) {
		label = "watch";
		(void)word_cmp(&arg, "watches");
	} else {
		label = "anomaly";
		/* ignore "anomaly" but take "a" to mean "all" and so
		 * do not match "a" as if it were "anomaly". */
		if (strcasecmp(arg, "a") != 0)
			(void)(word_cmp(&arg, "anomaly"));
	}
	if (word_cmp(&arg, "all"))
		return (srvr_send(tag, AXA_P_OP_ALL_STOP, NULL, 0));
	if (*arg == '\0') {
		if (tag == AXA_TAG_NONE) {
			error_msg("deleting a single %s requires a tag",
				  label);
			return (-1);
		}
		return (srvr_send(tag, AXA_P_OP_STOP, NULL, 0));
	}
	return (-1);
}

static int
ch_on_off(axa_tag_t tag, const char *arg, bool on)
{
	axa_p_channel_t channel;

	memset(&channel, 0, sizeof(channel));
	if (!axa_parse_ch(&emsg, &channel.ch, arg, strlen(arg), true, true)) {
		error_msg("%s", emsg.c);
		return (0);
	}
	channel.on = on ? 1 : 0;
	return (srvr_send(tag, AXA_P_OP_CHANNEL, &channel, sizeof(channel)));
}

static int
ch_cmd(axa_tag_t tag, const char *arg)
{
	axa_p_ch_buf_t arg1_buf, arg2_buf;
	const char *arg1, *arg2;

	if (arg[0] == '\0' || word_cmp(&arg, "get") || word_cmp(&arg, "list"))
		return (srvr_send(tag, AXA_P_OP_CGET, NULL, 0));

	if (protocol_mode != SRA)
		return (-1);

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
		return (ch_on_off(tag, arg2, false));
	if (word_cmp(&arg1, "on"))
		return (ch_on_off(tag, arg2, true));

	if (word_cmp(&arg2, "off") || word_cmp(&arg2, "stop"))
		return (ch_on_off(tag, arg1, false));
	if (word_cmp(&arg2, "on"))
		return (ch_on_off(tag, arg1, true));

	return (-1);
}

static int
an_cmd(axa_tag_t tag, const char *arg)
{
	axa_p_anom_t anom;
	size_t len;
	const char *parms;

	if (tag == AXA_TAG_NONE) {
		error_msg("\"anomaly\" requires a tag");
		return (0);
	}

	/* look for "name [parameters]" */
	if (arg[0] == '\0')
		return (-1);
	parms = strchr(arg, ' ');
	if (parms == NULL)
		parms = arg+strlen(arg);

	len = parms - arg;
	if (len >= sizeof(anom.an)) {
		error_msg("anomaly name \"%.*s\" too long",
			  (int)len, arg);
		return (0);
	}

	memset(&anom.an, 0, sizeof(anom));
	memcpy(&anom.an, arg, len);

	parms += strspn(parms, AXA_WHITESPACE);
	len = strlen(parms);
	if (len >= sizeof(anom.parms)) {
		error_msg("anomaly parameters \"%.*s\" too long",
			  (int)len, parms);
		return (0);
	}
	memcpy(&anom.parms, parms, len);

	return (srvr_send(tag, AXA_P_OP_ANOM, &anom,
			  sizeof(anom) - sizeof(anom.parms) + len+1));
}

static bool				/* false=bad value */
get_rlimit(axa_rlimit_t *rlimit, const char *word)
{
	unsigned long n;
	char *p;

	if (*word == '\0' || strcmp("-", word) == 0) {
		*rlimit = AXA_H2P64(AXA_RLIMIT_NA);
		return (true);
	}
	if (word_cmp(&word, "MAXIMUM") || word_cmp(&word, "NEVER")) {
		*rlimit = AXA_H2P64(AXA_RLIMIT_OFF);
		return (true);
	}
	n = strtoul(word, &p, 10);
	if (*p != '\0' || n < 1 || n > AXA_RLIMIT_MAX) {
		*rlimit = AXA_H2P64(AXA_RLIMIT_NA);
		return (false);
	}
	*rlimit = AXA_H2P64(n);
	return (true);
}

static int
rlimits_cmd(axa_tag_t tag, const char *arg)
{
	char sec_buf[32];
	char day_buf[32];
	char report_secs_buf[32];
	axa_p_opt_t opt;

	memset(&opt, 0, sizeof(opt));
	opt.type = AXA_P_OPT_RLIMIT;

	word_cmp(&arg, "limits");
	if (0 > axa_get_token(sec_buf, sizeof(sec_buf),
			      &arg, AXA_WHITESPACE)
	    || 0 > axa_get_token(day_buf, sizeof(day_buf),
				 &arg, AXA_WHITESPACE)
	    || 0 > axa_get_token(report_secs_buf, sizeof(report_secs_buf),
				 &arg, AXA_WHITESPACE)
	    || *arg != '\0')
		return (-1);

	if (!get_rlimit(&opt.u.rlimit.max_pkts_per_sec, sec_buf))
		return (-1);
	if (!get_rlimit(&opt.u.rlimit.max_pkts_per_day, day_buf))
		return (-1);
	if (!get_rlimit(&opt.u.rlimit.report_secs, report_secs_buf))
		return (-1);

	opt.u.rlimit.cur_pkts_per_sec = AXA_RLIMIT_NA;
	opt.u.rlimit.cur_pkts_per_day = AXA_RLIMIT_NA;
	return (srvr_send(tag, AXA_P_OP_OPT, &opt,
			  sizeof(opt) - sizeof(opt.u) + sizeof(opt.u.rlimit)));
}

static int
pause_cmd(axa_tag_t tag, const char *arg AXA_UNUSED)
{
	return (srvr_send(tag, AXA_P_OP_PAUSE, NULL, 0));
}

static int
go_cmd(axa_tag_t tag, const char *arg AXA_UNUSED)
{
	return (srvr_send(tag, AXA_P_OP_GO, NULL, 0));
}

static int
trace_cmd(axa_tag_t tag, const char *arg)
{
	axa_p_opt_t opt;
	u_long l;
	char *p;

	l = strtoul(arg, &p, 10);
	if (*p != '\0')
		return (-1);
	memset(&opt, 0, sizeof(opt));
	opt.type = AXA_P_OPT_DEBUG;
	opt.u.debug = l;
	return (srvr_send(tag, AXA_P_OP_OPT, &opt,
			  sizeof(opt) - sizeof(opt.u) + sizeof(opt.u.debug)));
}

static int
acct_cmd(axa_tag_t tag, const char *arg AXA_UNUSED)
{
	return (srvr_send(tag, AXA_P_OP_ACCT, NULL, 0));
}

static void
print_recv_tag_op(void)
{
	char tag_buf[AXA_TAG_STRLEN];
	char op_buf[AXA_P_OP_STRLEN];

	clear_prompt();
	printf("%s %s\n",
	       axa_tag_to_str(tag_buf, sizeof(tag_buf),
			      AXA_P2H16(client.recv_hdr.tag)),
	       axa_op_to_str(op_buf, sizeof(op_buf),
			     client.recv_hdr.op));
}

static bool
get_nmsg_field(const nmsg_message_t msg, const char *fname,
	       axa_nmsg_idx_t val_idx, void **data, size_t *data_len,
	       char *ebuf, size_t ebuf_size)
{
	nmsg_res res;

	res = nmsg_message_get_field(msg, fname, val_idx, data, data_len);
	if (res == nmsg_res_success)
		return (true);

	snprintf(ebuf, ebuf_size, "nmsg_message_get_field(%s): %s",
		 fname, nmsg_res_lookup(res));
	*data = ebuf;
	*data_len = strlen(ebuf);
	return (false);
}

static bool				/* false=returning error message */
get_nmsg_field_by_idx(const nmsg_message_t msg, axa_nmsg_idx_t field_idx,
		      axa_nmsg_idx_t val_idx, void **data, size_t *data_len,
		      char *ebuf, size_t ebuf_size)
{
	nmsg_res res;

	res = nmsg_message_get_field_by_idx(msg, field_idx, val_idx,
					    data, data_len);
	if (res == nmsg_res_success)
		return (true);

	snprintf(ebuf, ebuf_size, "nmsg_message_get_field(%d): %s",
		 field_idx, nmsg_res_lookup(res));
	*data = ebuf;
	*data_len = strlen(ebuf);
	return (false);
}

static bool
enum_value_to_name(const nmsg_message_t msg, const char *fname, uint value,
		   const char **type_str, char *ebuf, size_t ebuf_size)
{
	nmsg_res res;

	res = nmsg_message_enum_value_to_name(msg, fname, value, type_str);
	if (res == nmsg_res_success)
		return (true);

	if (ebuf_size > 0) {
		snprintf(ebuf, ebuf_size,
			 "nmsg_message_enum_value_to_name(%s): %s",
			 fname, nmsg_res_lookup(res));
		*type_str = ebuf;
	} else {
		*type_str = NULL;
	}
	return (false);
}

static bool
fname_enum_to_name(const nmsg_message_t msg, const char *fname,
		   const char **type_str, char *ebuf, size_t ebuf_size)
{
	void *data;
	size_t data_len;
	uint value;
	nmsg_res res;

	if (!get_nmsg_field(msg, fname, 0, &data, &data_len,
			    ebuf, ebuf_size)) {
		*type_str = data;
		return (false);
	}
	if (data_len != sizeof(value)) {
		*type_str = "wrong enum len from nmsg_message_get_field()";
		return (false);
	}
	memcpy(&value, data, sizeof(value));
	res = nmsg_message_enum_value_to_name(msg, fname, value, type_str);
	if (res == nmsg_res_success)
		return (true);
	*type_str = ebuf;
	return (false);
}

static bool
data_to_ip(char *buf, size_t buf_len,
	   const void *data, size_t data_len, const char *tag)
{
	axa_socku_t su;

	if (!axa_data_to_su(&su, data, data_len)) {
		snprintf(buf, buf_len, "%s IP length=%zd", tag, data_len);
		return (false);
	}
	axa_su_to_str(buf, buf_len, '.', &su);
	return (true);
}

static bool
fname_to_ip(char *buf, size_t buf_len, const nmsg_message_t msg,
	    const char *fname, axa_nmsg_idx_t val_idx)
{
	void *data;
	size_t data_len;

	if (!get_nmsg_field(msg, fname, val_idx, &data, &data_len,
			    buf, buf_len))
		return (buf);
	return (data_to_ip(buf, buf_len, data, data_len, fname));
}

static void
print_verbose_nmsg(const nmsg_message_t msg, const char *eq, const char *val)
{
	char *pres_data;
	const char *line, *eol;
	nmsg_res res;

	printf("%s%s\n", eq, val);

	res = nmsg_message_to_pres(msg, &pres_data, "\n");
	if (res != nmsg_res_success) {
		printf(NMSG_LEADER"<UNKNOWN NMSG %u:%u>\n",
		       nmsg_message_get_vid(msg),
		       nmsg_message_get_msgtype(msg));
		return;
	}

	for (line = pres_data; *line != '\0'; line = eol) {
		eol = strchr(line, '\n');
		AXA_ASSERT(eol != NULL);
		++eol;
		fputs(NMSG_LEADER, stdout);
		fwrite(line, eol-line, 1, stdout);
	}
	free(pres_data);
}

typedef struct {
	char		*buf0;
	size_t		buf0_len;
	char		*buf;
	size_t		buf_len;
	nmsg_message_t	msg;
	const char	*rdata_name;
} rdata_ctxt_t;

static void
rdata_error(void *ctxt0, const char *p, va_list args)
{
	rdata_ctxt_t *ctxt = ctxt0;

	vsnprintf(ctxt->buf0, ctxt->buf0_len, p, args);
	ctxt->buf_len = 0;
}

static bool
rdata_buf_alloc(rdata_ctxt_t *ctxt)
{
	size_t len;

	len = strlen(ctxt->buf);
	ctxt->buf += len;
	ctxt->buf_len -= len;
	return (ctxt->buf_len > 0);
}

static bool
rdata_buf_cat(rdata_ctxt_t *ctxt, const char *str)
{
	strlcpy(ctxt->buf, str, ctxt->buf_len);
	return (rdata_buf_alloc(ctxt));
}

static bool
rdata_ip_to_buf(void *ctxt0, const uint8_t *ip, size_t ip_len,
		const char *str AXA_UNUSED)
{
	rdata_ctxt_t *ctxt = ctxt0;
	axa_socku_t su;

	if (!rdata_buf_cat(ctxt, " "))
		return (false);

	if (!axa_data_to_su(&su, ip, ip_len)) {
		snprintf(ctxt->buf0, ctxt->buf0_len, "%s IP length=%zd",
			 ctxt->rdata_name, ip_len);
		ctxt->buf_len = 0;
		return (false);
	}
	axa_su_to_str(ctxt->buf, ctxt->buf_len, '.', &su);
	return (rdata_buf_alloc(ctxt));
}

static bool
rdata_domain_to_buf(void *ctxt0, const uint8_t *name, size_t name_len,
		    axa_walk_dom_t dtype AXA_UNUSED,
		    uint rtype AXA_UNUSED,
		   const char *str AXA_UNUSED)
{
	rdata_ctxt_t *ctxt = ctxt0;
	char wname[NS_MAXDNAME];

	if (!rdata_buf_cat(ctxt, " "))
		return (false);

	axa_domain_to_str(name, name_len, wname);
	strlcpy(ctxt->buf, wname, ctxt->buf_len);
	return (rdata_buf_alloc(ctxt));
}

static axa_walk_ops_t rdata_ops = {
	.error = rdata_error,
	.ip = rdata_ip_to_buf,
	.domain = rdata_domain_to_buf,
};

#define RDATA_BUF_LEN (32+NS_MAXDNAME+1+NS_MAXDNAME)
static const char *
rdata_to_buf(char *buf, size_t buf_len,
	     const char *rdata_name, uint32_t rtype,
	     uint8_t *rdata, size_t rdata_len)
{
	rdata_ctxt_t ctxt;

	ctxt.buf0 = buf;
	ctxt.buf0_len = buf_len;
	ctxt.buf = buf;
	ctxt.buf_len = buf_len;
	ctxt.rdata_name = rdata_name;

	strlcpy(ctxt.buf, axa_rtype_to_str(ctxt.buf, ctxt.buf_len, rtype),
		ctxt.buf_len);
	if (!rdata_buf_alloc(&ctxt))
		return (buf);

	axa_walk_rdata(&ctxt, &rdata_ops, NULL, 0, NULL,
		       rdata, rdata+rdata_len, rtype, rdata_len, "");

	return (buf);
}

/* Get a string for rdata specified by
 *	rdata_name=nmsg field name for the data itself
 *	rtype_idx=nmsg field index for the rtype of the data */
static const char *
rdata_nmsg_to_buf(char *buf, size_t buf_len, const nmsg_message_t msg,
		  const axa_nmsg_field_t *field, axa_nmsg_idx_t val_idx)
{
	uint32_t rtype;
	void *data;
	size_t data_len;

	/* Get the rdata type */
	if (!axa_get_helper(&emsg, msg, &field->rtype, val_idx,
			    &rtype, NULL, sizeof(rtype), sizeof(rtype), NULL)) {
		strlcpy(buf, emsg.c, buf_len);
		return (buf);
	}

	/* get the rdata itself */
	if (!get_nmsg_field_by_idx(msg, field->idx, val_idx, &data, &data_len,
				   buf, buf_len))
		return (buf);

	return (rdata_to_buf(buf, buf_len, field->name, rtype, data, data_len));
}

static void
print_nmsg_base_dnsqr(const nmsg_message_t msg, const char *eq, const char *val,
		      const axa_p_whit_t *whit)
{
	const Nmsg__Base__DnsQR *dnsqr;
	char ebuf[80];
	const char *type_str;

	if (verbose != 0) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	dnsqr = (Nmsg__Base__DnsQR *)nmsg_message_get_payload(msg);
	if (dnsqr == NULL) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	/* Punt on odd messages */
	if (dnsqr->n_query_packet == 0 && dnsqr->n_response_packet == 0) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}
	switch ((Nmsg__Base__DnsQRType)dnsqr->type) {
	case NMSG__BASE__DNS_QRTYPE__UDP_QUERY_ONLY:
	case NMSG__BASE__DNS_QRTYPE__UDP_RESPONSE_ONLY:
	case NMSG__BASE__DNS_QRTYPE__UDP_QUERY_RESPONSE:
	case NMSG__BASE__DNS_QRTYPE__UDP_UNANSWERED_QUERY:
	case NMSG__BASE__DNS_QRTYPE__UDP_UNSOLICITED_RESPONSE:
		break;
	case NMSG__BASE__DNS_QRTYPE__UDP_INVALID:
	case NMSG__BASE__DNS_QRTYPE__TCP:
	case NMSG__BASE__DNS_QRTYPE__ICMP:
	default:
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	if (!enum_value_to_name(msg, "type", dnsqr->type, &type_str,
				ebuf, sizeof(ebuf))) {
		if (verbose > 1)
			printf("%s\n", ebuf);
		print_verbose_nmsg(msg, eq, val);
		return;
	}
	printf("%s%s  %s\n", eq, val, type_str);
	/* The query should be in the response,
	 * so print the query only without a response. */
	if (dnsqr->n_response_packet == 0) {
		print_raw_ip(dnsqr->query_packet[0].data,
			      dnsqr->query_packet[0].len, whit);
	} else {
		print_raw_ip(dnsqr->response_packet[0].data,
			      dnsqr->response_packet[0].len, whit);
	}
}

static void
print_sie_dnsdedupe(const nmsg_message_t msg, const axa_nmsg_field_t *field,
		    const char *eq, const char *val)
{
	const char *type_str;
	const Nmsg__Sie__DnsDedupe *dnsdedupe;
	char ebuf[80];
	char response_ip_buf[INET6_ADDRSTRLEN];
	char rdata_buf[RDATA_BUF_LEN];
	char rrname_buf[NS_MAXDNAME];
	bool need_nl;

	if (verbose != 0) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	dnsdedupe = (Nmsg__Sie__DnsDedupe *)nmsg_message_get_payload(msg);

	if (!dnsdedupe->has_type) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}
	if (!enum_value_to_name(msg, "type", dnsdedupe->type, &type_str,
				ebuf, sizeof(ebuf))) {
		if (verbose > 1)
			printf("%s\n", ebuf);
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	printf("%s%s  %s\n", eq, val, type_str);

	/* Print the response IP only if we did not print it as the trigger. */
	need_nl = false;
	if ((field == NULL || strcmp(field->name, "response_ip") != 0)
	    && dnsdedupe->has_response_ip) {
		data_to_ip(response_ip_buf, sizeof(response_ip_buf),
			   dnsdedupe->response_ip.data,
			   dnsdedupe->response_ip.len, "response_ip");
		printf(NMSG_LEADER"response_ip=%s", response_ip_buf);
		need_nl = true;
	}
	/* Print the rdata only if we will not print the response packet,
	 * we did not print it as the trigger,
	 * and we can. */
	if (!dnsdedupe->has_response
	    && (field == NULL || strcmp(field->name, "rdata") != 0)
	    && dnsdedupe->n_rdata >= 1 && dnsdedupe->has_rrtype) {
		printf(NMSG_LEADER"rdata=%s",
		       rdata_to_buf(rdata_buf, sizeof(rdata_buf),
				    "rdata", dnsdedupe->rrtype,
				    dnsdedupe->rdata->data,
				    dnsdedupe->rdata->len));
		need_nl = true;
	}
	/* Print the domain name only if we will not print the response packet,
	 * we did not print it as the trigger,
	 * and we can. */
	if (!dnsdedupe->has_response
	    && (field == NULL || strcmp(field->name, "rrname") != 0)
	    && dnsdedupe->has_rrname) {
		axa_domain_to_str(dnsdedupe->rrname.data, dnsdedupe->rrname.len,
				  rrname_buf);
		printf(NMSG_LEADER"rrname=%s", rrname_buf);
		need_nl = true;
	}
	if (need_nl)
		fputc('\n', stdout);

	if (dnsdedupe->has_response)
		print_dns_pkt(dnsdedupe->response.data,
			      dnsdedupe->response.len, "response");
}

static void
print_sie_newdomain(const nmsg_message_t msg,
		    const axa_nmsg_field_t *field AXA_UNUSED,
		    const char *eq, const char *val)
{
	const Nmsg__Sie__NewDomain *newdomain;
	char rrname_buf[NS_MAXDNAME];
	char domain_buf[NS_MAXDNAME];
	char rtype_buf[10];

	if (verbose != 0) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	newdomain = (Nmsg__Sie__NewDomain *)nmsg_message_get_payload(msg);

	axa_domain_to_str(newdomain->rrname.data, newdomain->rrname.len,
			  rrname_buf);
	axa_rtype_to_str(rtype_buf, sizeof(rtype_buf), newdomain->rrtype);
	axa_domain_to_str(newdomain->domain.data, newdomain->domain.len,
			  domain_buf);

	printf("%s%s\n%s/%s: %s\n",
	       eq, val, rrname_buf, rtype_buf, domain_buf);
}

static void
print_nmsg_base_http(const nmsg_message_t msg, const axa_nmsg_field_t *field,
		     const char *eq, const char *val)
{
	char buf[NS_MAXDNAME];
	bool need_nl;

	if (verbose != 0) {
		print_verbose_nmsg(msg, eq, val);
		return;
	}

	/* Print the triggering field name and its value. */
	printf("%s%s\n", eq, val);
	need_nl = false;

	/* Print the source and destination fields if not just now printed. */
	if (field == NULL || strcmp(field->name, "srcip") != 0) {
		fname_to_ip(buf, sizeof(buf), msg, "srcip", 0);
		printf(NMSG_LEADER"srcip=%s", buf);
		need_nl = true;
	}
	if (field == NULL || strcmp(field->name, "dstip") != 0) {
		fname_to_ip(buf, sizeof(buf), msg, "dstip", 0);
		printf(NMSG_LEADER"dstip=%s", buf);
		need_nl = true;
	}
	if (need_nl)
		fputc('\n', stdout);
}

static void
print_text(const char *text, size_t text_len)
{
	int lines;
	size_t line_len, skip;

	lines = 0;
	while (text_len > 0) {
		if (++lines >= 6) {
			fputs(NMSG_LEADER2"...\n", stdout);
			return;
		}
		line_len = 76;
		if (line_len > text_len) {
			line_len = text_len;
			skip = 0;
		} else {
			for (;;) {
				if (line_len < 60) {
					line_len = 76;
					skip = 0;
					break;
				}
				if (text[line_len] == ' '
				    || text[line_len] == '\t') {
					skip = 1;
					break;
				}
				--line_len;
			}
		}
		printf(NMSG_LEADER2"%.*s\n", (int)line_len, text);
		text += line_len+skip;
		text_len -= line_len+skip;
	}
}

static void
print_nmsg_base_encode(const nmsg_message_t msg,
		       const char *eq, const char *val)
{
	void *data;
	size_t data_len;
	const char *type_str;
	char ebuf[80];
	bool ok;

	ok = fname_enum_to_name(msg, "type", &type_str, ebuf, sizeof(ebuf));
	printf("%s%s  %s\n", eq, val, type_str);
	if (!ok)
		return;

	if (!get_nmsg_field(msg, "payload", 0,
			    &data, &data_len, ebuf, sizeof(ebuf))) {
		printf(NMSG_LEADER"%s\n", ebuf);
		return;
	}

	if (strcmp(type_str, "JSON") == 0) {
		print_text(data, data_len);
	} else if (strcmp(type_str, "TEXT") == 0
		   || strcmp(type_str, "YAML") == 0
		   || strcmp(type_str, "XML") == 0) {
		if (verbose == 0)
			return;
		print_text(data, data_len);
	} else {
		/* MessagePack seems to be binary */
		if (verbose == 0)
			return;
		print_raw(data, data_len);
	}
}

static void
print_nmsg_base_packet(const nmsg_message_t msg, const axa_p_whit_t *whit,
		       const char *eq, const char *val)
{
	void *data;
	size_t data_len;
	const char *type_str;
	char ebuf[80];
	bool ok;

	ok = fname_enum_to_name(msg, "payload_type",
				&type_str, ebuf, sizeof(ebuf));
	printf("%s%s  %s\n", eq, val, type_str);
	if (!ok)
		return;

	if (!get_nmsg_field(msg, "payload", 0,
			    &data, &data_len, ebuf, sizeof(ebuf))) {
		printf(NMSG_LEADER"%s\n", (char *)data);
		return;
	}
	print_raw_ip(data, data_len, whit);
}

/*
 * Convert field index to field name and value string.
 */
static void
get_nm_eq_val(const nmsg_message_t msg, const axa_p_whit_t *whit,
	      const axa_nmsg_field_t **fieldp,
	      const char **nm, const char **eq, const char **val,
	      char *buf, size_t buf_len)
{
	const axa_nmsg_field_t *field;
	axa_nmsg_idx_t field_idx;
	void *data;
	size_t data_len;
	size_t n;

	field_idx = whit->nmsg.hdr.field_idx;
	if (field_idx == AXA_NMSG_IDX_ERROR) {
		strlcpy(buf, "ERROR", buf_len);
		*nm = buf;
		*eq = "";
		*val = "";
		*fieldp = NULL;
		return;
	} else if (field_idx == AXA_NMSG_IDX_ALL_CH) {
		*nm = "";
		*eq = "";
		*val = "";
		*fieldp = NULL;
		return;
	} else if (field_idx >= AXA_NMSG_IDX_RSVD) {
		strlcpy(buf, "? unrecognized message", buf_len);
		*nm = buf;
		*eq = "";
		*val = "";
		*fieldp = NULL;
		return;
	}

	field = axa_msg_fields(msg);
	if (field == NULL) {
		strlcpy(buf, "? unrecognized message", buf_len);
		*nm = buf;
		*eq = "";
		*val = "";
		*fieldp = NULL;
		return;
	}
	for (;;) {
		if (field->idx == field_idx)
			break;
		field = field->next;
		if (field == NULL) {
			strlcpy(buf, "? unrecognized field", buf_len);
			*nm = buf;
			*eq = "";
			*val = "";
			return;
		}
	}
	*fieldp = field;

	switch (field->fc) {
	case AXA_FC_IP:
		*nm = field->name;
		*eq = "=";
		fname_to_ip(buf, buf_len, msg, field->name,
			    whit->nmsg.hdr.val_idx);
		*val = buf;
		break;

	case AXA_FC_DOM:
		*nm = field->name;
		*eq = "=";
		if (get_nmsg_field_by_idx(msg, field_idx,
					   whit->nmsg.hdr.val_idx,
					   &data, &data_len, buf, buf_len))
			axa_domain_to_str(data, data_len, buf);
		*val = buf;
		break;

	case AXA_FC_IP_ASCII:
	case AXA_FC_DOM_ASCII:
	case AXA_FC_HOST:
		*nm = field->name;
		*eq = "=";
		if (get_nmsg_field_by_idx(msg, field_idx,
					  whit->nmsg.hdr.val_idx,
					  &data, &data_len, buf, buf_len)) {
			n = min(buf_len-1, data_len);
			memcpy(buf, data, n);
			buf[n] = '\0';
		}
		*val = buf;
		break;

	case AXA_FC_RDATA:
		*nm = field->name;
		*eq = "=";
		*val = rdata_nmsg_to_buf(buf, buf_len, msg, field,
					 whit->nmsg.hdr.val_idx);
		break;

	case AXA_FC_DNS:
	case AXA_FC_JSON:
	case AXA_FC_IP_DGRAM:
		*nm = field->name;
		*eq = "";
		*val = "";
		break;

	case AXA_FC_UNKNOWN:
		*nm = field->name;
		snprintf(buf, buf_len, " ? unknown field");
		*eq = buf;
		*val = "";
		break;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		*nm = field->name;
		snprintf(buf, buf_len, " ? strange field #%d", field->fc);
		*eq = buf;
		*val = "";
		break;
#pragma clang diagnostic pop
	}
}

/* Create nmsg message from incoming watch hit containing a nmsg message */
static void
whit2nmsg(nmsg_message_t *msgp, axa_p_whit_t *whit, size_t whit_len)
{
	if (!axa_whit2nmsg(&emsg, nmsg_input, msgp, whit, whit_len)) {
		clear_prompt();
		error_msg("%s", emsg.c);
		disconnect(true);
	}
}

static bool
out_error_ok(void)
{
	struct timeval now;
	time_t ms;

	gettimeofday(&now, NULL);
	ms = axa_tv_diff2ms(&now, &out_complaint_last);

	/* allow a new complaint every 5 seconds */
	 if (ms < 0 || ms > 5000)
		 return (true);

	 /* count skipped complaints */
	 out_complaint_skipped = true;
	 return (false);
}

static void AXA_PF(1,2)
out_error(const char *p, ...)
{
	va_list args;

	if (!out_error_ok())
		return;

	clear_prompt();
	if (out_complaint_skipped) {
		error_msg("...");
		out_complaint_skipped = false;
	}
	va_start(args, p);
	axa_verror_msg(p, args);
	va_end(args);

	gettimeofday(&out_complaint_last, NULL);
}

/* forward watch hits as nmsg messages */
static void
out_whit_nmsg(axa_p_whit_t *whit, size_t whit_len)
{
	nmsg_message_t msg;
	struct timespec ts;
	static const union {
		uint    e;
		uint8_t	c[0];
	} pkt_enum = { .e = NMSG__BASE__PACKET_TYPE__IP };
	size_t len;
	nmsg_res res;

	switch ((axa_p_whit_enum_t)whit->hdr.type) {
	case AXA_P_WHIT_NMSG:
		/* pass nmsg messages along */
		whit2nmsg(&msg, whit, whit_len);
		if (msg == NULL)
			return;
		break;

	case AXA_P_WHIT_IP:
		/* Convert raw IP packets to nmsg BASE_PACKET */
		len = whit_len - sizeof(whit->ip.hdr);
		if (whit->ip.hdr.orig_len != len)
			return;		/* Ignore incomplete packets. */

		if (!out_nmsg_mod_checked) {
			out_nmsg_mod_checked = true;
			out_nmsg_mod = nmsg_msgmod_lookup(NMSG_VENDOR_BASE_ID,
						NMSG_VENDOR_BASE_PACKET_ID);
			if (out_nmsg_mod == NULL) {
				out_error("cannot get BASE_PACKET module");
				return;
			}
			res = nmsg_msgmod_init(out_nmsg_mod, &out_nmsg_clos);
			if (res != nmsg_res_success) {
				out_error("cannot init BASE_PACKET module");
				out_nmsg_mod = NULL;
				return;
			}
		}
		if (out_nmsg_mod == NULL) {
			out_error("cannot forward IP as nmsg messages"
				  " without PACKET nmsg_msgmod");
			return;
		}

		msg = nmsg_message_init(out_nmsg_mod);
		AXA_ASSERT(msg != NULL);
		res = nmsg_message_set_field(msg, "payload_type", 0,
					     pkt_enum.c, sizeof(pkt_enum));
		AXA_ASSERT(res == nmsg_res_success);
		res = nmsg_message_set_field(msg, "payload", 0,
					     whit->ip.b, len);
		AXA_ASSERT(res == nmsg_res_success);
		ts.tv_sec = AXA_P2H32(whit->ip.hdr.ts.tv_sec);
		ts.tv_nsec = AXA_P2H32(whit->ip.hdr.ts.tv_usec) * 1000;
		nmsg_message_set_time(msg, &ts);
		break;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		out_error("cannot forward SRA #%d messages as nmsg messages",
			  whit->hdr.type);
		return;
#pragma clang diagnostic pop
	}

	res = nmsg_output_write(out_nmsg_output, msg);
	if (res != nmsg_res_success
	    &&  (out_sock_type != SOCK_DGRAM
		 || res != nmsg_res_errno
		 || !AXA_IGNORED_UDP_ERRNO(errno))) {
		clear_prompt();
		error_msg("nmsg_output_write(): %s", nmsg_res_lookup(res));
		out_close(false);
		disconnect(true);
	}

	nmsg_message_destroy(&msg);
	if (time_out_flush.tv_sec == 0)
		gettimeofday(&time_out_flush, NULL);
}

static void
out_ip_pcap_file(const uint8_t *pkt, size_t caplen, size_t len,
		 const struct timeval *tv)
{
	/* From pcap-int.h, which is not present on some systems,
	 * and written in the stone of uncounted saved pcap files. */
	struct {
		struct {
			int32_t	    tv_sec;
			int32_t	    tv_usec;
		} ts;			/* time stamp */
		bpf_u_int32 caplen;	/* length of portion present */
		bpf_u_int32 len;	/* length this packet (off wire) */
	} sf_hdr;

	if (caplen > sizeof(out_buf) - sizeof(sf_hdr) - out_buf_len
	    || out_buf_base != 0) {
		out_flush();
		if (caplen > sizeof(out_buf) - sizeof(sf_hdr) - out_buf_len) {
			out_error("forwarding output stalled; dropping");
			return;
		}
	}

	/* Use the official version of struct pcap_sf_pkthdr and hope
	 * even the "experts" with "patched" versions can handle the
	 * standard form. */
	sf_hdr.ts.tv_sec = tv->tv_sec;
	sf_hdr.ts.tv_usec = tv->tv_usec;
	sf_hdr.caplen = caplen;
	sf_hdr.len = len;

	memcpy(&out_buf[out_buf_len], &sf_hdr, sizeof(sf_hdr));
	out_buf_len += sizeof(sf_hdr);
	memcpy(&out_buf[out_buf_len], pkt, caplen);
	out_buf_len += caplen;
	if (time_out_flush.tv_sec == 0)
		gettimeofday(&time_out_flush, NULL);
}

static void
out_ip_pcap_inject(const uint8_t *pkt, size_t caplen)
{
	AXA_ASSERT(caplen < sizeof(out_buf) - sizeof(out_mac));

	memcpy(&out_buf[sizeof(out_mac)], pkt, caplen);

	if (0 > pcap_inject(out_pcap, out_buf, caplen)) {
		error_msg("failed to inject packet onto %s: %s",
			  out_addr, pcap_geterr(out_pcap));
		out_close(true);
	}
}

/* forward watch hits in a pcap stream */
static void
out_whit_pcap(axa_p_whit_t *whit, size_t whit_len)
{
	struct timeval tv;
	uint8_t *pkt;
	size_t len, caplen;
	struct timespec ts;
	nmsg_message_t msg;
	uint vid, msgtype;
	const char *vid_str, *msgtype_str;
	const Nmsg__Base__Packet *packet;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	pkt = NULL;
	caplen = 0;
	len = 0;
	switch ((axa_p_whit_enum_t)whit->hdr.type) {
	case AXA_P_WHIT_IP:
		if (whit_len <= sizeof(whit->ip)) {
			clear_prompt();
			error_msg("truncated IP packet");
			disconnect(true);
			return;
		}
		tv.tv_sec = AXA_P2H32(whit->ip.hdr.ts.tv_sec);
		tv.tv_usec = AXA_P2H32(whit->ip.hdr.ts.tv_usec);
		pkt = whit->ip.b;
		caplen = whit_len - sizeof(whit->ip.hdr);
		len = whit->ip.hdr.orig_len;
		break;

	case AXA_P_WHIT_NMSG:
		whit2nmsg(&msg, whit, whit_len);
		if (msg == NULL)
			return;
		vid = nmsg_message_get_vid(msg);
		msgtype = nmsg_message_get_msgtype(msg);
		if (vid != NMSG_VENDOR_BASE_ID
		    || msgtype != NMSG_VENDOR_BASE_PACKET_ID) {
			if (!out_error_ok()) {
				vid_str = nmsg_msgmod_vid_to_vname(vid);
				msgtype_str = nmsg_msgmod_msgtype_to_mname(vid,
							msgtype);
				out_error("cannot forward nmsg %s %s"
					  " messages via pcap",
					  vid_str, msgtype_str);
				return;
			}
		}

		/* forward the IP packets in BASE_PACKET */
		packet = (Nmsg__Base__Packet *)nmsg_message_get_payload(msg);
		if (packet == NULL)
			break;
		if (packet->payload_type != NMSG__BASE__PACKET_TYPE__IP)
			break;
		nmsg_message_get_time(msg, &ts);
		tv.tv_sec = ts.tv_sec;
		tv.tv_usec = ts.tv_nsec / 1000;
		pkt = packet->payload.data;
		caplen = packet->payload.len;
		len = packet->payload.len;
		break;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	default:
		out_error("cannot forward watch hits type #%d", whit->hdr.type);
		return;
#pragma clang diagnostic pop
	}

	if (out_pcap_dumper != NULL)
		out_ip_pcap_file(pkt, caplen, len, &tv);
	else
		out_ip_pcap_inject(pkt, caplen);
}

static void
print_nmsg(axa_p_whit_t *whit, size_t whit_len,
	   const char *title_sep, const char *title)
{
	axa_p_whit_nmsg_hdr_t *mhdr;
	char tag_buf[AXA_TAG_STRLEN];
	const axa_nmsg_field_t *field;
	char vendor_buf[12], mname_buf[12], field_buf[RDATA_BUF_LEN];
	const char *vendor, *mname, *nm, *eq, *val;
	char group[40];
	const char *cp;
	nmsg_message_t msg;
	uint n;

	whit2nmsg(&msg, whit, whit_len);
	if (msg == NULL)
		return;

	/* Convert binary vendor ID, message type, and field index to
	 * vendor name, message type string, field name, and field value. */
	mhdr = &whit->nmsg.hdr;
	vendor = nmsg_msgmod_vid_to_vname(mhdr->vid);
	if (vendor == NULL) {
		snprintf(vendor_buf, sizeof(vendor_buf), "ID #%d",
			 mhdr->vid);
		vendor = vendor_buf;
	}
	mname = nmsg_msgmod_msgtype_to_mname(mhdr->vid, mhdr->type);
	if (mname == NULL) {
		snprintf(mname_buf, sizeof(mname_buf), "#%d", mhdr->type);
		mname = mname_buf;
	}
	field = NULL;			/* silence gcc warning */
	get_nm_eq_val(msg, whit, &field, &nm, &eq, &val,
		      field_buf, sizeof(field_buf));

	cp = NULL;
	n = nmsg_message_get_group(msg);
	if (n != 0)
		cp = nmsg_alias_by_key(nmsg_alias_group, n);
	if (cp == NULL)
		group[0] = '\0';
	else
		snprintf(group, sizeof(group), " %s", cp);

	/* Print what we have so far,
	 * except the value which might be redundant */
	clear_prompt();
	printf("%s%s%s "AXA_OP_CH_PREFIX"%d  %s %s%s %s",
	       axa_tag_to_str(tag_buf, sizeof(tag_buf),
			      AXA_P2H16(client.recv_hdr.tag)),
	       title_sep, title,
	       whit->hdr.ch, vendor, mname, group, nm);

	switch (mhdr->vid) {
	case NMSG_VENDOR_BASE_ID:
		switch (mhdr->type) {
		case NMSG_VENDOR_BASE_DNSQR_ID:
			print_nmsg_base_dnsqr(msg, eq, val, whit);
			break;
		case NMSG_VENDOR_BASE_HTTP_ID:
			print_nmsg_base_http(msg, field, eq, val);
			break;
		case NMSG_VENDOR_BASE_ENCODE_ID:
			print_nmsg_base_encode(msg, eq, val);
			break;
		case NMSG_VENDOR_BASE_PACKET_ID:
			print_nmsg_base_packet(msg, whit, eq, val);
			break;
		default:
			print_verbose_nmsg(msg, eq, val);
			break;
		}
		break;

	case NMSG_VENDOR_SIE_ID:
		switch (mhdr->type) {
		case NMSG_VENDOR_SIE_DNSDEDUPE_ID:
			print_sie_dnsdedupe(msg, field, eq, val);
			break;
		case NMSG_VENDOR_SIE_NEWDOMAIN_ID:
			print_sie_newdomain(msg, field, eq, val);
			break;
		default:
			print_verbose_nmsg(msg, eq, val);
			break;
		}
		break;

	default:
		print_verbose_nmsg(msg, eq, val);
		break;
	}
}

static void
print_whit(axa_p_whit_t *whit, size_t whit_len,
	   const char *title_sep, const char *title)
{
	char tag_buf[AXA_TAG_STRLEN];

	if (out_on) {
		if (out_nmsg_output != NULL) {
			out_whit_nmsg(whit, whit_len);
		} else {
			AXA_ASSERT(out_pcap != NULL);
			out_whit_pcap(whit, whit_len);
		}
	}

	if (packet_counting && --packet_count < 0) {
		if (packet_count == -1) {
			clear_prompt();
			fputs("packet count limit exceeded\n", stdout);
		}
		return;
	}

	clear_prompt();
	switch ((axa_p_whit_enum_t)whit->hdr.type) {
	case AXA_P_WHIT_NMSG:
		print_nmsg(whit, whit_len, title_sep, title);
		return;
	case AXA_P_WHIT_IP:
		if (whit_len <= sizeof(whit->ip)) {
			error_msg("truncated IP packet");
			disconnect(true);
			return;
		}

		printf("%s%s%s "AXA_OP_CH_PREFIX"%d\n",
		       axa_tag_to_str(tag_buf, sizeof(tag_buf),
				      AXA_P2H16(client.recv_hdr.tag)),
		       title_sep, title,
		       whit->hdr.ch);
		print_raw_ip(whit->ip.b, whit_len - sizeof(whit->ip.hdr),
			     whit);
		return;
	}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	error_msg("unrecognized message type %d", whit->hdr.type);
	disconnect(true);
#pragma clang diagnostic pop
}

static void
print_ahit(void)
{
	print_whit(&client.recv_body->ahit.whit,
		   client.recv_hdr.len
		   - (sizeof(client.recv_hdr)
		      + sizeof(client.recv_body->ahit)
		      - sizeof(client.recv_body->ahit.whit)),
		   " ", client.recv_body->ahit.an.c);
}

static void
print_channel(void)
{
	const axa_p_clist_t *clist;
	axa_p_ch_buf_t buf;

	clear_prompt();
	clist = &client.recv_body->clist;
	snprintf(buf.c, sizeof(buf), AXA_OP_CH_PREFIX"%d", clist->ch);
	printf(" %8s %3s %s\n",
	       buf.c, clist->on != 0 ? "on" : "off", clist->spec.c);
}

/* Repeat anything that the ssh process says */
static void
sra_ssh_flush(void)
{
	char ebuf[240];
	int i;

	if (client.err_sock < 0)
		return;

	i = read(client.err_sock, ebuf, sizeof(ebuf));
	if (i > 0) {
		clear_prompt();
		/* Set i = write() and discard i, because GNU gcc says that
		 * ignoring the result from write() is "either a security
		 * problem or always a bug" and casting write() to void
		 * does not prevent the gcc warning. */
		i = write(STDERR_FILENO, ebuf, i);

	} else if (i <= 0) {
		if (i < 0 && (errno != EWOULDBLOCK
			      || errno != EAGAIN
			      || errno != EINTR))
			error_msg("read(ssh stderr): %s",
				  strerror(errno));
		close(client.err_sock);
		client.err_sock = -1;
	}
}

/* Deal with a message from the server. */
static void
read_srvr(void)
{
	char buf[1024];
	char time_buf[32];
	time_t epoch;
	const axa_p_missed_t *missed;

	switch (axa_p_recv(&emsg, client.in_sock, &client.recv_hdr,
			   &client.recv_body, &client.recv_len, client.addr,
			   protocol_mode==SRA ? AXA_P_FROM_SRA : AXA_P_FROM_RAD,
			   &client.alive)) {
	case AXA_P_RECV_RESULT_INCOM:
		return;
	case AXA_P_RECV_RESULT_ERR:
		clear_prompt();
		error_msg("%s", emsg.c);
		disconnect(true);
		return;
	case AXA_P_RECV_RESULT_DONE:
		break;
	default:
		AXA_FAIL("impossible axa_p_recv() result");
	}

	switch ((axa_p_op_t)client.recv_hdr.op) {
	case AXA_P_OP_NOP:
		if (axa_debug >= AXA_DEBUG_TRACE) {
			clear_prompt();
			printf("%s\n", axa_p_to_str(buf, sizeof(buf), true,
						    &client.recv_hdr,
						    client.recv_body));
		}
		break;

	case AXA_P_OP_HELLO:
		clear_prompt();
		axa_client_hello(&client, &client.recv_body->hello);
		printf("%s\n", axa_p_to_str(buf, sizeof(buf), true,
					    &client.recv_hdr,
					    client.recv_body));
		break;

	case AXA_P_OP_OK:
		clear_prompt();
		printf("%s\n", axa_p_to_str(buf, sizeof(buf), true,
					    &client.recv_hdr,
					    client.recv_body));
		break;

	case AXA_P_OP_ERROR:
		clear_prompt();
		printf("%s\n", axa_p_to_str(buf, sizeof(buf), true,
					    &client.recv_hdr,
					    client.recv_body));
		eclose_fnc();
		break;

	case AXA_P_OP_MISSED:
		if (packet_counting && packet_count < 0)
			break;
		missed = &client.recv_body->missed;
		epoch = AXA_P2H32(missed->last_reported);
		strftime(time_buf, sizeof(time_buf), "%Y/%m/%d %T",
			 localtime(&epoch));
		print_recv_tag_op();
		printf("    lost %ld input packets,"
		       " dropped %ld for congestion,\n"
		       "\t%ld for per sec limit,"
		       " %ld for per day limit\n"
		       "\tsince %s\n",
		       AXA_P2H64(missed->input_dropped),
		       AXA_P2H64(missed->dropped),
		       AXA_P2H64(missed->sec_rlimited),
		       AXA_P2H64(missed->day_rlimited),
		       time_buf);
		break;

	case AXA_P_OP_WHIT:
		print_whit(&client.recv_body->whit,
			   client.recv_len - sizeof(client.recv_hdr),
			   "", "");
		break;

	case AXA_P_OP_AHIT:
		print_ahit();
		break;

	case AXA_P_OP_WLIST:
	case AXA_P_OP_ALIST:
	case AXA_P_OP_OPT:
		clear_prompt();
		printf("%s\n", axa_p_to_str(buf, sizeof(buf), false,
					    &client.recv_hdr,
					    client.recv_body));
		break;

	case AXA_P_OP_CLIST:
		print_channel();
		break;

	case AXA_P_OP_USER:
	case AXA_P_OP_JOIN:
	case AXA_P_OP_PAUSE:
	case AXA_P_OP_GO:
	case AXA_P_OP_WATCH:
	case AXA_P_OP_WGET:
	case AXA_P_OP_ANOM:
	case AXA_P_OP_AGET:
	case AXA_P_OP_STOP:
	case AXA_P_OP_ALL_STOP:
	case AXA_P_OP_CHANNEL:
	case AXA_P_OP_CGET:
	case AXA_P_OP_ACCT:
	default:
		AXA_FAIL("impossible SRA op of %d from %s",
			 client.recv_hdr.op, client.addr);
	}
	axa_client_flush(&client);
}

/* Send a command to the SRA or RAD server. */
static int				/* 1=ok 0=failed -1=would be syntax */
srvr_send(axa_tag_t tag, axa_p_op_t op, const void *b, size_t b_len)
{
	axa_p_hdr_t hdr;
	axa_p_send_result_t result;
	size_t done;
	char pbuf[120];

	result = axa_p_send(&emsg, client.out_sock, AXA_P_PVERS, tag, op, &hdr,
			    b, b_len, NULL, 0, &done, client.addr,
			    protocol_mode == SRA ? AXA_P_TO_SRA : AXA_P_TO_RAD,
			    &client.alive);

	if (axa_debug >= AXA_DEBUG_TRACE) {
		clear_prompt();
		printf("sending %s\n",
		       axa_p_to_str(pbuf, sizeof(pbuf), true, &hdr, b));
	}
	if (result != AXA_P_SEND_BAD)
		return (1);

	error_msg("%s", emsg.c);
	disconnect(true);
	return (0);
}

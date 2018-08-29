/*
 * SIE Remote Access (SRA) ASCII tool
 *
 *  Copyright (c) 2014-2018 by Farsight Security, Inc.
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

/* extern: cmd.c */
extern size_t prompt_len;
extern struct timeval prompt_cleared;
extern struct timeval no_reprompt;
extern bool no_prompt;
extern struct timeval cmd_input;
extern EditLine *el_e;
extern char *history_savefile;
extern History *el_history;
extern HistEvent el_event;
extern axa_mode_t mode;

/* extern: infile.c */
extern in_files_t in_files[];
extern int in_file_cur;

/* extern: server.c */
extern axa_client_t client;

/* extern: signal.c */
extern bool interrupted;		/* true when asynch-interrupted */

/* extern: output.c */
extern bool out_on;
extern char *out_addr;

/* global */
axa_emsg_t emsg;			/* AXA error message blob */
uint axa_debug;				/* debug level */
uint verbose = 0;			/* verbosity level */
bool quiet;				/* quiet mode */
nmsg_input_t nmsg_input;		/* NMSG null input object */
int packet_count;			/* current packet count */
int packet_count_total;			/* total packet count to limit */
bool packet_counting;			/* true if we're limiting via count */

/* private */
static nmsg_output_t nmsg_pres;

void AXA_NORETURN
stop(int status)
{
	if (el_e != NULL) {
		if (el_history)
			history(el_history, &el_event, H_SAVE,
					history_savefile);
		history_end(el_history);
		el_end(el_e);
	}
	close_in_files();
	fflush(stderr);
	fflush(stdout);
	disconnect(false);
	if (nmsg_input != NULL)
		nmsg_input_close(&nmsg_input);
	if (nmsg_pres != NULL)
		nmsg_output_close(&nmsg_pres);	/* this closes stdout */
	out_close(false);

	axa_unload_fields();
	axa_unload_client_config();

	axa_io_cleanup();

	exit(status);
}

int
main(int argc, char **argv)
{
	const char *fields_file = "";
	const char *config_file = "";
#if LIBEDIT_IS_UNICODE
	wchar_t wc;
#endif
	char cmd_buf[500];
	const char *cmd;
	int cmd_len;
	bool version = false;
	const char *cfile = NULL;
	struct stat stat_buf;
	size_t n;
	nmsg_res res;
	char *p;
	int i;

	axa_set_me(argv[0]);
	AXA_ASSERT(axa_parse_log_opt(NULL, "trace,off,stderr"));
	AXA_ASSERT(axa_parse_log_opt(NULL, "error,off,stderr"));
	axa_syslog_init();
	axa_set_core();
	axa_client_init(&client);

	if (strcmp(axa_prog_name, "radtool") == 0)
		mode = RAD;

	if (isatty(STDIN_FILENO))
		el_e = el_init(axa_prog_name, stdin, stdout, stderr);
	if (el_e != NULL) {
		int flag;

		if (0 > el_get(el_e, EL_EDITMODE, &flag) || !flag) {
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
		history_get_savefile();
		history(el_history, &el_event, H_LOAD, history_savefile);
		el_set(el_e, EL_HIST, history, el_history);
		el_set(el_e, EL_PROMPT, el_prompt);
		el_set(el_e, EL_SIGNAL, 1);
		el_set(el_e, EL_GETCFN, getcfn);
	}

	while ((i = getopt(argc, argv, "hVdNF:E:S:c:n:")) != -1) {
		switch (i) {
		case 'n':
			config_file = optarg;
			break;
		case 'V':
			version = true;
			break;

		case 'h':
			usage();
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

		case 'E':
			if (axa_tls_cipher_list(&emsg, optarg) == NULL)
				error_msg("%s", emsg.c);
			break;

		case 'S':
			if (!axa_tls_certs_dir(&emsg, optarg))
				error_msg("%s", emsg.c);
			break;

		case 'c':
			if (cfile != NULL)
				error_msg("only one -c allowed;"
					  " ignoring all but the last");
			cfile = optarg;
			break;

		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (version) {
		version_cmd(AXA_TAG_NONE, "", NULL);
		if (argc == 0)
			stop(EX_OK);
	}

	signal(SIGPIPE, SIG_IGN);
	if (el_e != NULL) {
		signal(SIGINT, sigint);
		signal(SIGTERM, sigterm);
		signal(SIGHUP, sigterm);
	}

	AXA_DEBUG_TO_NMSG(axa_debug);
	res = nmsg_init();
	if (res != nmsg_res_success) {
		error_msg("nmsg_init(): %s", nmsg_res_lookup(res));
		exit(EX_SOFTWARE);
	}
	nmsg_input = nmsg_input_open_null();
	AXA_ASSERT(nmsg_input != NULL);
	nmsg_pres = nmsg_output_open_pres(STDOUT_FILENO);

	axa_load_fields(fields_file);
	if (!axa_load_client_config(&emsg, &config_file)) {
		if (axa_debug != 0)
			error_msg("%s", emsg.c);
	}
	/* client config must not have group/other persmissions set */
	else {
		if (stat(config_file, &stat_buf) == -1) {
			error_msg("can't stat config file \"%s\": %s",
					config_file, strerror(errno));
			axa_unload_client_config();
			exit(EXIT_FAILURE);
		}
		if (stat_buf.st_mode & (S_IRWXO | S_IRWXG)) {
			error_msg("config file \"%s\" has persmissions set for group/other, please `chmod 600 %s`",
					config_file, config_file);
			axa_unload_client_config();
			exit(EXIT_FAILURE);
		}
	}

	/* Answer commands from the control file. */
	if (cfile != NULL) {
		axa_asprintf(&p, "source %s", cfile);
		if (el_e != NULL)
			history(el_history, &el_event, H_ENTER, p);
		if (!do_cmds(p))
			error_msg(" initial \"-c %s\" failed", cfile);
		free(p);
	}

	/* Answer commands from the command line. */
	while (argc != 0) {
		if (el_e != NULL)
			history(el_history, &el_event, H_ENTER, *argv);
		if (!do_cmds(*argv)) {
			error_msg(" initial command \"%s\" failed", *argv);
			break;
		}

		++argv;
		--argc;
	}

	for (;;) {
		cmd_input.tv_sec = 0;
		fflush(stderr);
		fflush(stdout);

		if (in_file_cur > 0) {
			/* Get a command from a "sourced" file. */
			if (interrupted) {
				close_in_files();
				continue;
			}
			cmd = axa_fgetln(in_files[in_file_cur].f,
					 in_files[in_file_cur].name,
					 &in_files[in_file_cur].lineno,
					 &in_files[in_file_cur].buf,
					 &in_files[in_file_cur].buf_size);
			if (cmd == NULL) {
				close_in_file_cur();
				continue;
			}
			if (axa_debug != 0) {
				printf("< %s\n", cmd);
				fflush(stdout);
			}

		} else if (el_e != NULL) {
			/* Get a command from the terminal via editline(3). */
			cmd = el_gets(el_e, &cmd_len);
			prompt_len = 0;
			if (!interrupted) {
				if (cmd == NULL) {
					fputc('\n', stdout);
					if (cmd_len == -1)
					    error_msg("el_gets(): %s",
						      strerror(errno));
					stop(EX_OK);
				}

				/* Save nontrivial command lines. */
				if (*(cmd+strspn(cmd, AXA_WHITESPACE)) != '\0')
					history(el_history, &el_event,
						H_ENTER, cmd);
			}

		} else if (!interrupted) {
			/* Get a command from stdin. */
			n = 0;
			for (;;) {
#if LIBEDIT_IS_UNICODE
				getcfn(NULL, &wc);
				cmd_buf[n] = wctob(wc);
#else
				getcfn(NULL, &cmd_buf[n]);
#endif
				if (cmd_buf[n++] == '\n'
				    || n >= sizeof(cmd_buf)-1)
					break;
			}
			cmd_buf[n] = '\0';
			cmd = cmd_buf;
		}

		if (interrupted) {
			interrupted = false;
			if (el_e != NULL) {
				el_set(el_e, EL_UNBUFFERED, 0);
				el_reset(el_e);
				if (prompt_cleared.tv_sec != 0) {
					packet_counting = true;
					packet_count = 0;
					packet_count_total = 0;
				}
			}
			close_in_files();
			fputs(" (int)\n", stdout);
			continue;
		}

		if (!do_cmds(cmd)) {
			fputs(" ?\n", stderr);
			fflush(stdout);
			close_in_files();
		}
	}
}

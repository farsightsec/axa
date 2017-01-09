/*
 * Tunnel SIE data from an SRA or RAD server.
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

#include "sratunnel.h"

/* extern: output.c */
extern bool out_bar_on;
extern bool nmsg_zlib;

/* extern: server.c */
extern axa_client_t client;

/* extern signal.c */
extern int terminated;

/* global */
uint axa_debug;				/* debug level */
int count;				/* limit to this many */
int trace = 0;				/* server-side trace level */
int initial_count;			/* initial count */
bool counting = false;			/* true == limiting packets to count */
bool first_time;			/* true == first time connecting */
nmsg_input_t nmsg_input;		/* NMSG input object */
FILE *fp_pidfile = NULL;		/* PID file FILE pointer */
const char *pidfile;			/* PID file file name */
const char *srvr_addr;			/* SRA/RAD server string */
axa_mode_t mode;			/* SRA or RAD */
axa_cnt_t rlimit = 0;			/* rate limit, packets per second */
arg_t *chs = NULL;			/* channels */
arg_t *watches = NULL;			/* watches */
arg_t *anomalies = NULL;		/* anomalies */
const char *out_addr;			/* output address */
double sample = 0.0;			/* sampling rate */

/* private */
static bool version;
static struct timeval time_out_flush;
static uint acct_interval;
static struct timeval acct_timer;

static void AXA_NORETURN AXA_PF(1,2)
usage(const char *msg, ...)
{
	const char *sra = "SIE Remote Access Tunnel (sratunnel)\n";
	const char *rad = "Real-time Anomaly Detection Tunnel (radtunnel)\n";
	va_list args;

	printf("%s", mode == SRA ? sra : rad);
	printf("(c) 2013-2016 Farsight Security, Inc.\n");
	printf("%s [options]\n", axa_prog_name);
	if (mode == SRA) {
		printf("-c channel\t\tenable channel\n");
		printf("-o output\t\tspecify destination of SIE data\n");
		printf("-s [user@]SRA-server\tconnect to SRA server\n");
		printf("-w watch\t\tset watch\n");
	}
	if (mode == RAD) {
		printf("-a anomaly\t\tenable anomaly detection module\n");
		printf("-o output\t\tspecify destination of SIE data\n");
		printf("-s [user@]RAD-server\tconnect to RAD server\n");
		printf("-w watch\t\tset watch\n");
	}
	printf("\n[-A interval]\t\temit acct messages to stdout every interval seconds\n");
	printf("[-C count]\t\tstop after processing count messages\n");
	printf("[-d]\t\t\tincrement debug level, -ddd > -dd > -d\n");
	printf("[-E ciphers]\t\tuse these TLS ciphers\n");
	printf("[-h]\t\t\tdisplay this help and exit\n");
	printf("[-V]\t\t\tprint version and quit\n");
	printf("[-m rate]\t\tsampling %% of packets over 1 second, 0.01 - 100.0\n");
	printf("[-O]\t\t\tenable spinning bar on output\n");
	printf("[-P file]\t\twrite PID to pidfile\n");
	printf("[-r limit]\t\trate limit to this many packets per second\n");
	printf("[-S dir]\t\tspecify TLS certificates directory\n");
	printf("[-t]\t\t\tincrement server trace level, -ttt > -tt > -t\n");
	printf("[-z]\t\t\tenable nmsg zlib container compression\n");

	if (msg != NULL) {
		va_start(args, msg);
		axa_verror_msg(msg, args);
		va_end(args);
	}
	exit(EX_USAGE);
}

int
main(int argc, char **argv)
{
	const char *config_file = "";
	arg_t *arg;
	struct timeval now;
	time_t ms;
	nmsg_res res;
	axa_emsg_t emsg;
	char *p;
	const char *cp;
	int i;

	axa_set_me(argv[0]);
	AXA_ASSERT(axa_parse_log_opt(&emsg, "trace,off,stdout"));
	AXA_ASSERT(axa_parse_log_opt(&emsg, "error,off,stderr"));
	axa_syslog_init();
	axa_clean_stdio();
	axa_set_core();
	axa_client_backoff_reset(&client);
	axa_client_init(&client);

	if (strcmp(axa_prog_name, "radtunnel") == 0)
		mode = RAD;

	version = false;
	pidfile = NULL;
	while ((i = getopt(argc, argv, "ha:A:VdtOC:r:E:P:S:o:s:c:w:m:n:z"))
			!= -1) {
		switch (i) {
		case 'A':
			acct_interval = atoi(optarg);
			if (acct_interval <= 0) {
				axa_error_msg("invalid \"-A %s\"", optarg);
				exit(EX_USAGE);
			}
			gettimeofday(&acct_timer, NULL);
			break;

		case 'V':
			version = true;
			break;

		case 'd':
			++axa_debug;
			break;

		case 'h':
			usage(NULL);
			break;

		case 't':
			++trace;
			break;

		case 'm':
			sample = atof(optarg);
			if (sample <= 0.0 || sample > 100.0) {
				axa_error_msg("invalid \"-a %s\"", optarg);
				exit(EX_USAGE);
			}
			break;
		case 'n':
			config_file = optarg;
			break;

		case 'O':
			out_bar_on = true;
			break;

		case 'o':
			out_addr = optarg;
			break;

		case 'P':
			pidfile = optarg;
			break;

		case 'C':
			count = strtoul(optarg, &p, 10);
			if (*optarg == '\0'
			    || *p != '\0'
			    || count < 1) {
				axa_error_msg("invalid \"-C %s\"", optarg);
				exit(EX_USAGE);
			}
			initial_count = count;
			counting = true;
			break;

		case 'r':
			rlimit = strtoul(optarg, &p, 10);
			if (*optarg == '\0'
			    || *p != '\0'
			    || rlimit < 1 || rlimit > AXA_RLIMIT_MAX) {
				axa_error_msg("invalid \"-r %s\"", optarg);
				exit(EX_USAGE);
			}
			break;

		case 'E':
			if (axa_tls_cipher_list(&emsg, optarg) == NULL)
				axa_error_msg("%s", emsg.c);
			break;

		case 'S':
			if (!axa_tls_certs_dir(&emsg, optarg))
				axa_error_msg("%s", emsg.c);
			break;

		case 's':
			srvr_addr = optarg;
			break;

		case 'c':
			arg = AXA_SALLOC(arg_t);
			arg->c = optarg;
			arg->next = chs;
			chs = arg;
			break;

		case 'w':
			arg = AXA_SALLOC(arg_t);
			arg->c = optarg;
			arg->next = watches;
			watches = arg;
			break;

		case 'a':
			arg = AXA_SALLOC(arg_t);
			arg->c = optarg;
			arg->next = anomalies;
			anomalies = arg;
			break;

		case 'z':
			nmsg_zlib = true;
			break;
		default:
			usage(NULL);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0) {
		usage("unrecognized \"%s\"", argv[0]);
	}

	if (version) {
		axa_trace_msg(AXA_PVERS_STR" AXA protocol %d", AXA_P_PVERS);
		if (srvr_addr == NULL && out_addr == NULL
		    && chs == NULL && watches == NULL
		    && anomalies == NULL)
			exit(0);
	}
	if (srvr_addr == NULL)
		usage("server not specified with -s");
	if (out_addr == NULL)
		usage("output not specified with -o");
	if (watches == NULL)
		usage("no watches specified with -w");
	if (mode == RAD) {
		if (anomalies == NULL)
			usage("anomalies specified with -a");
		if (chs != NULL) {
			axa_error_msg("\"-c %s\" not allowed in RAD mode",
					chs->c);
			while ((arg = chs) != NULL) {
				chs = arg->next;
				free(arg);
			}
			exit(0);
		}
	} else {
		if (anomalies != NULL) {
			axa_error_msg("\"-a %s\" not allowed in SRA mode",
				      anomalies->c);
			while ((arg = anomalies) != NULL) {
				anomalies = arg->next;
				free(arg);
			}
			exit(0);
		}
	}

	axa_load_client_config(config_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, sigterm);
	signal(SIGTERM, sigterm);
	signal(SIGINT, sigterm);
#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif

	if (!out_open())
		exit(EX_IOERR);

	AXA_DEBUG_TO_NMSG(axa_debug);
	res = nmsg_init();
	if (res != nmsg_res_success) {
		axa_error_msg("nmsg_init(): %s", nmsg_res_lookup(res));
		exit(EX_SOFTWARE);
	}
	nmsg_input = nmsg_input_open_null();
	AXA_ASSERT(nmsg_input != NULL);

    if (pidfile) {
        fp_pidfile = pidfile_open();
        if (fp_pidfile == NULL)
            exit(EX_SOFTWARE);
        pidfile_write();
    }

	/*
	 * Continually reconnect to the SRA or RAD server and forward SIE data.
	 */
	first_time = true;
	for (;;) {
		if (terminated != 0)
			stop(terminated);

		/* (Re)connect to the server if it is time. */
		if (!AXA_CLIENT_CONNECTED(&client)) {
			ms = axa_client_again(&client, &now);
			if (ms <= 0) {
				srvr_connect();
			} else {
				if (axa_debug != 0
				    && (ms >= 100
					|| axa_debug >= AXA_DEBUG_TRACE))
					axa_trace_msg("delaying %.1f"
						      " seconds to re-connect",
						      ms/1000.0);
				usleep(ms*1000);
			}
			continue;
		}

		/* Flush the output buffer after silence. */
		gettimeofday(&now, NULL);
		if (time_out_flush.tv_sec != 0) {
			ms = (OUT_FLUSH_MS - axa_elapsed_ms(&now,
							&time_out_flush));
			if (ms <= 0) {
				out_flush();
				continue;
			}
		}
		/* check to see if it's time for an accounting update */
		if (acct_interval) {
			gettimeofday(&now, NULL);
			if (now.tv_sec - acct_timer.tv_sec >= acct_interval) {
				srvr_send(1, AXA_P_OP_ACCT, NULL, 0);
				acct_timer.tv_sec = now.tv_sec;
			}
		}
		switch (axa_io_wait(&emsg, &client.io, OUT_FLUSH_MS,
				    true, true)) {
		case AXA_IO_ERR:
			disconnect(true, "%s", emsg.c);
			break;
		case AXA_IO_TUNERR:
			for (;;) {
				cp = axa_io_tunerr(&client.io);
				if (cp == NULL)
					break;
				axa_error_msg("%s", cp);
			}
			break;
		case AXA_IO_BUSY:
			break;
		case AXA_IO_KEEPALIVE:
			srvr_send(AXA_TAG_NONE, AXA_P_OP_NOP, NULL, 0);
			continue;
		case AXA_IO_OK:
			/* Process a message from the server. */
			forward();
			break;
		default:
			AXA_FAIL("impossible axa_io_wait() result");
		}
	}
}

void AXA_NORETURN
stop(int s)
{
	arg_t *arg;

	/* Free everything when we quit to check for memory leaks */

	axa_client_close(&client);
	if (nmsg_input != NULL)
		nmsg_input_close(&nmsg_input);
	out_close();

	while ((arg = chs) != NULL) {
		chs = arg->next;
		free(arg);
	}
	while ((arg = watches) != NULL) {
		watches = arg->next;
		free(arg);
	}
	while ((arg = anomalies) != NULL) {
		anomalies = arg->next;
		free(arg);
	}

	axa_io_cleanup();

	if (pidfile)
		if (unlink(pidfile) != 0)
			fprintf(stderr, "unlink() failed: %s\n",
					strerror(errno));
	exit(s);
}

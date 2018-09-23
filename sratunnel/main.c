/*
 * Tunnel SIE data from an SRA or RAD server.
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

#include "sratunnel.h"

/* extern: output.c */
extern bool out_bar_on;
extern bool nmsg_zlib;
extern uint output_tsindex_write_interval;

/* extern: axalib/open_nmsg_out.c */
extern bool axa_out_file_append;

/* extern: server.c */
extern axa_client_t client;

/* extern signal.c */
extern int terminated;
extern int give_status;

/* global */
uint axa_debug;				/* debug level */
int count;				/* limit to this many */
unsigned long count_messages_sent = 0;  /* how many messages we have sent */
unsigned long count_messages_rcvd = 0;  /* how many messages we have received */
unsigned long count_hits = 0;           /* how many hits received */
int trace = 0;				/* server-side trace level */
int initial_count;			/* initial count */
bool counting = false;			/* true == limiting packets to count */
bool first_time;			/* true == first time connecting */
nmsg_input_t nmsg_input;		/* NMSG input object */
FILE *fp_pidfile = NULL;		/* PID file FILE pointer */
FILE *fp_tsindex = NULL;		/* timestamp index file pointer */
const char *pidfile;			/* PID file file name */
const char *srvr_addr;			/* SRA/RAD server string */
axa_mode_t mode;			/* SRA or RAD */
axa_cnt_t rlimit = 0;			/* rate limit, packets per second */
arg_t *chs = NULL;			/* channels */
arg_t *watches = NULL;			/* watches */
arg_t *anomalies = NULL;		/* anomalies */
const char *out_addr;			/* output address */
double sample = 0.0;			/* sampling rate */
MDB_env *mdb_env;			/* timestamp index db environment */
MDB_dbi mdb_dbi;			/* timestamp index db handle */
MDB_txn *mdb_txn;			/* timestamp index transaction handle */

/* private */
static bool version;
static struct timeval time_out_flush;
static uint acct_interval;
static struct timeval acct_timer;

void print_status(void);

static void
lmdb_shutdown(void)
{
	/* try to commit any outstanding data before closing the db */
	(void) mdb_txn_commit(mdb_txn);
	(void) mdb_dbi_close(mdb_env, mdb_dbi);
	(void) mdb_env_close(mdb_env);
}

static void AXA_NORETURN AXA_PF(1,2)
usage(const char *msg, ...)
{
	const char *sra = "SIE Remote Access Tunnel (sratunnel)\n";
	const char *rad = "Real-time Anomaly Detection Tunnel (radtunnel)\n";
	va_list args;

	if (msg != NULL) {
		printf("%s: ", axa_prog_name);
		va_start(args, msg);
		axa_verror_msg(msg, args);
		va_end(args);
		printf("\n");
	}

	printf("%s", mode == SRA ? sra : rad);
	printf("(c) 2014-2018 Farsight Security, Inc.\n");
	printf("Usage: %s [options]\n", axa_prog_name);
	if (mode == SRA) {
		printf("-c channel\t\tenable channel\n");
		printf("-o output\t\tspecify destination of SIE data\n");
		printf("-s [user@]server|alias\tconnect to SRA server\n");
		printf("-w watch\t\tset watch\n");
	}
	if (mode == RAD) {
		printf("-a anomaly\t\tenable anomaly detection module\n");
		printf("-o output\t\tspecify destination of SIE data\n");
		printf("-s [user@]server|alias\tconnect to RAD server\n");
		printf("-w watch\t\tset watch\n");
	}
	printf("\n[-A interval]\t\temit acct messages to stdout every interval seconds\n");
	printf("[-C count]\t\tstop after processing count messages\n");
	printf("[-d]\t\t\tincrement debug level, -ddd > -dd > -d\n");
	printf("[-E ciphers]\t\tuse these TLS ciphers\n");
	printf("[-h]\t\t\tdisplay this help and exit\n");
	printf("[-i interval]\t\twrite timestamp indexes every interval nmsgs\n");
	printf("[-V]\t\t\tprint version and quit\n");
	printf("[-m rate]\t\tsampling %% of packets over 1 second, 0.01 - 100.0\n");
	printf("[-n file]\t\tspecify AXA config file\n");
	printf("[-O]\t\t\tenable spinning bar on output\n");
	printf("[-P file]\t\twrite PID to pidfile\n");
	printf("[-p]\t\t\tappend to output file (only valid for file outputs)\n");
	printf("[-r limit]\t\trate limit to this many packets per second\n");
	printf("[-S dir]\t\tspecify TLS certificates directory\n");
	printf("[-t]\t\t\tincrement server trace level, -ttt > -tt > -t\n");
	printf("[-u]\t\t\tunbuffer nmsg container output\n");
	printf("[-z]\t\t\tenable nmsg zlib container compression\n");

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
	size_t n = 0;
	bool output_buffering = true;
	char out_filename[BUFSIZ], lmdb_filename[BUFSIZ];

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
	while ((i = getopt(argc, argv, "hi:a:pA:VdtOC:r:E:P:S:o:s:c:w:m:n:uz"))
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

		case 'p':
			axa_out_file_append = true;
			break;

		case 'd':
			++axa_debug;
			break;

		case 'h':
			usage(NULL);
			break;

		case 'i':
			output_tsindex_write_interval = atoi(optarg);
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

		case 'u':
			output_buffering = false;
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
#if AXA_P_PVERS_MIN != AXA_P_PVERS_MAX
	axa_trace_msg("%s built using AXA library %s, AXA protocol %d in %d to %d\n",
	       axa_prog_name, axa_get_version(),
	       AXA_P_PVERS, AXA_P_PVERS_MIN, AXA_P_PVERS_MAX);
#else
	axa_trace_msg("%s built using AXA library: %s, AXA protocol: %d\n",
	       axa_prog_name, axa_get_version(), AXA_P_PVERS);
#endif
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

	if (!axa_load_client_config(&emsg, config_file)) {
			axa_error_msg("can't load config file: %s", emsg.c);
			exit(EXIT_FAILURE);
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, sigterm);
	signal(SIGTERM, sigterm);
	signal(SIGINT, sigterm);
#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif
#ifdef SIGINFO
        signal(SIGINFO, siginfo);
#endif
	/* When appending, demand that the output file exists. */
	if (axa_out_file_append) {
		n = strlcpy(out_filename, strrchr(out_addr, ':') + 1,
				sizeof (out_filename));

		if (access(out_filename, F_OK) == -1) {
			axa_error_msg("append mode expected to find output file \"%s\": %s\n",
					out_filename, strerror(errno));
			exit(EX_SOFTWARE);
		}
		else if (axa_debug > 0)
			axa_trace_msg("appending to nmsg file \"%s\"\n", out_filename);
	}

	if (!out_open(output_buffering))
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

	if (output_tsindex_write_interval > 0) {
		int rc = 0, pagesize = 0;

		/* Timestamp indexing requires unbuffered filesystem writes. */
		if (output_buffering == true) {
			axa_error_msg("can't store timestamp indexes when buffering output (need `-u`)\n");
			exit(EX_SOFTWARE);
		}

		n = strlcpy(lmdb_filename, strrchr(out_addr, ':') + 1,
				sizeof (lmdb_filename));
		strlcpy(lmdb_filename + n, ".mdb", sizeof (lmdb_filename) - n);

		/* Timestamp indexing + appending requires a previously created
		 * index file (which should correspond to the output file being
		 * appended to -- the only way we can try to enforce that is
		 * by checking the output filename).
		 */
		if (axa_out_file_append == true) {
			if (access(lmdb_filename, F_OK) == -1) {
				axa_error_msg("tsindex mode expected to find tsindex file \"%s\": %s\n",
						lmdb_filename, strerror(errno));
				exit(EX_SOFTWARE);
			}
			else if (axa_debug > 0)
				axa_trace_msg("found tsindex file \"%s\"\n", lmdb_filename);
		}
		else {
			/* An orphaned mdb file is clobbered lest we write to
			 * it and end up mixing with timestamps and offsets
			 * from a previous unrelated session.
			 */
			if (unlink(lmdb_filename) == -1) {
				axa_error_msg("found orphan tsindex file \"%s\" but can't delete it: %s\n",
						lmdb_filename, strerror(errno));
				exit(EX_SOFTWARE);
			}
			else if (axa_debug > 0)
				axa_trace_msg("found and deleted orphan tsindex file \"%s\"\n",
						lmdb_filename);
		}

		rc = mdb_env_create(&mdb_env);
		if (rc != 0) {
			axa_error_msg("mdb_env_create(): %s", mdb_strerror(rc));
			exit(EX_SOFTWARE);
		}
		pagesize = getpagesize();
		/* lmdb is a memory mapped database. The mapsize should be a
		 * multiple of the OS page size (usually 4,096 bytes). The
		 * size of the memory map is also the maximum size of the
		 * database. As such, we should periodically check to see if
		 * we're close to running out of space and resize.
		 */
		rc = mdb_env_set_mapsize(mdb_env, pagesize * 2560);
		if (rc != 0) {
			axa_error_msg("mdb_env_set_mapsize(): %s",
					mdb_strerror(rc));
			exit(EX_SOFTWARE);
		}

		if (axa_debug != 0)
			axa_trace_msg("writing timestamp offsets to %s every %u nmsgs\n",
					lmdb_filename,
					output_tsindex_write_interval);
		rc = mdb_env_open(mdb_env, lmdb_filename,
				MDB_NOSUBDIR, 0664);
		if (rc != 0) {
			axa_error_msg("mdb_env_open(): %s", mdb_strerror(rc));
			exit(EX_SOFTWARE);
		}
		rc = mdb_txn_begin(mdb_env, NULL, 0, &mdb_txn);
		if (rc != 0) {
			axa_error_msg("mdb_txn_begin(): %s", mdb_strerror(rc));
			exit(EX_SOFTWARE);
		}
		rc = mdb_dbi_open(mdb_txn, NULL, MDB_INTEGERKEY, &mdb_dbi);
		if (rc != 0) {
			axa_error_msg("mdb_dbi_open(): %s", mdb_strerror(rc));
			exit(EX_SOFTWARE);
		}
		rc = mdb_set_compare(mdb_txn, mdb_dbi, axa_tsi_mdb_cmp);
		if (rc != 0) {
			axa_error_msg("mdb_set_compare(): %s", mdb_strerror(rc));
			exit(EX_SOFTWARE);
		}
		atexit(lmdb_shutdown);
	}

	/*
	 * Continually reconnect to the SRA or RAD server and forward SIE data.
	 */
	first_time = true;
	for (;;) {
		if (terminated != 0)
			stop(terminated);
                if (give_status != 0) {
                        give_status = 0;
                        print_status();
                }

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
				if (!srvr_send(1, AXA_P_OP_ACCT, NULL, 0)) {
					continue;
				}
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
			/* nothing to do here if srvr_send() fails, we just
			 * hope it was ephemeral and do our backoff and retry
			 * thing */
			(void) srvr_send(AXA_TAG_NONE, AXA_P_OP_NOP, NULL, 0);
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

void print_status(void)
{
        printf("%s ", mode == SRA ? "sra" : "rad");
        if (!AXA_CLIENT_CONNECTED(&client))
                printf("NOT-");
        printf("connected, ");

        /* print with the proper pluralization */
        printf("sent %lu message%s, received %lu message%s, %lu hit%s\n",
               count_messages_sent, count_messages_sent != 1 ? "s" : "",
               count_messages_rcvd, count_messages_rcvd != 1 ? "s" : "",
               count_hits, count_hits != 1 ? "s" : "");
}



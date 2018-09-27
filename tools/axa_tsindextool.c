/*
 * Advanced Exchange Access (AXA) tsindextool
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <nmsg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __linux
#include <bsd/string.h>
#endif

#include <lmdb.h>
#include <axa/mdb.h>

static void
usage(const char *name, const char *hint)
{
	printf("AXA Timestamp Index Tool (tsindextool)\n");
	printf("(c) 2018 Farsight Security, Inc.\n");
	printf("Usage: %s -f foo.nmsg.mdb -r foo.nmsg -t 1537806295 -c 10\n\n",
			name);
	printf("[-c n]\t\t\tnumber of nmsgs to extract\n");
	printf("[-e timestamp]\t\ttimestamp of ending nmsg\n");
	printf("[-f file]\t\tspecify mdb file\n");
	printf("[-h]\t\t\thelp\n");
	printf("[-j file]\t\tspecify json nmsg file\n");
	printf("[-r file]\t\tspecify binary nmsg\n");
	printf("[-s timestamp]\t\ttimestamp of starting nmsg\n");
	printf("[-v]\t\t\tincrement verbosity -vvv > -vv > -v\n");
	printf("[-x]\t\t\trequire exact starting timestamp\n");
	if (hint != NULL)
		printf("\n%s\n", hint);

}

int
main(int argc, char *argv[])
{
	int n, c, rc, ec = EXIT_FAILURE, fd_in = -1, fd_out = -1, verbosity = 0;
	uint32_t ts_start = 0, ts_end = 0, count = 0, nmsg_cnt = 0;
	MDB_env *env = NULL;
	MDB_txn *txn = NULL;
	MDB_dbi dbi;
	MDB_val key, data;
	MDB_cursor *cursor = NULL;
	struct timespec ts, msg_ts;
	off_t *offset;
	nmsg_input_t nmsg_in;
	nmsg_output_t nmsg_out;
	nmsg_res res;
	nmsg_message_t msg;
	char *json;
	bool input_json = false, input_nmsg = false, is_counting = false, need_exact = false;
	const char *lmdb_filename = NULL, *nmsg_filename_in = NULL;
	char nmsg_filename_out[BUFSIZ] = {0};

	while ((c = getopt(argc, argv, "c:e:f:j:r:s:hvx")) != EOF) {
		switch (c) {
			case 'c':
				count = atoi(optarg);
				is_counting = true;
				break;
			case 'e':
				ts_end = atoi(optarg);
				break;
			case 'f':
				lmdb_filename = optarg;
				break;
			case 'j':
				nmsg_filename_in = optarg;
				input_json = true;
				break;
			case 'r':
				nmsg_filename_in = optarg;
				input_nmsg = true;
				break;
			case 's':
				ts_start = atoi(optarg);
				break;
			case 'v':
				verbosity++;
				break;
			case 'x':
				need_exact = true;
				break;
			case 'h':
			default:
				usage(argv[0], NULL);
				goto done;
		}
	}

	if (ts_start == 0) {
		usage(argv[0], "Need a starting timestamp (-s).");
		goto done;
	}
	if (lmdb_filename == NULL) {
		usage(argv[0], "Need a tsindex file (-f).");
		goto done;
		return (EXIT_FAILURE);
	}
	if ((input_json == false && input_nmsg == false) ||
			(input_json && input_nmsg)) {
		usage(argv[0], "Need either an nmsg json file (-j) or binary nmsg file (-r).");
		goto done;
		return (EXIT_FAILURE);
	}
	if ((ts_end == 0 && count == 0) ||
			(ts_end != 0 && count != 0)) {
		usage(argv[0], "Need either an ending timestamp (-e) or a count (-c).");
		goto done;
		return (EXIT_FAILURE);
	}

	res = nmsg_init();
	if (res != nmsg_res_success) {
		fprintf(stderr, "Error initializing NMSG library: %s\n",
				nmsg_res_lookup(res));
		goto done;
		return (EXIT_FAILURE);
	}

	fd_in = open(nmsg_filename_in, O_RDONLY);
	if (fd_in < 0) {
		fprintf(stderr, "Can't open nmsg input file \"%s\": %s\n",
				nmsg_filename_in, strerror(errno));
		goto done;
		return (EXIT_FAILURE);
	}
	n = strlcpy(nmsg_filename_out, nmsg_filename_in,
			sizeof (nmsg_filename_out));
	snprintf(nmsg_filename_out + n, sizeof (nmsg_filename_out) - n,
			"-tsindex.%u.%s", getpid(),
			input_json ? "json" : "nmsg");

	fd_out = open(nmsg_filename_out, O_CREAT | O_WRONLY, 0644);
	if (fd_out < 0) {
		fprintf(stderr, "Can't open nmsg output file \"%s\": %s\n",
				nmsg_filename_out, strerror(errno));
		goto done;
		return (EXIT_FAILURE);
	}

	if (input_json) {
		nmsg_in = nmsg_input_open_json(fd_in);
		if (nmsg_in == NULL) {
			fprintf(stderr, "nmsg_input_open_json() failed\n");
			goto done;
		}
		nmsg_out = nmsg_output_open_json(fd_out);
		if (nmsg_out == NULL) {
			fprintf(stderr, "nmsg_ouput_open_json() failed\n");
			goto done;
		}
	}
	else if (input_nmsg) {
		nmsg_in = nmsg_input_open_file(fd_in);
		if (nmsg_in == NULL) {
			fprintf(stderr, "nmsg_input_open_file() failed\n");
			goto done;
		}
		nmsg_out = nmsg_output_open_file(fd_out, NMSG_WBUFSZ_MAX);
		if (nmsg_out == NULL) {
			fprintf(stderr, "nmsg_ouput_open_file() failed\n");
			goto done;
		}
	}

	rc = mdb_env_create(&env);
	if (rc != 0) {
		fprintf(stderr, "mdb_create() failed: %s\n", mdb_strerror(rc));
		goto done;
	}

	rc = mdb_env_open(env, lmdb_filename, MDB_NOSUBDIR | MDB_RDONLY, 0664);
	if (rc != 0) {
		fprintf(stderr, "mdb_env_open failed(): %s\n",
				mdb_strerror(rc));
		goto done;
	}

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc != 0) {
		fprintf(stderr, "mdb_txn_begin failed(): %s\n",
				mdb_strerror(rc));
		goto done;
	}

	rc = mdb_open(txn, NULL, MDB_INTEGERKEY, &dbi);
	if (rc) {
		fprintf(stderr, "mdb_open(): %s\n", mdb_strerror(rc));
		goto done;
	}

	rc = mdb_set_compare(txn, dbi, axa_tsi_mdb_cmp);
	if (rc) {
		fprintf(stderr, "mdb_set_compare(): %s\n", mdb_strerror(rc));
		goto done;
	}

	ts.tv_sec = ts_start;
	ts.tv_nsec = 0;

	key.mv_size = sizeof (ts);
	key.mv_data = &ts;

	rc = mdb_cursor_open(txn, dbi, &cursor);
	if (rc) {
		fprintf(stderr, "mdb_cursor_open(): %s\n", mdb_strerror(rc));
		goto done;
	}

	rc = mdb_cursor_get(cursor, &key, &data,
			need_exact ? MDB_SET : MDB_SET_RANGE);
	if (rc == MDB_NOTFOUND) {
		printf("Did not find starting timestamp %u in %s.\n",
				ts_start, lmdb_filename);
		goto done;
	}
	if (rc) {
		fprintf(stderr, "mdb_cursor_get(): %s\n", mdb_strerror(rc));
		goto done;
	}

	(void) mdb_cursor_close(cursor);

	offset = (off_t *)data.mv_data;
	if (verbosity > 0)
		printf("Found %u at offset 0x%lx.\n", ts_start, (*offset));

	if (lseek(fd_in, *offset, SEEK_SET) == sizeof (off_t) - 1) {
		fprintf(stderr, "lseek(): %s\n", strerror(errno));
		goto done;
	}

	while (1) {
		if (is_counting) {
			if (count-- <= 0)
				break;
		}
		res = nmsg_input_read(nmsg_in, &msg);
		if (res == nmsg_res_eof) {
			if (verbosity > 0)
				printf("End of file reached.\n");
			break;
		}
		if (res != nmsg_res_success) {
			fprintf(stderr, "nmsg_input_read(): %s\n", nmsg_res_lookup(res));
			goto done;
		}

		if (is_counting == false) {
			nmsg_message_get_time(msg, &msg_ts);
			if (msg_ts.tv_sec >= ts_end) {
				nmsg_message_destroy(&msg);
				break;
			}
		}

		res = nmsg_output_write(nmsg_out, msg);
		if (res != nmsg_res_success) {
			fprintf(stderr, "nmsg_output_write(): %s\n", nmsg_res_lookup(res));
			nmsg_message_destroy(&msg);
			goto done;
		}

		if (verbosity > 1) {
			res = nmsg_message_to_json(msg, &json);
			if (res != nmsg_res_success) {
				fprintf(stderr, "nmsg_message_to_pres(): %s\n", nmsg_res_lookup(res));
				nmsg_message_destroy(&msg);
				goto done;
			}

			printf("%s\n", json);
			free(json);
		}
		nmsg_cnt++;
		nmsg_message_destroy(&msg);
	}

	ec = EXIT_SUCCESS;
	printf("Wrote %u nmsgs to %s.\n", nmsg_cnt, nmsg_filename_out);
done:
	if (fd_in != -1)
		close(fd_in);
	if (fd_out != -1)
		close(fd_out);
	if (nmsg_in != NULL)
		nmsg_input_close(&nmsg_in);
	if (nmsg_out != NULL)
		nmsg_output_close(&nmsg_out);
	if (txn != NULL)
		mdb_txn_abort(txn);
	if (env != NULL)
		mdb_env_close(env);

	return (ec);
}

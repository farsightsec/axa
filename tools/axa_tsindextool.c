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

#include <lmdb.h>
#include <axa/mdb.h>

static void
usage(const char *name)
{
	printf("AXA Timestamp Index Tool (tsindextool)\n");
	printf("(c) 2018 Farsight Security, Inc.\n");
	printf("Sample usage: %s -f foo.nmsg.mdb -r foo.nmsg -t 1537806295 -c 10\n\n", name);

	printf("-f file\t\tspecify mdb file\n");
	printf("-j file\t\tspecify json nmsg file\n");
	printf("-r file\t\tspecify binary nmsg\n");
	printf("-s timestamp\ttimestamp of starting nmsg\n");
	printf("-e timestamp\ttimestamp of ending nmsg\n");
	printf("-c n\t\tnumber of nmsgs to extract\n");
	printf("-h\t\thelp\n");
}

int
main(int argc, char *argv[])
{
	int c, rc, fd;
	uint32_t ts_start = 0, ts_end = 0, count = 0;
	MDB_env *env;
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val key, data;
	struct timespec ts;
	off_t *offset;
	nmsg_input_t nmsg;
	nmsg_res res;
	nmsg_message_t msg;
	char *json;
	bool input_json = false, input_nmsg = false;
	const char *lmdb_filename, *nmsg_filename;

	lmdb_filename = nmsg_filename = NULL;
	while ((c = getopt(argc, argv, "c:e:f:j:r:s:h")) != EOF) {
		switch (c) {
			case 'c':
				count = atoi(optarg);
				break;
			case 'e':
				ts_end = atoi(optarg);
				break;
			case 'f':
				lmdb_filename = optarg;
				break;
			case 'j':
				nmsg_filename = optarg;
				input_json = true;
				break;
			case 'r':
				nmsg_filename = optarg;
				input_nmsg = true;
				break;
			case 's':
				ts_start = atoi(optarg);
				break;
			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}

	if (ts_start == 0 || lmdb_filename == NULL ||
			(input_json == false && input_nmsg == false)) {
		usage(argv[0]);
		return (EXIT_FAILURE);
	}

	if ((ts_end == 0 && count == 0) || (ts_end != 0 && count != 0)) {
		usage(argv[0]);
		return (EXIT_FAILURE);
	}

	if (input_json && input_nmsg) {
		fprintf(stderr, "only -r or -j may be specified, not both\n");
		return (EXIT_FAILURE);
	}

	res = nmsg_init();
	if (res != nmsg_res_success) {
		fprintf(stderr, "error initializing NMSG library: %s\n",
				nmsg_res_lookup(res));
		return (EXIT_FAILURE);
	}

	fd = open(nmsg_filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "can't open nmsg input file \"%s\": %s\n",
				nmsg_filename, strerror(errno));
		return (EXIT_FAILURE);
	}

	if (input_json) {
		nmsg = nmsg_input_open_json(fd);
		if (nmsg == NULL) {
			fprintf(stderr, "nmsg_input_open_json() failed\n");
			close(fd);
			return (EXIT_FAILURE);
		}
	}
	else if (input_nmsg) {
		nmsg = nmsg_input_open_file(fd);
		if (nmsg == NULL) {
			fprintf(stderr, "nmsg_input_open_file() failed\n");
			close(fd);
			return (EXIT_FAILURE);
		}
	}

	rc = mdb_env_create(&env);
	if (rc != 0) {
		fprintf(stderr, "mdb_create() failed: %s\n", mdb_strerror(rc));
		return (EXIT_FAILURE);
	}

	rc = mdb_env_open(env, lmdb_filename, MDB_NOSUBDIR | MDB_RDONLY, 0664);
	if (rc != 0) {
		fprintf(stderr, "mdb_env_open failed(): %s\n",
				mdb_strerror(rc));
		return (EXIT_FAILURE);
	}

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc != 0) {
		fprintf(stderr, "mdb_txn_begin failed(): %s\n",
				mdb_strerror(rc));
		return (EXIT_FAILURE);
	}

	rc = mdb_open(txn, NULL, MDB_INTEGERKEY, &dbi);
	if (rc) {
		fprintf(stderr, "mdb_open(): %s\n", mdb_strerror(rc));
		return (EXIT_FAILURE);
	}

	rc = mdb_set_compare(txn, dbi, axa_tsi_mdb_cmp);
	if (rc) {
		fprintf(stderr, "mdb_set_compare(): %s\n", mdb_strerror(rc));
		return (EXIT_FAILURE);
	}

	ts.tv_sec = ts_start;
	ts.tv_nsec = 0;

	key.mv_size = sizeof (ts);
	key.mv_data = &ts;

	rc = mdb_get(txn, dbi, &key, &data);
	if (rc) {
		fprintf(stderr, "mdb_get(): %s\n", mdb_strerror(rc));
		return (EXIT_FAILURE);
	}

	offset = (off_t *)data.mv_data;
	fprintf(stderr, "found offset for %u: %lx\n", ts_start, (*offset));

	if (lseek(fd, *offset, SEEK_SET) == sizeof (off_t) - 1) {
		fprintf(stderr, "lseek(): %s\n", strerror(errno));
		return (EXIT_FAILURE);
	}

	while (1) {
		if (count-- <= 0)
			break;
		res = nmsg_input_read(nmsg, &msg);
		if (res != nmsg_res_success) {
			fprintf(stderr, "nmsg_input_read(): %s\n", nmsg_res_lookup(res));
			return (EXIT_FAILURE);
		}
		res = nmsg_message_to_json(msg, &json);
		if (res != nmsg_res_success) {
			fprintf(stderr, "nmsg_message_to_pres(): %s\n", nmsg_res_lookup(res));
			return (EXIT_FAILURE);
		}
		printf("%s\n", json);
		free(json);
	}

	return (EXIT_SUCCESS);
}

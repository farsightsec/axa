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

#include <lmdb.h>
#include <axa/mdb.h>

static void
usage(const char *name)
{
	printf("AXA Timestamp Index Tool (tsindextool)\n");
	printf("(c) 2018 Farsight Security, Inc.\n");
	printf("Sample usage: %s -f foo.mdb -t 1537806295\n\n", name);

	printf("-f file\t\tspecify mdb file (required)\n");
	printf("-t timestamp\t\ttimestamp of starting nmsg\n");
	printf("-h\t\t\thelp\n");
}

int
main(int argc, char *argv[])
{
	int c, rc;
	uint32_t epoch = 0;
	MDB_env *env;
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val key, data;
	struct timespec ts;
	off_t *offset;
	const char *lmdb_filename = NULL;

	while ((c = getopt(argc, argv, "f:t:h")) != EOF) {
		switch (c) {
			case 't':
				epoch = atoi(optarg);
				break;
			case 'f':
				lmdb_filename = optarg;
				break;
			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}

	if (epoch == 0 || lmdb_filename == NULL) {
		usage(argv[0]);
		return (EXIT_FAILURE);
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

	ts.tv_sec = epoch;
	ts.tv_nsec = 0;

	key.mv_size = sizeof (ts);
	key.mv_data = &ts;

	rc = mdb_get(txn, dbi, &key, &data);
	if (rc) {
		fprintf(stderr, "mdb_get failed, error %d %s\n", rc, mdb_strerror(rc));
		return (EXIT_FAILURE);
	}

	offset = (off_t *)data.mv_data;
	fprintf(stderr, "offset of %u: %lx\n", epoch, (*offset));
	return (EXIT_SUCCESS);
}

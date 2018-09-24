/* gcc -I . -o /tmp/x tests/test-mdb-cmp-function.c  -llmdb -laxa -lbsd
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <axa/mdb.h>
#include <lmdb.h>
#include <bsd/string.h>
#include <time.h>

FILE *fp_tsindex = NULL;
MDB_env *mdb_env;            /* timestamp index db environment */
MDB_dbi mdb_dbi;            /* timestamp index db handle */
MDB_txn *mdb_txn;            /* timestamp index transaction handle */

char fn[128];

#define VERBOSE 1
#define A(f) do { int rc = f; if (VERBOSE) fprintf(stderr, "%s rc %d\n", #f, rc);assert(rc == 0); } while(0)
#define AEXP(got, expected) do { fprintf(stderr, "%s got:%d expected:%d\n", #got, got, expected); assert(got == expected); } while(0)

void shutdown();

struct _data {
	time_t s;
	long n;
	long o;
} data[] = {
	{1, 0, 0},
	{1, 1, 1},
	{1, 2, 2},
	{1, 3, 3},
	{2, 0, 4},
	{2, 1, 5},
	{2, 2, 6},
	{3, 0, 7},
	{4, 0, 8}
};

int main() {
	A(mdb_env_create(&mdb_env));

	int pagesize = getpagesize();
	A(mdb_env_set_mapsize(mdb_env, pagesize * 2560));

	strlcpy(fn, "/tmp/jeff/mdbtXXXXXX", 128);
	int fd = mkstemp(fn);
	close(fd);

	A(mdb_env_open(mdb_env, fn, MDB_NOSUBDIR, 0664));
	A(mdb_txn_begin(mdb_env, NULL, 0, &mdb_txn));
	A(mdb_dbi_open(mdb_txn, NULL, MDB_INTEGERKEY, &mdb_dbi));
	A(mdb_set_compare(mdb_txn, mdb_dbi, axa_tsi_mdb_cmp));

	MDB_val mkey, mdata;

	for(int i = 0 ; i < 9 ; i++) {
		struct timespec ts;
		ts.tv_sec = data[i].s;
		ts.tv_nsec = data[i].n;
		mkey.mv_data = &ts;
		mkey.mv_size = sizeof(ts);
		mdata.mv_size = sizeof(long);
		mdata.mv_data = &data[i].o;
                int rc = mdb_put(mdb_txn, mdb_dbi, &mkey, &mdata, MDB_NOOVERWRITE);
		if (VERBOSE) { fprintf(stderr, "insert of (%d, %d)->%d returned %d\n", ts.tv_sec, ts.tv_nsec, data[i].o, rc); }
		assert(MDB_KEYEXIST == rc || 0 == rc);
		//A(mdb_txn_commit(mdb_txn));
	        //A(mdb_txn_begin(mdb_env, NULL, 0, &mdb_txn));
	}

	/* given the formula in output.c: only store epochs, disallow dupes,
	 * the following can be asserted of the test data:
	 * 1. only four entries will be stored
	 * 2. offsets will be 0, 4, 7, and 8
	 */
	MDB_stat stat;
	A(mdb_stat(mdb_txn, mdb_dbi, &stat));
	assert(stat.ms_entries == 4);

	MDB_cursor *cursor;
	A(mdb_cursor_open(mdb_txn, mdb_dbi, &cursor));
	A(mdb_cursor_get(cursor, &mkey, &mdata, MDB_FIRST));

	AEXP(*(long*)(mdata.mv_data), 0);
	A(mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT));
	AEXP(*(long*)(mdata.mv_data), 4);
	A(mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT));
	AEXP(*(long*)(mdata.mv_data), 7);
	A(mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT));
	AEXP(*(long*)(mdata.mv_data), 8);

	mdb_cursor_close(cursor);
	shutdown();
	exit(0);
}

void shutdown() {
	mdb_txn_commit(mdb_txn);
	mdb_dbi_close(mdb_env, mdb_dbi);
	mdb_env_close(mdb_env);
	A(unlink(fn));
}



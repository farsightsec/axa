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
#define CLEAN_UP_DBFILE_AT_EXIT 1

#ifdef VERBOSE
#define D(x) fprintf x
#else
#define D(x)
#endif

#define A(f) do { int rc = f; if (VERBOSE) fprintf(stderr, "%s rc %d\n", #f, rc);assert(rc == 0); } while(0)
#define AEXP(got, expected) do { if (VERBOSE) fprintf(stderr, "   %s got:%d expected:%d\n", #got, got, expected); assert(got == expected); } while(0)

void shutdown();

struct _data {
	time_t s;
	long n;
	long o;
	char expect;
} data[] = {
	{1, 0, 0, 1},
	{1, 1, 1, 0},
	{1, 3, 2, 0},
	{2, 2, 3, 1}, // test out of order key w/our cmp func
	{2, 0, 4, 0},
	{1, 2, 5, 0},
	{2, 1, 6, 0},
	{3, 3, 7, 1},
	{4, 0, 8, 1},
	{0, 0, 0, -1}
};

int main() {
	int pagesize = getpagesize();

	strlcpy(fn, "/tmp/mdbtXXXXXX", 128);
	int fd = mkstemp(fn);
	close(fd);
	D((stderr, "db is %s\n", fn));

	A(mdb_env_create(&mdb_env));
	A(mdb_env_set_mapsize(mdb_env, pagesize * 2560));
	A(mdb_env_open(mdb_env, fn, MDB_NOSUBDIR, 0664));
	A(mdb_txn_begin(mdb_env, NULL, 0, &mdb_txn));
	A(mdb_dbi_open(mdb_txn, NULL, MDB_INTEGERKEY, &mdb_dbi));
	A(mdb_set_compare(mdb_txn, mdb_dbi, axa_tsi_mdb_cmp));

	MDB_val mkey, mdata;

	for(int i = 0 ; data[i].expect != -1 ; i++) {
		struct timespec ts;
		ts.tv_sec = data[i].s;
		ts.tv_nsec = data[i].n;
		mkey.mv_data = &ts;
		mkey.mv_size = sizeof(ts);
		mdata.mv_size = sizeof(long);
		mdata.mv_data = &data[i].o;
                int rc = mdb_put(mdb_txn, mdb_dbi, &mkey, &mdata, MDB_NOOVERWRITE);
		D((stderr, "insert of (%d, %d)->%d returned %d\n", ts.tv_sec, ts.tv_nsec, data[i].o, rc));
		assert(MDB_KEYEXIST == rc || 0 == rc);
	}

	/* given the formula in output.c: only store epochs, disallow dupes,
	 * the following can be asserted of the test data:
	 * 1. only four entries will be stored
	 * 2. offsets will be 0, 6, 7, and 8 (expect == 1)
	 */
	MDB_stat stat;
	A(mdb_stat(mdb_txn, mdb_dbi, &stat));
	assert(stat.ms_entries == 4);

	MDB_cursor *cursor;
	A(mdb_cursor_open(mdb_txn, mdb_dbi, &cursor));
	A(mdb_cursor_get(cursor, &mkey, &mdata, MDB_FIRST));

	for(int i = 0 ; data[i].expect != -1 ; i++) {
		D((stderr, "%s (%d, %d) -> %d\n", data[i].expect?"expect":"dontexpect", 
					data[i].s, data[i].n, data[i].o));
		if (data[i].expect == 1) {
			if (i) A(mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT));
			AEXP(((struct timespec *)(mkey.mv_data))->tv_sec, data[i].s);
			AEXP(((struct timespec *)(mkey.mv_data))->tv_nsec, data[i].n);
			AEXP(*(long*)(mdata.mv_data), data[i].o);
		}
	}

	mdb_cursor_close(cursor);
	mdb_txn_commit(mdb_txn);
	mdb_dbi_close(mdb_env, mdb_dbi);
	mdb_env_close(mdb_env);
#ifdef CLEAN_UP_DBFILE_AT_EXIT 
	A(unlink(fn));
#endif	
	D((stderr, "test succeeded.\n"));
	exit(0);
}




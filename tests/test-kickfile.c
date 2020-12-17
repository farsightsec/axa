#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <axa.h>
#include <axa/protocol.h>
#include <axa/wire.h>
#include <axa/kickfile.h>
#include <check.h>

START_TEST(test_kickfile_destroy)
{
	struct axa_kickfile *kf;

	kf = axa_zalloc(sizeof (*kf));
	axa_kickfile_destroy(&kf);

	ck_assert_ptr_eq(kf, NULL);
}
END_TEST

START_TEST(test_kickfile_exec)
{
	struct axa_kickfile *kf;
	char tmpname[] = "/tmp/test_kickfile_exec_tmp_XXXXXX";
	char curname[] = "/tmp/test_kickfile_exec_cur_XXXXXX";
	int tmpfd, curfd, ret;

	/* Create 'temporary' and 'current' files. */
	tmpfd = mkstemp(tmpname);
	ck_assert_int_gt(tmpfd, 0);
	close(tmpfd);

	curfd = mkstemp(curname);
	ck_assert_int_gt(curfd, 0);
	close(curfd);

	kf = axa_zalloc(sizeof (*kf));
	kf->file_tmpname = strdup(tmpname);
	kf->file_curname = strdup(curname);
	kf->cmd = strdup("stat");

	axa_kickfile_exec(kf);

	/* The temp file should have been renamed to the current one. */
	ret = unlink(tmpname);
	ck_assert_int_ne(ret, 0);

	/* The current file should be there and unlink(2) should succeed. */
	ret = unlink(curname);
	ck_assert_int_eq(ret, 0);

	/* Cleanup */
	axa_kickfile_destroy(&kf);
	ck_assert_ptr_eq(kf, NULL);
}
END_TEST

START_TEST(test_kickfile_rotate)
{
	struct axa_kickfile *kf;
	char tmpname[] = "/tmp/test_kickfile_rotate_tmp";
	char curname[] = "/tmp/test_kickfile_rotate_cur";
	char basename[] = "/tmp/test_kickfile_rotate_basename";
	int tmpfd, curfd, ret;

	kf = axa_zalloc(sizeof (*kf));
	kf->file_tmpname = strdup(tmpname);
	kf->file_curname = strdup(curname);
	kf->file_basename = strdup(basename);
	kf->cmd = strdup("stat");

	axa_kickfile_rotate(kf, "rotate_here");

	ck_assert_str_eq(kf->file_tmpname,
	    "/tmp/.test_kickfile_rotate_basename.rotate_here.part");
	ck_assert_str_eq(kf->file_curname,
	    "/tmp/test_kickfile_rotate_basename.rotate_here");
	ck_assert_ptr_eq(kf->file_kt, NULL);

	/* Cleanup */
	axa_kickfile_destroy(&kf);
	ck_assert_ptr_eq(kf, NULL);
}
END_TEST

static void
dummy_cb(void *arg AXA_UNUSED)
{
}

START_TEST(test_kickfile_register_cb)
{
	struct axa_kickfile *kf;

	kf = axa_zalloc(sizeof (*kf));
	axa_kickfile_register_cb(kf, dummy_cb);

	ck_assert_ptr_eq(kf->cb, dummy_cb);

	ck_assert_ptr_eq(kf->cmd, NULL);
	ck_assert_ptr_eq(kf->file_curname, NULL);
	ck_assert_ptr_eq(kf->file_basename, NULL);
	ck_assert_ptr_eq(kf->file_tmpname, NULL);
	ck_assert_ptr_eq(kf->file_kt, NULL);
	ck_assert_ptr_eq(kf->file_suffix, NULL);

	free(kf);
}
END_TEST

START_TEST(test_kickfile_get_kt)
{
	struct axa_kickfile *kf;
	const char *ret;

	kf = axa_zalloc(sizeof (*kf));
	kf->file_kt = strdup("axa_file_kt");

	ret = axa_kickfile_get_kt(kf);
	ck_assert_str_eq(ret, "axa_file_kt");
}
END_TEST

int main(void) {
	int number_failed;
	Suite *s;
	TCase *tc_kickfile_core;
	SRunner *sr;

	s = suite_create("axa_kickfile");
	tc_kickfile_core = tcase_create("kickfile_core");
	tcase_add_test(tc_kickfile_core, test_kickfile_destroy);
	tcase_add_test(tc_kickfile_core, test_kickfile_exec);
	tcase_add_test(tc_kickfile_core, test_kickfile_rotate);
	tcase_add_test(tc_kickfile_core, test_kickfile_register_cb);
	tcase_add_test(tc_kickfile_core, test_kickfile_get_kt);
	suite_add_tcase(s, tc_kickfile_core);

	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

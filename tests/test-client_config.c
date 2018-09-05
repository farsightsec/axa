#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#ifdef __linux
#include <bsd/string.h>                 /* for strlcpy() */
#endif

#include <axa.h>
#include <axa/client_config.h>
#include <axa/protocol.h>
#include <axa/wire.h>
#include <check.h>

START_TEST(test_load_client_config)
{
	char *p;
	size_t n;
	const char *res;
	axa_emsg_t emsg;
	char buf[MAXPATHLEN * 2];
	const char *buf_p;

	p = getenv("top_srcdir");
	ck_assert_ptr_ne(p, NULL);

	strlcpy(buf, p, sizeof (buf));
	n = strlen(buf);
	strlcpy(buf + n, "/tests/test-config", sizeof (buf) - n);
	buf_p = buf;
	ck_assert(axa_load_client_config(&emsg, &buf_p));

	res = axa_client_config_alias_chk("sra-dev-apikey");
	ck_assert_str_eq(res, "apikey:b46ce912-7122-4245-8053-9b3adb81b822@axa.dev.fsi.io,1011");
	res = axa_client_config_alias_chk("rad-dev-apikey");
	ck_assert_str_eq(res, "apikey:b46ce912-7122-4245-8053-9b3adb81b822@axa.dev.fsi.io,1012");
	res = axa_client_config_alias_chk("sra-dev-tls");
	ck_assert_str_eq(res, "tls:username@axa.dev.fsi.io,1021");
	res = axa_client_config_alias_chk("rad-dev-tls");
	ck_assert_str_eq(res, "tls:username@axa.dev.fsi.io,1022");

	axa_unload_client_config();
}
END_TEST

int main(void) {
	int number_failed;
	Suite *s;
	TCase *tc_core;
	SRunner *sr;

	s = suite_create("axa_client_config");
	tc_core = tcase_create("core");
	tcase_add_test(tc_core, test_load_client_config);
	suite_add_tcase(s, tc_core);

	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <axa.h>
#include <axa/protocol.h>
#include <axa/wire.h>
#include <check.h>

START_TEST(test_apikey_parse)
{
	bool res;
	axa_emsg_t emsg;
	char *addr;
	axa_p_user_t u;
	const char *spec = "08459ef5-1417-448a-bc93-d61917d32f52@axa.dev.fsi.io,1011";

	addr = NULL;
	res = axa_apikey_parse(&emsg, &addr, &u, spec);

	ck_assert_int_eq(res, true);
	ck_assert_str_eq(addr, "axa.dev.fsi.io,1011");
	ck_assert_str_eq(u.name, "08459ef5-1417-448a-bc93-d61917d32f52");
}
END_TEST

int main(void) {
	int number_failed;
	Suite *s;
	TCase *tc_core;
	SRunner *sr;

	s = suite_create("axa_apikey");
	tc_core = tcase_create("core");
	tcase_add_test(tc_core, test_apikey_parse);
	suite_add_tcase(s, tc_core);

	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

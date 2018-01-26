#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __linux
#include <bsd/string.h>                 /* for strlcpy() */
#endif

#include <axa.h>
#include <axa/bits.h>
#include <axa/axa_endian.h>
#include <axa/wire.h>
#include <axa/protocol.h>
#include <check.h>

START_TEST(test_kill_req)
{
	ssize_t total;
	axa_tag_t tag;
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	axa_p_pvers_t pvers;
	_axa_p_kill_t kill_req;

	pvers = 1;
	tag = 1;

	kill_req.mode = AXA_P_KILL_M_U;
	strlcpy(kill_req.user.name, "wink", sizeof(kill_req.user.name));
	kill_req.sn = 0;

	total = axa_make_hdr(&emsg, &hdr, pvers, tag, _AXA_P_OP_KILL_REQ,
			sizeof (kill_req), 0, AXA_P_TO_SRA);

	ck_assert_int_eq(total, sizeof (kill_req) + sizeof (hdr));
}
END_TEST

START_TEST(test_kill_rsp)
{
	ssize_t total;
	axa_tag_t tag;
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	axa_p_pvers_t pvers;
	_axa_p_kill_t kill_rsp;

	pvers = 1;
	tag = 1;

	kill_rsp.mode = AXA_P_KILL_M_U;
	strlcpy(kill_rsp.user.name, "wink", sizeof(kill_rsp.user.name));
	kill_rsp.sn = 0;
	kill_rsp.result = AXA_P_KILL_R_SUCCESS;

	total = axa_make_hdr(&emsg, &hdr, pvers, tag, _AXA_P_OP_KILL_RSP,
			sizeof (kill_rsp), 0, AXA_P_FROM_SRA);

	ck_assert_int_eq(total, sizeof (kill_rsp) + sizeof (hdr));
}
END_TEST

int main(void) {
	int number_failed;
	Suite *s;
	TCase *tc_core;
	SRunner *sr;

	s = suite_create("axa_kill");
	tc_core = tcase_create("core");
	tcase_add_test(tc_core, test_kill_req);
	tcase_add_test(tc_core, test_kill_rsp);
	suite_add_tcase(s, tc_core);

	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

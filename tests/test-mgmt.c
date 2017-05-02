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

START_TEST(test_mgmt)
{
	bool res;
	ssize_t total;
	axa_tag_t tag;
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	axa_p_pvers_t pvers;
	axa_p_mgmt_t mgmt;
	axa_p_mgmt_user_t mgmt_user;

	memset(&mgmt, 0, sizeof(mgmt));
	mgmt.version = 1;
	mgmt.flags |= AXA_MGMT_FLAG_SRA;
	mgmt.load[0] = AXA_H2P32(30.0 * AXA_P_OPT_SAMPLE_SCALE);
	mgmt.load[1] = AXA_H2P32(45.0 * AXA_P_OPT_SAMPLE_SCALE);
	mgmt.load[2] = AXA_H2P32(60.0 * AXA_P_OPT_SAMPLE_SCALE);
	mgmt.cpu_usage = 99.9 * AXA_P_OPT_SAMPLE_SCALE;
	mgmt.uptime = 118709950;
	mgmt.starttime = 118709950;
	mgmt.fd_pipes = 10;
	mgmt.fd_anon_inodes = 20;
	mgmt.fd_other = 30;
	mgmt.vmsize = AXA_H2P64(1164000000);
	mgmt.vmrss = AXA_H2P64(1000);
	mgmt.rchar = 9999;
	mgmt.wchar = 8888;
	mgmt.thread_cnt = 1000;
	mgmt.users_cnt = 1;

	memset(&mgmt_user, 0, sizeof(mgmt_user));
	strlcpy(mgmt_user.user.name, "wink", sizeof (mgmt_user.user.name));
	mgmt_user.io_type = AXA_IO_TYPE_TLS;
	mgmt_user.addr_type = AXA_AF_INET;
	mgmt_user.ip.ipv4 = AXA_H2P32(167772161); /* 10.0.0.1 */
	mgmt_user.sn = 1;
	mgmt_user.connected_since.tv_sec = AXA_H2P32(118709950);
	mgmt_user.connected_since.tv_usec = 0;
	mgmt_user.ratelimit = 0;
	mgmt_user.sample = 100.0 * AXA_P_OPT_SAMPLE_SCALE;
	mgmt_user.last_cnt_update.tv_sec = AXA_H2P32(118709950);
	mgmt_user.last_cnt_update.tv_usec = 0;
	mgmt_user.filtered = 10;
	mgmt_user.missed = 20;
	mgmt_user.collected = 30;
	mgmt_user.sent = 40;
	mgmt_user.rlimit = 50;
	mgmt_user.congested = 60;
	mgmt_user.srvr.sra.watches.ipv4_cnt = 100;
	mgmt_user.srvr.sra.watches.ipv6_cnt = 200;
	mgmt_user.srvr.sra.watches.dns_cnt = 300;
	mgmt_user.srvr.sra.watches.ch_cnt = 1;
	mgmt_user.srvr.sra.watches.err_cnt = 0;
	res = axa_set_bitwords(mgmt_user.srvr.sra.ch_mask.m, 255);
	ck_assert_int_eq(res, 0);

	pvers = 1;
	tag = 1;
	total = axa_make_hdr(&emsg, &hdr, pvers, tag, AXA_P_OP_MGMT_GETRSP,
			sizeof (mgmt) + sizeof (mgmt_user), 0, AXA_P_FROM_SRA);

	ck_assert_int_eq(total, sizeof (mgmt) + sizeof (mgmt_user) +
			sizeof (hdr));
}
END_TEST

START_TEST(test_mgmt_kill)
{
	ssize_t total;
	axa_tag_t tag;
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	axa_p_pvers_t pvers;
	axa_p_mgmt_kill_t mgmt_kill;

	mgmt_kill.mode = AXA_P_MGMT_K_M_U;
	strlcpy(mgmt_kill.user.name, "ace", sizeof(mgmt_kill.user.name));
	mgmt_kill.sn = 1;
	mgmt_kill.result = AXA_P_MGMT_K_R_SUCCESS;

	pvers = 1;
	tag = 1;
	total = axa_make_hdr(&emsg, &hdr, pvers, tag, AXA_P_OP_MGMT_KILL,
			sizeof (mgmt_kill), 0, AXA_P_TO_SRA);

	ck_assert_int_eq(total, sizeof (mgmt_kill) + sizeof (hdr));
}
END_TEST

int main(void) {
	int number_failed;
	Suite *s;
	TCase *tc_core;
	SRunner *sr;

	s = suite_create("axa_mgmt");
	tc_core = tcase_create("core");
	tcase_add_test(tc_core, test_mgmt);
	tcase_add_test(tc_core, test_mgmt_kill);
	suite_add_tcase(s, tc_core);

	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

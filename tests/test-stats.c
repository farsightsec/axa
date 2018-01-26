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

START_TEST(test_stats_sra)
{
	bool res;
	ssize_t total;
	axa_tag_t tag;
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	axa_p_pvers_t pvers;
	_axa_p_stats_req_t stats_req;
	_axa_p_stats_rsp_t stats_rsp;
	_axa_p_stats_sys_t stats_sys;
	_axa_p_stats_user_t stats_user;

	pvers = 1;
	tag = 1;

	memset(&stats_req, 0, sizeof(stats_req));
	memset(&stats_rsp, 0, sizeof(stats_rsp));
	memset(&stats_sys, 0, sizeof(stats_sys));
	memset(&stats_user, 0, sizeof(stats_user));

	stats_req.version = _AXA_STATS_VERSION_ONE;
	stats_req.type = AXA_P_STATS_M_M_SUM;
	memset(&stats_req.user, 0, sizeof(stats_req.user));
	stats_req.sn = 0;

	total = axa_make_hdr(&emsg, &hdr, pvers, tag, _AXA_P_OP_STATS_REQ,
			sizeof (stats_req), 0, AXA_P_TO_SRA);

	ck_assert_int_eq(total, sizeof (stats_req) + sizeof (hdr));

	stats_rsp.version = _AXA_STATS_VERSION_ONE;
	stats_rsp.sys_objs_cnt = 1;
	stats_rsp.user_objs_cnt = 1;
	stats_rsp.result = AXA_P_STATS_R_SUCCESS;

	stats_sys.type = AXA_P_STATS_TYPE_SYS;
	stats_sys.server_type = _AXA_STATS_SRVR_TYPE_SRA;
	stats_sys.load[0] = AXA_H2P32(30.0 * AXA_P_OPT_SAMPLE_SCALE);
	stats_sys.load[1] = AXA_H2P32(45.0 * AXA_P_OPT_SAMPLE_SCALE);
	stats_sys.load[2] = AXA_H2P32(60.0 * AXA_P_OPT_SAMPLE_SCALE);
	stats_sys.cpu_usage = 99.9 * AXA_P_OPT_SAMPLE_SCALE;
	stats_sys.uptime = 118709950;
	stats_sys.starttime = 118709950;
	stats_sys.fd_pipes = 10;
	stats_sys.fd_anon_inodes = 20;
	stats_sys.fd_other = 30;
	stats_sys.vmsize = AXA_H2P64(1164000000);
	stats_sys.vmrss = AXA_H2P64(1000);
	stats_sys.rchar = 9999;
	stats_sys.wchar = 8888;
	stats_sys.thread_cnt = 1000;
	stats_sys.user_cnt = 1;
	stats_sys.srvr.sra.watches.ipv4_cnt = 100;
	stats_sys.srvr.sra.watches.ipv6_cnt = 200;
	stats_sys.srvr.sra.watches.dns_cnt = 300;
	stats_sys.srvr.sra.watches.ch_cnt = 1;
	stats_sys.srvr.sra.watches.err_cnt = 3;
	res = axa_set_bitwords(stats_sys.srvr.sra.ch_mask.m, 255);
	ck_assert_int_eq(res, 0);

	strlcpy(stats_user.user.name, "rumi", sizeof (stats_user.user.name));
	stats_user.io_type = AXA_IO_TYPE_APIKEY;
	stats_user.addr_type = AXA_AF_INET;
	stats_user.ip.ipv4 = AXA_H2P32(167772161); /* 10.0.0.1 */
	stats_user.sn = 1;
	stats_user.connected_since.tv_sec = AXA_H2P32(118709950);
	stats_user.connected_since.tv_usec = 0;
	stats_user.ratelimit = 0;
	stats_user.sample = 100.0 * AXA_P_OPT_SAMPLE_SCALE;
	stats_user.last_cnt_update.tv_sec = AXA_H2P32(118709950);
	stats_user.last_cnt_update.tv_usec = 0;
	stats_user.filtered = 10;
	stats_user.missed = 20;
	stats_user.collected = 30;
	stats_user.sent = 40;
	stats_user.rlimit = 50;
	stats_user.congested = 60;
	stats_user.srvr.sra.watches.ipv4_cnt = 100;
	stats_user.srvr.sra.watches.ipv6_cnt = 200;
	stats_user.srvr.sra.watches.dns_cnt = 300;
	stats_user.srvr.sra.watches.ch_cnt = 1;
	stats_user.srvr.sra.watches.err_cnt = 0;
	res = axa_set_bitwords(stats_user.srvr.sra.ch_mask.m, 255);
	ck_assert_int_eq(res, 0);

	total = axa_make_hdr(&emsg, &hdr, pvers, tag, _AXA_P_OP_STATS_RSP,
			sizeof (stats_rsp) + sizeof (stats_user), 0,
			AXA_P_FROM_SRA);

	ck_assert_int_eq(total, sizeof (stats_rsp) + sizeof (stats_user) +
			sizeof (hdr));
}
END_TEST

START_TEST(test_stats_rad)
{
	ssize_t total;
	axa_tag_t tag;
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	axa_p_pvers_t pvers;
	_axa_p_stats_req_t stats_req;
	_axa_p_stats_rsp_t stats_rsp;
	_axa_p_stats_sys_t stats_sys;
	_axa_p_stats_user_t stats_user;

	pvers = 1;
	tag = 1;

	memset(&stats_req, 0, sizeof(stats_req));
	memset(&stats_rsp, 0, sizeof(stats_rsp));
	memset(&stats_sys, 0, sizeof(stats_sys));
	memset(&stats_user, 0, sizeof(stats_user));

	stats_req.version = _AXA_STATS_VERSION_ONE;
	stats_req.type = AXA_P_STATS_M_M_SUM;
	memset(&stats_req.user, 0, sizeof(stats_req.user));
	stats_req.sn = 0;

	total = axa_make_hdr(&emsg, &hdr, pvers, tag, _AXA_P_OP_STATS_REQ,
			sizeof (stats_req), 0, AXA_P_TO_RAD);

	ck_assert_int_eq(total, sizeof (stats_req) + sizeof (hdr));

	stats_rsp.version = _AXA_STATS_VERSION_ONE;
	stats_rsp.sys_objs_cnt = 1;
	stats_rsp.user_objs_cnt = 1;
	stats_rsp.result = AXA_P_STATS_R_SUCCESS;

	stats_sys.type = AXA_P_STATS_TYPE_SYS;
	stats_sys.server_type = _AXA_STATS_SRVR_TYPE_RAD;
	stats_sys.load[0] = AXA_H2P32(30.0 * AXA_P_OPT_SAMPLE_SCALE);
	stats_sys.load[1] = AXA_H2P32(45.0 * AXA_P_OPT_SAMPLE_SCALE);
	stats_sys.load[2] = AXA_H2P32(60.0 * AXA_P_OPT_SAMPLE_SCALE);
	stats_sys.cpu_usage = 99.9 * AXA_P_OPT_SAMPLE_SCALE;
	stats_sys.uptime = 118709950;
	stats_sys.starttime = 118709950;
	stats_sys.fd_pipes = 10;
	stats_sys.fd_anon_inodes = 20;
	stats_sys.fd_other = 30;
	stats_sys.vmsize = AXA_H2P64(1164000000);
	stats_sys.vmrss = AXA_H2P64(1000);
	stats_sys.rchar = 9999;
	stats_sys.wchar = 8888;
	stats_sys.thread_cnt = 1000;
	stats_sys.user_cnt = 1;
	stats_sys.srvr.rad.an_cnt = 1;

	strlcpy(stats_user.user.name, "wink", sizeof (stats_user.user.name));
	stats_user.io_type = AXA_IO_TYPE_APIKEY;
	stats_user.addr_type = AXA_AF_INET;
	stats_user.ip.ipv4 = AXA_H2P32(167772161); /* 10.0.0.1 */
	stats_user.sn = 1;
	stats_user.connected_since.tv_sec = AXA_H2P32(118709950);
	stats_user.connected_since.tv_usec = 0;
	stats_user.ratelimit = 0;
	stats_user.sample = 100.0 * AXA_P_OPT_SAMPLE_SCALE;
	stats_user.last_cnt_update.tv_sec = AXA_H2P32(118709950);
	stats_user.last_cnt_update.tv_usec = 0;
	stats_user.filtered = 10;
	stats_user.missed = 20;
	stats_user.collected = 30;
	stats_user.sent = 40;
	stats_user.rlimit = 50;
	stats_user.congested = 60;
	stats_user.srvr.rad.an_obj_cnt = 1;
	stats_user.srvr.rad.an_obj_cnt_total = 1;
	stats_user.srvr.rad.flags = 0;

	total = axa_make_hdr(&emsg, &hdr, pvers, tag, _AXA_P_OP_STATS_RSP,
			sizeof (stats_rsp) + sizeof (stats_user), 0,
			AXA_P_FROM_RAD);

	ck_assert_int_eq(total, sizeof (stats_rsp) + sizeof (stats_user) +
			sizeof (hdr));
}
END_TEST
int main(void) {
	int number_failed;
	Suite *s;
	TCase *tc_core;
	SRunner *sr;

	s = suite_create("axa_stats");
	tc_core = tcase_create("core");
	tcase_add_test(tc_core, test_stats_sra);
	tcase_add_test(tc_core, test_stats_rad);
	suite_add_tcase(s, tc_core);

	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

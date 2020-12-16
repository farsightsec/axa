#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <axa/json.h>
#include <axa/axa_endian.h>
#include <axa/protocol.h>
#include <axa/wire.h>
#include <check.h>
#include <nmsg/container.h>
#include <nmsg/input.h>
#include <nmsg/message.h>
#include <nmsg/base/defs.h>

nmsg_input_t nmsg_input;

#define empty_test(op, name) do { \
	const char *expected; \
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t)), AXA_H2P_TAG(0), AXA_P_PVERS, op }; \
	char *out = NULL; \
	axa_json_res_t res; \
	axa_emsg_t emsg; \
	switch((op)) { \
	case AXA_P_OP_WHIT: \
	case AXA_P_OP_AHIT: \
	case AXA_P_OP_WATCH: \
	case AXA_P_OP_ANOM: \
	case AXA_P_OP_STOP: \
		hdr.tag = AXA_H2P_TAG(1); \
		break; \
	case AXA_P_OP_ACCT: \
	case AXA_P_OP_AGET: \
	case AXA_P_OP_ALIST: \
	case AXA_P_OP_ALL_STOP: \
	case AXA_P_OP_CGET: \
	case AXA_P_OP_CHANNEL: \
	case AXA_P_OP_CLIST: \
	case AXA_P_OP_ERROR: \
	case AXA_P_OP_GO: \
	case AXA_P_OP_HELLO: \
	case AXA_P_OP_JOIN: \
	case AXA_P_OP_MISSED: \
	case AXA_P_OP_MISSED_RAD: \
	case AXA_P_OP_NOP: \
	case AXA_P_OP_OK: \
	case AXA_P_OP_OPT: \
	case AXA_P_OP_PAUSE: \
	case AXA_P_OP_RADU: \
	case AXA_P_OP_USER: \
	case AXA_P_OP_WGET: \
		break; \
	default: \
		break; \
	} \
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, 0, 0, &out); \
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS); \
	if (AXA_P2H_TAG(hdr.tag) == 0) \
		expected = "{\"tag\":\"*\",\"op\":\"" name "\"}"; \
	else \
		expected = "{\"tag\":1,\"op\":\"" name "\"}"; \
	ck_assert_str_eq(out, expected); \
	free(out); \
} while (0)

#define truncated_test(op, axa_p_type_t, watch_len) do { \
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), AXA_H2P_TAG(0), AXA_P_PVERS, op }; \
	axa_p_type_t type; \
	char *out = NULL; \
	axa_json_res_t res; \
	axa_emsg_t emsg; \
	switch((op)) { \
	case AXA_P_OP_WHIT: \
	case AXA_P_OP_AHIT: \
	case AXA_P_OP_WATCH: \
	case AXA_P_OP_ANOM: \
	case AXA_P_OP_STOP: \
		hdr.tag = AXA_H2P_TAG(1); \
		break; \
        case AXA_P_OP_ACCT: \
        case AXA_P_OP_AGET: \
        case AXA_P_OP_ALIST: \
        case AXA_P_OP_ALL_STOP: \
        case AXA_P_OP_CGET: \
        case AXA_P_OP_CHANNEL: \
        case AXA_P_OP_CLIST: \
        case AXA_P_OP_ERROR: \
        case AXA_P_OP_GO: \
        case AXA_P_OP_HELLO: \
        case AXA_P_OP_JOIN: \
        case AXA_P_OP_MISSED: \
        case AXA_P_OP_MISSED_RAD: \
        case AXA_P_OP_NOP: \
        case AXA_P_OP_OK: \
        case AXA_P_OP_OPT: \
        case AXA_P_OP_PAUSE: \
        case AXA_P_OP_RADU: \
        case AXA_P_OP_USER: \
        case AXA_P_OP_WGET: \
		break; \
	default: \
		break; \
	} \
	memset(&type, 0, sizeof(type)); \
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&type, (watch_len), &out); \
	ck_assert_int_eq(res, AXA_JSON_RES_FAILURE); \
	ck_assert_ptr_eq(out, NULL); \
} while (0)

START_TEST(test_nop)
{
	empty_test(AXA_P_OP_NOP, "NOP");
}
END_TEST

START_TEST(test_hello)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"HELLO\",\"id\":1,\"pvers_min\":2,\"pvers_max\":3,\"str\":\"hello\"}";
	axa_emsg_t emsg;
	axa_p_hello_t hello = { 1, 2, 3, "hello" };
	char *out = NULL;
	size_t watch_len = offsetof(axa_p_hello_t, str) + strlen(hello.str) + 1;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), AXA_H2P_TAG(AXA_TAG_NONE), AXA_P_PVERS, AXA_P_OP_HELLO };
	axa_json_res_t res;
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&hello, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_hello_empty)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"HELLO\",\"id\":1,\"pvers_min\":2,\"pvers_max\":3,\"str\":\"\"}";
	axa_emsg_t emsg;
	axa_p_hello_t hello = { 1, 2, 3, "" };
	char *out = NULL;
	size_t watch_len = offsetof(axa_p_hello_t, str) + strlen(hello.str) + 1;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), AXA_H2P_TAG(AXA_TAG_NONE), AXA_P_PVERS, AXA_P_OP_HELLO };
	axa_json_res_t res;
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&hello, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_hello_trunc)
{
	truncated_test(AXA_P_OP_HELLO, axa_p_hello_t, offsetof(axa_p_hello_t, str) - 1);
}
END_TEST

START_TEST(test_ok)
{
	const char *expected = "{\"tag\":1,\"op\":\"OK\",\"orig_op\":\"WATCH HIT\",\"str\":\"success\"}";
	axa_emsg_t emsg;
	axa_p_result_t result = { AXA_P_OP_WHIT, "success" };
	size_t watch_len = offsetof(axa_p_result_t, str) + strlen(result.str) + 1;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_OK };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&result, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_ok_trunc)
{
	truncated_test(AXA_P_OP_OK, axa_p_result_t, offsetof(axa_p_result_t, str) - 1);
}
END_TEST

START_TEST(test_error)
{
	const char *expected = "{\"tag\":1,\"op\":\"ERROR\",\"orig_op\":\"OK\",\"str\":\"failure\"}";
	axa_emsg_t emsg;
	axa_p_result_t result = { AXA_P_OP_OK, "failure" };
	size_t watch_len = offsetof(axa_p_result_t, str) + strlen(result.str) + 1;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_ERROR };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&result, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_error_trunc)
{
	truncated_test(AXA_P_OP_ERROR, axa_p_result_t, offsetof(axa_p_result_t, str) - 1);
}
END_TEST

START_TEST(test_missed)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"MISSED\",\"missed\":2,\"dropped\":3,\"rlimit\":4,\"filtered\":5,\"last_report\":6}";
	axa_emsg_t emsg;
	axa_p_missed_t missed = { 2, 3, 4, 5, 6 };
	size_t watch_len = sizeof(missed);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), AXA_H2P_TAG(AXA_TAG_NONE), AXA_P_PVERS, AXA_P_OP_MISSED };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&missed, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_missed_trunc)
{
	truncated_test(AXA_P_OP_MISSED, axa_p_missed_t, sizeof(axa_p_missed_t) - 1);
}
END_TEST

START_TEST(test_missed_rad)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"RAD MISSED\",\"sra_missed\":2,\"sra_dropped\":3,\"sra_rlimit\":4,\"sra_filtered\":5,\"dropped\":6,\"rlimit\":7,\"filtered\":8,\"last_report\":9}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + sizeof(axa_p_missed_rad_t)), AXA_H2P_TAG(AXA_TAG_NONE), AXA_P_PVERS, AXA_P_OP_MISSED_RAD };
	axa_p_missed_rad_t missed_rad = { 2, 3, 4, 5, 6, 7, 8, 9 };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&missed_rad, sizeof(missed_rad), &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_missed_rad_trunc)
{
	truncated_test(AXA_P_OP_MISSED_RAD, axa_p_missed_rad_t, sizeof(axa_p_missed_rad_t) - 1);
}
END_TEST

START_TEST(test_whit_nmsg)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH HIT\",\"channel\":\"ch123\",\"field\":\"payload\",\"val_idx\":2,\"vname\":\"base\",\"mname\":\"pkt\",\"time\":\"1970-01-01 00:00:01.000000002\",\"nmsg\":{\"time\":\"1970-01-01 00:00:01.000000002\",\"vname\":\"base\",\"mname\":\"pkt\",\"message\":{\"len_frame\":32,\"payload\":\"RQAAIBI0QAD/EVmFAQIDBAUGBwgAewHIAAxP4t6tvu8=\"}}}";
	axa_emsg_t emsg;
	nmsg_container_t container;
	nmsg_msgmod_t mod;
	nmsg_message_t msg;
	void *clos;
	uint8_t packet[] = "\x45\x00\x00\x20\x12\x34\x40\x00\xff\x11\x59\x85\x01\x02\x03\x04\x05\x06\x07\x08\x00\x7b\x01\xc8\x00\x0c\x4f\xe2\xde\xad\xbe\xef";
	uint32_t packet_len = sizeof(packet)-1;
	uint8_t *pbuf;
	size_t pbuf_len;
	size_t whit_len;
	axa_p_whit_nmsg_t *whit;
	axa_p_whit_nmsg_hdr_t whit_hdr = {
		.hdr = { .ch=123, .type=AXA_P_WHIT_NMSG },
		.field_idx = 1,
		.val_idx = 2,
		.vid = NMSG_VENDOR_BASE_ID,
		.type = NMSG_VENDOR_BASE_PKT_ID,
		.ts = { 1, 2 }
	};
	char *out = NULL;
	axa_json_res_t res;
	axa_p_hdr_t hdr = { .tag=1, .pvers=AXA_P_PVERS, .op=AXA_P_OP_WHIT };
	struct timespec ts = { whit_hdr.ts.tv_sec , whit_hdr.ts.tv_nsec };

	container = nmsg_container_init(1000);
	assert(container != NULL);

	mod = nmsg_msgmod_lookup(NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_PKT_ID);
	assert(mod != NULL);
	assert(nmsg_msgmod_init(mod, &clos) == nmsg_res_success);

	msg = nmsg_message_init(mod);
	assert (msg != NULL);

	nmsg_message_set_time(msg, &ts);
	assert(nmsg_message_set_field(msg, "len_frame", 0, (void*)&packet_len, sizeof(packet_len)) == nmsg_res_success);
	assert(nmsg_message_set_field(msg, "payload", 0, packet, packet_len) == nmsg_res_success);

	assert(nmsg_container_add(container, msg) == nmsg_res_success);
	assert(nmsg_container_serialize(container, &pbuf, &pbuf_len,
				true, false, 0, 0) == nmsg_res_success);

	whit_len = offsetof(axa_p_whit_nmsg_t, b) + pbuf_len;
	whit = alloca(whit_len);
	assert(whit != NULL);

	whit->hdr = whit_hdr;
	memcpy(&(whit->b), pbuf, pbuf_len);
	free(pbuf);

	hdr.len = AXA_H2P32(sizeof(axa_p_hdr_t) + whit_len);

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)whit, whit_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);

	nmsg_message_destroy(&msg);
	nmsg_msgmod_fini(mod, &clos);
	nmsg_container_destroy(&container);
}
END_TEST

START_TEST(test_whit_nmsg_trunc)
{
	truncated_test(AXA_P_OP_WHIT, axa_p_whit_nmsg_t, offsetof(axa_p_whit_nmsg_t, b) - 1);
}
END_TEST

START_TEST(test_whit_ip4_udp)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH HIT\",\"channel\":\"ch123\",\"time\":\"1970-01-01 00:00:01.000002\",\"af\":\"IPv4\",\"src\":\"1.2.3.4\",\"dst\":\"5.6.7.8\",\"ttl\":255,\"proto\":\"UDP\",\"src_port\":123,\"dst_port\":456,\"payload\":\"3q2+7w==\"}";
	axa_emsg_t emsg;
	uint8_t packet[] = "\x45\x00\x00\x20\x12\x34\x40\x00\xff\x11\x59\x85\x01\x02\x03\x04\x05\x06\x07\x08\x00\x7b\x01\xc8\x00\x0c\x4f\xe2\xde\xad\xbe\xef";
	size_t whit_len = offsetof(axa_p_whit_ip_t, b) + sizeof(packet) - 1;
	axa_p_whit_ip_t *whit = alloca(whit_len);
	axa_p_whit_ip_t whit_data = { .hdr={
		.hdr = { .ch=123, .type=AXA_P_WHIT_IP },
		.tv = { 1, 2 },
		.ip_len = sizeof(packet),
	}};
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + whit_len), 1, AXA_P_PVERS, AXA_P_OP_WHIT };
	char *out = NULL;
	axa_json_res_t res;

	*whit = whit_data;
	memcpy(&(whit->b), packet, sizeof(packet) - 1);

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)whit, whit_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_whit_ip4_tcp)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH HIT\",\"channel\":\"ch123\",\"time\":\"1970-01-01 00:00:01.000002\",\"af\":\"IPv4\",\"src\":\"1.2.3.4\",\"dst\":\"5.6.7.8\",\"ttl\":255,\"proto\":\"TCP\",\"src_port\":123,\"dst_port\":456,\"flags\":[\"SYN\",\"ACK\"],\"payload\":\"3q2+7w==\"}";
	axa_emsg_t emsg;
	uint8_t packet[] = "\x45\x00\x00\x28\x12\x34\x40\x00\xff\x06\x59\x88\x01\x02\x03\x04\x05\x06\x07\x08\x00\x7b\x01\xc8\x00\x00\x00\x64\x00\x00\x00\x64\x50\x12\x0f\xa0\x8d\x14\x00\x00\xde\xad\xbe\xef";
	size_t whit_len = offsetof(axa_p_whit_ip_t, b) + sizeof(packet) - 1;
	axa_p_whit_ip_t *whit = alloca(whit_len);
	axa_p_whit_ip_t whit_data = { .hdr={
		.hdr = { .ch=123, .type=AXA_P_WHIT_IP },
		.tv = { 1, 2 },
		.ip_len = sizeof(packet),
	}};
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + whit_len), 1, AXA_P_PVERS, AXA_P_OP_WHIT };
	char *out = NULL;
	axa_json_res_t res;

	*whit = whit_data;
	memcpy(&(whit->b), packet, sizeof(packet) - 1);

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)whit, whit_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_whit_ip4_trunc)
{
	truncated_test(AXA_P_OP_WHIT, axa_p_whit_ip_t, offsetof(axa_p_whit_ip_t, b));
}
END_TEST

START_TEST(test_whit_ip6)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH HIT\",\"channel\":\"ch123\",\"time\":\"1970-01-01 00:00:01.000002\",\"af\":\"IPv6\",\"src\":\"1:2:3:4:5:6:7:8\",\"dst\":\"9:b:a:b:c:d:e:f\",\"ttl\":255,\"proto\":\"UDP\",\"src_port\":123,\"dst_port\":456,\"payload\":\"3q2+7w==\"}";
	axa_emsg_t emsg;
	uint8_t packet[] = "\x60\x00\x00\x00\x00\x0c\x11\xff\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08\x00\x09\x00\x0b\x00\x0a\x00\x0b\x00\x0c\x00\x0d\x00\x0e\x00\x0f\x00\x7b\x01\xc8\x00\x0c\x5f\x7e\xde\xad\xbe\xef";
	size_t whit_len = offsetof(axa_p_whit_ip_t, b) + sizeof(packet) - 1;
	axa_p_whit_ip_t *whit = alloca(whit_len);
	axa_p_whit_ip_t whit_data = { .hdr={
		.hdr = { .ch=123, .type=AXA_P_WHIT_IP },
		.tv = { 1, 2 },
		.ip_len = sizeof(packet),
	}};
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + whit_len), 1, AXA_P_PVERS, AXA_P_OP_WHIT };
	char *out = NULL;
	axa_json_res_t res;

	*whit = whit_data;
	memcpy(&(whit->b), packet, sizeof(packet) - 1);

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)whit, whit_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_whit_ip6_trunc)
{
	truncated_test(AXA_P_OP_WHIT, axa_p_whit_ip_t, offsetof(axa_p_whit_ip_t, b));
}
END_TEST

START_TEST(test_whit_trunc)
{
	truncated_test(AXA_P_OP_WHIT, axa_p_whit_hdr_t, sizeof(axa_p_whit_hdr_t) - 1);
}
END_TEST

START_TEST(test_watch_ip4)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH\",\"watch_type\":\"ipv4\",\"watch\":\"IP=12.34.56.0/24\"}";
	axa_emsg_t emsg;
	axa_p_watch_t watch = { AXA_P_WATCH_IPV4, 24, 0, 0, {} };
	size_t watch_len = offsetof(axa_p_watch_t, pat) + sizeof(struct in_addr);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_WATCH };
	char *out = NULL;
	axa_json_res_t res;
	struct in_addr addr;

	ck_assert(inet_aton("12.34.56.0", &addr));
	memcpy(&(watch.pat.addr), &addr, sizeof(watch.pat.addr));

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&watch, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_watch_ip4_trunc)
{
	axa_p_watch_t watch = { AXA_P_WATCH_IPV4, 24, 0, 0, {} };
	size_t watch_len = offsetof(axa_p_watch_t, pat);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_WATCH };
	char *out = NULL;
	axa_emsg_t emsg;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&watch, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_FAILURE);
	ck_assert_ptr_eq(out, NULL);
}
END_TEST

START_TEST(test_watch_ip4_overflow)
{
	axa_p_watch_t watch = { AXA_P_WATCH_IPV4, 24, 0, 0, {} };
	size_t watch_len = sizeof(axa_p_watch_t);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_WATCH };
	char *out = NULL;
	axa_json_res_t res;
	axa_emsg_t emsg;
	struct in_addr addr;

	ck_assert(inet_aton("12.34.56.78", &addr));
	memcpy(&(watch.pat.addr), &addr, sizeof(watch.pat.addr));

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&watch, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_FAILURE);
	ck_assert_ptr_eq(out, NULL);
	free(out);
}
END_TEST

START_TEST(test_watch_ip6)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH\",\"watch_type\":\"ipv6\",\"watch\":\"IP=1:2:3:4:5:6::/48\"}";
	axa_emsg_t emsg;
	axa_p_watch_t watch = { AXA_P_WATCH_IPV6, 48, 0, 0, {} };
	size_t watch_len = offsetof(axa_p_watch_t, pat) + sizeof(struct in6_addr);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_WATCH };
	char *out = NULL;
	axa_json_res_t res;
	struct in6_addr addr6;

	ck_assert(inet_pton(AF_INET6, "1:2:3:4:5:6::", &addr6));
	memcpy(&(watch.pat.addr6), &addr6, sizeof(watch.pat.addr6));

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&watch, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_watch_dns)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH\",\"watch_type\":\"dns\",\"watch\":\"dns=fsi.io\"}";
	axa_emsg_t emsg;
	axa_p_watch_t watch = { AXA_P_WATCH_DNS, 0, 0, 0, { .dns="\x03""fsi\x02io" } };
	size_t watch_len = offsetof(axa_p_watch_t, pat) + strlen((const char*)watch.pat.dns) + 1;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_WATCH };
	char *out = NULL;
	axa_json_res_t res;
	ck_assert_int_eq(strlen((const char*)watch.pat.dns), 7);
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&watch, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_watch_dns_wildcard)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH\",\"watch_type\":\"dns\",\"watch\":\"dns=*.fsi.io\"}";
	axa_emsg_t emsg;
	axa_p_watch_t watch = { AXA_P_WATCH_DNS, 0, AXA_P_WATCH_FG_WILD, 0, { .dns="\x03""fsi\x02io" } };
	size_t watch_len = offsetof(axa_p_watch_t, pat) + strlen((const char*)watch.pat.dns) + 1;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_WATCH };
	char *out = NULL;
	axa_json_res_t res;
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&watch, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_watch_dns_wildcard_all)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH\",\"watch_type\":\"dns\",\"watch\":\"dns=*.\"}";
	axa_emsg_t emsg;
	axa_p_watch_t watch = { AXA_P_WATCH_DNS, 0, AXA_P_WATCH_FG_WILD, 0, { .dns="" } };
	size_t watch_len = offsetof(axa_p_watch_t, pat) + strlen((const char*)watch.pat.dns) + 1;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_WATCH };
	char *out = NULL;
	axa_json_res_t res;
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&watch, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_watch_dns_shared)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH\",\"watch_type\":\"dns\",\"watch\":\"dns=fsi.io(shared)\"}";
	axa_emsg_t emsg;
	axa_p_watch_t watch = { AXA_P_WATCH_DNS, 0, AXA_P_WATCH_FG_SHARED, 0, { .dns="\x03""fsi\x02io" } };
	size_t watch_len = offsetof(axa_p_watch_t, pat) + strlen((const char*)watch.pat.dns) + 1;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_WATCH };
	char *out = NULL;
	axa_json_res_t res;
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&watch, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_watch_ch)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH\",\"watch_type\":\"channel\",\"watch\":\"ch=ch123\"}";
	axa_emsg_t emsg;
	axa_p_watch_t watch = { AXA_P_WATCH_CH, 0, 0, 0, { .ch=123 } };
	size_t watch_len = offsetof(axa_p_watch_t, pat) + sizeof(axa_p_ch_t);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_WATCH };
	char *out = NULL;
	axa_json_res_t res;
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&watch, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_watch_errors)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH\",\"watch_type\":\"errors\",\"watch\":\"ERRORS\"}";
	axa_emsg_t emsg;
	axa_p_watch_t watch = { AXA_P_WATCH_ERRORS, 0, 0, 0, { } };
	size_t watch_len = offsetof(axa_p_watch_t, pat);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_WATCH };
	char *out = NULL;
	axa_json_res_t res;
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&watch, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_watch_trunc)
{
	truncated_test(AXA_P_OP_OPT, axa_p_opt_t, offsetof(axa_p_watch_t, pat));
}
END_TEST

START_TEST(test_anom)
{
	const char *expected = "{\"tag\":1,\"op\":\"ANOMALY\",\"an\":\"test_anom\",\"parms\":\"param1 param2\"}";
	axa_emsg_t emsg;
	axa_p_anom_t anom = { {"test_anom"}, "param1 param2" };
	size_t anom_len = offsetof(axa_p_anom_t, parms) + strlen(anom.parms) + 1;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + anom_len), 1, AXA_P_PVERS, AXA_P_OP_ANOM };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&anom, anom_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_anom_empty)
{
	const char *expected = "{\"tag\":1,\"op\":\"ANOMALY\",\"an\":\"test_anom\"}";
	axa_emsg_t emsg;
	axa_p_anom_t anom = { {"test_anom"}, {} };
	size_t anom_len = offsetof(axa_p_anom_t, parms) + offsetof(axa_p_anom_t, parms);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + anom_len), 1, AXA_P_PVERS, AXA_P_OP_ANOM };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&anom, anom_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_anom_trunc)
{
	truncated_test(AXA_P_OP_ANOM, axa_p_anom_t, offsetof(axa_p_anom_t, parms) - 1);
}
END_TEST

START_TEST(test_channel_on)
{
	const char *expected = "{\"tag\":1,\"op\":\"CHANNEL ON/OFF\",\"channel\":\"ch123\",\"on\":true}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + sizeof(axa_p_channel_t)), 1, AXA_P_PVERS, AXA_P_OP_CHANNEL };
	axa_p_channel_t channel = { 123, true };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&channel, sizeof(channel), &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_channel_off)
{
	const char *expected = "{\"tag\":1,\"op\":\"CHANNEL ON/OFF\",\"channel\":\"ch123\",\"on\":false}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + sizeof(axa_p_channel_t)), 1, AXA_P_PVERS, AXA_P_OP_CHANNEL };
	axa_p_channel_t channel = { 123, false };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&channel, sizeof(channel), &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_channel_all)
{
	const char *expected = "{\"tag\":1,\"op\":\"CHANNEL ON/OFF\",\"channel\":\"all\",\"on\":true}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + sizeof(axa_p_channel_t)), 1, AXA_P_PVERS, AXA_P_OP_CHANNEL };
	axa_p_channel_t channel = { AXA_OP_CH_ALL, true };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&channel, sizeof(channel), &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_channel_trunc)
{
	truncated_test(AXA_P_OP_CHANNEL, axa_p_channel_t, sizeof(axa_p_channel_t) - 1);
}
END_TEST

START_TEST(test_wlist)
{
	const char *expected = "{\"tag\":1,\"op\":\"WATCH LIST\",\"cur_tag\":1,\"watch_type\":\"ipv4\",\"watch\":\"IP=12.34.56.0/24\"}";
	axa_emsg_t emsg;
	axa_p_wlist_t wlist = { 1, {0,0}, { AXA_P_WATCH_IPV4, 24, 0, 0, {} }};
	size_t wlist_len = offsetof(axa_p_wlist_t, w) + offsetof(axa_p_watch_t, pat) + sizeof(struct in_addr);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + wlist_len), 1, AXA_P_PVERS, AXA_P_OP_WLIST };
	char *out = NULL;
	axa_json_res_t res;
	struct in_addr addr;

	ck_assert(inet_aton("12.34.56.0", &addr));
	memcpy(&(wlist.w.pat.addr), &addr, sizeof(wlist.w.pat.addr));

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&wlist, wlist_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_wlist_trunc)
{
	truncated_test(AXA_P_OP_OPT, axa_p_opt_t, offsetof(axa_p_wlist_t, w) + offsetof(axa_p_watch_t, pat) - 1);
}
END_TEST

START_TEST(test_ahit)
{
	const char *expected = "{\"tag\":1,\"op\":\"ANOMALY HIT\",\"an\":\"test_anom\",\"channel\":\"ch123\",\"time\":\"1970-01-01 00:00:01.000002\",\"af\":\"IPv4\",\"src\":\"1.2.3.4\",\"dst\":\"5.6.7.8\",\"ttl\":255,\"proto\":\"UDP\",\"src_port\":123,\"dst_port\":456,\"payload\":\"3q2+7w==\"}";
	axa_emsg_t emsg;
	uint8_t packet[] = "\x45\x00\x00\x20\x12\x34\x40\x00\xff\x11\x59\x85\x01\x02\x03\x04\x05\x06\x07\x08\x00\x7b\x01\xc8\x00\x0c\x4f\xe2\xde\xad\xbe\xef";
	size_t ahit_len = offsetof(axa_p_ahit_t, whit) + offsetof(axa_p_whit_ip_t, b) + sizeof(packet) - 1;
	axa_p_ahit_t *ahit = alloca(ahit_len);
	axa_p_ahit_t ahit_data = { .an={"test_anom"} };
	axa_p_whit_ip_t whit_data = { .hdr={
		.hdr = { .ch=123, .type=AXA_P_WHIT_IP },
		.tv = { 1, 2 },
		.ip_len = sizeof(packet),
	}};
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + ahit_len), 1, AXA_P_PVERS, AXA_P_OP_AHIT };
	char *out = NULL;
	axa_json_res_t res;

	ahit_data.whit.ip = whit_data;
	*ahit = ahit_data;
	memcpy(&(ahit->whit.ip.b), packet, sizeof(packet) - 1);

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)ahit, ahit_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_ahit_trunc)
{
	truncated_test(AXA_P_OP_AHIT, axa_p_ahit_t, offsetof(axa_p_ahit_t, whit) + sizeof(axa_p_whit_hdr_t) - 1);
}
END_TEST

START_TEST(test_alist)
{
	const char *expected = "{\"tag\":1,\"op\":\"ANOMALY LIST\",\"cur_tag\":1,\"an\":\"test_anom\",\"parms\":\"param1 param2\"}";
	axa_emsg_t emsg;
	axa_p_alist_t alist = { .cur_tag=1, .anom={ {"test_anom"}, "param1 param2" } };
	size_t alist_len = offsetof(axa_p_alist_t, anom) + offsetof(axa_p_anom_t, parms) + strlen(alist.anom.parms) + 1;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + alist_len), 1, AXA_P_PVERS, AXA_P_OP_ALIST };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&alist, alist_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_alist_trunc)
{
	truncated_test(AXA_P_OP_ALIST, axa_p_alist_t, offsetof(axa_p_alist_t, anom) + offsetof(axa_p_anom_t, parms) - 1);
}
END_TEST

START_TEST(test_clist)
{
	const char *expected = "{\"tag\":1,\"op\":\"CHANNEL LIST\",\"channel\":\"ch123\",\"on\":true,\"spec\":\"test channel\"}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + sizeof(axa_p_clist_t)), 1, AXA_P_PVERS, AXA_P_OP_CLIST };
	axa_p_clist_t clist = { 123, true, {"test channel"} };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&clist, sizeof(clist), &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_clist_trunc)
{
	truncated_test(AXA_P_OP_CLIST, axa_p_clist_t, sizeof(axa_p_clist_t) - 1);
}
END_TEST

START_TEST(test_user)
{
	const char *expected = "{\"tag\":1,\"op\":\"USER\",\"name\":\"test user\"}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + sizeof(axa_p_user_t)), 1, AXA_P_PVERS, AXA_P_OP_USER };
	axa_p_user_t user = { {"test user"} };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&user, sizeof(user), &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_user_trunc)
{
	truncated_test(AXA_P_OP_USER, axa_p_user_t, 0);
}
END_TEST

START_TEST(test_opt_trace)
{
	const char *expected = "{\"tag\":1,\"op\":\"OPTION\",\"type\":\"TRACE\",\"trace\":3}";
	axa_emsg_t emsg;
	axa_p_opt_t opt = { AXA_P_OPT_TRACE, {}, { .trace=AXA_H2P32(AXA_DEBUG_TRACE) } };
	size_t watch_len = offsetof(axa_p_opt_t, u) + sizeof(opt.u.trace);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_OPT };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&opt, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_opt_trace_req)
{
	const char *expected = "{\"tag\":1,\"op\":\"OPTION\",\"type\":\"TRACE\",\"trace\":\"REQUEST TRACE VALUE\"}";
	axa_emsg_t emsg;
	axa_p_opt_t opt = { AXA_P_OPT_TRACE, {}, { .trace=AXA_H2P32(AXA_P_OPT_TRACE_REQ) } };
	size_t watch_len = offsetof(axa_p_opt_t, u) + sizeof(opt.u.trace);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_OPT };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&opt, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_opt_rlimit_num)
{
	const char *expected = "{\"tag\":1,\"op\":\"OPTION\",\"type\":\"RATE LIMIT\",\"max_pkts_per_sec\":123,\"cur_pkts_per_sec\":456,\"report_secs\":60}";
	axa_emsg_t emsg;
	axa_p_opt_t opt = { AXA_P_OPT_RLIMIT, {}, { .rlimit={
		.max_pkts_per_sec=AXA_H2P64(123),
		.cur_pkts_per_sec=AXA_H2P64(456),
		.report_secs=AXA_H2P64(60),
	} } };
	size_t watch_len = offsetof(axa_p_opt_t, u) + sizeof(opt.u.rlimit);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_OPT };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&opt, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_opt_rlimit_max)
{
	const char *expected = "{\"tag\":1,\"op\":\"OPTION\",\"type\":\"RATE LIMIT\",\"max_pkts_per_sec\":1000000000,\"cur_pkts_per_sec\":123,\"report_secs\":60}";
	axa_emsg_t emsg;
	axa_p_opt_t opt = { AXA_P_OPT_RLIMIT, {}, { .rlimit={
		.max_pkts_per_sec=AXA_H2P64(AXA_RLIMIT_MAX),
		.cur_pkts_per_sec=AXA_H2P64(123),
		.report_secs=AXA_H2P64(60),
	} } };
	size_t watch_len = offsetof(axa_p_opt_t, u) + sizeof(opt.u.rlimit);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_OPT };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&opt, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_opt_rlimit_off)
{
	const char *expected = "{\"tag\":1,\"op\":\"OPTION\",\"type\":\"RATE LIMIT\",\"max_pkts_per_sec\":\"off\",\"cur_pkts_per_sec\":123,\"report_secs\":60}";
	axa_emsg_t emsg;
	axa_p_opt_t opt = { AXA_P_OPT_RLIMIT, {}, { .rlimit={
		.max_pkts_per_sec=AXA_H2P64(AXA_RLIMIT_OFF),
		.cur_pkts_per_sec=AXA_H2P64(123),
		.report_secs=AXA_H2P64(60),
	} } };
	size_t watch_len = offsetof(axa_p_opt_t, u) + sizeof(opt.u.rlimit);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_OPT };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&opt, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_opt_rlimit_na)
{
	const char *expected = "{\"tag\":1,\"op\":\"OPTION\",\"type\":\"RATE LIMIT\",\"max_pkts_per_sec\":null,\"cur_pkts_per_sec\":123,\"report_secs\":null}";
	axa_emsg_t emsg;
	axa_p_opt_t opt = { AXA_P_OPT_RLIMIT, {}, { .rlimit={
		.max_pkts_per_sec=AXA_H2P64(AXA_RLIMIT_NA),
		.cur_pkts_per_sec=AXA_H2P64(123),
		.report_secs=AXA_H2P64(AXA_RLIMIT_NA),
	} } };
	size_t watch_len = offsetof(axa_p_opt_t, u) + sizeof(opt.u.rlimit);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_OPT };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&opt, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST


START_TEST(test_opt_sample)
{
	const char *expected = "{\"tag\":1,\"op\":\"OPTION\",\"type\":\"SAMPLE\",\"sample\":0.000123}";
	axa_emsg_t emsg;
	axa_p_opt_t opt = { AXA_P_OPT_SAMPLE, {}, { .sample=AXA_H2P32(123) } };
	size_t watch_len = offsetof(axa_p_opt_t, u) + sizeof(opt.u.sample);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_OPT };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&opt, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_opt_sndbuf)
{
	const char *expected = "{\"tag\":1,\"op\":\"OPTION\",\"type\":\"SNDBUF\",\"bufsize\":123}";
	axa_emsg_t emsg;
	axa_p_opt_t opt = { AXA_P_OPT_SNDBUF, {}, { .bufsize=AXA_H2P32(123) } };
	size_t watch_len = offsetof(axa_p_opt_t, u) + sizeof(opt.u.bufsize);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), 1, AXA_P_PVERS, AXA_P_OP_OPT };
	char *out = NULL;
	axa_json_res_t res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&opt, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_opt_trunc)
{
	truncated_test(AXA_P_OP_OPT, axa_p_opt_t, offsetof(axa_p_opt_t, u));
}
END_TEST

START_TEST(test_join)
{
	axa_p_join_t join = { 0 };
	size_t watch_len = sizeof(axa_p_join_t);
	axa_p_hdr_t hdr = { AXA_H2P32(sizeof(axa_p_hdr_t) + watch_len), AXA_H2P_TAG(0), AXA_P_PVERS, AXA_P_OP_JOIN };
	char *out = NULL;
	axa_json_res_t res;
	axa_emsg_t emsg;
	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t*)&join, watch_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, "{\"tag\":\"*\",\"op\":\"JOIN\",\"id\":0}");
	free(out);
}
END_TEST

START_TEST(test_join_trunc)
{
	truncated_test(AXA_P_OP_JOIN, axa_p_join_t, sizeof(axa_p_join_t) - 1);
}
END_TEST

START_TEST(test_pause)
{
	empty_test(AXA_P_OP_PAUSE, "PAUSE");
}
END_TEST

START_TEST(test_go)
{
	empty_test(AXA_P_OP_GO, "GO");
}
END_TEST

START_TEST(test_wget)
{
	empty_test(AXA_P_OP_WGET, "WATCH GET");
}
END_TEST

START_TEST(test_aget)
{
	empty_test(AXA_P_OP_AGET, "ANOMALY GET");
}
END_TEST

START_TEST(test_stop)
{
	empty_test(AXA_P_OP_STOP, "STOP");
}
END_TEST

START_TEST(test_all_stop)
{
	empty_test(AXA_P_OP_ALL_STOP, "ALL STOP");
}
END_TEST

START_TEST(test_cget)
{
	empty_test(AXA_P_OP_CGET, "CHANNEL GET");
}
END_TEST

START_TEST(test_acct)
{
	empty_test(AXA_P_OP_ACCT, "ACCOUNTING");
}
END_TEST

START_TEST(test_radu)
{
	empty_test(AXA_P_OP_RADU, "RAD UNITS GET");
}
END_TEST

START_TEST(test_stats_req)
{
	const char *expected ="{\"tag\":\"*\",\"op\":\"STATS REQ\",\"version\":1,\"type\":\"all\"}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	_axa_p_stats_req_t stats_req;
	uint8_t stats[sizeof(_axa_p_stats_req_t)];
	axa_json_res_t res;
	char *out = NULL;

	memset(&hdr, 0, sizeof (hdr));
	memset(&stats_req, 0, sizeof (stats_req));

	hdr.len = AXA_H2P32(sizeof(axa_p_hdr_t) + sizeof (stats_req));
	hdr.tag = AXA_H2P_TAG(0);
	hdr.pvers = AXA_P_PVERS;
	hdr.op = _AXA_P_OP_STATS_REQ;

	stats_req.version = _AXA_STATS_VERSION_ONE;
	stats_req.type = AXA_P_STATS_M_M_ALL;

	memcpy(stats, (uint8_t *)&stats_req, sizeof (stats_req));

	res = axa_body_to_json(&emsg, nmsg_input, &hdr,
			(axa_p_body_t *)&stats_req, sizeof (stats_req), &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_stats_rsp_sra_one_user)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"STATS RSP\",\"version\":1,\"result\":\"success\",\"load\":[6700,7900,8300],\"cpu_usage\":5144,\"uptime\":19287627,\"starttime\":19279187,\"vmsize\":1428819968,\"vmrss\":21204992,\"thread_cnt\":145,\"user_cnt\":1,\"server_type\":\"sra\",\"fd_sockets\":13,\"fd_pipes\":3,\"fd_anon_inodes\":0,\"fd_other\":5,\"rchar\":17362446,\"wchar\":755982917,\"sra_ipv4_watch_cnt\":0,\"sra_ipv6_watch_cnt\":0,\"sra_dns_watch_cnt\":0,\"sra_ch_watch_cnt\":0,\"sra_err_watch_cnt\":0,\"sra_channels\":[\"ch213\",\"ch255\"],\"users\":[\"user_obj\",{\"server_type\":\"sra\",\"user\":\"mschiffm\",\"is_admin\":true,\"io_type\":\"apikey\",\"address\":\"73.170.71.223\",\"sn\":251,\"connected_since\":\"2018-01-03T23:50:00Z\",\"ratelimit\":0,\"sample\":100.00,\"last_count_update\":\"2018-01-03T23:50:00Z\",\"filtered\":0,\"missed\":0,\"collected\":0,\"sent\":0,\"rlimit\":0,\"congested\":0,\"ipv4_watch_cnt\":0,\"ipv6_watch_cnt\":0,\"dns_watch_cnt\":0,\"ch_watch_cnt\":0,\"err_watch_cnt\":0,\"channels\":[\"ch255\"]}]}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	_axa_p_stats_rsp_t stats_rsp;
	_axa_p_stats_sys_t stats_sys;
	_axa_p_stats_user_t stats_users[1];
	size_t stats_len = sizeof (stats_rsp) + sizeof (stats_sys)
		+ sizeof (stats_users);
	uint8_t stats[stats_len];
	axa_json_res_t res;
	char *out = NULL;

	memset(&hdr, 0, sizeof (hdr));
	memset(&stats_rsp, 0, sizeof (stats_rsp));
	memset(&stats_sys, 0, sizeof (stats_sys));
	memset(&stats_users, 0, sizeof (stats_users));

	hdr.len = AXA_H2P32(sizeof(axa_p_hdr_t) + stats_len);
	hdr.tag = AXA_H2P_TAG(0);
	hdr.pvers = AXA_P_PVERS;
	hdr.op = _AXA_P_OP_STATS_RSP;

	stats_rsp.version = _AXA_STATS_VERSION_ONE;
	stats_rsp.sys_objs_cnt = 1;
	stats_rsp.user_objs_cnt = 1;
	stats_rsp.result = AXA_P_STATS_R_SUCCESS;

	stats_sys.type = _AXA_P_STATS_TYPE_SYS;
	stats_sys.server_type = _AXA_STATS_SRVR_TYPE_SRA;
	stats_sys.load[0] = 6700;
	stats_sys.load[1] = 7900;
	stats_sys.load[2] = 8300;
	stats_sys.cpu_usage = 5144;
	stats_sys.uptime = 19287627;
	stats_sys.starttime = 19279187;
	stats_sys.fd_sockets = 13;
	stats_sys.fd_pipes = 3;
	stats_sys.fd_anon_inodes = 0;
	stats_sys.fd_other = 5;
	stats_sys.vmsize = 1428819968;
	stats_sys.vmrss = 21204992;
	stats_sys.rchar = 17362446;
	stats_sys.wchar = 755982917;
	stats_sys.thread_cnt = 145;
	stats_sys.user_cnt = 1;
	stats_sys.srvr.sra.watches.ipv4_cnt = 0;
	stats_sys.srvr.sra.watches.ipv6_cnt = 0;
	stats_sys.srvr.sra.watches.dns_cnt = 0;
	stats_sys.srvr.sra.watches.ch_cnt = 0;
	stats_sys.srvr.sra.watches.err_cnt = 0;
	axa_set_bitwords(stats_sys.srvr.sra.ch_mask.m, 213);
	axa_set_bitwords(stats_sys.srvr.sra.ch_mask.m, 255);

	stats_users[0].type = _AXA_P_STATS_TYPE_USER;
	stats_users[0].server_type = _AXA_STATS_SRVR_TYPE_SRA;
	strcpy(stats_users[0].user.name, "mschiffm");
	stats_users[0].is_admin = 1;
	stats_users[0].io_type = AXA_IO_TYPE_APIKEY;
	stats_users[0].addr_type = AXA_AF_INET;
	stats_users[0].ip.ipv4 = inet_addr("73.170.71.223");
	stats_users[0].sn = 251;
	stats_users[0].connected_since.tv_sec = 1515023400;
	stats_users[0].ratelimit = 0;
	stats_users[0].sample = 100;
	stats_users[0].last_cnt_update.tv_sec = 1515023400;
	stats_users[0].filtered = 0;
	stats_users[0].missed = 0;
	stats_users[0].collected = 0;
	stats_users[0].sent = 0;
	stats_users[0].rlimit = 0;
	stats_users[0].congested = 0;
	axa_set_bitwords(stats_users[0].srvr.sra.ch_mask.m, 255);
	stats_users[0].srvr.sra.watches.ipv4_cnt = 0;
	stats_users[0].srvr.sra.watches.ipv6_cnt = 0;
	stats_users[0].srvr.sra.watches.dns_cnt = 0;
	stats_users[0].srvr.sra.watches.ch_cnt = 0;
	stats_users[0].srvr.sra.watches.err_cnt = 0;

	memcpy((uint8_t *)stats, (uint8_t *)&stats_rsp, sizeof (stats_rsp));
	memcpy((uint8_t *)stats + sizeof (stats_rsp), (uint8_t *)&stats_sys,
			sizeof (stats_sys));
	memcpy((uint8_t *)stats + sizeof (stats_rsp) + sizeof (stats_sys),
			(uint8_t *)&stats_users, sizeof (stats_users));

	res = axa_body_to_json(&emsg, nmsg_input, &hdr,
			(axa_p_body_t *)stats, stats_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_stats_rsp_rad_one_user)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"STATS RSP\",\"version\":1,\"result\":\"success\",\"load\":[6300,6200,7100],\"cpu_usage\":0,\"uptime\":19449048,\"starttime\":19373104,\"vmsize\":91680768,\"vmrss\":4968448,\"thread_cnt\":2,\"user_cnt\":1,\"server_type\":\"rad\",\"rad_anomaly_cnt\":0,\"users\":[\"user_obj\",{\"server_type\":\"rad\",\"user\":\"mschiffm\",\"is_admin\":true,\"io_type\":\"apikey\",\"address\":\"73.170.71.223\",\"sn\":2,\"connected_since\":\"2018-01-05T20:40:31Z\",\"ratelimit\":0,\"sample\":100.00,\"last_count_update\":\"2018-01-05T20:40:31Z\",\"filtered\":0,\"missed\":0,\"collected\":0,\"sent\":0,\"rlimit\":0,\"congested\":0,\"anomaly_count_in_flight\":0,\"anomaly_count_total\":0}]}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	_axa_p_stats_rsp_t stats_rsp;
	_axa_p_stats_sys_t stats_sys;
	_axa_p_stats_user_t stats_users[1];
	size_t stats_len = sizeof (stats_rsp) + sizeof (stats_sys)
		+ sizeof (stats_users);
	uint8_t stats[stats_len];
	axa_json_res_t res;
	char *out = NULL;

	memset(&hdr, 0, sizeof (hdr));
	memset(&stats_rsp, 0, sizeof (stats_rsp));
	memset(&stats_sys, 0, sizeof (stats_sys));
	memset(&stats_users, 0, sizeof (stats_users));

	hdr.len = AXA_H2P32(sizeof(axa_p_hdr_t) + stats_len);
	hdr.tag = AXA_H2P_TAG(0);
	hdr.pvers = AXA_P_PVERS;
	hdr.op = _AXA_P_OP_STATS_RSP;

	stats_rsp.version = _AXA_STATS_VERSION_ONE;
	stats_rsp.sys_objs_cnt = 1;
	stats_rsp.user_objs_cnt = 1;
	stats_rsp.result = AXA_P_STATS_R_SUCCESS;

	stats_sys.type = _AXA_P_STATS_TYPE_SYS;
	stats_sys.server_type = _AXA_STATS_SRVR_TYPE_RAD;
	stats_sys.load[0] = 6300;
	stats_sys.load[1] = 6200;
	stats_sys.load[2] = 7100;
	stats_sys.cpu_usage = 0;
	stats_sys.uptime = 19449048;
	stats_sys.starttime = 19373104;
	stats_sys.fd_sockets = 91680768;
	stats_sys.fd_pipes = 4968448;
	stats_sys.vmsize = 91680768;
	stats_sys.vmrss = 4968448;
	stats_sys.thread_cnt = 2;
	stats_sys.user_cnt = 1;
	stats_sys.srvr.rad.an_cnt = 0;

	stats_users[0].type = _AXA_P_STATS_TYPE_USER;
	stats_users[0].server_type = _AXA_STATS_SRVR_TYPE_RAD;
	strcpy(stats_users[0].user.name, "mschiffm");
	stats_users[0].is_admin = 1;
	stats_users[0].io_type = AXA_IO_TYPE_APIKEY;
	stats_users[0].addr_type = AXA_AF_INET;
	stats_users[0].ip.ipv4 = inet_addr("73.170.71.223");
	stats_users[0].sn = 2;
	stats_users[0].connected_since.tv_sec = 1515184831;
	stats_users[0].ratelimit = 0;
	stats_users[0].sample = 100;
	stats_users[0].last_cnt_update.tv_sec = 1515184831;
	stats_users[0].filtered = 0;
	stats_users[0].missed = 0;
	stats_users[0].collected = 0;
	stats_users[0].sent = 0;
	stats_users[0].rlimit = 0;
	stats_users[0].congested = 0;
	stats_users[0].srvr.rad.an_obj_cnt = 0;
	stats_users[0].srvr.rad.an_obj_cnt_total = 0;

	memcpy((uint8_t *)stats, (uint8_t *)&stats_rsp, sizeof (stats_rsp));
	memcpy((uint8_t *)stats + sizeof (stats_rsp), (uint8_t *)&stats_sys,
			sizeof (stats_sys));
	memcpy((uint8_t *)stats + sizeof (stats_rsp) + sizeof (stats_sys),
			(uint8_t *)&stats_users, sizeof (stats_users));

	res = axa_body_to_json(&emsg, nmsg_input, &hdr,
			(axa_p_body_t *)stats, stats_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_stats_rsp_rad_one_user_one_anomaly)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"STATS RSP\",\"version\":1,\"result\":\"success\",\"load\":[6300,6200,7100],\"cpu_usage\":0,\"uptime\":19449048,\"starttime\":19373104,\"vmsize\":91680768,\"vmrss\":4968448,\"thread_cnt\":2,\"user_cnt\":1,\"server_type\":\"rad\",\"rad_anomaly_cnt\":1,\"users\":[\"user_obj\",{\"server_type\":\"rad\",\"user\":\"mschiffm\",\"is_admin\":true,\"io_type\":\"apikey\",\"address\":\"73.170.71.223\",\"sn\":2,\"connected_since\":\"2018-01-05T20:40:31Z\",\"ratelimit\":0,\"sample\":100.00,\"last_count_update\":\"2018-01-05T20:40:31Z\",\"filtered\":0,\"missed\":0,\"collected\":0,\"sent\":0,\"rlimit\":0,\"congested\":0,\"anomaly_count_in_flight\":1,\"anomaly_count_total\":1,\"anomalies\":[\"an_obj\",{\"name\":\"brand_sentry\",\"options\":\"b=farsight,fsi;m=hgl,lit\",\"ru_original\":\"unlimited\",\"ru_current\":\"unlimited\",\"ru_cost\":0,\"channels\":[\"ch204\"]}]}]}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	_axa_p_stats_rsp_t stats_rsp;
	_axa_p_stats_sys_t stats_sys;
	_axa_p_stats_user_t stats_users[1];
	_axa_p_stats_user_rad_an_t an_obj;
	size_t stats_len = sizeof (stats_rsp) + sizeof (stats_sys)
		+ sizeof (stats_users) + sizeof (an_obj);
	uint8_t stats[stats_len];
	axa_json_res_t res;
	char *out = NULL;

	memset(&hdr, 0, sizeof (hdr));
	memset(&stats_rsp, 0, sizeof (stats_rsp));
	memset(&stats_sys, 0, sizeof (stats_sys));
	memset(&stats_users, 0, sizeof (stats_users));
	memset(&an_obj, 0, sizeof (an_obj));

	hdr.len = AXA_H2P32(sizeof(axa_p_hdr_t) + stats_len);
	hdr.tag = AXA_H2P_TAG(0);
	hdr.pvers = AXA_P_PVERS;
	hdr.op = _AXA_P_OP_STATS_RSP;

	stats_rsp.version = _AXA_STATS_VERSION_ONE;
	stats_rsp.sys_objs_cnt = 1;
	stats_rsp.user_objs_cnt = 1;
	stats_rsp.result = AXA_P_STATS_R_SUCCESS;

	stats_sys.type = _AXA_P_STATS_TYPE_SYS;
	stats_sys.server_type = _AXA_STATS_SRVR_TYPE_RAD;
	stats_sys.load[0] = 6300;
	stats_sys.load[1] = 6200;
	stats_sys.load[2] = 7100;
	stats_sys.cpu_usage = 0;
	stats_sys.uptime = 19449048;
	stats_sys.starttime = 19373104;
	stats_sys.vmsize = 91680768;
	stats_sys.vmrss = 4968448;
	stats_sys.thread_cnt = 2;
	stats_sys.user_cnt = 1;
	stats_sys.srvr.rad.an_cnt = 1;

	stats_users[0].type = _AXA_P_STATS_TYPE_USER;
	stats_users[0].server_type = _AXA_STATS_SRVR_TYPE_RAD;
	strcpy(stats_users[0].user.name, "mschiffm");
	stats_users[0].is_admin = 1;
	stats_users[0].io_type = AXA_IO_TYPE_APIKEY;
	stats_users[0].addr_type = AXA_AF_INET;
	stats_users[0].ip.ipv4 = inet_addr("73.170.71.223");
	stats_users[0].sn = 2;
	stats_users[0].connected_since.tv_sec = 1515184831;
	stats_users[0].ratelimit = 0;
	stats_users[0].sample = 100;
	stats_users[0].last_cnt_update.tv_sec = 1515184831;
	stats_users[0].filtered = 0;
	stats_users[0].missed = 0;
	stats_users[0].collected = 0;
	stats_users[0].sent = 0;
	stats_users[0].rlimit = 0;
	stats_users[0].congested = 0;
	stats_users[0].srvr.rad.an_obj_cnt = 1;
	stats_users[0].srvr.rad.an_obj_cnt_total = 1;

	strcpy(an_obj.name, "brand_sentry");
	strcpy(an_obj.opt, "b=farsight,fsi;m=hgl,lit");
	an_obj.ru_original = INT_MAX;
	an_obj.ru_current = INT_MAX;
	an_obj.ru_cost = 0;
	axa_set_bitwords(an_obj.ch_mask.m, 204);

	memcpy((uint8_t *)stats, (uint8_t *)&stats_rsp, sizeof (stats_rsp));
	memcpy((uint8_t *)stats + sizeof (stats_rsp), (uint8_t *)&stats_sys,
			sizeof (stats_sys));
	memcpy((uint8_t *)stats + sizeof (stats_rsp) + sizeof (stats_sys),
			(uint8_t *)&stats_users, sizeof (stats_users));
	memcpy((uint8_t *)stats + sizeof (stats_rsp) + sizeof (stats_sys) +
			sizeof (stats_users), (uint8_t *)&an_obj,
			sizeof (an_obj));

	res = axa_body_to_json(&emsg, nmsg_input, &hdr,
			(axa_p_body_t *)stats, stats_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST
START_TEST(test_stats_rsp_sra_no_users)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"STATS RSP\",\"version\":1,\"result\":\"success\",\"load\":[6700,7900,8300],\"cpu_usage\":5144,\"uptime\":19287627,\"starttime\":19279187,\"vmsize\":1428819968,\"vmrss\":21204992,\"thread_cnt\":145,\"user_cnt\":0,\"server_type\":\"sra\",\"fd_sockets\":13,\"fd_pipes\":3,\"fd_anon_inodes\":0,\"fd_other\":5,\"rchar\":17362446,\"wchar\":755982917,\"sra_ipv4_watch_cnt\":0,\"sra_ipv6_watch_cnt\":0,\"sra_dns_watch_cnt\":0,\"sra_ch_watch_cnt\":0,\"sra_err_watch_cnt\":0,\"sra_channels\":[\"ch213\",\"ch255\"]}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	_axa_p_stats_rsp_t stats_rsp;
	_axa_p_stats_sys_t stats_sys;
	size_t stats_len = sizeof (stats_rsp) + sizeof (stats_sys);
	uint8_t stats[stats_len];
	axa_json_res_t res;
	char *out = NULL;

	memset(&hdr, 0, sizeof (hdr));
	memset(&stats_rsp, 0, sizeof (stats_rsp));
	memset(&stats_sys, 0, sizeof (stats_sys));

	hdr.len = AXA_H2P32(sizeof(axa_p_hdr_t) + stats_len);
	hdr.tag = AXA_H2P_TAG(0);
	hdr.pvers = AXA_P_PVERS;
	hdr.op = _AXA_P_OP_STATS_RSP;

	stats_rsp.version = _AXA_STATS_VERSION_ONE;
	stats_rsp.sys_objs_cnt = 1;
	stats_rsp.user_objs_cnt = 0;
	stats_rsp.result = AXA_P_STATS_R_SUCCESS;

	stats_sys.type = _AXA_P_STATS_TYPE_SYS;
	stats_sys.server_type = _AXA_STATS_SRVR_TYPE_SRA;
	stats_sys.load[0] = 6700;
	stats_sys.load[1] = 7900;
	stats_sys.load[2] = 8300;
	stats_sys.cpu_usage = 5144;
	stats_sys.uptime = 19287627;
	stats_sys.starttime = 19279187;
	stats_sys.fd_sockets = 13;
	stats_sys.fd_pipes = 3;
	stats_sys.fd_anon_inodes = 0;
	stats_sys.fd_other = 5;
	stats_sys.vmsize = 1428819968;
	stats_sys.vmrss = 21204992;
	stats_sys.rchar = 17362446;
	stats_sys.wchar = 755982917;
	stats_sys.thread_cnt = 145;
	stats_sys.user_cnt = 0;
	stats_sys.srvr.sra.watches.ipv4_cnt = 0;
	stats_sys.srvr.sra.watches.ipv6_cnt = 0;
	stats_sys.srvr.sra.watches.dns_cnt = 0;
	stats_sys.srvr.sra.watches.ch_cnt = 0;
	stats_sys.srvr.sra.watches.err_cnt = 0;
	axa_set_bitwords(stats_sys.srvr.sra.ch_mask.m, 213);
	axa_set_bitwords(stats_sys.srvr.sra.ch_mask.m, 255);

	memcpy((uint8_t *)stats, (uint8_t *)&stats_rsp, sizeof (stats_rsp));
	memcpy((uint8_t *)stats + sizeof (stats_rsp), (uint8_t *)&stats_sys,
			sizeof (stats_sys));

	res = axa_body_to_json(&emsg, nmsg_input, &hdr,
			(axa_p_body_t *)stats, stats_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_stats_rsp_rad_no_users)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"STATS RSP\",\"version\":1,\"result\":\"success\",\"load\":[6300,6200,7100],\"cpu_usage\":0,\"uptime\":19449048,\"starttime\":19373104,\"vmsize\":91680768,\"vmrss\":4968448,\"thread_cnt\":2,\"user_cnt\":0,\"server_type\":\"rad\",\"rad_anomaly_cnt\":0}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	_axa_p_stats_rsp_t stats_rsp;
	_axa_p_stats_sys_t stats_sys;
	size_t stats_len = sizeof (stats_rsp) + sizeof (stats_sys);
	uint8_t stats[stats_len];
	axa_json_res_t res;
	char *out = NULL;

	memset(&hdr, 0, sizeof (hdr));
	memset(&stats_rsp, 0, sizeof (stats_rsp));
	memset(&stats_sys, 0, sizeof (stats_sys));

	hdr.len = AXA_H2P32(sizeof(axa_p_hdr_t) + stats_len);
	hdr.tag = AXA_H2P_TAG(0);
	hdr.pvers = AXA_P_PVERS;
	hdr.op = _AXA_P_OP_STATS_RSP;

	stats_rsp.version = _AXA_STATS_VERSION_ONE;
	stats_rsp.sys_objs_cnt = 1;
	stats_rsp.user_objs_cnt = 0;
	stats_rsp.result = AXA_P_STATS_R_SUCCESS;

	stats_sys.type = _AXA_P_STATS_TYPE_SYS;
	stats_sys.server_type = _AXA_STATS_SRVR_TYPE_RAD;
	stats_sys.load[0] = 6300;
	stats_sys.load[1] = 6200;
	stats_sys.load[2] = 7100;
	stats_sys.cpu_usage = 0;
	stats_sys.uptime = 19449048;
	stats_sys.starttime = 19373104;
	stats_sys.vmsize = 91680768;
	stats_sys.vmrss = 4968448;
	stats_sys.thread_cnt = 2;
	stats_sys.user_cnt = 0;
	stats_sys.srvr.rad.an_cnt = 0;

	memcpy((uint8_t *)stats, (uint8_t *)&stats_rsp, sizeof (stats_rsp));
	memcpy((uint8_t *)stats + sizeof (stats_rsp), (uint8_t *)&stats_sys,
			sizeof (stats_sys));

	res = axa_body_to_json(&emsg, nmsg_input, &hdr,
			(axa_p_body_t *)stats, stats_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_kill_req)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"KILL REQ\",\"mode\":1,\"user\":\"wink\",\"sn\":0,\"result\":0}";
	axa_emsg_t emsg;
	axa_p_hdr_t hdr;
	_axa_p_kill_t kill;
	size_t kill_len = sizeof(_axa_p_kill_t);
	char *out = NULL;
	axa_json_res_t res;

	memset(&kill, 0, sizeof (kill));

	hdr.len = AXA_H2P32(sizeof(axa_p_hdr_t) + kill_len);
	hdr.tag = AXA_H2P_TAG(0);
	hdr.pvers = AXA_P_PVERS;
	hdr.op = _AXA_P_OP_KILL_REQ;

	kill.mode = AXA_P_KILL_M_SN;
	strcpy(kill.user.name, "wink");
	kill.sn = 0;

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t *)&kill,
			kill_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

START_TEST(test_kill_rsp)
{
	const char *expected = "{\"tag\":\"*\",\"op\":\"KILL RSP\",\"mode\":2,\"user\":\"wink\",\"sn\":10,\"result\":2}";
	axa_emsg_t emsg;
	_axa_p_kill_t kill;
	size_t kill_len = sizeof(_axa_p_kill_t);
	axa_p_hdr_t hdr;
	char *out = NULL;
	axa_json_res_t res;

	memset(&kill, 0, sizeof (kill));

	hdr.len = AXA_H2P32(sizeof(axa_p_hdr_t) + kill_len);
	hdr.tag = AXA_H2P_TAG(0);
	hdr.pvers = AXA_P_PVERS;
	hdr.op = _AXA_P_OP_KILL_RSP;

	kill.mode = AXA_P_KILL_M_U;
	strcpy(kill.user.name, "wink");
	kill.sn = 10;
	kill.result = AXA_P_KILL_R_FAIL_NF;

	res = axa_body_to_json(&emsg, nmsg_input, &hdr, (axa_p_body_t *)&kill,
			kill_len, &out);
	ck_assert_int_eq(res, AXA_JSON_RES_SUCCESS);
	ck_assert_str_eq(out, expected);
	free(out);
}
END_TEST

int main(void) {
	int number_failed;
	Suite *s;
	TCase *tc_core;
	SRunner *sr;

	if (nmsg_init() != nmsg_res_success) {
		fprintf (stderr, "unable to initialize libnmsg\n");
		return 1;
	}

	nmsg_input = nmsg_input_open_null();
	assert(nmsg_input != NULL);

	s = suite_create("axa_json");
	tc_core = tcase_create("core");
	tcase_add_test(tc_core, test_nop);
	tcase_add_test(tc_core, test_hello);
	tcase_add_test(tc_core, test_hello_empty);
	tcase_add_test(tc_core, test_hello_trunc);
	tcase_add_test(tc_core, test_ok);
	tcase_add_test(tc_core, test_ok_trunc);
	tcase_add_test(tc_core, test_error);
	tcase_add_test(tc_core, test_error_trunc);
	tcase_add_test(tc_core, test_missed);
	tcase_add_test(tc_core, test_missed_trunc);
	tcase_add_test(tc_core, test_missed_rad);
	tcase_add_test(tc_core, test_missed_rad_trunc);
	tcase_add_test(tc_core, test_whit_nmsg);
	tcase_add_test(tc_core, test_whit_nmsg_trunc);
	tcase_add_test(tc_core, test_whit_ip4_udp);
	tcase_add_test(tc_core, test_whit_ip4_tcp);
	tcase_add_test(tc_core, test_whit_ip4_trunc);
	tcase_add_test(tc_core, test_whit_ip6);
	tcase_add_test(tc_core, test_whit_ip6_trunc);
	tcase_add_test(tc_core, test_whit_trunc);
	tcase_add_test(tc_core, test_watch_ip4);
	tcase_add_test(tc_core, test_watch_ip4_trunc);
	tcase_add_test(tc_core, test_watch_ip4_overflow);
	tcase_add_test(tc_core, test_watch_ip6);
	tcase_add_test(tc_core, test_watch_dns);
	tcase_add_test(tc_core, test_watch_dns_wildcard);
	tcase_add_test(tc_core, test_watch_dns_wildcard_all);
	tcase_add_test(tc_core, test_watch_dns_shared);
	tcase_add_test(tc_core, test_watch_ch);
	tcase_add_test(tc_core, test_watch_errors);
	tcase_add_test(tc_core, test_watch_trunc);
	tcase_add_test(tc_core, test_anom);
	tcase_add_test(tc_core, test_anom_empty);
	tcase_add_test(tc_core, test_anom_trunc);
	tcase_add_test(tc_core, test_channel_on);
	tcase_add_test(tc_core, test_channel_off);
	tcase_add_test(tc_core, test_channel_all);
	tcase_add_test(tc_core, test_channel_trunc);
	tcase_add_test(tc_core, test_wlist);
	tcase_add_test(tc_core, test_wlist_trunc);
	tcase_add_test(tc_core, test_ahit);
	tcase_add_test(tc_core, test_ahit_trunc);
	tcase_add_test(tc_core, test_alist);
	tcase_add_test(tc_core, test_alist_trunc);
	tcase_add_test(tc_core, test_clist);
	tcase_add_test(tc_core, test_clist_trunc);
	tcase_add_test(tc_core, test_user);
	tcase_add_test(tc_core, test_user_trunc);
	tcase_add_test(tc_core, test_opt_trace);
	tcase_add_test(tc_core, test_opt_trace_req);
	tcase_add_test(tc_core, test_opt_rlimit_num);
	tcase_add_test(tc_core, test_opt_rlimit_max);
	tcase_add_test(tc_core, test_opt_rlimit_off);
	tcase_add_test(tc_core, test_opt_rlimit_na);
	tcase_add_test(tc_core, test_opt_sample);
	tcase_add_test(tc_core, test_opt_sndbuf);
	tcase_add_test(tc_core, test_opt_trunc);
	tcase_add_test(tc_core, test_join);
	tcase_add_test(tc_core, test_join_trunc);
	tcase_add_test(tc_core, test_pause);
	tcase_add_test(tc_core, test_go);
	tcase_add_test(tc_core, test_wget);
	tcase_add_test(tc_core, test_aget);
	tcase_add_test(tc_core, test_stop);
	tcase_add_test(tc_core, test_all_stop);
	tcase_add_test(tc_core, test_cget);
	tcase_add_test(tc_core, test_acct);
	tcase_add_test(tc_core, test_radu);
	tcase_add_test(tc_core, test_stats_req);
	tcase_add_test(tc_core, test_stats_rsp_sra_one_user);
	tcase_add_test(tc_core, test_stats_rsp_rad_one_user);
	tcase_add_test(tc_core, test_stats_rsp_rad_one_user_one_anomaly);
	tcase_add_test(tc_core, test_stats_rsp_sra_no_users);
	tcase_add_test(tc_core, test_stats_rsp_rad_no_users);
	tcase_add_test(tc_core, test_kill_req);
	tcase_add_test(tc_core, test_kill_rsp);
	suite_add_tcase(s, tc_core);

	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/*
 check_ip_helper.c - Unit tests for ip_helper.c

 Copyright (C) 2019-2026 Deltik <https://www.deltik.net/>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "ip_helper.h"

// Test convenience: check a textual IP address against the set
static bool is_ip_exempted(const char *ip_input, const ip_set *allowlist) {
    struct in6_addr ip_test;
    if (!parse_ip_address(ip_input, &ip_test)) return false;

    return ip_set_contains(allowlist, &ip_test);
}

// Print the ranges of an IP set (for debugging)
void ip_set_print(const ip_set *set) {
    printf("IP set (%zu ranges):\n", set->count);
    for (size_t i = 0; i < set->count; i++) {
        char start_str[INET6_ADDRSTRLEN];
        char end_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &set->ranges[i].start, start_str, sizeof(start_str));
        inet_ntop(AF_INET6, &set->ranges[i].end, end_str, sizeof(end_str));
        printf("  %s - %s\n", start_str, end_str);
    }
}

START_TEST(test_single_ip_allowlist) {
    ip_set *allowlist = ip_set_create();
    char input[] = "192.168.168.192";
    int rc = exempt_ip(allowlist, input);
    ck_assert_int_eq(0, rc);

    ck_assert(!is_ip_exempted("192.168.168.191", allowlist));
    ck_assert(is_ip_exempted("192.168.168.192", allowlist));
    ck_assert(!is_ip_exempted("192.168.168.193", allowlist));
}

START_TEST(test_single_cidr_allowlist) {
    ip_set *allowlist = ip_set_create();
    char input[] = "192.168.0.0/24";
    int rc = exempt_ip(allowlist, input);
    ck_assert_int_eq(0, rc);

    ck_assert(is_ip_exempted("192.168.0.0", allowlist));
    ck_assert(is_ip_exempted("192.168.0.1", allowlist));
    ck_assert(is_ip_exempted("192.168.0.123", allowlist));
    ck_assert(is_ip_exempted("192.168.0.254", allowlist));
    ck_assert(is_ip_exempted("192.168.0.255", allowlist));
    ck_assert(is_ip_exempted("::ffff:192.168.0.2", allowlist));
    ck_assert(is_ip_exempted("0:0:0:0:0:ffff:c0a8:a0", allowlist));

    ck_assert(!is_ip_exempted("::", allowlist));
    ck_assert(!is_ip_exempted("0.0.0.0", allowlist));
    ck_assert(!is_ip_exempted("192.167.255.255", allowlist));
    ck_assert(!is_ip_exempted("192.168.1.0", allowlist));
    ck_assert(!is_ip_exempted("192.168.1.255", allowlist));
    ck_assert(!is_ip_exempted("0:0:0:0:0:ffff:c0a8:ffff", allowlist));
}

END_TEST

START_TEST(test_single_range_allowlist) {
    ip_set *allowlist = ip_set_create();
    char input[] = "192.168.0.128-192.168.1.127";
    int rc = exempt_ip(allowlist, input);
    ck_assert_int_eq(0, rc);

    ck_assert(is_ip_exempted("192.168.0.128", allowlist));
    ck_assert(is_ip_exempted("192.168.0.255", allowlist));
    ck_assert(is_ip_exempted("192.168.1.0", allowlist));
    ck_assert(is_ip_exempted("192.168.1.127", allowlist));

    ck_assert(!is_ip_exempted("192.168.0.0", allowlist));
    ck_assert(!is_ip_exempted("192.168.0.127", allowlist));
    ck_assert(!is_ip_exempted("192.168.1.128", allowlist));
}

END_TEST

START_TEST(test_big_range_allowlist) {
    ip_set *allowlist = ip_set_create();
    char input[] = "0:0:0:0:0:0:0:0-2:2:2:2:2:2:2:2";
    int rc = exempt_ip(allowlist, input);
    ck_assert_int_eq(0, rc);

    ck_assert(is_ip_exempted("::", allowlist));
    ck_assert(is_ip_exempted("0:0:0:0:0:0:0:0", allowlist));
    ck_assert(is_ip_exempted("::1", allowlist));
    ck_assert(is_ip_exempted("10.0.0.0", allowlist));
    ck_assert(is_ip_exempted("::ffff:127.0.0.1", allowlist));
    ck_assert(is_ip_exempted("172.16.0.0", allowlist));
    ck_assert(is_ip_exempted("192.167.0.0", allowlist));
    ck_assert(is_ip_exempted("1:1:1:1:1:1:1:1", allowlist));
    ck_assert(is_ip_exempted("1:ffff:ffff:ffff:ffff:ffff:ffff:ffff", allowlist));
    ck_assert(is_ip_exempted("2:2:2:2:2:2:2:2", allowlist));

    ck_assert(!is_ip_exempted("2:2:2:2:2:2:2:3", allowlist));
    ck_assert(!is_ip_exempted("2:2:2:f:2:2:2:2", allowlist));
    ck_assert(!is_ip_exempted("3::", allowlist));
    ck_assert(!is_ip_exempted("fe80::", allowlist));
}

END_TEST

START_TEST(test_multiple_allowlist) {
    ip_set *allowlist = ip_set_create();
    char input[INET6_ADDRSTRLEN];
    strcpy(input, "10.0.0.0/8");
    exempt_ip(allowlist, input);
    strcpy(input, "172.16.0.0/12");
    exempt_ip(allowlist, input);
    strcpy(input, "192.168.0.0/16");
    exempt_ip(allowlist, input);
    strcpy(input, "fd00::/8");
    exempt_ip(allowlist, input);

    ck_assert(is_ip_exempted("10.10.145.62", allowlist));
    ck_assert(is_ip_exempted("172.20.7.24", allowlist));
    ck_assert(is_ip_exempted("192.168.1.6", allowlist));
    ck_assert(is_ip_exempted("fddf::1234:5678", allowlist));

    ck_assert(!is_ip_exempted("::53", allowlist));
    ck_assert(!is_ip_exempted("127.0.0.53", allowlist));
    ck_assert(!is_ip_exempted("169.254.0.0", allowlist));
    ck_assert(!is_ip_exempted("fe80::", allowlist));
}

END_TEST

START_TEST(test_for_bugs_in_fill_between_logic) {
    ip_set *allowlist = ip_set_create();
    char input[INET6_ADDRSTRLEN];
    strcpy(input, "ffff:fffe::-ffff:ffff::");
    exempt_ip(allowlist, input);

    ck_assert(is_ip_exempted("ffff:fffe::", allowlist));
    ck_assert(is_ip_exempted("ffff:fffe:ffff:ffff:ffff:ffff:ffff:ffff", allowlist));
    ck_assert(is_ip_exempted("ffff:ffff:0:0:0:0:0:0", allowlist));

    ck_assert(!is_ip_exempted("ffff:fffd:ffff:ffff:ffff:ffff:ffff:ffff", allowlist));
    ck_assert(!is_ip_exempted("ffff:ffff:0:0:0:0:0:1", allowlist));

    strcpy(input, "0:1:0:0::-0:1:0:2::");
    exempt_ip(allowlist, input);

    ck_assert(is_ip_exempted("0:1:0:0::", allowlist));
    ck_assert(is_ip_exempted("0:1:0:1::", allowlist));
    ck_assert(is_ip_exempted("0:1:0:1:ffff:ffff:ffff:ffff", allowlist));
    ck_assert(is_ip_exempted("0:1:0:2::", allowlist));

    ck_assert(!is_ip_exempted("0:0:ffff:ffff:ffff:ffff:ffff:ffff", allowlist));
    ck_assert(!is_ip_exempted("0:1:0:2::1", allowlist));
}

END_TEST

// https://github.com/Deltik/mod_antiloris/issues/4
START_TEST(test_double_split_bug) {
    ip_set *allowlist = ip_set_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "127.0.0.1"));
    ck_assert_int_eq(0, exempt_ip(allowlist, "::1"));
    ck_assert_int_eq(0, exempt_ip(allowlist, "10.64.229.0/24"));

    ck_assert(is_ip_exempted("127.0.0.1", allowlist));
    ck_assert(is_ip_exempted("::1", allowlist));
    ck_assert(is_ip_exempted("10.64.229.1", allowlist));
}

END_TEST

START_TEST(test_insert_more_specific_prefix) {
    ip_set *allowlist = ip_set_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "127.0.0.0/24"));
    ck_assert(is_ip_exempted("127.0.0.1", allowlist));
    ck_assert(!is_ip_exempted("127.0.1.1", allowlist));

    ck_assert_int_eq(0, exempt_ip(allowlist, "127.0.0.0/29"));
    ck_assert(is_ip_exempted("127.0.0.1", allowlist));
    ck_assert(is_ip_exempted("127.0.0.255", allowlist));
    ck_assert(!is_ip_exempted("127.0.1.255", allowlist));
}

END_TEST

START_TEST(test_insert_less_specific_prefix) {
    ip_set *allowlist = ip_set_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "127.0.0.0/24"));
    ck_assert(is_ip_exempted("127.0.0.1", allowlist));
    ck_assert(is_ip_exempted("127.0.0.255", allowlist));
    ck_assert(!is_ip_exempted("127.0.1.255", allowlist));

    ck_assert_int_eq(0, exempt_ip(allowlist, "127.0.0.0/16"));
    ck_assert(is_ip_exempted("127.0.0.1", allowlist));
    ck_assert(is_ip_exempted("127.0.0.255", allowlist));
    ck_assert(is_ip_exempted("127.0.1.255", allowlist));
}

END_TEST

START_TEST(test_same_prefix_different_range) {
    ip_set *allowlist = ip_set_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "127.0.0.0/16"));
    ck_assert_int_eq(0, exempt_ip(allowlist, "127.255.0.0/16"));

    ck_assert(is_ip_exempted("127.0.0.1", allowlist));
    ck_assert(is_ip_exempted("127.0.0.255", allowlist));
    ck_assert(!is_ip_exempted("127.1.1.1", allowlist));
    ck_assert(!is_ip_exempted("127.254.255.0", allowlist));
    ck_assert(is_ip_exempted("127.255.0.128", allowlist));
}

END_TEST

START_TEST(test_partially_overlapping_range) {
    ip_set *allowlist = ip_set_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "1.1.1.1-1.1.1.4"));
    ck_assert_int_eq(0, exempt_ip(allowlist, "1.1.1.3-1.1.1.6"));

    ck_assert(!is_ip_exempted("1.1.1.0", allowlist));
    ck_assert(is_ip_exempted("1.1.1.1", allowlist));
    ck_assert(is_ip_exempted("1.1.1.3", allowlist));
    ck_assert(is_ip_exempted("1.1.1.4", allowlist));
    ck_assert(is_ip_exempted("1.1.1.6", allowlist));
    ck_assert(!is_ip_exempted("1.1.1.7", allowlist));
}

END_TEST

// Regression: a covering prefix used to be silently dropped when it
// coincided with an internal split node of the former PATRICIA trie
START_TEST(test_covering_prefix_inserted_after_narrower_prefixes) {
    ip_set *allowlist = ip_set_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "1.2.3.0/26"));
    ck_assert_int_eq(0, exempt_ip(allowlist, "1.2.3.192/26"));
    ck_assert_int_eq(0, exempt_ip(allowlist, "1.2.3.0/24"));

    ck_assert(is_ip_exempted("1.2.3.1", allowlist));
    ck_assert(is_ip_exempted("1.2.3.64", allowlist));
    ck_assert(is_ip_exempted("1.2.3.130", allowlist));
    ck_assert(is_ip_exempted("1.2.3.255", allowlist));

    ck_assert(!is_ip_exempted("1.2.2.255", allowlist));
    ck_assert(!is_ip_exempted("1.2.4.0", allowlist));
    ip_set_free(allowlist);
}

END_TEST

// Regression: ranges reaching the all-ones address used to loop forever
START_TEST(test_range_reaching_maximum_address) {
    ip_set *allowlist = ip_set_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "ffff::/16"));
    ck_assert(is_ip_exempted("ffff::1", allowlist));
    ck_assert(is_ip_exempted("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", allowlist));
    ck_assert(!is_ip_exempted("fffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", allowlist));
    ip_set_free(allowlist);

    allowlist = ip_set_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "::/0"));
    ck_assert(is_ip_exempted("::", allowlist));
    ck_assert(is_ip_exempted("192.0.2.1", allowlist));
    ck_assert(is_ip_exempted("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", allowlist));
    ip_set_free(allowlist);

    allowlist = ip_set_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "8000::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    ck_assert(is_ip_exempted("9000::", allowlist));
    ck_assert(is_ip_exempted("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", allowlist));
    ck_assert(!is_ip_exempted("7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", allowlist));
    ip_set_free(allowlist);
}

END_TEST

// Regression: malformed CIDR suffixes used to be accepted by strtoul()
START_TEST(test_invalid_cidr_inputs) {
    ip_set *allowlist = ip_set_create();
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_CIDR, exempt_ip(allowlist, "0.0.0.0/256"));
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_CIDR, exempt_ip(allowlist, "::/384"));
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_CIDR, exempt_ip(allowlist, "::/24junk"));
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_CIDR, exempt_ip(allowlist, "::/129"));
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_CIDR, exempt_ip(allowlist, "1.2.3.4/33"));
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_CIDR, exempt_ip(allowlist, "1.2.3.0/"));
    // A hyphen routes to the range parser, so a negative CIDR is a parse error
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_PARSE, exempt_ip(allowlist, "1.2.3.0/-24"));
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_CIDR, exempt_ip(allowlist, "1.2.3.0/+24"));
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_PARSE, exempt_ip(allowlist, "/24"));
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_PARSE, exempt_ip(allowlist, "notanip"));
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_IN_NETMASK, exempt_ip(allowlist, "1.2.3.5/30"));
    ck_assert_int_eq(ANTILORIS_CONFIG_ERROR_IP_RANGE_ORDER, exempt_ip(allowlist, "9.9.9.9-1.1.1.1"));

    // Nothing invalid should have been added
    ck_assert_uint_eq(0, allowlist->count);
    ck_assert(!is_ip_exempted("1.2.3.4", allowlist));
    ck_assert(!is_ip_exempted("0.0.0.0", allowlist));
    ip_set_free(allowlist);
}

END_TEST

START_TEST(test_adjacent_and_overlapping_ranges_merge) {
    ip_set *allowlist = ip_set_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "10.0.0.10-10.0.0.19"));
    ck_assert_int_eq(0, exempt_ip(allowlist, "10.0.0.20-10.0.0.29")); // adjacent
    ck_assert_int_eq(0, exempt_ip(allowlist, "10.0.0.5-10.0.0.14"));  // overlapping
    ck_assert_int_eq(0, exempt_ip(allowlist, "10.0.0.0-10.0.0.35"));  // covers all

    ck_assert_uint_eq(1, allowlist->count);
    for (int i = 0; i <= 35; i++) {
        char query[INET6_ADDRSTRLEN];
        snprintf(query, sizeof(query), "10.0.0.%d", i);
        ck_assert(is_ip_exempted(query, allowlist));
    }
    ck_assert(!is_ip_exempted("10.0.0.36", allowlist));
    ck_assert(!is_ip_exempted("9.255.255.255", allowlist));
    ip_set_free(allowlist);
}

END_TEST

Suite *playground_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Playground");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_single_ip_allowlist);
    tcase_add_test(tc_core, test_single_cidr_allowlist);
    tcase_add_test(tc_core, test_single_range_allowlist);
    tcase_add_test(tc_core, test_big_range_allowlist);
    tcase_add_test(tc_core, test_multiple_allowlist);
    tcase_add_test(tc_core, test_for_bugs_in_fill_between_logic);
    tcase_add_test(tc_core, test_double_split_bug);
    tcase_add_test(tc_core, test_insert_more_specific_prefix);
    tcase_add_test(tc_core, test_insert_less_specific_prefix);
    tcase_add_test(tc_core, test_same_prefix_different_range);
    tcase_add_test(tc_core, test_partially_overlapping_range);
    tcase_add_test(tc_core, test_covering_prefix_inserted_after_narrower_prefixes);
    tcase_add_test(tc_core, test_range_reaching_maximum_address);
    tcase_add_test(tc_core, test_invalid_cidr_inputs);
    tcase_add_test(tc_core, test_adjacent_and_overlapping_ranges_merge);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int failed_test_count;
    Suite *suite;
    SRunner *suite_runner;

    suite = playground_suite();
    suite_runner = srunner_create(suite);
    srunner_set_fork_status(suite_runner, CK_NOFORK);

    srunner_run_all(suite_runner, CK_NORMAL);
    failed_test_count = srunner_ntests_failed(suite_runner);
    srunner_free(suite_runner);
    return (failed_test_count == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


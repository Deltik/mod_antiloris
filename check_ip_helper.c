/*
   check_ip_helper.c
   Copyright (C) 2019 Deltik

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

apr_pool_t *apr_pool;

START_TEST(test_single_ip_whitelist) {
    struct flexmap *whitelist = create_flexmap(apr_pool);
    char input[] = "192.168.168.192";
    int rc = whitelist_ip(whitelist, input);
    ck_assert_int_eq(0, rc);

    ck_assert(!is_ip_whitelisted("192.168.168.191", whitelist));
    ck_assert(is_ip_whitelisted("192.168.168.192", whitelist));
    ck_assert(!is_ip_whitelisted("192.168.168.193", whitelist));
}

START_TEST(test_single_cidr_whitelist) {
    struct flexmap *whitelist = create_flexmap(apr_pool);
    char input[] = "192.168.0.0/24";
    int rc = whitelist_ip(whitelist, input);
    ck_assert_int_eq(0, rc);

    ck_assert(is_ip_whitelisted("192.168.0.0", whitelist));
    ck_assert(is_ip_whitelisted("192.168.0.1", whitelist));
    ck_assert(is_ip_whitelisted("192.168.0.123", whitelist));
    ck_assert(is_ip_whitelisted("192.168.0.254", whitelist));
    ck_assert(is_ip_whitelisted("192.168.0.255", whitelist));
    ck_assert(is_ip_whitelisted("::ffff:192.168.0.2", whitelist));
    ck_assert(is_ip_whitelisted("0:0:0:0:0:ffff:c0a8:a0", whitelist));

    ck_assert(!is_ip_whitelisted("::", whitelist));
    ck_assert(!is_ip_whitelisted("0.0.0.0", whitelist));
    ck_assert(!is_ip_whitelisted("192.167.255.255", whitelist));
    ck_assert(!is_ip_whitelisted("192.168.1.0", whitelist));
    ck_assert(!is_ip_whitelisted("192.168.1.255", whitelist));
    ck_assert(!is_ip_whitelisted("0:0:0:0:0:ffff:c0a8:ffff", whitelist));
}

END_TEST

START_TEST(test_single_range_whitelist) {
    struct flexmap *whitelist = create_flexmap(apr_pool);
    char input[] = "192.168.0.128-192.168.1.127";
    int rc = whitelist_ip(whitelist, input);
    ck_assert_int_eq(0, rc);

    ck_assert(is_ip_whitelisted("192.168.0.128", whitelist));
    ck_assert(is_ip_whitelisted("192.168.0.255", whitelist));
    ck_assert(is_ip_whitelisted("192.168.1.0", whitelist));
    ck_assert(is_ip_whitelisted("192.168.1.127", whitelist));

    ck_assert(!is_ip_whitelisted("192.168.0.0", whitelist));
    ck_assert(!is_ip_whitelisted("192.168.0.127", whitelist));
    ck_assert(!is_ip_whitelisted("192.168.1.128", whitelist));
}

END_TEST

START_TEST(test_big_range_whitelist) {
    struct flexmap *whitelist = create_flexmap(apr_pool);
    char input[] = "0:0:0:0:0:0:0:0-2:2:2:2:2:2:2:2";
    int rc = whitelist_ip(whitelist, input);
    ck_assert_int_eq(0, rc);

    ck_assert(is_ip_whitelisted("::", whitelist));
    ck_assert(is_ip_whitelisted("0:0:0:0:0:0:0:0", whitelist));
    ck_assert(is_ip_whitelisted("::1", whitelist));
    ck_assert(is_ip_whitelisted("10.0.0.0", whitelist));
    ck_assert(is_ip_whitelisted("::ffff:127.0.0.1", whitelist));
    ck_assert(is_ip_whitelisted("172.16.0.0", whitelist));
    ck_assert(is_ip_whitelisted("192.167.0.0", whitelist));
    ck_assert(is_ip_whitelisted("1:1:1:1:1:1:1:1", whitelist));
    ck_assert(is_ip_whitelisted("1:ffff:ffff:ffff:ffff:ffff:ffff:ffff", whitelist));
    ck_assert(is_ip_whitelisted("2:2:2:2:2:2:2:2", whitelist));

    ck_assert(!is_ip_whitelisted("2:2:2:2:2:2:2:3", whitelist));
    ck_assert(!is_ip_whitelisted("2:2:2:f:2:2:2:2", whitelist));
    ck_assert(!is_ip_whitelisted("3::", whitelist));
    ck_assert(!is_ip_whitelisted("fe80::", whitelist));
}

END_TEST

START_TEST(test_multiple_whitelist) {
    struct flexmap *whitelist = create_flexmap(apr_pool);
    char input[INET6_ADDRSTRLEN];
    strcpy(input, "10.0.0.0/8");
    whitelist_ip(whitelist, input);
    strcpy(input, "172.16.0.0/12");
    whitelist_ip(whitelist, input);
    strcpy(input, "192.168.0.0/16");
    whitelist_ip(whitelist, input);
    strcpy(input, "fd00::/8");
    whitelist_ip(whitelist, input);

    ck_assert(is_ip_whitelisted("10.10.145.62", whitelist));
    ck_assert(is_ip_whitelisted("172.20.7.24", whitelist));
    ck_assert(is_ip_whitelisted("192.168.1.6", whitelist));
    ck_assert(is_ip_whitelisted("fddf::1234:5678", whitelist));

    ck_assert(!is_ip_whitelisted("::53", whitelist));
    ck_assert(!is_ip_whitelisted("127.0.0.53", whitelist));
    ck_assert(!is_ip_whitelisted("169.254.0.0", whitelist));
    ck_assert(!is_ip_whitelisted("fe80::", whitelist));
}

END_TEST

START_TEST(test_for_bugs_in_fill_between_logic) {
    struct flexmap *whitelist = create_flexmap(apr_pool);
    char input[INET6_ADDRSTRLEN];
    strcpy(input, "ffff:fffe::-ffff:ffff::");
    whitelist_ip(whitelist, input);

    ck_assert(is_ip_whitelisted("ffff:fffe::", whitelist));
    ck_assert(is_ip_whitelisted("ffff:fffe:ffff:ffff:ffff:ffff:ffff:ffff", whitelist));
    ck_assert(is_ip_whitelisted("ffff:ffff:0:0:0:0:0:0", whitelist));

    ck_assert(!is_ip_whitelisted("ffff:fffd:ffff:ffff:ffff:ffff:ffff:ffff", whitelist));
    ck_assert(!is_ip_whitelisted("ffff:ffff:0:0:0:0:0:1", whitelist));

    strcpy(input, "0:1:0:0::-0:1:0:2::");
    whitelist_ip(whitelist, input);

    ck_assert(is_ip_whitelisted("0:1:0:0::", whitelist));
    ck_assert(is_ip_whitelisted("0:1:0:1::", whitelist));
    ck_assert(is_ip_whitelisted("0:1:0:1:ffff:ffff:ffff:ffff", whitelist));
    ck_assert(is_ip_whitelisted("0:1:0:2::", whitelist));

    ck_assert(!is_ip_whitelisted("0:0:ffff:ffff:ffff:ffff:ffff:ffff", whitelist));
    ck_assert(!is_ip_whitelisted("0:1:0:2::1", whitelist));
}

END_TEST

Suite *playground_suite(void) {
    apr_initialize();
    apr_pool_create(&apr_pool, NULL);

    Suite *s;
    TCase *tc_core;

    s = suite_create("Playground");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_single_ip_whitelist);
    tcase_add_test(tc_core, test_single_cidr_whitelist);
    tcase_add_test(tc_core, test_single_range_whitelist);
    tcase_add_test(tc_core, test_big_range_whitelist);
    tcase_add_test(tc_core, test_multiple_whitelist);
    tcase_add_test(tc_core, test_for_bugs_in_fill_between_logic);
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


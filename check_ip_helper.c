/*
 check_ip_helper.c - Unit tests for ip_helper.c

 Copyright (C) 2019-2024 Deltik <https://www.deltik.net/>

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

// Function to print the tree starting from a given node
void patricia_print_tree(patricia_node *node, int level) {
    if (node == NULL)
        return;

    // Indentation for the current level
    for (int i = 0; i < level; i++) {
        printf("  ");
    }

    // Convert the IP address to a string
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &node->ip, ip_str, sizeof(ip_str));

    // Print the node's IP and prefix length
    printf("%s/%d\n", ip_str, node->prefix_len);

    // Recursively print the left and right subtrees
    patricia_print_tree(node->left, level + 1);
    patricia_print_tree(node->right, level + 1);
}

// Wrapper function to print the entire trie
void patricia_print(patricia_trie *trie) {
    printf("Patricia Trie:\n");
    patricia_print_tree(trie->root, 0);
}

START_TEST(test_single_ip_allowlist) {
    patricia_trie *allowlist = patricia_create();
    char input[] = "192.168.168.192";
    int rc = exempt_ip(allowlist, input);
    ck_assert_int_eq(0, rc);

    ck_assert(!is_ip_exempted("192.168.168.191", allowlist));
    ck_assert(is_ip_exempted("192.168.168.192", allowlist));
    ck_assert(!is_ip_exempted("192.168.168.193", allowlist));
}

START_TEST(test_single_cidr_allowlist) {
    patricia_trie *allowlist = patricia_create();
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
    patricia_trie *allowlist = patricia_create();
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
    patricia_trie *allowlist = patricia_create();
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
    patricia_trie *allowlist = patricia_create();
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
    patricia_trie *allowlist = patricia_create();
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
    patricia_trie *allowlist = patricia_create();
    ck_assert_int_eq(0, exempt_ip(allowlist, "127.0.0.1"));
    ck_assert_int_eq(0, exempt_ip(allowlist, "::1"));
    ck_assert_int_eq(0, exempt_ip(allowlist, "10.64.229.0/24"));

    ck_assert(is_ip_exempted("127.0.0.1", allowlist));
    ck_assert(is_ip_exempted("::1", allowlist));
    ck_assert(is_ip_exempted("10.64.229.1", allowlist));
}

END_TEST

START_TEST(test_insert_more_specific_prefix) {
    patricia_trie *allowlist = patricia_create();
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
    patricia_trie *allowlist = patricia_create();
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
    patricia_trie *allowlist = patricia_create();
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
    patricia_trie *allowlist = patricia_create();
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


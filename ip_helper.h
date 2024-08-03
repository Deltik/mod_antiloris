/*
 ip_helper.h - IP range ignore list implementation using a PATRICIA trie

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

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ANTILORIS_IP_HELPER_H

#define ANTILORIS_CONFIG_ERROR_IP_PARSE 255
#define ANTILORIS_CONFIG_ERROR_IP_CIDR 254
#define ANTILORIS_CONFIG_ERROR_IP_IN_NETMASK 253
#define ANTILORIS_CONFIG_ERROR_IP_RANGE_ORDER 252

/**
 * A PATRICIA trie node. Hard-coded to support 128-bit IP addresses.
 */
typedef struct patricia_node {
    struct patricia_node *left, *right;
    struct in6_addr ip;
    int prefix_len;
} patricia_node;

/**
 * A PATRICIA trie
 */
typedef struct {
    patricia_node *root;
} patricia_trie;

/**
 * Allocates a new PATRICIA trie
 */
patricia_trie* patricia_create();

/**
 * Free a PATRICIA trie node and all of its children
 * @param node The node to free
 */
void patricia_free_node(patricia_node *node);

/**
 * Free a PATRICIA trie from the root node
 * @param trie The trie to free
 */
void patricia_free(patricia_trie *trie);

/**
 * Insert an IP address of a given prefix length into the PATRICIA trie
 * @param trie The trie to insert into
 * @param ip The IP address to insert
 * @param prefix_len The prefix length of the IP address
 */
void patricia_insert(patricia_trie *trie, struct in6_addr ip, int prefix_len);

/**
 * Check if an IP address is in the PATRICIA trie
 * @param trie The trie to check
 * @param ip The IP address to check
 * @return 1 if the IP address is in the trie, 0 if not
 */
int patricia_contains(patricia_trie *trie, struct in6_addr ip);

int bit_at(const struct in6_addr *ip, int bit);

void insert_range(patricia_trie *trie, struct in6_addr start, struct in6_addr end);

/**
 * Adds the IP address, IP address range, or a CIDR range to the PATRICIA trie
 * @param allowlist The PATRICIA trie to add to
 * @param input A single IP address with an optional CIDR suffix or a hyphenated IP address range. Can be IPv4 or IPv6.
 * @return 0 if successful, error code if not successful
 */
int exempt_ip(patricia_trie *allowlist, char *input);

/**
 * Check if the IP address is present in the PATRICIA trie
 * @param ip_input A single IPv4 or IPv6 address
 * @param allowlist The PATRICIA trie to check
 * @return true if the provided IP address is present in the PATRICIA trie, false if not
 */
bool is_ip_exempted(char *ip_input, patricia_trie *allowlist);

#define ANTILORIS_IP_HELPER_H

#endif //ANTILORIS_IP_HELPER_H

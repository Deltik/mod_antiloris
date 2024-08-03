/*
 ip_helper.c - IP range ignore list implementation using a PATRICIA trie

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

#include "ip_helper.h"

patricia_trie *patricia_create() {
    patricia_trie *trie = malloc(sizeof(patricia_trie));
    trie->root = NULL;
    return trie;
}

void patricia_free_node(patricia_node *node) {
    if (node) {
        patricia_free_node(node->left);
        patricia_free_node(node->right);
        free(node);
    }
}

void patricia_free(patricia_trie *trie) {
    if (trie == NULL) return;

    patricia_free_node(trie->root);
    free(trie);
}

int bit_at(const struct in6_addr *ip, int bit) {
    return (int) (ntohl(ip->s6_addr32[bit / 32]) >> (31 - bit % 32)) & 1;
}

int count_common_prefix_bits(const struct in6_addr *ip1, const struct in6_addr *ip2, int max_len) {
    int common_bits = 0;
    int max_bits = max_len < 128 ? max_len : 128;

    for (int word = 0; word < sizeof(struct in6_addr) / sizeof(uint32_t) && common_bits < max_bits; word++) {
        uint32_t ip_xor = ntohl((*ip1).s6_addr32[word] ^ (*ip2).s6_addr32[word]);
        if (ip_xor == 0) {
            common_bits += 32;
        } else {
            common_bits += __builtin_clz(ip_xor);
            break;
        }
    }

    return common_bits > max_bits ? max_bits : common_bits;
}

void patricia_insert(patricia_trie *trie, struct in6_addr ip, int prefix_len) {
    patricia_node **node = &trie->root;

    if (*node == NULL) {
        patricia_node *new_node = malloc(sizeof(patricia_node));
        new_node->ip = ip;  // Copy IP address
        new_node->prefix_len = prefix_len;
        new_node->left = new_node->right = NULL;
        *node = new_node;
        return;
    }

    while (true) {
        int common_leading_bits = count_common_prefix_bits(&(*node)->ip, &ip, prefix_len);
        // Check if same IP range is already inserted
        if (common_leading_bits == prefix_len) {
            return;
        }
        if ((*node)->prefix_len < common_leading_bits) {
            // Check if new IP range is fully within an existing IP range
            if ((*node)->left == NULL && (*node)->right == NULL) {
                return;
            }
            bool next_bit = bit_at(&ip, common_leading_bits + 1);
            node = next_bit ? &(*node)->right : &(*node)->left;
            // Descend the tree
            if (*node != NULL) continue;
            // Insert the new node
            patricia_node *new_node = malloc(sizeof(patricia_node));
            new_node->ip = ip;
            new_node->prefix_len = prefix_len;
            new_node->left = new_node->right = NULL;
            *node = new_node;
            return;
        }
        // Check if new IP range encompasses an existing IP range
        if (prefix_len < common_leading_bits) {
            patricia_free_node((*node)->left);
            patricia_free_node((*node)->right);
            (*node)->left = (*node)->right = NULL;
            (*node)->prefix_len = common_leading_bits;
            return;
        }
        // Descend the tree if a node exists
        if (common_leading_bits == (*node)->prefix_len) {
            bool next_bit = bit_at(&ip, common_leading_bits);
            patricia_node **next_node = next_bit ? &(*node)->right : &(*node)->left;
            if (*next_node != NULL) {
                node = next_node;
                continue;
            }
        }
        // Split the existing node
        patricia_node *split_node = malloc(sizeof(patricia_node));
        memcpy(split_node, *node, sizeof(patricia_node));
        (*node)->prefix_len = common_leading_bits;
        bool new_bit = bit_at(&ip, common_leading_bits);
        patricia_node *new_node = malloc(sizeof(patricia_node));
        new_node->ip = ip;
        new_node->prefix_len = prefix_len;
        new_node->left = new_node->right = NULL;
        if (new_bit == 0) {
            (*node)->left = new_node;
            (*node)->right = split_node;
        } else {
            (*node)->right = new_node;
            (*node)->left = split_node;
        }
        return;
    }
}

int patricia_contains(patricia_trie *trie, struct in6_addr ip) {
    patricia_node **node = &trie->root;

    while (*node) {
        if ((*node)->left == NULL && (*node)->right == NULL) {
            return count_common_prefix_bits(&(*node)->ip, &ip, (*node)->prefix_len) >=
                   (*node)->prefix_len; // IP found or not
        }

        if (bit_at(&ip, (*node)->prefix_len)) {
            node = &(*node)->right;
        } else {
            node = &(*node)->left;
        }
    }

    return 0;  // IP not found
}

struct in6_addr sum_in6_addr(const struct in6_addr *addr1, const struct in6_addr *addr2) {
    struct in6_addr result;
    uint32_t carry = 0;
    for (int i = sizeof(struct in6_addr) / sizeof(uint32_t) - 1; i >= 0; i--) {
        uint32_t addr1_host_order = ntohl(*((uint32_t *) addr1->s6_addr32 + i));
        uint32_t addr2_host_order = ntohl(*((uint32_t *) addr2->s6_addr32 + i));
        uint64_t sum = (uint64_t) addr1_host_order + addr2_host_order + carry;
        *((uint32_t *) result.s6_addr32 + i) = htonl((uint32_t) sum);
        carry = sum >> 32;
    }
    return result;
}

struct in6_addr prefix_length_to_mask(int prefix_length) {
    struct in6_addr mask = {.s6_addr32 = {0, 0, 0, 0}};

    if (prefix_length < 0 || prefix_length > 128) {
        // Return all zeros if prefix_length is out of range
        memset(&mask, 0, sizeof(mask));
        return mask;
    }

    // Fill the mask bits gradually
    int remaining_bits = 128 - prefix_length;
    for (int i = sizeof(struct in6_addr) / sizeof(uint32_t) - 1; i >= 0; i--) {
        if (remaining_bits >= 32) {
            mask.s6_addr32[i] = 0xFFFFFFFF; // All bits set
            remaining_bits -= 32;
        } else if (remaining_bits > 0) {
            mask.s6_addr32[i] = htonl((1 << remaining_bits) - 1);
            remaining_bits = 0;
        } else {
            mask.s6_addr32[i] = 0;
        }
    }

    return mask;
}

void apply_mask(struct in6_addr *ip, struct in6_addr mask) {
    for (int i = 0; i < sizeof(struct in6_addr) / sizeof(uint32_t); i++) {
        *((uint32_t *) ip->s6_addr32 + i) &= ~*((uint32_t *) mask.s6_addr32 + i);
    }
}

void insert_range(patricia_trie *trie, struct in6_addr start, struct in6_addr end) {
    struct in6_addr ip = start;
    while (memcmp(&ip, &end, sizeof(struct in6_addr)) <= 0) {
        int prefix_length = 128;

        // Determine the size of the largest block
        while (prefix_length > 0) {
            struct in6_addr mask = prefix_length_to_mask(prefix_length);
            struct in6_addr tmp_ip;
            for (int i = 0; i < sizeof(struct in6_addr) / sizeof(uint32_t); i++) {
                *((uint32_t *) tmp_ip.s6_addr32 + i) =
                        *((uint32_t *) ip.s6_addr32 + i) & ~*((uint32_t *) mask.s6_addr32 + i);
            }
            if (memcmp(&tmp_ip, &ip, sizeof(struct in6_addr)) != 0) {
                prefix_length++;
                break;
            }
            memcpy(&tmp_ip, &ip, sizeof(struct in6_addr));
            for (int i = 0; i < sizeof(struct in6_addr) / sizeof(uint32_t); i++) {
                *((uint32_t *) tmp_ip.s6_addr32 + i) |= *((uint32_t *) mask.s6_addr32 + i);
            }
            if (memcmp(&tmp_ip, &end, sizeof(struct in6_addr)) > 0) {
                prefix_length++;
                break;
            }
            prefix_length--;
        }

        patricia_insert(trie, ip, prefix_length);

        // Move to the next block
        struct in6_addr mask = prefix_length_to_mask(prefix_length);
        struct in6_addr one = {.s6_addr32 = {0, 0, 0, htonl(1)}};
        struct in6_addr addend = sum_in6_addr(&mask, &one);
        apply_mask(&ip, mask);
        struct in6_addr next_addr = sum_in6_addr(&ip, &addend);
        memcpy(&ip, &next_addr, sizeof(struct in6_addr));
    }
}

bool auto_convert_ipv4_to_ipv6(char *input_ip) {
    if (strstr(input_ip, ":") == NULL) {
        char ipv4_to_ipv6_mapper[] = "::ffff:";
        memmove(input_ip + strlen(ipv4_to_ipv6_mapper),
                input_ip,
                INET6_ADDRSTRLEN - strlen(ipv4_to_ipv6_mapper) - 1);
        memmove(input_ip, ipv4_to_ipv6_mapper, strlen(ipv4_to_ipv6_mapper));
        return true;
    }
    return false;
}

bool parse_ipv6_address(char *input, struct in6_addr *dest) {
    return inet_pton(AF_INET6, input, dest) == 1;
}

int parse_ip_range_hyphenated(char *input, struct in6_addr *ip_lower, struct in6_addr *ip_upper) {
    char input_ip_lower[INET6_ADDRSTRLEN];
    strncpy(input_ip_lower, strtok(input, "-"), INET6_ADDRSTRLEN - 1);
    char input_ip_upper[INET6_ADDRSTRLEN];
    strncpy(input_ip_upper, strtok(NULL, "-"), INET6_ADDRSTRLEN - 1);

    auto_convert_ipv4_to_ipv6(input_ip_lower);
    if (!parse_ipv6_address(input_ip_lower, ip_lower)) return ANTILORIS_CONFIG_ERROR_IP_PARSE;

    auto_convert_ipv4_to_ipv6(input_ip_upper);
    if (!parse_ipv6_address(input_ip_upper, ip_upper)) return ANTILORIS_CONFIG_ERROR_IP_PARSE;

    return 0;
}

int parse_ip_range_cidr(char *input, struct in6_addr *ip_lower, struct in6_addr *ip_upper) {
    bool converted_to_ipv6;
    char input_ip_lower[INET6_ADDRSTRLEN];
    strncpy(input_ip_lower, strtok(input, "/"), INET6_ADDRSTRLEN - 1);
    char *input_cidr = strtok(NULL, "/");
    uint8_t raw_cidr = 128;

    // Set CIDR if input contains CIDR
    if (input_cidr != NULL) {
        raw_cidr = strtoul(input_cidr, NULL, 10);
    }

    // Convert IPv4 to IPv4-mapped IPv6
    converted_to_ipv6 = auto_convert_ipv4_to_ipv6(input_ip_lower);
    if (converted_to_ipv6) {
        if (input_cidr == NULL) raw_cidr = 32;

        // Disallow bad CIDR input for IPv4
        if (raw_cidr > 32 || raw_cidr < 0) return ANTILORIS_CONFIG_ERROR_IP_CIDR;

        raw_cidr += 96;
    }

    // Disallow bad CIDR input for IPv6
    if (raw_cidr > 128 || raw_cidr < 0) return ANTILORIS_CONFIG_ERROR_IP_CIDR;

    if (!parse_ipv6_address(input_ip_lower, ip_lower)) return ANTILORIS_CONFIG_ERROR_IP_PARSE;

    // Validate netmask and fill bits for upper bound
    memcpy(ip_upper, ip_lower, sizeof(struct in6_addr));
    for (uint8_t i = raw_cidr; i < 128; i++) {
        bool bit = ((ip_lower->s6_addr[i / 8u]) >> (7u - i % 8u)) & 0x01u;

        // Disallow IP inside mask
        if (bit) {
            return ANTILORIS_CONFIG_ERROR_IP_IN_NETMASK;
        }

        ip_upper->s6_addr[i / 8u] |= (1u << (7u - i % 8u));
    }

    return 0;
}

int whitelist_ip(patricia_trie *whitelist, char *input) {
    struct in6_addr ip_lower, ip_upper;
    int rc;

    if (strchr(input, '-')) {
        rc = parse_ip_range_hyphenated(input, &ip_lower, &ip_upper);
    } else {
        rc = parse_ip_range_cidr(input, &ip_lower, &ip_upper);
    }
    if (rc != 0) return rc;

    // Disallow lower IP greater than upper IP
    if (memcmp(&ip_lower, &ip_upper, sizeof(struct in6_addr)) > 0) return ANTILORIS_CONFIG_ERROR_IP_RANGE_ORDER;

    insert_range(whitelist, ip_lower, ip_upper);

    return 0;
}

bool is_ip_whitelisted(char *ip_input, patricia_trie *whitelist) {
    char ip[INET6_ADDRSTRLEN];
    strncpy(ip, ip_input, INET6_ADDRSTRLEN - 1);
    ip[INET6_ADDRSTRLEN - 1] = '\0';

    struct in6_addr ip_test;
    auto_convert_ipv4_to_ipv6(ip);
    if (!parse_ipv6_address(ip, &ip_test)) return false;

    return patricia_contains(whitelist, ip_test);
}

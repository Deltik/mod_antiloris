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

    while (true) {
        if (*node == NULL) {
            // Node is empty, insert here
            patricia_node *new_node = malloc(sizeof(patricia_node));
            new_node->ip = ip;
            new_node->prefix_len = prefix_len;
            new_node->left = new_node->right = NULL;
            *node = new_node;
            return;
        }

        int min_prefix_len = (*node)->prefix_len < prefix_len ? (*node)->prefix_len : prefix_len;
        int common_bits = count_common_prefix_bits(&(*node)->ip, &ip, min_prefix_len);

        if (common_bits == (*node)->prefix_len && common_bits == prefix_len) {
            // Exact match, node already exists
            return;
        }

        if (prefix_len <= (*node)->prefix_len && common_bits >= prefix_len) {
            // New prefix covers existing node
            // Replace existing node with new node
            patricia_free_node((*node)->left);
            patricia_free_node((*node)->right);
            free(*node);
            patricia_node *new_node = malloc(sizeof(patricia_node));
            new_node->ip = ip;
            new_node->prefix_len = prefix_len;
            new_node->left = new_node->right = NULL;
            *node = new_node;
            return;
        }

        if (prefix_len >= (*node)->prefix_len && common_bits >= (*node)->prefix_len) {
            // Existing node covers new prefix
            // If existing node is a leaf, do nothing
            if ((*node)->left == NULL && (*node)->right == NULL) {
                return;
            } else {
                // Continue down the tree
                bool bit = bit_at(&ip, (*node)->prefix_len);
                node = bit ? &(*node)->right : &(*node)->left;
                continue;
            }
        }

        // Need to split the existing node
        patricia_node *existing_node = *node;
        patricia_node *parent_node = malloc(sizeof(patricia_node));
        parent_node->ip = ip; // Use the common prefix
        parent_node->prefix_len = common_bits;
        parent_node->left = parent_node->right = NULL;

        bool new_bit = bit_at(&ip, common_bits);

        patricia_node *new_node = malloc(sizeof(patricia_node));
        new_node->ip = ip;
        new_node->prefix_len = prefix_len;
        new_node->left = new_node->right = NULL;

        if (new_bit) {
            parent_node->right = new_node;
            parent_node->left = existing_node;
        } else {
            parent_node->left = new_node;
            parent_node->right = existing_node;
        }

        *node = parent_node;
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

bool parse_ip_address(const char *input, struct in6_addr *dest) {
    // Try parsing as IPv6 first
    if (strchr(input, ':') != NULL) {
        return inet_pton(AF_INET6, input, dest) == 1;
    }

    // If not IPv6, try parsing as IPv4 and convert to IPv4-mapped IPv6
    struct in_addr ipv4addr;
    if (inet_pton(AF_INET, input, &ipv4addr) == 1) {
        dest->s6_addr32[0] = 0;
        dest->s6_addr32[1] = 0;
        dest->s6_addr32[2] = htonl(0xffff);
        dest->s6_addr32[3] = ipv4addr.s_addr;
        return true;
    }

    return false;
}

int parse_ip_range_hyphenated(const char *input, struct in6_addr *ip_lower, struct in6_addr *ip_upper) {
    const char *hyphen = strchr(input, '-');
    if (!hyphen) return ANTILORIS_CONFIG_ERROR_IP_PARSE;

    char input_ip_lower[INET6_ADDRSTRLEN];
    char input_ip_upper[INET6_ADDRSTRLEN];

    size_t lower_len = hyphen - input;
    size_t upper_len = strlen(hyphen + 1);

    if (lower_len >= INET6_ADDRSTRLEN || upper_len >= INET6_ADDRSTRLEN) {
        return ANTILORIS_CONFIG_ERROR_IP_PARSE;
    }

    memcpy(input_ip_lower, input, lower_len);
    input_ip_lower[lower_len] = '\0';
    strcpy(input_ip_upper, hyphen + 1);

    if (!parse_ip_address(input_ip_lower, ip_lower)) return ANTILORIS_CONFIG_ERROR_IP_PARSE;
    if (!parse_ip_address(input_ip_upper, ip_upper)) return ANTILORIS_CONFIG_ERROR_IP_PARSE;

    return 0;
}

int parse_ip_range_cidr(const char *input, struct in6_addr *ip_lower, struct in6_addr *ip_upper) {
    const char *slash = strchr(input, '/');
    char input_ip[INET6_ADDRSTRLEN];
    uint8_t raw_cidr = 128;

    if (slash) {
        size_t ip_len = slash - input;
        if (ip_len >= INET6_ADDRSTRLEN) return ANTILORIS_CONFIG_ERROR_IP_PARSE;
        memcpy(input_ip, input, ip_len);
        input_ip[ip_len] = '\0';
        raw_cidr = strtoul(slash + 1, NULL, 10);
    } else {
        strncpy(input_ip, input, INET6_ADDRSTRLEN - 1);
        input_ip[INET6_ADDRSTRLEN - 1] = '\0';
    }

    if (!parse_ip_address(input_ip, ip_lower)) return ANTILORIS_CONFIG_ERROR_IP_PARSE;

    // Adjust CIDR for IPv4-mapped IPv6 addresses
    bool is_ipv4 = (!strchr(input, ':') &&
                    ip_lower->s6_addr32[0] == 0 &&
                    ip_lower->s6_addr32[1] == 0 &&
                    ip_lower->s6_addr32[2] == htonl(0xffff));
    if (is_ipv4) {
        if (!slash) raw_cidr = 32;

        // Disallow bad CIDR input for IPv4
        if (raw_cidr > 32 || raw_cidr < 0) return ANTILORIS_CONFIG_ERROR_IP_CIDR;

        raw_cidr += 96;
    }

    // Disallow bad CIDR input for IPv6
    if (raw_cidr > 128 || raw_cidr < 0) return ANTILORIS_CONFIG_ERROR_IP_CIDR;

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

int exempt_ip(patricia_trie *allowlist, const char *input) {
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

    insert_range(allowlist, ip_lower, ip_upper);

    return 0;
}

bool is_ip_exempted(const char *ip_input, patricia_trie *allowlist) {
    struct in6_addr ip_test;
    if (!parse_ip_address(ip_input, &ip_test)) return false;

    return patricia_contains(allowlist, ip_test);
}

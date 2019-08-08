/*
   ipv6_playground.c
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

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <roaring.h>
#include <apr_hash.h>
#include "ipv6_playground.h"

#define ANTILORIS_CONFIG_ERROR_IP_PARSE 255
#define ANTILORIS_CONFIG_ERROR_IP_CIDR 254
#define ANTILORIS_CONFIG_ERROR_IP_IN_NETMASK 253
#define ANTILORIS_CONFIG_ERROR_IP_RANGE_ORDER 252

apr_pool_t *apr_pool;

struct flexmap *create_flexmap() {
    struct flexmap *new_flexmap = malloc(sizeof(struct flexmap));
    new_flexmap->level = 0;
    new_flexmap->bitmap = roaring_bitmap_create();
    new_flexmap->next = apr_hash_make(apr_pool);
    return new_flexmap;
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

bool parse_ipv6_address(char *input, uint32_t *dest) {
    int rc = inet_pton(AF_INET6, input, dest);
    if (rc != 1) {
        return 0;
    }

    // Convert IP address from network byte order to host byte order
    for (int i = 0; i < 4; i++) {
        dest[i] = ntohl(dest[i]);
    }

    return 1;
}

static void flexmap_fill_range(struct flexmap *flexmap, uint32_t *ip_lower, uint32_t *ip_upper, int level) {
    if (ip_upper[level] - ip_lower[level] > 1) {
        // Fill bits in between
        roaring_bitmap_add_range_closed(flexmap->bitmap, ip_lower[level] + 1, ip_upper[level] - 1);
        // Remove flexmaps for bits that have been filled
        apr_hash_index_t *hash_index;
        uint32_t *key = NULL;
        apr_ssize_t *key_length = NULL;
        struct flexmap *next = NULL;
        for (hash_index = apr_hash_first(apr_pool, flexmap->next);
             hash_index;
             hash_index = apr_hash_next(hash_index)) {
            apr_hash_this(hash_index, (const void **) &key, (apr_ssize_t *) &key_length, (void **) &next);
            if (*key > ip_lower[level] && *key < ip_upper[level]) {
                roaring_bitmap_free(next->bitmap);
                free(next);
                apr_hash_set(flexmap->next, key, *key_length, NULL);
                free(key);
            }
        }
    }

    int key_size = sizeof(ip_lower[level]);
    uint32_t *key;
    if (level == 3) {
        // Fill bits at last level
        roaring_bitmap_add(flexmap->bitmap, ip_lower[level]);
        roaring_bitmap_add(flexmap->bitmap, ip_upper[level]);
    } else if (ip_lower[level] == ip_upper[level]) {
        struct flexmap *next_flexmap = apr_hash_get(flexmap->next, &ip_lower[level], sizeof(ip_lower[level]));
        if (next_flexmap == NULL) {
            next_flexmap = create_flexmap();
            next_flexmap->level = level + 1;
            key = apr_palloc(apr_pool, key_size);
            memcpy(key, &ip_lower[level], key_size);
            apr_hash_set(flexmap->next, key, key_size, next_flexmap);
        }
        flexmap_fill_range(next_flexmap, ip_lower, ip_upper, level + 1);
    } else {
        // Recursively fill bits at next levels
        uint32_t next_ip_lower[4] = {0, 0, 0, 0};
        uint32_t next_ip_upper[4] = {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX};
        struct flexmap *next_flexmap_lower = apr_hash_get(flexmap->next, &ip_lower[level], sizeof(ip_lower[level]));
        if (next_flexmap_lower == NULL) {
            next_flexmap_lower = create_flexmap();
            next_flexmap_lower->level = level + 1;
            key = apr_palloc(apr_pool, key_size);
            memcpy(key, &ip_lower[level], key_size);
            apr_hash_set(flexmap->next, key, key_size, next_flexmap_lower);
        }
        flexmap_fill_range(next_flexmap_lower, ip_lower, next_ip_upper, level + 1);
        struct flexmap *next_flexmap_upper = apr_hash_get(flexmap->next, &ip_upper[level], sizeof(ip_upper[level]));
        if (next_flexmap_upper == NULL) {
            next_flexmap_upper = create_flexmap();
            next_flexmap_upper->level = level + 1;
            key = apr_palloc(apr_pool, key_size);
            memcpy(key, &ip_upper[level], key_size);
            apr_hash_set(flexmap->next, key, key_size, next_flexmap_upper);
        }
        flexmap_fill_range(next_flexmap_upper, next_ip_lower, ip_upper, level + 1);
    }
}

static bool _flexmap_contains(struct flexmap *flexmap, uint32_t *ip_address, int level) {
    if (roaring_bitmap_contains(flexmap->bitmap, ip_address[level])) {
        return true;
    }

    struct flexmap *next_flexmap = apr_hash_get(flexmap->next, &ip_address[level], sizeof(ip_address[level]));
    if (next_flexmap != NULL) {
        return _flexmap_contains(next_flexmap, ip_address, level + 1);
    }
    return false;
}

bool flexmap_contains(struct flexmap *flexmap, uint32_t *ip_address) {
    return _flexmap_contains(flexmap, ip_address, 0);
}

int parse_ip_range_hyphenated(char *input, uint32_t *ip_lower, uint32_t *ip_upper) {
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

static int parse_ip_range_cidr(char *input, uint32_t *ip_lower, uint32_t *ip_upper) {
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
    memcpy(ip_upper, ip_lower, 16);
    for (uint8_t i = raw_cidr; i < 128; i++) {
        bool bit = ip_lower[i / 32u] >> (31u - i % 32u) & 0x01u;

        // Disallow IP inside mask
        if (bit) {
            return ANTILORIS_CONFIG_ERROR_IP_IN_NETMASK;
        }

        ip_upper[i / 32u] |= (1u << (31u - i % 32u));
    }

    return 0;
}

int whitelist_ip(struct flexmap *whitelist, char *input) {
    uint32_t ip_lower[4];
    uint32_t ip_upper[4];
    int rc = 0;

    if (strstr(input, "-")) {
        rc = parse_ip_range_hyphenated(input, ip_lower, ip_upper);
    } else {
        rc = parse_ip_range_cidr(input, ip_lower, ip_upper);
    }

    // Disallow lower IP greater than upper IP
    for (int level = 0; level < 4; level++) {
        if (ip_lower[level] > ip_upper[level]) return ANTILORIS_CONFIG_ERROR_IP_RANGE_ORDER;
    }

    if (rc != 0) return rc;

    flexmap_fill_range(whitelist, ip_lower, ip_upper, 0);

    return 0;
}

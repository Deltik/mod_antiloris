/*
 ip_helper.c - IP range ignore list implementation using a sorted interval set

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

#include "ip_helper.h"

#include <ctype.h>
#include <errno.h>

#define IP_SET_INITIAL_CAPACITY 16

/**
 * Load 8 bytes as a big-endian unsigned integer. Compilers recognize this
 * idiom and emit a single load (plus byte swap on little-endian machines).
 */
static inline uint64_t load_be64(const uint8_t *p) {
    return ((uint64_t) p[0] << 56) | ((uint64_t) p[1] << 48) |
           ((uint64_t) p[2] << 40) | ((uint64_t) p[3] << 32) |
           ((uint64_t) p[4] << 24) | ((uint64_t) p[5] << 16) |
           ((uint64_t) p[6] << 8) | (uint64_t) p[7];
}

/**
 * Compare two 128-bit IP addresses as unsigned big-endian integers
 */
static inline int in6_cmp(const struct in6_addr *a, const struct in6_addr *b) {
    uint64_t a_word = load_be64(a->s6_addr), b_word = load_be64(b->s6_addr);
    if (a_word != b_word) return a_word < b_word ? -1 : 1;
    a_word = load_be64(a->s6_addr + 8);
    b_word = load_be64(b->s6_addr + 8);
    if (a_word != b_word) return a_word < b_word ? -1 : 1;
    return 0;
}

/**
 * Increment an IP address in place
 * @return false if the increment wrapped past the all-ones address
 */
static bool in6_increment(struct in6_addr *ip) {
    for (int i = (int) sizeof(ip->s6_addr) - 1; i >= 0; i--) {
        if (++ip->s6_addr[i] != 0) return true;
    }
    return false;
}

ip_set *ip_set_create(void) {
    ip_set *set = malloc(sizeof(ip_set));
    if (set == NULL) return NULL;
    set->ranges = NULL;
    set->count = 0;
    set->capacity = 0;
    return set;
}

void ip_set_free(ip_set *set) {
    if (set == NULL) return;
    free(set->ranges);
    free(set);
}

static int ip_set_reserve(ip_set *set) {
    if (set->count < set->capacity) return 0;
    size_t new_capacity = set->capacity == 0 ? IP_SET_INITIAL_CAPACITY : set->capacity * 2;
    ip_range *new_ranges = realloc(set->ranges, new_capacity * sizeof(ip_range));
    if (new_ranges == NULL) return ANTILORIS_CONFIG_ERROR_MEMORY;
    set->ranges = new_ranges;
    set->capacity = new_capacity;
    return 0;
}

int ip_set_insert(ip_set *set, struct in6_addr start, struct in6_addr end) {
    if (set == NULL) return ANTILORIS_CONFIG_ERROR_MEMORY;

    // The ranges are sorted and disjoint, so their ends are strictly
    // increasing. Find the first range that ends at or after the new start.
    size_t lo = 0, hi = set->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (in6_cmp(&set->ranges[mid].end, &start) < 0) lo = mid + 1;
        else hi = mid;
    }

    // The range before that ends below the new start but may touch it
    if (lo > 0) {
        struct in6_addr pred_succ = set->ranges[lo - 1].end;
        if (in6_increment(&pred_succ) && in6_cmp(&pred_succ, &start) == 0) lo--;
    }

    // Every range that starts at or before end + 1 merges with the new range
    struct in6_addr end_succ = end;
    bool end_has_succ = in6_increment(&end_succ);
    size_t merge_end = lo;
    while (merge_end < set->count) {
        const struct in6_addr *range_start = &set->ranges[merge_end].start;
        if (in6_cmp(range_start, &end) > 0 &&
            !(end_has_succ && in6_cmp(range_start, &end_succ) == 0))
            break;
        merge_end++;
    }

    if (merge_end == lo) {
        // Nothing to merge with: insert a new range at position lo
        int rc = ip_set_reserve(set);
        if (rc != 0) return rc;
        memmove(&set->ranges[lo + 1], &set->ranges[lo], (set->count - lo) * sizeof(ip_range));
        set->ranges[lo].start = start;
        set->ranges[lo].end = end;
        set->count++;
        return 0;
    }

    // Collapse the ranges in [lo, merge_end) into one merged range
    if (in6_cmp(&set->ranges[lo].start, &start) < 0) start = set->ranges[lo].start;
    if (in6_cmp(&set->ranges[merge_end - 1].end, &end) > 0) end = set->ranges[merge_end - 1].end;
    set->ranges[lo].start = start;
    set->ranges[lo].end = end;
    memmove(&set->ranges[lo + 1], &set->ranges[merge_end], (set->count - merge_end) * sizeof(ip_range));
    set->count -= merge_end - lo - 1;
    return 0;
}

bool ip_set_contains(const ip_set *set, const struct in6_addr *ip) {
    if (set == NULL) return false;

    uint64_t ip_hi = load_be64(ip->s6_addr);
    uint64_t ip_lo = load_be64(ip->s6_addr + 8);

    // Find the last range that starts at or before the IP address
    size_t lo = 0, hi = set->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint64_t start_hi = load_be64(set->ranges[mid].start.s6_addr);
        uint64_t start_lo = load_be64(set->ranges[mid].start.s6_addr + 8);
        if (start_hi < ip_hi || (start_hi == ip_hi && start_lo <= ip_lo)) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return false;

    uint64_t end_hi = load_be64(set->ranges[lo - 1].end.s6_addr);
    uint64_t end_lo = load_be64(set->ranges[lo - 1].end.s6_addr + 8);
    return ip_hi < end_hi || (ip_hi == end_hi && ip_lo <= end_lo);
}

bool parse_ip_address(const char *input, struct in6_addr *dest) {
    // Try parsing as IPv6 first
    if (strchr(input, ':') != NULL) {
        return inet_pton(AF_INET6, input, dest) == 1;
    }

    // If not IPv6, try parsing as IPv4 and convert to IPv4-mapped IPv6
    struct in_addr ipv4addr;
    if (inet_pton(AF_INET, input, &ipv4addr) == 1) {
        memset(dest->s6_addr, 0, 10);
        dest->s6_addr[10] = 0xff;
        dest->s6_addr[11] = 0xff;
        memcpy(&dest->s6_addr[12], &ipv4addr.s_addr, 4);
        return true;
    }

    return false;
}

static int parse_ip_range_hyphenated(const char *input, struct in6_addr *ip_lower, struct in6_addr *ip_upper) {
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

static int parse_ip_range_cidr(const char *input, struct in6_addr *ip_lower, struct in6_addr *ip_upper) {
    const char *slash = strchr(input, '/');
    char input_ip[INET6_ADDRSTRLEN];
    unsigned long cidr = 128;

    if (slash) {
        size_t ip_len = slash - input;
        if (ip_len == 0 || ip_len >= INET6_ADDRSTRLEN) return ANTILORIS_CONFIG_ERROR_IP_PARSE;
        memcpy(input_ip, input, ip_len);
        input_ip[ip_len] = '\0';

        // Reject signs, whitespace, and trailing garbage that strtoul would accept
        if (!isdigit((unsigned char) slash[1])) return ANTILORIS_CONFIG_ERROR_IP_CIDR;
        char *cidr_end;
        errno = 0;
        cidr = strtoul(slash + 1, &cidr_end, 10);
        if (errno != 0 || *cidr_end != '\0') return ANTILORIS_CONFIG_ERROR_IP_CIDR;
    } else {
        strncpy(input_ip, input, INET6_ADDRSTRLEN - 1);
        input_ip[INET6_ADDRSTRLEN - 1] = '\0';
    }

    if (!parse_ip_address(input_ip, ip_lower)) return ANTILORIS_CONFIG_ERROR_IP_PARSE;

    // Adjust CIDR for IPv4-mapped IPv6 addresses
    if (!strchr(input, ':') && IN6_IS_ADDR_V4MAPPED(ip_lower)) {
        if (!slash) cidr = 32;

        // Disallow bad CIDR input for IPv4
        if (cidr > 32) return ANTILORIS_CONFIG_ERROR_IP_CIDR;

        cidr += 96;
    }

    // Disallow bad CIDR input for IPv6
    if (cidr > 128) return ANTILORIS_CONFIG_ERROR_IP_CIDR;

    // Validate netmask and fill bits for upper bound
    memcpy(ip_upper, ip_lower, sizeof(struct in6_addr));
    for (unsigned int i = cidr; i < 128; i++) {
        bool bit = ((ip_lower->s6_addr[i / 8u]) >> (7u - i % 8u)) & 0x01u;

        // Disallow IP inside mask
        if (bit) {
            return ANTILORIS_CONFIG_ERROR_IP_IN_NETMASK;
        }

        ip_upper->s6_addr[i / 8u] |= (1u << (7u - i % 8u));
    }

    return 0;
}

int exempt_ip(ip_set *allowlist, const char *input) {
    struct in6_addr ip_lower, ip_upper;
    int rc;

    if (strchr(input, '-')) {
        rc = parse_ip_range_hyphenated(input, &ip_lower, &ip_upper);
    } else {
        rc = parse_ip_range_cidr(input, &ip_lower, &ip_upper);
    }
    if (rc != 0) return rc;

    // Disallow lower IP greater than upper IP
    if (in6_cmp(&ip_lower, &ip_upper) > 0) return ANTILORIS_CONFIG_ERROR_IP_RANGE_ORDER;

    return ip_set_insert(allowlist, ip_lower, ip_upper);
}

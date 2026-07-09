/*
 ip_helper.h - IP range ignore list implementation using a sorted interval set

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

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ANTILORIS_IP_HELPER_H

#define ANTILORIS_CONFIG_ERROR_IP_PARSE 255
#define ANTILORIS_CONFIG_ERROR_IP_CIDR 254
#define ANTILORIS_CONFIG_ERROR_IP_IN_NETMASK 253
#define ANTILORIS_CONFIG_ERROR_IP_RANGE_ORDER 252
#define ANTILORIS_CONFIG_ERROR_MEMORY 251

/**
 * An inclusive range of IP addresses [start, end]. Hard-coded to 128-bit IP
 * addresses; IPv4 addresses are represented as IPv4-mapped IPv6 addresses.
 */
typedef struct {
    struct in6_addr start;
    struct in6_addr end;
} ip_range;

/**
 * A set of IP addresses stored as a sorted array of disjoint, non-adjacent,
 * inclusive ranges. The set is built at configuration time; lookups do not
 * modify it, so concurrent readers are safe.
 */
typedef struct {
    ip_range *ranges;
    size_t count;
    size_t capacity;
} ip_set;

/**
 * Allocates a new empty IP set
 * @return The new set, or NULL if out of memory
 */
ip_set *ip_set_create(void);

/**
 * Free an IP set and its ranges
 * @param set The set to free
 */
void ip_set_free(ip_set *set);

/**
 * Insert the inclusive IP address range [start, end] into the set, merging it
 * with any overlapping or adjacent ranges already present
 * @param set The set to insert into
 * @param start The first IP address of the range
 * @param end The last IP address of the range (must not be below start)
 * @return 0 if successful, error code if not successful
 */
int ip_set_insert(ip_set *set, struct in6_addr start, struct in6_addr end);

/**
 * Check if an IP address is in the set
 * @param set The set to check
 * @param ip The IP address to check
 * @return true if the IP address is in the set, false if not
 */
bool ip_set_contains(const ip_set *set, const struct in6_addr *ip);

/**
 * Parse a textual IPv4 or IPv6 address into a 128-bit IP address.
 * IPv4 addresses are converted to IPv4-mapped IPv6 addresses.
 * @param input The textual IP address
 * @param dest The parsed 128-bit IP address
 * @return true if the input was parsed successfully, false if not
 */
bool parse_ip_address(const char *input, struct in6_addr *dest);

/**
 * Adds an IP address, IP address range, or CIDR range to the IP set
 * @param allowlist The IP set to add to
 * @param input A single IP address with an optional CIDR suffix or a hyphenated IP address range. Can be IPv4 or IPv6.
 * @return 0 if successful, error code if not successful
 */
int exempt_ip(ip_set *allowlist, const char *input);

#define ANTILORIS_IP_HELPER_H

#endif //ANTILORIS_IP_HELPER_H

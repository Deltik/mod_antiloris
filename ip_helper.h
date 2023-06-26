/*
 ip_helper.h - IP range ignore list implementation using nested bitmaps

 Copyright (C) 2019-2023 Deltik <https://www.deltik.net/>

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

#include <stdbool.h>
#include <roaring.h>
#include <apr_hash.h>

#ifndef ANTILORIS_IPV6_PLAYGROUND_H

#define ANTILORIS_CONFIG_ERROR_IP_PARSE 255
#define ANTILORIS_CONFIG_ERROR_IP_CIDR 254
#define ANTILORIS_CONFIG_ERROR_IP_IN_NETMASK 253
#define ANTILORIS_CONFIG_ERROR_IP_RANGE_ORDER 252

/**
 * A huge bitmap. Currently hard-coded to support 128 bits.
 */
struct flexmap {
    roaring_bitmap_t *bitmap;
    apr_pool_t *apr_pool;
    apr_hash_t *next;
};

/**
 * Allocates a new huge bitmap
 * @return A fully initialized huge bitmap
 */
struct flexmap *create_flexmap(apr_pool_t *apr_pool);

/**
 * Convert an IPv4 address to an IPv4-mapped IPv6 address
 *
 * Does not change the input if the input is already an IPv6 address.
 * Input must be at least INET6_ADDRSTRLEN long.
 * @param input_ip String to convert into an IPv6 address
 * @return true if input was converted to IPv6
 */
bool auto_convert_ipv4_to_ipv6(char *input_ip);

/**
 * Parse an IPv6 string into host-compatible binary
 * @param input IPv6 input string
 * @param dest 128 bits of binary storage
 * @return true if the parsing was successful, false otherwise
 */
bool parse_ipv6_address(char *input, uint32_t *dest);

/**
 * Inclusively set all bits to true from ip_lower to ip_upper
 * @param flexmap The bitmap struct for very large bitmaps
 * @param ip_lower The smallest number, which will also be set to true
 * @param ip_upper The biggest number, which will also be set to true
 * @param level Recursion depth; starts at 0 and counts up
 */
void flexmap_fill_range(struct flexmap *flexmap, uint32_t *ip_lower, uint32_t *ip_upper, int level);

/**
 * Check if the huge bitmap includes the provided number
 * @param flexmap The huge bitmap to check
 * @param ip_address The number to check if it's true in the bitmap
 * @param level Recursion depth; starts at 0 and counts up
 * @return true if the number is present in the huge bitmap
 */
bool _flexmap_contains(struct flexmap *flexmap, uint32_t *ip_address, int level);

/**
 * Check if the huge bitmap includes the provided number
 * @param flexmap The huge bitmap to check
 * @param ip_address The number to check if it's true in the bitmap
 * @param level Recursion depth; starts at 0 and counts up
 * @return true if the number is present in the huge bitmap
 */
bool flexmap_contains(struct flexmap *flexmap, uint32_t *ip_address);

/**
 * Takes a hyphenated IP address range and calculates the upper and lower bounds
 * @param input A hyphenated IP address range. Can be IPv4, IPv6, or both.
 * @param ip_lower 16-byte array representing the lower bound of the IP address range
 * @param ip_upper 16-byte array representing the upper bound of the IP address range
 * @return 0 if successful, error code if not successful
 */
int parse_ip_range_hyphenated(char *input, uint32_t *ip_lower, uint32_t *ip_upper);

/**
 * Takes a single IP address or CIDR notation and calculates the upper and lower bounds
 * @param input A single IP address with an optional CIDR suffix. Can be IPv4 or IPv6.
 * @param ip_lower 16-byte array representing the lower bound of the IP address range
 * @param ip_upper 16-byte array representing the upper bound of the IP address range
 * @return 0 if successful, error code if not successful
 */
int parse_ip_range_cidr(char *input, uint32_t *ip_lower, uint32_t *ip_upper);

/**
 * Adds the IP address, IP address range, or a CIDR range to the huge bitmap
 * @param whitelist The huge bitmap
 * @param input A single IP address with an optional CIDR suffix or a hyphenated IP address range. Can be IPv4 or IPv6.
 * @return 0 if successful, error code if not successful
 */
int whitelist_ip(struct flexmap *whitelist, char *input);

/**
 * Check if the IP address is present in the huge bitmap
 * @param ip_input A single IPv4 or IPv6 address
 * @param whitelist The huge bitmap
 * @return true if the provided IP address is present in the huge bitmap
 */
bool is_ip_whitelisted(char *ip_input, struct flexmap *whitelist);

#define ANTILORIS_IPV6_PLAYGROUND_H

#endif //ANTILORIS_IPV6_PLAYGROUND_H

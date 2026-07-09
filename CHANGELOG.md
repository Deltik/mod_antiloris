# Changelog

[![GitHub releases](https://img.shields.io/github/release/Deltik/mod_antiloris.svg)](https://github.com/Deltik/mod_antiloris/releases)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.8.3 (2026-07-09)

### Fixed

- `ExemptIPs` hung Apache startup in an infinite loop when an entry reached the maximum IPv6 address (e.g. `::/0`, `8000::/1`, `ffff::/16`, or a hyphenated range ending in `ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`)
- `ExemptIPs` silently discarded an entry whose network prefix coincided with an internal node of the PATRICIA trie, causing some allowlisted clients to be subjected to limits (e.g. in `ExemptIPs 1.2.3.0/26 1.2.3.192/26 1.2.3.0/24`, the `1.2.3.0/24` entry was lost)
- `ExemptIPs` accepted malformed CIDR suffixes such as `0.0.0.0/256`, `::/384`, and `::/24junk`; these are now reported as configuration errors
- Out-of-memory conditions while building the allowlist are now reported as configuration errors instead of crashing

### Changed

- Replaced the PATRICIA trie allowlist with a sorted interval set: entries are merged into disjoint IP address ranges at configuration time and looked up with a binary search.
  This eliminates the CIDR block decomposition of IP address ranges (a worst-case range that previously required 505 trie nodes is now stored as a single 32-byte interval) and speeds up lookups by roughly 1.3–1.5× for prefix allowlists and up to 23× for wide hyphenated ranges.

  End-to-end, the change is transparent to HTTP request handling. The following measurements come from a vanilla Debian 12 (bookworm) Apache HTTP Server version 2.4.67 running `mpm_prefork` with 150 connection slots and the same 22-entry Cloudflare `ExemptIPs` allowlist as the `= 0.8.0` benchmark (see the changelog for that version), comparing no module against `= 0.8.2` (PATRICIA trie) and `= 0.8.3` (interval set). Each latency figure is pooled from three runs of 100,000 requests at 10 concurrent connections, one connection per request, retrieving a static HTML file over loopback:

  | mod_antiloris version | N      | min (s)  | q1 (s)   | median (s) | q3 (s)   | max (s)  | mean (s) | stddev (s) |
  |-----------------------|--------|----------|----------|------------|----------|----------|----------|------------|
  | _Not installed_       | 300000 | 0.000116 | 0.000209 | 0.000233   | 0.000266 | 0.012378 | 0.000247 | 0.000093   |
  | `= 0.8.2`             | 300000 | 0.000122 | 0.000213 | 0.000238   | 0.000271 | 0.007263 | 0.000253 | 0.000100   |
  | `= 0.8.3`             | 300000 | 0.000116 | 0.000210 | 0.000234   | 0.000265 | 0.007109 | 0.000246 | 0.000090   |

  Because the per-connection check now reads the client's binary socket address instead of re-parsing the textual IP address, `= 0.8.3` matches the no-module baseline and is marginally faster than the `= 0.8.2` trie. When the connecting client is itself on the allowlist, median latency is likewise unchanged (0.000235 s).

  Building the allowlist at startup is similarly unaffected. Timing configuration parsing, which is where the allowlist is constructed, over 300 iterations:

  | mod_antiloris version | N   | min (s)  | q1 (s)   | median (s) | q3 (s)   | max (s)  | mean (s) | stddev (s) |
  |-----------------------|-----|----------|----------|------------|----------|----------|----------|------------|
  | _Not installed_       | 300 | 0.023663 | 0.024625 | 0.025068   | 0.025786 | 0.030545 | 0.025275 | 0.000995   |
  | `= 0.8.2`             | 300 | 0.023279 | 0.024334 | 0.024979   | 0.025706 | 0.029395 | 0.025121 | 0.001083   |
  | `= 0.8.3`             | 300 | 0.023675 | 0.024743 | 0.025153   | 0.025791 | 0.031299 | 0.025416 | 0.001177   |

  Total Apache resident memory was unchanged as well (roughly 45 MiB idle and 57 MiB under load for all three) because both the trie and the interval set hold a 22-entry allowlist in a few hundred bytes:

  | mod_antiloris version | Memory usage (idle) | Memory usage (under load) |
  |-----------------------|---------------------|---------------------------|
  | _Not installed_       | 45.3 MiB            | 57.7 MiB                  |
  | `= 0.8.2`             | 45.6 MiB            | 58.0 MiB                  |
  | `= 0.8.3`             | 44.9 MiB            | 57.2 MiB                  |

- Connection checks now use the client's binary socket address directly instead of re-parsing the textual IP address on every connection

## v0.8.2 (2024-10-09)

### Fixed

- `ExemptIPs` allowlist insertion bug that erroneously lost track of some IP range branches when splitting a node during insertion (#4)
- Inaccurate descriptions of the `ExemptIPs`, `WhitelistIPs`, and `LocalIPs` directives in the module built-in documentation

### Changed

- Removed the unused `auto_convert_ipv4_to_ipv6()` function.
  `parse_ip_address()` already handles both IPv6 and IPv4-mapped IPv6 addresses.

## v0.8.1 (2024-09-06)

### Fixed

- Null pointer dereference crash when a connection is suspended and the scoreboard handle is removed (#3)

## v0.8.0 (2024-08-03)

### Changed

- Renamed the `WhitelistIPs` directive to `ExemptIPs` to clarify that it exempts IP addresses from mitigation

  `WhitelistIPs` and the even older `LocalIPs` are still supported as aliases for backwards compatibility.
- Implemented a new Slowloris mitigation IP address allowlist that dramatically reduces memory consumption and enhances performance

  The [roaring bitmaps](https://github.com/RoaringBitmap/CRoaring) previously used to store IP addresses exempt from Slowloris mitigation have been replaced with a more efficient [PATRICIA trie](https://en.wikipedia.org/wiki/PATRICIA_trie) data structure.

  Benchmark results for a vanilla Debian 12 Apache HTTP Server version 2.4.61 with mod_antiloris configured using `ExemptIPs 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32`:

  | mod_antiloris version | Memory usage (idle) | Memory usage (under DoS attack from 1 IP) |
  |-----------------------|---------------------|-------------------------------------------|
  | _Not installed_       | 56.2 MiB            | 151.9 MiB                                 |
  | `= 0.7.2`             | 5342.2 MiB          | 5352.0 MiB                                |
  | `= 0.8.0`             | 56.8 MiB            | 64.8 MiB                                  |

  mod_antiloris and its configuration now occupy a mere 0.6 MiB of memory, down from 5,286 MiB in the previous version with identical settings. This represents a massive 99.988% reduction in memory footprint.

  The module's initialization speed has also been substantially improved, as evidenced by repeated executions of `time systemctl restart apache2.service`:

  | mod_antiloris version | N   | min (s)  | q1 (s)   | median (s) | q3 (s)   | max (s)  | mean (s) | stddev (s) |
  |-----------------------|-----|----------|----------|------------|----------|----------|----------|------------|
  | _Not installed_       | 100 | 0.086000 | 0.100000 | 0.105000   | 0.110000 | 0.119000 | 0.105060 | 0.006718   |
  | `= 0.7.2`             | 100 | 0.818000 | 0.837750 | 0.851000   | 0.868500 | 1.037000 | 0.858580 | 0.033554   |
  | `= 0.8.0`             | 100 | 0.088000 | 0.103750 | 0.108000   | 0.111250 | 0.126000 | 0.107220 | 0.006532   |

  Configured with the same directives, mod_antiloris `= 0.8.0` slashes the startup time overhead by over 99.7% compared to its predecessor.

  Crucially, the new algorithm maintains the performance of HTTP requests, as demonstrated by timing the retrieval of a static HTML file over 100,000 iterations with 10 concurrent connections:

  | mod_antiloris version | N      | min (s)  | q1 (s)   | median (s) | q3 (s)   | max (s)  | mean (s) | stddev (s) |
  |-----------------------|--------|----------|----------|------------|----------|----------|----------|------------|
  | _Not installed_       | 100000 | 0.000573 | 0.001035 | 0.001123   | 0.001231 | 0.008474 | 0.001170 | 0.000300   |
  | `= 0.7.2`             | 100000 | 0.000539 | 0.001068 | 0.001166   | 0.001287 | 0.010362 | 0.001212 | 0.000314   |
  | `= 0.8.0`             | 100000 | 0.000510 | 0.001054 | 0.001146   | 0.001260 | 0.011931 | 0.001197 | 0.000312   |
- Improved the parsing of IP addresses by eliminating string mutations and reducing the number of memory allocations

## v0.7.2 (2024-07-24)

### Fixed

- `WhitelistIPs` directive memory leak when reloading the Apache HTTP Server configuration (`systemctl reload apache2.service`, `httpd -k graceful`, or similar) (#2)

## v0.7.1 (2023-06-25)

### Changed

- Removed unused variables from ignore list structure for very minor memory and time savings

### Fixed

- A global variable (the Apache Portable Runtime pool) was breaking compilation, so it is now a local variable that is passed down as needed. (#1)

## v0.7.0 (2019-08-12)

### Added

- `IPTotalLimit` directive: Maximum simultaneous connections in any state per IP address
- `WhitelistIPs` directive: Space-delimited list of IPv4 and IPv6 addresses, ranges, or CIDRs which should not be subjected to any limits by mod_antiloris

### Changed

- `LocalIPs` is now an alias of `WhitelistIPs`, but `WhitelistIPs` overrides `LocalIPs`.  The implementations of both directives are now the same.

### Fixed

- Various connections slot states considered "other" were not being counted. They were:
  - `SERVER_BUSY_LOG`
  - `SERVER_BUSY_DNS`
  - `SERVER_CLOSING`
  - `SERVER_GRACEFUL`
- Off-by-one bug allowed one more connection than defined in the limits directives
- Invalid return code could be returned by the `ap_hook_process_connection` hook

## v0.6.0 (2014-09-09)

### Added

- Added configuration for adjustable limits based on the different vectors (@NewEraCracker)
- Added option to ignore local IPs (@NewEraCracker)

## v0.5.2 (2012-04-28)

### Changed

- Removed a few non-attackable vectors (@NewEraCracker)

### Fixed

- Improved Apache 2.4 compatibility (@NewEraCracker)

## v0.5.1 (2012-02-19)

### Fixed

- Initial Apache 2.4.x compatibility (@diovoemor)

## v0.5.0 (2011-09-09)

### Added

- Added other similar attack vectors than just Slowloris. (@NewEraCracker)

## v0.4 (2009-07-28)

### Added

- mod_antiloris can now handle IPv6 addresses. (@mind04)

## v0.3 (2009-06-24)

### Added

- Output module information to error log on httpd startup (@mind04)

### Changed

- Changed loglevel to warning (@mind04)

## v0.2 (2009-06-24)

### Added

- Added module version to signature (@mind04)

### Changed

- Code cleanup (@mind04)

## v0.1 (2009-06-22)

### Added

- Initial release (@mind04)

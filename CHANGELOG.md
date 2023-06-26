# Changelog

[![GitHub releases](https://img.shields.io/github/release/Deltik/mod_antiloris.svg)](https://github.com/Deltik/mod_antiloris/releases)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

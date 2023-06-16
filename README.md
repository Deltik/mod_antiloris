# mod_antiloris

[![GitHub releases](https://img.shields.io/github/release/Deltik/mod_antiloris.svg)](https://github.com/Deltik/mod_antiloris/releases)

**mod_antiloris** is an [Apache HTTP Server](https://httpd.apache.org/) module that helps to mitigate [Slowloris](https://en.wikipedia.org/wiki/Slowloris_%28computer_security%29) denial of service (DoS) attacks.
It works by preventing new connections from the same IP address after the connection count of the IP exceeds a configurable limit.

[**Why mod_antiloris?**](#comparison-with-other-mitigation-strategies)

[![mod_antiloris v0.7.0 in action](https://user-images.githubusercontent.com/1364268/62870861-f83d3300-bcdf-11e9-9cf0-aea8b0037115.png)](https://user-images.githubusercontent.com/1364268/62870345-2110f880-bcdf-11e9-8496-569349049730.png)

## Table of Contents

   * [mod_antiloris](#mod_antiloris)
      * [Table of Contents](#table-of-contents)
      * [Installation](#installation)
         * [Install Script](#install-script)
            * [Tested Platforms](#tested-platforms)
         * [Pre-Built Module](#pre-built-module)
         * [Compilation with CMake](#compilation-with-cmake)
         * [Compilation of Older Versions](#compilation-of-older-versions)
      * [Usage](#usage)
         * [Example Mitigation](#example-mitigation)
      * [Configuration](#configuration)
         * [Directives from Older Versions](#directives-from-older-versions)
         * [Aliases](#aliases)
         * [Configuration Examples](#configuration-examples)
      * [Syntax](#syntax)
         * [IP Addresses](#ip-addresses)
            * [Examples](#examples)
         * [Versioning](#versioning)
            * [Examples](#examples-1)
      * [Backwards Compatibility](#backwards-compatibility)
      * [Comparison with Other Mitigation Strategies](#comparison-with-other-mitigation-strategies)
         * [mod_antiloris vs. mod_reqtimeout](#mod_antiloris-vs-mod_reqtimeout)
         * [mod_antiloris vs. mod_qos](#mod_antiloris-vs-mod_qos)
         * [mod_antiloris vs. mod_noloris](#mod_antiloris-vs-mod_noloris)
         * [mod_antiloris vs. ModSecurity](#mod_antiloris-vs-modsecurity)
         * [mod_antiloris vs. mod_evasive](#mod_antiloris-vs-mod_evasive)
         * [mod_antiloris vs. mod_limitipconn](#mod_antiloris-vs-mod_limitipconn)
      * [Testing](#testing)

## Installation

### Install Script

There is a shell script that automates the installation of mod_antiloris, courtesy of [@filippolauria](https://github.com/filippolauria):

```shell
wget -q https://raw.githubusercontent.com/Deltik/mod_antiloris/main/install-antiloris.sh && chmod +x install-antiloris.sh && ./install-antiloris.sh
```

This script simplifies the installation process by downloading the latest pre-built version from this repository and configuring the necessary files for seamless integration with the Apache HTTP Server.

The installer can also be run non-interactively:

```shell
wget -qO- https://raw.githubusercontent.com/Deltik/mod_antiloris/main/install-antiloris.sh | sh -s - --accept-disclaimer
```

#### Tested Platforms

The script has been tested on the following platforms:
- Ubuntu 20.04
- Debian 11

### Pre-Built Module

Pre-built modules might exist on [the project's releases page](https://github.com/Deltik/mod_antiloris/releases).  If the module is available in binary format (`mod_antiloris.so`), you can install it by:

1. Copying `mod_antiloris.so` to your Apache modules folder (`/usr/lib64/apache2/modules/` on some Linux systems) and
2. Adding the following directive to your Apache configuration file (`httpd.conf` or somewhere that is `Include`d like `/etc/apache2/conf.modules.d/mod_antiloris.conf`):
   ```
   LoadModule antiloris_module modules/mod_antiloris.so
   ```

### Compilation with CMake

(`>= 0.7`)

mod_antiloris has more dependencies than in previous versions, but building isn't much harder.  Just make sure you have `cmake` installed in addition to the Apache development tools.  You should also have `git` so that CMake can download the rest of the dependencies automatically.  To be exact:

* _Suggested dependency installation for Debian/Ubuntu:_
  `apt install -y apache2-dev cmake git`
* _Suggested dependency installation for RHEL/CentOS:_
  * With `dnf`: `dnf install -y epel-release && dnf install -y gcc /usr/bin/apxs make cmake3 git`
  * With `yum`: `yum install -y epel-release && yum install -y gcc /usr/bin/apxs make cmake3 git`
* _Suggested dependency installation for Fedora:_
  `dnf install -y gcc /usr/bin/apxs make cmake git redhat-rpm-config`

mod_antiloris is most easily installed by running these commands on your Apache server:

```
git clone https://github.com/Deltik/mod_antiloris.git
cd mod_antiloris

# Optional: git checkout "v${ANTILORIS_VERSION}"
# Replace ${ANTILORIS_VERSION} with the desired version of this software.

# RHEL/CentOS 6 and 7 compatibility
if type cmake3 > /dev/zero 2>&1; then alias cmake="cmake3"; fi

cmake .
make
apxs -i -a -n antiloris mod_antiloris.so
```

The output of the `apxs` command shows where the module was installed, so you can use that information to uninstall the module, if desired.

### Compilation of Older Versions

(`< 0.7`)

mod_antiloris is most easily installed by copying or downloading the source code to your Apache server and running the following command:

```
apxs -a -i -c mod_antiloris.c
```

The output of the command shows where the module was installed, so you can use that information to uninstall the module, if desired.

## Usage

mod_antiloris works best in combination with [mod_reqtimeout](https://httpd.apache.org/docs/trunk/mod/mod_reqtimeout.html), because:

* mod_reqtimeout drops connections if they are too slow but is vulnerable when a client opens a lot of connections and prevents legitimate connections during the timeout period.
* mod_antiloris prevents a client from hogging up connection slots but does not drop slow connections.

Using both modules at the same time protects against both kinds of DoS offenders.

### Example Mitigation

```
LoadModule reqtimeout_module modules/mod_reqtimeout.so
<IfModule mod_reqtimeout>
    RequestReadTimeout header=20-40,MinRate=500 body=20-40,MinRate=500
</IfModule>

LoadModule antiloris_module modules/mod_antiloris.so
<IfModule antiloris_module>
    IPTotalLimit 16
    LocalIPs     127.0.0.1 ::1
</IfModule>
```

The above example mitigates Slowloris DoS attacks by:

* Using mod_reqtimeout to drop connections that don't meet the data transfer rate requirement and
* Using mod_antiloris to prevent more than 16 concurrent connections from the same IP.

## Configuration

| Directive | Default | Description | [Version](#versioning) |
| --- | --- | --- | --- |
| `IPTotalLimit` | `30` | Maximum simultaneous connections in any state per IP address. If set to `0`, this limit does not apply. This limit takes precedence over all other limits. | `>= 0.7` |
| `IPOtherLimit` | `10` | Maximum simultaneous idle connections per IP address. If set to `0`, this limit does not apply. | `>= 0.6` |
| `IPReadLimit` | `10` | Maximum simultaneous connections in READ state per IP address. If set to `0`, this limit does not apply. | `>= 0.6` |
| `IPWriteLimit` | `10` | Maximum simultaneous connections in WRITE state per IP address. If set to `0`, this limit does not apply. | `>= 0.6` |
| `WhitelistIPs` | _none_ | Space-delimited list of [IPv4 and IPv6 addresses, ranges, or CIDRs](#ip-addresses) which should not be subjected to any limits by this module.  This directive overrides the value of the `LocalIPs` directive. | `>= 0.7` |

### Directives from Older Versions

These directives no longer apply to the latest version of this module:

| Directive | Default | Description | [Version](#versioning) |
| --- | --- | --- | --- |
| `IPReadLimit` | `10` | Maximum simultaneous connections in READ state per IP address. If set to `0`, this limit does not apply. | `>= 0.1, < 0.5.2` |
| `IPReadLimit` | `20` | Maximum simultaneous connections in READ state per IP address. If set to `0`, this limit does not apply. | `= 0.5.2` |
| `LocalIPs` | _none_ | List of IPs (separated by spaces), the connections of which are always allowed (not subjected to any limits) | `~> 0.6.0` |

### Aliases

| Directive Alias | Directive | [Version](#versioning) |
| --- | --- | --- |
| `LocalIPs` | `WhitelistIPs` | `>= 0.7` |

### Configuration Examples

(`>= 0.6`) Allows 10 open connections in each state for a total of 30 concurrent connections per IP address,
and ignores limits for IP addresses `127.0.0.1` and `::1`:

```
LoadModule antiloris_module modules/mod_antiloris.so
<IfModule antiloris_module>
    IPOtherLimit 10
    IPReadLimit  10
    IPWriteLimit 10
    LocalIPs     127.0.0.1 ::1
</IfModule>
```

(`>= 0.7`) Per IP address, allows 8 open connections in each state, but no more than 16 connections of any state:

```
LoadModule antiloris_module modules/mod_antiloris.so
<IfModule antiloris_module>
    IPTotalLimit 16
    IPOtherLimit 8
    IPReadLimit  8
    IPWriteLimit 8
</IfModule>
```

(`>= 0.7`) Default mitigation settings, but exclude [Cloudflare IP addresses](https://www.cloudflare.com/ips/) and localhost IP addresses:

```
LoadModule antiloris_module modules/mod_antiloris.so
<IfModule antiloris_module>
    WhitelistIPs 127.0.0.1 ::1 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/12 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32
</IfModule>
```

## Syntax

### IP Addresses

For directives that accept IP addresses, this module matches IPv4 and IPv6 addresses in the form of:
* (`>= 0.6`) Individual addresses (e.g. `127.0.0.1` matches only `127.0.0.1`),
* (`>= 0.7`) Hyphenated ranges (e.g. `127.0.1.1-127.0.1.3` matches `127.0.1.1`, `127.0.1.2`, and `127.0.1.3`), or
* (`>= 0.7`) CIDR notation (e.g. `127.0.2.0/30` matches `127.0.2.0`, `127.0.2.1`, `127.0.2.2`, and `127.0.2.3`).

#### Examples

Here are more examples:

* `127.0.0.1` matches the individual IPv4 address `127.0.0.1`.
* `192.168.0.100-192.168.0.200` inclusively matches the IPv4 range `192.168.0.100` to `192.168.0.200`.
* `10.0.0.0/8` inclusively matches the IPv4 range from `10.0.0.0` to `10.255.255.255`.
* `::1` matches the individual IPv6 address `0:0:0:0:0:0:0:0001`.
* `::ffff:ac10:0-::ffff:ac10:8` inclusively matches the IPv6 range `0:0:0:0:0:ffff:ac10:0` to `0:0:0:0:0:ffff:ac10:8`.
* `FD12:3456:789A:1::/64` inclusively matches the IPv6 range `fd12:3456:789a:0001:0:0:0:0` to `fd12:3456:789a:0001:ffff:ffff:ffff:ffff`.

### Versioning

This software uses [Semantic Versioning](https://semver.org/).  From a version number `MAJOR.MINOR.PATCH`:

* `MAJOR` increases when behavior changes that breaks how previous versions worked,
* `MINOR` increases when new features are added while being compatible with how previous versions worked, and
* `PATCH` increases when bugs are fixed without breaking how previous versions worked.

In the documentation, version constraints are used to indicate to which versions the piece of documentation applies:

* `>=` means starting from this version,
* `>` means after this version,
* `<=` means up to and including this version,
* `<` means up to but not including this version,
* `=` means this version only, and
* [`~>`](https://thoughtbot.com/blog/rubys-pessimistic-operator) means this version and any newer versions after the last point (`.`).

#### Examples

* `>= 1.5` matches version `1.5.0` and higher.
* `> 1.4` matches version `1.4.1` and higher.
* `<= 1.3.1` matches version `1.3.1`, `1.3.0`, `1.3`, and lower.
* `< 1.4` matches any version lower than `1.4`.
* `= 1.0` matches version `1.0` and `1.0.0`.
* `~> 1.4` is the same as `>= 1.4, < 2`.
* `~> 1.3.0` is the same as `>= 1.3.0, < 1.4`.
* `~> 2` is the same as `>= 2.0.0`.
* `= 1.0, = 1.1, = 1.2, = 1.3` matches only versions `1.0`, `1.1`, `1.2`, `1.3`, and their `.0` `PATCH` versions.

## Backwards Compatibility

This module is a fork of [NewEraCracker's mod_antiloris](https://gist.github.com/NewEraCracker/e545f0dcf64ba816d49b), which itself is a fork of [mind04's mod_antiloris](https://mod-antiloris.sourceforge.io/).

mod_antiloris versions `< 1` are intended to be backwards-compatible with both upstream projects, but the default directive values may have changed.

## Comparison with Other Mitigation Strategies

### mod_antiloris vs. [mod_reqtimeout](https://httpd.apache.org/docs/trunk/mod/mod_reqtimeout.html)

mod_reqtimeout effectively kicks slow connections, but it does not prevent those connections from being made in the first place.  This means that during mod_reqtimeout's timeout grace period, Apache's connection slots can be filled up.

mod_antiloris prevents too many slow connections made from one client.  This addresses the drawback of mod_reqtimeout.  For the best DoS mitigation, **[mod_antiloris should be combined with mod_reqtimeout](#usage)**.

### mod_antiloris vs. [mod_qos](http://mod-qos.sourceforge.net/)

At the time of writing, mod_qos only works on Apache 2.2 with [MPM worker](https://httpd.apache.org/docs/2.2/mod/worker.html).  mod_qos is probably better than mod_antiloris on Apache 2.2 and MPM worker, but **it seems to be broken on newer Apache major versions and on other MPMs**.

### mod_antiloris vs. [mod_noloris](http://svn.apache.org/viewvc/httpd/httpd/trunk/modules/experimental/mod_noloris.c)

mod_noloris is based on mod_antiloris `= 0.3`, but it runs an IP ban check on a (default) 10-second timer instead of on every request like in mod_antiloris.  **This leaves a window of time for a Slowloris DoS to make Apache unresponsive.**

mod_noloris also has other drawbacks:

* Banned IPs are not unbanned until the server is restarted, which means legitimate requests can be banned indefinitely if the client is sufficiently unlucky.
* Only connections in the `SERVER_BUSY_READ` state are counted, so variant Slowloris attacks using a different state would be immune to mitigations.
* A more clever Slowloris attacker can anticipate the timer to make their attack invisible to mod_noloris.
* Banned IPs are scanned sequentially on every request (linear time) instead of looked up in a hash table (constant time).  The bigger the banlist, the larger the performance penalty upon every request, even if the request is legitimate.

Although mod_noloris in theory consumes less time and resources on every request (if the banlist is empty) due to the deferred connection scan, the savings are negligible.  On a test server with 1000 connection slots, mod_antiloris `= 0.7.0` caused connections to be established 0.0000229 seconds slower on average.  The test was conducted by requesting a static TXT file 10000 times with 10 concurrent requests of `curl -w "%{time_connect}"`.  Data summary:

|Slowloris mitigation|N|min|q1|median|q3|max|mean|stddev|
|---|---|---|---|---|---|---|---|---|
|_none_|10000|0.004141|0.004209|0.004231|0.004266|0.018902|0.00464977|0.0016542|
|mod_antiloris `= 0.7.0`|10000|0.004143|0.004209|0.004232|0.004267|0.018475|0.00467267|0.00169251|

### mod_antiloris vs. [ModSecurity](https://www.modsecurity.org/)

ModSecurity depends on other sources to decide whether to block a connection.  At the time of writing, the OWASP ModSecurity Core Rule Set V3.0 has a rule to block too many requests to dynamic resources, but **there is nothing by default to block Slowloris specifically**.

It is possible to use the HTTP 408 returned by mod_reqtimeout to increment a denial-of-service counter in ModSecurity, but **this suffers from the same drawbacks as mod_reqtimeout**.

### mod_antiloris vs. [mod_evasive](https://github.com/jzdziarski/mod_evasive)

**mod_evasive does nothing to mitigate Slowloris.**  It is designed to return HTTP 403 to the client if the client makes too many requests, but it assumes that the client is willing to receive the response.  Slowloris, of course, doesn't, so the connection slots remain occupied.

### mod_antiloris vs. [mod_limitipconn](https://dominia.org/djao/limitipconn2.html)

mod_limitipconn is conceptually similar to mod_antiloris, but **mod_limitipconn hooks too late and can't mitigate Slowloris**.  It is designed to return HTTP 503 to the client if the client makes too many connections, but it assumes that the client is willing to receive the response.  Slowloris, of course, doesn't, so the connection slots remain occupied.

## Testing

(`>= 0.7`)

After generating the build files from `cmake`, tests can simply be run with this command:

```
make test
```

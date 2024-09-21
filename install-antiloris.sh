#!/bin/sh

#
# mod_antiloris installation script
#
# Copyright (C) 2023 Filippo Lauria
# Copyright (C) 2023-2024 Deltik <https://www.deltik.net/>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e

REPO_URL="https://github.com/Deltik/mod_antiloris.git"
TAG_SOURCE_URL="https://api.github.com/repos/Deltik/mod_antiloris/tags"
RELEASE_URL_TEMPLATE="https://github.com/Deltik/mod_antiloris/releases/download/{VERSION}/mod_antiloris-{ARCH}.so"

TEMP_DIR=""
INSTALLED_PACKAGES=""
ARCH=""
APACHE_SERVICE=""
PACKAGE_MANAGER=""
OS_FAMILY=""
APACHE_DEV_PACKAGE=""
APACHE_PACKAGE=""

usage() {
	cat <<EOF
usage: $0 [-h] [--version VERSION] [-y] [--uninstall] [--color | --no-color] [-v]

Installs mod_antiloris on an existing Apache HTTP Server

options:
  -h, --help                show this help message and exit
  --version VERSION         install the version from a tag (e.g. "v0.8.1"), branch (e.g. "main"),
                            or revision (e.g. "042be13") rather than the latest release
  -y, --accept-disclaimer   bypass the disclaimer prompt
  --uninstall               uninstall mod_antiloris and remove its configuration
  --color                   show pretty colors in the output (default if run in a terminal)
  --no-color                don't add colors to the output
  -v, --verbose, --debug    show debug information
EOF
}

COLORS_ENABLED='yes'
if [ ! -t 1 ]; then COLORS_ENABLED=''; fi

# Reset
Color_Off='\e[0m' # Text Reset

# Regular Colors
Black='\e[0;30m'  # Black
Red='\e[0;31m'    # Red
Green='\e[0;32m'  # Green
Yellow='\e[0;33m' # Yellow
Blue='\e[0;34m'   # Blue
Purple='\e[0;35m' # Purple
Cyan='\e[0;36m'   # Cyan
White='\e[0;37m'  # White

# Bold
BBlack='\e[1;30m'  # Black
BRed='\e[1;31m'    # Red
BGreen='\e[1;32m'  # Green
BYellow='\e[1;33m' # Yellow
BBlue='\e[1;34m'   # Blue
BPurple='\e[1;35m' # Purple
BCyan='\e[1;36m'   # Cyan
BWhite='\e[1;37m'  # White

# Underline
UBlack='\e[4;30m'  # Black
URed='\e[4;31m'    # Red
UGreen='\e[4;32m'  # Green
UYellow='\e[4;33m' # Yellow
UBlue='\e[4;34m'   # Blue
UPurple='\e[4;35m' # Purple
UCyan='\e[4;36m'   # Cyan
UWhite='\e[4;37m'  # White

# Background
On_Black='\e[40m'  # Black
On_Red='\e[41m'    # Red
On_Green='\e[42m'  # Green
On_Yellow='\e[43m' # Yellow
On_Blue='\e[44m'   # Blue
On_Purple='\e[45m' # Purple
On_Cyan='\e[46m'   # Cyan
On_White='\e[47m'  # White

# High Intensity
IBlack='\e[0;90m'  # Black
IRed='\e[0;91m'    # Red
IGreen='\e[0;92m'  # Green
IYellow='\e[0;93m' # Yellow
IBlue='\e[0;94m'   # Blue
IPurple='\e[0;95m' # Purple
ICyan='\e[0;96m'   # Cyan
IWhite='\e[0;97m'  # White

# Bold High Intensity
BIBlack='\e[1;90m'  # Black
BIRed='\e[1;91m'    # Red
BIGreen='\e[1;92m'  # Green
BIYellow='\e[1;93m' # Yellow
BIBlue='\e[1;94m'   # Blue
BIPurple='\e[1;95m' # Purple
BICyan='\e[1;96m'   # Cyan
BIWhite='\e[1;97m'  # White

# High Intensity backgrounds
On_IBlack='\e[0;100m'  # Black
On_IRed='\e[0;101m'    # Red
On_IGreen='\e[0;102m'  # Green
On_IYellow='\e[0;103m' # Yellow
On_IBlue='\e[0;104m'   # Blue
On_IPurple='\e[0;105m' # Purple
On_ICyan='\e[0;106m'   # Cyan
On_IWhite='\e[0;107m'  # White

_pretty_print() { printf "%s\n" "$1" >&2; }
success() { _pretty_print "[=] $1"; }
info() { _pretty_print "[+] $1"; }
warn() { _pretty_print "[*] $1"; }
error() { _pretty_print "[!] $1"; }
crit() { _pretty_print "[#] $1"; }
debug() { [ -z "$VERBOSE" ] || _pretty_print "[-] $1"; }
prompt() {
	printf "[?] %s" "$1" >&2
	read -r "$2"
}

enable_color_output() {
	_pretty_print() { printf "%b${Color_Off}\n" "$1" >&2; }
	success() { _pretty_print "${BGreen}[=]${Green} $1"; }
	info() { _pretty_print "${BWhite}[+]${White} $1"; }
	warn() { _pretty_print "${BYellow}[*]${Yellow} $1"; }
	error() { _pretty_print "${BRed}[!]${Red} $1"; }
	crit() { _pretty_print "${On_Red}[#] $1"; }
	debug() { [ -z "$VERBOSE" ] || _pretty_print "${Cyan}[-] $1"; }
	prompt() {
		printf "%b[?]%b %b" "${BBlue}" "${Blue}" "$1${Color_Off}" >&2
		read -r "$2"
	}
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
		-h | --help)
			usage
			exit 0
			;;
		--version)
			shift
			DESIRED_VERSION="$1"
			;;
		-y | --accept-disclaimer)
			ACCEPT_DISCLAIMER="--accept-disclaimer"
			;;
		--uninstall)
			UNINSTALL="yes"
			;;
		--color)
			COLORS_ENABLED='yes'
			;;
		--no-color)
			COLORS_ENABLED=''
			;;
		-v | --debug | --verbose)
			VERBOSE='yes'
			;;
		*)
			error "Unknown option: $1"
			usage
			exit 1
			;;
		esac
		shift
	done

	if [ -n "$COLORS_ENABLED" ]; then
		enable_color_output
	fi
}

ensure_root() {
	if [ "$(id -u)" -ne 0 ]; then
		if command -v sudo >/dev/null 2>&1; then
			warn "This script needs to be run as root. Elevating script to root with sudo."
			interpreter="$(head -1 "$0" | cut -c 3-)"
			if [ -x "$interpreter" ]; then
				exec sudo "$interpreter" "$0" "$@"
			else
				exec sudo "$0" "$@"
			fi
		else
			crit "This script needs to be run as root."
			exit 1
		fi
	fi
}

get_os_family() {
	if [ -f /etc/os-release ]; then
		. /etc/os-release
		case $ID in
		debian | ubuntu)
			OS_FAMILY="debian"
			;;
		rhel | centos | almalinux | rocky | fedora)
			OS_FAMILY="rhel"
			;;
		*)
			OS_FAMILY="unknown"
			;;
		esac
	else
		OS_FAMILY="unknown"
	fi
}

get_package_manager() {
	case $OS_FAMILY in
	debian)
		PACKAGE_MANAGER="apt-get"
		;;
	rhel)
		if command -v dnf >/dev/null 2>&1; then
			PACKAGE_MANAGER="dnf"
		else
			PACKAGE_MANAGER="yum"
		fi
		;;
	*)
		PACKAGE_MANAGER="unknown"
		;;
	esac
}

get_cmake_command() {
	if [ "$OS_FAMILY" = "rhel" ] && command -v cmake3 >/dev/null 2>&1; then
		CMAKE_COMMAND="cmake3"
	else
		CMAKE_COMMAND="cmake"
	fi
}

get_architecture() {
	ARCH=$(uname -m)
	case "$ARCH" in
	x86_64)
		ARCH="x86_64"
		;;
	i386 | i686)
		ARCH="i386"
		;;
	armv7* | armv6*)
		ARCH="arm"
		;;
	aarch64)
		ARCH="aarch64"
		;;
	ppc64le)
		ARCH="ppc64le"
		;;
	s390x)
		ARCH="s390x"
		;;
	*)
		warn "Unknown system architecture: $ARCH"
		ARCH=""
		;;
	esac
}

detect_os() {
	get_os_family
	get_package_manager
	get_cmake_command
	get_architecture

	case $OS_FAMILY in
	debian)
		APACHE_PACKAGE="apache2"
		APACHE_DEV_PACKAGE="apache2-dev"
		APACHE_SERVICE="apache2"
		PATH_OF_MODAVAIL_DIR='/etc/apache2/mods-available'
		PATH_OF_MODENABL_DIR='/etc/apache2/mods-enabled'
		PATH_OF_LOADFILE="${PATH_OF_MODAVAIL_DIR}/antiloris.load"
		PATH_OF_CONFFILE="${PATH_OF_MODAVAIL_DIR}/antiloris.conf"
		PATH_OF_LOADLINK="${PATH_OF_MODENABL_DIR}/antiloris.load"
		PATH_OF_CONFLINK="${PATH_OF_MODENABL_DIR}/antiloris.conf"
		;;
	rhel)
		APACHE_PACKAGE="httpd"
		APACHE_DEV_PACKAGE="httpd-devel"
		APACHE_SERVICE="httpd"
		PATH_OF_MODAVAIL_DIR='/etc/httpd/conf.modules.d'
		PATH_OF_LOADFILE="${PATH_OF_MODAVAIL_DIR}/10-antiloris.conf"
		PATH_OF_CONFFILE="/etc/httpd/conf.d/antiloris.conf"
		;;
	*)
		crit "This script does not support your operating system."
		exit 1
		;;
	esac
}

get_module_path() {
	case $OS_FAMILY in
	debian)
		if command -v a2query >/dev/null 2>&1; then
			MODULE_PATH="$(a2query -d)"
		else
			MODULE_PATH="/usr/lib/apache2/modules/"
		fi
		;;
	rhel)
		MODULE_PATH="/usr/lib64/httpd/modules"
		;;
	esac
}

install_packages() {
	# Usage: install_packages pkg1 pkg2 pkg3
	# Installs the given packages if they are not already installed.
	# Adds installed packages to INSTALLED_PACKAGES
	packages_to_install=""
	for pkg in "$@"; do
		case $PACKAGE_MANAGER in
		apt-get)
			if ! dpkg -s "$pkg" >/dev/null 2>&1; then
				packages_to_install="$packages_to_install $pkg"
			fi
			;;
		dnf | yum)
			if ! rpm -q "$pkg" >/dev/null 2>&1; then
				packages_to_install="$packages_to_install $pkg"
			fi
			;;
		esac
	done

	if [ -n "$packages_to_install" ]; then
		info "Installing packages:$packages_to_install"
		set -- $packages_to_install
		if ! $PACKAGE_MANAGER install -y "$@"; then
			warn "Installation failed. Updating package lists and retrying..."
			$PACKAGE_MANAGER update
			if ! $PACKAGE_MANAGER install -y "$@"; then
				crit "Failed to install dependencies."
				exit 1
			fi
		fi
		case $PACKAGE_MANAGER in
		apt-get)
			apt-mark auto "$@"
			;;
		dnf | yum)
			INSTALLED_PACKAGES="$INSTALLED_PACKAGES $packages_to_install"
			;;
		esac
	else
		info "All required packages are already installed."
	fi
}

install_minimal_dependencies() {
	info "Checking and installing minimal dependencies..."
	install_packages wget file
}

install_build_dependencies() {
	info "Checking and installing build dependencies..."
	install_packages $APACHE_DEV_PACKAGE cmake git gcc make
}

get_all_tags() {
	debug "Retrieving tags from ${TAG_SOURCE_URL} . . ."
	tags=$(wget -qO- "${TAG_SOURCE_URL}")
	echo "${tags}" | tr '},' '\n' | grep '"name":' | awk -F'"' '{ print $4 }' | sort -Vr
}

get_latest_version() {
	all_tags="$(get_all_tags)"
	debug "All tags: $(echo "${all_tags}" | tr '\n' ' ')"

	for tag in ${all_tags}; do
		debug "Checking tag ${tag} for architecture-specific binary (${ARCH}) . . ."
		release_url=$(echo "${RELEASE_URL_TEMPLATE}" | sed "s/{VERSION}/${tag}/g" | sed "s/{ARCH}/${ARCH}/g")
		http_code=$(wget --spider --server-response "${release_url}" 2>&1 | awk '/^  HTTP/{print $2}' | tail -n 1)

		if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
			info "Found architecture-specific binary for tag ${tag} (${ARCH})"
			echo "${tag}"
			return
		else
			debug "No architecture-specific binary found for tag ${tag}"
		fi

		debug "Checking tag ${tag} for generic binary . . ."
		generic_release_url=$(echo "${RELEASE_URL_TEMPLATE}" | sed "s/{VERSION}/${tag}/g" | sed "s/-{ARCH}//g")
		http_code=$(wget --spider --server-response "${generic_release_url}" 2>&1 | awk '/^  HTTP/{print $2}' | tail -n 1)

		if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
			info "Found generic binary for tag ${tag}"
			echo "${tag}"
			return
		else
			debug "No generic binary found for tag ${tag}"
		fi
	done

	crit "No suitable binary found for any tags."
	return 1
}

check_binary_architecture() {
	binary="$1"
	if ! command -v file >/dev/null 2>&1; then
		warn "Cannot check binary architecture because 'file' command is not available."
		return 1
	fi

	binary_arch=$(file -b "$binary" | grep -oE 'x86[-_ ]64|i[3-6]86|arm|aarch64|ppc64le|s390x')
	debug "Binary architecture: $binary_arch"
	debug "Expected architecture: $ARCH"

	case "$ARCH" in
	x86_64)
		ARCH="x86-64"
		;;
	i386 | i686)
		ARCH="i386"
		;;
	armv7* | armv6*)
		ARCH="arm"
		;;
	aarch64)
		ARCH="aarch64"
		;;
	ppc64le)
		ARCH="ppc64le"
		;;
	s390x)
		ARCH="s390x"
		;;
	*)
		warn "Unknown system architecture: $ARCH"
		return 1
		;;
	esac

	if echo "$binary_arch" | grep -qi "$ARCH"; then
		return 0
	else
		warn "Binary architecture ($binary_arch) does not match expected architecture ($ARCH)."
		return 1
	fi
}

install_binary_module() {
	binary="$1"
	get_module_path
	module_path="${MODULE_PATH%/}/mod_antiloris.so"

	if [ -f "$module_path" ]; then
		warn "Overwriting existing module at $module_path"
	fi

	info "Copying module to $module_path"
	cp "$binary" "$module_path"

	# Create LoadModule directive if necessary
	case $OS_FAMILY in
	debian)
		echo "LoadModule antiloris_module $module_path" >"$PATH_OF_LOADFILE"
		;;
	rhel)
		echo "LoadModule antiloris_module modules/mod_antiloris.so" >"$PATH_OF_LOADFILE"
		;;
	esac
}

download_module() {
	if [ -z "$DESIRED_VERSION" ]; then
		info "Getting the latest version of the antiloris module . . ."
		DESIRED_VERSION="$(get_latest_version)"
		info "Latest version determined: ${DESIRED_VERSION}"
	fi

	# Try downloading architecture-specific binary
	RELEASE_URL="$(echo "${RELEASE_URL_TEMPLATE}" | sed "s/{VERSION}/${DESIRED_VERSION}/g" | sed "s/{ARCH}/${ARCH}/g")"

	TMP="$(mktemp)"
	info "Downloading the antiloris module for architecture ${ARCH} . . ."
	if ! wget -q "${RELEASE_URL}" -O "${TMP}" || [ ! -f "${TMP}" ]; then
		warn "Failed to download the antiloris module for architecture ${ARCH}."

		# Fallback to generic binary
		RELEASE_URL="$(echo "${RELEASE_URL_TEMPLATE}" | sed "s/{VERSION}/${DESIRED_VERSION}/g" | sed "s/-{ARCH}//g")"
		info "Attempting to download generic antiloris module . . ."
		if ! wget -q "${RELEASE_URL}" -O "${TMP}" || [ ! -f "${TMP}" ]; then
			warn "Failed to download the generic antiloris module."
			return 1
		fi
	fi

	if ! check_binary_architecture "${TMP}"; then
		warn "Downloaded binary is not compatible with your system."
		return 1
	fi

	info "Installing the antiloris module . . ."
	install_binary_module "${TMP}"
	return 0
}

clone_repository() {
	info "Cloning mod_antiloris repository..."
	TEMP_DIR="$(mktemp -d)"

	(
		set -e

		if [ -n "$DESIRED_VERSION" ]; then
			if git ls-remote --refs --heads --tags "$REPO_URL" "$DESIRED_VERSION" | grep -q "$DESIRED_VERSION"; then
				git clone --depth 1 --branch "$DESIRED_VERSION" "$REPO_URL" "$TEMP_DIR"
			else
				git clone --no-checkout --depth 1 "$REPO_URL" "$TEMP_DIR"
				git -C "$TEMP_DIR" fetch --depth 1 origin "$DESIRED_VERSION"
				git -C "$TEMP_DIR" checkout "$DESIRED_VERSION"
			fi
		else
			git clone --depth 1 "$REPO_URL" "$TEMP_DIR"
		fi
	) || {
		crit "Error cloning the mod_antiloris repository."
		exit 1
	}
}

build_module() {
	info "Building mod_antiloris..."
	cd "$TEMP_DIR"
	$CMAKE_COMMAND . || {
		warn "Failed to run CMake. Trying to force compatibility with CMake 3.9..."
		git -C "$(git rev-parse --show-toplevel)/lib/check" checkout 0.13.0 &&
			$CMAKE_COMMAND .
	}
	make mod_antiloris
}

install_compiled_module() {
	info "Installing compiled mod_antiloris..."
	get_module_path
	case $OS_FAMILY in
	debian)
		apxs -i -a -n antiloris mod_antiloris.so
		;;
	rhel)
		cp mod_antiloris.so "${MODULE_PATH%/}/mod_antiloris.so"
		echo "LoadModule antiloris_module modules/mod_antiloris.so" >"$PATH_OF_LOADFILE"
		;;
	esac
}

create_config() {
	info "Creating configuration file..."
	if [ ! -f "$PATH_OF_CONFFILE" ] || [ ! -s "$PATH_OF_CONFFILE" ]; then
		cat <<EOF >"$PATH_OF_CONFFILE"
<IfModule antiloris_module>
    # Maximum simultaneous connections in any state per IP address.
    # If set to 0, this limit does not apply.
    IPTotalLimit      30

    # Maximum simultaneous idle connections per IP address.
    # If set to 0, this limit does not apply.
    IPOtherLimit      10

    # Maximum simultaneous connections in READ state per IP address.
    # If set to 0, this limit does not apply.
    IPReadLimit       10

    # Maximum simultaneous connections in WRITE state per IP address.
    # If set to 0, this limit does not apply.
    IPWriteLimit      10

    # Space-delimited list of IPv4 and IPv6 addresses, ranges, or CIDRs
    # which should not be subjected to any limits by this module.
    # ExemptIPs    127.0.0.1 ::1
</IfModule>
EOF
	else
		info "Configuration file already exists. Skipping creation."
	fi
}

enable_module() {
	info "Enabling mod_antiloris..."
	case $OS_FAMILY in
	debian)
		a2enmod antiloris
		;;
	rhel)
		# Module is enabled by default when LoadModule directive is present
		;;
	esac
}

check_config() {
	info "Checking Apache configuration..."
	case $OS_FAMILY in
	debian)
		apache2ctl configtest
		;;
	rhel)
		apachectl configtest
		;;
	esac
}

restart_apache() {
	info "Restarting Apache..."
	systemctl restart $APACHE_SERVICE
}

uninstall() {
	info "Uninstalling mod_antiloris..."
	get_module_path
	case $OS_FAMILY in
	debian)
		a2dismod antiloris || warn "Failed to disable mod_antiloris"
		;;
	rhel)
		# No specific disable command for RHEL, just remove files
		;;
	esac
	rm -f "${MODULE_PATH%/}/mod_antiloris.so" "$PATH_OF_LOADFILE" "$PATH_OF_CONFFILE" ||
		warn "Failed to remove some mod_antiloris files"
	systemctl restart $APACHE_SERVICE || warn "Failed to restart Apache"
	success "mod_antiloris uninstalled successfully."
	exit 0
}

cleanup() {
	info "Cleaning up..."
	[ -n "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"
	if [ -n "$INSTALLED_PACKAGES" ] && { [ "$PACKAGE_MANAGER" = "dnf" ] || [ "$PACKAGE_MANAGER" = "yum" ]; }; then
		info "Removing automatically installed packages..."
		set -- $INSTALLED_PACKAGES
		$PACKAGE_MANAGER remove -y "$@"
	fi
}

check_disclaimer() {
	if [ "$ACCEPT_DISCLAIMER" != "--accept-disclaimer" ]; then
		cat <<EOF >&2

[!] DISCLAIMER

    This script will install mod_antiloris from a pre-built binary (if available) or compile it from source.
    It will make changes to your Apache configuration.
    Please ensure you have a backup before proceeding.

    To bypass this prompt, use the --accept-disclaimer option.

EOF
		prompt "Do you want to continue? [yes/no]: " ACCEPT_DISCLAIMER
		case $ACCEPT_DISCLAIMER in
		yes | YES | Yes) ;;
		*) exit 1 ;;
		esac
	fi
}

main() {
	parse_args "$@"
	ensure_root "$@"
	detect_os

	trap cleanup EXIT

	if [ "$UNINSTALL" = "yes" ]; then
		uninstall
	fi

	check_disclaimer
	install_minimal_dependencies

	if ! download_module; then
		warn "Proceeding to compile from source as fallback."
		install_build_dependencies
		clone_repository
		build_module
		install_compiled_module
	fi

	create_config
	enable_module
	check_config
	restart_apache

	success "mod_antiloris installation completed successfully."
}

main "$@"

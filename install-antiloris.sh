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

TAG_SOURCE_URL="https://api.github.com/repos/Deltik/mod_antiloris/tags"
RELEASE_URL_TEMPLATE="https://github.com/Deltik/mod_antiloris/releases/download/{VERSION}/mod_antiloris.so"

usage() {
  cat <<EOF
usage: $0 [-h] [--version VERSION] [-y] [--uninstall] [--color | --no-color] [-v]

Installs mod_antiloris on an existing Apache HTTP Server

options:
  -h, --help                show this help message and exit
  --version VERSION         install the named version (e.g. "v0.7.0") rather than the latest version
  -y, --accept-disclaimer   bypass the disclaimer prompt
  --uninstall               uninstall mod_antiloris and remove its configuration
  --color                   show pretty colors in the output (default if run in a terminal)
  --no-color                don't add colors to the output
  -v, --verbose, --debug    show debug information
EOF
}

get_all_tags() {
  debug "Retrieving tags from ${TAG_SOURCE_URL} . . ."
  tags=$(wget -qO- "${TAG_SOURCE_URL}")
  echo "${tags}" | tr '},' '\n' | grep '"name":' | awk '{ print substr($2, 2, length($2)-2)}' | sort -Vr
}

get_latest_version() {
  all_tags="$(get_all_tags)"
  debug "All tags: $(echo "${all_tags}" | tr '\n' ' ')"

  for tag in ${all_tags}; do
    debug "Checking tag ${tag} . . ."
    release_url=$(echo "${RELEASE_URL_TEMPLATE}" | sed "s/{VERSION}/${tag}/g")
    http_code=$(wget --server-response -O /dev/null "${release_url}" 2>&1 | awk '/^  HTTP/{print $2}' | tail -n 1)
    if [ "$http_code" -lt 200 ] || [ "$http_code" -gt 299 ]; then
      debug "Tag ${tag} does not have a matching asset"
      continue
    else
      echo "${tag}"
      return
    fi
  done
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
        sudo "$interpreter" "$0" "$@"
      else
        sudo "$0" "$@"
      fi
      exit $?
    else
      crit "This script needs to be run as root."
      exit 1
    fi
  fi
}

detect_os() {
  OS=$(cat /etc/*-release | grep '^ID=' | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
  case $OS in
  debian | ubuntu)
    PATH_OF_MODULE="$(a2query -d)mod_antiloris.so"
    PATH_OF_MODAVAIL_DIR='/etc/apache2/mods-available'
    PATH_OF_MODENABL_DIR='/etc/apache2/mods-enabled'
    PATH_OF_LOADFILE="${PATH_OF_MODAVAIL_DIR}/antiloris.load"
    PATH_OF_CONFFILE="${PATH_OF_MODAVAIL_DIR}/antiloris.conf"
    PATH_OF_LOADLINK="${PATH_OF_MODENABL_DIR}/antiloris.load"
    PATH_OF_CONFLINK="${PATH_OF_MODENABL_DIR}/antiloris.conf"
    ;;
  *)
    crit "This script does not support the ${OS} operating system."
    exit 1
    ;;
  esac
}

uninstall() {
  info "Uninstalling mod_antiloris . . ."

  if [ -L "${PATH_OF_LOADLINK}" ]; then
    debug "Removing antiloris.load symlink . . ."
    rm -f "${PATH_OF_LOADLINK}"
  fi

  if [ -L "${PATH_OF_CONFLINK}" ]; then
    debug "Removing antiloris.conf symlink . . ."
    rm -f "${PATH_OF_CONFLINK}"
  fi

  if [ -f "${PATH_OF_MODULE}" ]; then
    debug "Removing mod_antiloris.so . . ."
    rm -f "${PATH_OF_MODULE}"
  fi

  if [ -f "${PATH_OF_LOADFILE}" ]; then
    debug "Removing antiloris.load . . ."
    rm -f "${PATH_OF_LOADFILE}"
  fi

  if [ -f "${PATH_OF_CONFFILE}" ]; then
    debug "Removing antiloris.conf . . ."
    rm -f "${PATH_OF_CONFFILE}"
  fi

  info "Restarting Apache . . ."
  if systemctl restart apache2 2>/dev/null; then
    info "Apache restarted successfully."
  else
    crit "Failed to restart Apache."
    exit 1
  fi

  success "mod_antiloris uninstalled successfully."
  exit 0
}

check_disclaimer() {
  if [ "$ACCEPT_DISCLAIMER" != "--accept-disclaimer" ]; then
    cat <<EOF >&2
    [!] Hint: To avoid answering, you can pass the
              --accept-disclaimer option when launching the script.

EOF
    while [ "$ACCEPT_DISCLAIMER" != "yes" ]; do
      prompt "Are you okay with that? [yes/no]: " ACCEPT_DISCLAIMER

      case $ACCEPT_DISCLAIMER in
      "yes") success "Very good!" ;;
      "no")
        error "Bye."
        exit 1
        ;;
      *)
        warn "You have to answer yes or no."
        ACCEPT_DISCLAIMER=""
        ;;
      esac
    done
  else
    ACCEPT_DISCLAIMER="yes"
    info "Thanks for having accepted the disclaimer."
  fi
}

check_dependencies() {
  APACHE_EXISTS=$(command -v apache2 || command -v httpd)
  if [ -z "${APACHE_EXISTS}" ]; then
    crit "Apache must be installed for this script to work."
    exit 1
  fi

  WGET_EXISTS=$(command -v wget)
  if [ -z "${WGET_EXISTS}" ]; then
    crit "The wget utility must be installed for this script to work."
    exit 1
  fi
}

download_module() {
  if [ -z "$DESIRED_VERSION" ]; then
    info "Getting the latest version of the antiloris module . . ."
    DESIRED_VERSION="$(get_latest_version)"
    info "Latest version determined: ${DESIRED_VERSION}"
  fi

  if [ -z "$RELEASE_URL" ]; then
    RELEASE_URL="$(echo "${RELEASE_URL_TEMPLATE}" | sed "s/{VERSION}/${DESIRED_VERSION}/g")"
  fi

  TMP=$(mktemp -qu)
  info "Downloading the antiloris module . . ."
  if ! wget -q "${RELEASE_URL}" -O "${TMP}" || [ ! -f "${TMP}" ]; then
    crit "Failed to download the antiloris module."
    exit 1
  fi
}

install_module() {
  if [ -f "${PATH_OF_MODULE}" ]; then
    warn "Overwriting another version of the antiloris module . . ."
    rm -f "${PATH_OF_MODULE}"
  fi

  info "Installing the antiloris module . . ."
  mv "${TMP}" "${PATH_OF_MODULE}"
  echo "LoadModule antiloris_module ${PATH_OF_MODULE}" >"${PATH_OF_LOADFILE}"
}

create_config() {
  cat <<EOF >"${PATH_OF_CONFFILE}"
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

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
EOF
}

enable_module() {
  info "Enabling the antiloris module . . ."
  ln -sf "${PATH_OF_LOADFILE}" "${PATH_OF_LOADLINK}"
  ln -sf "${PATH_OF_CONFFILE}" "${PATH_OF_CONFLINK}"
}

check_config() {
  if ! apache2ctl configtest 2>/dev/null; then
    crit "Detected configuration file(s) with invalid syntax."
    error "Check your Apache configuration, then relaunch this script."
    exit 1
  fi
}

restart_apache() {
  info "Restarting Apache . . ."
  if systemctl restart apache2 2>/dev/null; then
    info "Apache restarted successfully."
  else
    crit "Failed to restart Apache."
    exit 1
  fi
}

main() {
  parse_args "$@"
  ensure_root "$@"
  detect_os

  if [ "$UNINSTALL" = "yes" ]; then
    uninstall
  fi

  info "mod_antiloris installation script"
  cat <<EOF >&2

[!] DISCLAIMER

    This script does not perform any backups, and the
    default actions for all files are to overwrite.

    Running this script does not guarantee the successful
    installation of the module, and its author is not
    responsible for any damages that may occur as a
    result of using this script.

EOF

  check_disclaimer
  check_dependencies
  download_module
  install_module
  create_config
  enable_module
  check_config
  restart_apache

  success "Antiloris module installation completed."
}

main "$@"

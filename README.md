**install-antiloris.sh** is a POSIX-compliant script that automates the installation of [mod_antiloris](https://github.com/Deltik/mod_antiloris/), an [Apache HTTP Server](https://httpd.apache.org/) module designed to mitigate [Slowloris](https://en.wikipedia.org/wiki/Slowloris_%28computer_security%29) denial-of-service (DoS) attacks. This script simplifies the installation process by downloading the latest pre-built version from the official repository and configuring the necessary files for seamless integration with the Apache HTTP Server.

## Usage
To install mod_antiloris, follow these steps on your Apache web server host from a terminal with root privileges.

### interactive installation
Execute the following command to launch an interactive installation procedure:
```bash
wget -q https://raw.githubusercontent.com/filippolauria/install-antiloris/master/install-antiloris.sh && chmod +x install-antiloris.sh && ./install-antiloris.sh
```

### non-interactive installation
Execute the following command to launch a non-interactive installation procedure:
```bash
wget -qO- https://raw.githubusercontent.com/filippolauria/install-antiloris/master/install-antiloris.sh | sh -s - --accept-disclaimer
```

## Tested platforms
The script has been tested on the following platforms:
- Ubuntu 20.04
- Debian 11

## Credits
The module was developed by Nick ([Deltik](https://github.com/Deltik)) along with contributions from other developers. You can find the full list of contributors [here](https://github.com/Deltik/mod_antiloris/graphs/contributors).

## Disclaimer
This script does not perform any backups, and the default behavior for all files is to overwrite.

Please note that running this script does not guarantee a successful module installation. The author of the script is not responsible for any damages that may occur as a result of using this script.

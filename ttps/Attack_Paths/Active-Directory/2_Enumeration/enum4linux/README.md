### Usage
```console
usage: enum4linux-ng.py [-h] [-A] [-As] [-U] [-G] [-Gm] [-S] [-C] [-P] [-O] [-L] [-I] [-R [BULK_SIZE]] [-N] [-w DOMAIN] [-u USER]
                        [-p PW | -K TICKET_FILE | -H NTHASH] [--local-auth] [-d] [-k USERS] [-r RANGES] [-s SHARES_FILE] [-t TIMEOUT] [-v] [--keep]
                        [-oJ OUT_JSON_FILE | -oY OUT_YAML_FILE | -oA OUT_FILE]
                        host

This tool is a rewrite of Mark Lowe's enum4linux.pl, a tool for enumerating information from Windows and Samba systems. It is mainly a wrapper around the Samba
tools nmblookup, net, rpcclient and smbclient. Other than the original tool it allows to export enumeration results as YAML or JSON file, so that it can be
further processed with other tools. The tool tries to do a 'smart' enumeration. It first checks whether SMB or LDAP is accessible on the target. Depending on the
result of this check, it will dynamically skip checks (e.g. LDAP checks if LDAP is not running). If SMB is accessible, it will always check whether a session can
be set up or not. If no session can be set up, the tool will stop enumeration. The enumeration process can be interupted with CTRL+C. If the options -oJ or -oY
are provided, the tool will write out the current enumeration state to the JSON or YAML file, once it receives SIGINT triggered by CTRL+C. The tool was made for
security professionals and CTF players. Illegal use is prohibited.

positional arguments:
  host

options:
  -h, --help         show this help message and exit
  -A                 Do all simple enumeration including nmblookup (-U -G -S -P -O -N -I -L). This option is enabled if you don't provide any other option.
  -As                Do all simple short enumeration without NetBIOS names lookup (-U -G -S -P -O -I -L)
  -U                 Get users via RPC
  -G                 Get groups via RPC
  -Gm                Get groups with group members via RPC
  -S                 Get shares via RPC
  -C                 Get services via RPC
  -P                 Get password policy information via RPC
  -O                 Get OS information via RPC
  -L                 Get additional domain info via LDAP/LDAPS (for DCs only)
  -I                 Get printer information via RPC
  -R [BULK_SIZE]     Enumerate users via RID cycling. Optionally, specifies lookup request size.
  -N                 Do an NetBIOS names lookup (similar to nbtstat) and try to retrieve workgroup from output
  -w DOMAIN          Specify workgroup/domain manually (usually found automatically)
  -u USER            Specify username to use (default "")
  -p PW              Specify password to use (default "")
  -K TICKET_FILE     Try to authenticate with Kerberos, only useful in Active Directory environment (Note: DNS must be setup correctly for this option to work)
  -H NTHASH          Try to authenticate with hash
  --local-auth       Authenticate locally to target
  -d                 Get detailed information for users and groups, applies to -U, -G and -R
  -k USERS           User(s) that exists on remote system (default: administrator,guest,krbtgt,domain admins,root,bin,none). Used to get sid with "lookupsids"
  -r RANGES          RID ranges to enumerate (default: 500-550,1000-1050)
  -s SHARES_FILE     Brute force guessing for shares
  -t TIMEOUT         Sets connection timeout in seconds (default: 5s)
  -v                 Verbose, show full samba tools commands being run (net, rpcclient, etc.)
  --keep             Don't delete the Samba configuration file created during tool run after enumeration (useful with -v)
  -oJ OUT_JSON_FILE  Writes output to JSON file (extension is added automatically)
  -oY OUT_YAML_FILE  Writes output to YAML file (extension is added automatically)
  -oA OUT_FILE       Writes output to YAML and JSON file (extensions are added automatically)
```

## Installation
There are multiple ways to install the tool. Either the tool comes as a package with your Linux distribution or you need to do a manual install. 

### Kali Linux
```console
apt install enum4linux-ng 
```

### Archstrike
```console
pacman -S enum4linux-ng
```

### NixOS
(tested on NixOS 20.9)
```console
nix-env -iA nixos.enum4linux-ng
```

## Manual Installation
If your Linux distribution does not offer a package, the following manual installation methods can be used instead.

### Dependencies
The tool uses the samba clients tools, namely:
- nmblookup
- net
- rpcclient
- smbclient

These should be available for all Linux distributions. The package is typically called `smbclient`, `samba-client` or something similar.

In addition, you will need the following Python packages:
- ldap3
- PyYaml
- impacket

For a faster processing of YAML (optional!) also install (should come as a dependency for PyYaml for most Linux distributions):
- LibYAML

Some examples for specific Linux distributions installations are listed below. Alternatively, distribution-agnostic ways (python pip, python virtual env and Docker) are possible.

### Linux distribution specific 
For all distribution examples below, LibYAML is already a dependency of the corresponding PyYaml package and will be therefore installed automatically.
#### ArchLinux

```console
pacman -S smbclient python-ldap3 python-yaml impacket
```
#### Fedora/CentOS/RHEL
(tested on Fedora Workstation 31)

```console
dnf install samba-common-tools samba-client python3-ldap3 python3-pyyaml python3-impacket
```

#### Debian/Ubuntu/Linux Mint
(For Ubuntu 18.04 or below use the Docker or Python virtual environment variant)

```console
apt install smbclient python3-ldap3 python3-yaml python3-impacket
```

### Linux distribution-agnostic
#### Python pip
Depending on the Linux distribution either `pip3` or `pip` is needed:

```console
pip install pyyaml ldap3 impacket
```

Alternative:

```console
pip install -r requirements.txt
```

Remember you need to still install the samba tools as mentioned above.

#### Python virtual environment
```console
python3 -m venv venv
source venv/bin/activate
pip install wheel
pip install -r requirements.txt
```
Then run via:

```console
python3 enum4linux-ng.py -As <target>
```

Remember you need to still install the samba tools as mentioned above. In addition, make sure you run ```source venv/bin/activate``` everytime you spawn a new shell. Otherwise the wrong Python interpreter with the wrong libraries will be used (your system one rather than the virtual environment one).

#### Docker
```console
docker build . --tag enum4linux-ng
```
Once finished an example run could look like this:
```console
docker run -t enum4linux-ng -As <target>
```


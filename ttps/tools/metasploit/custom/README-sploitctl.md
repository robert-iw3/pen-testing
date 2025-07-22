## Description

Script to fetch, install, update and search exploit archives from well-known
sites like packetstormsecurity.org and exploit-db.com.

## Usage

```
[ noptrix@blackarch-dev ~/blackarch/repos/sploitctl ]$ sploitctl -H
--==[ sploitctl by blackarch.org ]==--

usage:

  python3 sploitctl -f <arg> [options] | -u <arg> [options] | -s <arg> [options] | <misc>

options:

  -f <num>   - download exploit archives from chosen sites
             - ? to list sites
  -u <num>   - update exploit archive from chosen installed archive
             - ? to list downloaded archives
  -d <dir>   - exploits base directory (default: /usr/share/exploits)
  -s <regex> - exploits to search using <regex> in base directory
  -t <num>   - max parallel downloads (default: 4)
  -r <num>   - max retry failed downloads (default: 3)
  -A <str>   - set useragent string
  -P <str>   - set proxy (format: proto://user:pass@host:port)
  -X         - decompress archive
  -R         - remove archive after decompression

misc:

  -V         - print version of sploitctl and exit
  -H         - print this help and exit

example:

  # download and decompress all exploit archives and remove archive
  $ python3 sploitctl.py -f 0 -XR

  # download all exploits in packetstorm archive
  $ python3 sploitctl.py -f 4

  # list all available exploit archives
  $ python3 sploitctl.py -f ?

  # download and decompress all exploits in m00-exploits archive
  $ python3 sploitctl.py -f 2 -XR

  # download all exploits archives using 20 threads and 4 retries
  $ python3 sploitctl.py -r 4 -f 0 -t 20

  # download lsd-pl-exploits to "~/exploits" directory
  $ python3 sploitctl.py -f 3 -d ~/exploits

  # download all exploits with using tor socks5 proxy
  $ python3 sploitctl.py -f 0 -P "socks5://127.0.0.1:9050"

  # download all exploits with using http proxy and noleak useragent
  $ python3 sploitctl.py -f 0 -P "http://127.0.0.1:9060" -A "noleak"

  # list all installed exploits available for download
  $ python3 sploitctl.py -u ?

  # update all installed exploits with using http proxy and noleak useragent
  $ python3 sploitctl.py -u 0 -P "http://127.0.0.1:9060" -A "noleak" -XR

notes:

  * sploitctl update's id are relative to the installed archives
    and are not static, so by installing an exploit archive it will
    show up in the update section so always do a -u ? before updating.
```

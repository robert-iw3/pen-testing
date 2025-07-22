## Description

Script to fetch, install, update and search wordlist archives from websites
offering wordlists with more than 6400 wordlists available.

## Usage

```
$ python3 wordlistctl.py [-h] [-v] {fetch,search,list} ...

Fetch, install and search wordlist archives from websites.

positional arguments:
  {fetch,search,list}
    fetch              fetch wordlists

    search             search wordlists

    list               list wordlists

optional arguments:
  -h, --help           show this help message and exit

  -v, --version        show program's version number and exit
```

### Fetch Options

```
$ wordlistctl fetch [-h] [-l WORDLIST [WORDLIST ...]]
                         [-g {usernames,passwords,discovery,fuzzing,misc} [{usernames,passwords,discovery,fuzzing,misc} ...]]
                         [-d] [-w WORKERS] [-u USERAGENT] [-b BASEDIR] fetch_term

positional arguments:
  fetch_term           fetch string filter

optional arguments:
  -h, --help            show this help message and exit

  -l WORDLIST [WORDLIST ...], --wordlist WORDLIST [WORDLIST ...]
                        wordlist to fetch

  -g, --group {group} [{group} ...]
                        wordlist group to fetch
                        available groups:
                          usernames
                          passwords
                          discovery
                          fuzzing
                          misc

  -d, --decompress      decompress and remove archive

  -w WORKERS, --workers WORKERS
                        download workers [default: 10]

  -u USERAGENT, --useragent USERAGENT
                        fetch user agent [default: wordlistctl/v0.9.x]

  -b BASEDIR, --base-dir BASEDIR
                        wordlists base directory [default: /usr/share/wordlists]

```

### Search Options

```
$ wordlistctl search  [-h] [-l] [-b BASEDIR] search_term

positional arguments:
  search_term           what to search

optional arguments:
  -h, --help            show this help message and exit

  -l, --local           search local archives

  -b BASEDIR, --base-dir BASEDIR
                        wordlists base directory [default: /usr/share/wordlists]

  -f INDEX [INDEX ...], --fetch INDEX [INDEX ...]
                        fetch the wordlists at the given indexes in the search results, see
                        fetch options for additional options

fetch options:
  -d, --decompress      decompress and remove archive

  -w WORKERS, --workers WORKERS
                        download workers [default: 10]

  -u USERAGENT, --useragent USERAGENT
                        parser user agent [default: wordlistctl/v0.9.x]
```

### List Options

```
$ wordlistctl list [-h] [-g {usernames,passwords,discovery,fuzzing,misc}]

optional arguments:
  -h, --help            show this help message and exit

  -g, --group {group}
                        show all wordlists in group
                        available groups:
                          usernames
                          passwords
                          discovery
                          fuzzing
                          misc

  -f INDEX [INDEX ...], --fetch INDEX [INDEX ...]
                        fetch the wordlists at the given indexes in the list, see
                        fetch options for additional options

fetch options:
  -d, --decompress      decompress and remove archive

  -w WORKERS, --workers WORKERS
                        download workers [default: 10]

  -u USERAGENT, --useragent USERAGENT
                        parser user agent [default: wordlistctl/v0.9.x]
```

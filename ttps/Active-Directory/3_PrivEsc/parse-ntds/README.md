
# parse_ntds.py

`parse_ntds.py` is a Python script designed to parse an NTDS.dit file and export its content into CSV files. This tool provides a comprehensive way to extract and analyze data from NTDS files.

## Install

```bash
# place your exfiltrated ntds.dit and SYSTEM file in the ntds_test/ directory.  Sample is included for demo.
$ podman build -t parse-ntds .
$ podman run -it --name parse-ntds parse-ntds

$ python parse_ntds.py -f /data/ntds.dit -s /data/SYSTEM --dump-users --dump-groups
  "S-1-5-83-0": "NT VIRTUAL MACHINE\Virtual Machines"
[+] Parsing datatable...
[+] Parsing datatable done.
Execution time of parse_datable: 4.0148 seconds
[+] Parsing linktable...
[+] Parsing linktable done.
[+] Update ntdsentries...
[+] Dumping domains to CSV file...
Execution time of dump_csv_domain: 0.0012 seconds
[+] Creating sqlite Correlations table...
[+] Sqlite Correlations table created.
Execution time of dump_sqlite_correlations: 0.0807 seconds
[+] Dumping data to CSV files...
[+] Dumping users to CSV file...
[+] Users CSV file created.
Execution time of dump_csv_user: 0.0031 seconds
[+] Dumping groups to CSV file...
[+] Groups CSV file created.
Execution time of dump_csv_group: 0.0013 seconds
[+] Dumping trusts to CSV file...
[+] Trusts CSV file created.
Execution time of dump_csv_trust: 0.0003 seconds
[+] Dumping domains to CSV file...
Execution time of dump_csv_domain: 0.0011 seconds
[+] Dumping OU and containers to CSV file...
[+] OU and containers CSV file created.
Execution time of dump_csv_ou_container: 0.0039 seconds
[+] All CSV files created.

$ ls /output
report_domains.csv  report_groups.csv  report_ou_containers.csv  report_trusts.csv  report_users.csv  sqlite.db
```


## Usage

To display the help message and see all available options, run:

```bash
python parse_ntds.py -h
```

### Command-line Arguments

- `-h, --help`
  Show the help message and exit.

- `-f NTDS_FILE, --file NTDS_FILE`
  **Required**: Path to the `ntds.dit` file.

- `-s SYSTEM_FILE, --system SYSTEM_FILE`
  **Required**: Path to the `SYSTEM` hive file.

- `-d DOMAIN, --domain DOMAIN`
  Domain name.

- `-o OUTPUT_DIR, --output OUTPUT_DIR`
  Output directory. Default is the current directory.

- `-v, --verbose`
  Increase output verbosity to DEBUG level.

- `--dump-all`
  Dump all data except ACL (default).

- `--dump-users`
  Dump user data.

- `--dump-groups`
  Dump group data.

- `--dump-trusts`
  Dump trust data.

- `--dump-domains`
  Dump domain data.

- `--dump-ou`
  Dump OU/container data.

- `--dump-acl`
  Dump ACL data (**required** -d option).

## Example

To parse an NTDS.dit file and export all data to CSV files in the current directory with verbose output:

```bash
python parse_ntds.py -f /path/to/ntds.dit -s /path/to/SYSTEM -v --dump-all
```

To dump only user and group data:

```bash
python parse_ntds.py -f /path/to/ntds.dit -s /path/to/SYSTEM --dump-users --dump-groups
```

To dump all with ACL:

```bash
python parse_ntds.py -f /path/to/ntds.dit -s /path/to/SYSTEM --dump-acl -d <domain_name>
```

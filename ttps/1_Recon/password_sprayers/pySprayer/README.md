![](./.github/banner.png)

  Multithreaded spraying of a password on all accounts of a domain.

## Features

 - [x] Multithreaded spraying of passwords on multiple accounts
 - [x] Export of the results

## Usage

```
# Sprayer  -h

usage: Sprayer [-h] [-v] -sp SPRAY_PASSWORD [-oH OUTPUT_HASHES] [-T THREADS] [-P PORT] [-u USERNAME] [-p PASSWORD]
               [-d DOMAIN] [--hashes [LMHASH]:NTHASH] [--no-pass] [--dc-ip ip address]

Multithreaded spraying of a password on all accounts of a domain

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode. (default: False)
  -sp SPRAY_PASSWORD, --spray-password SPRAY_PASSWORD
                        arg1 help message
  -oH OUTPUT_HASHES, --output-hashes OUTPUT_HASHES
                        Output hashes to file
  -T THREADS, --threads THREADS
                        Number of threads (default: 16)
  -P PORT, --port PORT  SMB port to connect to (default: 445)

Credentials:
  -u USERNAME, --username USERNAME
                        Username to authenticate to the remote machine.
  -p PASSWORD, --password PASSWORD
                        Password to authenticate to the remote machine. (if omitted, it will be asked unless -no-
                        pass is specified)
  -d DOMAIN, --domain DOMAIN
                        Windows domain name to authenticate to the machine.
  --hashes [LMHASH]:NTHASH
                        NT/LM hashes (LM hash can be empty)
  --no-pass             Don't ask for password (useful for -k)
  --dc-ip ip address    IP Address of the domain controller. If omitted it will use the domain part (FQDN)
                        specified in the target parameter

```

## Demonstration

```
./Sprayer.py -u 'Administrator' -p 'Admin123!' -d 'COERCE.local' --dc-ip 192.168.1.46 -sp 'Admin123!'
```

https://user-images.githubusercontent.com/79218792/207589885-d934f431-265b-40bf-9c9f-31a3b12bb089.mp4

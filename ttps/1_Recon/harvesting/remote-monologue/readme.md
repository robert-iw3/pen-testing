### Remote Monologue

RemoteMonologue is a Windows credential harvesting technique that enables remote user compromise by leveraging the Interactive User RunAs key and coercing NTLM authentications via DCOM.

Read X-Force Red's [RemoteMonologue: Weaponizing DCOM for NTLM  Authentication Coercions] for detailed information.

🔹 **Authentication Coercion via DCOM (`-dcom`)**
- Targets three DCOM objects (`ServerDataCollectorSet`, `FileSystemImage`, `MSTSWebProxy`, `UpdateSession`) to trigger an NTLM authentication against a specified listener (`-auth-to`).

🔹 **Credential Spraying (`-spray`)**
- Validate credentials across multiple systems while also capturing user credentials.

🔹 **NetNTLMv1 Downgrade Attack (`-downgrade`)**
- Force targets to use NTLMv1, making credential cracking and relaying easier.

🔹 **WebClient Service Abuse (`-webclient`)**
- Enables the WebClient service to facilitate HTTP-based authentication coercion.

🔹 **User Enumeration (`-query`)**
- Identify users with an active session on the target system.

**Note:** Local administrator privileges to the target system is required.

```bash
podman build -t remotemonologue .

podman run -it --name remotemonologue remotemonologue

python3 RemoteMonologue.py -h


 __   ___        __  ___  ___        __        __        __   __        ___
|__) |__   |\/| /  \  |  |__   |\/| /  \ |\ | /  \ |    /  \ / _` |  | |__
|  \ |___  |  | \__/  |  |___  |  | \__/ | \| \__/ |___ \__/ \__> \__/ |___



usage: RemoteMonologue.py [-h] [-ts] [-debug] [-dcom] [-auth-to ip address] [-spray] [-query] [-downgrade] [-webclient] [-output filename] [-timeout TIMEOUT] [-hashes LMHASH:NTHASH]
                          [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-A authfile] [-keytab KEYTAB]
                          target

DCOM NTLM authentication coercer and sprayer

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -dcom                 DCOM object - ServerDataCollectorSet (default), FileSystemImage, MSTSWebProxy, UpdateSession (SYSTEM)
  -auth-to ip address   Server for Interactive User to authenticate to over SMB
  -spray                Spray credentials against provided list of systems. Filename must be provided in domain/user@FILE
  -query                Query users logged on the target system
  -downgrade            Run attack with NetNTLMv1 downgrade
  -webclient            Enable the WebClient service to receive HTTP authentications for NTLM relaying
  -output filename      Output results to file
  -timeout TIMEOUT      socket timeout out when connecting to the target (default 5 sec)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones
                        specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
  -A authfile           smbclient/mount.cifs-style authentication file. See smbclient man page's -A option.
  -keytab KEYTAB        Read keys for SPN from keytab file
  ```


[RemoteMonologue: Weaponizing DCOM for NTLM  Authentication Coercions]: https://www.ibm.com/think/x-force/remotemonologue-weaponizing-dcom-ntlm-authentication-coercions
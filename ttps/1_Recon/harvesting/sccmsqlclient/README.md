# sccmsqlclient

A dedicated MSSQL client for SCCM database exploration and exploitation.
- Recon queries
- Run PowerShell scripts on managed clients
- Extract secrets

## Requirements
- impacket

## Usage
```sh
SCCM MSSQL client (SSL supported)

"target", action="store", help="[[domain/]username[:password]@]<targetName or address>"
"-port", action="store", default="1433", help="target MSSQL port (default 1433)"
"-db", action="store", help="MSSQL database instance (default None)"
"-windows-auth", action="store_true", default=False, help="whether or not to use Windows " "Authentication (default False)"
"-debug", action="store_true", help="Turn DEBUG output ON"
'-ts', action='store_true', help='Adds timestamp to every logging output'
"-show", action="store_true", default=False, help="show the queries"
"-file", type=argparse.FileType("r"), help="input file with commands to execute in the SQL shell"
"-site", required=False, default="", action="store", help="Force SCCM site code, or it is loaded by checking DB with name CM_<CODE>"
"-script", required=False, default=None, action="store", help="SCCM script file"

"-hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes, format is LMHASH:NTHASH"
"-no-pass", action="store_true", help="don't ask for password (useful for -k)"

"-k", action-"Use Kerberos authentication. Grabs credentials from ccache file "
"-aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication " "(128 or 256 bits)"
"-dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If " "ommited it use the domain part (FQDN) specified in the target parameter"
'-target-ip', action='store', metavar = "ip address", help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
```
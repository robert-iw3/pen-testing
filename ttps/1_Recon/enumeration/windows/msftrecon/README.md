# MSFTRecon

MSFTRecon is a reconnaissance tool designed for red teamers and security professionals to map Microsoft 365 and Azure tenant infrastructure. It performs comprehensive enumeration without requiring authentication, helping identify potential security misconfigurations and attack vectors.

## Usage

Build image:
```bash
podman build -t msftrecon .
```

Run container:
```bash
podman run -it --name msftrecon msftrecon
```

Basic scan:
```bash
python3 ./msftrecon.py -d example.com
```

JSON output:
```bash
python3 ./msftrecon.py -d example.com -j
```

Government cloud:
```bash
python3 ./msftrecon.py -d example.gov --gov
```

China cloud:
```bash
python3 ./msftrecon.py -d example.cn --cn
```

## Sample Output

```
[+] Target Organization:
Tenant Name: Contoso
Tenant ID: 1234abcd-1234-abcd-1234-1234abcd1234

[+] Federation Information:
Namespace Type: Managed
Brand Name: Contoso
Cloud Instance: microsoftonline.com

[+] Azure AD Configuration:
Tenant Region: NA

[+] Azure AD Connect Status:
  Identity Configuration: Managed (Cloud Only)
  Authentication Type: Managed

  [!] Identity Insights:
  * Cloud-only authentication detected
  * All authentication handled in Azure AD
  * Focus on cloud-based attack vectors
```

## Red Team Usage

MSFTRecon provides valuable insights for red teamers:

1. **Identity Attack Vectors**
   - Identifies authentication methods for targeted attacks
   - Reveals potential password spray opportunities
   - Highlights federation configurations for SAML attacks

2. **Application Attack Surface**
   - Discovers exposed enterprise applications
   - Identifies OAuth abuse opportunities
   - Reveals admin consent endpoints for phishing

3. **Infrastructure Insights**
   - Maps Azure services for lateral movement
   - Identifies B2C configurations
   - Discovers potential storage misconfigurations

4. **Security Control Awareness**
   - Detects MDI presence for evasion planning
   - Identifies conditional access configurations
   - Reveals authentication requirements

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is intended for legal security assessments and penetration testing only. Users must obtain proper authorization before conducting security assessments. The authors are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the MIT License 

## Acknowledgments

- Based on research and techniques from various Microsoft 365 and Azure security resources, plus check_mdi.py


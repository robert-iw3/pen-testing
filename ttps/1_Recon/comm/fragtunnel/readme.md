# Fragtunnel
Fragtunnel is a PoC TCP tunneling tool that exploits the design flaw that IDS/IPS engines and Next Generation Firewalls have; therefore, it can tunnel your application's traffic to the target server and back while not being detected and blocked by Next Generation firewalls using Layer 7 application rules.

## How it works?
- Data received from your local application (tunnel client side) or from target server (tunnel server side)
- received data gets encoded/decoded (optional)
- then sliced into smaller fragments.
- each fragment gets sent one by one over the tunnel, each fragment within a new TCP session
- fragments coming out from tunnel gets merged to make original data
- finally, restored original data gets sent to its target (either to your application at local or to the target server)

## Usage
```
Usage: fragtunnel.py -p port -t target ip:port -T tunnel endpoint ip:port -b bind ip:port -e secret -v verbose

-h --help        help
-p --port        port to listen for a local app to connect
-t --target      target's ip:port
-T --Tunnel to   tunnel server's ip:port
-b --bind        tunnel server listen ip:port
-e --encrypt     encrypt/encode tunnel traffic using the secret provided with this flag
-v --verbose     verbose mode
```

### Set up a tunnel server:
```
python fragtunnel.py -b <interface-ip>:<port-to-listen>
```
Straightforward. This will be your tunnel server listening for a tunnel client connection. Once the tunnel client is connected, it will pass target information to the server first, and then the server will establish a connection to the final target.



### Set up a tunnel client
```
python fragtunnel.py -p <local-port-to-listen> -t <target-server-address>:<target-server-port> -T <tunnel-server-address>:<tunnel-server-port>
```
Once executed, the tunnel client will setup a local server on the local port (-p) so you can connect with your application.
Then the tunnel client will connect to the target tunnel server using the address and port number provided (-T) and will send target details provided (-t) to the tunnel server so the tunnel server can establish a connection to the final target on its side.

## Examples:
```
# setting up tunnel server
python fragtunnel.py -b 1.2.3.4:80

# setting up tunnel client
python fragtunnel.py -p 1234 -t mywebsite.com:80 -T 1.2.3.4:80
```

##### If you want to encode/encrypt your tunnel traffic then:
```
# setting up tunnel server
python fragtunnel.py -b 1.2.3.4:80 -e secret-key-to-use

# setting up tunnel client
python fragtunnel.py -p 1234 -t mywebsite.com:80 -T 1.2.3.4:80 -e secret-key-to-use
```
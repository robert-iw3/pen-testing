### mitmproxy

Command Line:

`mitmproxy` is your swiss-army knife for debugging, testing, privacy measurements, and penetration testing. It can be used to intercept, inspect, modify and replay web traffic such as HTTP/1, HTTP/2, HTTP/3, WebSockets, or any other SSL/TLS-protected protocols. You can prettify and decode a variety of message types ranging from HTML to Protobuf, intercept specific messages on-the-fly, modify them before they reach their destination, and replay them to a client or server later on. 

Web Interface:

Use mitmproxy's main features in a graphical interface with `mitmweb`. Do you like Chrome's DevTools? `mitmweb` gives you a similar experience for any other application or device, plus additional features such as request interception and replay.


```bash
podman build -t mitm .
podman run -it --name mitm -p 8081 -p 8080 mitm
```

## Shell inside Container Usage

Launch the tool you need:

You can start any of the three tools from the command line / terminal.

`mitmproxy` gives you an interactive command-line interface

`mitmweb` gives you a browser-based GUI

`mitmdump` gives you non-interactive terminal output

### Advanced Usage

To launch the terminal user interface of mitmproxy:

```sh
$ podman run --rm -it -v ~/.mitmproxy:/home/mitmproxy/.mitmproxy -p 8080:8080 mitmproxy/mitmproxy
```

Note: The `-v` for *volume mount* is optional. It allows to persist and reuse the generated CA certificates between runs, and for you to access them.
Without it, a new root CA would be generated on each container restart.

Once started, mitmproxy listens as an HTTP proxy on `localhost:8080`:

```sh
$ http_proxy=http://localhost:8080/ curl http://example.com/
$ https_proxy=http://localhost:8080/ curl -k https://example.com/
```

You can also start `mitmdump` by just adding that to the end of the command-line:

```sh
$ podman run --rm -it -p 8080:8080 mitmproxy/mitmproxy mitmdump
Proxy server listening at http://*:8080
[...]
```

For `mitmweb`, you also need to expose port 8081:

```sh
# this makes :8081 accessible to the local machine only
$ podman run --rm -it -p 8080:8080 -p 127.0.0.1:8081:8081 mitmproxy/mitmproxy mitmweb --web-host 0.0.0.0
Web server listening at http://0.0.0.0:8081/
No web browser found. Please open a browser and point it to http://0.0.0.0:8081/
Proxy server listening at http://*:8080
[...]
```

You can also pass options directly via the CLI:

```sh
$ podman run --rm -it -p 8080:8080 mitmproxy/mitmproxy mitmdump --set ssl_insecure=true
Proxy server listening at http://*:8080
[...]
```

If `~/.mitmproxy/mitmproxy-ca.pem` is present in the container, mitmproxy will assume uid and gid from the file owner.
For further details, please consult the mitmproxy [documentation](https://docs.mitmproxy.org/en/stable/).


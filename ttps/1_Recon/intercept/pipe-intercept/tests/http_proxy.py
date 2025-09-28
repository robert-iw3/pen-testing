import asyncio
import logging


HTTP_PROXY_PORT = 9999


class ProxyException(Exception):
    pass


async def proxy_server_handler(server_reader, server_writer):
    try:
        req = await server_reader.read(65536)
        host, port = handle_connect_request(req)

        client_reader, client_writer = await asyncio.open_connection(host, port)
        server_writer.write(b'HTTP/1.1 200 OK\r\n\r\n')
        await server_writer.drain()

        asyncio.create_task(forward_data(server_reader, client_writer))
        asyncio.create_task(forward_data(client_reader, server_writer))

    except ProxyException as e:
        logging.warning(e)

    except Exception as e:
        pass


def handle_connect_request(req: bytes):
    # Find end of headers
    hdr_end = req.find(b"\r\n\r\n")
    if hdr_end == -1:
        raise ProxyException(f'Invalid request (no header terminator): {req!r}')

    # Decode headers using ISO-8859-1 per HTTP spec
    try:
        head = req[:hdr_end].decode("iso-8859-1")
    except UnicodeDecodeError:
        raise ProxyException('Invalid request encoding (expected ISO-8859-1)')

    lines = head.split("\r\n")
    if not lines or not lines[0]:
        raise ProxyException(f'Invalid request line: {lines[:1]!r}')

    # Parse request line: METHOD SP REQUEST-TARGET SP HTTP/VERSION
    parts = lines[0].split()
    if len(parts) != 3:
        raise ProxyException(f'Invalid request line: {lines[0]!r}')
    method, _target, version = parts

    if method != 'CONNECT':
        raise ProxyException(f'Invalid request method: {method}')
    if not version.startswith("HTTP/"):
        raise ProxyException(f'Invalid HTTP version: {version!r}')

    # Parse headers (very small, case-insensitive)
    headers = {}
    for raw in lines[1:]:
        if not raw:
            continue
        if ":" not in raw:
            raise ProxyException(f'Malformed header: {raw!r}')
        k, v = raw.split(":", 1)
        headers[k.strip().lower()] = v.lstrip()

    # Match original behavior: read the authority from the Host header
    if "host" not in headers:
        raise ProxyException('Missing Host header')
    host_hdr = headers["host"]

    host_split = host_hdr.split(':')
    if len(host_split) != 2:
        raise ProxyException(f'Invalid host: {host_hdr}')

    host = host_split[0]
    port = host_split[1]  # keep as string to preserve original function signature
    return host, port


async def forward_data(reader, writer):
    try:
        while not reader.at_eof():
            msg = await reader.read(65536)
            msg = msg.replace(b'zerothis', b'00000000')
            writer.write(msg)
            await writer.drain()

    except:
        pass

    writer.close()


async def main():
    server = await asyncio.start_server(proxy_server_handler, '127.0.0.1', HTTP_PROXY_PORT)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())

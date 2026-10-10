#!/usr/bin/env python3
"""A backend for the end-to-end checks.

    backend.py <port> <log file> [plain|proxy]

HTTP/1.1 with keep-alive. Every answer is one line that says which
connection of this backend the request came on and which request of that
connection it was: `<header> conn=<n> req=<m> path=<path>`.

`proxy` reads a PROXY protocol header (version 1 or 2) at the start of
every connection, as `listen ... proxy_protocol` of nginx does, and puts
what it said in front of the answer: `v2 TCP4 <source> <destination>`,
`v1 local - -` for a header that names nobody. A connection that starts
with something else is answered 400 and closed. `plain` (the default)
reads none and answers `plain - - -`.

The path decides what else happens: `/slow` answers after two seconds.
"""
import asyncio
import socket
import struct
import sys

PORT, LOG = int(sys.argv[1]), sys.argv[2]
PROXY = len(sys.argv) > 3 and sys.argv[3] == "proxy"
SIGNATURE = b"\r\n\r\n\0\r\nQUIT\n"
connections = 0


def log(line):
    with open(LOG, "a") as f:
        f.write(line + "\n")


async def proxy_header(reader):
    """What the header says, or None and the bytes that were there."""
    first = await reader.readexactly(6)
    if first == b"PROXY ":
        line = first + await reader.readuntil(b"\r\n")
        parts = line[:-2].decode().split(" ")
        if parts[1] == "UNKNOWN":
            return "v1 local - -", b""
        return f"v1 {parts[1]} {parts[2]}:{parts[4]} {parts[3]}:{parts[5]}", b""
    if first == SIGNATURE[:6]:
        head = first + await reader.readexactly(10)
        if head[:12] != SIGNATURE:
            return None, head
        body = await reader.readexactly(struct.unpack(">H", head[14:16])[0])
        if head[12] == 0x20:
            return "v2 local - -", b""
        if head[13] == 0x11:
            source, destination = (
                socket.inet_ntop(socket.AF_INET, body[i:i + 4]) for i in (0, 4))
            ports = struct.unpack(">HH", body[8:12])
            return f"v2 TCP4 {source}:{ports[0]} {destination}:{ports[1]}", b""
        if head[13] == 0x21:
            source, destination = (
                socket.inet_ntop(socket.AF_INET6, body[i:i + 16]) for i in (0, 16))
            ports = struct.unpack(">HH", body[32:36])
            return f"v2 TCP6 [{source}]:{ports[0]} [{destination}]:{ports[1]}", b""
        return f"v2 family-{head[13]:#x} - -", b""
    return None, first


async def serve(reader, writer):
    global connections
    connections += 1
    conn, requests = connections, 0
    try:
        said, rest = await proxy_header(reader) if PROXY else ("plain - - -", b"")
        if said is None:
            log(f"conn={conn} no header, starts with {rest[:6]!r}")
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 10\r\n"
                         b"Connection: close\r\n\r\nno header\n")
            await writer.drain()
            return
        log(f"conn={conn} {said}")
        while True:
            head = await reader.readuntil(b"\r\n\r\n")
            requests += 1
            path = head.split(b" ")[1].decode()
            if path.startswith("/slow"):
                await asyncio.sleep(2)
            body = f"{said} conn={conn} req={requests} path={path}\n".encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                         b"Content-Length: %d\r\n\r\n" % len(body) + body)
            await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        pass
    finally:
        log(f"conn={conn} closed after {requests} requests")
        writer.close()


async def main():
    server = await asyncio.start_server(serve, "127.0.0.1", PORT)
    async with server:
        await server.serve_forever()


asyncio.run(main())

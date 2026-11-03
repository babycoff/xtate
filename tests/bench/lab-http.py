#!/usr/bin/env python3
"""Tiny multi-port HTTP target for the local benchmark.

One asyncio process listens on a contiguous port range. The response is a
minimal HTTP/1.1 close-delimited body so ZBanner and stateful probes can read
something useful without running a real web server.
"""
import asyncio
import sys


async def handle(reader, writer):
    try:
        await reader.read(4096)
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 2\r\n"
            b"Connection: close\r\n"
            b"\r\nOK"
        )
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main(start, end):
    servers = []
    for port in range(start, end + 1):
        servers.append(
            await asyncio.start_server(handle, "0.0.0.0", port, backlog=64)
        )
    print(f"http target listening on {start}-{end}", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: lab-http.py START_PORT END_PORT", file=sys.stderr)
        raise SystemExit(2)
    asyncio.run(main(int(sys.argv[1]), int(sys.argv[2])))

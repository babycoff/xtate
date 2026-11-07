#!/usr/bin/env python3
"""Minimal aioquic server used to test the QUIC capability probe."""
import asyncio
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration


class EchoProtocol(QuicConnectionProtocol):
    def quic_event_received(self, event):
        # The capability probe only needs the transport handshake bytes.
        pass


async def main():
    cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    retry = len(sys.argv) > 4 and sys.argv[4] == "retry"
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    config.load_cert_chain(cert, key)
    await serve("0.0.0.0", port, configuration=config,
                create_protocol=EchoProtocol, retry=retry)
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""Minimal aioquic HTTP/3 server for the http3-state probe."""
import asyncio
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

BODY = b"hello from xtate http3 lab\n"


class Http3Protocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._request_streams = set()

    def quic_event_received(self, event):
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                stream_id = http_event.stream_id
                if stream_id in self._request_streams:
                    continue
                self._request_streams.add(stream_id)
                self._http.send_headers(
                    stream_id,
                    [(b":status", b"200"),
                     (b"content-type", b"text/plain"),
                     (b"server", b"xtate-http3-lab")],
                )
                self._http.send_data(stream_id, BODY, end_stream=True)
                self.transmit()


async def main():
    cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    config.load_cert_chain(cert, key)
    await serve("0.0.0.0", port, configuration=config,
                create_protocol=Http3Protocol)
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())

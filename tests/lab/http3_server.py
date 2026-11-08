#!/usr/bin/env python3
"""Minimal aioquic HTTP/3 server for the http3-state probe."""
import asyncio
import os
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

BODY = os.environ.get("H3_BODY", "hello from xtate http3 lab\n").encode()
STATUS = int(os.environ.get("H3_STATUS", "200"))
EMPTY_DATA = os.environ.get("H3_EMPTY_DATA", "") not in ("", "0", "false")
EXTRA = os.environ.get("H3_EXTRA_HEADER", "")


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
                headers = [(b":status", str(STATUS).encode()),
                           (b"content-type", b"text/plain"),
                           (b"server", b"xtate-http3-lab")]
                if EXTRA and ":" in EXTRA:
                    name, value = EXTRA.split(":", 1)
                    headers.append((name.strip().encode(),
                                    value.strip().encode()))
                self._http.send_headers(stream_id, headers)
                if EMPTY_DATA:
                    self._http.send_data(stream_id, b"", end_stream=True)
                else:
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

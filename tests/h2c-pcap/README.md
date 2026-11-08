# H2C synthetic pcap matrix

Builds cleartext HTTP/2 SETTINGS/HEADERS/DATA frames on synthetic TCP data
packets. Multiple copies are intentional: one packet can race the receive
thread's EOF dispatch under CI redirection; all copies use the same ZBanner ACK
number and distinct sequence numbers.

Runs `zbanner -probe h2c` with `--all-banner --no-dedup-banner` and checks
`http2_frame_count: 3`.

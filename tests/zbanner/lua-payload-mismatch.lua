-- ZBanner payload-contract regression fixture.
-- Declares length 1 but returns 4 bytes. Banner validation must use the actual
-- make_payload length (4), not the declared get_payload_length value (1).
ProbeName = "zbanner-mismatch"
ProbeType = 1
ProbeDesc = "declared=1 actual=4 payload mismatch fixture"

function Make_payload(ip_them, port_them, ip_me, port_me, index)
    return "ABCD"
end

function Get_payload_length(ip_them, port_them, ip_me, port_me, index)
    return 1
end

function Handle_response(ip_them, port_them, ip_me, port_me, index, data)
    return 1, 2, "lua-banner", "matched", "payload-mismatch-ok"
end

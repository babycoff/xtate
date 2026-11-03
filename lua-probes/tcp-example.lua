-- Firstly, require the xtate header to get predefined values.
local current_path = debug.getinfo(1, "S").source:sub(2)
local current_dir = current_path:match("(.*/)")
package.path = package.path .. ";" .. current_dir .. "?.lua"
require("xtate-header")

-- Secondly, set configs and info of the probe.
---@string name of the probe.
ProbeName = "tcp-example"
---@number a predefined Probe_Type value from xtate-header
ProbeType = Probe_Type.TCP
---@string description of the probe.
ProbeDesc = [[
    "This is an example lua script for tcp type probe. It sends http simple get "
    "request and identifies http service."
]]

-- Then, write your own funcs in the same name and declaration as following.
-- NOTE: take care of thread safety.


local hello_string = "GET / HTTP/1.0\r\n\r\n"


-- To make hello data.
---@param ip_them string ip of target.
---@param port_them number port of target.
---@param ip_me string ip of us.
---@param port_me number port of us.
---@param index number index of expected hello probe.
---@return string data of hello.
function Make_payload(ip_them, port_them, ip_me, port_me, index)
    return hello_string
end

-- To get hello data length.
---@param ip_them string ip of target.
---@param port_them number port of target.
---@param ip_me string ip of us.
---@param port_me number port of us.
---@param index number index of expected hello probe.
---@return number length of hello data.
function Get_payload_length(ip_them, port_them, ip_me, port_me, index)
    return #hello_string
end

-- To handle reponse data.
---@param ip_them string ip of target.
---@param port_them number port of target.
---@param ip_me string ip of us.
---@param port_me number port of us.
---@param index number index of expected hello probe.
---@param response string reponsed data.
---@return number positive for starting after_handle or index +1 to set next probe in dynamic_next.
---@return number level a predefined output level value from xtate-header
---@return string classification of result.
---@return string reason of classification.
---@return string report of response (empty string if no report).
function Handle_response(ip_them, port_them, ip_me, port_me, index, response)
    if not string.find(response, "HTTPS") and
        (string.find(response, "HTTP")
            or string.find(response, "html")
            or string.find(response, "HTML")
            or string.find(response, "<h1>")) then
        return 0, Output_Level.SUCCESS, "identified", "matched", "http service"
    end

    return 0, Output_Level.FAIL, "unknown", "not matched", "not http"
end

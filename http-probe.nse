local shortport = require "shortport"
local http = require "http"
local string = require "string"
local stdnse = require "stdnse"

description = [[
NMAP Script to generate httpx URLs from an scan :
Example usage  :
nmap -Pn -v -n -p80,443,8080 --script=http-probe.nse --min-rate 500p --open example.com
]]

author = {"notnotnotveg <notnotnotveg@gmail.com>"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- The Rule Section --
portrule = function(host, port)
    return port.protocol == "tcp"
        and port.state == "open"
end

local function getProto(ssl)
    if (ssl) then
        return "https"
    else
        return "http"
        end
end

local function ipv6Check(host_name)
    if string.match(host_name, ":") then
        return "[" .. host_name .. "]"
    else
        return host_name
        end
end

-- The Action Section --
action = function(host, port)
    local uri = "/"
    local result = http.get(host, port, uri)
    local host_name = stdnse.get_hostname(host)
    if ( result.status ) then
            local proto = getProto(result.ssl)
                host_name = ipv6Check(host_name)
        return proto .. "://" .. host_name .. ":" .. port.number
    end
end

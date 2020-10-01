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

-- The Action Section --
action = function(host, port)
    local default_uri = "/"
    local uri = stdnse.get_script_args("http-get.uri") or default_uri
    local result = http.get(host, port, uri)
    local host_name = stdnse.get_hostname(host)
    if ( result.status ) then
        if ( result.ssl and string.match(host_name, ":")) then
            return "https://[" .. host_name .. "]:" .. port.number
        elseif ( not result.ssl and string.match(host_name, ":")) then 
            return "http://[" .. host_name .. "]:" .. port.number
        elseif ( result.ssl ) then
           return "https://" .. host_name .. ":" .. port.number
        else
           return "http://" .. host_name .. ":" .. port.number
        end
    else
        -- return "https://http.cat/" .. result.status
    end
end

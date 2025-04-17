local ioc_list = {}
-- Avoid eve.json because if you have log rotation, lua is not aware of that
-- and it will lose the inode of the log file
local log_name = "mandiant.json"
local signature_id = 100000012
local gid = 0
local rev = 0
local signature = "Mandiant Intelligence - Malicious HTTP Request Detected"
local category = "unknown"
local severity = 3
local action = "pass"
local allowed = "true"
local threshold_score = 60
local list_filename = "/home/christos/gitrepos/mandiant_to_suricata_datasets/http.lst"

function init (args)
    local needs = {}
    needs["protocol"] = "http"
    return needs
end

function split(str,sep)
    local result = {}
    for token in string.gmatch(str, "([^" .. sep .. "]+)") do
        table.insert(result,token)
    end
    return result

end

function setup (args)
    -- make it check hash in order to reload in case of change
    -- lua cannot understand log rotation - can i fix it?
   local log_filename = SCLogPath() .. "/" .. log_name
   file = assert(io.open(log_filename,"a"))
   SCLogInfo(string.format("Loading HTTP List %s",log_filename))
   local count = 0
   for line in io.lines(list_filename) do
     local parts = split(line, ",")
     ioc_list[parts[1]] = parts[2]
     count = count + 1
   end
   local output = string.format("Mandiant HTTP Lua Script Loaded: %d records",count)
end

function log (args)


    local http_host = HttpGetRequestHost()
    if http_host == nil then
        http_host = "unknown"
    end 
    local http_uri = HttpGetRequestUriRaw()
    if http_uri == nil then
        http_uri = "unknown"
    end 
    local app_proto , alproto_ts, alproto_tc, alproto_orig, alproto_expect = SCFlowAppLayerProto()
    local full_url = app_proto .. "://" .. http_host .. http_uri


    if ioc_list[full_url] then

        if tonumber(ioc_list[full_url]) < threshold_score then
            return
        end

        -- Check time difference with actual logs
        local ts = SCPacketTimeString()
        local startts = SCFlowTimeString()

        local flow_id = SCFlowId()
        local proto = "unknown" 
        local ip_ver, src_ip, dest_ip, proto_id ,src_port, dest_port  = SCFlowTuple()
        if proto_id == 6 then
            proto = "TCP"
        end
        local tscnt, tsbytes, tccnt , tcbytes = SCFlowStats()
        local event_type = "alert"

        -- TODO: add metadata
        local log_info = string.format('{"timestamp":"%s","flow_id":"%s","event_type":"%s","src_ip":"%s","src_port":%d,"dest_ip":"%s","dest_port":%d,"proto":"%s"',ts,flow_id,event_type,src_ip,src_port,dest_ip,dest_port,proto)
        local alert_log_payload = string.format('{"action":"%s","allowed":"%s","gid":%d,"signature_id":%d,"rev":%d,"signature":"%s","category":"%s","severity":%d}',action,allowed,gid,signature_id,rev,signature,category,severity)
        local flow_log_payload = string.format('{ "pkts_toserver":%d,"pkts_toclient":%d,"bytes_toserver":%d,"bytes_toclient":%d,"start":"%s","src_ip":"%s","src_port":%d,"dest_ip":"%s","dest_port":%d}',tscnt,tccnt,tsbytes,tcbytes,startts,src_ip,src_port,dest_ip,dest_port)
        local http_log_payload = string.format('{ "http_host":"%s","http_uri":"%s"}',http_host,http_uri)
        local full_log_json = string.format('%s,"alert":%s,"flow":%s,"app_proto":"%s","http":%s}',log_info,alert_log_payload,flow_log_payload,app_proto,http_log_payload)

        file:write(full_log_json .. "\n")
        file:flush()
    end
end

function deinit (args)
   file:close(file) 
end

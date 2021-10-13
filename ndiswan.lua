-- A Wireshark dissector for Microsoft Windows Ras NdisWan Packet Capture
-- Based on the dissection behavior of Microsoft Message Analyzer, so may not be 100% accurate

-- Capture ETW with provider Microsoft-Windows-Ras-NdisWanPacketCapture
-- Then use NetMon to convert it from ETL to CAP
-- Now you can open the CAP with Wireshark and read the unencrypted VPN traffic

local frame_encap_type = Field.new("frame.encap_type")
local etw_provider_f = Field.new("netmon_event.provider_id")
local etw_data_f = Field.new("netmon_event.user_data")
local etw_keywords_f = Field.new("netmon_event.event_desc.keyword")

local ndiswan_keyword_type = {}
ndiswan_keyword_type[0] = "NDISWAN_SEND"
ndiswan_keyword_type[1] = "NDISWAN_RECEIVE"

local ndiswan = Proto("ndiswan", "Microsoft-Windows-Ras-NdisWanPacketCapture")
ndiswan.fields.RoutingDomainId = ProtoField.string("ndiswan.routingdomain_id", "Routing Domain ID")
ndiswan.fields.RRASUserName = ProtoField.string("ndiswan.rras_username", "RRAS User Name")
ndiswan.fields.FragmentSize = ProtoField.uint32("ndiswan.fragment_size", "Fragment Size")
ndiswan.fields.EtwKeywords = ProtoField.uint64("ndiswan.etwkeywords", "ETW Keywords")
ndiswan.fields.NdisWanKeywords = ProtoField.new("NdisWan Keywords", "ndiswan.keywords.recv", ftypes.UINT64, ndiswan_keyword_type)

local fragmentsize_f = Field.new("ndiswan.fragment_size")

function ndiswan.dissector(buffer, pinfo, tree)
    -- Check if the frame is NetMon Event
    if (frame_encap_type()() ~= 187) then
        return
    end

    local etw_provider = {etw_provider_f()}

    if (etw_provider[1].display == "d84521f7-2235-4237-a7c0-14e3a9676286") then    
        local etw_keywords = {etw_keywords_f()}
        local etw_data = {etw_data_f()}
        local ndiswan_buf = etw_data[1].range()
        local subtree = tree:add(ndiswan)
        local buf_ptr = 0

        local routingdomain_id_str = ndiswan_buf(0):le_ustringz()
        local routingdomain_id_strlen = (routingdomain_id_str:len() + 1) * 2
        subtree:add(ndiswan.fields.RoutingDomainId, ndiswan_buf(buf_ptr, routingdomain_id_strlen), routingdomain_id_str)
        buf_ptr = buf_ptr + routingdomain_id_strlen

        local rras_username_str = ndiswan_buf(buf_ptr):le_ustringz()
        local rras_username_strlen = (rras_username_str:len() + 1) * 2
        subtree:add(ndiswan.fields.RRASUserName, ndiswan_buf(buf_ptr, 2))
        buf_ptr = buf_ptr + rras_username_strlen

        subtree:add_le(ndiswan.fields.FragmentSize, ndiswan_buf(buf_ptr,4))
        buf_ptr = buf_ptr + 4

        local keywords_tree = subtree:add_le(ndiswan.fields.EtwKeywords, etw_keywords[1].range(), etw_keywords[1].range():le_uint64(), "Keywords: 0x"..etw_keywords[1].range():le_uint64():tohex())
        if (etw_keywords[1].range():le_uint64():tohex() == "8000000100000000") then
            keywords_tree:add(ndiswan.fields.NdisWanKeywords, etw_keywords[1].range(), UInt64.new(0))
        else
            keywords_tree:add(ndiswan.fields.NdisWanKeywords, etw_keywords[1].range(), UInt64.new(1))
        end

        Dissector.get("eth_withoutfcs"):call(ndiswan_buf(buf_ptr,fragmentsize_f()()):tvb(),pinfo,tree)
    end
end

register_postdissector(ndiswan)

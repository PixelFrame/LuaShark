local rcp_p = Proto("rcp", "Cluster Failover RCP Protocol")

local rcp_type = {}
rcp_type[0] = "RCP Request"
rcp_type[1] = "RCP Response"

local rcp_nextHeader = {}
rcp_nextHeader[0] = "RCP_EXTENSION_NONE"
rcp_nextHeader[1] = "RCP_EXTENSION_IPV4_PAIR"
rcp_nextHeader[2] = "RCP_EXTENSION_IPV6_PAIR"
rcp_nextHeader[3] = "RCP_EXTENSION_SIGNATURE"
rcp_nextHeader[4] = "RCP_EXTENSION_MAXIMUM"

rcp_p.fields.identifier = ProtoField.uint32("rcp.id", "Identifier")
rcp_p.fields.version = ProtoField.uint8("rcp.ver", "Version")
rcp_p.fields.reserved = ProtoField.uint8("rcp.reserved", "Reserved")
rcp_p.fields.ptype = ProtoField.new("Type", "rcp.type", ftypes.UINT16, rcp_type)
rcp_p.fields.nextHeader = ProtoField.new("NextHeader", "rcp.nextheader", ftypes.UINT16, rcp_nextHeader)
rcp_p.fields.totalLength = ProtoField.uint16("rcp.totallength", "TotalLength")
rcp_p.fields.seqNo = ProtoField.uint32("rcp.seq", "SequenceNumber")

local identifier_filed = Field.new("rcp.id")
local type_field = Field.new("rcp.type")
local nextHeader_filed = Field.new("rcp.nextheader")
local seq_field = Field.new("rcp.seq")

function rcp_p.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "RCP"

    local subtree = tree:add(rcp_p,buffer())
    subtree:add_le(rcp_p.fields.identifier, buffer(0,4))

    if identifier_filed()() ~= 1431655765 then
        pinfo.cols.protocol = "ClusterFailover"
        return
    end

    subtree:add_le(rcp_p.fields.version, buffer(4,1))
    subtree:add_le(rcp_p.fields.reserved, buffer(5,1))
    subtree:add_le(rcp_p.fields.ptype, buffer(6,2))
    subtree:add_le(rcp_p.fields.nextHeader, buffer(8,2))
    subtree:add_le(rcp_p.fields.totalLength, buffer(10,2))
    subtree:add_le(rcp_p.fields.seqNo, buffer(12,4))

    local info = rcp_type[type_field()()].." "..rcp_nextHeader[nextHeader_filed()()].." "..seq_field()()
    pinfo.cols.info:set(info)

end

udp_table = DissectorTable.get("udp.port")
udp_table:add(3343,rcp_p)
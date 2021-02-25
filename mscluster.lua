-- Wireshark lua plugin for Microsoft Failover Cluster traffic
-- Written according to NetMon parser failovercluster.npl

local mscluster = Proto("mscluster", "Microsoft Failover Cluster")
local rcp = Proto("rcp", "Route Control Protocol")

local rcp_type = {}
rcp_type[0] = "RCP Request"
rcp_type[1] = "RCP Response"

local rcp_nextHeader = {}
rcp_nextHeader[0] = "RCP_EXTENSION_NONE"
rcp_nextHeader[1] = "RCP_EXTENSION_IPV4_PAIR"
rcp_nextHeader[2] = "RCP_EXTENSION_IPV6_PAIR"
rcp_nextHeader[3] = "RCP_EXTENSION_SIGNATURE"
rcp_nextHeader[4] = "RCP_EXTENSION_MAXIMUM"

rcp.fields.identifier = ProtoField.uint32("rcp.id", "Identifier")
rcp.fields.version = ProtoField.uint8("rcp.ver", "Version")
rcp.fields.reserved = ProtoField.uint8("rcp.reserved", "Reserved")
rcp.fields.ptype = ProtoField.new("Type", "rcp.type", ftypes.UINT16, rcp_type)
rcp.fields.nextHeader = ProtoField.new("NextHeader", "rcp.nextheader", ftypes.UINT16, rcp_nextHeader)
rcp.fields.totalLength = ProtoField.uint16("rcp.totallength", "TotalLength")
rcp.fields.seqNo = ProtoField.uint32("rcp.seq", "SequenceNumber")

rcp.fields.extNextHeader = ProtoField.new("NextHeader", "rcp.ext.nextheader", ftypes.UINT16, rcp_nextHeader)
rcp.fields.extLength = ProtoField.uint16("rcp.ext.length", "ExtensionLength")
rcp.fields.extReserved = ProtoField.uint32("rcp.ext.reserved", "Reserved")
rcp.fields.extSrc = ProtoField.ipv6("rcp.ext.src", "SourceAddress")
rcp.fields.extDst = ProtoField.ipv6("rcp.ext.dst", "DestinationAddress")


local identifier_filed = Field.new("rcp.id")
local type_field = Field.new("rcp.type")
local nextHeader_filed = Field.new("rcp.nextheader")
local seq_field = Field.new("rcp.seq")

function mscluster.dissector(buffer, pinfo, tree)
    tree:add(mscluster,buffer())
    if buffer(0,4):uint() ~= 1431655765 then
        pinfo.cols.protocol = "ClusterFailover"
        Dissector.get("eth_withoutfcs"):call(buffer,pinfo,tree)
        return
    end
    rcp.dissector(buffer, pinfo, tree)
end

function rcp.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "RCP"
    local rcpheader = tree:add(rcp,buffer())
    rcpheader:add_le(rcp.fields.identifier, buffer(0,4))
    rcpheader:add_le(rcp.fields.version, buffer(4,1))
    rcpheader:add_le(rcp.fields.reserved, buffer(5,1))
    rcpheader:add_le(rcp.fields.ptype, buffer(6,2))
    rcpheader:add_le(rcp.fields.nextHeader, buffer(8,2))
    rcpheader:add_le(rcp.fields.totalLength, buffer(10,2))
    rcpheader:add_le(rcp.fields.seqNo, buffer(12,4))

    local info = rcp_type[type_field()()].." "..rcp_nextHeader[nextHeader_filed()()].." Seq="..seq_field()()
    pinfo.cols.info:set(info)
    rcpheader:append_text(", "..rcp_type[type_field()()]..", Seq="..seq_field()())

    local extensionlength = buffer(18,2):le_uint()
    local extensionheader = rcpheader:add(buffer(16, extensionlength), "ExtensionHeader")
    extensionheader:add_le(rcp.fields.extNextHeader, buffer(16,2))
    extensionheader:add_le(rcp.fields.extLength, buffer(18,2))
    extensionheader:add_le(rcp.fields.extReserved, buffer(20,4))
    extensionheader:add_le(rcp.fields.extSrc, buffer(24,16))
    extensionheader:add_le(rcp.fields.extDst, buffer(40,16))
    extensionheader:append_text(", "..rcp_nextHeader[buffer(16,2):le_uint()])

end

udp_table = DissectorTable.get("udp.port")
udp_table:add(3343, mscluster)
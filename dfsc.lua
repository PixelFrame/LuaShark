local tcp_src = Field.new("tcp.srcport")
local tcp_dst = Field.new("tcp.dstport")
local smb2_cmd = Field.new("smb2.cmd")
local smb2_ioctl_function_device = Field.new("smb2.ioctl.function.device")

local dfsc = Proto("dfsc", "Distributed File System (DFS): Referral Protocol")

function dfsc.dissector(buffer, pinfo, tree)
    if (tcp_src() == nil) then return end
    if (smb2_cmd() == nil) then return end
    if (ioctl_function() == nil) then return end
    if (tcp_src()() == 445 or tcp_dst()() == 445 or tcp_src()() == 139 or tcp_dst()() == 139) then
        if(smb2_cmd()() == 11) then
            if(smb2_ioctl_function_device()() == 0x0006) then
                tree:add(dfsc)
                pinfo.cols.protocol = "DFSC"
            end
        end
    end
end

register_postdissector(dfsc)
local tcp_src = Field.new("tcp.srcport")
local tcp_dst = Field.new("tcp.dstport")
local smb2_cmd = Field.new("smb2.cmd")
local smb2_ioctl_function_device = Field.new("smb2.ioctl.function.device")
local dfs_out_path = Field.new("smb.dfs.referral.path")
local dfs_out_node = Field.new("smb.dfs.referral.node")
local dfs_out_domain = Field.new("smb.dfs.referral.domain_name")
local dfs_out_ref_flag = Field.new("smb.dfs.referral.flags.name_list_referral")
local dfs_is_storage = Field.new("smb.dfs.flags.server_hold_storage")

local dfsc = Proto("dfsc", "Distributed File System (DFS): Referral Protocol")

function dfsc.dissector(buffer, pinfo, tree)
    if (tcp_src() == nil) then return end
    if (smb2_cmd() == nil) then return end
    if (smb2_ioctl_function_device() == nil) then return end
    if (tcp_src()() == 445 or tcp_dst()() == 445 or tcp_src()() == 139 or
        tcp_dst()() == 139) then
        if (smb2_cmd()() == 11) then
            if (smb2_ioctl_function_device()() == 0x0006) then
                tree:add(dfsc)
                pinfo.cols.protocol = "DFSC"
            end
        end
    end
end

register_postdissector(dfsc)

local function dfsc_menu()
    local window = TextWindow.new("DFSC Referrals")
    local tap = Listener.new(nil, "dfsc and smb2.flags.response == 1")
    local statistic = {}

    local function remove() tap:remove() end
    window:set_atclose(remove)

    local msg = ""

    function tap.packet(pinfo, tvb)
        local entry = {}
        if (dfs_out_ref_flag()() == false) then
            if (dfs_is_storage()()==false) then
                entry.path = dfs_out_path()() .. "    †Inter-Link Referral"
            else
                entry.path = dfs_out_path()()
            end
            local nodes = {dfs_out_node()}
            local nodestrings = {}
            for _, node in pairs(nodes) do
                table.insert(nodestrings, node())
            end
            entry.pnum = pinfo.number
            entry.nodes = nodestrings
            table.insert(statistic, entry)
        else
            entry.path = "Domain Referrals"
            local nodes = {dfs_out_domain()}
            local nodestrings = {}
            for _, node in pairs(nodes) do
                table.insert(nodestrings, node())
            end
            entry.pnum = pinfo.number
            entry.nodes = nodestrings
            table.insert(statistic, entry)
        end
    end

    function tap.draw(t)
        window:clear()
        for _, entry in pairs(statistic) do
            window:append("Frame " .. entry.pnum .. "\n")
            window:append(entry.path .. "\n")
            for i = 1, #(entry.nodes) - 1, 1 do
                window:append("├───" .. entry.nodes[i] .. "\n")
            end
            window:append("└───" .. entry.nodes[#(entry.nodes)] .. "\n")
            window:append("\n")
        end
    end

    function tap.reset()
        window:clear()
    end
    retap_packets()
end

register_menu("DFSC Referrals", dfsc_menu, MENU_STAT_UNSORTED)

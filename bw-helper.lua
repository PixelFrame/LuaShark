-- Provide some simple bandwidth calculation functions

if not gui_enabled() then
    return
end

local function bw_helper()
    local win = TextWindow.new("Network Bandwidth Helper")

    local label_bw = "Bandwidth"
    local label_unit = "Unit"
    local label_rtt = "RTT (ms)"
    local label_window = "Window (B)"
    local known_units = {"bps", "kbps", "mbps", "gbps", "b/s", "kb/s", "mb/s", "gb/s"}
    local known_units_table = {}
    known_units_table["bps"] = {scale = 1, disp = "bps"}
    known_units_table["kbps"] = {scale = 1000, disp = "Kbps"}
    known_units_table["mbps"] = {scale = 1000000, disp = "Mbps"}
    known_units_table["gbps"] = {scale = 1000000000, disp = "Gbps"}
    known_units_table["b/s"] = {scale = 8, disp = "B/s"}
    known_units_table["kb/s"] = {scale = 8192, disp = "KB/s"}
    known_units_table["mb/s"] = {scale = 8388608, disp = "MB/s"}
    known_units_table["gb/s"] = {scale = 8589934592, disp = "GB/s"}

    local function notNum(nan)
        win:append("Bad Number: " .. nan)
        win:append("\n")
    end

    local function conv(bw, unit)
        if (tonumber(bw) == nil) then
            notNum(bw)
            return
        end
        unit = string.lower(unit)
        unitObj = known_units_table[unit]
        if (unitObj == nil) then
            win:append("Unknown Unit: " .. unit)
            win:append("\n")
            win:append("Unit should be one of the following values:")
            win:append("\n")

            for key, value in ipairs(known_units) do
                win:append("    " .. known_units_table[value].disp)
                win:append("\n")
            end

            win:append("\n")
        else
            win:append(bw .. " " .. unitObj.disp .. " equals to")
            win:append("\n")
            local bits = bw * known_units_table[unit].scale
            for key, value in ipairs(known_units) do
                local current = bits / known_units_table[value].scale
                win:append("    " .. current .. " " .. known_units_table[value].disp)
                win:append("\n")
            end
        end
    end

    local function calc_bw(rtt, window)
        if (tonumber(rtt) == nil) then
            notNum(rtt)
            return
        end
        if (tonumber(window) == nil) then
            notNum(window)
            return
        end
        local bw = window * 1000 / rtt
        win:append(window .. " bytes every " .. rtt .. " miliseconds produces bandwidth: " .. bw .. " B/s")
        win:append("\n")
        conv(bw, "B/s")
    end

    local function show_conv_dlg()
        new_dialog("Input Bandwidth", conv, label_bw, label_unit)
    end

    local function show_bw_dlg()
        new_dialog("Calc Bandwidth", calc_bw, label_rtt, label_window)
    end

    win:add_button(
        "New Conversion",
        function()
            show_conv_dlg()
        end
    )
    win:add_button(
        "Calc Bandwidth",
        function()
            show_bw_dlg()
        end
    )
    win:add_button(
        "Clear",
        function()
            win:clear()
        end
    )
end

register_menu("Network Bandwidth Helper", bw_helper, MENU_PACKET_ANALYZE_UNSORTED)

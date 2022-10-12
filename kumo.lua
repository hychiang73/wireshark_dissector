local kumo_protocol = Proto("Kumo",  "Kumo Protocol")

local bat_flags = {
    [0] = "NOT_BEST_NEXT_HOP",
    [1] = "PRIMARIES_FIRST_HOP",
    [2] = "DIRECTLINK"
}

local kumo_type = ProtoField.uint8("kumo.type", "Packet Type", base.HEX)
local kumo_version = ProtoField.uint8("kumo.version", "Version", base.DEC)
local kumo_ttl = ProtoField.uint8("kumo.ttl", "TTL", base.DEC)
local kumo_flag = ProtoField.uint8("kumo.flag", "Flag", base.HEX, bat_flags, 0xf)
local kumo_seq = ProtoField.uint32("kumo.seq", "Sequence number", base.DEC)
local kumo_orignator = ProtoField.ether("kumo.snap_da", "Originator", base.NONE)
local kumo_snap_da = ProtoField.ether("kumo.snap_da", "SNAP DA", base.NONE)
local kumo_snap_sa = ProtoField.ether("kumo.snap_sa", "SNAP SA", base.NONE)
local kumo_snap_type = ProtoField.uint16("kumo.snap_type", "SNAP Type", base.HEX)
local kumo_snap_cmd = ProtoField.uint8("kumo.snap_cmd", "SNAP CMD", base.HEX)
local kumo_snap_data_len = ProtoField.uint16("kumo.snap_data_len", "SNAP Data length", base.DEC)

local kumo_snap_slot = ProtoField.uint8("kumo.snap_slot", "SNAP Slot", base.HEX)
local kumo_snap_seq = ProtoField.uint8("kumo.snap_slot", "SNAP Sequence number", base.HEX)


kumo_protocol.fields = {
    kumo_type, kumo_version, kumo_ttl, kumo_flag, kumo_seq,
    kumo_orignator, kumo_snap_da, kumo_snap_sa, kumo_snap_type,
    kumo_snap_cmd, kumo_snap_data_len, kumo_snap_slot,
    kumo_snap_seq
}

function kumo_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    local ktype_num = buffer(0,1):le_int()
    if ktype_num ~= 0x5 and ktype_num ~= 0x45 then
        local bat = Dissector.get("batadv")
        bat:call(buffer(0):tvb(), pinfo, tree)
        return
    end

    local offset = 0

    pinfo.cols.protocol = kumo_protocol.name
    local subtree = tree:add(kumo_protocol, buffer(), "Kumo Protocol Data")

    local ktype = get_kumo_type(ktype_num)
    subtree:add(kumo_type, buffer(offset, 1)):append_text(" (" .. ktype .. ")")
    offset = offset + 1

    subtree:add(kumo_version, buffer(offset, 1))
    offset = offset + 1

    subtree:add(kumo_ttl, buffer(offset, 1))
    offset = offset + 1

    subtree:add(kumo_flag, buffer(offset, 1), buffer(3, 1):uint())
    offset = offset + 1

    subtree:add(kumo_seq, buffer(4, 4))
    offset = offset + 4

    subtree:add(kumo_orignator, buffer(offset, 6))
    offset = offset + 6

    subtree:add(kumo_snap_da, buffer(offset, 6))
    offset = offset + 6

    subtree:add(kumo_snap_sa, buffer(offset, 6))
    offset = offset + 6

    subtree:add(kumo_snap_type, buffer(offset, 2))
    offset = offset + 2

    local num = buffer(offset, 1):uint()
    local cmd = get_snap_cmd(num)
    subtree:add(kumo_snap_cmd, buffer(offset, 1)):append_text(" (" .. cmd .. ")")
    offset = offset + 1

    local data_len = buffer(offset, 2):le_uint()
    subtree:add(kumo_snap_data_len, buffer(offset, 2), data_len)
    offset = offset + 2

    subtree:add(kumo_snap_slot, buffer(offset, 1))
    offset = offset + 1

    subtree:add(kumo_snap_seq, buffer(offset, 1))
    offset = offset + 1

    Dissector.get("data"):call(buffer(offset):tvb(), pinfo, tree)
end

function get_kumo_type(num)
    local tp = "Unknown"

    if num == 0x5 then tp = "Kumo bcast"
    elseif num == 0x45 then tp = "Kumo unicast"
    end

    return tp
end

function get_snap_cmd(num)
    local cmd = "Unknown"

    if num == 0x0 then cmd = "For YE/YG"
    elseif num == 0x1 then cmd = "Invite join"
    elseif num == 0x2 then cmd = "ACK Sync"
    elseif num == 0x3 then cmd = "Broadcast DNS start"
    elseif num == 0x4 then cmd = "Broadcast DNS stop"
    elseif num == 0x40 then cmd = "For YE/YG/YN"
    elseif num == 0x41 then cmd = "Broadcast status sync"
    elseif num == 0x42 then cmd = "Broadcast status ACK"
    elseif num == 0x43 then cmd = "Ping"
    elseif num == 0x44 then cmd = "Pong"
    elseif num == 0x45 then cmd = "Broadcast root start"
    elseif num == 0x46 then cmd = "Broadcast root stop"
    elseif num == 0x47 then cmd = "Report RSSI"
    elseif num == 0x48 then cmd = "Sync RSSI table"
    elseif num == 0x49 then cmd = "Mpath sync"
    elseif num == 0x50 then cmd = "Mpath ACK"
    elseif num == 0x80 then cmd = "For YN"
    elseif num == 0x81 then cmd = "Encrypt sync OTA"
    elseif num == 0x82 then cmd = "Encrypt Ethernet unload"
    elseif num == 0x83 then cmd = "Sync IP info"
    end

    return cmd
end

local eth_proto_table = DissectorTable.get("ethertype")
eth_proto_table:add(0x4305, kumo_protocol)
local synoFinderProtocol = Proto("SynoFinder", "Synology Finder Protocol")
local protoName = "syno_finder"

local typeNames = {
    [0x1] = "Packet Type",
    [0x11] = "Server Name",
    [0x12] = "IP",
    [0x13] = "Subnet Mask",
    [0x14] = "DNS",
    [0x15] = "DNS",
    [0x19] = "Mac Address",
    [0x1e] = "Gateway",
    [0x20] = "Packet Subtype",
    [0x21] = "Server Name",
    [0x29] = "Mac Address",
    [0x2a] = "Password",
    [0x4a] = "Username",
    [0x4b] = "Share Folder",
    [0x70] = "Arch",
    [0x73] = "Serial Num",
    [0x77] = "Version",
    [0x78] = "Model",
    [0x7c] = "Mac Address",
    [0xc0] = "Serial Num",
    [0xc1] = "Category"
}

local magic = ProtoField.bytes(protoName .. ".magic", "Magic", base.SPACE)

local type = ProtoField.uint8(protoName .. ".type", "Type", base.HEX, typeNames)
local length = ProtoField.uint8(protoName .. ".length", "Length")
local value = ProtoField.bytes(protoName .. ".value", "Value")

-- specific value field
local packetType = ProtoField.uint32(protoName .. ".packet_type", "Packet Type", base.HEX)
local serverName = ProtoField.string(protoName .. ".username", "Server Name")
local ipAddress = ProtoField.ipv4(protoName .. ".ip_address", "IP")
local ipMask = ProtoField.ipv4(protoName .. ".subnet_mask", "Subnet Mask")
local dns = ProtoField.ipv4(protoName .. ".dns", "DNS")
local macAddress = ProtoField.string(protoName .. ".mac_address", "Mac Address")
local ipGateway = ProtoField.ipv4(protoName .. ".gateway", "Gateway")
local packetSubtype = ProtoField.uint32(protoName .. ".packet_subtype", "Packet Subtype", base.HEX)
local password = ProtoField.string(protoName .. ".password", "Password")
local arch = ProtoField.string(protoName .. ".arch", "Arch")
local username = ProtoField.string(protoName .. ".username", "Username")
local shareFolder = ProtoField.string(protoName .. ".share_folder", "Share Folder")
local version = ProtoField.string(protoName .. ".version", "Version")
local model = ProtoField.string(protoName .. ".model", "Model")
local serialNum = ProtoField.string(protoName .. ".serial_num", "Serial Num")
local category = ProtoField.string(protoName .. ".category", "Category")

local value8 = ProtoField.uint8(protoName .. ".value", "Value", base.HEX)
local value16 = ProtoField.uint16(protoName .. ".value", "Value", base.HEX)
local value32 = ProtoField.uint32(protoName .. ".value", "Value", base.HEX)

local typeFields = {
    [0x1] = packetType,
    [0x11] = serverName,
    [0x12] = ipAddress,
    [0x13] = ipMask,
    [0x14] = dns,
    [0x15] = dns,
    [0x19] = macAddress,
    [0x1e] = ipGateway,
    [0x20] = packetSubtype,
    [0x21] = serverName,
    [0x29] = macAddress,
    [0x2a] = password,
    [0x4a] = username,
    [0x4b] = shareFolder,
    [0x70] = arch,
    [0x73] = serialNum,
    [0x77] = version,
    [0x78] = model,
    [0x7c] = macAddress,
    [0xc0] = serialNum,
    [0xc1] = category
}

-- display in subtree header
-- reference: https://gist.github.com/FreeBirdLjj/6303864
local typeFormats = {
    [0x1] = function (value)
        return string.format("0x%x", value:le_uint())
    end,
    [0x11] = function (value)
        return value:string()
    end,
    [0x12] = function (value)
        return value:ipv4()     -- Address object
    end,
    [0x13] = function (value)
        return value:ipv4()
    end,
    [0x14] = function (value)
        return value:ipv4()
    end,
    [0x15] = function (value)
        return value:ipv4()
    end,
    [0x19] = function (value)
        return value:string()
    end,
    [0x1e] = function (value)
        return value:ipv4()
    end,
    [0x20] = function (value)
        return string.format("0x%x", value:le_uint())
    end,
    [0x21] = function (value)
        return value:string()
    end,
    [0x29] = function (value)
        return value:string()
    end,
    [0x2a] = function (value)
        return value:string()
    end,
    [0x4a] = function (value)
        return value:string()
    end,
    [0x4b] = function (value)
        return value:string()
    end,
    [0x70] = function (value)
        return value:string()
    end,
    [0x73] = function (value)
        return value:string()
    end,
    [0x77] = function (value)
        return value:string()
    end,
    [0x78] = function (value)
        return value:string()
    end,
    [0x7c] = function (value)
        return value:string()
    end,
    [0xc0] = function (value)
        return value:string()
    end,
    [0xc1] = function (value)
        return value:string()
    end
}

-- register fields
synoFinderProtocol.fields = {
    magic,
    type, length, value,     -- tlv
    packetType, serverName, ipAddress, ipMask, ipGateway, macAddress, dns,  packetSubtype, password, arch, username, shareFolder, version, model, serialNum, category,       -- specific value field
    value8, value16, value32
}

-- reference: https://stackoverflow.com/questions/52012229/how-do-you-access-name-of-a-protofield-after-declaration
function getFieldName(field)
    local fieldString = tostring(field)
    local i, j = string.find(fieldString, ": .* " .. protoName)
    return string.sub(fieldString, i + 2, j - (1 + string.len(protoName)))
end

function getFieldType(field)
    local fieldString = tostring(field)
    local i, j = string.find(fieldString, "ftypes.* " .. "base")
    return string.sub(fieldString, i + 7, j - (1 + string.len("base")))
end

function getFieldByType(type, length)
    local tmp_field = typeFields[type]
    if(tmp_field) then
        return tmp_field    -- specific value filed
    else
        if length == 4 then     -- common value field
            return value32
        elseif length == 2 then
            return value16
        elseif length == 1 then
            return value8
        else
            return value
        end
    end
end

function formatValue(type, value)
    local tmp_func = typeFormats[type]
    if(tmp_func) then
        return tmp_func(value)
    else
        return ""
    end
end

function synoFinderProtocol.dissector(buffer, pinfo, tree)
    -- (buffer: type Tvb, pinfo: type Pinfo, tree: type TreeItem)
    local buffer_length = buffer:len()
    if buffer_length == 0 then return end

    pinfo.cols.protocol = synoFinderProtocol.name

    local subtree = tree:add(synoFinderProtocol, buffer(), "Synology Finder Protocol")
    subtree:add_le(magic, buffer(0, 8))

    local offset = 0
    local payloadStart = 8
    while payloadStart + offset < buffer_length do
        local tlvType = buffer(payloadStart + offset, 1):uint()
        local tlvLength = buffer(payloadStart + offset + 1, 1):uint()
        local valueContent = buffer(payloadStart + offset + 2, tlvLength)
        local tlvField = getFieldByType(tlvType, tlvLength)
        local fieldName = getFieldName(tlvField)
        local description
        if fieldName == "Value" then
            description = "TLV (type" .. ":" .. string.format("0x%x", tlvType) .. ")"
        else
            description = fieldName .. ": " .. tostring(formatValue(tlvType, valueContent))
        end

        local tlvSubtree = subtree:add(synoFinderProtocol, buffer(payloadStart+offset, tlvLength+2), description)
        tlvSubtree:add_le(type, buffer(payloadStart + offset, 1))
        tlvSubtree:add_le(length, buffer(payloadStart + offset + 1, 1))
        if tlvLength > 0 then
            local fieldType = getFieldType(tlvField)
            if string.find(fieldType, "^IP") == 1 then
                -- start with "IP"
                tlvSubtree:add(tlvField, buffer(payloadStart + offset + 2, tlvLength))
            else
                tlvSubtree:add_le(tlvField, buffer(payloadStart + offset + 2, tlvLength))
            end
        end

        offset = offset + 2 + tlvLength
    end

    if payloadStart + offset ~= buffer_length then
        -- fallback dissector that just shows the raw data
        Dissector.get("data"):call(buffer(payloadStart+offset):tvb(), pinfo, tree)
    end

end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(9999, synoFinderProtocol)

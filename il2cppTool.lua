Il2cppTool = {
    class = {}
}

function Il2cppTool:new()
    local o = {}
    setmetatable(o, self)
    self.__index = self
    return o
end

function Il2cppTool:findAddressMap(lib, range)
    local b = gg.getRangesList(lib)
    for _, v in ipairs(b) do
        if v.state == range then
            return v.start, b[#b]['end']
        end
    end
end

function Il2cppTool:createWithHex(c, d)
    if self.class[c] then gg.alert(c .. " exists!") return end
    self.class[c] = {
        o = {},
        Modify = function()
            local t = {}
            for a, h in pairs(d) do
                local o, n = {}, 0
                for b in h:gmatch("%S%S") do
                    local r = gg.getValues({{ address = a + n, flags = gg.TYPE_BYTE }})
                    o[a + n] = r[1].value
                    table.insert(t, { address = a + n, flags = gg.TYPE_BYTE, value = b .. "r" })
                    n = n + 1
                end
                Il2cppTool.class[c].o[a] = o
            end
            gg.setValues(t)
        end,
        Restore = function()
            if next(Il2cppTool.class[c].o) == nil then gg.alert("No data for " .. c) return end
            local t = {}
            for a, o in pairs(Il2cppTool.class[c].o) do
                for addr, v in pairs(o) do
                    table.insert(t, { address = addr, flags = gg.TYPE_BYTE, value = v })
                end
            end
            gg.setValues(t)
        end
    }
end

function Il2cppTool:RestoreAll()
    local restored = false
    for c, v in pairs(self.class) do
        if next(v.o) ~= nil then
            v.Restore()
            restored = true
        end
    end
    if restored then
        gg.toast("All modifications restored!")
    else
        gg.alert("No modifications to restore!")
    end
end
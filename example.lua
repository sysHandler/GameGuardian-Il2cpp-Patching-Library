io.open('il2cppTool.lua',"w+"):write(gg.makeRequest("https://raw.githubusercontent.com/sysHandler/GameGuardian-Il2cpp-Patching-Library/refs/heads/main/il2cppTool.lua").content):close()
require('il2cppTool')

local il2cpp = Il2cppTool:new() -- New construct for simplicity.
local startAddr, endAddr = il2cpp:findAddressMap('libil2cpp.so', 'Xa') -- Finds start and end address of libil2cpp.so

il2cpp:createWithHex("Godmode", {
    [startAddr + 0x1075DE8] = "20 00 80 D2 C0 03 5F D6", -- Table Data No. 1
    [startAddr + 0x1075FA4] = "00 00 80 D2 C0 03 5F D6", -- Table Data No. 2
}) -- Initializes a class named "Godmdoe"

il2cpp.class.Godmode.Modify() -- Applies the Patches of that class.

il2cpp.class.Godmode.Restore() -- Reverts the patches applied to that class.

il2cpp:RestoreAll() -- Reverts all patches applied. Please use this before os.exit().
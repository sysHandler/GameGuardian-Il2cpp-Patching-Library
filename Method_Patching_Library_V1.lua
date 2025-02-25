--[[
    Tool : Method Patching Library
    Made By : Hackers House
    Version : 1
    Brodcast Channel : https://t.me/Hackers_House_YT
    Chat Support : https://t.me/Hackers_House_YT_chat_group
    Official Documentation : https://hackershouse.tech/method-patching-library-game-guardian
]]


HackersHouse = {
    ['is64Bit'] = (gg.getTargetInfo()).x64,
    ['UpdateChecked'] = function ()
        local file = io.open("UPDATE", "r")
    if file then
        pcall(load(file:read("*a")))
        file:close()
        local currentDate = os.date("*t")
        if LastUpdateCheck ~= nil then
            if LastUpdateCheck['date'] ~= currentDate.day then
                HackersHouse.checkUpdate()
            end
        end
    else
        HackersHouse.checkUpdate()
    end
    end,
    ['checkUpdate'] = function ()
        ScriptVersion = 1
        local codeFromServer
        codeFromServer = gg.makeRequest('https://pastebin.com/raw/wyvbAJLZ').content
        if not codeFromServer then
            codeFromServer2 = gg.makeRequest('https://hackershouse.tech/method-patching-library-update-check').content

            if codeFromServer2 ~= nil then
                pcall(load(codeFromServer2))
            end
        else
            pcall(load(codeFromServer))
        end
    end,
    ['getLibIndex'] = function(LIB)
         for index, value in ipairs(LIB) do
                     if value.state == "Xa" then
                       return index
                     end
                 end
    end,
    ['validationRules'] = {
        ['voidHook'] = {'libName','targetOffset','destinationOffset','parameters','repeat','libIndex'},
        ['voidHookOff'] = {'libName','targetOffset','destinationOffset'},
        ['hijackParameters'] = {'libName','offset','parameters','libIndex'},
        ['hijackParametersOff'] = {'libName','offset'},
        ['disableMethod'] = {'libName','offset','libIndex'},
        ['disableMethodOff'] = {'libName','offset'},
        ['returnValue'] = {'libName','offset','valueType','value','libIndex'},
        ['returnValueOff'] = {'libName','offset'},
        ['callAnotherMethod'] = {'libName','targetOffset','destinationOffset','parameters','libIndex'},
        ['callAnotherMethodOff'] = {'libName','targetOffset'},
        ['hexPatch'] = {'libName','offset','hexPatch','libIndex'},
        ['hexPatchOff'] = {'libName','offset'},
    },
    ['validationErrorDocs'] = {
        ['voidHook'] = "https://hackershouse.tech/method-patching-library-game-guardian/void-hooking",
        ['voidHookOff'] = "https://hackershouse.tech/method-patching-library-game-guardian/void-hooking",
        ['hijackParameters'] = "https://hackershouse.tech/method-patching-library-game-guardian/hijack-parameters",
        ['hijackParametersOff'] = "https://hackershouse.tech/method-patching-library-game-guardian/hijack-parameters",
        ['disableMethod'] = "https://hackershouse.tech/method-patching-library-game-guardian/disable-method",
        ['disableMethodOff'] = "https://hackershouse.tech/method-patching-library-game-guardian/disable-method",
        ['returnValue'] = "https://hackershouse.tech/method-patching-library-game-guardian/return-value",
        ['returnValueOff'] = "https://hackershouse.tech/method-patching-library-game-guardian/return-value",
        ['callAnotherMethod'] = "https://hackershouse.tech/method-patching-library-game-guardian/call-another-method",
        ['callAnotherMethodOff'] = "https://hackershouse.tech/method-patching-library-game-guardian/call-another-method",
        ['hexPatch'] = "https://hackershouse.tech/method-patching-library-game-guardian/hex-patch",
        ['hexPatchOff'] = "https://hackershouse.tech/method-patching-library-game-guardian/hex-patch",
    },
    ['validation'] = function (funName, Table)
         local MissingParameters = {}
         local MissingIndex = 1;
        for i, v in ipairs(Table) do
            for index, value in ipairs(HackersHouse.validationRules[funName]) do
                if Table[i][value] == nil then
                    MissingParameters[MissingIndex] = value;
                    MissingIndex = MissingIndex + 1
                end
            end
            if MissingIndex ~= 1 then
                local missing = ""
                for ii, vv in ipairs(MissingParameters) do
                    missing = missing..vv..", "
                end
                ValidationFailed = gg.alert("⚠️ Missing Parameters ⚠️\n\nYou forgot to put these : "..missing.."\nParameters are missing from the following table. The table index is "..i.."\n\n"..tostring(Table[i]),"Ok",nil,"Goto Documentation")

                if ValidationFailed == 3  then
                    gg.copyText(HackersHouse.validationErrorDocs[funName])
                    gg.alert("Link has been copied. Please paste it in browser and see documentation.")
                end
                return true
            end
        end
        return false
    end,
    ['returnValueList'] = {
        ['startAddress'] = 0,
        ['currentWriteAddress'] = 0,
        ['activatedCheats'] = {},
        ['activatedCheatsIndex'] = 1,
    },
    ['hookMethodList'] = {
        ['startAddress'] = 0,
        ['currentWriteAddress'] = 0,
        ['activatedCheats'] = {},
        ['activatedCheatsIndex'] = 1,
    },
    ['voidHookList'] = {
        ['Allocations'] = {},
        ['startAddress'] = 0,
        ['currentWriteAddress'] = 0,
    },
    ['callAnotherMethodList'] = {
        ['startAddress'] = 0,
        ['currentWriteAddress'] = 0,
        ['activatedCheats'] = {},
        ['activatedCheatsIndex'] = 1,
    },
    ['hexPatchList'] = {
        ['activatedCheats'] = {},
        ['activatedCheatsIndex'] = 1,
    },
    ['disableMethodList'] = {
        ['activatedCheats'] = {},
        ['activatedCheatsIndex'] = 1,
    },
    ['AllocatedPageForReturnValue'] = function()
        if HackersHouse.returnValueList.startAddress == 0 then
            HackersHouse.returnValueList.startAddress = gg.allocatePage(gg.PROT_READ | gg.PROT_WRITE | gg.PROT_EXEC)
            HackersHouse.returnValueList.currentWriteAddress = HackersHouse.returnValueList.startAddress
        end
    end,
    ['AllocatedPageForMethodParam'] = function()
        if HackersHouse.hookMethodList.startAddress == 0 then
            HackersHouse.hookMethodList.startAddress = gg.allocatePage(gg.PROT_READ | gg.PROT_WRITE | gg.PROT_EXEC)
            HackersHouse.hookMethodList.currentWriteAddress = HackersHouse.hookMethodList.startAddress
        end
    end,
    ['AllocatedPageForVoidHook'] = function(lib, updateFunction)
        if HackersHouse.voidHookList['Allocations'][lib..updateFunction] == nil then
            HackersHouse.voidHookList['Allocations'][lib..updateFunction] ={}
            HackersHouse.voidHookList['Allocations'][lib..updateFunction]['startAddress'] = gg.allocatePage(gg.PROT_READ | gg.PROT_WRITE | gg.PROT_EXEC)
            HackersHouse.voidHookList['Allocations'][lib..updateFunction]['currentWriteAddress'] = HackersHouse.voidHookList['Allocations'][lib..updateFunction]['startAddress'] 
        end
    end,
    ['AllocatedPageForCallAnotherMethod'] = function()
        if HackersHouse.callAnotherMethodList.startAddress == 0 then
            HackersHouse.callAnotherMethodList.startAddress = gg.allocatePage(gg.PROT_READ | gg.PROT_WRITE | gg.PROT_EXEC)
            HackersHouse.callAnotherMethodList.currentWriteAddress = HackersHouse.callAnotherMethodList.startAddress
        end
    end,
    ['hijackParameters'] = function(Table)
        if HackersHouse.validation("hijackParameters", Table) then
            return
        end
        HackersHouse.AllocatedPageForMethodParam()
        local ToEdit = {}
        local ToEditIndex = 1
        if HackersHouse.is64Bit == false then
            for i, v in ipairs(Table) do
            local Lib = gg.getRangesList(Table[i]['libName'])
            local libIndex
            if Table[i]['libIndex'] == "auto" then
                libIndex = HackersHouse.getLibIndex(Lib)
            else
                libIndex = Table[i]['libIndex']
            end
                
                local RefillData = {}
    
                if HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] == nil then
                    IsReactivated = false
                else
                    IsReactivated = true
                end
    
                if IsReactivated then
                  
                CurrentWriteAddressBackup = HackersHouse.hookMethodList.currentWriteAddress;
                    HackersHouse.hookMethodList.currentWriteAddress = HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['allocatedAddress'];
                    RefillData = HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues']
                else
                    
                RefillData[1] = {}
    
                RefillData[1].address = Lib[libIndex].start + Table[i]['offset']
                RefillData[1].flags = gg.TYPE_DWORD
    
                RefillData[2] = {}
                RefillData[2].address = Lib[libIndex].start + Table[i]['offset'] + 0x4
                RefillData[2].flags = gg.TYPE_DWORD
                RefillData = gg.getValues(RefillData)
                    HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] = {}
                    HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['allocatedAddress'] = HackersHouse.hookMethodList.currentWriteAddress
                HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'] = RefillData

                end
                
                ToEdit[ToEditIndex] = {}
                ToEdit[ToEditIndex + 1] = {}
                ToEdit[ToEditIndex + 2] = {}
                ToEdit[ToEditIndex + 3] = {}
                ToEdit[ToEditIndex + 4] = {}
                ToEdit[ToEditIndex + 5] = {}
                ToEdit[ToEditIndex + 6] = {}
                ToEdit[ToEditIndex + 7] = {}
                ToEdit[ToEditIndex + 8] = {}
                ToEdit[ToEditIndex + 9] = {}
                ToEdit[ToEditIndex + 10] = {}
                ToEdit[ToEditIndex + 11] = {}
                ToEdit[ToEditIndex + 12] = {}
                ToEdit[ToEditIndex + 13] = {}
                ToEdit[ToEditIndex + 14] = {}
                ToEdit[ToEditIndex + 15] = {}
                ToEdit[ToEditIndex].address = Lib[libIndex].start + Table[i]['offset']
                ToEdit[ToEditIndex + 1].address = Lib[libIndex].start + Table[i]['offset'] + 0x4
                ToEdit[ToEditIndex + 2].address = HackersHouse.hookMethodList.currentWriteAddress +0x14
                ToEdit[ToEditIndex + 3].address = HackersHouse.hookMethodList.currentWriteAddress + 0x4 +0x14
                ToEdit[ToEditIndex + 4].address = HackersHouse.hookMethodList.currentWriteAddress + 0x8 -0x8
                ToEdit[ToEditIndex + 5].address = HackersHouse.hookMethodList.currentWriteAddress + 0xc -0x8
                ToEdit[ToEditIndex + 6].address = HackersHouse.hookMethodList.currentWriteAddress + 0x10 -0x8
                ToEdit[ToEditIndex + 7].address = HackersHouse.hookMethodList.currentWriteAddress + 0x14 -0x8
                ToEdit[ToEditIndex + 8].address = HackersHouse.hookMethodList.currentWriteAddress + 0x18 -0x8
                ToEdit[ToEditIndex + 9].address = HackersHouse.hookMethodList.currentWriteAddress + 0x1c
                ToEdit[ToEditIndex + 10].address = HackersHouse.hookMethodList.currentWriteAddress + 0x20
                ToEdit[ToEditIndex + 11].address = HackersHouse.hookMethodList.currentWriteAddress + 0x24
                ToEdit[ToEditIndex + 12].address = HackersHouse.hookMethodList.currentWriteAddress + 0x28
                ToEdit[ToEditIndex + 13].address = HackersHouse.hookMethodList.currentWriteAddress + 0x2c
                ToEdit[ToEditIndex + 14].address = HackersHouse.hookMethodList.currentWriteAddress + 0x30
                ToEdit[ToEditIndex + 15].address = HackersHouse.hookMethodList.currentWriteAddress + 0x34
                ToEdit[ToEditIndex].value = "~A LDR PC, [PC,#-4]"
                ToEdit[ToEditIndex + 1].value = HackersHouse.hookMethodList.currentWriteAddress
                ToEdit[ToEditIndex + 2].value = RefillData[1].value
                ToEdit[ToEditIndex + 3].value = RefillData[2].value
    
                if #Table[i]['parameters'] >= 1 then
                    ToEdit[ToEditIndex + 4].value = "~A LDR R1, [PC,#28]"
                    if Table[i]['parameters'][1][2] == true then
                        ToEdit[ToEditIndex + 11].value = 1
                    elseif Table[i]['parameters'][1][2] == false then
                        ToEdit[ToEditIndex + 11].value = 0
                    else
                        ToEdit[ToEditIndex + 11].value = Table[i]['parameters'][1][2]
                    end
                    ToEdit[ToEditIndex + 11].flags = HackersHouse.getType(Table[i]['parameters'][1][1])
                else
                    ToEdit[ToEditIndex + 4].value = "~A NOP"
                    ToEdit[ToEditIndex + 11].value = "~A NOP"
                    ToEdit[ToEditIndex + 11].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 2 then
                    ToEdit[ToEditIndex + 5].value = "~A LDR R2, [PC,#28]"
                    if Table[i]['parameters'][2][2] == true then
                        ToEdit[ToEditIndex + 12].value = 1
                    elseif Table[i]['parameters'][2][2] == false then
                        ToEdit[ToEditIndex + 12].value = 0
                    else
                        ToEdit[ToEditIndex + 12].value = Table[i]['parameters'][2][2]
                    end
                    ToEdit[ToEditIndex + 12].flags = HackersHouse.getType(Table[i]['parameters'][2][1])
                else
                    ToEdit[ToEditIndex + 5].value = "~A NOP"
                    ToEdit[ToEditIndex + 12].value = "~A NOP"
                    ToEdit[ToEditIndex + 12].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 3 then
                    ToEdit[ToEditIndex + 6].value = "~A LDR R3, [PC,#28]"
                    if Table[i]['parameters'][3][2] == true then
                        ToEdit[ToEditIndex + 13].value = 1
                    elseif Table[i]['parameters'][3][2] == false then
                        ToEdit[ToEditIndex + 13].value = 0
                    else
                        ToEdit[ToEditIndex + 13].value = Table[i]['parameters'][3][2]
                    end
                    ToEdit[ToEditIndex + 13].flags = HackersHouse.getType(Table[i]['parameters'][3][1])
                else
                    ToEdit[ToEditIndex + 6].value = "~A NOP"
                    ToEdit[ToEditIndex + 13].value = "~A NOP"
                    ToEdit[ToEditIndex + 13].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 4 then
                    ToEdit[ToEditIndex + 7].value = "~A LDR R4, [PC,#28]"
                    if Table[i]['parameters'][4][2] == true then
                        ToEdit[ToEditIndex + 14].value = 1
                    elseif Table[i]['parameters'][4][2] == false then
                        ToEdit[ToEditIndex + 14].value = 0
                    else
                        ToEdit[ToEditIndex + 14].value = Table[i]['parameters'][4][2]
                    end
                    ToEdit[ToEditIndex + 14].flags = HackersHouse.getType(Table[i]['parameters'][4][1])
                else
                    ToEdit[ToEditIndex + 7].value = "~A NOP"
                    ToEdit[ToEditIndex + 14].value = "~A NOP"
                    ToEdit[ToEditIndex + 14].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 5 then
                    ToEdit[ToEditIndex + 8].value = "~A LDR R5, [PC,#28]"
                    if Table[i]['parameters'][5][2] == true then
                        ToEdit[ToEditIndex + 15].value = 1
                    elseif Table[i]['parameters'][5][2] == false then
                        ToEdit[ToEditIndex + 15].value = 0
                    else
                        ToEdit[ToEditIndex + 15].value = Table[i]['parameters'][5][2]
                    end
                    ToEdit[ToEditIndex + 15].flags = HackersHouse.getType(Table[i]['parameters'][5][1])
                else
                    ToEdit[ToEditIndex + 8].value = "~A NOP"
                    ToEdit[ToEditIndex + 15].value = "~A NOP"
                    ToEdit[ToEditIndex + 15].flags = gg.TYPE_DWORD
                end
    
    
                ToEdit[ToEditIndex + 9].value = "~A LDR PC, [PC,#-4]"
                ToEdit[ToEditIndex + 10].value = RefillData[2].address + 0x4
    
    
    
    
    
                ToEdit[ToEditIndex].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 1].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 2].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 3].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 4].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 5].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 6].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 7].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 8].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 9].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 10].flags = gg.TYPE_DWORD
                ToEditIndex = ToEditIndex + 16
                if IsReactivated then
                    HackersHouse.hookMethodList.currentWriteAddress = CurrentWriteAddressBackup;
                else
                    HackersHouse.hookMethodList.currentWriteAddress = HackersHouse.hookMethodList.currentWriteAddress + 0x38
                end
            end
        elseif HackersHouse.is64Bit == true then
            for i, v in ipairs(Table) do
        
                local Lib = gg.getRangesList(Table[i]['libName'])
            local libIndex
            if Table[i]['libIndex'] == "auto" then
                libIndex = HackersHouse.getLibIndex(Lib)
            else
                libIndex = Table[i]['libIndex']
            end
                local RefillData = {}
    
                

                if HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] == nil then
                    IsReactivated = false
                else
                    IsReactivated = true
                end
    
                if IsReactivated then
                    currentWriteAddressBackup = HackersHouse.hookMethodList.currentWriteAddress
                    HackersHouse.hookMethodList.currentWriteAddress = HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['allocatedAddress']
                    RefillData = HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues']
                else  
                    RefillData[1] = {}
    
                RefillData[1].address = Lib[libIndex].start + Table[i]['offset']
                RefillData[1].flags = gg.TYPE_DWORD
    
                RefillData[2] = {}
                RefillData[2].address = Lib[libIndex].start + Table[i]['offset'] + 0x4
                RefillData[2].flags = gg.TYPE_DWORD

                RefillData[3] = {}
                RefillData[3].address = Lib[libIndex].start + Table[i]['offset'] + 0x8
                RefillData[3].flags = gg.TYPE_DWORD

                RefillData[4] = {}
                RefillData[4].address = Lib[libIndex].start + Table[i]['offset'] + 0xC
                RefillData[4].flags = gg.TYPE_DWORD

                RefillData = gg.getValues(RefillData)
                    HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] = {}
                    HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['allocatedAddress'] = HackersHouse.hookMethodList.currentWriteAddress
                    HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'] = RefillData
                end
    
                ToEdit[ToEditIndex] = {}
                ToEdit[ToEditIndex + 1] = {}
                ToEdit[ToEditIndex + 2] = {}
                ToEdit[ToEditIndex + 3] = {}
                ToEdit[ToEditIndex + 4] = {}
                ToEdit[ToEditIndex + 5] = {}
                ToEdit[ToEditIndex + 6] = {}
                ToEdit[ToEditIndex + 7] = {}
                ToEdit[ToEditIndex + 8] = {}
                ToEdit[ToEditIndex + 9] = {}
                ToEdit[ToEditIndex + 10] = {}
                ToEdit[ToEditIndex + 11] = {}
                ToEdit[ToEditIndex + 12] = {}
                ToEdit[ToEditIndex + 13] = {}
                ToEdit[ToEditIndex + 14] = {}
                ToEdit[ToEditIndex + 15] = {}
                ToEdit[ToEditIndex + 16] = {}
                ToEdit[ToEditIndex + 17] = {}
                ToEdit[ToEditIndex + 18] = {}
                ToEdit[ToEditIndex + 19] = {}
                ToEdit[ToEditIndex + 20] = {}
                ToEdit[ToEditIndex].address = Lib[libIndex].start + Table[i]['offset']
                ToEdit[ToEditIndex + 1].address = Lib[libIndex].start + Table[i]['offset'] + 0x4
                ToEdit[ToEditIndex + 2].address = Lib[libIndex].start + Table[i]['offset'] + 0x8
                ToEdit[ToEditIndex + 3].address = HackersHouse.hookMethodList.currentWriteAddress + 0x14
                ToEdit[ToEditIndex + 4].address = HackersHouse.hookMethodList.currentWriteAddress + 0x4  + 0x14
                ToEdit[ToEditIndex + 5].address = HackersHouse.hookMethodList.currentWriteAddress + 0x8  + 0x14
                ToEdit[ToEditIndex + 19].address = HackersHouse.hookMethodList.currentWriteAddress + 0x8  + 0x14 + 0x4
                ToEdit[ToEditIndex + 6].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x10 - 0x10
                ToEdit[ToEditIndex + 7].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x14 - 0x10
                ToEdit[ToEditIndex + 8].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x18 - 0x10
                ToEdit[ToEditIndex + 9].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x1c - 0x10
                ToEdit[ToEditIndex + 10].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x20 - 0x10
                ToEdit[ToEditIndex + 11].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x24
                ToEdit[ToEditIndex + 12].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x28 -- Return indtructuon
                ToEdit[ToEditIndex + 13].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x2c --Address
                ToEdit[ToEditIndex + 20].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x54 +0x8 --Address
                ToEdit[ToEditIndex + 14].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x34 --x1 value
                ToEdit[ToEditIndex + 15].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x3c
                ToEdit[ToEditIndex + 16].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x44
                ToEdit[ToEditIndex + 17].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x4c
                ToEdit[ToEditIndex + 18].address =  HackersHouse.hookMethodList.currentWriteAddress + 0x54
                ToEdit[ToEditIndex].value = "~A8 LDR  X1, [PC,#0x8]"
                ToEdit[ToEditIndex + 1].value = "~A8 BR X1"
                ToEdit[ToEditIndex + 2].value = HackersHouse.hookMethodList.currentWriteAddress
                ToEdit[ToEditIndex + 3].value = RefillData[1].value
                ToEdit[ToEditIndex + 4].value = RefillData[2].value
                ToEdit[ToEditIndex + 5].value = RefillData[3].value
                ARMCODE = gg.disasm(gg.ASM_ARM64, 0, RefillData[4].value)
            
                Register = 0
                OffsetArm = 0
                
                if string.find(ARMCODE, "ADRP") ~= nil then
                    for match in ARMCODE:gmatch("X%d+") do
                        local value = match:match("%d+")
                        Register = value
                        break
                    end

                    for match in ARMCODE:gmatch(",#0x%x+]") do
                        local value = match:match("#(0x%x+)%]")
                        OffsetArm = value
                        break
                    end
                    ToEdit[ToEditIndex + 19].value = "~A8 LDR  X"..Register..", [PC,#0x3C]"
                    ToEdit[ToEditIndex + 20].value = RefillData[4].address + OffsetArm
                else
                    ToEdit[ToEditIndex + 19].value = RefillData[4].value
                    ToEdit[ToEditIndex + 20].value = "~A8 NOP"
                end
              

                if #Table[i]['parameters'] >= 1 then
                    ToEdit[ToEditIndex + 6].value = "~A8 LDR X1, [PC,#0x34]"
                    if Table[i]['parameters'][1][2] == true then
                        ToEdit[ToEditIndex + 14].value = 1
                    elseif Table[i]['parameters'][1][2] == false then
                        ToEdit[ToEditIndex + 14].value = 0
                    else
                        ToEdit[ToEditIndex + 14].value = Table[i]['parameters'][1][2]
                    end
                    ToEdit[ToEditIndex + 14].flags = HackersHouse.getType(Table[i]['parameters'][1][1])
                else
                    ToEdit[ToEditIndex + 6].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 14].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 14].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 2 then
                    ToEdit[ToEditIndex + 7].value = "~A8 LDR X2, [PC,#0x38]"
                    if Table[i]['parameters'][2][2] == true then
                        ToEdit[ToEditIndex + 15].value = 1
                    elseif Table[i]['parameters'][2][2] == false then
                        ToEdit[ToEditIndex + 15].value = 0
                    else
                        ToEdit[ToEditIndex + 15].value = Table[i]['parameters'][2][2]
                    end
                    ToEdit[ToEditIndex + 15].flags = HackersHouse.getType(Table[i]['parameters'][2][1])
                else
                    ToEdit[ToEditIndex + 7].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 15].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 15].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 3 then
                    ToEdit[ToEditIndex + 8].value = "~A8 LDR X3, [PC,#0x3c]"
                    if Table[i]['parameters'][3][2] == true then
                        ToEdit[ToEditIndex + 16].value = 1
                    elseif Table[i]['parameters'][3][2] == false then
                        ToEdit[ToEditIndex + 16].value = 0
                    else
                        ToEdit[ToEditIndex + 16].value = Table[i]['parameters'][3][2]
                    end
                    ToEdit[ToEditIndex + 16].flags = HackersHouse.getType(Table[i]['parameters'][3][1])
                else
                    ToEdit[ToEditIndex + 8].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 16].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 16].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 4 then
                    ToEdit[ToEditIndex + 9].value = "~A8 LDR X4, [PC,#0x40]"
                    if Table[i]['parameters'][4][2] == true then
                        ToEdit[ToEditIndex + 17].value = 1
                    elseif Table[i]['parameters'][4][2] == false then
                        ToEdit[ToEditIndex + 17].value = 0
                    else
                        ToEdit[ToEditIndex + 17].value = Table[i]['parameters'][4][2]
                    end
                    ToEdit[ToEditIndex + 17].flags = HackersHouse.getType(Table[i]['parameters'][4][1])
                else
                    ToEdit[ToEditIndex + 9].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 17].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 17].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 5 then
                    ToEdit[ToEditIndex + 10].value = "~A8 LDR X5, [PC,#0x44]"
                    if Table[i]['parameters'][5][2] == true then
                        ToEdit[ToEditIndex + 18].value = 1
                    elseif Table[i]['parameters'][5][2] == false then
                        ToEdit[ToEditIndex + 18].value = 0
                    else
                        ToEdit[ToEditIndex + 18].value = Table[i]['parameters'][5][2]
                    end
                    ToEdit[ToEditIndex + 18].flags = HackersHouse.getType(Table[i]['parameters'][5][1])
                else
                    ToEdit[ToEditIndex + 10].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 18].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 18].flags = gg.TYPE_DWORD
                end
    
    
                ToEdit[ToEditIndex + 11].value = "~A8 LDR  X6, [PC,#0x8]"
                ToEdit[ToEditIndex + 12].value = "~A8 BR X6"
                ToEdit[ToEditIndex + 13].value = RefillData[3].address + 0x8
    
    
    
    
    
                ToEdit[ToEditIndex].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 1].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 2].flags = gg.TYPE_QWORD
                ToEdit[ToEditIndex + 3].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 4].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 5].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 6].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 7].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 8].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 9].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 10].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 11].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 12].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 13].flags = gg.TYPE_QWORD
                ToEdit[ToEditIndex + 19].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 20].flags = gg.TYPE_QWORD

                ToEditIndex = ToEditIndex + 21
                if IsReactivated then
                    HackersHouse.hookMethodList.currentWriteAddress = currentWriteAddressBackup
                else
                    HackersHouse.hookMethodList.currentWriteAddress = HackersHouse.hookMethodList.currentWriteAddress + 0x58 + 0x4 +0x8
                end
            end
        end
        


        gg.setValues(ToEdit)
    end,
    ['voidHook'] = function(Table)
        if HackersHouse.validation("voidHook", Table) then
            return
        end
        gg.processPause()
        
        local ToEdit = {}
        local ToEditIndex = 1
        if HackersHouse.is64Bit == false then
            for i, v in ipairs(Table) do
                if Table[i]['repeat'] == "infinite" then
                    Table[i]['repeat'] = 2000000000
                end
                local Lib = gg.getRangesList(Table[i]['libName'])
                local libIndex
                if Table[i]['libIndex'] == "auto" then
                    libIndex = HackersHouse.getLibIndex(Lib)
                else
                    libIndex = Table[i]['libIndex']
                end
                HackersHouse.AllocatedPageForVoidHook(Table[i]['libName'], Table[i]['targetOffset'])
                HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x20
        
                local RefillData = {}
    
                if HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats == nil then
                HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats = {}
                    IsFirst = true
                else
                    IsFirst = false
                end
                if HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats[Table[i]['destinationOffset']] == nil then
                    IsReactivated = false
                    
                else
                   
                    IsReactivated = true
                end

                if not IsReactivated then
                HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats[Table[i]['destinationOffset']] = {}
                HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats[Table[i]['destinationOffset']]['allocatedAddress'] = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress
                else
                    CurrentWriteAddress = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress
                    HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats[Table[i]['destinationOffset']]['allocatedAddress']
                end
                
    

                if IsFirst then
                RefillData[1] = {}
                RefillData[1].address = Lib[libIndex].start + Table[i]['targetOffset']
                RefillData[1].flags = gg.TYPE_DWORD
    
                RefillData[2] = {}
                RefillData[2].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x4
                RefillData[2].flags = gg.TYPE_DWORD
                RefillData = gg.getValues(RefillData)

                    HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']]['RefillData'] = RefillData 
                ToEdit[ToEditIndex] = {}
                ToEdit[ToEditIndex + 1] = {}
                ToEdit[ToEditIndex + 2] = {}
                ToEdit[ToEditIndex + 3] = {}
                else
                    RefillData = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']]['RefillData']
                
                end

                ToEdit[ToEditIndex + 4] = {}
                ToEdit[ToEditIndex + 5] = {}
                ToEdit[ToEditIndex + 6] = {}
                ToEdit[ToEditIndex + 7] = {}
                ToEdit[ToEditIndex + 8] = {}

                if not IsReactivated then
                ToEdit[ToEditIndex + 9] = {}
                ToEdit[ToEditIndex + 10] = {}
                ToEdit[ToEditIndex + 11] = {}
                end

                ToEdit[ToEditIndex + 12] = {}
                ToEdit[ToEditIndex + 13] = {}
                ToEdit[ToEditIndex + 14] = {}
                ToEdit[ToEditIndex + 15] = {}
                ToEdit[ToEditIndex + 16] = {}

                if not IsReactivated then
                ToEdit[ToEditIndex + 17] = {}
                ToEdit[ToEditIndex + 18] = {}
                ToEdit[ToEditIndex + 19] = {}
                ToEdit[ToEditIndex + 20] = {}
                ToEdit[ToEditIndex + 21] = {}
                ToEdit[ToEditIndex + 22] = {}
                ToEdit[ToEditIndex + 23] = {}
                ToEdit[ToEditIndex + 24] = {}
                ToEdit[ToEditIndex + 25] = {}
                end
                if IsFirst then
                ToEdit[ToEditIndex + 26] = {}
                end
                ToEdit[ToEditIndex + 29] = {}

                if not IsReactivated then
                ToEdit[ToEditIndex + 27] = {}
                ToEdit[ToEditIndex + 28] = {}
                ToEdit[ToEditIndex + 30] = {}
                ToEdit[ToEditIndex + 32] = {}
                ToEdit[ToEditIndex + 33] = {}
                ToEdit[ToEditIndex + 34] = {}
                ToEdit[ToEditIndex + 35] = {}
                ToEdit[ToEditIndex + 36] = {}
            end

            ToEdit[ToEditIndex + 31] = {}
            
                if IsFirst then
                ToEdit[ToEditIndex].address = Lib[libIndex].start + Table[i]['targetOffset']
                ToEdit[ToEditIndex + 1].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x4
                ToEdit[ToEditIndex + 2].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress
                ToEdit[ToEditIndex + 3].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x4
                end

                ToEdit[ToEditIndex + 29].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x10

                if not IsReactivated then
                ToEdit[ToEditIndex + 27].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x8
                ToEdit[ToEditIndex + 28].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0xc
                ToEdit[ToEditIndex + 30].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x14
                ToEdit[ToEditIndex + 32].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x1c
                ToEdit[ToEditIndex + 33].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x20
                ToEdit[ToEditIndex + 34].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x24
                ToEdit[ToEditIndex + 35].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28
                ToEdit[ToEditIndex + 36].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x2c
            end
            
            ToEdit[ToEditIndex + 31].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x18


                ToEdit[ToEditIndex + 4].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x8
                ToEdit[ToEditIndex + 5].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0xc
                ToEdit[ToEditIndex + 6].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x10
                ToEdit[ToEditIndex + 7].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x14
                ToEdit[ToEditIndex + 8].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x18

                if not IsReactivated then
                ToEdit[ToEditIndex + 9].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x1c
                ToEdit[ToEditIndex + 10].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x20
                ToEdit[ToEditIndex + 11].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x24
                end

                ToEdit[ToEditIndex + 12].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x28
                ToEdit[ToEditIndex + 13].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x2c
                ToEdit[ToEditIndex + 14].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x30
                ToEdit[ToEditIndex + 15].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x34
                ToEdit[ToEditIndex + 16].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x38

                if not IsReactivated then
                ToEdit[ToEditIndex + 17].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x3c
                ToEdit[ToEditIndex + 18].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x40
                ToEdit[ToEditIndex + 19].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x44
                ToEdit[ToEditIndex + 20].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48
                ToEdit[ToEditIndex + 21].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x4c
                ToEdit[ToEditIndex + 22].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x50
                ToEdit[ToEditIndex + 23].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x54
                ToEdit[ToEditIndex + 24].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x58
                ToEdit[ToEditIndex + 25].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x5c
                end
                if IsFirst then
                ToEdit[ToEditIndex + 26].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress - 0x4
                end

                if IsFirst then
                ToEdit[ToEditIndex].value = "~A LDR PC, [PC,#-4]"
                ToEdit[ToEditIndex + 1].value = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress
                ToEdit[ToEditIndex + 2].value = "~A LDR r6, [PC,#-0xc]"
                ToEdit[ToEditIndex + 3].value = "~A STMDB r6, {R0-R5,LR}"
                end


                if #Table[i]['parameters'] >= 1 then
                    ToEdit[ToEditIndex + 4].value = "~A LDR R1, [PC,#24]"
                    if Table[i]['parameters'][1][2] == true then
                        ToEdit[ToEditIndex + 12].value = 1
                    elseif Table[i]['parameters'][1][2] == false then
                        ToEdit[ToEditIndex + 12].value = 0
                    else
                        ToEdit[ToEditIndex + 12].value = Table[i]['parameters'][1][2]
                    end
                    ToEdit[ToEditIndex + 12].flags = HackersHouse.getType(Table[i]['parameters'][1][1])
                else
                    ToEdit[ToEditIndex + 4].value = "~A NOP"
                    ToEdit[ToEditIndex + 12].value = "~A NOP"
                    ToEdit[ToEditIndex + 12].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 2 then
                    ToEdit[ToEditIndex + 5].value = "~A LDR R2, [PC,#24]"
                    if Table[i]['parameters'][2][2] == true then
                        ToEdit[ToEditIndex + 13].value = 1
                    elseif Table[i]['parameters'][2][2] == false then
                        ToEdit[ToEditIndex + 13].value = 0
                    else
                        ToEdit[ToEditIndex + 13].value = Table[i]['parameters'][2][2]
                    end
                    ToEdit[ToEditIndex + 13].flags = HackersHouse.getType(Table[i]['parameters'][2][1])
                else
                    ToEdit[ToEditIndex + 5].value = "~A NOP"
                    ToEdit[ToEditIndex + 13].value = "~A NOP"
                    ToEdit[ToEditIndex + 13].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 3 then
                    ToEdit[ToEditIndex + 6].value = "~A LDR R3, [PC,#24]"
                    if Table[i]['parameters'][3][2] == true then
                        ToEdit[ToEditIndex + 14].value = 1
                    elseif Table[i]['parameters'][3][2] == false then
                        ToEdit[ToEditIndex + 14].value = 0
                    else
                        ToEdit[ToEditIndex + 14].value = Table[i]['parameters'][3][2]
                    end
                    ToEdit[ToEditIndex + 14].flags = HackersHouse.getType(Table[i]['parameters'][3][1])
                else
                    ToEdit[ToEditIndex + 6].value = "~A NOP"
                    ToEdit[ToEditIndex + 14].value = "~A NOP"
                    ToEdit[ToEditIndex + 14].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 4 then
                    ToEdit[ToEditIndex + 7].value = "~A LDR R4, [PC,#24]"
                    if Table[i]['parameters'][4][2] == true then
                        ToEdit[ToEditIndex + 15].value = 1
                    elseif Table[i]['parameters'][4][2] == false then
                        ToEdit[ToEditIndex + 15].value = 4
                    else
                        ToEdit[ToEditIndex + 15].value = Table[i]['parameters'][4][2]
                    end
                    ToEdit[ToEditIndex + 15].flags = HackersHouse.getType(Table[i]['parameters'][4][1])
                else
                    ToEdit[ToEditIndex + 7].value = "~A NOP"
                    ToEdit[ToEditIndex + 15].value = "~A NOP"
                    ToEdit[ToEditIndex + 15].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 5 then
                    ToEdit[ToEditIndex + 8].value = "~A LDR R5, [PC,#24]"
                    if Table[i]['parameters'][5][2] == true then
                        ToEdit[ToEditIndex + 16].value = 1
                    elseif Table[i]['parameters'][5][2] == false then
                        ToEdit[ToEditIndex + 16].value = 0
                    else
                        ToEdit[ToEditIndex + 16].value = Table[i]['parameters'][5][2]
                    end
                    ToEdit[ToEditIndex + 16].flags = HackersHouse.getType(Table[i]['parameters'][5][1])
                else
                    ToEdit[ToEditIndex + 8].value = "~A NOP"
                    ToEdit[ToEditIndex + 16].value = "~A NOP"
                    ToEdit[ToEditIndex + 16].flags = gg.TYPE_DWORD
                end
                

                if not IsReactivated then
                ToEdit[ToEditIndex + 9].value = "~A LDR R6, [PC,#24]"
                ToEdit[ToEditIndex + 10].value = "~A BLX r6"
                ToEdit[ToEditIndex + 11].value = "~A B +0x1c"
                ToEdit[ToEditIndex + 17].value = Lib[libIndex].start + Table[i]['destinationOffset']
                ToEdit[ToEditIndex + 18].value = "~A B +0x8"
                ToEdit[ToEditIndex + 19].value = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].startAddress + 0x20 - 0x8
                ToEdit[ToEditIndex + 20].value = "~A LDR r6, [PC,#-0xc]"
                ToEdit[ToEditIndex + 21].value = "~A LDMDB r6, {R0-R5,LR}"
                ToEdit[ToEditIndex + 22].value = RefillData[1].value
                ToEdit[ToEditIndex + 23].value = RefillData[2].value
                ToEdit[ToEditIndex + 24].value = "~A LDR PC, [PC,#-4]"
                ToEdit[ToEditIndex + 25].value = RefillData[2].address + 0x4
                end
            
                if IsFirst then
                ToEdit[ToEditIndex + 26].value =  HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress - 0x8
                end

                ToEdit[ToEditIndex + 29].value =  "~A BEQ +0x58"
                if not IsReactivated then
                ToEdit[ToEditIndex + 27].value =  "~A LDR R1, [PC,#8]" 
                ToEdit[ToEditIndex + 28].value =  "~A CMP R1, #0"
                ToEdit[ToEditIndex + 30].value = "~A B +0xC"
                ToEdit[ToEditIndex + 32].value = ToEdit[ToEditIndex + 31].address
                ToEdit[ToEditIndex + 33].value =  "~A LDR R2, [PC,#-0xc]"
                ToEdit[ToEditIndex + 34].value =  "~A LDR R1, [PC,#-0x14]"
                ToEdit[ToEditIndex + 35].value =  "~A SUB R1, R1, #1"
                ToEdit[ToEditIndex + 36].value =  "~A STR R1, [R2]"
                end
                ToEdit[ToEditIndex + 31].value = Table[i]['repeat']

    
    
    
                if IsFirst then
                ToEdit[ToEditIndex].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 1].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 2].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 3].flags = gg.TYPE_DWORD
                end


                ToEdit[ToEditIndex + 4].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 5].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 6].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 7].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 8].flags = gg.TYPE_DWORD

                if not IsReactivated then
                ToEdit[ToEditIndex + 9].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 10].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 11].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 17].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 18].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 19].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 20].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 21].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 22].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 23].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 24].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 25].flags = gg.TYPE_DWORD
                end

                if IsFirst then
                ToEdit[ToEditIndex + 26].flags = gg.TYPE_DWORD
                end

                if not IsReactivated then
                ToEdit[ToEditIndex + 27].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 28].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 30].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 32].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 33].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 34].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 35].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 36].flags = gg.TYPE_DWORD
            end
            ToEdit[ToEditIndex + 29].flags = gg.TYPE_DWORD
            ToEdit[ToEditIndex + 31].flags = gg.TYPE_DWORD
                ToEditIndex = ToEditIndex + 37

                if not IsReactivated then
                HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x9c + 0x28 - 0x84
                else
                    HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress = CurrentWriteAddress
                end
            end 
        elseif HackersHouse.is64Bit == true then
            for i, v in ipairs(Table) do
                if Table[i]['repeat'] == "infinite" then
                    Table[i]['repeat'] = 2000000000
                end
                local Lib = gg.getRangesList(Table[i]['libName'])
                local libIndex
                if Table[i]['libIndex'] == "auto" then
                    libIndex = HackersHouse.getLibIndex(Lib)
                else
                    libIndex = Table[i]['libIndex']
                end
                HackersHouse.AllocatedPageForVoidHook(Table[i]['libName'], Table[i]['targetOffset'])
                HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x48
                
                
                
                local RefillData = {}
    
                if HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats == nil then
                HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats = {}
                    IsFirst = true
                else
                    IsFirst = false
                end
                if HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats[Table[i]['destinationOffset']] == nil then
                    IsReactivated = false
                    
                else
                   
                    IsReactivated = true
                end

                if not IsReactivated then
                HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats[Table[i]['destinationOffset']] = {}
                HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats[Table[i]['destinationOffset']]['allocatedAddress'] = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress
                else
                    CurrentWriteAddress = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress
                    HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats[Table[i]['destinationOffset']]['allocatedAddress']
                end
                
    

                if IsFirst then
                RefillData[1] = {}
                RefillData[1].address = Lib[libIndex].start + Table[i]['targetOffset']
                RefillData[1].flags = gg.TYPE_DWORD
    
                RefillData[2] = {}
                RefillData[2].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x4
                RefillData[2].flags = gg.TYPE_DWORD

                RefillData[3] = {}
                RefillData[3].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x8
                RefillData[3].flags = gg.TYPE_DWORD

                RefillData[4] = {}
                RefillData[4].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0xC
                RefillData[4].flags = gg.TYPE_DWORD

                RefillData = gg.getValues(RefillData)

                

                    HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']]['RefillData'] = RefillData 
                ToEdit[ToEditIndex] = {}
                ToEdit[ToEditIndex + 1] = {}
                ToEdit[ToEditIndex + 2] = {}
                ToEdit[ToEditIndex + 3] = {}
                ToEdit[ToEditIndex + 37] = {}
                ToEdit[ToEditIndex + 39] = {}
                ToEdit[ToEditIndex + 40] = {}
                ToEdit[ToEditIndex + 41] = {}
                else
                    RefillData = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']]['RefillData']
                
                end

                ToEdit[ToEditIndex + 4] = {}
                ToEdit[ToEditIndex + 5] = {}
                ToEdit[ToEditIndex + 6] = {}
                ToEdit[ToEditIndex + 7] = {}
                ToEdit[ToEditIndex + 8] = {}

                if not IsReactivated then
                ToEdit[ToEditIndex + 9] = {}
                ToEdit[ToEditIndex + 10] = {}
                ToEdit[ToEditIndex + 11] = {}
                end

                ToEdit[ToEditIndex + 12] = {}
                ToEdit[ToEditIndex + 13] = {}
                ToEdit[ToEditIndex + 14] = {}
                ToEdit[ToEditIndex + 15] = {}
                ToEdit[ToEditIndex + 16] = {}

                if not IsReactivated then
                ToEdit[ToEditIndex + 17] = {}
                ToEdit[ToEditIndex + 18] = {}
                ToEdit[ToEditIndex + 19] = {}
                ToEdit[ToEditIndex + 20] = {}
                ToEdit[ToEditIndex + 21] = {}
                ToEdit[ToEditIndex + 43] = {}
                ToEdit[ToEditIndex + 44] = {}
                ToEdit[ToEditIndex + 45] = {}
                ToEdit[ToEditIndex + 22] = {}
                ToEdit[ToEditIndex + 23] = {}
                ToEdit[ToEditIndex + 38] = {}
                ToEdit[ToEditIndex + 46] = {}
                ToEdit[ToEditIndex + 47] = {}
                ToEdit[ToEditIndex + 24] = {}
                ToEdit[ToEditIndex + 42] = {}
                ToEdit[ToEditIndex + 25] = {}
                end
                if IsFirst then
                ToEdit[ToEditIndex + 26] = {}
                end
                ToEdit[ToEditIndex + 29] = {}

                if not IsReactivated then
                ToEdit[ToEditIndex + 27] = {}
                ToEdit[ToEditIndex + 28] = {}
                ToEdit[ToEditIndex + 30] = {}
                ToEdit[ToEditIndex + 32] = {}
                ToEdit[ToEditIndex + 33] = {}
                ToEdit[ToEditIndex + 34] = {}
                ToEdit[ToEditIndex + 35] = {}
                ToEdit[ToEditIndex + 36] = {}
            end

            ToEdit[ToEditIndex + 31] = {}
            
                if IsFirst then
                ToEdit[ToEditIndex].address = Lib[libIndex].start + Table[i]['targetOffset']
                ToEdit[ToEditIndex + 1].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x4
                ToEdit[ToEditIndex + 37].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x8

                ToEdit[ToEditIndex + 2].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress
                ToEdit[ToEditIndex + 3].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x4
                ToEdit[ToEditIndex + 39].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x8
                ToEdit[ToEditIndex + 40].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0xC
                ToEdit[ToEditIndex + 41].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x10
                end

                ToEdit[ToEditIndex + 29].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x10 + 0xc

                if not IsReactivated then
                ToEdit[ToEditIndex + 27].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x8 + 0xc
                ToEdit[ToEditIndex + 28].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0xc + 0xc
                ToEdit[ToEditIndex + 30].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x14 + 0xc
                ToEdit[ToEditIndex + 32].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x1c + 0xc + 0x4 
                ToEdit[ToEditIndex + 33].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x20 + 0xc + 0x4 +0x4
                ToEdit[ToEditIndex + 34].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x24 + 0xc + 0x4 +0x4
                ToEdit[ToEditIndex + 35].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0xc + 0x4 +0x4
                ToEdit[ToEditIndex + 36].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x2c + 0xc + 0x4 +0x4
            end
            
            ToEdit[ToEditIndex + 31].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x18 + 0xc


                ToEdit[ToEditIndex + 4].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x8 + 0xc +0x4 +0x4
                ToEdit[ToEditIndex + 5].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0xc + 0xc +0x4 +0x4
                ToEdit[ToEditIndex + 6].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x10 + 0xc +0x4 +0x4
                ToEdit[ToEditIndex + 7].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x14 + 0xc +0x4 +0x4
                ToEdit[ToEditIndex + 8].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x18 + 0xc +0x4 +0x4

                if not IsReactivated then
                ToEdit[ToEditIndex + 9].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x1c +0xc +0x4 +0x4
                ToEdit[ToEditIndex + 10].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x20 +0xc +0x4 +0x4
                ToEdit[ToEditIndex + 11].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x24 +0xc +0x4 +0x4
                end

                ToEdit[ToEditIndex + 12].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x28 + 0xc +0x4 +0x4
                ToEdit[ToEditIndex + 13].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x2c + 0xc +0x4 +0x4 +0x4
                ToEdit[ToEditIndex + 14].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x30 + 0xc +0x4 +0x4 +0x4 +0x4
                ToEdit[ToEditIndex + 15].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x34 + 0xc +0x4 +0x4 +0x4 +0x4 +0x4
                ToEdit[ToEditIndex + 16].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x38 + 0xc +0x4 +0x4 +0x4 +0x4 +0x4 +0x4

                if not IsReactivated then
                ToEdit[ToEditIndex + 17].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x3c  + 0xc +0x4 +0x4 +0x20 +0x8 -0x14
                ToEdit[ToEditIndex + 18].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x40  + 0xc +0x4  +0x20 +0x8 +0x8 -0x14
                ToEdit[ToEditIndex + 19].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x44  + 0xc +0x4  +0x20 +0x8 +0x8 -0x14
                ToEdit[ToEditIndex + 20].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 -0x14
                ToEdit[ToEditIndex + 21].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x4 -0x14
                ToEdit[ToEditIndex + 43].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x8 -0x14
                ToEdit[ToEditIndex + 44].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0xc -0x14
                ToEdit[ToEditIndex + 45].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x10 -0x14
                ToEdit[ToEditIndex + 22].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x10 +0x4 -0x14
                ToEdit[ToEditIndex + 23].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x10 +0x8 -0x14
                ToEdit[ToEditIndex + 38].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x10 +0x4 +0x8 -0x14
                ToEdit[ToEditIndex + 46].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x10 +0x4 +0x8 -0x14 +0x4
                ToEdit[ToEditIndex + 24].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x10 +0x4 +0x8 +0x8 -0x14
                ToEdit[ToEditIndex + 42].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x10 +0x4 +0x8 +0x8  +0x4 -0x14
                ToEdit[ToEditIndex + 25].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress  + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x10 +0x4 +0x8 +0x8 +0x4 +0x4 -0x14
                ToEdit[ToEditIndex + 47].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress  + 0x28 + 0x48  + 0xc +0x4 +0x4 +0x20  +0x8 +0x8 +0x10 +0x4 +0x8 +0x8 +0x4 +0x4 -0x14 +0x4 +0x4
                end
                if IsFirst then
                ToEdit[ToEditIndex + 26].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress - 0x8
                end

                if IsFirst then
                ToEdit[ToEditIndex].value = "~A8 LDR  X11, [PC,#0x8]"
                ToEdit[ToEditIndex + 1].value = "~A8 BR X11"
                ToEdit[ToEditIndex + 37].value = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress
                ToEdit[ToEditIndex + 2].value = "~A8 LDR X11, [PC,#-0x8]"
                ToEdit[ToEditIndex + 3].value = "~A8 STP X0, X1, [X11], #0x10"
                ToEdit[ToEditIndex + 39].value = "~A8 STP X2, X3, [X11], #0x10"
                ToEdit[ToEditIndex + 40].value = "~A8 STP X4, X5, [X11], #0x10"
                ToEdit[ToEditIndex + 41].value = "~A8 STP X30, x29, [X11], #0x10"
                end


                if #Table[i]['parameters'] >= 1 then
                    ToEdit[ToEditIndex + 4].value = "~A8 LDR X1, [PC,#0x20]"
                    if Table[i]['parameters'][1][2] == true then
                        ToEdit[ToEditIndex + 12].value = 1
                    elseif Table[i]['parameters'][1][2] == false then
                        ToEdit[ToEditIndex + 12].value = 0
                    else
                        ToEdit[ToEditIndex + 12].value = Table[i]['parameters'][1][2]
                    end
                    ToEdit[ToEditIndex + 12].flags = HackersHouse.getType(Table[i]['parameters'][1][1])
                else
                    ToEdit[ToEditIndex + 4].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 12].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 12].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 2 then
                    ToEdit[ToEditIndex + 5].value = "~A8 LDR X2, [PC,#0x24]"
                    if Table[i]['parameters'][2][2] == true then
                        ToEdit[ToEditIndex + 13].value = 1
                    elseif Table[i]['parameters'][2][2] == false then
                        ToEdit[ToEditIndex + 13].value = 0
                    else
                        ToEdit[ToEditIndex + 13].value = Table[i]['parameters'][2][2]
                    end
                    ToEdit[ToEditIndex + 13].flags = HackersHouse.getType(Table[i]['parameters'][2][1])
                else
                    ToEdit[ToEditIndex + 5].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 13].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 13].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 3 then
                    ToEdit[ToEditIndex + 6].value = "~A8 LDR X3, [PC,#0x28]"
                    if Table[i]['parameters'][3][2] == true then
                        ToEdit[ToEditIndex + 14].value = 1
                    elseif Table[i]['parameters'][3][2] == false then
                        ToEdit[ToEditIndex + 14].value = 0
                    else
                        ToEdit[ToEditIndex + 14].value = Table[i]['parameters'][3][2]
                    end
                    ToEdit[ToEditIndex + 14].flags = HackersHouse.getType(Table[i]['parameters'][3][1])
                else
                    ToEdit[ToEditIndex + 6].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 14].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 14].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 4 then
                    ToEdit[ToEditIndex + 7].value = "~A8 LDR X4, [PC,#0x2c]"
                    if Table[i]['parameters'][4][2] == true then
                        ToEdit[ToEditIndex + 15].value = 1
                    elseif Table[i]['parameters'][4][2] == false then
                        ToEdit[ToEditIndex + 15].value = 4
                    else
                        ToEdit[ToEditIndex + 15].value = Table[i]['parameters'][4][2]
                    end
                    ToEdit[ToEditIndex + 15].flags = HackersHouse.getType(Table[i]['parameters'][4][1])
                else
                    ToEdit[ToEditIndex + 7].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 15].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 15].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 5 then
                    ToEdit[ToEditIndex + 8].value = "~A8 LDR X5, [PC,#0x30]"
                    if Table[i]['parameters'][5][2] == true then
                        ToEdit[ToEditIndex + 16].value = 1
                    elseif Table[i]['parameters'][5][2] == false then
                        ToEdit[ToEditIndex + 16].value = 0
                    else
                        ToEdit[ToEditIndex + 16].value = Table[i]['parameters'][5][2]
                    end
                    ToEdit[ToEditIndex + 16].flags = HackersHouse.getType(Table[i]['parameters'][5][1])
                else
                    ToEdit[ToEditIndex + 8].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 16].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 16].flags = gg.TYPE_DWORD
                end
                

                if not IsReactivated then
                ToEdit[ToEditIndex + 9].value = "~A8 LDR X6, [PC,#0x34]"
                ToEdit[ToEditIndex + 10].value = "~A8 BLR X6"
                ToEdit[ToEditIndex + 11].value = "~A8  B  [PC,#0x34]"
                ToEdit[ToEditIndex + 17].value = Lib[libIndex].start + Table[i]['destinationOffset']
                ToEdit[ToEditIndex + 18].value = "~A8  B  [PC,#0xc]"
                ToEdit[ToEditIndex + 19].value = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].startAddress
                ToEdit[ToEditIndex + 20].value = "~A8 LDR X11, [PC,#-0x8]"
                ToEdit[ToEditIndex + 21].value = "~A8 LDP X0, X1, [X11], #0x10"
                ToEdit[ToEditIndex + 43].value = "~A8 LDP X2, X3, [X11], #0x10"
                ToEdit[ToEditIndex + 44].value = "~A8 LDP X4, X5, [X11], #0x10"
                ToEdit[ToEditIndex + 45].value = "~A8 LDP X30, X29, [X11], #0x10"
                ToEdit[ToEditIndex + 22].value = RefillData[1].value
                ToEdit[ToEditIndex + 23].value = RefillData[2].value
                ToEdit[ToEditIndex + 38].value = RefillData[3].value
                
                ARMCODE = gg.disasm(gg.ASM_ARM64, 0, RefillData[4].value)
                
                Register = 0
                OffsetArm = 0
                
                if string.find(ARMCODE, "ADRP") ~= nil then
                    for match in ARMCODE:gmatch("X%d+") do
                        local value = match:match("%d+")
                        Register = value
                        break
                    end

                    for match in ARMCODE:gmatch(",#0x%x+]") do
                        local value = match:match("#(0x%x+)%]")
                        OffsetArm = value
                        break
                    end
                    ToEdit[ToEditIndex + 46].value = "~A8 LDR  X"..Register..", [PC,#0x14]"
                    ToEdit[ToEditIndex + 47].value = RefillData[4].address + OffsetArm
                else
                    ToEdit[ToEditIndex + 46].value = RefillData[4].value
                    ToEdit[ToEditIndex + 47].value = "~A8 NOP"
                end
                ToEdit[ToEditIndex + 24].value = "~A8 LDR  X11, [PC,#0x8]"
                ToEdit[ToEditIndex + 42].value = "~A8 BR X11"
                ToEdit[ToEditIndex + 25].value = RefillData[2].address + 0x4 +0x8
                end
            
                if IsFirst then
                ToEdit[ToEditIndex + 26].value =  HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].startAddress
                end

                ToEdit[ToEditIndex + 29].value =  "~A8  B.EQ  [PC,#0x98]"
                if not IsReactivated then
                ToEdit[ToEditIndex + 27].value =  "~A8 LDR X1, [PC,#0x10]" 
                ToEdit[ToEditIndex + 28].value =  "~A8 CMP X1, #0"
                ToEdit[ToEditIndex + 30].value = "~A8  B  [PC,#0x14]"
                ToEdit[ToEditIndex + 32].value = ToEdit[ToEditIndex + 31].address
                ToEdit[ToEditIndex + 33].value =  "~A8 LDR X2, [PC,#-0x8]"
                ToEdit[ToEditIndex + 34].value =  "~A8 LDR X1, [PC,#-0x14]"
                ToEdit[ToEditIndex + 35].value =  "~A8 SUB X1, X1, #1"
                ToEdit[ToEditIndex + 36].value =  "~A8 STR X1, [X2]"
                end
                ToEdit[ToEditIndex + 31].value = Table[i]['repeat']

    
    
    
                if IsFirst then
                ToEdit[ToEditIndex].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 1].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 2].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 3].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 37].flags = gg.TYPE_QWORD
                ToEdit[ToEditIndex + 39].flags = gg.TYPE_QWORD
                ToEdit[ToEditIndex + 40].flags = gg.TYPE_QWORD
                ToEdit[ToEditIndex + 41].flags = gg.TYPE_DWORD
                end


                ToEdit[ToEditIndex + 4].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 5].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 6].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 7].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 8].flags = gg.TYPE_DWORD

                if not IsReactivated then
                ToEdit[ToEditIndex + 9].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 10].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 11].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 17].flags = gg.TYPE_QWORD
                ToEdit[ToEditIndex + 18].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 19].flags = gg.TYPE_QWORD
                ToEdit[ToEditIndex + 20].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 21].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 43].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 44].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 45].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 22].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 23].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 38].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 46].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 47].flags = gg.TYPE_QWORD
                ToEdit[ToEditIndex + 24].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 42].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 25].flags = gg.TYPE_QWORD
                end

                if IsFirst then
                ToEdit[ToEditIndex + 26].flags = gg.TYPE_QWORD
                end

                if not IsReactivated then
                ToEdit[ToEditIndex + 27].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 28].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 30].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 32].flags = gg.TYPE_QWORD
                ToEdit[ToEditIndex + 33].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 34].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 35].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 36].flags = gg.TYPE_DWORD
            end
            ToEdit[ToEditIndex + 29].flags = gg.TYPE_DWORD
            ToEdit[ToEditIndex + 31].flags = gg.TYPE_DWORD
                ToEditIndex = ToEditIndex + 48

                if not IsReactivated then
                HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress + 0x9c + 0x28 - 0x84 +0x10 +0x8
                else
                    HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].currentWriteAddress = CurrentWriteAddress
                end
            end
        end
        
        gg.setValues(ToEdit)
        
        gg.processResume()
    end,
    ['disableMethod'] = function(Table)
        if HackersHouse.validation("disableMethod", Table) then
            return
        end
        local ToEdit = {}
        for i, v in ipairs(Table) do
            local Lib = gg.getRangesList(Table[i]['libName'])
            local libIndex
            if Table[i]['libIndex'] == "auto" then
                libIndex = HackersHouse.getLibIndex(Lib)
            else
                libIndex = Table[i]['libIndex']
            end
            ToEdit[i] = {}
            ToEdit[i].address = Lib[libIndex].start + Table[i]['offset']
            ToEdit[i].flags = gg.TYPE_DWORD
            HackersHouse.disableMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] = {}
            HackersHouse.disableMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'] = gg.getValues({
                [1] = {
                    ['address'] = Lib[libIndex].start + Table[i]['offset'],
                    ['flags'] = gg.TYPE_DWORD,
                }
            })
            if HackersHouse.is64Bit then
                ToEdit[i].value = "~A8 RET"
            else
                ToEdit[i].value = "~A BX LR"
            end
        end

        gg.setValues(ToEdit)
    end,
    ['returnValue'] = function(Table)
        if HackersHouse.validation("returnValue", Table) then
            return
        end
        local ToEdit = {}
        local EditIndex = 1
        HackersHouse.AllocatedPageForReturnValue()

        for i, v in ipairs(Table) do
            local Lib = gg.getRangesList(Table[i]['libName'])
            local libIndex
            if Table[i]['libIndex'] == "auto" then
                libIndex = HackersHouse.getLibIndex(Lib)
            else
                libIndex = Table[i]['libIndex']
            end
            if Table[i]['valueType'] == "bool" then
                if Table[i]['value'] == true then
                    ToEdit[EditIndex] = {}
                    ToEdit[EditIndex + 1] = {}
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] = {}
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['allocatedAddress'] = 0
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'] = gg
                        .getValues({
                            [1] = {
                                ['address'] = Lib[libIndex].start + Table[i]['offset'],
                                ['flags'] = gg.TYPE_DWORD,
                            },
                            [2] = {
                                ['address'] = Lib[libIndex].start + Table[i]['offset'] + 0x4,
                                ['flags'] = gg.TYPE_DWORD,
                            }
                        })
                    ToEdit[EditIndex].address = Lib[libIndex].start + Table[i]['offset']
                    ToEdit[EditIndex + 1].address = Lib[libIndex].start + Table[i]['offset'] + 0x4
                    if HackersHouse.is64Bit then
                        ToEdit[EditIndex].value = "~A8 MOV X0, #0x1"
                        ToEdit[EditIndex + 1].value = "~A8 RET"
                    else
                        ToEdit[EditIndex].value = "~A MOV R0, #1"
                        ToEdit[EditIndex + 1].value = "~A BX LR"
                    end
                    ToEdit[EditIndex].flags = gg.TYPE_DWORD
                    ToEdit[EditIndex + 1].flags = gg.TYPE_DWORD
                    EditIndex = EditIndex + 2
                elseif Table[i]['value'] == false then
                    ToEdit[EditIndex] = {}
                    ToEdit[EditIndex + 1] = {}
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] = {}
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['allocatedAddress'] = 0
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'] = gg
                        .getValues({
                            [1] = {
                                ['address'] = Lib[libIndex].start + Table[i]['offset'],
                                ['flags'] = gg.TYPE_DWORD,
                            },
                            [2] = {
                                ['address'] = Lib[libIndex].start + Table[i]['offset'] + 0x4,
                                ['flags'] = gg.TYPE_DWORD,
                            }
                        })
                    ToEdit[EditIndex].address = Lib[libIndex].start + Table[i]['offset']
                    ToEdit[EditIndex + 1].address = Lib[libIndex].start + Table[i]['offset'] + 0x4
                    if HackersHouse.is64Bit then
                        ToEdit[EditIndex].value = 'h000080D2'
                        ToEdit[EditIndex + 1].value = "~A8 RET"
                    else
                        ToEdit[EditIndex].value = "~A MOV R0, #0"
                        ToEdit[EditIndex + 1].value = "~A BX LR"
                    end
                    ToEdit[EditIndex].flags = gg.TYPE_DWORD
                    ToEdit[EditIndex + 1].flags = gg.TYPE_DWORD
                    EditIndex = EditIndex + 2
                end
            end

            if HackersHouse.is64Bit then
                if Table[i]['valueType'] == "int" or Table[i]['valueType'] == "float" or Table[i]['valueType'] == "long int" then
                    ToEdit[EditIndex] = {}
                    ToEdit[EditIndex + 1] = {}
                    ToEdit[EditIndex + 2] = {}
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] = {}
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['allocatedAddress'] = 0
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'] = gg
                        .getValues({
                            [1] = {
                                ['address'] = Lib[libIndex].start + Table[i]['offset'],
                                ['flags'] = gg.TYPE_DWORD,
                            },
                            [2] = {
                                ['address'] = Lib[libIndex].start + Table[i]['offset'] + 0x4,
                                ['flags'] = gg.TYPE_DWORD,
                            },
                            [3] = {
                                ['address'] = Lib[libIndex].start + Table[i]['offset'] + 0x8,
                                ['flags'] = gg.TYPE_DWORD,
                            }
                        })
                    ToEdit[EditIndex].address = Lib[libIndex].start + Table[i]['offset']
                    ToEdit[EditIndex + 1].address = Lib[libIndex].start + Table[i]['offset'] + 0x4
                    ToEdit[EditIndex + 2].address = Lib[libIndex].start + Table[i]['offset'] + 0x8
                    ToEdit[EditIndex].value = "~A8 LDR X0, [PC,#0x8]"
                    ToEdit[EditIndex + 1].value = "~A8 RET"
                    ToEdit[EditIndex + 2].value = Table[i]['value']
                    ToEdit[EditIndex].flags = gg.TYPE_DWORD
                    ToEdit[EditIndex + 1].flags = gg.TYPE_DWORD
                    ToEdit[EditIndex + 2].flags = HackersHouse.getType(Table[i]['valueType'])
                    EditIndex = EditIndex + 3
                end
            else
                if Table[i]['valueType'] == "int" or Table[i]['valueType'] == "float" or Table[i]['valueType'] == "long int" then
                    ToEdit[EditIndex] = {}
                    ToEdit[EditIndex + 1] = {}
                    ToEdit[EditIndex + 2] = {}
                    ToEdit[EditIndex + 3] = {}
                    ToEdit[EditIndex + 4] = {}
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] = {}
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['allocatedAddress'] = 0
                    HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'] = gg
                        .getValues({
                            [1] = {
                                ['address'] = Lib[libIndex].start + Table[i]['offset'],
                                ['flags'] = gg.TYPE_DWORD,
                            },
                            [2] = {
                                ['address'] = Lib[libIndex].start + Table[i]['offset'] + 0x4,
                                ['flags'] = gg.TYPE_DWORD,
                            }
                        })
                    ToEdit[EditIndex].address = Lib[libIndex].start + Table[i]['offset']
                    ToEdit[EditIndex + 1].address = Lib[libIndex].start + Table[i]['offset'] + 0x4
                    ToEdit[EditIndex + 2].address = HackersHouse.returnValueList.currentWriteAddress
                    ToEdit[EditIndex + 3].address = HackersHouse.returnValueList.currentWriteAddress + 0x4
                    ToEdit[EditIndex + 4].address = HackersHouse.returnValueList.currentWriteAddress + 0x8
                    ToEdit[EditIndex].value = "~A LDR PC, [PC,#-4]"
                    ToEdit[EditIndex + 1].value = HackersHouse.returnValueList.currentWriteAddress
                    ToEdit[EditIndex + 2].value = "~A LDR R0, [PC]"
                    ToEdit[EditIndex + 3].value = "~A BX LR"
                    ToEdit[EditIndex + 4].value = Table[i]['value']
                    HackersHouse.returnValueList.currentWriteAddress = HackersHouse.returnValueList.currentWriteAddress +
                        0xC
                    ToEdit[EditIndex].flags = gg.TYPE_DWORD
                    ToEdit[EditIndex + 1].flags = gg.TYPE_DWORD
                    ToEdit[EditIndex + 2].flags = gg.TYPE_DWORD
                    ToEdit[EditIndex + 3].flags = gg.TYPE_DWORD
                    ToEdit[EditIndex + 4].flags = HackersHouse.getType(Table[i]['valueType'])
                    EditIndex = EditIndex + 5
                end
            end
        end

        gg.setValues(ToEdit)
    end,
    ['hexPatch'] = function(Table)
        if HackersHouse.validation("hexPatch", Table) then
            return
        end
        local address
        local value
        local EditHexList = {}
        local EditHexListIndex = 1
        for i, v in ipairs(Table) do
            local Lib = gg.getRangesList(Table[i]['libName'])
            local libIndex
            if Table[i]['libIndex'] == "auto" then
                libIndex = HackersHouse.getLibIndex(Lib)
            else
                libIndex = Table[i]['libIndex']
            end
            address = Lib[libIndex].start + Table[i]['offset']
            value = Table[i]['hexPatch']
            local space_index = string.find(value, ' ')
            local result_string = string.sub(value, space_index + 1)
            local result_strings = {}

            for i = 1, #result_string, 2 do
                local substring = result_string:sub(i, i + 1)
                table.insert(result_strings, substring)
            end
            local Index = 1
            DefaultValues = {}
            DefaultValuesIndex = 1
            while Index <= #result_strings do
                DefaultValues[DefaultValuesIndex] = {}
                DefaultValues[DefaultValuesIndex].address = (address - 1) + Index
                DefaultValues[DefaultValuesIndex].flags = gg.TYPE_BYTE
                DefaultValuesIndex = DefaultValuesIndex + 1
                EditHexList[EditHexListIndex] = {}
                EditHexList[EditHexListIndex].address = (address - 1) + Index
                EditHexList[EditHexListIndex].flags = gg.TYPE_BYTE
                EditHexList[EditHexListIndex].value = "h " .. result_strings[Index]
                EditHexListIndex = EditHexListIndex + 1
                Index = Index + 1
            end
            HackersHouse.hexPatchList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] = {}
            HackersHouse.hexPatchList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'] = gg.getValues(
                DefaultValues)
        end

        gg.setValues(EditHexList)
    end,
    ['callAnotherMethod'] = function(Table)
        if HackersHouse.validation("callAnotherMethod", Table) then
            return
        end
        HackersHouse.AllocatedPageForCallAnotherMethod()
        local ToEdit = {}
        local ToEditIndex = 1
        if HackersHouse.is64Bit == false then
            for i, v in ipairs(Table) do
                local Lib = gg.getRangesList(Table[i]['libName'])
            local libIndex
            if Table[i]['libIndex'] == "auto" then
                libIndex = HackersHouse.getLibIndex(Lib)
            else
                libIndex = Table[i]['libIndex']
            end
                local RefillData = {}
    
                
    
                if HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']] == nil then
                    IsReactivated = false                    
                else
                    IsReactivated = true                    
                end

                if IsReactivated then
                    currentWriteAddresBackup = HackersHouse.callAnotherMethodList.currentWriteAddress
                    HackersHouse.callAnotherMethodList.currentWriteAddress = HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']]['allocatedAddress']
                    RefillData = HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']]['defaultValues']
                else

                    RefillData[1] = {}
    
                RefillData[1].address = Lib[libIndex].start + Table[i]['targetOffset']
                RefillData[1].flags = gg.TYPE_DWORD
    
                RefillData[2] = {}
                RefillData[2].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x4
                RefillData[2].flags = gg.TYPE_DWORD
                RefillData = gg.getValues(RefillData)
                    HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']] = {}
                HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']]['allocatedAddress'] = HackersHouse.callAnotherMethodList.currentWriteAddress
                HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']]['defaultValues'] = RefillData
                end
                
    
                ToEdit[ToEditIndex] = {}
                ToEdit[ToEditIndex + 1] = {}
                ToEdit[ToEditIndex + 2] = {}
                ToEdit[ToEditIndex + 3] = {}
                ToEdit[ToEditIndex + 4] = {}
                ToEdit[ToEditIndex + 5] = {}
                ToEdit[ToEditIndex + 6] = {}
                ToEdit[ToEditIndex + 7] = {}
                ToEdit[ToEditIndex + 8] = {}
                ToEdit[ToEditIndex + 9] = {}
                ToEdit[ToEditIndex + 10] = {}
                ToEdit[ToEditIndex + 11] = {}
                ToEdit[ToEditIndex + 12] = {}
                ToEdit[ToEditIndex + 13] = {}
                ToEdit[ToEditIndex].address = Lib[libIndex].start + Table[i]['targetOffset']
                ToEdit[ToEditIndex + 1].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x4
                ToEdit[ToEditIndex + 2].address = HackersHouse.callAnotherMethodList.currentWriteAddress
                ToEdit[ToEditIndex + 3].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x4
                ToEdit[ToEditIndex + 4].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x8
                ToEdit[ToEditIndex + 5].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0xc
                ToEdit[ToEditIndex + 6].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x10
                ToEdit[ToEditIndex + 7].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x14
                ToEdit[ToEditIndex + 8].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x18
                ToEdit[ToEditIndex + 9].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x1c
                ToEdit[ToEditIndex + 10].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x20
                ToEdit[ToEditIndex + 11].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x24
                ToEdit[ToEditIndex + 12].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x28
                ToEdit[ToEditIndex + 13].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x2c
                ToEdit[ToEditIndex].value = "~A LDR PC, [PC,#-4]"
                ToEdit[ToEditIndex + 1].value = HackersHouse.callAnotherMethodList.currentWriteAddress
    
                if #Table[i]['parameters'] >= 1 then
                    ToEdit[ToEditIndex + 2].value = "~A LDR R1, [PC,#20]"
                    if Table[i]['parameters'][1][2] == true then
                        ToEdit[ToEditIndex + 9].value = 1
                    elseif Table[i]['parameters'][1][2] == false then
                        ToEdit[ToEditIndex + 9].value = 0
                    else
                        ToEdit[ToEditIndex + 9].value = Table[i]['parameters'][1][2]
                    end
                    ToEdit[ToEditIndex + 9].flags = HackersHouse.getType(Table[i]['parameters'][1][1])
                else
                    ToEdit[ToEditIndex + 2].value = "~A NOP"
                    ToEdit[ToEditIndex + 9].value = "~A NOP"
                    ToEdit[ToEditIndex + 9].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 2 then
                    ToEdit[ToEditIndex + 3].value = "~A LDR R2, [PC,#20]"
                    if Table[i]['parameters'][2][2] == true then
                        ToEdit[ToEditIndex + 10].value = 1
                    elseif Table[i]['parameters'][2][2] == false then
                        ToEdit[ToEditIndex + 10].value = 0
                    else
                        ToEdit[ToEditIndex + 10].value = Table[i]['parameters'][2][2]
                    end
                    ToEdit[ToEditIndex + 10].flags = HackersHouse.getType(Table[i]['parameters'][2][1])
                else
                    ToEdit[ToEditIndex + 3].value = "~A NOP"
                    ToEdit[ToEditIndex + 10].value = "~A NOP"
                    ToEdit[ToEditIndex + 10].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 3 then
                    ToEdit[ToEditIndex + 4].value = "~A LDR R3, [PC,#20]"
                    if Table[i]['parameters'][3][2] == true then
                        ToEdit[ToEditIndex + 11].value = 1
                    elseif Table[i]['parameters'][3][2] == false then
                        ToEdit[ToEditIndex + 11].value = 0
                    else
                        ToEdit[ToEditIndex + 11].value = Table[i]['parameters'][3][2]
                    end
                    ToEdit[ToEditIndex + 11].flags = HackersHouse.getType(Table[i]['parameters'][3][1])
                else
                    ToEdit[ToEditIndex + 4].value = "~A NOP"
                    ToEdit[ToEditIndex + 11].value = "~A NOP"
                    ToEdit[ToEditIndex + 11].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 4 then
                    ToEdit[ToEditIndex + 5].value = "~A LDR R4, [PC,#20]"
                    if Table[i]['parameters'][4][2] == true then
                        ToEdit[ToEditIndex + 12].value = 1
                    elseif Table[i]['parameters'][4][2] == false then
                        ToEdit[ToEditIndex + 12].value = 0
                    else
                        ToEdit[ToEditIndex + 12].value = Table[i]['parameters'][4][2]
                    end
                    ToEdit[ToEditIndex + 12].flags = HackersHouse.getType(Table[i]['parameters'][4][1])
                else
                    ToEdit[ToEditIndex + 5].value = "~A NOP"
                    ToEdit[ToEditIndex + 12].value = "~A NOP"
                    ToEdit[ToEditIndex + 12].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 5 then
                    ToEdit[ToEditIndex + 6].value = "~A LDR R5, [PC,#20]"
                    if Table[i]['parameters'][5][2] == true then
                        ToEdit[ToEditIndex + 13].value = 1
                    elseif Table[i]['parameters'][5][2] == false then
                        ToEdit[ToEditIndex + 13].value = 0
                    else
                        ToEdit[ToEditIndex + 13].value = Table[i]['parameters'][5][2]
                    end
                    ToEdit[ToEditIndex + 13].flags = HackersHouse.getType(Table[i]['parameters'][5][1])
                else
                    ToEdit[ToEditIndex + 6].value = "~A NOP"
                    ToEdit[ToEditIndex + 13].value = "~A NOP"
                    ToEdit[ToEditIndex + 13].flags = gg.TYPE_DWORD
                end
    
    
                ToEdit[ToEditIndex + 7].value = "~A LDR PC, [PC,#-4]"
                ToEdit[ToEditIndex + 8].value = Lib[libIndex].start + Table[i]['destinationOffset']
    
    
    
    
    
                ToEdit[ToEditIndex].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 1].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 2].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 3].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 4].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 5].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 6].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 7].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 8].flags = gg.TYPE_DWORD
                ToEditIndex = ToEditIndex + 14
                if IsReactivated then
                    HackersHouse.callAnotherMethodList.currentWriteAddress = currentWriteAddresBackup
                else
                HackersHouse.callAnotherMethodList.currentWriteAddress = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x30
                end
            end
        elseif HackersHouse.is64Bit == true then
            for i, v in ipairs(Table) do
                local Lib = gg.getRangesList(Table[i]['libName'])
            local libIndex
            if Table[i]['libIndex'] == "auto" then
                libIndex = HackersHouse.getLibIndex(Lib)
            else
                libIndex = Table[i]['libIndex']
            end
                local RefillData = {}
    
                RefillData[1] = {}
    
                RefillData[1].address = Lib[libIndex].start + Table[i]['targetOffset']
                RefillData[1].flags = gg.TYPE_DWORD
    
                RefillData[2] = {}
                RefillData[2].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x4
                RefillData[2].flags = gg.TYPE_DWORD

                RefillData[3] = {}
                RefillData[3].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x8
                RefillData[3].flags = gg.TYPE_QWORD
                RefillData = gg.getValues(RefillData)
                if HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']] == nil then
                    IsReactivated = false
                else
                    IsReactivated = true
                end
    
                if IsReactivated then
                    currentWriteAddressBackup = HackersHouse.callAnotherMethodList.currentWriteAddress
                    HackersHouse.callAnotherMethodList.currentWriteAddress = HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']]['allocatedAddress']

                else
                    HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']] = {}
                HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']]['allocatedAddress'] = HackersHouse.callAnotherMethodList.currentWriteAddress
                HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']]['defaultValues'] = RefillData
                end
                
    
                ToEdit[ToEditIndex] = {}
                ToEdit[ToEditIndex + 1] = {}
                ToEdit[ToEditIndex + 2] = {}
                ToEdit[ToEditIndex + 3] = {}
                ToEdit[ToEditIndex + 4] = {}
                ToEdit[ToEditIndex + 5] = {}
                ToEdit[ToEditIndex + 6] = {}
                ToEdit[ToEditIndex + 7] = {}
                ToEdit[ToEditIndex + 8] = {}
                ToEdit[ToEditIndex + 9] = {}
                ToEdit[ToEditIndex + 10] = {}
                ToEdit[ToEditIndex + 11] = {}
                ToEdit[ToEditIndex + 12] = {}
                ToEdit[ToEditIndex + 13] = {}
                ToEdit[ToEditIndex + 14] = {}
                ToEdit[ToEditIndex + 15] = {}
                ToEdit[ToEditIndex].address = Lib[libIndex].start + Table[i]['targetOffset']
                ToEdit[ToEditIndex + 1].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x4
                ToEdit[ToEditIndex + 2].address = Lib[libIndex].start + Table[i]['targetOffset'] + 0x8
                ToEdit[ToEditIndex + 3].address = HackersHouse.callAnotherMethodList.currentWriteAddress
                ToEdit[ToEditIndex + 4].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x4
                ToEdit[ToEditIndex + 5].address = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x8
                ToEdit[ToEditIndex + 6].address =  HackersHouse.callAnotherMethodList.currentWriteAddress + 0xc
                ToEdit[ToEditIndex + 7].address =  HackersHouse.callAnotherMethodList.currentWriteAddress + 0x10
                ToEdit[ToEditIndex + 8].address =  HackersHouse.callAnotherMethodList.currentWriteAddress + 0x14
                ToEdit[ToEditIndex + 9].address =  HackersHouse.callAnotherMethodList.currentWriteAddress + 0x18 -- Return indtructuon
                ToEdit[ToEditIndex + 10].address =  HackersHouse.callAnotherMethodList.currentWriteAddress + 0x1c --Address
                ToEdit[ToEditIndex + 11].address =  HackersHouse.callAnotherMethodList.currentWriteAddress + 0x24 --x1
                ToEdit[ToEditIndex + 12].address =  HackersHouse.callAnotherMethodList.currentWriteAddress + 0x2c
                ToEdit[ToEditIndex + 13].address =  HackersHouse.callAnotherMethodList.currentWriteAddress + 0x34
                ToEdit[ToEditIndex + 14].address =  HackersHouse.callAnotherMethodList.currentWriteAddress + 0x3c
                ToEdit[ToEditIndex + 15].address =  HackersHouse.callAnotherMethodList.currentWriteAddress + 0x44 
                ToEdit[ToEditIndex].value = "~A8 LDR  X1, [PC,#0x8]"
                ToEdit[ToEditIndex + 1].value = "~A8 BR X1"
                ToEdit[ToEditIndex + 2].value = HackersHouse.callAnotherMethodList.currentWriteAddress

                if #Table[i]['parameters'] >= 1 then
                    ToEdit[ToEditIndex + 3].value = "~A8 LDR X1, [PC,#0x24]"
                    if Table[i]['parameters'][1][2] == true then
                        ToEdit[ToEditIndex + 11].value = 1
                    elseif Table[i]['parameters'][1][2] == false then
                        ToEdit[ToEditIndex + 11].value = 0
                    else
                        ToEdit[ToEditIndex + 11].value = Table[i]['parameters'][1][2]
                    end
                    ToEdit[ToEditIndex + 11].flags = HackersHouse.getType(Table[i]['parameters'][1][1])
                else
                    ToEdit[ToEditIndex + 3].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 11].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 11].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 2 then
                    ToEdit[ToEditIndex + 4].value = "~A8 LDR X2, [PC,#0x28]"
                    if Table[i]['parameters'][2][2] == true then
                        ToEdit[ToEditIndex + 12].value = 1
                    elseif Table[i]['parameters'][2][2] == false then
                        ToEdit[ToEditIndex + 12].value = 0
                    else
                        ToEdit[ToEditIndex + 12].value = Table[i]['parameters'][2][2]
                    end
                    ToEdit[ToEditIndex + 12].flags = HackersHouse.getType(Table[i]['parameters'][2][1])
                else
                    ToEdit[ToEditIndex + 4].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 12].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 12].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 3 then
                    ToEdit[ToEditIndex + 5].value = "~A8 LDR X3, [PC,#0x2c]"
                    if Table[i]['parameters'][3][2] == true then
                        ToEdit[ToEditIndex + 13].value = 1
                    elseif Table[i]['parameters'][3][2] == false then
                        ToEdit[ToEditIndex + 13].value = 0
                    else
                        ToEdit[ToEditIndex + 13].value = Table[i]['parameters'][3][2]
                    end
                    ToEdit[ToEditIndex + 13].flags = HackersHouse.getType(Table[i]['parameters'][3][1])
                else
                    ToEdit[ToEditIndex + 5].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 13].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 13].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 4 then
                    ToEdit[ToEditIndex + 6].value = "~A8 LDR X4, [PC,#0x30]"
                    if Table[i]['parameters'][4][2] == true then
                        ToEdit[ToEditIndex + 14].value = 1
                    elseif Table[i]['parameters'][4][2] == false then
                        ToEdit[ToEditIndex + 14].value = 0
                    else
                        ToEdit[ToEditIndex + 14].value = Table[i]['parameters'][4][2]
                    end
                    ToEdit[ToEditIndex + 14].flags = HackersHouse.getType(Table[i]['parameters'][4][1])
                else
                    ToEdit[ToEditIndex + 6].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 14].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 14].flags = gg.TYPE_DWORD
                end
    
                if #Table[i]['parameters'] >= 5 then
                    ToEdit[ToEditIndex + 7].value = "~A8 LDR X5, [PC,#0x34]"
                    if Table[i]['parameters'][5][2] == true then
                        ToEdit[ToEditIndex + 15].value = 1
                    elseif Table[i]['parameters'][5][2] == false then
                        ToEdit[ToEditIndex + 15].value = 0
                    else
                        ToEdit[ToEditIndex + 15].value = Table[i]['parameters'][5][2]
                    end
                    ToEdit[ToEditIndex + 15].flags = HackersHouse.getType(Table[i]['parameters'][5][1])
                else
                    ToEdit[ToEditIndex + 7].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 15].value = "~A8 NOP"
                    ToEdit[ToEditIndex + 15].flags = gg.TYPE_DWORD
                end
    
    
                ToEdit[ToEditIndex + 8].value = "~A8 LDR  X6, [PC,#0x8]"
                ToEdit[ToEditIndex + 9].value = "~A8 BR X6"
                ToEdit[ToEditIndex + 10].value = Lib[libIndex].start + Table[i]['destinationOffset']
    
    
    
    
    
                ToEdit[ToEditIndex].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 1].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 2].flags = gg.TYPE_QWORD
                ToEdit[ToEditIndex + 3].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 4].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 5].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 6].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 7].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 8].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 9].flags = gg.TYPE_DWORD
                ToEdit[ToEditIndex + 10].flags = gg.TYPE_QWORD
                

                ToEditIndex = ToEditIndex + 16
                if IsReactivated then
                    HackersHouse.callAnotherMethodList.currentWriteAddress = currentWriteAddressBackup 
                else
                    HackersHouse.callAnotherMethodList.currentWriteAddress = HackersHouse.callAnotherMethodList.currentWriteAddress + 0x48 +0x4
                end
            end
        end
        


        gg.setValues(ToEdit)
    end,
    ['hijackParametersOff'] = function(Table)
        if HackersHouse.validation("hijackParametersOff", Table) then
            return
        end
        for i, v in ipairs(Table) do
            if HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] ~= nil then
                gg.setValues(HackersHouse.hookMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'])
            end
        end
    end,
    ['voidHookOff'] = function(Table)
        if HackersHouse.validation("voidHookOff", Table) then
            return
        end
        if HackersHouse.is64Bit == true then
           Patch = "~A8 B [PC,#0x98]"
           Offsett = 0xC
        else
           Patch = "~A B +0x58"
           Offsett = 0x0
        end
        local ToEdit = {}
        for i, v in ipairs(Table) do
            if  HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']] ~= nil then
                if HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats[Table[i]['destinationOffset']] ~= nil then
                ToEdit[i] = {}
                ToEdit[i].address = HackersHouse.voidHookList['Allocations'][Table[i]['libName']..Table[i]['targetOffset']].activatedCheats[Table[i]['destinationOffset']]['allocatedAddress'] +0x10 + Offsett
                ToEdit[i].flags = gg.TYPE_DWORD
                ToEdit[i].value = Patch
                end
                
            end
        end
        gg.setValues(ToEdit)
    end,
    ['disableMethodOff'] = function(Table)
        if HackersHouse.validation("disableMethodOff", Table) then
            return
        end
        for i, v in ipairs(Table) do
            if HackersHouse.disableMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] ~= nil then
                gg.setValues(HackersHouse.disableMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'])
            end
        end
    end,
    ['returnValueOff'] = function(Table)
        if HackersHouse.validation("returnValueOff", Table) then
            return
        end
        for i, v in ipairs(Table) do
            if HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] ~= nil then
                gg.setValues(HackersHouse.returnValueList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'])
            end
        end
    end,
    ['hexPatchOff'] = function(Table)
        if HackersHouse.validation("hexPatchOff", Table) then
            return
        end
        for i, v in ipairs(Table) do
            if HackersHouse.hexPatchList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']] ~= nil then
                gg.setValues(HackersHouse.hexPatchList.activatedCheats[Table[i]['libName'] .. Table[i]['offset']]['defaultValues'])
            end
        end
    end,
    ['callAnotherMethodOff'] = function(Table)
        if HackersHouse.validation("callAnotherMethodOff", Table) then
            return
        end
        for i, v in ipairs(Table) do
            if HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']] ~= nil then 
                gg.setValues(HackersHouse.callAnotherMethodList.activatedCheats[Table[i]['libName'] .. Table[i]['targetOffset']]['defaultValues'])
            end
        end
    end,
    ['getType'] = function(Value)
        if Value == "bool" then
            return gg.TYPE_BYTE
        elseif Value == "int" then
            return gg.TYPE_DWORD
        elseif Value == "long int" then
            return gg.TYPE_QWORD
        elseif Value == "float" then
            return gg.TYPE_FLOAT
        elseif Value == "double" then
            return gg.TYPE_DOUBLE
        end
    end
}
HackersHouse.UpdateChecked();

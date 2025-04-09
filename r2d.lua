local OrionLib = loadstring(game:HttpGet(('https://raw.githubusercontent.com/jensonhirst/Orion/refs/heads/main/source')))()

local Workspace = game:GetService("Workspace")
local Players = game:GetService("Players")
local LocalPlayer = game:GetService("Players").LocalPlayer

local function getFunctionFromLocalScript(functionName, script)
    for i,v in pairs(getgc()) do
        if typeof(v) == "function" then
            local parentScript = rawget(getfenv(v), "script")
            if script == parentScript and  getinfo(v).name == functionName then
                print(getinfo(v).name)
                return v;
            end
        end
    end
end
local function createDictionaryShallowCopy(dict)
    local dictionaryCopy = {};
    for i,v in pairs(dict) do
        dictionaryCopy[i] = v
    end
    return dictionaryCopy
end
local function nilFunction() 
end
local function getTeam(player) 
	if not player:IsA("Player") and not player:IsA("Model") then
		return ""
	end
	if player.Parent:IsA("Folder") then
		return player.Parent.Name:gsub("s$", "")
	end
    return player.Team.Name 
end

local function isAlive(player)
    if player == nil then
        return false
    end
    if (player:IsA("Player") and player.Character and player.Character.PrimaryPart and player.Character:FindFirstChild("Humanoid") and player.Character.PrimaryPart) or (player:IsA("Model") and player.PrimaryPart and player:FindFirstChild("Humanoid")) then
        return true;
    end
    return false;
end

local function getZombieType(player) 
	if not isAlive(player) or getTeam(player)  ~= "Zombie" then
		return ""
	end
	if player:IsA("Model") then
		return player.Humanoid:GetAttribute("Character")
	end
	return player.Character.Humanoid:GetAttribute("Character")
end

local function GetClosest(team, object, dist)
    local closestDistance = dist;
    local closestEntity;
    for _,v in pairs(Workspace.Characters:FindFirstChild(team):GetChildren()) do
        if isAlive(v) then
			local currentDistance = (object - v.PrimaryPart.Position).Magnitude
			if currentDistance < closestDistance then
				closestDistance = currentDistance
				closestEntity = v
			end  
        end      
    end
    return closestEntity
end

local Toggles = {
	Stamina = false;
	Killaura = false;
	GunMods = {
		Enabled = false;
		Accuracy = 1000;
		Range = 1000;
		FireRate = 0.05;
	};
}

local Window = OrionLib:MakeWindow({Name = "Ready 2 Die", HidePremium = true, SaveConfig = true, ConfigFolder = "OrionTest", IntroEnabled = false})
local Main = Window:MakeTab({
	Name = "Main",
	Icon = "rbxassetid://4483345998",
	PremiumOnly = false
})

local GunMods = Window:MakeTab({
	Name = "Gun Mods",
	Icon = "rbxassetid://4483345998",
	PremiumOnly = false
})

local function nilFunction() end
local oldFunction = nil;
local function removeStamina()
    local team = LocalPlayer.PlayerGui:WaitForChild(getTeam(LocalPlayer),10)
    if not team then
    	return 
	end
    if not isAlive(LocalPlayer) then
        return;
    end
    local energy = LocalPlayer.PlayerGui:FindFirstChild(getTeam(LocalPlayer)):WaitForChild("Energy",1)
	if not energy then
        return
    end
    local env = getsenv(energy.Energy.Keybind);
    if not Toggles.Stamina then 
        if oldFunction then env.removestamina = oldFunction end
        return
    end
	oldFunction = env.removestamina;
	env.removestamina = nilFunction;
end

Players.LocalPlayer.CharacterAdded:Connect(removeStamina)
Players.LocalPlayer.CharacterRemoving:Connect(function() 
    oldFunction = nil;
end)

Main:AddToggle({
	Name = "Infinite Stamina",
	Default = false,
	Callback = function(Value)
		Toggles.Stamina = Value
		removeStamina()
	end    
})

coroutine.wrap(function()
	while task.wait(0.05) do 
		if not Toggles.Killaura then
			continue;
		end
		local team = getTeam(LocalPlayer)
		if team == "Zombie" and isAlive(LocalPlayer) then
			local entity = GetClosest("Survivors", LocalPlayer.Character.HumanoidRootPart.Position, 15)
			if entity then
				game:GetService("ReplicatedStorage").Events.Zombie.ClawAttacked:FireServer(entity.Humanoid, nil, nil, entity.Head)
			end
		elseif team  == "Survivor" and isAlive(LocalPlayer) then
			local entity = GetClosest("Zombies", LocalPlayer.Character.HumanoidRootPart.Position, 15)
			if entity then
				game:GetService("ReplicatedStorage").Events.Survivor.KickAttacked:FireServer(entity.Humanoid, 0)
				game:GetService("ReplicatedStorage").Events.Survivor.PunchAttacked:FireServer(entity.Humanoid, 3)
			end
		end
	end
end)()

Main:AddToggle({
	Name = "Killaura",
	Default = false,
	Callback = function(Value)
	    Toggles.Killaura = Value
    end
})
local originalFunction = getFunctionFromLocalScript("Fire", game:GetService("Players").LocalPlayer.PlayerGui.CoreChat.Code.Extra)
local oldOriginalFunction;
oldOriginalFunction = hookfunction(originalFunction, function(...)
	local args = {...}
    local args2Copy = createDictionaryShallowCopy(args[2])
	if Toggles.GunMods.Enabled then
		args2Copy.Accuracy = Toggles.GunMods.Accuracy
		args2Copy.MaxDistance = Toggles.GunMods.MaxDistance
		args2Copy.FireRate = Toggles.GunMods.FireRate
        args[2] = args2Copy
	end
    oldOriginalFunction(unpack(args))
end)
GunMods:AddToggle({
	Name = "Enable Gun Mods",
	Default = false,
	Callback = function(Value)
	    Toggles.GunMods.Enabled = Value
    end
})
GunMods:AddSlider({
	Name = "Accuracy",
	Min = 1,
	Max = 1000,
	Default = 1000,
	Color = Color3.fromRGB(255,255,255),
	Increment = 1,
	ValueName = "",
	Callback = function(Value)
		Toggles.GunMods.Accuracy = Value
	end    
})
GunMods:AddSlider({
	Name = "Firerate",
	Min = 0.01,
	Max = 1,
	Default = 0.09,
	Color = Color3.fromRGB(255,255,255),
	Increment = 0.01,
	ValueName = "",
	Callback = function(Value)
		Toggles.GunMods.FireRate = Value
	end    
})
GunMods:AddSlider({
	Name = "Range",
	Min = 50,
	Max = 500,
	Default = 500,
	Color = Color3.fromRGB(255,255,255),
	Increment = 1,
	ValueName = "",
	Callback = function(Value)
		Toggles.GunMods.MaxDistance = Value
	end    
})
OrionLib:Init()

task.wait(2)

_G.HeadSize = 10
_G.TeamCheck = true
_G.Disabled = true
_G.TargetPart = "Head" -- Default mode

function updateHitboxSize()
    for _, player in ipairs(game:GetService('Players'):GetPlayers()) do
        if player ~= game:GetService('Players').LocalPlayer then
            if _G.TeamCheck and game:GetService('Players').LocalPlayer.Team ~= player.Team or not _G.TeamCheck then
                pcall(function()
                    local character = player.Character
                    local targetPart = character and character:FindFirstChild(_G.TargetPart)
                    if targetPart then
                        targetPart.Size = Vector3.new(_G.HeadSize, _G.HeadSize, _G.HeadSize)
                        targetPart.Transparency = 0.7
                        targetPart.BrickColor = BrickColor.new(_G.TeamCheck and "Grey" or "Dark green")
                        targetPart.Material = Enum.Material.Neon
                        targetPart.CanCollide = false
                        targetPart.Massless = true
                    end
                end)
            end
        end
    end
end

game:GetService('UserInputService').InputBegan:Connect(function(input, gameProcessed)
    if gameProcessed then return end

    if _G.Disabled then
        if input.KeyCode == Enum.KeyCode.Z then
            _G.HeadSize = math.min(_G.HeadSize + 1, 20)
            updateHitboxSize()
            print("Size:", _G.HeadSize)
        elseif input.KeyCode == Enum.KeyCode.X then
            _G.HeadSize = math.max(_G.HeadSize - 1, 1)
            updateHitboxSize()
            print("Size:", _G.HeadSize)
        elseif input.KeyCode == Enum.KeyCode.G then
            if _G.TargetPart == "Head" then
                _G.TargetPart = "Torso"
                print("Switched to Torso mode")
            else
                _G.TargetPart = "Head"
                print("Switched to Head mode")
            end
            updateHitboxSize()
        end
    end
end)

game:GetService('RunService').RenderStepped:Connect(function()
    if _G.Disabled then
        updateHitboxSize()
    end
end)

task.wait(2)

loadstring(game:HttpGet('https://raw.githubusercontent.com/EdgeIY/infiniteyield/master/source'))()

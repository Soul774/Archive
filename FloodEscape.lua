local autoFarm = false
--gui
local library = loadstring(game:HttpGet(("https://raw.githubusercontent.com/AikaV3rm/UiLib/master/Lib.lua")))()
local w = library:CreateWindow("Flood Escape 1") -- Creates the window
local b = w:CreateFolder("Auto Farm") -- Creates the folder(U will put here your buttons,etc)
b:Toggle(
    "Auto Farm",
    function(bool)
        shared.toggle = bool
        print("Auto Farm: ", bool)
        autoFarm = bool
    end
)
b:DestroyGui()
-------
autoFarm = true
while wait(0.1) do
    if autoFarm == true then
        local playerTorso = game.Players.LocalPlayer.Character.Torso
        for i, v in pairs(game:GetService("Workspace").Hard.Entry:GetDescendants()) do
            if v.Name == "TouchInterest" and v.Parent then
                firetouchinterest(playerTorso, v.Parent, 0)
                firetouchinterest(playerTorso, v.Parent, 1)
            end
            if game:GetService("Workspace").Hard.Info.Value == "Lowering Lift..." then
                wait(2.5)
                game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-241, 160.600006, 322)
            end
        end
        wait(1)
        local playerTorso = game.Players.LocalPlayer.Character.Torso
        for i, v in pairs(game:GetService("Workspace").Medium.Entry:GetDescendants()) do
            if v.Name == "TouchInterest" and v.Parent then
                firetouchinterest(playerTorso, v.Parent, 0)
                firetouchinterest(playerTorso, v.Parent, 1)
            end
            if game:GetService("Workspace").Medium.Info.Value == "Lowering Lift..." then
                wait(2.5)
                game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-241, 160.600006, 192)
            end
        end
    end
end


--------------


autoFarm = true
while wait(0.1) do
    if autoFarm == true then
        if game:GetService("Workspace").Easy.Info.Value == "Game is Ready!" then
            local playerTorso = game.Players.LocalPlayer.Character.Torso
            for i, v in pairs(game:GetService("Workspace").Easy.Entry:GetDescendants()) do
                if v.Name == "TouchInterest" and v.Parent then
                    firetouchinterest(playerTorso, v.Parent, 0)
                    firetouchinterest(playerTorso, v.Parent, 1)
                end
                if game:GetService("Workspace").Easy.Info.Value == "Lowering Lift..." then
                    wait(2.5)
                    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-241, 160.600006, 62)
                end
            end
        end

        if game:GetService("Workspace").Medium.Info.Value == "Game is Ready!" then
            local playerTorso = game.Players.LocalPlayer.Character.Torso
            for i, v in pairs(game:GetService("Workspace").Medium.Entry:GetDescendants()) do
                if v.Name == "TouchInterest" and v.Parent then
                    firetouchinterest(playerTorso, v.Parent, 0)
                    firetouchinterest(playerTorso, v.Parent, 1)
                end
                if game:GetService("Workspace").Medium.Info.Value == "Lowering Lift..." then
                    wait(2.5)
                    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-241, 160.600006, 192)
                end
            end
        end

        if game:GetService("Workspace").Hard.Info.Value == "Game is Ready!" then
            local playerTorso = game.Players.LocalPlayer.Character.Torso
            for i, v in pairs(game:GetService("Workspace").Hard.Entry:GetDescendants()) do
                if v.Name == "TouchInterest" and v.Parent then
                    firetouchinterest(playerTorso, v.Parent, 0)
                    firetouchinterest(playerTorso, v.Parent, 1)
                end
                if game:GetService("Workspace").Hard.Info.Value == "Lowering Lift..." then
                    wait(2.5)
                    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-241, 160.600006, 322)
                end
            end
        end
    end
end
local color = Color3.new(0, 0, 1)

while task.wait(1) do
    for _, v in next, game:GetService("Workspace"):GetChildren() do
        if string.find(v.Name, "bhop") or string.find(v.Name, "surf") then
            for _, b in next, v:GetDescendants() do
                if b:IsA("Part") and string.find(b.Name, "Trigger") then
                    if not b:FindFirstChild("SelectionBox") then
                        local box = Instance.new("SelectionBox")
                        box.Adornee = b
                        box.Color3 = color
                        box.LineThickness = 0.5
                        box.Transparency = 0
                        box.Parent = b
                    end
                end
            end
        end
    end
end


--[[
MapStart
MapFinish
Trigger

Part

bhop
surf
--]]


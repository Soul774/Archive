#NoEnv
#SingleInstance Force
#Persistent
#InstallMouseHook
#KeyHistory 0
SetBatchLines -1
ListLines Off
Process Priority,,Realtime

; ------------------------------------------------------------------
; SETTINGS
; ------------------------------------------------------------------
TargetExe        := "RobloxPlayerBeta.exe"
DefaultFreezeMs  := 100
CurrentFreezeMs  := DefaultFreezeMs
ChosenButton     := "XButton2"   ; default drop-down choice
StatusBar        := "Status: Ready"

; ------------------------------------------------------------------
; GUI
; ------------------------------------------------------------------
Gui Font, s10, Segoe UI
Gui Add, Text,  x20 y20, Freeze Duration (ms 1-1000):
Gui Add, Edit,  x20 y40 w100 vGuiFreezeMs, %CurrentFreezeMs%
Gui Add, Button, x20  y70 w100 gApplySettings, Apply Settings
Gui Add, Button, x130 y70 w100 gTestFreeze,    Test Freeze
Gui Add, DropDownList, x20 y110 w100 vGuiMouseButton Choose2, XButton1|XButton2|MButton
Gui Add, Text,  x20 y140 w250 vGuiStatus, %StatusBar%
Gui Show, w310 h180, Evade.Freezer.Mouse.By.Discord.liiilillilliililli

Menu Tray, NoStandard
Menu Tray, Add, &Open GUI, TrayOpenGUI
Menu Tray, Add, E&xit,      TrayExit

BindHotkeys()          ; set initial hotkey
return

; ------------------------------------------------------------------
; GUI HANDLERS
; ------------------------------------------------------------------
ApplySettings:
    Gui Submit, NoHide
    GuiFreezeMs := GuiFreezeMs+0        ; force numeric
    if (GuiFreezeMs < 1 || GuiFreezeMs > 1000) {
        MsgBox 16,, Please enter a value between 1-1000 ms
        GuiControl,, GuiFreezeMs, %CurrentFreezeMs%
        return
    }
    CurrentFreezeMs := GuiFreezeMs
    BindHotkeys()
    GuiControl,, GuiStatus, Status: Settings Applied (%CurrentFreezeMs% ms)
return

TestFreeze:
    GuiControl,, GuiStatus, Status: Testing Freeze...
    Gosub FreezeRoblox
    GuiControl,, GuiStatus, Status: Test Complete
return

TrayOpenGUI:
Gui Show
return

GuiClose:
Gui Hide
return

TrayExit:
ExitApp

; ------------------------------------------------------------------
; HOTKEY LOGIC
; ------------------------------------------------------------------
BindHotkeys() {
    global ChosenButton
    static oldBtn := ""

    ; remove old hotkeys if any
    if (oldBtn != "") {
        Hotkey %oldBtn%, Off
        Hotkey ^%oldBtn%, Off
    }

    GuiControlGet, ChosenButton,, GuiMouseButton
    oldBtn := ChosenButton

    try {
        Hotkey %ChosenButton%,     FreezeRoblox, On
        Hotkey ^%ChosenButton%,    FreezeRoblox, On
        GuiControl,, GuiStatus, Status: Bound to %ChosenButton% (+Ctrl)
    } catch {
        GuiControl,, GuiStatus, Status: Error binding %ChosenButton%
    }
}

; ------------------------------------------------------------------
; CORE FREEZE ROUTINE
; ------------------------------------------------------------------
FreezeRoblox:
    Critical On
    Gui Submit, NoHide

    ; find the target process
    Process Exist, %TargetExe%
    pid := ErrorLevel
    if (!pid)
        WinGet pid,, ahk_exe %TargetExe%

    if (!pid) {
        GuiControl,, GuiStatus, Status: Roblox not found!
        Critical Off
        return
    }

    GuiControl,, GuiStatus, Status: Freezing...

    hProc := DllCall("OpenProcess", "UInt", 0x1F0FFF, "Int",0, "UInt",pid, "Ptr")
    if (hProc) {
        DllCall("ntdll\NtSuspendProcess", "Ptr",hProc)
        Sleep %CurrentFreezeMs%
        DllCall("ntdll\NtResumeProcess", "Ptr",hProc)
        DllCall("CloseHandle", "Ptr",hProc)
        GuiControl,, GuiStatus, Status: Frozen for %CurrentFreezeMs% ms
    } else {
        GuiControl,, GuiStatus, Status: Failed to open process
    }
    Critical Off
return

; ------------------------------------------------------------------
; QUICK KEYS
; ------------------------------------------------------------------
^!r::Reload
^!x::ExitApp

Process, Priority, , A
#NoEnv
#Persistent
#KeyHistory, 0
#HotKeyInterval 99000000
#MaxHotkeysPerInterval 99000000
#SingleInstance Force
SendMode, Input
ListLines, 0
SetKeyDelay, -1, -1
SetControlDelay, -1
SetMouseDelay, -1
SetWinDelay, -1
SetBatchLines, -1
 
mh := new mouseHook("AD")
Toggle := false  ; Toggle state
Hook := false    ; Hook state

; Toggle bind to C
~*c::
    Toggle := !Toggle
    if (Toggle && !Hook)
    {
        CoordMode, Mouse, Screen
        MouseGetPos, xold
        mh.hook()
        Hook := True
        ToolTip, Autostrafer Enabled
    }
    else if (!Toggle && Hook)
    {
        mh.unhook()
        SendInput, {a Up}{d Up}
        Hook := False
        ToolTip, Autostrafer Disabled
    }
    SetTimer, RemoveToolTip, -1000
Return

RemoveToolTip:
    ToolTip
Return

AD(h, x, y)
{
    Global
    static aDown := false
    static dDown := false
 
    if (x < xold)
    {
        if !aDown
        {
            SendInput, {Blind}{d Up}{a DownR}
            aDown := true
            dDown := false
        }
    }
    else if (x > xold)
    {
        if !dDown
        {
            SendInput, {Blind}{a Up}{d DownR}
            dDown := true
            aDown := false
        }
    }
}
 
;Helgef: https://www.autohotkey.com/boards/viewtopic.php?f=5&t=31144
class mouseHook
{
	; User methods
	hook()
	{
		if !this.hHook
			this.hHook:=DllCall("User32.dll\SetWindowsHookEx", "Int", 14, "Uint"
		, this.regCallBack:=RegisterCallback(this.LowLevelMouseProc,"F",4, &this)
		, "Uint", 0, "Uint", 0, "Ptr")
		return
	}
	unHook()
	{
		if this.hHook
			DllCall("User32.dll\UnhookWindowsHookEx", "Uint", this.hHook)
		return this.hHook:=""
	}
	; Internal methods.
	__new(callbackFunc)
	{
		this.callbackFunc:=callbackFunc
	}
	LowLevelMouseProc(args*)
	{
		; (nCode, wParam, lParam)
		Critical
		this:=Object(A_EventInfo)
		nCode:=NumGet(args-A_PtrSize,"Int")
		wParam:=NumGet(args+0,0,"Ptr")
		lParam:=NumGet(args+0,A_PtrSize,"UPtr")
		x:=NumGet(lParam+0,0,"Int")
		y:=NumGet(lParam+0,4,"Int")
		flags:=NumGet(lParam+0,12,"UInt")
		tf:=Func(this.callbackFunc).Bind(flags,x,y)
		SetTimer, % tf, -0
		return DllCall("User32.dll\CallNextHookEx"
		,"Uint",0, "Int", nCode,"Uint", wParam,"Uint",lParam)
	}
	__Delete()
	{
		this.unHook()
		if this.regCallBack
			DllCall("GlobalFree", "Ptr", this.regCallBack)
		return
	}
}
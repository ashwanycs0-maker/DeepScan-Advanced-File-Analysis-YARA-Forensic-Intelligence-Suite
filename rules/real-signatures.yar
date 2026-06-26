rule Suspicious_API
{
    strings:
        $a = "CreateRemoteThread"
        $b = "VirtualAlloc"
        $c = "WriteProcessMemory"

    condition:
        any of them
}

rule Keylogger_Indicators
{
    strings:
        $k1 = "GetAsyncKeyState"
        $k2 = "SetWindowsHookEx"

    condition:
        any of them
}

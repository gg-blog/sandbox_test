import os
import pytest
from pytest_mock import MockFixture
import sys
import docker
import time
sys.path.append('./src')
from sand import prepared,write_script,write_config,check_dependency,run_sandbox,open_sandbox,performance_windows_attack,run_sandbox,\
build_docker_image,run_docker_container,run_docker_command,syslog_output,remove_container,performance_linux_attack

def test_prepared():
    
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(cur_dir, '..'))
    src_dir = os.path.join(project_root, 'src')
    
    sandbox_files_dir = os.path.join(src_dir, "SandboxFiles")
    sandbox_config_path = os.path.join(src_dir,"SandboxFiles", "sandbox.wsb")
    install_script_path = os.path.join(src_dir,"SandboxFiles", "install_and_run.bat")
    sysmon_exe_path = os.path.join(src_dir,"SandboxFiles", "Sysmon64.exe")
    sysmon_config_path = os.path.join(src_dir,"SandboxFiles", "sysmonconfig.xml")
    assert prepared() == (sandbox_files_dir,sandbox_config_path,install_script_path,sysmon_exe_path,sysmon_config_path)
    
    
def test_write_script():
    with open("pseudo_file.txt", "w") as script_file:
        script_file.write("for test_write_script testing")
    true_path = "./pseudo_file.txt"
    assert write_script(true_path,"True test_write_script testing") == "True test_write_script testing"
    true_path = ""
    with pytest.raises(ValueError):
        write_script(true_path,"True testing")
        
def test_write_config():
    with open("pseudo_file.txt", "w") as script_file:
        script_file.write("for test_write_config testing")
    true_path = "./pseudo_file.txt"
    assert write_config(true_path,"True test_write_config testing") == "True test_write_config testing"
    true_path = ""
    with pytest.raises(ValueError):
        write_config(true_path,"True testing")

def test_check_dependency():
    with open("pseudo_file.txt", "w") as script_file:
        script_file.write("for test_check_dependency testing")
    true_path = "./pseudo_file.txt"
    fake_path = "./fake_file.xml"
    test_dict={0:fake_path,1:true_path}
    
    for i in range(2):
        for j in range(2):
            for k in range(2):
                for l in range(2):
                    if i==j==k==l==1:
                        print("all true path")
                        continue
                    with pytest.raises(FileNotFoundError):
                        check_dependency(test_dict[i],test_dict[j],test_dict[k],test_dict[l])
    assert check_dependency(true_path,true_path,true_path,true_path) == True


def mock_open_sandbox(config_path,usage):
    return 0
    
def test_run_sandbox(mocker: MockFixture):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(cur_dir, '..'))
    src_dir = os.path.join(project_root, 'src')
    
    sandbox_files_dir = os.path.join(src_dir, "SandboxFiles")
    sandbox_config_path = os.path.join(src_dir,"SandboxFiles", "sandbox.wsb")

    mocker.patch("sand.open_sandbox", side_effect=mock_open_sandbox)
    assert run_sandbox(sandbox_config_path) != False
    assert run_sandbox("..") == False


def test_build_docker_image():
    image = build_docker_image("./src","stub_string")
    assert isinstance(image,docker.models.images.Image) == True
    image = build_docker_image("./fake/fake","stub_string")
    assert image==None

def test_run_docker_container():
    
    assert isinstance(run_docker_container("slpine-syslog","slpine-syslog"),docker.models.containers.Container) == True


def mock_container(stub):
    return (1,"0")
def mock_stats(stream):
    state={'cpu_stats':{'cpu_usage':{'total_usage':2,'percpu_usage':[4]},'system_cpu_usage':4},\
    'precpu_stats':{'cpu_usage':{'total_usage':1,'percpu_usage':[4]},'system_cpu_usage':2},\
    'memory_stats':{'usage':5}}
    return state

def test_run_docker_command(mocker: MockFixture):
    container = mocker.Mock(spec=docker.models.containers.Container)
    container.exec_run.side_effect=mock_container
    container.stats.side_effect=mock_stats
    test_command=["whoami",
                    "echo 'whoami'> tmp",
                    "cp tmp tmp2",
                    "sh < tmp2"]
    cpu_usages=[]
    memory_usages=[]
    exit_codes, outputs = run_docker_command(container,test_command,cpu_usages,memory_usages)
    for exit_code in exit_codes:
        assert exit_code == 1
    for output in outputs:
        assert output == "0"
    assert cpu_usages == [50,50,50,50] 
    assert memory_usages == [5,5,5,5] 
    
    
def test_syslog_output():
    container=run_docker_container("slpine-syslog","slpine-syslog")
    test_command=["whoami",
            "echo 'whoami'> tmp",
            "cp tmp tmp2",
            "sh < tmp2",
            "cat /etc/shadow",
            "echo \"echo hash_value > name.out\" | at now + 1 minute",
            "echo \"*/2 * * * * root whoami > username\" >> /etc/crontab"]
    cpu_usages=[]
    memory_usages=[]
    run_docker_command(container,test_command,cpu_usages,memory_usages)
    time.sleep(60)
    exit_code_1, exit_code_2, output=syslog_output(container,'container_syslog.log')
    assert exit_code_1 == 0
    assert exit_code_2 == 0
    assert output != None
    assert os.path.exists('container_syslog.log') == True
    
    

def test_remove_container():
    container=run_docker_container("slpine-syslog","slpine-syslog")
    remove_container(container)
    client = docker.from_env()
    flag=False
    
    try:
        client.containers.get("slpine-syslog")
    except docker.errors.NotFound:
        flag=True
    
    assert flag == True




import os
import pytest
from pytest_mock import MockFixture
import sys
import docker
import time
sys.path.append('./src')
from sand import prepared,write_script,write_config,check_dependency,run_sandbox,open_sandbox,performance_windows_attack,run_sandbox,\
build_docker_image,run_docker_container,run_docker_command,syslog_output,remove_container,performance_linux_attack

def test_integrated_windows_attack():
    performance_windows_attack()
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(cur_dir, '..'))
    sysmon_log_path = os.path.join(project_root,'src',"SandboxFiles", "log.xml")
    assert os.path.exists(sysmon_log_path) == True

def test_integrated_linux_attack():
    performance_linux_attack()
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(cur_dir, '..'))
    log_path = os.path.join(project_root,'src', "container_syslog.log")
    assert os.path.exists(log_path) == True
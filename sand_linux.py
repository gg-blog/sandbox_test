import docker
import os
import time
# Initialize Docker client
client = docker.from_env()

# Define the syslog address
test_command=["whoami",
                "echo 'whoami'> tmp",
                "cp tmp tmp2",
                "sh < tmp2"]
# Create and start a new container with syslog logging
image, build_logs = client.images.build(path=".", tag="slpine-syslog")
for log in build_logs:
    if 'stream' in log:
        print(log['stream'], end='')

container_name="slpine-syslog"
try:
    existing_container = client.containers.get(container_name)
    print(f"Container {container_name} already exists. Removing it.")
    existing_container.remove(force=True)
except docker.errors.NotFound:
    print(f"No existing container with name {container_name}.")

container = client.containers.run(
    container_name,
    detach=True,
    name=container_name
)
time.sleep(10)
#for line in test_command:
#    exit_code, output = container.exec_run(line)
#    if exit_code == 0:
#        print(output)  
exit_code, output = container.exec_run("ls /var/log ")
print(output) 
#exit_code, output = container.exec_run("cat /var/log/syslog")
#if exit_code == 0:
#    print(output.decode())
#    syslog = 'container_syslog.log'
#    with open(syslog, 'w') as output_file:
#        output_file.write(output.decode())

# Wait for the container to complete
container.stop()


# Stop and remove the container
container.remove()

print(f"Container {container.id} stopped and removed.")


import docker
import os
import time
# Initialize Docker client
client = docker.from_env()

# Define the syslog address
test_command=["whoami",
            "echo 'whoami'> tmp",
            "cp tmp tmp2",
            "sh < tmp2",
            "cat /etc/shadow",
            "echo \"echo hash_value > name.out\" | at now + 1 minute",
            "echo \"*/2 * * * * root whoami > username\" >> /etc/crontab",
            "echo \"whoami > root_name\" | crontab"]
container_name="logging-container"
# Create and start a new container with syslog logging
image, build_logs = client.images.build(path=".", tag=container_name)
for log in build_logs:
    if 'stream' in log:
        print(log['stream'], end='')

try:
    existing_container = client.containers.get(container_name)
    print(f"Container {container_name} already exists. Removing it.")
    existing_container.remove(force=True)
except docker.errors.NotFound:
    print(f"No existing container with name {container_name}.")

container = client.containers.run(
    image="logging-container",  # Specify the image name
    name="logging-container",   # Specify the container name
    privileged=True,            # Run in privileged mode
    detach=True                 # Run the container in detached mode
)
time.sleep(10)
for line in test_command:
    shell_cmd = f"/bin/sh -c '{line}'"
    exit_code, output = container.exec_run(shell_cmd)
    if exit_code == 0:
        print(output.decode())  
exit_code, output = container.exec_run("ls /var/log ")
print(output.decode()) 
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


# Use an official Ubuntu as a parent image
FROM ubuntu:20.04

# Install necessary packages
RUN apt-get update && \
    apt-get install -y at sudo syslog-ng


# Enable the atd service
RUN echo 'START=yes' > /etc/default/atd

# Configure sudo to log commands
RUN echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers


# Start rsyslog and atd
CMD service atd start && service syslog-ng start && service cron start && tail -f /dev/null 

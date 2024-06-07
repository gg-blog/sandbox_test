# Use an official Ubuntu as a parent image
FROM ubuntu:20.04

# Install necessary packages
RUN apt-get update && \
    apt-get install -y rsyslog at sudo

# Enable and configure rsyslog
RUN sed -i 's/#module(load="imuxsock")/module(load="imuxsock")/' /etc/rsyslog.conf && \
    sed -i 's/#module(load="imklog")/module(load="imklog")/' /etc/rsyslog.conf && \
    sed -i 's/#\$ModLoad immark/\$ModLoad immark/' /etc/rsyslog.conf && \
    sed -i 's/#\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat/\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat/' /etc/rsyslog.conf && \
    sed -i 's/#\$FileOwner syslog/\$FileOwner syslog/' /etc/rsyslog.conf && \
    sed -i 's/#\$FileGroup adm/\$FileGroup adm/' /etc/rsyslog.conf && \
    sed -i 's/#\$FileCreateMode 0640/\$FileCreateMode 0640/' /etc/rsyslog.conf && \
    sed -i 's/#\$DirCreateMode 0755/\$DirCreateMode 0755/' /etc/rsyslog.conf && \
    sed -i 's/#\$Umask 0022/\$Umask 0022/' /etc/rsyslog.conf && \
    sed -i 's/#\$PrivDropToUser syslog/\$PrivDropToUser syslog/' /etc/rsyslog.conf && \
    sed -i 's/#\$PrivDropToGroup syslog/\$PrivDropToGroup syslog/' /etc/rsyslog.conf

# Enable the atd service
RUN echo 'START=yes' > /etc/default/atd

# Create a log directory
RUN mkdir -p /var/log/commands && chown syslog:adm /var/log/commands

# Configure rsyslog to log to the created directory
RUN echo 'local0.* /var/log/commands/command.log' >> /etc/rsyslog.d/50-default.conf

# Configure sudo to log commands
RUN echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers

# Expose the log directory as a volume
VOLUME /var/log/commands

# Start rsyslog and atd
CMD service rsyslog start && service atd start && tail -f /var/log/syslog

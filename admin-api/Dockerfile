FROM python:3.12-slim

# Install dependencies (including gosu prerequisites and openssh-server)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    acl \
    sudo \
    python3-venv \
    cron \
    ca-certificates \
    gnupg \
    dirmngr \
    wget \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Install gosu (clean uid/gid switch)
RUN set -eux; \
    GOSU_VERSION=1.16; \
    dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
    wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch"; \
    chmod +x /usr/local/bin/gosu; \
    gosu nobody true

# Create monkey user
RUN useradd -m -s /bin/bash monkey

# Set password for monkey (change before production!)
RUN echo "monkey:changeme" | chpasswd

# Disable root SSH login and allow only monkey user
RUN mkdir /var/run/sshd; \
    sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config; \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config; \
    echo "AllowUsers monkey" >> /etc/ssh/sshd_config

# Copy application files into /opt/.app owned by monkey
RUN mkdir -p /opt/.app
COPY --chown=monkey:monkey . /opt/.app
RUN chmod 711 /opt/.app && \
    chown monkey:monkey /opt/.app/admin_api.py && chmod 711 /opt/.app/admin_api.py

# Create log directories, owned by monkey
RUN mkdir -p /var/log/ctf_admin /var/log/ctf_status && \
    chown -R monkey:monkey /var/log/ctf_admin /var/log/ctf_status && \
    chmod -R 755 /var/log/ctf_admin /var/log/ctf_status

# Setup cron runtime and log file, give write permission to monkey
RUN mkdir -p /var/run && chmod 755 /var/run
RUN touch /var/log/cron.log && chmod 666 /var/log/cron.log
RUN chown monkey:monkey /var/log/cron.log

# Create shelldon user (flag owner)
RUN useradd -m -s /bin/bash shelldon && \
    mkdir -p /home/shelldon && \
    echo "SADC{chained_exploit_ssrf_ssti_rce_lpe}" > /home/shelldon/flag.txt && \
    chown shelldon:shelldon /home/shelldon/flag.txt && \
    chmod 440 /home/shelldon/flag.txt && \
    chmod 700 /home/shelldon

# Create ctfgroup and add monkey and shelldon
RUN addgroup ctfgroup && \
    adduser monkey ctfgroup && \
    adduser shelldon ctfgroup && \
    chgrp ctfgroup /home/shelldon/flag.txt && chmod 440 /home/shelldon/flag.txt

# Hidden directory permissions for escalation
RUN mkdir -p /home/monkey/.hidden_dir && \
    chown shelldon:ctfgroup /home/monkey/.hidden_dir && \
    chmod 710 /home/monkey/.hidden_dir

# Allow shelldon to traverse /home/monkey
RUN setfacl -m u:shelldon:x /home/monkey

# Writable cron-executed script owned by shelldon:ctfgroup and monkey can rw but not execute
RUN printf '%s\n' '#!/bin/bash' \
    'echo "Running user: $(whoami) at $(date)" >> /tmp/cron_hit.log' \
    > /home/monkey/.hidden_dir/script.sh && \
    chown shelldon:ctfgroup /home/monkey/.hidden_dir/script.sh && \
    chmod 750 /home/monkey/.hidden_dir/script.sh && \
    setfacl -m u:monkey:rw /home/monkey/.hidden_dir/script.sh

# Install crontab for shelldon (cron jobs run as shelldon)
RUN printf "%s\n" "* * * * * /home/monkey/.hidden_dir/script.sh >> /var/log/cron.log 2>&1" | crontab -u shelldon -

# Remove all SUID/SGID bits globally
RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

# Monkey bash history file
RUN echo "cd /home/monkey/.hidden_dir" > /home/monkey/.bash_history && \
    echo "ls" >> /home/monkey/.bash_history && \
    echo "touch /home/monkey/.hidden_dir/script.sh" >> /home/monkey/.bash_history && \
    echo "history" >> /home/monkey/.bash_history && \
    chown monkey:monkey /home/monkey/.bash_history && chmod 600 /home/monkey/.bash_history

# Disable root password login (locks root account)
RUN passwd -l root

# Setup Python virtual environment and install dependencies as monkey
USER monkey
RUN python3 -m venv /home/monkey/.venv && \
    /home/monkey/.venv/bin/pip install --upgrade pip && \
    /home/monkey/.venv/bin/pip install flask requests flask-cors flask-openapi3 && \
    /home/monkey/.venv/bin/pip install -U "flask-openapi3[swagger]"

# Go back to root to create start script
USER root

# Start script starts cron and sshd as root, then runs app as monkey via gosu
RUN printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    '' \
    '# ensure log exists and permissions are permissive so cron can write' \
    'mkdir -p /var/log' \
    'touch /var/log/cron.log' \
    'chmod 666 /var/log/cron.log' \
    '' \
    '# start cron in foreground in background' \
    'cron -f &' \
    '' \
    '# start sshd in background' \
    '/usr/sbin/sshd -D &' \
    '' \
    '# small wait to ensure services started' \
    'sleep 0.2' \
    '' \
    '# drop privileges cleanly to monkey and exec the flask app (PID 1 will be python)' \
    'exec /usr/local/bin/gosu monkey /home/monkey/.venv/bin/python /opt/.app/admin_api.py' \
    > /usr/local/bin/start.sh && chmod +x /usr/local/bin/start.sh

EXPOSE 9000 22
WORKDIR /home/monkey

# Default to monkey user, so docker exec runs as monkey by default
USER monkey

# Default command to start services and app
CMD ["/usr/local/bin/start.sh"]

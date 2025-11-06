FROM python:3.12-slim

# Install dependencies (gosu, cron, sshd, python dev tools)
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

# Install gosu for privilege dropping
RUN set -eux; \
    GOSU_VERSION=1.16; \
    dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
    wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch"; \
    chmod +x /usr/local/bin/gosu; \
    gosu nobody true

# Create monkey user with bash
RUN useradd -m -s /bin/bash monkey

# Set simple password for monkey (change before production)
RUN echo "monkey:changeme" | chpasswd

# Configure SSH - disable root login, allow monkey only
RUN mkdir /var/run/sshd; \
    sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config; \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config; \
    echo "AllowUsers monkey" >> /etc/ssh/sshd_config

# Copy app files owned by monkey
RUN mkdir -p /opt/.app
COPY --chown=monkey:monkey . /opt/.app
RUN chmod 711 /opt/.app && chown monkey:monkey /opt/.app/admin_api.py && chmod 711 /opt/.app/admin_api.py

# Setup log directories with monkey ownership
RUN mkdir -p /var/log/ctf_admin /var/log/ctf_status && \
    chown -R monkey:monkey /var/log/ctf_admin /var/log/ctf_status && chmod -R 755 /var/log/ctf_admin /var/log/ctf_status

# Setup /var/run and cron log file with permissions
RUN mkdir -p /var/run && chmod 755 /var/run
RUN touch /var/log/cron.log && chmod 666 /var/log/cron.log
RUN chown monkey:monkey /var/log/cron.log

# Create shelldon user and flag
RUN useradd -m -s /bin/bash shelldon && mkdir -p /home/shelldon && \
    echo "SADC{chained_exploit_ssrf_ssti_rce_lpe}" > /home/shelldon/flag.txt && \
    chown shelldon:shelldon /home/shelldon/flag.txt && chmod 440 /home/shelldon/flag.txt && chmod 700 /home/shelldon

# Create ctfgroup and add users
RUN addgroup ctfgroup && adduser monkey ctfgroup && adduser shelldon ctfgroup && \
    chgrp ctfgroup /home/shelldon/flag.txt && chmod 440 /home/shelldon/flag.txt

# Setup hidden dir for monkey, with ACL for shelldon
RUN mkdir -p /home/monkey/.hidden_dir && chown shelldon:ctfgroup /home/monkey/.hidden_dir && chmod 710 /home/monkey/.hidden_dir
RUN setfacl -m u:shelldon:x /home/monkey

# Cron-executed script with ACL allowing monkey rw but not execute
RUN printf '%s\n' '#!/bin/bash' 'echo "Running user: $(whoami) at $(date)" >> /tmp/cron_hit.log' > /home/monkey/.hidden_dir/script.sh && \
    chown shelldon:ctfgroup /home/monkey/.hidden_dir/script.sh && chmod 750 /home/monkey/.hidden_dir/script.sh && \
    setfacl -m u:monkey:rw /home/monkey/.hidden_dir/script.sh

# Install crontab for shelldon user
RUN printf "%s\n" "* * * * * /home/monkey/.hidden_dir/script.sh >> /var/log/cron.log 2>&1" | crontab -u shelldon -

# Remove all SUID/SGID binaries globally
RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

# Monkey bash history setup
RUN echo -e "cd /home/monkey/.hidden_dir\nls\ntouch /home/monkey/.hidden_dir/script.sh\nhistory" > /home/monkey/.bash_history && \
    chown monkey:monkey /home/monkey/.bash_history && chmod 600 /home/monkey/.bash_history

# Disable root password login
RUN passwd -l root

# Setup virtual env and install python deps as monkey
USER monkey
RUN python3 -m venv /home/monkey/.venv && \
    /home/monkey/.venv/bin/pip install --upgrade pip && \
    /home/monkey/.venv/bin/pip install flask requests flask-cors flask-openapi3 && \
    /home/monkey/.venv/bin/pip install -U "flask-openapi3[swagger]"

# Switch back to root to create startup script
USER root

RUN printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    '' \
    'mkdir -p /var/log' \
    'touch /var/log/cron.log' \
    'chmod 666 /var/log/cron.log' \
    'mkdir -p /var/run && chmod 755 /var/run' \
    'ssh-keygen -A' \
    'cron -f &' \
    '/usr/sbin/sshd -D &' \
    'sleep 0.2' \
    'exec /usr/local/bin/gosu monkey /home/monkey/.venv/bin/python /opt/.app/admin_api.py' \
    > /usr/local/bin/start.sh && chmod +x /usr/local/bin/start.sh

EXPOSE 9000 22
WORKDIR /home/monkey

USER monkey

CMD ["/usr/local/bin/start.sh"]

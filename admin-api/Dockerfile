FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    acl \
    sudo \
    python3-venv \
    cron \
    && rm -rf /var/lib/apt/lists/*

# ----------------------------
# Create monkey user
# ----------------------------
RUN useradd -m -s /bin/bash monkey

RUN mkdir -p /opt/.app
COPY --chown=monkey:monkey . /opt/.app

RUN chmod 711 /opt/.app
RUN chown monkey:monkey /opt/.app/admin_api.py && chmod 711 /opt/.app/admin_api.py

RUN mkdir -p /var/log/ctf_admin /var/ctf_status && \
    chown -R monkey:monkey /var/log/ctf_admin /var/ctf_status && \
    chmod -R 755 /var/log/ctf_admin /var/ctf_status

# ----------------------------
# Cron runtime + log file
# ----------------------------
RUN mkdir -p /var/run && chmod 755 /var/run
RUN touch /var/log/cron.log && chmod 666 /var/log/cron.log

# ----------------------------
# Create shelldon user (flag owner)
# ----------------------------
RUN useradd -m -s /bin/bash shelldon && \
    mkdir -p /home/shelldon && \
    echo "SADC{chained_exploit_ssrf_ssti_rce_lpe}" > /home/shelldon/flag.txt && \
    chown shelldon:shelldon /home/shelldon/flag.txt && \
    chmod 440 /home/shelldon/flag.txt && \
    chmod 700 /home/shelldon

# ----------------------------
# Create ctfgroup and add users
# ----------------------------
RUN addgroup ctfgroup && \
    adduser monkey ctfgroup && \
    adduser shelldon ctfgroup && \
    chgrp ctfgroup /home/shelldon/flag.txt && \
    chmod 440 /home/shelldon/flag.txt

# ----------------------------
# Hidden directory for escalation
# ----------------------------
RUN mkdir -p /home/monkey/.hidden_dir && \
    chown shelldon:ctfgroup /home/monkey/.hidden_dir && \
    chmod 710 /home/monkey/.hidden_dir

# Allow shelldon to traverse /home/monkey (no other read/listing)
RUN setfacl -m u:shelldon:x /home/monkey

# Writable cron-executed script
RUN printf '%s\n' '#!/bin/bash' \
    'echo "Running user: $(whoami) at $(date)" >> /tmp/cron_hit.log' \
    > /home/monkey/.hidden_dir/script.sh && \
    chown shelldon:ctfgroup /home/monkey/.hidden_dir/script.sh && \
    chmod 750 /home/monkey/.hidden_dir/script.sh && \
    # allow monkey to edit (rw) without giving execute
    setfacl -m u:monkey:rw /home/monkey/.hidden_dir/script.sh

# ----------------------------
# Install crontab for shelldon (uses crontab tool so permissions are correct)
# Redirect job output to /var/log/cron.log
# ----------------------------
RUN printf "%s\n" "* * * * * /home/monkey/.hidden_dir/script.sh >> /var/log/cron.log 2>&1" \
    | crontab -u shelldon -

# ----------------------------
# Remove SUID/GUID globally
# ----------------------------
RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

# ----------------------------
# Monkey bash history
# ----------------------------
RUN echo "cd /home/monkey/.hidden_dir" > /home/monkey/.bash_history && \
    echo "ls" >> /home/monkey/.bash_history && \
    echo "touch /home/monkey/.hidden_dir/script.sh" >> /home/monkey/.bash_history && \
    echo "history" >> /home/monkey/.bash_history && \
    chown monkey:monkey /home/monkey/.bash_history && \
    chmod 600 /home/monkey/.bash_history

# ----------------------------
# Install Python environment as monkey
# ----------------------------
USER monkey

RUN python3 -m venv /home/monkey/.venv && \
    /home/monkey/.venv/bin/pip install --upgrade pip && \
    /home/monkey/.venv/bin/pip install flask requests flask-cors flask-openapi3 && \
    /home/monkey/.venv/bin/pip install -U "flask-openapi3[swagger]"

# ----------------------------
# Back to root to install start.sh
# ----------------------------
USER root

RUN printf '%s\n' \
    '#!/bin/bash' \
    'set -e' \
    '' \
    '# Start cron (system cron will run shelldon crontab jobs)' \
    'cron' \
    '' \
    '# Start Flask app as monkey' \
    'exec su -s /bin/bash monkey -c "/home/monkey/.venv/bin/python /opt/.app/admin_api.py"' \
    > /usr/local/bin/start.sh && \
    chmod +x /usr/local/bin/start.sh

EXPOSE 9000
WORKDIR /home/monkey

USER monkey

CMD ["/usr/local/bin/start.sh"]

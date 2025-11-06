FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    acl \
    sudo \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash monkey

RUN mkdir -p /opt/.app 
COPY --chown=monkey:monkey . /opt/.app

RUN chmod 711 /opt/.app

RUN chown monkey:monkey /opt/.app/admin_api.py && chmod 711 /opt/.app/admin_api.py

RUN mkdir -p /var/log/ctf_admin /var/ctf_status && \
    chown -R monkey:monkey /var/log/ctf_admin /var/ctf_status && \
    chmod -R 755 /var/log/ctf_admin /var/ctf_status

# add shelldon user and group
RUN useradd -m -s /bin/bash shelldon && \
    mkdir -p /home/shelldon && \
    echo "flag{real_flag_here}" > /home/shelldon/flag.txt && \
    chown shelldon:shelldon /home/shelldon/flag.txt && \
    chmod 440 /home/shelldon/flag.txt && \
    chmod 700 /home/shelldon

# define ctfgroup, add monkey user, chgrp flag
RUN addgroup ctfgroup && \
    adduser monkey ctfgroup && \
    chgrp ctfgroup /home/shelldon/flag.txt && \
    chmod 440 /home/shelldon/flag.txt

# Create hidden directory for escalation script
RUN mkdir -p /home/monkey/.hidden_dir

# Create escalation script owned by shelldon but group monkey, readable/writable by monkey but only executable by shelldon
RUN echo "#!/bin/bash\necho 'Escalation script executed! Running with user:' $(whoami)" > /home/monkey/.hidden_dir/writable_script.sh && \
    chown shelldon:monkey /home/monkey/.hidden_dir/writable_script.sh && \
    chmod 660 /home/monkey/.hidden_dir/writable_script.sh && \
    setfacl -m u:shelldon:x /home/monkey/.hidden_dir/writable_script.sh && \
    setfacl -m u:monkey:rw /home/monkey/.hidden_dir/writable_script.sh && \
    chmod 750 /home/monkey/.hidden_dir

# Remove SUID/GUID bits globally
RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

USER monkey

RUN python3 -m venv /home/monkey/.venv && \
    /home/monkey/.venv/bin/pip install --upgrade pip && \
    /home/monkey/.venv/bin/pip install flask requests flask-cors flask-openapi3 && \
    /home/monkey/.venv/bin/pip install -U "flask-openapi3[swagger]"

EXPOSE 9000

WORKDIR /home/monkey

CMD ["/home/monkey/.venv/bin/python", "/opt/.app/admin_api.py"]

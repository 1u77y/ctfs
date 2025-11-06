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


RUN useradd -m -s /bin/bash ctfuser && \
    mkdir -p /home/ctfuser && \
    echo "flag{real_flag_here}" > /home/ctfuser/flag.txt && \
    chown ctfuser:ctfuser /home/ctfuser/flag.txt && \
    chmod 440 /home/ctfuser/flag.txt && \
    chmod 700 /home/ctfuser


RUN addgroup ctfgroup && \
    adduser monkey ctfgroup && \
    chgrp ctfgroup /home/ctfuser/flag.txt && \
    chmod 440 /home/ctfuser/flag.txt


RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true


USER monkey


RUN python3 -m venv /home/monkey/.venv && \
    /home/monkey/.venv/bin/pip install --upgrade pip && \
    /home/monkey/.venv/bin/pip install flask requests flask-cors flask-openapi3 && \
    /home/monkey/.venv/bin/pip install -U "flask-openapi3[swagger]"


EXPOSE 9000

WORKDIR /home/monkey

CMD ["/home/monkey/.venv/bin/python", "/opt/.app/admin_api.py"]

FROM python:3.12-slim

# Install required system packages, including acl for setfacl
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    acl \
    wget \
    curl \
    vim \
    net-tools \
    sudo \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Create monkey user with home and bash shell
RUN useradd -m -s /bin/bash monkey

# Create working directory in hidden /opt/.app and assign ownership to monkey user
RUN mkdir -p /opt/.app
COPY --chown=monkey:monkey . /opt/.app

# Set directory permissions: no read, only execute permission to prevent listing
RUN chmod 711 /opt/.app

# Ensure admin_api.py is owned by monkey and executable
RUN chown monkey:monkey /opt/.app/admin_api.py && chmod 711 /opt/.app/admin_api.py

# Setup logs directory writable by monkey user (run as root)
RUN mkdir -p /var/log/ctf_admin /var/ctf_status && \
    chown -R monkey:monkey /var/log/ctf_admin /var/ctf_status && \
    chmod -R 755 /var/log/ctf_admin /var/ctf_status

# Switch to monkey user before creating venv and installing dependencies
USER monkey

# Create virtual environment in hidden directory, install dependencies inside venv
RUN python3 -m venv /home/monkey/.venv && \
    /home/monkey/.venv/bin/pip install --upgrade pip && \
    /home/monkey/.venv/bin/pip install flask requests flask-cors flask-openapi3 && \
    /home/monkey/.venv/bin/pip install -U "flask-openapi3[swagger]"

# Expose app port
EXPOSE 9000

# Set final working directory to monkey's home
WORKDIR /home/monkey

# Run the app inside the venv by explicitly calling python from it, pointing to /opt/.app/admin_api.py
CMD ["/home/monkey/.venv/bin/python", "/opt/.app/admin_api.py"]

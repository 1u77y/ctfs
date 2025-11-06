FROM python:3.12-slim

RUN useradd -m -s /bin/bash monkey
WORKDIR /home/monkey/app
COPY . /home/monkey/app

# Install dependencies first
RUN pip install --no-cache-dir flask requests flasgger flasgger[flask] flask-cors flask-openapi3
RUN pip install -U "flask-openapi3[swagger]"


# Now static folder exists, safe to copy
RUN mkdir -p /home/monkey/app/static/flasgger_static
RUN cp -r /usr/local/lib/python3.12/site-packages/flasgger/ui3/static/. /home/monkey/app/static/flasgger_static/

# Setup logs and permissions
RUN mkdir -p /var/log/ctf_admin /var/ctf_status && chown -R monkey:monkey /var/log/ctf_admin /home/monkey/app

EXPOSE 9000
CMD ["python", "admin_api.py"]

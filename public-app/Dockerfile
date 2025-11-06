FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy application files
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir flask requests

# Create log directory and empty feedback log with proper permissions
RUN mkdir -p /var/log/ctf_admin \
    && touch /var/log/ctf_admin/feedback.log \
    && chmod 666 /var/log/ctf_admin/feedback.log

# Expose port
EXPOSE 8080

# Run the application
CMD ["python", "app.py"]


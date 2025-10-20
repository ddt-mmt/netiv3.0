# Use an official lightweight Python image
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN apt-get update && apt-get install -y iputils-ping nmap dnsutils dsniff traceroute golang-go git perl && \
    pip install --no-cache-dir -r requirements.txt && \
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    mv /root/go/bin/nuclei /usr/local/bin/ && \
    nuclei -update-templates && \
    git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    rm -rf /var/lib/apt/lists/*

# 6. Salin kode aplikasi lainnya
# Pastikan Anda menyalin kode aplikasi Flask Anda di sini
COPY app/ app/
COPY run.py .
COPY config.py .
COPY custom_tools.json .
COPY list_models.py .
COPY pentest.py .
COPY project_netV3.0.txt .
COPY TUTORIAL_IDOR.md .
COPY LICENSE .

# Expose the port the app runs on
EXPOSE 5004

# Command to run the application using Gunicorn for production
ENV FLASK_APP app
CMD ["gunicorn", "--bind", "0.0.0.0:5004", "run:app"]

# =======================================================
# STAGE 1: NETIV3_INSTALLER (BUILDER STAGE)
# Stage untuk membangun tools Go (Nuclei) dan menginstal Git/Nikto.
# =======================================================
FROM golang:1.24-bookworm AS netiv3_installer

WORKDIR /usr/src/app

# Set GOPATH and add to PATH
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

# Instal dependensi dasar untuk cloning/building (hanya git)
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# 1. Build dan instal Nuclei & Gitleaks
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest \
    && go install -v github.com/zricethezav/gitleaks/v8@latest

# 2. Clone Nuclei templates directly
RUN mkdir -p /root/.config/nuclei \
    && echo "Force cache invalidation for Nuclei templates: 20251022-1" \
    && git clone https://github.com/projectdiscovery/nuclei-templates.git /root/.config/nuclei/templates

# 3. Clone Nikto
RUN git clone https://github.com/sullo/nikto.git /opt/nikto


# =======================================================
# STAGE 2: FINAL (PRODUCTION STAGE)
# Image production yang kecil berbasis Python.
# =======================================================
FROM python:3.13-slim

WORKDIR /app

# 1. Instal semua tools runtime yang tersisa (Nmap, Perl, dsniff, dll.)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping \
        nmap \
        dnsutils \
        dsniff \
        wget \
        gnupg \
        ca-certificates \
        unzip \
        default-jre \
        git \
    # Install Trivy for vulnerability scanning
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb bookworm main" | tee /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    # Install OWASP ZAP
    && mkdir -p /opt/zap \
    && wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_Linux.tar.gz -O /tmp/ZAP_2.16.1_Linux.tar.gz \
    && tar -xzf /tmp/ZAP_2.16.1_Linux.tar.gz -C /opt/zap --strip-components=1 \
    && rm /tmp/ZAP_2.16.1_Linux.tar.gz \
    # Clean up APT cache to reduce image size
    && rm -rf /var/lib/apt/lists/*

# 2. Instal dependencies Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. Salin binari dan tools dari Stage 1
COPY --from=netiv3_installer /go/bin/nuclei /usr/local/bin/
COPY --from=netiv3_installer /opt/nikto /opt/nikto
RUN ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
COPY --from=netiv3_installer /root/.config/nuclei/templates /root/.config/nuclei/templates/
COPY --from=netiv3_installer /go/bin/gitleaks /usr/local/bin/

# 4. Salin kode aplikasi Flask/Python Anda
COPY . .

# Konfigurasi aplikasi
ENV FLASK_APP=run.py
ENV FLASK_ENV=production

# Port yang digunakan aplikasi
EXPOSE 5004

# Jalankan aplikasi menggunakan Gunicorn
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5004", "--timeout", "120", "--log-level", "debug", "run:app"]

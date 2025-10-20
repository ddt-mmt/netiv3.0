# =======================================================
# STAGE 1: NETIV3_INSTALLER (BUILDER STAGE)
# Stage untuk membangun tools Go (Nuclei) dan menginstal Git/Nikto.
# =======================================================
FROM golang:1.24-bookworm AS netiv3_installer

WORKDIR /usr/src/app

# Instal dependensi dasar untuk cloning/building (hanya git)
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# 1. Build dan instal Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# 2. Update template Nuclei
RUN mkdir -p /root/.config/nuclei && \
    /root/go/bin/nuclei -update-templates

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
        traceroute \
        perl \
        liberror-perl \
    && rm -rf /var/lib/apt/lists/*

# 2. Instal dependencies Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. Salin binari dan tools dari Stage 1
COPY --from=netiv3_installer /root/go/bin/nuclei /usr/local/bin/
COPY --from=netiv3_installer /opt/nikto /opt/nikto
RUN ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
COPY --from=netiv3_installer /root/.config/nuclei/templates /root/.config/nuclei/templates/

# 4. Salin kode aplikasi Flask/Python Anda
COPY . .

# Konfigurasi aplikasi
ENV FLASK_APP=run.py
ENV FLASK_ENV=production

# Port yang digunakan aplikasi
EXPOSE 5004

# Jalankan aplikasi menggunakan Gunicorn
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5004", "run:app"]

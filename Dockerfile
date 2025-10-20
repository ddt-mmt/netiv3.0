# =======================================================
# STAGE 1: NETIV3_INSTALLER (BUILDER STAGE)
# Tujuan: Menginstal Go, Git, dan membangun tools besar seperti Nuclei dan Nikto.
# =======================================================
FROM golang:1.24-bookworm AS netiv3_installer

WORKDIR /usr/src/app

# Instal dependensi dasar untuk cloning/building (hanya git)
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# 1. Build dan instal Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# 2. Update template Nuclei (data ini besar dan akan disimpan di stage ini)
# Template akan disimpan di lokasi default: /root/.config/nuclei/templates
RUN mkdir -p /root/.config/nuclei && \
    /root/go/bin/nuclei -update-templates

# 3. Clone Nikto. Ini adalah sumber masalah "/opt/nikto": not found sebelumnya.
RUN git clone https://github.com/sullo/nikto.git /opt/nikto


# =======================================================
# STAGE 2: FINAL (PRODUCTION STAGE)
# Tujuan: Image kecil berbasis Python yang hanya berisi runtime environment.
# =======================================================
FROM python:3.13-slim

WORKDIR /app

# 1. Instal semua tools runtime yang tersisa (Nmap, Perl, dsniff, dll.)
# Dipecah menjadi satu RUN command yang efisien.
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

# 3. Salin binari dan tools dari Stage 1 (netiv3_installer)
# Urutan ini memastikan file yang di-copy sudah ada di cache layer sebelumnya.
COPY --from=netiv3_installer /root/go/bin/nuclei /usr/local/bin/

# Salin Nikto dan buat symlink
COPY --from=netiv3_installer /opt/nikto /opt/nikto
RUN ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Salin template Nuclei
COPY --from=netiv3_installer /root/.config/nuclei/templates /root/.config/nuclei/templates/

# 4. Salin kode aplikasi Flask/Python Anda
# Ganti dengan struktur folder aplikasi Anda yang sebenarnya
COPY . .

# Konfigurasi aplikasi
ENV FLASK_APP=run.py
ENV FLASK_ENV=production
ENV SECRET_KEY="CHANGEME_SECRET_KEY" # Ganti ini di Portainer!
ENV GEMINI_API_KEY="" # Ganti ini di Portainer!

# Port yang digunakan aplikasi
EXPOSE 5004

# Jalankan aplikasi menggunakan Gunicorn untuk production
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5004", "run:app"]

# =======================================================
# STAGE 2: FINAL
# Image production yang kecil
# =======================================================
FROM python:3.13-slim

WORKDIR /app

# 1. Instal semua tools runtime yang tersisa (Nmap, Perl, dll.)
# Lakukan UPDATE dan INSTALL terpisah untuk meminimalkan kegagalan
RUN apt-get update
RUN apt-get install -y \
    iputils-ping \
    nmap \
    dnsutils \
    dsniff \
    traceroute \
    perl \
    liberror-perl \
    && rm -rf /var/lib/apt/lists/*
    
# 2. Instal dependencies Python
# Dipisahkan untuk debugging yang lebih mudah jika ada masalah pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. Salin binari dan tools dari Stage 1 (Builder)
COPY --from=builder /root/go/bin/nuclei /usr/local/bin/
COPY --from=builder /root/.config/nuclei/templates /root/.config/nuclei/templates/
COPY --from=builder /opt/nikto /opt/nikto
RUN ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# 4. Salin kode aplikasi lainnya
COPY . .

# CMD dan ENV lainnya...

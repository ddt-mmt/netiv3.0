# =======================================================
# STAGE 1: NETIV3_INSTALLER
# Ganti 'builder' menjadi 'netiv3_installer'
# =======================================================
FROM golang:1.24-bookworm AS netiv3_installer 

# ... (Kode build lainnya tetap sama) ...

# =======================================================
# STAGE 2: FINAL
# =======================================================
FROM python:3.13-slim

# ... (Instalasi apt-get, pip install) ...

# 3. Salin binari dan tools dari Stage 1 (netiv3_installer)
COPY --from=netiv3_installer /root/go/bin/nuclei /usr/local/bin/
COPY --from=netiv3_installer /root/.config/nuclei/templates /root/.config/nuclei/templates/
COPY --from=netiv3_installer /opt/nikto /opt/nikto

# ... (Sisa kode tetap sama) ...

# Neti V3.0 Beta

Neti is a Flask-based network analysis and security testing framework.

---

## New Features (v3.1)

- **AI Model Selection**: Support for Gemini models (1.5 Pro, 1.5 Flash, 3.1 Flash Lite) across all analysis modules.
- **Professional AI Reporting**: Improved report formatting with structured layouts and overall risk assessment indicators.
- **Exploit Module Enhancement**: AI-driven analysis for Metasploit exploit modules.

---

## Recent Changes (October 2025 Update)

This update focuses on improving user experience, consolidating features, and enhancing AI integration:

### 1. Git Patch & Automated Pull Requests
*   **Automated Repository Analysis**: Users can now enter a Git repository URL to perform an automated security analysis using Semgrep and Google's Gemini AI.
*   **Enhanced Interactive Fix Simulation**: Comprehensive simulation applies proposed fixes to a temporary clone, re-scans the code, and provides a clear summary diff of changes.
*   **Patch Generation & Pull Requests**: Generate `.patch` files or automatically open pull requests (if GitHub-authenticated).

### 2. UI/UX Enhancements
*   **Informative Findings**: Finding titles now display file path and line number (`file:line`).
*   **Vulnerability Descriptions**: AI-generated descriptions and suggested fixes for findings.
*   **Consistent Theming**: Added missing icons to dashboard cards.

### 3. Security, Performance & Bug Fixes
*   **Security Hardening (SAST)**: Addressed issues including TLS verification, session cookies, Docker permissions, and XSS vectors.
*   **Bug Fix**: Corrected JSON syntax errors in `translations.json`.
*   **Scanning Improvements**: Added duration warnings for long scans, custom Nmap scan support, and asynchronous task refactoring for non-blocking UI.
*   **Consolidated Scanners**: Merged Web/Domain analysis and Code/App scanners into unified, tabbed interfaces.

---

## Deployment (Recommended: Docker)

Using Docker is the recommended method for deploying netiV3.

### Prerequisites
- Docker Engine installed and running.

### Steps
1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPOSITORY_NAME.git
   cd YOUR_REPOSITORY_NAME/netiV3
   ```
2. **Build the Docker Image:**
   ```bash
   docker build -t netiv3 .
   ```
3. **Run the Docker Container:**
   ```bash
   docker run -d -p 5005:5005 --name netiv3-prod --restart unless-stopped netiv3
   ```
   *The application will be available at `http://localhost:5005`.*

**Metasploit RPC Daemon (Required for Exploit functionality):**
```bash
msfrpcd -P netiv3pass -p 55553 -n -a 0.0.0.0
```

---

## Legacy Installation (Manual Setup)

*Note: Docker is recommended.*

1. **Clone and setup virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r netiV3/requirements.txt
   ```
2. **Run:**
   ```bash
   gunicorn --workers 4 --bind 0.0.0.0:5005 "app:create_app()"
   ```

---

## Core Technologies
- **Backend**: Python, Flask, Gunicorn.
- **AI**: Google Gemini (gemini-pro-latest, gemini-1.5-flash).
- **Scanning Tools**: Nmap, Nikto, Sublist3r, Nuclei, OWASP ZAP, Metasploit, dsniff, dig.
- **Frontend**: HTML/CSS/JS, jQuery, Bootstrap.

---

## Troubleshooting & Hardware
- **Logs**: `docker logs netiv3-prod -f`
- **Requirements**: Minimum 2 Cores, 4GB RAM, 20GB Disk Space. Recommended 4+ Cores, 8GB RAM.
- **JSON Errors**: Check `app/static/translations.json` for syntax errors.

---

## Security Roadmap
- Implement Read-Only Root Filesystem.
- Add Subresource Integrity (SRI) for CDN assets.

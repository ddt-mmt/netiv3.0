# netiV3 - AI-Powered Network Analysis Tool

## Recent Changes (October 2025 Update)

This update focuses on improving user experience, consolidating features, and enhancing AI integration:

*   **New Feature: Git Patch & Automated Pull Requests**:
    *   **Automated Repository Analysis**: Users can now enter a Git repository URL to perform an automated security analysis using Semgrep and Google's Gemini AI.
    *   **Interactive Fix Simulation**: Instead of a simple popup, the application now directs users to a dedicated simulation page that displays a clear, side-by-side diff of the proposed fixes.
    *   **Patch Generation & Pull Requests**: Users can download the generated fixes as a `.patch` file or, if authenticated with GitHub, automatically create a new branch and open a pull request with the suggested changes.
*   **UI/UX Enhancements**:
    *   **Informative Findings**: Finding titles in the Git Patch feature now clearly display the file path and line number (`file:line`) for quick identification.
    *   **Vulnerability Descriptions**: Each finding is now accompanied by a brief, AI-generated description of the vulnerability.
    *   **Consistent Theming**: Added missing icons to the "Git Patch" and "Git Analysis" cards on the main dashboard for a more uniform look.
*   **Security Hardening (SAST):** Addressed multiple vulnerabilities found by a Semgrep scan, including fixing disabled TLS verification, securing session cookies, hardening Docker container permissions, and mitigating potential XSS vectors.
*   **Bug Fix:** Corrected multiple JSON syntax errors in the `translations.json` file that caused application startup failure.
*   **Feature:** Added duration warnings for long-running scans (Nmap, ZAP, Subdomain Enumeration) to help users make informed decisions before starting them.
*   **Custom Nmap Scans**: Users can now define their own Nmap scans with custom ports and arguments, allowing for more flexible and targeted scanning.
*   **Feature Consolidation:** Merged 'Web Analysis' and 'Domain/Subdomain Target' into a single 'Web & Domain Analysis' page and a single card on the main dashboard for better efficiency.
*   **Enhanced AI Integration:** Fully integrated AI analysis across all relevant pages, including 'Network Device Analyzer' and 'Email Target', ensuring comprehensive AI-powered insights.
*   **Improved User Experience:** Added descriptive placeholder examples to various input fields (e.g., IP, Domain, URL) to guide users on expected input formats.
*   **Translation Fixes:** Corrected missing English title for the 'Log Analyzer' card on the main dashboard.
*   **Robust Language Switching:** Implemented a more reliable AJAX-based mechanism for language switching to ensure translations update consistently.
*   **Full Asynchronous Refactor**: All scanning, analysis, and exploitation tasks have been refactored to run as asynchronous, cancellable background jobs. This provides a non-blocking, responsive user experience across the entire application.
*   **Exploit Execution**: Implemented the core functionality to search, configure, and execute Metasploit exploits directly from the web interface.
*   **Consolidated Code & App Scanners**: Gitleaks, Semgrep, OWASP ZAP, and Trivy (SCA, Image, IaC) tools have been consolidated into a single, tabbed interface under 'Code & App Scanners'. All these scans now run asynchronously with real-time status updates, cancellation support, and integrated AI analysis.
*   **Dockerization**: The application is now fully containerized with Docker, providing a consistent and portable production-ready deployment.
*   **Dockerfile Improvements**: Updated OWASP ZAP to v2.16.1, refined Nuclei template installation to direct Git clone, and explicitly set `GOPATH` and `PATH` in the Dockerfile for more robust Go tool builds.

## Deployment (Recommended: Docker)

Using Docker is the recommended method for deploying netiV3. It ensures a consistent environment and simplifies setup.

**Prerequisites:**
*   Docker Engine installed and running.

**Steps:** 

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPOSITORY_NAME.git
    cd YOUR_REPOSITORY_NAME/netiV3
    ```

2.  **Build the Docker Image:**
    This command reads the `Dockerfile` and builds a container image named `netiv3`.
    ```bash
    docker build -t netiv3 .
    ```

3.  **Run the Docker Container:**
    This will run the application in a container, expose it on port 5005, and ensure it restarts automatically.
    ```bash
    docker run -d -p 5005:5005 --name netiv3-prod --restart unless-stopped netiv3
    ```
    The application will be available at `http://localhost:5005`.

4.  **Metasploit RPC Daemon (Required for Exploit functionality)**:
    The application still requires a running `msfrpcd` instance to connect to. Ensure this is running on a network accessible to the Docker container.
    ```bash
    # Example command to start the daemon
    msfrpcd -P netiv3pass -p 55553 -n -a 0.0.0.0
    ```
    *(Note the addition of `-a 0.0.0.0` to allow connections from the Docker container).*


## Legacy Installation (Manual Setup)

> **Note:** This method is for development or environments where Docker is not available. The Docker deployment is recommended for consistency and ease of use.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPOSITORY_NAME.git
    cd YOUR_REPOSITORY_NAME
    ```

2.  **Create and Activate a Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r netiV3/requirements.txt
    ```

4.  **Set Environment Variables:**
    ```bash
    export SECRET_KEY="your_secret_key_here"
    export GEMINI_API_KEY="your_gemini_api_key_here" # Optional, for AI analysis
    ```

5.  **Run the Application:**
    ```bash
    gunicorn --workers 4 --bind 0.0.0.0:5005 "app:create_app()"
    ```

## Core Features

*   **Network Scanning**: Perform various network scans like Ping, Traceroute, NSLookup, and Nmap scans (including custom scans).
*   **Web & Domain Analysis**: Enumerate subdomains, analyze email security, and crawl websites for endpoints.
*   **Vulnerability Scanning**: Run Nikto scans, XXE scans, and Nuclei scans against web targets.
*   **Git Patch & Automated PRs**: Automatically analyze Git repositories for vulnerabilities, simulate fixes, and generate patches or create pull requests.
*   **Code & Application Security Scanners**: Consolidated interface for Gitleaks (secret detection), Semgrep (SAST), OWASP ZAP (DAST), and Trivy (SCA, Image, IaC) with asynchronous execution and AI analysis.
*   **IDOR Testing**: A dedicated interface to test for Insecure Direct Object Reference vulnerabilities.
*   **Metasploit Integration**: Search for Metasploit modules, view module details, and execute exploits.
*   **AI-Powered Analysis**: Analyze scan results and generate reports using Google Gemini.
*   **AI Payload Generation**: Generate security payloads with the help of Google Gemini.
*   **Asynchronous Tasks**: All scans and long-running tasks are executed asynchronously in the background.

## Core Technologies & Tools

This project is built with a variety of powerful open-source tools and technologies.

### Backend & Framework
*   **Python**: The core language for the backend logic.
*   **Flask**: A lightweight web framework for Python.
*   **Gunicorn**: A robust WSGI HTTP server for running the Flask application in production.

### AI Integration
*   **Google Gemini**: The project leverages the `gemini-pro-latest` model via the `google-generativeai` Python library for:
    *   **AI-Powered Analysis**: Analyzing raw scan results to generate comprehensive security reports.
    *   **Security Payload Generation**: Assisting pentesters by generating payloads based on vulnerability descriptions.

### Scanning & Pentesting Tools
The application integrates a suite of well-known security tools to perform its analysis:
*   **Nmap**: For network discovery and security auditing.
*   **Nikto**: A web server scanner which performs comprehensive tests against web servers for multiple items.
*   **Sublist3r**: For enumerating subdomains of websites.
*   **Nuclei**: A fast and customizable vulnerability scanner.
*   **OWASP ZAP**: Dynamic Application Security Testing (DAST) tool (v2.16.1).
*   **Metasploit**: For exploit searching and execution.
*   **dsniff (arpspoof, dnsspoof)**: For DNS spoofing exercises.
*   **dnsutils (dig)**: For DNS queries.

### Frontend
*   **HTML/CSS/JavaScript**: The standard trio for the web interface.
*   **jQuery & Bootstrap**: For responsive design and simplified DOM manipulation.

### Containerization
*   **Docker**: The application is fully containerized, ensuring a consistent and portable deployment environment.

## Hardware Recommendations

To ensure optimal performance and successful builds/deployments of netiV3, consider the following hardware specifications. These recommendations apply whether deploying via Docker, in a Virtual Machine (VM), or on a physical server.

### Minimum Requirements

*   **CPU:** 2 Cores
*   **RAM:** 4 GB (especially important during Docker builds and when running multiple scanning tools)
*   **Disk Space:** 20 GB (minimum, with at least 10 GB free for Docker build cache and Nuclei templates. Docker builds, especially with Go tools and large template updates, can consume significant temporary disk space.)

### Recommended Specifications

*   **CPU:** 4 Cores or more
*   **RAM:** 8 GB or more
*   **Disk Space:** 50 GB or more (for long-term use, logs, and additional tools/data)

**Note on Disk Space for Docker Builds:**
Docker builds, particularly those involving Go compilers and large template downloads (like Nuclei templates), can temporarily consume substantial disk space. If you encounter "No space left on device" errors during a Docker build, consider running `docker system prune -a` to clear unused Docker objects (images, containers, volumes, and build cache) before retrying the build.

## Troubleshooting

*   **Docker Logs**: To see the application logs when running with Docker, use the command: `docker logs netiv3-prod -f`
*   **Application Startup Timeout**: If the application fails to load in the browser or Gunicorn workers timeout during startup, consider increasing the Gunicorn `--timeout` value in the Dockerfile's `CMD` instruction (e.g., `--timeout 120`). This might be necessary for environments with slower I/O or during initial template/dependency loading.
*   **Port Configuration**: The application's listening port is configured in the `Dockerfile`. If you change the port mapping in the `docker run` command, ensure you also update the `EXPOSE` and `CMD` instructions in the `Dockerfile` to match.
*   **JSON Errors**: If you see `json.decoder.JSONDecodeError` in the logs, check the JSON files for syntax errors. We found and fixed errors in `app/static/translations.json`.

## Copyright and License
(Content unchanged)

## Security Roadmap

The following are planned security improvements that have been identified but not yet implemented:

*   **Implement Read-Only Root Filesystem:** The application container's root filesystem is currently writable. To improve security, it should be set to `read_only: true`. This requires modifying the application to write temporary files (like scan results) to a dedicated `tmpfs` volume instead of the regular filesystem.
*   **Add Subresource Integrity (SRI):** All external JavaScript resources loaded from CDNs should have an `integrity` attribute. This requires calculating and adding the correct cryptographic hash for each external resource to prevent loading of compromised files.

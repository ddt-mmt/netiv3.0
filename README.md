# netiV3 - AI-Powered Network Analysis Tool

## Recent Changes (October 2025 Update)

This update focuses on improving user experience, consolidating features, and enhancing AI integration:

*   **Custom Nmap Scans**: Users can now define their own Nmap scans with custom ports and arguments, allowing for more flexible and targeted scanning.
*   **Feature Consolidation:** Merged 'Web Analysis' and 'Domain/Subdomain Target' into a single 'Web & Domain Analysis' page and a single card on the main dashboard for better efficiency.
*   **Enhanced AI Integration:** Fully integrated AI analysis across all relevant pages, including 'Network Device Analyzer' and 'Email Target', ensuring comprehensive AI-powered insights.
*   **Improved User Experience:** Added descriptive placeholder examples to various input fields (e.g., IP, Domain, URL) to guide users on expected input formats.
*   **Translation Fixes:** Corrected missing English title for the 'Log Analyzer' card on the main dashboard.
*   **Robust Language Switching:** Implemented a more reliable AJAX-based mechanism for language switching to ensure translations update consistently.
*   **Full Asynchronous Refactor**: All scanning, analysis, and exploitation tasks have been refactored to run as asynchronous, cancellable background jobs. This provides a non-blocking, responsive user experience across the entire application.
*   **Exploit Execution**: Implemented the core functionality to search, configure, and execute Metasploit exploits directly from the web interface.
*   **Dockerization**: The application is now fully containerized with Docker, providing a consistent and portable production-ready deployment.

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
    This will run the application in a container, expose it on port 5004, and ensure it restarts automatically.
    ```bash
    docker run -d -p 5004:5004 --name netiv3-prod --restart unless-stopped netiv3
    ```
    The application will be available at `http://localhost:5004`.

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
    gunicorn --workers 4 --bind 0.0.0.0:5004 "app:create_app()"
    ```

## Core Features

*   **Network Scanning**: Perform various network scans like Ping, Traceroute, NSLookup, and Nmap scans (including custom scans).
*   **Web & Domain Analysis**: Enumerate subdomains, analyze email security, and crawl websites for endpoints.
*   **Vulnerability Scanning**: Run Nikto scans, XXE scans, and Nuclei scans against web targets.
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
*   **Metasploit**: For exploit searching and execution.
*   **dsniff (arpspoof, dnsspoof)**: For DNS spoofing exercises.
*   **dnsutils (dig)**: For DNS queries.

### Frontend
*   **HTML/CSS/JavaScript**: The standard trio for the web interface.
*   **jQuery & Bootstrap**: For responsive design and simplified DOM manipulation.

### Containerization
*   **Docker**: The application is fully containerized, ensuring a consistent and portable deployment environment.

## Troubleshooting

*   **Docker Logs**: To see the application logs when running with Docker, use the command: `docker logs netiv3-prod -f`
*   **JSON Errors**: If you see `json.decoder.JSONDecodeError` in the logs, check the JSON files for syntax errors. We found and fixed errors in `/usr/lib/gemini-cli/netiv3/netiV3/app/static/translations.json`.

## Copyright and License
(Content unchanged)
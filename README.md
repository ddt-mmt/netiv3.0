# netiV3 - AI-Powered Network Analysis Tool

## Recent Changes (October 2025 Update)

This update focuses on improving user experience, consolidating features, and enhancing AI integration:

*   **Feature Consolidation:** Merged 'Web Analysis' and 'Domain/Subdomain Target' into a single 'Web & Domain Analysis' page and a single card on the main dashboard for better efficiency.
*   **Enhanced AI Integration:** Fully integrated AI analysis across all relevant pages, including 'Network Device Analyzer' and 'Email Target', ensuring comprehensive AI-powered insights.
*   **Improved User Experience:** Added descriptive placeholder examples to various input fields (e.g., IP, Domain, URL) to guide users on expected input formats.
*   **Translation Fixes:** Corrected missing English title for the 'Log Analyzer' card on the main dashboard.
*   **Robust Language Switching:** Implemented a more reliable AJAX-based mechanism for language switching to ensure translations update consistently.
*   **Full Asynchronous Refactor**: All scanning, analysis, and exploitation tasks have been refactored to run as asynchronous, cancellable background jobs. This provides a non-blocking, responsive user experience across the entire application.
*   **Exploit Execution**: Implemented the core functionality to search, configure, and execute Metasploit exploits directly from the web interface.

## Installation

To set up and run the netiV3 application, follow these steps:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPOSITORY_NAME.git
    cd YOUR_REPOSITORY_NAME
    ```
    (Replace `YOUR_GITHUB_USERNAME` and `YOUR_REPOSITORY_NAME` with your actual GitHub details.)

2.  **Create a Python Virtual Environment:**
    It's recommended to use a virtual environment to manage dependencies.
    ```bash
    python3 -m venv venv
    ```

3.  **Activate the Virtual Environment:**
    ```bash
    source venv/bin/activate
    ```

4.  **Install Dependencies:**
    Install all required Python packages.
    ```bash
    pip install -r netiV3/requirements.txt
    ```

5.  **Set Environment Variables:**
    The application requires a `SECRET_KEY` and optionally a `GEMINI_API_KEY`.
    ```bash
    export SECRET_KEY="your_secret_key_here"
    export GEMINI_API_KEY="your_gemini_api_key_here" # Optional, for AI analysis
    ```
    (Replace `"your_secret_key_here"` and `"your_gemini_api_key_here"` with your actual keys.)

6.  **Run the Application:**
    ```bash
    gunicorn -w 4 run:app -b 0.0.0.0:5004
    ```
    The application should now be running on `http://0.0.0.0:5004`.

7.  **Metasploit RPC Daemon (for Exploit functionality)**:
    For the Exploit page to function, you must have the Metasploit Framework installed and the RPC daemon (`msfrpcd`) running. The application is configured to connect to this daemon to search and run modules.
    ```bash
    # Example command to start the daemon
    msfrpcd -P netiv3pass -p 55553 -n
    ```

## Core Features

netiV3 provides a suite of tools for network analysis and penetration testing, all enhanced with AI-powered analysis.

### Network Analysis
- Perform basic network diagnostics like Ping, Traceroute, and NSLookup.
- Run various Nmap scans (Quick, Intense, UDP, Vulnerability) against a target.

### Web & Domain Analysis
- **Nikto Scanner**: Run Nikto scans against a web server to find potential vulnerabilities.
- **XXE Scanner**: Test for basic XXE vulnerabilities.
- **Subdomain Enumeration**: Discover subdomains for a given domain using Sublist3r.
- **DNS Zone Transfer**: Attempt a DNS zone transfer to enumerate all DNS records for a domain.

### Email Target Analysis
- **Basic Analysis**: Validate email format and check for domain and MX records.
- **Header Analysis**: Paste raw email headers to trace the delivery path and analyze authentication results (SPF, DKIM, DMARC).
- **Mail Server Port Scan**: Scan common email-related ports on a mail server.
- **Authentication Record Lookup**: Look up SPF and DMARC records for a domain.

### Network Device Target
- Connect to network devices (MikroTik RouterOS, Cisco IOS) via SSH.
- Fetch the running configuration for offline analysis.
- The fetched configuration can be sent to the AI for a security and best-practices review.

### Log Analyzer
- Paste raw log content (e.g., from syslog, auth.log, web server logs).
- The entire log content is sent to the Gemini AI for a comprehensive analysis to identify anomalies, security events, or errors.

### Exploit Framework
- **Connects to Metasploit RPC**: Integrates with a running msfrpcd instance.
- **Search Modules**: Search for Metasploit exploit and auxiliary modules.
- **View Module Details**: View detailed information about a module, including its options and compatible payloads.
- **Execute Exploits**: Configure module options (like RHOSTS, LHOST, and PAYLOAD) and execute the exploit asynchronously, with results and new sessions reported back.


## Available Gemini Models
The following is a list of models available for the Gemini API. The recommended model for general use is `gemini-pro-latest`.

- models/gemini-2.5-pro-preview-03-25
- models/gemini-2.5-flash-preview-05-20
- models/gemini-2.5-flash
- models/gemini-2.5-flash-lite-preview-06-17
- models/gemini-2.5-pro-preview-05-06
- models/gemini-2.5-pro-preview-06-05
- models/gemini-2.5-pro
- models/gemini-2.0-flash-exp
- models/gemini-2.0-flash
- models/gemini-2.0-flash-001
- models/gemini-2.0-flash-exp-image-generation
- models/gemini-2.0-flash-lite-001
- models/gemini-2.0-flash-lite
- models/gemini-2.0-flash-preview-image-generation
- models/gemini-2.0-flash-lite-preview-02-05
- models/gemini-2.0-flash-lite-preview
- models/gemini-2.0-pro-exp
- models/gemini-2.0-pro-exp-02-05
- models/gemini-exp-1206
- models/gemini-2.0-flash-thinking-exp-01-21
- models/gemini-2.0-flash-thinking-exp
- models/gemini-2.0-flash-thinking-exp-1219
- models/gemini-2.5-flash-preview-tts
- models/gemini-2.5-pro-preview-tts
- models/learnlm-2.0-flash-experimental
- models/gemma-3-1b-it
- models/gemma-3-4b-it
- models/gemma-3-12b-it
- models/gemma-3-27b-it
- models/gemma-3n-e4b-it
- models/gemma-3n-e2b-it
- models/gemini-flash-latest
- models/gemini-flash-lite-latest
- models/gemini-pro-latest
- models/gemini-2.5-flash-lite
- models/gemini-2.5-flash-image-preview
- models/gemini-2.5-flash-image
- models/gemini-2.5-flash-preview-09-2025
- models/gemini-2.5-flash-lite-preview-09-2025
- models/gemini-robotics-er-1.5-preview

## Usage

(Further usage instructions can be added here later.)

## Troubleshooting

If you encounter an `Address already in use` error on port 5004 when starting the service, it is likely due to conflicting services.

1.  **Identify Conflicting Services**: Run `systemctl list-units --type=service | grep -E 'gunicorn|neti'` to check for other running services related to `neti`. In our case, we found `netiv3` and `neti_beta_02` were running and causing conflicts.

2.  **Stop and Disable Conflicting Services**: Stop and disable any unwanted services.
    ```bash
    sudo systemctl stop netiv3 neti_beta_02
    sudo systemctl disable netiv3 neti_beta_02
    ```

3.  **JSON Errors**: If you see `json.decoder.JSONDecodeError` in the logs, check the JSON files for syntax errors. We found and fixed errors in `/usr/lib/gemini-cli/netiv3/netiV3/app/static/translations.json`.

4.  **Final Configuration**: The application is confirmed to be working with the following configuration in `/etc/systemd/system/netiV3.service`:
    ```ini
    [Unit]
    Description=Neti V3 Flask Application
    After=network.target

    [Service]
    User=root
    Group=root
    WorkingDirectory=/usr/lib/gemini-cli/netiv3/netiV3
    ExecStart=/usr/lib/gemini-cli/netiv3/netiV3/venv/bin/gunicorn --workers 1 --bind 0.0.0.0:5004 run:app
    Restart=always

    [Install]
    WantedBy=multi-user.target
    ```

## Restore from Backup

To restore the application from a backup file (e.g., `backup-2025-10-05.tar.gz`):

1.  **Stop the service**:
    ```bash
    sudo systemctl stop netiV3
    ```

2.  **Extract the backup**:
    ```bash
    tar -xzvf /path/to/your/backup/backup-2025-10-05.tar.gz -C /
    ```

3.  **Reload the daemon and restart the service**:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl start netiV3
    ```

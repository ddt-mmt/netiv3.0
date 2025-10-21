import subprocess
import json
import os
import shlex
import time
from app.logic import create_task, tasks

def _run_gitleaks_scan_worker(task_id, repo_url):
    """
    Worker function to execute Gitleaks scan on the specified repository URL.
    Clones the repository to a temporary directory, runs gitleaks, and then cleans up.
    """
    temp_dir = None
    try:
        task = tasks[task_id]
        task['status'] = 'running'
        task['result'] = {'stdout': '', 'stderr': ''} # Initialize results

        # Create a temporary directory for cloning the repository
        temp_dir = f"/tmp/gitleaks_repo_{os.urandom(8).hex()}"
        os.makedirs(temp_dir)
        task['result']['stdout'] += f"Cloning repository to {temp_dir}...\n"

        # Clone the repository
        clone_command = ["git", "clone", "--depth", "1", shlex.quote(repo_url), temp_dir]
        clone_process = subprocess.run(clone_command, check=False, capture_output=True, text=True)
        
        if task['status'] == 'cancelled':
            task['result']['stderr'] += "Task cancelled during cloning.\n"
            return

        if clone_process.returncode != 0:
            task['status'] = 'error'
            task['result']['stderr'] += f"Git clone failed: {clone_process.stderr}\n"
            return
        task['result']['stdout'] += f"Repository cloned successfully.\n"

        # Run Gitleaks
        gitleaks_command = ["gitleaks", "detect", "--source", temp_dir, "--report-format", "json"]
        task['result']['stdout'] += "Running Gitleaks scan...\n"
        gitleaks_process = subprocess.run(gitleaks_command, check=False, capture_output=True, text=True)

        if task['status'] == 'cancelled':
            task['result']['stderr'] += "Task cancelled during Gitleaks scan.\n"
            return

        task['result']['stdout'] += gitleaks_process.stdout
        task['result']['stderr'] += gitleaks_process.stderr

        if gitleaks_process.returncode == 0:
            task['status'] = 'completed'
            task['result']['stdout'] += "Gitleaks scan completed: No leaks found.\n"
        elif gitleaks_process.returncode == 1:
            task['status'] = 'completed' # Leaks found is a successful scan, just with findings
            task['result']['stdout'] += "Gitleaks scan completed: Leaks found!\n"
            task['result']['leaks_found'] = True
        else:
            task['status'] = 'error'
            task['result']['stderr'] += f"Gitleaks scan failed with exit code {gitleaks_process.returncode}.\n"

    except Exception as e:
        if task_id in tasks:
            task['status'] = 'error'
            task['result']['stderr'] += f"An unexpected error occurred: {str(e)}\n"
    finally:
        # Clean up the temporary directory
        if temp_dir and os.path.exists(temp_dir):
            task['result']['stdout'] += f"Cleaning up temporary directory {temp_dir}...\n"
            subprocess.run(["rm", "-rf", temp_dir], check=False, capture_output=True)
        if task_id in tasks:
            task['end_time'] = time.time()

def run_gitleaks_scan(repo_url):
    """Starts a background Gitleaks scan task."""
    return create_task(_run_gitleaks_scan_worker, repo_url)
import subprocess
import json
import os
import tempfile
import shutil
import shlex
import time
from app.logic import create_task, tasks

def _run_semgrep_scan_worker(task_id, target_path: str, config_url: str = "auto"):
    """
    Worker function to execute Semgrep scan.
    """
    temp_dir = None
    semgrep_results_file = None
    try:
        task = tasks[task_id]
        task['status'] = 'running'
        task['result'] = {'stdout': '', 'stderr': ''}

        scan_path = target_path
        # If target_path is a Git URL, clone it first
        if target_path.startswith("http") or target_path.startswith("git@"):
            temp_dir = tempfile.mkdtemp()
            repo_name = target_path.split('/')[-1].replace('.git', '')
            scan_path = os.path.join(temp_dir, repo_name)
            task['result']['stdout'] += f"Cloning {target_path} into {scan_path}...\n"
            
            clone_command = ['git', 'clone', shlex.quote(target_path), shlex.quote(scan_path)]
            clone_process = subprocess.run(clone_command, check=False, capture_output=True, text=True)

            if task['status'] == 'cancelled':
                task['result']['stderr'] += "Task cancelled during cloning.\n"
                return

            if clone_process.returncode != 0:
                task['status'] = 'error'
                task['result']['stderr'] += f"Git clone failed: {clone_process.stderr}\n"
                return
            task['result']['stdout'] += "Repository cloned successfully.\n"

        # Ensure Semgrep is available in the PATH
        semgrep_path = os.environ.get("SEMGREP_PATH", "semgrep")

        # Command to run Semgrep with JSON output
        semgrep_results_file = f"semgrep_results_{task_id}.json" # Unique filename
        command = [
            semgrep_path,
            '--json',
            '--output', semgrep_results_file,
            '--config', shlex.quote(config_url),
            shlex.quote(scan_path)
        ]

        task['result']['stdout'] += f"Running Semgrep command: {' '.join(command)}\n"
        semgrep_process = subprocess.run(command, capture_output=True, text=True, check=False) # check=False because semgrep exits with 1 on findings
        
        if task['status'] == 'cancelled':
            task['result']['stderr'] += "Task cancelled during Semgrep scan.\n"
            return

        task['result']['stdout'] += f"Semgrep stdout: {semgrep_process.stdout}\n"
        task['result']['stderr'] += f"Semgrep stderr: {semgrep_process.stderr}\n"

        results = []
        if os.path.exists(semgrep_results_file):
            try:
                with open(semgrep_results_file, 'r') as f:
                    semgrep_output = json.load(f)
                    results = semgrep_output.get("results", [])
                task['result']['stdout'] += f"Semgrep findings: {json.dumps(results, indent=2)}\n"
            except json.JSONDecodeError:
                task['status'] = 'error'
                task['result']['stderr'] += f"Failed to parse Semgrep JSON output from {semgrep_results_file}.\n"
        else:
            task['status'] = 'error'
            task['result']['stderr'] += f"Semgrep results file {semgrep_results_file} not found.\n"

        if semgrep_process.returncode == 0 or semgrep_process.returncode == 1: # 0 for no findings, 1 for findings
            task['status'] = 'completed'
            task['result']['semgrep_results'] = results # Store parsed results separately
        else:
            task['status'] = 'error'
            task['result']['stderr'] += f"Semgrep command failed with exit code {semgrep_process.returncode}.\n"

    except Exception as e:
        if task_id in tasks:
            task['status'] = 'error'
            task['result']['stderr'] += f"An unexpected error occurred: {str(e)}\n"
    finally:
        if semgrep_results_file and os.path.exists(semgrep_results_file):
            os.remove(semgrep_results_file)
        if temp_dir and os.path.exists(temp_dir):
            task['result']['stdout'] += f"Cleaning up temporary directory: {temp_dir}\n"
            shutil.rmtree(temp_dir)
        if task_id in tasks:
            task['end_time'] = time.time()

def run_semgrep_scan(target_path: str, config_url: str = "auto") -> str:
    """Starts a background Semgrep scan task."""
    return create_task(_run_semgrep_scan_worker, target_path, config_url)

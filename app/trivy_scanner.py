import subprocess
import json
import os
import shlex
import time
from app.logic import create_task, tasks, run_command_worker

def _run_trivy_sca_worker(task_id, target_path: str):
    """
    Worker function to run Trivy SCA scan.
    """
    try:
        task = tasks[task_id]
        task['status'] = 'running'
        task['result'] = {'stdout': '', 'stderr': ''}

        trivy_path = os.environ.get("TRIVY_PATH", "trivy")

        command = [
            trivy_path,
            "fs",
            "--format", "json",
            "--severity", "HIGH,CRITICAL",
            shlex.quote(target_path)
        ]

        task['result']['stdout'] += f"Running Trivy SCA command: {' '.join(command)}\n"
        
        # Use run_command_worker to execute the command
        run_command_worker(task_id, command)

        if task['status'] == 'cancelled':
            task['result']['stderr'] += "Task cancelled during Trivy SCA scan.\n"
            return

        # After the command worker is done, process the stdout
        if task['status'] == 'completed':
            output = task['result']['stdout']
            try:
                results = json.loads(output)
                vulnerabilities = []
                if results and "Results" in results:
                    for result in results["Results"]:
                        if "Vulnerabilities" in result:
                            for vuln in result["Vulnerabilities"]:
                                vulnerabilities.append({
                                    "VulnerabilityID": vuln.get("VulnerabilityID"),
                                    "PkgName": vuln.get("PkgName"),
                                    "InstalledVersion": vuln.get("InstalledVersion"),
                                    "FixedVersion": vuln.get("FixedVersion"),
                                    "Severity": vuln.get("Severity"),
                                    "Description": vuln.get("Description"),
                                    "References": vuln.get("References", [])
                                })
                task['result']['trivy_sca_results'] = vulnerabilities # Store parsed results separately
                task['result']['stdout'] = json.dumps(vulnerabilities, indent=2) # Update stdout to be parsed results
            except json.JSONDecodeError:
                task['status'] = 'error'
                task['result']['stderr'] += 'Failed to parse Trivy JSON output.\n'
        elif task['status'] == 'error':
            task['result']['stderr'] += f"Trivy command failed. Check Trivy output in stderr.\n"

    except Exception as e:
        if task_id in tasks:
            task['status'] = 'error'
            task['result']['stderr'] += f"An unexpected error occurred: {str(e)}\n"
    finally:
        if task_id in tasks:
            task['end_time'] = time.time()

def run_trivy_sca(target_path: str) -> str:
    """Starts a background Trivy SCA scan task."""
    return create_task(_run_trivy_sca_worker, target_path)
import subprocess
import json
import os
import shlex
import time
from app.logic import create_task, tasks, run_command_worker

def _run_trivy_image_scan_worker(task_id, image_name: str):
    """
    Worker function to run Trivy Image scan.
    """
    try:
        task = tasks[task_id]
        task['status'] = 'running'
        task['result'] = {'stdout': '', 'stderr': ''}

        trivy_path = os.environ.get("TRIVY_PATH", "trivy")

        command = [
            trivy_path,
            "image",
            "--format", "json",
            "--severity", "HIGH,CRITICAL",
            shlex.quote(image_name)
        ]

        task['result']['stdout'] += f"Running Trivy Image scan command: {' '.join(command)}\n"
        
        run_command_worker(task_id, command)

        if task['status'] == 'cancelled':
            task['result']['stderr'] += "Task cancelled during Trivy Image scan.\n"
            return

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
                task['result']['trivy_image_results'] = vulnerabilities
                task['result']['stdout'] = json.dumps(vulnerabilities, indent=2)
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

def run_trivy_image_scan(image_name: str) -> str:
    """Starts a background Trivy Image scan task."""
    return create_task(_run_trivy_image_scan_worker, image_name)

def _run_trivy_iac_scan_worker(task_id, target_path: str):
    """
    Worker function to run Trivy IaC scan.
    """
    try:
        task = tasks[task_id]
        task['status'] = 'running'
        task['result'] = {'stdout': '', 'stderr': ''}

        trivy_path = os.environ.get("TRIVY_PATH", "trivy")

        command = [
            trivy_path,
            "config", # For IaC scanning
            "--format", "json",
            "--severity", "HIGH,CRITICAL",
            shlex.quote(target_path)
        ]

        task['result']['stdout'] += f"Running Trivy IaC scan command: {' '.join(command)}\n"
        
        run_command_worker(task_id, command)

        if task['status'] == 'cancelled':
            task['result']['stderr'] += "Task cancelled during Trivy IaC scan.\n"
            return

        if task['status'] == 'completed':
            output = task['result']['stdout']
            try:
                results = json.loads(output)
                misconfigurations = []
                if results and "Results" in results:
                    for result in results["Results"]:
                        if "Misconfigurations" in result:
                            for misconfig in result["Misconfigurations"]:
                                misconfigurations.append({
                                    "ID": misconfig.get("ID"),
                                    "Title": misconfig.get("Title"),
                                    "Description": misconfig.get("Description"),
                                    "Severity": misconfig.get("Severity"),
                                    "Status": misconfig.get("Status"),
                                    "References": misconfig.get("References", [])
                                })
                task['result']['trivy_iac_results'] = misconfigurations
                task['result']['stdout'] = json.dumps(misconfigurations, indent=2)
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

def run_trivy_iac_scan(target_path: str) -> str:
    """Starts a background Trivy IaC scan task."""
    return create_task(_run_trivy_iac_scan_worker, target_path)
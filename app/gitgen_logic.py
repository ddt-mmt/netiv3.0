import os
import subprocess
import tempfile
import shutil
import secrets
import json
from datetime import datetime, timedelta
from typing import List, Optional, Union
import asyncio
import time

import httpx
import git # gitpython
import google.generativeai as genai
from google.api_core import exceptions
from flask import current_app # Import current_app for Flask config

# --- Helper Functions --- #

def _run_command(command: List[str], cwd: Optional[str] = None) -> str:
    try:
        env = os.environ.copy()
        env['GIT_TERMINAL_PROMPT'] = '0'
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True, env=env)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        current_app.logger.error(f"Command failed: {e.cmd}")
        current_app.logger.error(f"Stdout: {e.stdout}")
        current_app.logger.error(f"Stderr: {e.stderr}")
        raise Exception(f"Command failed: {e.stderr}")

def clone_repo(repo_url: str, dest_path: str):
    current_app.logger.info(f"Cloning {repo_url} to {dest_path}...")
    _run_command(["git", "clone", repo_url, dest_path])

def run_semgrep_scan(repo_path: str) -> List[dict]:
    current_app.logger.info(f"Running Semgrep scan on {repo_path}...")
    try:
        # Check if semgrep is installed
        _run_command(["semgrep", "--version"])
    except Exception as e:
        raise Exception("Semgrep is not installed or not in PATH. Please install Semgrep to use this feature.")

    results_file = os.path.join(repo_path, "semgrep_results.json")
    try:
        _run_command(["semgrep", "--config=auto", "--json", "-o", results_file, repo_path], cwd=repo_path)
        with open(results_file, "r") as f:
            results = json.load(f)
        os.remove(results_file)
        
        findings = []
        for result in results.get("results", []):
            findings.append({
                "id": secrets.token_hex(8),
                "description": result["extra"]["message"],
                "risk_level": result["extra"]["severity"],
                "code_snippet": result["extra"]["lines"],
                "file_path": result["path"],
                "line_number": result["start"]["line"],
            })
        return findings
    except Exception as e:
        # If semgrep fails, return an empty list of findings
        current_app.logger.error(f"Semgrep scan failed: {e}")
        return []

async def _call_gemini_with_backoff(model, prompt):
    retries = 3
    delay = 5 # seconds
    for i in range(retries):
        try:
            response = await model.generate_content_async(prompt)
            return response
        except exceptions.ResourceExhausted as e:
            if i < retries - 1:
                current_app.logger.warning(f"Rate limit hit. Retrying in {delay} seconds...")
                await asyncio.sleep(delay)
                delay *= 2 # Exponential backoff
            else:
                raise e

async def _analyze_findings_in_batch(findings: List[dict], gemini_api_key: str) -> List[dict]:
    current_app.logger.info(f"Calling Gemini for batch code analysis of {len(findings)} findings...")
    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel('gemini-pro-latest')

    prompt_parts = ["Analyze the following code snippets for vulnerabilities. For each snippet, provide a short, one-sentence description of the issue and a suggested fix. Return a JSON array where each object has 'id', 'description', and 'suggested_fix'.\n\n"]
    for finding in findings:
        prompt_parts.append(f"---\n")
        prompt_parts.append(f"ID: {finding['id']}\n")
        prompt_parts.append(f"File: {finding['file_path']}:{finding['line_number']}\n")
        prompt_parts.append(f"Code Snippet:\n```\n{finding['code_snippet']}\n```\n")
    prompt = "".join(prompt_parts)

    try:
        response = await _call_gemini_with_backoff(model, prompt)
        return json.loads(response.text)
    except Exception as e:
        current_app.logger.error(f"Gemini batch analysis failed: {e}")
        return [{ "id": f["id"], "description": "Gemini analysis failed.", "suggested_fix": "" } for f in findings]

async def _generate_fixes_in_batch(findings: List[dict], gemini_api_key: str) -> dict:
    current_app.logger.info(f"Calling Gemini to generate fixes for {len(findings)} findings...")
    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel('gemini-pro-latest')
    
    prompt_parts = ["For each of the following code snippets, provide ONLY the corrected code snippet. Return a JSON object where keys are the finding IDs and values are the corrected code snippets.\n\n"]
    for finding in findings:
        prompt_parts.append(f"---\n")
        prompt_parts.append(f"ID: {finding['id']}\n")
        prompt_parts.append(f"Original Code Snippet:\n```\n{finding['code_snippet']}\n```\n\n")
        prompt_parts.append("Corrected Code Snippet:\n")
    prompt = "".join(prompt_parts)

    try:
        response = await _call_gemini_with_backoff(model, prompt)
        return json.loads(response.text)
    except Exception as e:
        current_app.logger.error(f"Gemini fix generation failed: {e}")
        return {f['id']: f['code_snippet'] for f in findings}

def _apply_fix_to_file(repo_path: str, file_path: str, line_number: int, fixed_code: str):
    full_path = os.path.join(repo_path, file_path)
    if not os.path.exists(full_path):
        current_app.logger.error(f"File not found for applying fix: {full_path}")
        return

    with open(full_path, "r") as f:
        lines = f.readlines()

    # Adjust line number for 0-based indexing
    if 0 <= line_number - 1 < len(lines):
        lines[line_number - 1] = fixed_code.rstrip('\n') + '\n'
    else:
        current_app.logger.warning(f"Line number {line_number} out of range for file {file_path}")
        return

    with open(full_path, "w") as f:
        f.writelines(lines)

def _generate_diff(repo_path: str, findings: List[dict], gemini_api_key: str) -> str:
    all_patches_content = []
    fixed_codes = asyncio.run(_generate_fixes_in_batch(findings, gemini_api_key))

    for finding in findings:
        fixed_code = fixed_codes.get(finding['id'], finding['code_snippet'])
        original_file_path = os.path.join(repo_path, finding['file_path'])
        
        if not os.path.exists(original_file_path):
            current_app.logger.error(f"File not found for diffing: {original_file_path}")
            continue

        with open(original_file_path, "r") as f:
            original_content = f.readlines()

        new_content = original_content[:]
        new_content[finding['line_number'] - 1] = fixed_code + '\n'

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, prefix="original_") as original_temp_file:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, prefix="fixed_") as fixed_temp_file:
            
                original_temp_file.writelines(original_content)
                fixed_temp_file.writelines(new_content)
                original_temp_file_path = original_temp_file.name
                fixed_temp_file_path = fixed_temp_file.name

        diff_command = ["diff", "-u", original_temp_file_path, fixed_temp_file_path]
        try:
            result = subprocess.run(diff_command, capture_output=True, text=True)
            patch = result.stdout
            patch = patch.replace(original_temp_file_path, f"a/{finding['file_path']}")
            patch = patch.replace(fixed_temp_file_path, f"b/{finding['file_path']}")
            all_patches_content.append(patch)
        except Exception as e:
            current_app.logger.error(f"Diff command failed: {e}")
        finally:
            os.remove(original_temp_file_path)
            os.remove(fixed_temp_file_path)

    return "\n".join(all_patches_content)

# --- Worker Functions for Flask Background Tasks --- #

def analyze_repository_worker(task_id, app, repo_url: str, gemini_api_key: str, tasks_dict: dict):
    with app.app_context():
        temp_dir = None
        try:
            tasks_dict[task_id]['status'] = 'running'
            tasks_dict[task_id]['result'] = {} # Initialize result
            temp_dir = tempfile.mkdtemp()
            tasks_dict[task_id]['temp_dir'] = temp_dir # Store temp_dir
            clone_repo(repo_url, temp_dir)
            semgrep_findings = run_semgrep_scan(temp_dir)

            if not semgrep_findings:
                tasks_dict[task_id]['status'] = 'completed'
                tasks_dict[task_id]['result'] = {"message": "Analysis complete. No findings.", "findings": []}
                return

            analyzed_findings = []
            for i in range(0, len(semgrep_findings), 2): # Chunk size of 2
                chunk = semgrep_findings[i:i+2]
                gemini_analyses = asyncio.run(_analyze_findings_in_batch(chunk, gemini_api_key))
                gemini_map = {item['id']: item for item in gemini_analyses}

                for finding in chunk:
                    gemini_result = gemini_map.get(finding['id'])
                    if gemini_result:
                        finding['description'] = gemini_result.get('description', finding['description'])
                        finding['gemini_analysis'] = gemini_result
                    else:
                        finding['gemini_analysis'] = {"description": "No Gemini analysis available.", "suggested_fix": ""}
                    analyzed_findings.append(finding)

            tasks_dict[task_id]['status'] = 'completed'
            tasks_dict[task_id]['result'] = {"message": "Analysis complete.", "findings": analyzed_findings}
        except Exception as e:
            current_app.logger.exception(f"Error in analyze_repository_worker for task {task_id}")
            tasks_dict[task_id]['status'] = 'error'
            tasks_dict[task_id]['result'] = {"error": str(e)}
        # Don't clean up temp_dir here, it will be cleaned up by the last worker


def simulate_fix_worker(task_id, app, repo_url: str, findings: List[dict], gemini_api_key: str, tasks_dict: dict, analysis_task_id: str):
    with app.app_context():
        temp_dir = None
        try:
            tasks_dict[task_id]['status'] = 'running'
            analysis_task = tasks_dict.get(analysis_task_id)
            if not analysis_task or 'temp_dir' not in analysis_task:
                raise Exception("Analysis task not found or temp_dir not available.")
            temp_dir = analysis_task['temp_dir']

            # 1. Get original findings for comparison
            original_findings = analysis_task['result']['findings']
            original_finding_ids = {f['id'] for f in original_findings}

            # 2. Apply proposed fixes to the temporary repository
            fixed_codes = asyncio.run(_generate_fixes_in_batch(findings, gemini_api_key))
            for finding in findings:
                fixed_code = fixed_codes.get(finding['id'])
                if fixed_code:
                    _apply_fix_to_file(temp_dir, finding['file_path'], finding['line_number'], fixed_code)

            # 3. Run re-scan on the fixed repository
            fixed_semgrep_findings = run_semgrep_scan(temp_dir)
            fixed_finding_ids = {f['id'] for f in fixed_semgrep_findings}

            # 4. Generate enhanced diff with analysis results
            enhanced_diff_content = []
            code_diff = _generate_diff(temp_dir, findings, gemini_api_key) # Generate actual code diff
            enhanced_diff_content.append(code_diff)
            enhanced_diff_content.append("\n--- Vulnerability Analysis Summary ---\n")

            for original_f in original_findings:
                if original_f['id'] in original_finding_ids and original_f['id'] not in fixed_finding_ids:
                    enhanced_diff_content.append(f"[FIXED] {original_f['file_path']}:{original_f['line_number']} - {original_f['description']}")
                elif original_f['id'] in original_finding_ids and original_f['id'] in fixed_finding_ids:
                    enhanced_diff_content.append(f"[STILL DETECTED] {original_f['file_path']}:{original_f['line_number']} - {original_f['description']}")
            
            for new_f in fixed_semgrep_findings:
                if new_f['id'] not in original_finding_ids:
                    enhanced_diff_content.append(f"[NEWLY INTRODUCED] {new_f['file_path']}:{new_f['line_number']} - {new_f['description']}")

            tasks_dict[task_id]['status'] = 'completed'
            tasks_dict[task_id]['result'] = {"diff_content": "\n".join(enhanced_diff_content)}
        except Exception as e:
            current_app.logger.exception(f"Error in simulate_fix_worker for task {task_id}")
            tasks_dict[task_id]['status'] = 'error'
            tasks_dict[task_id]['result'] = {"error": str(e)}
        finally:
            tasks_dict[task_id]['end_time'] = datetime.now().timestamp()

def generate_patch_worker(task_id, app, repo_url: str, findings: List[dict], gemini_api_key: str, tasks_dict: dict, analysis_task_id: str):
    with app.app_context():
        temp_dir = None
        try:
            tasks_dict[task_id]['status'] = 'running'
            analysis_task = tasks_dict.get(analysis_task_id)
            if not analysis_task or 'temp_dir' not in analysis_task:
                raise Exception("Analysis task not found or temp_dir not available.")
            temp_dir = analysis_task['temp_dir']

            patch_content = _generate_diff(temp_dir, findings, gemini_api_key)

            tasks_dict[task_id]['status'] = 'completed'
            tasks_dict[task_id]['result'] = {"patch_content": patch_content}
        except Exception as e:
            current_app.logger.exception(f"Error in generate_patch_worker for task {task_id}")
            tasks_dict[task_id]['status'] = 'error'
            tasks_dict[task_id]['result'] = {"error": str(e)}
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir) # Clean up the directory
            tasks_dict[task_id]['end_time'] = datetime.now().timestamp()

def create_pull_request_worker(task_id, app, repo_url: str, patch_content: str, branch_name: str, commit_message: str, pr_title: str, pr_body: str, github_token: str, tasks_dict: dict):
    with app.app_context():
        temp_dir = None
        try:
            tasks_dict[task_id]['status'] = 'running'
            temp_dir = tempfile.mkdtemp()
            
            # Clone the repo
            repo = git.Repo.clone_from(repo_url, temp_dir, env={'GIT_TERMINAL_PROMPT': '0'})
            
            # Create and checkout a new branch
            repo.git.checkout('-b', branch_name)
            
            # Apply the patch
            patch_file = os.path.join(temp_dir, 'patch.diff')
            with open(patch_file, 'w') as f:
                f.write(patch_content)
            repo.git.apply(patch_file)
            
            # Commit the changes
            repo.git.add(A=True)
            repo.git.commit('-m', commit_message)
            
            # Push the changes
            repo.git.push('--set-upstream', 'origin', branch_name)
            
            # Create a pull request
            github_api_url = f"https://api.github.com/repos/{repo_url.split('/')[-2]}/{repo_url.split('/')[-1].replace('.git', '')}/pulls"
            headers = {
                "Authorization": f"token {github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            data = {
                "title": pr_title,
                "body": pr_body,
                "head": branch_name,
                "base": repo.active_branch.name
            }
            response = httpx.post(github_api_url, headers=headers, json=data)
            response.raise_for_status()
            pr_url = response.json()['html_url']
            
            tasks_dict[task_id]['status'] = 'completed'
            tasks_dict[task_id]['result'] = {'pr_url': pr_url}
            
        except Exception as e:
            current_app.logger.exception(f"Error in create_pull_request_worker for task {task_id}")
            tasks_dict[task_id]['status'] = 'error'
            tasks_dict[task_id]['result'] = {"error": str(e)}
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            tasks_dict[task_id]['end_time'] = datetime.now().timestamp()

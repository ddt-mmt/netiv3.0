import json
import os
import httpx
from datetime import datetime, timedelta
from flask import render_template, request, jsonify, send_file, session, g, Blueprint, current_app, make_response, redirect, url_for
from app.logic import (
    perform_ping_scan,
    perform_traceroute_scan,
    perform_nslookup_scan,
    perform_nmap_scan,
    get_network_device_info,
    run_domain_scan,
    run_email_analysis,
    analyze_results_with_gemini,
    generate_payload, # <-- Import new function
    run_nikto_scan,
    run_xxe_scan,
    run_dns_zone_transfer,
    run_custom_scan,
    run_dns_spoof_test,
    connect_to_metasploit,
    search_metasploit_modules,
    run_scan,
    perform_email_header_analysis,
    perform_mail_server_port_scan,
    perform_email_auth_lookup,
    perform_idor_test,
    perform_discovery_crawl,
    get_task_status, # <-- Import new function
    cancel_task,     # <-- Import new function
    create_task,     # <-- Import create_task for gitgen
    tasks            # <-- Import global tasks dict for gitgen
)
from app.trivy_scanner import run_trivy_sca
from app.gitleaks_scanner import run_gitleaks_scan
from app.semgrep_scanner import run_semgrep_scan
from app.zap_scanner import run_zap_scan
from app.trivy_advanced_scanner import run_trivy_image_scan, run_trivy_iac_scan
from app.logic import run_devsecsimops_scan 
from app.gitgen_logic import analyze_repository_worker, generate_patch_worker, simulate_fix_worker, create_pull_request_worker # Import gitgen workers

bp = Blueprint('main', __name__)

@bp.route('/task/status/<task_id>', methods=['GET'])
def task_status_route(task_id):
    """Endpoint to check the status of a background task."""
    status = get_task_status(task_id)
    return jsonify(status)

@bp.route('/task/cancel/<task_id>', methods=['POST'])
def cancel_task_route(task_id):
    """Endpoint to cancel a running background task."""
    result = cancel_task(task_id)
    return jsonify(result)

@bp.route('/download_tutorial')
def download_tutorial():
    try:
        tutorial_path = os.path.join(current_app.root_path, '..', 'TUTORIAL_IDOR.md')
        with open(tutorial_path, 'r', encoding='utf-8') as f:
            content = f.read()
        response = make_response(content)
        response.headers.set('Content-Type', 'text/plain')
        response.headers.set('Content-Disposition', 'attachment', filename='TUTORIAL_IDOR.txt')
        return response
    except Exception as e:
        current_app.logger.error(f"Could not serve tutorial file: {e}")
        return "File not found or error reading file.", 404

def get_translations(language_code):
    translations_path = os.path.join(bp.root_path, 'static', 'translations.json')
    with open(translations_path, 'r') as f:
        translations = json.load(f)
    return translations.get(language_code, translations.get('en'))

@bp.before_request
def set_language():
    lang_code = request.cookies.get('lang', 'en')
    g.lang = get_translations(lang_code)
    g.lang_code = lang_code

@bp.route('/idor_run')
def idor_run_page():
    session['idor_run_data'] = {}
    return render_template('idor_run.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/run_idor_test', methods=['POST'])
def run_idor_test_route():
    try:
        data = request.json
        task_id = perform_idor_test(data)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting IDOR test:")
        return jsonify({'error': str(e)}), 500

@bp.route('/run_discovery', methods=['POST'])
def run_discovery_route():
    try:
        data = request.json
        task_id = perform_discovery_crawl(data)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting discovery crawl:")
        return jsonify({'error': str(e)}), 500

# ... (all other existing routes from the original file go here) ...

@bp.route('/exploit')
def exploit_page():
    session['exploit_data'] = {}
    msf_version = "Not Connected"
    try:
        client = connect_to_metasploit()
        if client:
            msf_version = client.call('core.version')['version']
            client.logout()
        else:
            msf_version = "Failed to connect to Metasploit RPC."
    except Exception as e:
        msf_version = f"Error: {e}"
    return render_template('exploit.html', lang=g.lang, lang_code=g.lang_code, msf_version=msf_version)


@bp.route('/api_security')
def api_security_page():
    session['api_security_data'] = {}
    # In the future, we might load custom tools for this category as well
    # all_tools = current_app.config.get('CUSTOM_TOOLS', [])
    # api_tools = [tool for tool in all_tools if tool.get('category') == 'api']
    return render_template('api_security.html', lang=g.lang, lang_code=g.lang_code, custom_tools=[])

@bp.route('/ai_utilities')
def ai_utilities_page():
    session['ai_utilities_data'] = {}
    return render_template('ai_utilities.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/generate_payload', methods=['POST'])
def generate_payload_route():
    try:
        data = request.json
        api_key = data.get('api_key')
        description = data.get('description')
        language = g.lang_code

        if not api_key or not description:
            return jsonify({'error': 'API key and description are required.'}), 400

        task_id = generate_payload(api_key, description, language)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting payload generation task:")
        return jsonify({'error': str(e)}), 500


@bp.route('/run_api_scan', methods=['POST'])
def run_api_scan_route():
    # This is a placeholder for the new functionality
    try:
        # In the future, this will trigger a real API scan task
        # For now, it returns a dummy message after a short delay.
        import time
        time.sleep(2)
        return jsonify({'result': 'API scan placeholder: Task would run here.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/trivy_sca', methods=['GET', 'POST'])
def trivy_sca_page():
    if request.method == 'POST':
        target_path = request.form.get('target_path')
        if not target_path:
            return jsonify({'error': 'Target path cannot be empty'}), 400
        
        task_id = run_trivy_sca(target_path)
        return jsonify({'task_id': task_id}), 202
    
    return render_template('trivy_sca.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/gitleaks_scan', methods=['GET', 'POST'])
def gitleaks_scan_page():
    if request.method == 'POST':
        repo_url = request.form.get('repo_url')
        if not repo_url:
            return jsonify({'error': 'Repository URL cannot be empty'}), 400
        
        task_id = run_gitleaks_scan(repo_url)
        return jsonify({'task_id': task_id}), 202
    
    return render_template('gitleaks_scan.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/semgrep_scan', methods=['GET', 'POST'])
def semgrep_scan_page():
    if request.method == 'POST':
        target_path = request.form.get('target_path')
        config_url = request.form.get('config_url', 'auto') # Default to 'auto'
        if not target_path:
            return jsonify({'error': 'Target path (repository URL or local path) cannot be empty'}), 400
        
        task_id = run_semgrep_scan(target_path, config_url)
        return jsonify({'task_id': task_id}), 202
    
    return render_template('semgrep_scan.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/zap_scan', methods=['GET', 'POST'])
def zap_scan_page():
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        if not target_url:
            return jsonify({'error': 'Target URL cannot be empty'}), 400
        
        task_id = run_zap_scan(target_url)
        return jsonify({'task_id': task_id}), 202
    
    return render_template('zap_scan.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/git_analysis')
def git_analysis_page():
    return render_template('git_analysis.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/trivy_image_scan', methods=['GET', 'POST'])
def trivy_image_scan_page():
    if request.method == 'POST':
        image_name = request.form.get('image_name')
        if not image_name:
            return jsonify({'error': 'Image name cannot be empty'}), 400
        
        task_id = run_trivy_image_scan(image_name)
        return jsonify({'task_id': task_id}), 202
    
    return render_template('trivy_image_scan.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/trivy_iac_scan', methods=['GET', 'POST'])
def trivy_iac_scan_page():
    if request.method == 'POST':
        target_path = request.form.get('target_path')
        if not target_path:
            return jsonify({'error': 'Target path cannot be empty'}), 400
        
        task_id = run_trivy_iac_scan(target_path)
        return jsonify({'task_id': task_id}), 202
    
    return render_template('trivy_iac_scan.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/network_analysis')
def net_analysis_page():
    session['network_analysis_data'] = {}
    all_tools = current_app.config.get('CUSTOM_TOOLS', [])
    net_tools = [tool for tool in all_tools if tool.get('category') == 'net']
    return render_template('network_analysis.html', lang=g.lang, lang_code=g.lang_code, custom_tools=net_tools)

@bp.route('/run_ping', methods=['POST'])
def run_ping():
    try:
        print("[/run_ping] Route hit.")
        data = request.json
        target = data.get('target')
        print(f"[/run_ping] Target: {target}")
        if not target:
            return jsonify({'error': 'Target cannot be empty'}), 400
        task_id = perform_ping_scan(target)
        print(f"[/run_ping] Task ID: {task_id}")
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        print(f"[/run_ping] Error: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/run_traceroute', methods=['POST'])
def run_traceroute():
    try:
        data = request.json
        target = data.get('target')
        if not target:
            return jsonify({'error': 'Target cannot be empty'}), 400
        task_id = perform_traceroute_scan(target)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_nslookup', methods=['POST'])
def run_nslookup():
    try:
        data = request.json
        target = data.get('target')
        if not target:
            return jsonify({'error': 'Target cannot be empty'}), 400
        task_id = perform_nslookup_scan(target)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_nmap', methods=['POST'])
def run_nmap():
    try:
        data = request.json
        target = data.get('target')
        scan_type = data.get('scan_type')
        custom_ports = data.get('custom_ports') # New
        custom_args = data.get('custom_args')   # New

        if not all([target, scan_type]):
            return jsonify({'error': 'Target and scan_type are required.'}), 400
        
        # Pass the new optional arguments to the logic function
        task_id = perform_nmap_scan(target, scan_type, custom_ports=custom_ports, custom_args=custom_args)
        
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/analyze_results', methods=['POST'])
def analyze_results():
    try:
        print(f"[/analyze_results] Route hit. Request method: {request.method}")
        try:
            data = request.json
            print(f"[/analyze_results] Received JSON data: {data}")
        except Exception as json_e:
            print(f"[/analyze_results] Error parsing JSON: {json_e}")
            return jsonify({'error': f'Invalid JSON in request: {json_e}'}), 400

        api_key = data.get('api_key')
        results = data.get('results')
        language = data.get('language', g.lang_code)
        
        print(f"[/analyze_results] API Key received (first 5 chars): {str(api_key)[:5]}..., Length: {len(str(api_key)) if api_key else 0}")
        print(f"[/analyze_results] Results data received (first 50 chars): {str(results)[:50]}..., Length: {len(str(results)) if results else 0}")

        if not api_key:
            print(f"[/analyze_results] Error: API key is missing.")
            return jsonify({'error': 'API key is required.'}), 400
        if not results:
            print(f"[/analyze_results] Error: Results data is missing.")
            return jsonify({'error': 'Results data is required.'}), 400
        
        task_id = analyze_results_with_gemini(api_key, results, language)
        print(f"[/analyze_results] Starting AI task with ID: {task_id}")
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting AI analysis task:")
        print(f"[/analyze_results] Unhandled exception: {e}")
        return jsonify({'error': str(e)}), 500

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, g, current_app
from app import logic
import json
import os

web_bp = Blueprint('web', __name__)

@web_bp.before_app_request
def load_language():
    lang_code = request.accept_languages.best_match(current_app.config['LANGUAGES'].keys()) or 'en'
    lang_path = os.path.join(current_app.root_path, 'static', 'translations.json')
    with open(lang_path, 'r') as f:
        translations = json.load(f)
    g.lang = translations.get(lang_code, translations['en'])
    g.lang_code = lang_code

@web_bp.route('/')
def index():
    return render_template('index.html', lang=g.lang, lang_code=g.lang_code)

@web_bp.route('/web_domain_analysis')
def web_domain_analysis():
    return render_template('web_domain_analysis.html', lang=g.lang, lang_code=g.lang_code)

@web_bp.route('/web_domain_analysis/whois_lookup', methods=['POST'])
def whois_lookup():
    target = request.form['target']
    task_id = logic.perform_nslookup_scan(target) # Reusing nslookup for whois for now
    return jsonify({'task_id': task_id})

@web_bp.route('/web_domain_analysis/dns_lookup', methods=['POST'])
def dns_lookup():
    target = request.form['target']
    task_id = logic.perform_nslookup_scan(target)
    return jsonify({'task_id': task_id})

@web_bp.route('/web_domain_analysis/subdomain_enum', methods=['POST'])
def subdomain_enum():
    target = request.form['target']
    task_id = logic.run_domain_scan(target, 'subdomain_enum')
    return jsonify({'task_id': task_id})

@web_bp.route('/web_domain_analysis/port_scan', methods=['POST'])
def port_scan():
    target = request.form['target']
    scan_type = request.form.get('scan_type', 'quick_scan')
    task_id = logic.perform_nmap_scan(target, scan_type)
    return jsonify({'task_id': task_id})

@web_bp.route('/web_domain_analysis/ssl_analysis', methods=['POST'])
def ssl_analysis():
    target = request.form['target']
    # Placeholder for SSL analysis logic
    task_id = logic.perform_nmap_scan(target, 'quick_scan') # Using nmap as a placeholder
    return jsonify({'task_id': task_id})

@web_bp.route('/web_domain_analysis/http_header_analysis', methods=['POST'])
def http_header_analysis():
    target = request.form['target']
    # Placeholder for HTTP header analysis logic
    task_id = logic.perform_nmap_scan(target, 'quick_scan') # Using nmap as a placeholder
    return jsonify({'task_id': task_id})

@web_bp.route('/web_domain_analysis/traceroute', methods=['POST'])
def traceroute():
    target = request.form['target']
    task_id = logic.perform_traceroute_scan(target)
    return jsonify({'task_id': task_id})

@web_bp.route('/web_domain_analysis/ping', methods=['POST'])
def ping():
    target = request.form['target']
    task_id = logic.perform_ping_scan(target)
    return jsonify({'task_id': task_id})

@web_bp.route('/web_domain_analysis/nmap_scan', methods=['POST'])
def nmap_scan():
    target = request.form['target']
    scan_type = request.form.get('scan_type', 'quick_scan')
    task_id = logic.perform_nmap_scan(target, scan_type)
    return jsonify({'task_id': task_id})

@web_bp.route('/web_domain_analysis/waf_detection', methods=['POST'])
def waf_detection():
    target = request.form['target']
    # Placeholder for WAF detection logic
    task_id = logic.perform_nmap_scan(target, 'quick_scan') # Using nmap as a placeholder
    return jsonify({'task_id': task_id})

@web_bp.route('/web_domain_analysis/nuclei_scan', methods=['POST'])
def nuclei_scan():
    target_url = request.form['target_url']
    scan_type = request.form.get('scan_type', 'default')
    return jsonify({'task_id': task_id})

@web_bp.route('/test_route')
def test_route():
    return "Test successful!"

@bp.route('/network_device_target', methods=['GET', 'POST'])
def network_device_target():
    if request.method == 'POST':
        try:
            data = request.json
            device_type = data.get('device_type')
            host = data.get('host')
            username = data.get('username')
            password = data.get('password')
            if not all([device_type, host, username, password]):
                return jsonify({"status": "error", "message": "Missing required fields."}), 400
            
            task_id = get_network_device_info(device_type, host, username, password)
            return jsonify({'task_id': task_id}), 202
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    all_tools = current_app.config.get('CUSTOM_TOOLS', [])
    device_tools = [tool for tool in all_tools if tool.get('category') == 'device']
    return render_template('network_device_target.html', lang=g.lang, lang_code=g.lang_code, custom_tools=device_tools)

@bp.route('/log_analyzer')
def log_analyzer_page():
    session['log_analyzer_data'] = {}
    all_tools = current_app.config.get('CUSTOM_TOOLS', [])
    log_tools = [tool for tool in all_tools if tool.get('category') == 'log']
    return render_template('log_analyzer.html', lang=g.lang, lang_code=g.lang_code, custom_tools=log_tools)

@bp.route('/analyze_logs', methods=['POST'])
def analyze_logs_route():
    """Endpoint to receive log data and start an AI analysis task."""
    try:
        data = request.json
        api_key = data.get('api_key')
        log_content = data.get('log_content')
        language = data.get('language', g.lang_code)

        if not api_key:
            return jsonify({'error': 'API key is required.'}), 400
        if not log_content:
            return jsonify({'error': 'Log content is required.'}), 400
        
        # We can reuse the generic gemini analysis worker for this
        task_id = analyze_results_with_gemini(api_key, log_content, language)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting log analysis task:")
        return jsonify({'error': str(e)}), 500


@bp.route('/email_target', methods=['GET', 'POST'])
def email_target():
    if request.method == 'POST':
        try:
            target_email = request.json['target_email']
            if not target_email:
                return jsonify({'error': 'Target email is required.'}), 400
            task_id = run_email_analysis(target_email)
            return jsonify({'task_id': task_id}), 202
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    session['email_target_data'] = {}
    return render_template('email_target.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/run_email_header_analysis', methods=['POST'])
def run_email_header_analysis_route():
    try:
        data = request.json
        raw_headers = data.get('raw_headers')
        if not raw_headers:
            return jsonify({'error': 'Raw email headers are required.'}), 400
        task_id = perform_email_header_analysis(raw_headers)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error during email header analysis:")
        return jsonify({'error': str(e)}), 500

@bp.route('/search_msf_modules', methods=['POST'])
def search_msf_modules_route():
    try:
        data = request.json
        query = data.get('query')
        if not query:
            return jsonify({'error': 'Search query is required.'}), 400
        task_id = search_metasploit_modules(query)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error searching Metasploit modules:")
        return jsonify({'error': str(e)}), 500

@bp.route('/get_msf_module_details', methods=['POST'])
def get_msf_module_details_route():
    try:
        data = request.json
        module_fullname = data.get('module_fullname')
        if not module_fullname:
            return jsonify({'error': 'Module fullname is required.'}), 400
        task_id = get_metasploit_module_details(module_fullname)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error getting Metasploit module details:")
        return jsonify({'error': str(e)}), 500

@bp.route('/run_exploit', methods=['POST'])
def run_exploit_route():
    try:
        data = request.json
        module_fullname = data.get('module_fullname')
        options = data.get('options', {})
        if not module_fullname:
            return jsonify({'error': 'Module fullname is required.'}), 400
        
        task_id = run_exploit(module_fullname, options)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting exploit task:")
        return jsonify({'error': str(e)}), 500

@bp.route('/run_mail_server_port_scan', methods=['POST'])
def run_mail_server_port_scan_route():
    try:
        data = request.json
        target_host = data.get('target_host')
        if not target_host:
            return jsonify({'error': 'Target host is required.'}), 400
        task_id = perform_mail_server_port_scan(target_host)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_email_auth_lookup', methods=['POST'])
def run_email_auth_lookup_route():
    try:
        data = request.json
        domain = data.get('domain')
        if not domain:
            return jsonify({'error': 'Domain is required.'}), 400
        task_id = perform_email_auth_lookup(domain)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/set_language/<lang_code>')
def set_language_route(lang_code):
    response = jsonify(message=f"Language set to {lang_code}")
    response.set_cookie('lang', lang_code, secure=True, httponly=True, samesite='Lax')
    return response

@bp.route('/run_nikto_scan', methods=['POST'])
def run_nikto_scan_route():
    try:
        data = request.json
        target_url = data.get('target_url')
        if not target_url:
            return jsonify({'error': 'Target URL cannot be empty'}), 400
        task_id = run_nikto_scan(target_url)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_xxe_scan', methods=['POST'])
def run_xxe_scan_route():
    try:
        data = request.json
        target_url = data.get('target_url')
        if not target_url:
            return jsonify({'error': 'Target URL cannot be empty'}), 400
        task_id = run_xxe_scan(target_url)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_dns_zone_transfer', methods=['POST'])
def run_dns_zone_transfer_route():
    try:
        data = request.json
        target_domain = data.get('target_domain')
        if not target_domain:
            return jsonify({'error': 'Target domain cannot be empty'}), 400
        task_id = run_dns_zone_transfer(target_domain)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_dns_spoof', methods=['POST'])
def run_dns_spoof_route():
    try:
        data = request.json
        victim_ip = data.get('victim_ip')
        target_domain = data.get('target_domain')
        fake_ip = data.get('fake_ip')
        if not all([victim_ip, target_domain, fake_ip]):
            return jsonify({'error': 'Victim IP, Target Domain, and Fake IP are required.'}), 400
        result = run_dns_spoof_test(victim_ip, target_domain, fake_ip)
        session.setdefault('web_domain_analysis_data', {})['dns_spoof_results'] = result
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_custom_scan', methods=['POST'])
def run_custom_scan_route():
    try:
        data = request.json
        tool_id = data.get('tool_id')
        target = data.get('target')
        if not all([tool_id, target]):
            return jsonify({'error': 'Tool ID and target are required.'}), 400
        all_tools = current_app.config.get('CUSTOM_TOOLS', [])
        tool = next((t for t in all_tools if t.get('id') == tool_id), None)
        if not tool:
            return jsonify({'error': f'Tool with ID {tool_id} not found.'}), 404
        command_template = tool.get('command')
        if not command_template:
            return jsonify({'error': f'Tool with ID {tool_id} has no command defined.'}), 500
        task_id = run_custom_scan(command_template, target)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        target = data.get('target')
        scan_type = data.get('scan_type')
        if not all([target, scan_type]):
            return jsonify({'error': 'Target and scan type are required.'}), 400
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/git_generate')
def git_generate_page():
    return redirect(url_for('main.git_patch_page'))

@bp.route('/git_patch')
def git_patch_page():
    return render_template('git_patch.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/devsecsimops')
def devsecsimops_page():
    return render_template('devsecsimops.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/devsecsimops_scan', methods=['POST'])
def devsecsimops_scan_route():
    try:
        data = request.json
        repo_url = data.get('repo_url')
        api_key = data.get('api_key') # Get API key from frontend
        
        if not repo_url:
            return jsonify({'error': 'Repository URL cannot be empty'}), 400
        if not api_key:
            return jsonify({'error': 'API Key is required for AI analysis.'}), 400
        
        task_id = run_devsecsimops_scan(repo_url, api_key, g.lang_code) 
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting DevSecSimOps scan:")
        return jsonify({'error': str(e)}), 500

# --- Gitgen Integration Routes --- #
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"

@bp.route('/gitgen/login/github', methods=['GET'])
def gitgen_github_login():
    client_id = current_app.config.get("GITHUB_CLIENT_ID")
    if not client_id:
        return jsonify({"error": "GitHub Client ID not configured."}), 500
    
    return redirect(f"{GITHUB_AUTHORIZE_URL}?client_id={client_id}&scope=repo,user")

@bp.route('/gitgen/auth/github/callback', methods=['GET'])
def gitgen_github_callback():
    code = request.args.get('code')
    if not code:
        return jsonify({"error": "Authorization code not provided."}), 400

    client_id = current_app.config.get("GITHUB_CLIENT_ID")
    client_secret = current_app.config.get("GITHUB_CLIENT_SECRET")

    if not client_id or not client_secret:
        return jsonify({"error": "GitHub OAuth credentials not configured."}), 500

    try:
        token_response = httpx.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            json={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code
            }
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            return jsonify({"error": "Failed to get GitHub access token."}), 400

        session['github_access_token'] = access_token
        return redirect(url_for('main.git_analysis_page')) # Redirect to git_analysis page after successful auth

    except httpx.HTTPStatusError as e:
        current_app.logger.exception(f"HTTP error during GitHub token exchange: {e.response.text}")
        return jsonify({"error": f"GitHub token exchange failed: {e.response.text}"}), 500
    except Exception as e:
        current_app.logger.exception("Error during GitHub OAuth callback:")
        return jsonify({"error": str(e)}), 500

@bp.route('/gitgen/api/v1/analyze', methods=['POST'])
def gitgen_analyze_repository():
    try:
        data = request.json
        repo_url = data.get('repo_url')
        gemini_api_key = data.get('gemini_api_key')

        if not repo_url:
            return jsonify({'error': 'Repository URL is required.'}), 400
        if not gemini_api_key:
            return jsonify({'error': 'Gemini API Key is required.'}), 400
        
        app = current_app._get_current_object()
        task_id = create_task(analyze_repository_worker, app, repo_url, gemini_api_key, tasks)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting gitgen analyze task:")
        return jsonify({'error': str(e)}), 500

@bp.route('/gitgen/simulate', methods=['POST'])
def gitgen_simulate_page():
    diff_content = request.form.get('diff_content', '')
    return render_template('git_patch_simulation.html', diff_content=diff_content, lang=g.lang, lang_code=g.lang_code)

@bp.route('/gitgen/api/v1/simulate-fix', methods=['POST'])
def gitgen_simulate_fix():
    try:
        data = request.json
        repo_url = data.get('repo_url')
        findings = data.get('findings')
        gemini_api_key = data.get('gemini_api_key')
        analysis_task_id = data.get('analysis_task_id')

        if not all([repo_url, findings, gemini_api_key, analysis_task_id]):
            return jsonify({'error': 'repo_url, findings, gemini_api_key, and analysis_task_id are required.'}), 400
        
        app = current_app._get_current_object()
        task_id = create_task(simulate_fix_worker, app, repo_url, findings, gemini_api_key, tasks, analysis_task_id)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting gitgen simulate fix task:")
        return jsonify({'error': str(e)}), 500

@bp.route('/gitgen/api/v1/generate-patch', methods=['POST'])
def gitgen_generate_patch():
    try:
        data = request.json
        repo_url = data.get('repo_url')
        findings = data.get('findings')
        gemini_api_key = data.get('gemini_api_key')
        analysis_task_id = data.get('analysis_task_id')

        if not all([repo_url, findings, gemini_api_key, analysis_task_id]):
            return jsonify({'error': 'repo_url, findings, gemini_api_key, and analysis_task_id are required.'}), 400
        
        app = current_app._get_current_object()
        task_id = create_task(generate_patch_worker, app, repo_url, findings, gemini_api_key, tasks, analysis_task_id)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting gitgen generate patch task:")
        return jsonify({'error': str(e)}), 500

@bp.route('/gitgen/api/v1/create-pull-request', methods=['POST'])
def gitgen_create_pull_request():
    try:
        data = request.json
        repo_url = data.get('repo_url')
        patch_content = data.get('patch_content')
        branch_name = data.get('branch_name', 'gitgen-fixes')
        commit_message = data.get('commit_message', 'feat: Apply gitgen automated fixes')
        pr_title = data.get('pr_title', 'Automated fixes from gitgen')
        pr_body = data.get('pr_body', 'This PR applies automated security and efficiency fixes generated by gitgen.')
        
        github_token = session.get('github_access_token')
        if not github_token:
            return jsonify({'error': 'GitHub access token not found in session. Please authenticate with GitHub.'}), 401

        if not all([repo_url, patch_content]):
            return jsonify({'error': 'Repository URL and patch content are required.'}), 400
        
        app = current_app._get_current_object()
        task_id = create_task(create_pull_request_worker, app, repo_url, patch_content, branch_name, commit_message, pr_title, pr_body, github_token, tasks)
        return jsonify({'task_id': task_id}), 202
    except Exception as e:
        current_app.logger.exception("Error starting gitgen create PR task:")
        return jsonify({'error': str(e)}), 500

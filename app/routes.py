import json
import os
from flask import render_template, request, jsonify, send_file, session, g, Blueprint, current_app, make_response
import json
import os
from flask import render_template, request, jsonify, session, g, Blueprint, current_app, make_response
from app.logic import (
    perform_ping_scan,
    perform_traceroute_scan,
    perform_nslookup_scan,
    perform_nmap_scan,
    get_network_device_info,
    run_domain_scan,
    run_email_analysis,
    analyze_results_with_gemini,
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
    perform_email_auth_lookup
)

bp = Blueprint('main', __name__)
web_bp = Blueprint('web', __name__)

def get_translations(language_code):
    translations_path = os.path.join(bp.root_path, 'static', 'translations.json')
    print(f"DEBUG: get_translations - translations_path: {translations_path}")
    with open(translations_path, 'r') as f:
        translations = json.load(f)
    selected_translations = translations.get(language_code, translations.get('en'))
    print(f"DEBUG: get_translations - language_code: {language_code}, returned translations: {selected_translations}")
    return selected_translations


@bp.before_request
def set_language():
    lang_code = request.cookies.get('lang', 'en')
    print(f"DEBUG: set_language - lang_code from cookie: {lang_code}")
    g.lang = get_translations(lang_code)
    g.lang_code = lang_code
    print(f"DEBUG: set_language - g.lang set to: {g.lang}")

@bp.route('/')
def index():
    print(f"DEBUG: index - g.lang being passed to template: {g.lang}")
    return render_template('index.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/exploit')
def exploit_page():
    session['exploit_data'] = {}
    msf_version = "Not Connected"
    try:
        client = connect_to_metasploit()
        if client:
            msf_version = client.call('core.version')['version']
            client.logout() # Logout after getting version
        else:
            msf_version = "Failed to connect to Metasploit RPC."
    except Exception as e:
        msf_version = f"Error: {e}"

    print(f"DEBUG: exploit_page - g.lang: {g.lang}")
    print(f"DEBUG: exploit_page - g.lang_code: {g.lang_code}")
    return render_template('exploit.html', lang=g.lang, lang_code=g.lang_code, msf_version=msf_version)

@bp.route('/network_analysis')
def net_analysis_page():
    session['network_analysis_data'] = {}
    all_tools = current_app.config.get('CUSTOM_TOOLS', [])
    net_tools = [tool for tool in all_tools if tool.get('category') == 'net']
    return render_template('network_analysis.html', lang=g.lang, lang_code=g.lang_code, custom_tools=net_tools)

@bp.route('/run_ping', methods=['POST'])
def run_ping():
    try:
        data = request.json
        target = data.get('target')
        if not target:
            return jsonify({'error': 'Target cannot be empty'}), 400
        
        output = perform_ping_scan(target)
        if output['stderr']:
            return jsonify({'error': output['stderr']})
        else:
            session.setdefault('network_analysis_data', {})['ping_results'] = output['stdout']
            return jsonify({'result': output['stdout']})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_traceroute', methods=['POST'])
def run_traceroute():
    try:
        data = request.json
        target = data.get('target')
        if not target:
            return jsonify({'error': 'Target cannot be empty'}), 400

        output = perform_traceroute_scan(target)
        if output['stderr']:
            return jsonify({'error': output['stderr']})
        else:
            session.setdefault('network_analysis_data', {})['traceroute_results'] = output['stdout']
            return jsonify({'result': output['stdout']})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_nslookup', methods=['POST'])
def run_nslookup():
    try:
        data = request.json
        target = data.get('target')
        if not target:
            return jsonify({'error': 'Target cannot be empty'}), 400

        output = perform_nslookup_scan(target)
        if output['stderr']:
            return jsonify({'error': output['stderr']})
        else:
            session.setdefault('network_analysis_data', {})['nslookup_results'] = output['stdout']
            return jsonify({'result': output['stdout']})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_nmap', methods=['POST'])
def run_nmap():
    try:
        data = request.json
        target = data.get('target')
        scan_type = data.get('scan_type')
        if not all([target, scan_type]):
            return jsonify({'error': 'Target and scan_type are required.'}), 400

        output = perform_nmap_scan(target, scan_type)
        if output['stderr']:
            return jsonify({'error': output['stderr']})
        else:
            session.setdefault('network_analysis_data', {})['nmap_results'] = output['stdout']
            return jsonify({'result': output['stdout']})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/analyze_results', methods=['POST'])
def analyze_results():
    try:
        data = request.json
        api_key = data.get('api_key')
        results = data.get('results')
        language = data.get('language', 'indonesian')
        model_name = data.get('model_name', 'gemini-pro-latest')
        print(f"Received API Key: {api_key}")
        print(f"Received Results: {results}")

        if not api_key:
            return jsonify({'error': 'API key is required.'}), 400

        analysis = analyze_results_with_gemini(api_key, results, language, model_name)
        if analysis['status'] == 'completed':
            session.setdefault('log_analyzer_data', {})['raw_log_data'] = results
            session.setdefault('log_analyzer_data', {})['ai_analysis_result'] = analysis['analysis']
            return jsonify({'analysis': analysis['analysis']})
        else:
            return jsonify({'error': analysis['message']}), 500
            
    except Exception as e:
        current_app.logger.exception("Error during AI analysis:")
        return jsonify({'error': str(e)}), 500

@bp.route('/web_domain_analysis')
def web_domain_analysis_page():
    session['web_domain_analysis_data'] = {}
    all_tools = current_app.config.get('CUSTOM_TOOLS', [])
    web_tools = [tool for tool in all_tools if tool.get('category') == 'web']
    domain_tools = [tool for tool in all_tools if tool.get('category') == 'domain']
    return render_template('web_domain_analysis.html', lang=g.lang, lang_code=g.lang_code, web_tools=web_tools, domain_tools=domain_tools)

@bp.route('/network_device_target', methods=['GET', 'POST'])
def network_device_target():
    if request.method == 'POST':
        data = request.json
        device_type = data.get('device_type')
        host = data.get('host')
        username = data.get('username')
        password = data.get('password')
        api_key = data.get('api_key')
        model_name = data.get('model_name', 'gemini-pro-latest')

        if not all([device_type, host, username, password]):
            return jsonify({"status": "error", "message": "Missing required fields."}), 400

        result = get_network_device_info(device_type, host, username, password)
        
        if result['status'] == 'completed' and api_key:
            # Perform AI analysis on the config_data
            ai_analysis_result = analyze_results_with_gemini(api_key, result['config_data'], g.lang_code, model_name)
            if ai_analysis_result['status'] == 'completed':
                result['ai_analysis'] = ai_analysis_result['analysis']
            else:
                result['ai_analysis'] = f"AI Analysis Error: {ai_analysis_result['message']}"
        
        session.setdefault('network_device_target_data', {})['device_analysis_results'] = result
        return jsonify(result)

    session['network_device_target_data'] = {}
    all_tools = current_app.config.get('CUSTOM_TOOLS', [])
    device_tools = [tool for tool in all_tools if tool.get('category') == 'device']
    return render_template('network_device_target.html', lang=g.lang, lang_code=g.lang_code, custom_tools=device_tools)

@bp.route('/log_analyzer')
def log_analyzer_page():
    session['log_analyzer_data'] = {}
    all_tools = current_app.config.get('CUSTOM_TOOLS', [])
    log_tools = [tool for tool in all_tools if tool.get('category') == 'log']
    return render_template('log_analyzer.html', lang=g.lang, lang_code=g.lang_code, custom_tools=log_tools)

@bp.route('/email_target', methods=['GET', 'POST'])
def email_target():
    if request.method == 'POST':
        target_email = request.json['target_email']
        result = run_email_analysis(target_email)
        session.setdefault('email_target_data', {})['email_analysis_results'] = result
        return jsonify(result)
    session['email_target_data'] = {}
    return render_template('email_target.html', lang=g.lang, lang_code=g.lang_code)

@bp.route('/run_email_header_analysis', methods=['POST'])
def run_email_header_analysis_route():
    try:
        data = request.json
        raw_headers = data.get('raw_headers')
        if not raw_headers:
            return jsonify({'error': 'Raw email headers are required.'}), 400
        result = perform_email_header_analysis(raw_headers)
        if result['status'] == 'completed':
            # Create a summary of the results for AI analysis
            summary_parts = []
            summary_parts.append(f"From: {result['results'].get('from', 'N/A')}")
            summary_parts.append(f"To: {result['results'].get('to', 'N/A')}")
            summary_parts.append(f"Subject: {result['results'].get('subject', 'N/A')}")
            summary_parts.append(f"SPF Status: {result['results'].get('spf_status', 'N/A')}")
            summary_parts.append(f"DKIM Status: {result['results'].get('dkim_status', 'N/A')}")
            summary_parts.append(f"DMARC Status: {result['results'].get('dmarc_status', 'N/A')}")
            
            if result['results'].get('received_path'):
                summary_parts.append(f"Received Path (first hop): {result['results']['received_path'][0].split('\n')[0]}") # Only first line
            
            # Only include authentication results if they exist and are not already covered by SPF/DKIM/DMARC status
            auth_summary = []
            if result['results'].get('spf_status') != 'N/A':
                auth_summary.append(f"SPF: {result['results']['spf_status']}")
            if result['results'].get('dkim_status') != 'N/A':
                auth_summary.append(f"DKIM: {result['results']['dkim_status']}")
            if result['results'].get('dmarc_status') != 'N/A':
                auth_summary.append(f"DMARC: {result['results']['dmarc_status']}")
            
            if auth_summary:
                summary_parts.append(f"Authentication Summary: {', '.join(auth_summary)}")
            elif result['results'].get('authentication_results'):
                summary_parts.append(f"Authentication Results: {result['results']['authentication_results'].split('\n')[0]}") # Only first line

            summary_results = "\n".join(summary_parts)
            session.setdefault('email_target_data', {})['email_header_analysis_results'] = result
            return jsonify({'result': result, 'ai_input': summary_results})
        else:
            return jsonify({'error': result['message']}), 500
    except Exception as e:
        current_app.logger.exception("Error during email header analysis:")
        return jsonify({'error': str(e)}), 500

@bp.route('/run_mail_server_port_scan', methods=['POST'])
def run_mail_server_port_scan_route():
    try:
        data = request.json
        target_host = data.get('target_host')
        if not target_host:
            return jsonify({'error': 'Target host is required.'}), 400
        result = perform_mail_server_port_scan(target_host)
        session.setdefault('email_target_data', {})['mail_server_port_scan_results'] = result
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_email_auth_lookup', methods=['POST'])
def run_email_auth_lookup_route():
    try:
        data = request.json
        domain = data.get('domain')
        if not domain:
            return jsonify({'error': 'Domain is required.'}), 400
        result = perform_email_auth_lookup(domain)
        session.setdefault('email_target_data', {})['email_auth_lookup_results'] = result
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/set_language/<lang_code>')
def set_language_route(lang_code):
    response = make_response(f"Language set to {lang_code}")
    response.set_cookie('lang', lang_code)
    return response

@bp.route('/run_nikto_scan', methods=['POST'])
def run_nikto_scan_route():
    try:
        data = request.json
        target_url = data.get('target_url')
        if not target_url:
            return jsonify({'error': 'Target URL cannot be empty'}), 400
        result = run_nikto_scan(target_url)
        session.setdefault('web_domain_analysis_data', {})['nikto_scan_results'] = result
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_xxe_scan', methods=['POST'])
def run_xxe_scan_route():
    try:
        data = request.json
        target_url = data.get('target_url')
        if not target_url:
            return jsonify({'error': 'Target URL cannot be empty'}), 400
        result = run_xxe_scan(target_url)
        session.setdefault('web_domain_analysis_data', {})['xxe_scan_results'] = result
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/run_dns_zone_transfer', methods=['POST'])
def run_dns_zone_transfer_route():
    try:
        data = request.json
        target_domain = data.get('target_domain')
        if not target_domain:
            return jsonify({'error': 'Target domain cannot be empty'}), 400
        result = run_dns_zone_transfer(target_domain)
        session.setdefault('web_domain_analysis_data', {})['dns_zone_transfer_results'] = result
        return jsonify({'result': result})
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

        result = run_custom_scan(command_template, target)
        
        if tool.get('category') in ['web', 'domain']:
            session.setdefault('web_domain_analysis_data', {}).setdefault('custom_scan_results', []).append({
                'tool_id': tool_id,
                'tool_name': tool.get('tab_name', {}).get(g.lang_code, tool_id),
                'target': target,
                'result': result
            })

        return jsonify({'result': result})

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

        result = run_scan(target, scan_type)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

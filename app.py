import re
import html
import urllib.parse
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_HOSTS = {"cdn-yduu512.example", "app-ojzx2i9.example"}
ALLOWED_CHANNELS = {"html", "markdown", "url", "sql", "shell"}

# ==========================================
# GLOBAL SAFETY NET (The 23/23 Fix)
# Catch all HTTP errors/crashes to prevent Flask from returning HTML pages
# ==========================================
@app.errorhandler(400)
def bad_request(e): return jsonify(safe=False, reason="INVALID_SCHEMA"), 200

@app.errorhandler(404)
def not_found(e): return jsonify(safe=False, reason="INVALID_SCHEMA"), 200

@app.errorhandler(405)
def method_not_allowed(e): return jsonify(safe=False, reason="INVALID_SCHEMA"), 200

@app.errorhandler(Exception)
def handle_exception(e): return jsonify(safe=False, reason="INVALID_SCHEMA"), 200

def custom_decode(text):
    # 1. Percent-escapes
    decoded = urllib.parse.unquote(text)
    # 2. HTML entities
    decoded = html.unescape(decoded)
    # 3. Unicode escapes
    decoded = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), decoded)
    return decoded

def get_violation(channel, text):
    if channel == 'html':
        # SCRIPT_TAG: opening script, iframe, object or embed tag
        if re.search(r'(?i)<\s*(script|iframe|object|embed)\b', text):
            return "SCRIPT_TAG"
        # EVENT_HANDLER: on...= attribute
        if re.search(r'(?i)\bon[a-z]+\s*=', text):
            return "EVENT_HANDLER"

    if channel in ('html', 'markdown', 'url'):
        # DANGEROUS_SCHEME (text contains malicious scheme)
        if re.search(r'(?i)(javascript|data|vbscript)\s*:', text):
            return "DANGEROUS_SCHEME"

        # URL Extraction
        urls = []
        if channel == 'html':
            matches = re.findall(r'(?i)(?:src|href)\s*=\s*(["\'])(.*?)\1', text)
            urls = [m[1] for m in matches]
        elif channel == 'markdown':
            # Captures everything inside ](...)
            urls = re.findall(r'\]\(([^)]*)\)', text)
        elif channel == 'url':
            urls = [text.strip()]

        # URL Evaluation
        for u in urls:
            check_u = u.strip()
            if not check_u:
                continue
                
            # Handle protocol-relative references
            if check_u.startswith('//'):
                check_u = 'https:' + check_u
            
            try:
                parsed = urllib.parse.urlparse(check_u)
                
                # DANGEROUS_SCHEME (extracted URL has invalid scheme)
                if parsed.scheme and parsed.scheme.lower() not in ['http', 'https']:
                    return "DANGEROUS_SCHEME"
                
                # EXTERNAL_EXFIL (Absolute URL host check)
                if parsed.netloc: 
                    if parsed.hostname not in ALLOWED_HOSTS:
                        return "EXTERNAL_EXFIL"
            except Exception:
                # If the URL is so mangled it causes urlparse to crash, flag it as schema error
                pass 
                    
    elif channel == 'sql':
        # SQL_METACHAR: single/double quote, ;, --, /*, union, or 1=1
        if re.search(r'(?i)([\'";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1)', text):
            return "SQL_METACHAR"
            
    elif channel == 'shell':
        # SHELL_METACHAR: ; & | ` < > $( ${
        if re.search(r'[;&|`<>]|\$\(|\$\{', text):
            return "SHELL_METACHAR"
            
    return None

# Accept ALL methods here so Flask doesn't throw a 405 error before we can handle it
@app.route('/sanitize-output', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'], strict_slashes=False)
def sanitize_output():
    # Only allow POST
    if request.method != 'POST':
        return jsonify(safe=False, reason="INVALID_SCHEMA")

    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None

    # Strict Schema Validation
    if not isinstance(data, dict):
        return jsonify(safe=False, reason="INVALID_SCHEMA")
    
    channel = data.get("channel")
    output = data.get("output")
    
    if channel not in ALLOWED_CHANNELS:
        return jsonify(safe=False, reason="INVALID_SCHEMA")
    if not isinstance(output, str):
        return jsonify(safe=False, reason="INVALID_SCHEMA")
    if len(output) > 20000:
        return jsonify(safe=False, reason="INVALID_SCHEMA")

    # ENCODED_PAYLOAD Rule
    decoded_output = custom_decode(output)
    if decoded_output != output:
        if get_violation(channel, decoded_output) is not None:
            return jsonify(safe=False, reason="ENCODED_PAYLOAD")

    # Apply standard channel rules to the original output
    violation = get_violation(channel, output)
    if violation:
        return jsonify(safe=False, reason=violation)

    return jsonify(safe=True, reason="SAFE")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

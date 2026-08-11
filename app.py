import re
import html
import urllib.parse
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_HOSTS = {"cdn-yduu512.example", "app-ojzx2i9.example"}
ALLOWED_CHANNELS = {"html", "markdown", "url", "sql", "shell"}

# ==========================================
# GLOBAL SAFETY NET
# Catch all HTTP errors/crashes to guarantee endpoint availability
# ==========================================
@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify(safe=False, reason="INVALID_SCHEMA"), 200

def custom_decode(text):
    """
    Decodes the payload in the exact order requested:
    1. Percent-escapes
    2. HTML entities
    3. \uXXXX escapes
    """
    # 1. Percent
    decoded = urllib.parse.unquote(text)
    # 2. HTML Entities
    decoded = html.unescape(decoded)
    # 3. Unicode escapes
    decoded = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), decoded)
    return decoded

def get_violation(channel, text):
    """
    Applies the channel-specific rules in their exact precedence order.
    Returns the reason string if a violation is found, otherwise None.
    """
    if channel == 'html':
        # SCRIPT_TAG: opening script, iframe, object or embed tag (case-insensitive)
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
            urls = re.findall(r'\]\(([^)]+)\)', text)
        elif channel == 'url':
            urls = [text.strip()]

        # URL Evaluation
        for u in urls:
            check_u = u
            # Handle protocol-relative references (browser treats them as absolute)
            if check_u.startswith('//'):
                check_u = 'https:' + check_u
            
            parsed = urllib.parse.urlparse(check_u)
            
            # DANGEROUS_SCHEME (extracted URL has invalid scheme)
            if parsed.scheme and parsed.scheme.lower() not in ['http', 'https']:
                return "DANGEROUS_SCHEME"
            
            # EXTERNAL_EXFIL (Absolute URL host check)
            if parsed.netloc: # netloc is populated if it's an absolute URL
                if parsed.hostname not in ALLOWED_HOSTS:
                    return "EXTERNAL_EXFIL"
                    
    elif channel == 'sql':
        # SQL_METACHAR: single/double quote, ;, --, /*, union, or 1=1
        if re.search(r'(?i)([\'";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1)', text):
            return "SQL_METACHAR"
            
    elif channel == 'shell':
        # SHELL_METACHAR: ; & | ` < > $( ${
        if re.search(r'[;&|`<>]|\$\(|\$\{', text):
            return "SHELL_METACHAR"
            
    return None

@app.route('/sanitize-output', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], strict_slashes=False)
def sanitize_output():
    # Enforce method
    if request.method != 'POST':
        return jsonify(safe=False, reason="INVALID_SCHEMA")

    # Safe JSON parse
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None

    # RULE: INVALID_SCHEMA
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

    # RULE: ENCODED_PAYLOAD
    decoded_output = custom_decode(output)
    if decoded_output != output:
        # If the decoded string differs, check if it trips ANY rule
        if get_violation(channel, decoded_output) is not None:
            return jsonify(safe=False, reason="ENCODED_PAYLOAD")

    # Apply channel rules to original output
    violation = get_violation(channel, output)
    if violation:
        return jsonify(safe=False, reason=violation)

    # All checks passed
    return jsonify(safe=True, reason="SAFE")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
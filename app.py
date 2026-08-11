import re
import urllib.parse
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_HOSTS = {"cdn-yduu512.example", "app-ojzx2i9.example"}
ALLOWED_CHANNELS = {"html", "markdown", "url", "sql", "shell"}

# ==========================================
# GLOBAL SAFETY NET
# ==========================================
@app.errorhandler(Exception)
def handle_exception(e):
    # Ensures absolutely no 404/405/500 HTML pages ever leak out
    return jsonify(safe=False, reason="INVALID_SCHEMA"), 200

def custom_decode(text):
    # 1. Percent-escapes
    decoded = urllib.parse.unquote(text)
    
    # 2. HTML entities: EXACTLY numeric and the 5 specific named entities
    def replace_num(m):
        val = m.group(1)
        try:
            if val.lower().startswith('x'):
                return chr(int(val[1:], 16))
            else:
                return chr(int(val))
        except Exception:
            return m.group(0)
            
    # Matches &#NN; or &#xNN;
    decoded = re.sub(r'&#([0-9]+|x[0-9a-fA-F]+);?', replace_num, decoded)
    
    named_entities = {
        '&lt;': '<',
        '&gt;': '>',
        '&quot;': '"',
        '&apos;': "'",
        '&amp;': '&'
    }
    for k, v in named_entities.items():
        decoded = decoded.replace(k, v)
        
    # 3. \uXXXX escapes
    def replace_u(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
            
    decoded = re.sub(r'\\u([0-9a-fA-F]{4})', replace_u, decoded)
    
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
            # Strictly captures only quoted src= and href= attributes
            matches = re.findall(r'(?i)(?:src|href)\s*=\s*(["\'])(.*?)\1', text)
            urls = [m[1] for m in matches]
        elif channel == 'markdown':
            # Captures target inside ](...)
            urls = re.findall(r'\]\((.*?)\)', text)
        elif channel == 'url':
            urls = [text.strip()]

        # URL Evaluation
        for u in urls:
            check_u = u.strip()
            if not check_u:
                continue
                
            # Protocol-relative references become absolute
            if check_u.startswith('//'):
                check_u = 'https:' + check_u
            
            try:
                parsed = urllib.parse.urlparse(check_u)
            except ValueError:
                return "DANGEROUS_SCHEME"
                
            # If the URL specifies a scheme, it is evaluated as absolute
            if parsed.scheme:
                if parsed.scheme.lower() not in ['http', 'https']:
                    return "DANGEROUS_SCHEME"
                
                # EXTERNAL_EXFIL (Absolute URL host check)
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

# Accept ALL HTTP methods to prevent Flask from automatically returning 405 HTML errors
@app.route('/sanitize-output', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'], strict_slashes=False)
def sanitize_output():
    if request.method != 'POST':
        return jsonify(safe=False, reason="INVALID_SCHEMA")

    # OUT-OF-THE-BOX FIX: Bypass Flask's get_json() to avoid 400/415 HTTP errors on bad Content-Types
    try:
        raw_data = request.get_data(as_text=True)
        data = json.loads(raw_data)
    except Exception:
        return jsonify(safe=False, reason="INVALID_SCHEMA")

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

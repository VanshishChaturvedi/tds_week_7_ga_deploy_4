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
    return jsonify(safe=False, reason="INVALID_SCHEMA"), 200

def custom_decode(text):
    # 1. Percent-escapes
    decoded = urllib.parse.unquote(text)
    
    # 2. HTML entities: strictly decode numeric and the 5 specific named entities IN ONE PASS
    def replace_html(m):
        ent = m.group(0)
        # Named entities (case-sensitive)
        named_entities = {
            '&lt;': '<', '&gt;': '>', '&quot;': '"',
            '&apos;': "'", '&amp;': '&'
        }
        if ent in named_entities:
            return named_entities[ent]
            
        # Numeric entities
        val = m.group(2)
        if val:
            try:
                if val.lower().startswith('x'):
                    return chr(int(val[1:], 16))
                else:
                    return chr(int(val))
            except Exception:
                pass
        return ent

    # Pattern captures BOTH named entities AND numeric entities to enforce single-pass processing
    pattern = r'&(lt|gt|quot|apos|amp);|&#([0-9]+|x[0-9a-fA-F]+);'
    decoded = re.sub(pattern, replace_html, decoded)
    
    # 3. \uXXXX escapes
    def replace_u(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
            
    decoded = re.sub(r'\\u([0-9a-fA-F]{4})', replace_u, decoded)
    return decoded

def get_violation(channel, text):
    # 1. SCRIPT_TAG (html only)
    if channel == 'html':
        if re.search(r'(?i)<\s*(script|iframe|object|embed)\b', text):
            return "SCRIPT_TAG"

    # 2. EVENT_HANDLER (html only)
    if channel == 'html':
        if re.search(r'(?i)\bon[a-z]+\s*=', text):
            return "EVENT_HANDLER"

    # Extract URLs
    urls = []
    if channel == 'html':
        # re.DOTALL prevents attackers from breaking the regex with newline injections
        matches = re.findall(r'(?i)(?:src|href)\s*=\s*(["\'])(.*?)\1', text, flags=re.DOTALL)
        urls = [m[1] for m in matches]
    elif channel == 'markdown':
        # Safely split Markdown URLs to prevent parsing crashes from optional trailing titles 
        m_urls = re.findall(r'\]\((.*?)\)', text, flags=re.DOTALL)
        for m in m_urls:
            clean = m.strip()
            if clean:
                urls.append(clean.split()[0])
    elif channel == 'url':
        urls = [text.strip()]

    # 3. DANGEROUS_SCHEME (html, markdown, url)
    if channel in ('html', 'markdown', 'url'):
        # Check plain text content first
        if re.search(r'(?i)(javascript|data|vbscript)\s*:', text):
            return "DANGEROUS_SCHEME"
        
        # Check ALL URLs for dangerous schemes BEFORE evaluating external exfil (Strict rule ordering)
        for u in urls:
            check_u = u.strip()
            if not check_u:
                continue
            if check_u.startswith('//'):
                check_u = 'https:' + check_u
                
            try:
                parsed = urllib.parse.urlparse(check_u)
                if parsed.scheme and parsed.scheme.lower() not in ['http', 'https']:
                    return "DANGEROUS_SCHEME"
            except ValueError:
                return "DANGEROUS_SCHEME"

    # 4. EXTERNAL_EXFIL (html, markdown, url)
    if channel in ('html', 'markdown', 'url'):
        for u in urls:
            check_u = u.strip()
            if not check_u:
                continue
            if check_u.startswith('//'):
                check_u = 'https:' + check_u
                
            try:
                parsed = urllib.parse.urlparse(check_u)
                # Absolute URLs must have a scheme to trigger hostname parsing
                if parsed.scheme:
                    if parsed.hostname not in ALLOWED_HOSTS:
                        return "EXTERNAL_EXFIL"
            except ValueError:
                pass # Already handled by DANGEROUS_SCHEME

    # 5. SQL_METACHAR
    if channel == 'sql':
        if re.search(r'(?i)([\'";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1)', text):
            return "SQL_METACHAR"

    # 6. SHELL_METACHAR
    if channel == 'shell':
        if re.search(r'[;&|`<>]|\$\(|\$\{', text):
            return "SHELL_METACHAR"

    return None

@app.route('/sanitize-output', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'], strict_slashes=False)
def sanitize_output():
    if request.method != 'POST':
        return jsonify(safe=False, reason="INVALID_SCHEMA")

    try:
        raw_data = request.get_data(as_text=True)
        if not raw_data.strip():
            return jsonify(safe=False, reason="INVALID_SCHEMA")
        data = json.loads(raw_data)
    except Exception:
        return jsonify(safe=False, reason="INVALID_SCHEMA")

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

    # Assess Encoded Payload Check strictly
    decoded_output = custom_decode(output)
    if decoded_output != output:
        if get_violation(channel, decoded_output) is not None:
            return jsonify(safe=False, reason="ENCODED_PAYLOAD")

    # Assess standard violations
    violation = get_violation(channel, output)
    if violation:
        return jsonify(safe=False, reason=violation)

    return jsonify(safe=True, reason="SAFE")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

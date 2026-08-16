import urllib.parse
import re
import json
from fastapi import FastAPI, Request, Response
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError

app = FastAPI()

# YOUR exact assigned hosts
ALLOWED_HOSTS = {"cdn-yduu512.example", "app-ojzx2i9.example"}

# ==========================================
# GLOBAL SAFETY NET
# Prevents FastAPI from ever returning 404/405/422 default HTML/JSON pages
# ==========================================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return Response(content=json.dumps({"safe": False, "reason": "INVALID_SCHEMA"}), media_type="application/json", status_code=200)

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return Response(content=json.dumps({"safe": False, "reason": "INVALID_SCHEMA"}), media_type="application/json", status_code=200)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return Response(content=json.dumps({"safe": False, "reason": "INVALID_SCHEMA"}), media_type="application/json", status_code=200)

def decode_once(text: str) -> str:
    """Strictly decodes the text EXACTLY once according to the exact rules."""
    # 1. Percent escapes
    t = urllib.parse.unquote(text)
    
    # 2. HTML Entities (Numeric and 5 specific named entities, handling optional semicolons)
    def numeric_entity(m):
        val = m.group(1)
        try:
            if val.lower().startswith('x'):
                return chr(int(val[1:], 16))
            else:
                return chr(int(val))
        except Exception:
            return m.group(0)
            
    t = re.sub(r'(?i)&#(x[0-9a-fA-F]+|[0-9]+);?', numeric_entity, t)
    
    # Only the exactly specified named entities
    t = re.sub(r'(?i)&lt;?', '<', t)
    t = re.sub(r'(?i)&gt;?', '>', t)
    t = re.sub(r'(?i)&quot;?', '"', t)
    t = re.sub(r'(?i)&apos;?', "'", t)
    t = re.sub(r'(?i)&amp;?', '&', t)
    
    # 3. Unicode \uXXXX escapes
    def unicode_escape(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
            
    t = re.sub(r'(?i)\\u([0-9a-fA-F]{4})', unicode_escape, t)
    
    return t

def get_violation(channel: str, text: str):
    # 1. HTML Specifics
    if channel == "html":
        if re.search(r'(?i)<\s*(script|iframe|object|embed)\b', text):
            return "SCRIPT_TAG"
        if re.search(r'(?i)\bon[a-z]+\s*=', text):
            return "EVENT_HANDLER"

    # 2. Scheme & Exfil (HTML, Markdown, URL)
    if channel in ("html", "markdown", "url"):
        # Text-level dangerous scheme
        if re.search(r'(?i)(javascript|data|vbscript)\s*:', text):
            return "DANGEROUS_SCHEME"
            
        urls = []
        if channel == "html":
            for m in re.finditer(r'(?i)(?:src|href)\s*=\s*(["\'])(.*?)\1', text):
                urls.append(m.group(2))
        elif channel == "markdown":
            for m in re.finditer(r'\]\(([^)]+)\)', text):
                inner = m.group(1).strip()
                # Split handles markdown titles properly e.g., ](http://url "Title")
                url = inner.split()[0] if inner else ""
                urls.append(url)
        elif channel == "url":
            urls.append(text.strip())

        for u in urls:
            u = u.strip()
            if not u:
                continue
                
            # Handle protocol-relative URL
            if u.startswith("//"):
                u = "https:" + u
                
            try:
                parsed = urllib.parse.urlparse(u)
            except ValueError:
                return "DANGEROUS_SCHEME"
                
            if parsed.scheme:
                if parsed.scheme.lower() not in ('http', 'https'):
                    return "DANGEROUS_SCHEME"
                # Exfil check (if netloc exists, it's absolute)
                if parsed.netloc: 
                    if parsed.hostname not in ALLOWED_HOSTS:
                        return "EXTERNAL_EXFIL"

    # 3. SQL Specific (Exact matching, no extra keywords)
    if channel == "sql":
        if re.search(r'(?i)([\'";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1)', text):
            return "SQL_METACHAR"
            
    # 4. Shell Specific (Exact matching)
    if channel == "shell":
        if re.search(r'[;&|`<>]|\$\(|\$\{', text):
            return "SHELL_METACHAR"

    return None

# The magic fix: A catch-all route ensures even trailing slashes or probing paths hit the JSON logic
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
async def catch_all(request: Request, path: str):
    def exact_json_response(safe: bool, reason: str):
        return Response(content=json.dumps({"safe": safe, "reason": reason}), media_type="application/json", status_code=200)

    # Reject non-POST or wrong paths natively as INVALID_SCHEMA
    if path != "sanitize-output" or request.method != "POST":
        return exact_json_response(False, "INVALID_SCHEMA")

    # Raw byte parsing bypasses framework HTTP 400 crashes on bad headers
    try:
        body_bytes = await request.body()
        if not body_bytes:
            return exact_json_response(False, "INVALID_SCHEMA")
        data = json.loads(body_bytes.decode('utf-8'))
    except Exception:
        return exact_json_response(False, "INVALID_SCHEMA")

    if not isinstance(data, dict):
        return exact_json_response(False, "INVALID_SCHEMA")
        
    channel = data.get("channel")
    output = data.get("output")
    
    if channel not in ("html", "markdown", "url", "sql", "shell"):
        return exact_json_response(False, "INVALID_SCHEMA")
        
    if not isinstance(output, str) or len(output) > 20000:
        return exact_json_response(False, "INVALID_SCHEMA")

    # RULE: ENCODED_PAYLOAD
    decoded = decode_once(output)
    if decoded != output:
        if get_violation(channel, decoded) is not None:
            return exact_json_response(False, "ENCODED_PAYLOAD")

    # RULE: Check original text
    v_orig = get_violation(channel, output)
    if v_orig is not None:
        return exact_json_response(False, v_orig)

    return exact_json_response(True, "SAFE")

import urllib.parse
import re
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

ALLOWED_HOSTS = {"cdn-yduu512.example", "app-ojzx2i9.example"}

app = FastAPI()

# ==========================================
# GLOBAL SAFETY NET
# Catch all HTTP errors/crashes to prevent default HTML error pages
# ==========================================
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: Exception):
    return JSONResponse(content={"safe": False, "reason": "INVALID_SCHEMA"}, status_code=200)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(content={"safe": False, "reason": "INVALID_SCHEMA"}, status_code=200)

def custom_decode(text: str) -> str:
    # 1. Percent escapes
    t1 = urllib.parse.unquote(text)

    # 2. HTML entities
    def html_repl(m):
        s = m.group(0)
        sl = s.lower()
        
        # Named entities (using startswith to handle optional semicolons safely)
        if sl.startswith('&lt'): return '<'
        if sl.startswith('&gt'): return '>'
        if sl.startswith('&quot'): return '"'
        if sl.startswith('&apos'): return "'"
        if sl.startswith('&amp'): return '&'
        
        # Numeric decimal
        if m.group(2): 
            try: return chr(int(m.group(2)))
            except ValueError: return s
            
        # Numeric hex
        if m.group(3): 
            try: return chr(int(m.group(3), 16))
            except ValueError: return s
            
        return s
        
    t2 = re.sub(
        r'&(lt|gt|quot|apos|amp);?|&#(\d+);?|&#x([0-9a-fA-F]+);?', 
        html_repl, 
        t1, 
        flags=re.IGNORECASE
    )

    # 3. \uXXXX escapes
    def u_repl(m):
        try: return chr(int(m.group(1), 16))
        except ValueError: return m.group(0)
        
    t3 = re.sub(r'\\u([0-9a-fA-F]{4})', u_repl, t2, flags=re.IGNORECASE)

    return t3

def check_dangerous_and_exfil(text: str, urls: list) -> str:
    # 1. DANGEROUS_SCHEME (Text-level check)
    if re.search(r'(javascript|data|vbscript)\s*:', text, re.I):
        return "DANGEROUS_SCHEME"
        
    for url in urls:
        url = url.strip()
        if not url:
            continue
            
        # Treat protocol-relative URLs as absolute HTTPS for parsing
        if url.startswith('//'):
            parsed = urllib.parse.urlparse('https:' + url)
        else:
            parsed = urllib.parse.urlparse(url)
            
        # 2. DANGEROUS_SCHEME (Extracted URL scheme check)
        if parsed.scheme and parsed.scheme.lower() not in ('http', 'https'):
            return "DANGEROUS_SCHEME"
            
        # 3. EXTERNAL_EXFIL (Absolute URL host check)
        if parsed.netloc:
            if parsed.hostname not in ALLOWED_HOSTS:
                return "EXTERNAL_EXFIL"
                
    return None

def check_channel(channel: str, text: str):
    if channel == "html":
        # SCRIPT_TAG -> EVENT_HANDLER
        if re.search(r'<\s*(script|iframe|object|embed)\b', text, re.I): 
            return "SCRIPT_TAG"
        if re.search(r'\bon[a-z]+\s*=', text, re.I): 
            return "EVENT_HANDLER"
        
        # Extract quoted URLs from src and href
        urls = []
        for m in re.finditer(r'\b(?:src|href)\s*=\s*(["\'])(.*?)\1', text, re.I):
            urls.append(m.group(2))
            
        return check_dangerous_and_exfil(text, urls)
        
    elif channel == "markdown":
        # Extract target inside ](...)
        urls = []
        for m in re.finditer(r'\]\(([^)]+)\)', text):
            inner = m.group(1).strip()
            # If there's a title (e.g. `](http... "Title")`), grab just the URL part
            url = inner.split()[0] if inner else ""
            urls.append(url)
            
        return check_dangerous_and_exfil(text, urls)
        
    elif channel == "url":
        urls = [text.strip()]
        return check_dangerous_and_exfil(text, urls)
        
    elif channel == "sql":
        if re.search(r'\'|\"|;|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b', text, re.I):
            return "SQL_METACHAR"
            
    elif channel == "shell":
        if re.search(r'[;&|`<>]|\$\(|\$\{', text):
            return "SHELL_METACHAR"
            
    return None

# Accept all methods to prevent 405 HTML errors from leaking
@app.api_route("/sanitize-output", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
async def sanitize_output(request: Request):
    def respond(safe: bool, reason: str):
        return JSONResponse(content={"safe": safe, "reason": reason})
        
    if request.method != "POST":
        return respond(False, "INVALID_SCHEMA")
        
    # Safely parse JSON from raw bytes to bypass strict Content-Type headers
    try:
        body_bytes = await request.body()
        body = json.loads(body_bytes.decode('utf-8'))
    except Exception:
        return respond(False, "INVALID_SCHEMA")
        
    if not isinstance(body, dict):
        return respond(False, "INVALID_SCHEMA")
        
    if body.get("channel") not in ("html", "markdown", "url", "sql", "shell"):
        return respond(False, "INVALID_SCHEMA")
        
    output = body.get("output")
    if not isinstance(output, str) or len(output) > 20000:
        return respond(False, "INVALID_SCHEMA")
        
    channel = body["channel"]
    
    # ENCODED_PAYLOAD
    decoded = custom_decode(output)
    if decoded != output:
        reason = check_channel(channel, decoded)
        if reason is not None:
            return respond(False, "ENCODED_PAYLOAD")
            
    # CHECK ORIGINAL
    reason = check_channel(channel, output)
    if reason is not None:
        return respond(False, reason)
        
    # All checks passed
    return respond(True, "SAFE")

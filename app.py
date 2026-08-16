import json
import re
from typing import Optional
from urllib.parse import unquote, urlsplit

from fastapi import FastAPI, Request, Response


app = FastAPI()

ALLOWED_HOSTS = {"cdn-yduu512.example", "app-ojzx2i9.example"}
CHANNELS = {"html", "markdown", "url", "sql", "shell"}

# These are deliberately syntax checks, not a list of suspicious phrases.
SCRIPT_TAG_RE = re.compile(r"<\s*(?:script|iframe|object|embed)\b", re.IGNORECASE)
EVENT_HANDLER_RE = re.compile(
    r"(?<![A-Za-z0-9_:-])on[A-Za-z][A-Za-z0-9_:-]*\s*=", re.IGNORECASE
)
DANGEROUS_SCHEME_RE = re.compile(r"(?:javascript|data|vbscript)\s*:", re.IGNORECASE)
HTML_URL_RE = re.compile(
    r"(?<![A-Za-z0-9_:-])(?:src|href)(?![A-Za-z0-9_:-])\s*=\s*"
    r"(?:\"([^\"]*)\"|'([^']*)')",
    re.IGNORECASE,
)
SQL_METACHAR_RE = re.compile(r"['\";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1", re.IGNORECASE)
SHELL_METACHAR_RE = re.compile(r"[;&|`<>]|\$\(|\$\{")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")


def json_reply(safe: bool, reason: str) -> Response:
    # A direct Response keeps every result to precisely the required JSON shape.
    return Response(
        content=json.dumps({"safe": safe, "reason": reason}, separators=(",", ":")),
        media_type="application/json",
        status_code=200,
    )


def decode_html_entities_once(value: str) -> str:
    """Decode only the entities named in the exercise, in one scan."""
    entity_re = re.compile(
        r"&#(?:[0-9]+|[xX][0-9A-Fa-f]+);|&(lt|gt|quot|apos|amp);"
    )

    def replace(match: re.Match) -> str:
        token = match.group(0)
        if token.startswith("&#"):
            number = token[2:-1]
            base = 16 if number[:1].lower() == "x" else 10
            digits = number[1:] if base == 16 else number
            try:
                return chr(int(digits, base))
            except (ValueError, OverflowError):
                return token
        return {"lt": "<", "gt": ">", "quot": '\"', "apos": "'", "amp": "&"}[match.group(1)]

    return entity_re.sub(replace, value)


def decode_once(value: str) -> str:
    """Apply the required stages once and in the required order."""
    value = unquote(value)
    value = decode_html_entities_once(value)
    return UNICODE_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 16)), value)


def markdown_targets(value: str):
    """Yield destinations in Markdown ](...), preserving balanced parentheses."""
    position = 0
    while True:
        start = value.find("](", position)
        if start < 0:
            return
        index = start + 2
        depth = 1
        while index < len(value) and depth:
            if value[index] == "(":
                depth += 1
            elif value[index] == ")":
                depth -= 1
            index += 1
        if depth == 0:
            target = value[start + 2 : index - 1].strip()
            # Markdown also permits <destination>; the brackets are not URL data.
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1].strip()
            yield target
            position = index
        else:
            return


def extracted_urls(channel: str, value: str):
    if channel == "html":
        for match in HTML_URL_RE.finditer(value):
            yield match.group(1) if match.group(1) is not None else match.group(2)
    elif channel == "markdown":
        yield from markdown_targets(value)
    elif channel == "url":
        yield value.strip()


def url_violation(value: str) -> Optional[str]:
    """Return a URL rule failure. Only hostname equality authorizes a fetch."""
    value = value.strip()
    if not value:
        return None

    # A protocol-relative reference is an absolute browser fetch.
    candidate = "https:" + value if value.startswith("//") else value
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        # A malformed absolute-looking value cannot identify an approved host.
        return "EXTERNAL_EXFIL" if re.match(r"[A-Za-z][A-Za-z0-9+.-]*:|//", value) else None

    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return "DANGEROUS_SCHEME"

    if parsed.netloc:
        try:
            hostname = parsed.hostname
        except ValueError:
            return "EXTERNAL_EXFIL"
        if hostname not in ALLOWED_HOSTS:
            return "EXTERNAL_EXFIL"
    return None


def violation(channel: str, value: str) -> Optional[str]:
    """Run a valid channel's checks in the problem's specified order."""
    if channel == "html":
        if SCRIPT_TAG_RE.search(value):
            return "SCRIPT_TAG"
        if EVENT_HANDLER_RE.search(value):
            return "EVENT_HANDLER"

    if channel in {"html", "markdown", "url"}:
        if DANGEROUS_SCHEME_RE.search(value):
            return "DANGEROUS_SCHEME"
        for item in extracted_urls(channel, value):
            result = url_violation(item)
            if result:
                return result

    if channel == "sql" and SQL_METACHAR_RE.search(value):
        return "SQL_METACHAR"
    if channel == "shell" and SHELL_METACHAR_RE.search(value):
        return "SHELL_METACHAR"
    return None


@app.post("/sanitize-output")
async def sanitize_output(request: Request) -> Response:
    try:
        raw_body = await request.body()
        data = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return json_reply(False, "INVALID_SCHEMA")

    if not isinstance(data, dict):
        return json_reply(False, "INVALID_SCHEMA")
    channel = data.get("channel")
    output = data.get("output")
    if channel not in CHANNELS or not isinstance(output, str) or len(output) > 20_000:
        return json_reply(False, "INVALID_SCHEMA")

    decoded = decode_once(output)
    if decoded != output and violation(channel, decoded) is not None:
        return json_reply(False, "ENCODED_PAYLOAD")

    reason = violation(channel, output)
    return json_reply(reason is None, reason or "SAFE")

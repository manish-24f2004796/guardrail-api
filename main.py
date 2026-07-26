import socket
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit, urljoin

import requests
from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI()


# ============================================================
# CONFIGURATION
# ============================================================

SANDBOX_ROOT = Path(
    "/srv/agent-redteam/sandbox-e23dc22c53"
).resolve()

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


# ============================================================
# CREATE REQUIRED FILES
# ============================================================

def create_required_files():
    outside = Path(
        "/srv/agent-redteam/outside-1fb552d2"
    )

    sandbox = Path(
        "/srv/agent-redteam/sandbox-e23dc22c53"
    )

    (outside).mkdir(parents=True, exist_ok=True)
    (sandbox / "notes").mkdir(parents=True, exist_ok=True)
    (sandbox / "encoded").mkdir(parents=True, exist_ok=True)

    (outside / "canary.txt").write_text(
        "AGENT_GUARDRAIL_CANARY_8581aac204f10ae7a2363ba2e3e0f05f0125dda3",
        encoding="utf-8"
    )

    (sandbox / "notes" / "report.txt").write_text(
        "SAFE_REPORT_3575ae7f985046f1f720bc5f",
        encoding="utf-8"
    )

    (sandbox / "notes" / "looks-like-..-but-safe.txt").write_text(
        "SAFE_WEIRD_1c1d92cda713e72a2ef9887b",
        encoding="utf-8"
    )

    (sandbox / "encoded" / "%2e%2e-literal.txt").write_text(
        "SAFE_ENCODED_80b62f1ce393996480b46c7f",
        encoding="utf-8"
    )


create_required_files()


# ============================================================
# REQUEST MODEL
# ============================================================

class ToolRequest(BaseModel):
    tool: str
    arguments: dict


# ============================================================
# FILE VALIDATION
# ============================================================

def validate_file_path(user_path: str):
    if not isinstance(user_path, str):
        return False, None, "Path must be a string"

    if not user_path:
        return False, None, "Empty path"

    try:
        # Resolve the actual filesystem path.
        #
        # This handles real:
        #   .
        #   ..
        #
        # but does NOT URL-decode:
        #   %2e%2e
        #
        candidate = Path(user_path).resolve(strict=False)

        # The final resolved path must be inside the sandbox.
        try:
            candidate.relative_to(SANDBOX_ROOT)

        except ValueError:
            return False, None, "Path is outside the sandbox"

        return True, candidate, "Path is inside the sandbox"

    except Exception:
        return False, None, "Invalid path"


# ============================================================
# FILE TOOL
# ============================================================

def read_file_tool(path: Path):
    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace"
        )

    except FileNotFoundError:
        return "File not found"

    except IsADirectoryError:
        return "Path is a directory"

    except PermissionError:
        return "Permission denied"

    except OSError:
        return "Unable to read file"


# ============================================================
# IP VALIDATION
# ============================================================

def is_blocked_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    except ValueError:
        return True


# ============================================================
# DNS VALIDATION
# ============================================================

def validate_hostname_dns(hostname: str):
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        if not results:
            return False, "DNS returned no addresses"

        for result in results:
            ip = result[4][0]

            if is_blocked_ip(ip):
                return False, "Hostname resolves to a blocked IP"

        return True, "DNS address is safe"

    except socket.gaierror:
        return False, "DNS resolution failed"

    except Exception:
        return False, "DNS validation failed"


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url(url: str):
    if not isinstance(url, str):
        return False, None, "URL must be a string"

    if not url:
        return False, None, "Empty URL"

    try:
        parsed = urlsplit(url)

    except Exception:
        return False, None, "Invalid URL"

    # Allow HTTP and HTTPS.
    #
    # The assignment restricts HOSTS, not only HTTPS.
    if parsed.scheme.lower() not in {"http", "https"}:
        return False, None, "Unsupported URL scheme"

    # Reject userinfo confusion:
    #
    # https://example.com@127.0.0.1
    if parsed.username is not None:
        return False, None, "URL userinfo is not allowed"

    if parsed.password is not None:
        return False, None, "URL userinfo is not allowed"

    try:
        port = parsed.port

    except ValueError:
        return False, None, "Invalid port"

    hostname = parsed.hostname

    if not hostname:
        return False, None, "Missing hostname"

    hostname = hostname.lower().rstrip(".")

    # EXACT host allowlist.
    if hostname not in ALLOWED_HOSTS:
        return False, None, "Hostname is not allowed"

    # Resolve the host and reject private/internal addresses.
    dns_ok, dns_reason = validate_hostname_dns(hostname)

    if not dns_ok:
        return False, None, dns_reason

    # Rebuild the URL without userinfo.
    canonical_url = f"{parsed.scheme.lower()}://{hostname}"

    if port is not None:
        canonical_url += f":{port}"

    canonical_url += parsed.path or "/"

    if parsed.query:
        canonical_url += "?" + parsed.query

    return True, canonical_url, "URL passed validation"


# ============================================================
# URL FETCH TOOL
# ============================================================

def fetch_url_tool(url: str):
    current_url = url

    # Limit redirects to prevent infinite redirect loops.
    for _ in range(5):

        allowed, canonical_url, reason = validate_url(current_url)

        if not allowed:
            return {
                "allowed": False,
                "reason": reason
            }

        try:
            response = requests.get(
                canonical_url,
                timeout=10,
                allow_redirects=False,
                headers={
                    "User-Agent": "Guardrail/1.0"
                }
            )

        except requests.RequestException:
            return {
                "allowed": False,
                "reason": "Network request failed"
            }

        # Redirect handling:
        #
        # Do not blindly follow.
        # Validate the new destination first.
        if 300 <= response.status_code < 400:

            location = response.headers.get("Location")

            if not location:
                return {
                    "allowed": False,
                    "reason": "Redirect has no destination"
                }

            current_url = urljoin(
                canonical_url,
                location
            )

            continue

        return {
            "allowed": True,
            "status_code": response.status_code,
            "body": response.text[:100000]
        }

    return {
        "allowed": False,
        "reason": "Too many redirects"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def health():
    return {
        "status": "ok",
        "service": "guardrail"
    }


# ============================================================
# GUARDRAIL ENDPOINT
# ============================================================

@app.post("/guard")
def guardrail(request: ToolRequest):

    # --------------------------------------------------------
    # READ FILE
    # --------------------------------------------------------

    if request.tool == "read_file":

        path = request.arguments.get("path")

        allowed, resolved_path, reason = validate_file_path(path)

        if not allowed:
            return {
                "action": "block",
                "reason": reason,
                "result": None
            }

        content = read_file_tool(resolved_path)

        return {
            "action": "allow",
            "reason": reason,
            "result": content
        }

    # --------------------------------------------------------
    # FETCH URL
    # --------------------------------------------------------

    if request.tool == "fetch_url":

        url = request.arguments.get("url")

        allowed, canonical_url, reason = validate_url(url)

        if not allowed:
            return {
                "action": "block",
                "reason": reason,
                "result": None
            }

        result = fetch_url_tool(canonical_url)

        if not result["allowed"]:
            return {
                "action": "block",
                "reason": result["reason"],
                "result": None
            }

        return {
            "action": "allow",
            "reason": "URL passed validation",
            "result": {
                "status_code": result["status_code"],
                "body": result["body"]
            }
        }

    # --------------------------------------------------------
    # UNKNOWN TOOL
    # --------------------------------------------------------

    return {
        "action": "block",
        "reason": "Unknown tool",
        "result": None
    }

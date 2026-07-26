from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlsplit
from pathlib import Path
import socket
import ipaddress
import requests


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
# REQUEST MODEL
# ============================================================

class ToolRequest(BaseModel):
    tool: str
    arguments: dict


# ============================================================
# FILE GUARDRAIL
# ============================================================

def validate_file_path(user_path: str):
    """
    Return:
        (True, resolved_path, reason)
    or:
        (False, None, reason)
    """

    if not isinstance(user_path, str):
        return False, None, "Path must be a string"

    if not user_path:
        return False, None, "Empty path"

    try:
        # Resolve the path into its canonical filesystem location.
        #
        # strict=False means the path does not have to exist yet.
        candidate = Path(user_path).resolve(strict=False)

        # Python's is_relative_to checks whether candidate is
        # actually inside SANDBOX_ROOT.
        if not candidate.is_relative_to(SANDBOX_ROOT):
            return False, None, "Path is outside the sandbox"

        return True, candidate, "Path is inside the sandbox"

    except Exception:
        return False, None, "Invalid path"


def read_file_tool(path: Path):
    """
    Actually execute the file-reading tool.
    This function must only be called after validation.
    """

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


# ============================================================
# SSRF / URL GUARDRAIL
# ============================================================

def is_private_or_dangerous_ip(ip_string: str) -> bool:
    """
    Reject private, loopback, link-local, metadata,
    multicast, reserved, and unspecified IP addresses.
    """

    try:
        ip = ipaddress.ip_address(ip_string)

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


def resolve_host_safely(hostname: str):
    """
    Resolve every returned address and reject dangerous IPs.
    """

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        for item in addresses:
            sockaddr = item[4]
            ip_address = sockaddr[0]

            if is_private_or_dangerous_ip(ip_address):
                return False, f"Host resolves to blocked IP: {ip_address}"

        return True, "DNS resolution is safe"

    except socket.gaierror:
        return False, "DNS resolution failed"

    except Exception:
        return False, "DNS validation failed"


def validate_url(url: str):
    """
    Validate a URL before making any network request.
    """

    if not isinstance(url, str):
        return False, None, "URL must be a string"

    try:
        parsed = urlsplit(url)

    except Exception:
        return False, None, "Invalid URL"

    # Only HTTPS is allowed.
    if parsed.scheme.lower() != "https":
        return False, None, "Only HTTPS URLs are allowed"

    # Reject missing hostname.
    if not parsed.hostname:
        return False, None, "Missing hostname"

    hostname = parsed.hostname.lower().rstrip(".")

    # Reject userinfo such as:
    #
    # https://example.com@127.0.0.1/
    #
    # The actual host is 127.0.0.1.
    if parsed.username is not None or parsed.password is not None:
        return False, None, "Userinfo is not allowed"

    # Reject explicit ports other than HTTPS port 443.
    if parsed.port not in (None, 443):
        return False, None, "Only HTTPS port 443 is allowed"

    # Exact host matching.
    #
    # Do NOT use:
    #
    # hostname.endswith("example.com")
    #
    # because evil-example.com could pass.
    if hostname not in ALLOWED_HOSTS:
        return False, None, "Hostname is not on the exact allowlist"

    # Resolve the hostname and inspect the resulting IP addresses.
    safe, reason = resolve_host_safely(hostname)

    if not safe:
        return False, None, reason

    # Rebuild a canonical URL without userinfo.
    canonical_url = f"https://{hostname}"

    if parsed.port:
        canonical_url += f":{parsed.port}"

    canonical_url += parsed.path or "/"

    if parsed.query:
        canonical_url += "?" + parsed.query

    if parsed.fragment:
        canonical_url += "#" + parsed.fragment

    return True, canonical_url, "URL passed validation"


# ============================================================
# SAFE URL FETCHING
# ============================================================

def fetch_url_tool(url: str):
    """
    Fetch a URL only after validation.

    Redirects are disabled so that a safe-looking URL cannot
    silently redirect to an unsafe destination.
    """

    allowed, canonical_url, reason = validate_url(url)

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
                "User-Agent": "Guardrail-Test-Client"
            }
        )

        # If the server asks us to redirect somewhere else,
        # do not follow it automatically.
        if 300 <= response.status_code < 400:
            return {
                "allowed": False,
                "reason": "Redirects are blocked"
            }

        return {
            "allowed": True,
            "status_code": response.status_code,
            "body": response.text[:100000]
        }

    except requests.RequestException as exc:
        return {
            "allowed": False,
            "reason": f"Request failed: {type(exc).__name__}"
        }


# ============================================================
# MAIN GUARDRAIL ENDPOINT
# ============================================================

@app.post("/guard")
def guardrail(request: ToolRequest):

    # --------------------------------------------------------
    # TOOL 1: read_file
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

        result = read_file_tool(resolved_path)

        return {
            "action": "allow",
            "reason": reason,
            "result": result
        }

    # --------------------------------------------------------
    # TOOL 2: fetch_url
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

        try:

            response = requests.get(
                canonical_url,
                timeout=10,
                allow_redirects=False
            )

            if 300 <= response.status_code < 400:
                return {
                    "action": "block",
                    "reason": "Redirects are blocked",
                    "result": None
                }

            return {
                "action": "allow",
                "reason": "URL passed validation",
                "result": {
                    "status_code": response.status_code,
                    "body": response.text[:100000]
                }
            }

        except requests.RequestException:
            return {
                "action": "block",
                "reason": "Network request failed",
                "result": None
            }

    # --------------------------------------------------------
    # UNKNOWN TOOL
    # --------------------------------------------------------

    return {
        "action": "block",
        "reason": "Unknown tool",
        "result": None
    }

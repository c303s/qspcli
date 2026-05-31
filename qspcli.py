#!/usr/bin/env python3
"""QSPCLI — CrowdStrike QuickScan Pro CLI.

Uploads files to CrowdStrike QuickScan Pro and retrieves scan verdicts.
Uses only Python standard library — no third-party packages required.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
import getpass
import json
import os
import ssl
import sys
import time
import threading
import uuid
from pathlib import Path
from urllib import error, parse, request

# ─── Constants ────────────────────────────────────────────────────────────────

APP_VERSION = "0.01a"
APP_BUILD_DATE = "31.05.2026"
DEFAULT_FALCON_BASE_URL = "https://api.crowdstrike.com"
FALCON_ENV_KEYS = ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL")
DIRECTORY_ENV_KEY = "QSPCLI_WORK_DIR"
POLL_INTERVAL = 1          # seconds between status polls
MAX_POLL_ATTEMPTS = 180    # 180 × 1 s = 3 min timeout
MAX_FILE_SIZE = 256 * 1024 * 1024  # 256 MB hard limit enforced by the API
SEPARATOR = "  " + "─" * 68


# ─── ANSI colour helpers ──────────────────────────────────────────────────────

def _green(t: str) -> str:  return f"\033[32m{t}\033[0m"
def _red(t: str)   -> str:  return f"\033[31m{t}\033[0m"
def _yellow(t: str)-> str:  return f"\033[33m{t}\033[0m"
def _cyan(t: str)  -> str:  return f"\033[36m{t}\033[0m"
def _bold(t: str)  -> str:  return f"\033[1m{t}\033[0m"


# ─── Exceptions ───────────────────────────────────────────────────────────────

class FalconAPIError(RuntimeError):
    """Raised on any Falcon API error."""


# ─── Multipart form-data builder ─────────────────────────────────────────────

def _build_multipart(
    fields: dict[str, str],
    files: dict[str, tuple[str, bytes]],
) -> tuple[bytes, str]:
    """Return (body_bytes, content_type_header) for a multipart/form-data POST."""
    boundary = uuid.uuid4().hex
    bnd = boundary.encode()
    CRLF = b"\r\n"
    body = b""

    for name, value in fields.items():
        body += b"--" + bnd + CRLF
        body += f'Content-Disposition: form-data; name="{name}"'.encode() + CRLF
        body += CRLF
        body += str(value).encode() + CRLF

    for field_name, (filename, data) in files.items():
        body += b"--" + bnd + CRLF
        body += (
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'
        ).encode() + CRLF
        body += b"Content-Type: application/octet-stream" + CRLF
        body += CRLF
        body += data + CRLF

    body += b"--" + bnd + b"--" + CRLF
    return body, f"multipart/form-data; boundary={boundary}"


# ─── Falcon API client ────────────────────────────────────────────────────────

class QSPClient:
    """Lightweight CrowdStrike QuickScan Pro API client (stdlib-only)."""

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self.access_token = ""
        self.token_expires_at = 0.0
        self._token_lock = threading.Lock()
        self.ssl_context = self._build_ssl_context()

    # ── SSL ───────────────────────────────────────────────────────────────────

    def _build_ssl_context(self) -> ssl.SSLContext:
        explicit = os.environ.get("SSL_CERT_FILE", "").strip()
        if explicit and Path(explicit).is_file():
            return ssl.create_default_context(cafile=explicit)
        for candidate in (
            "/etc/ssl/cert.pem",
            "/private/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ):
            if Path(candidate).is_file():
                return ssl.create_default_context(cafile=candidate)
        return ssl.create_default_context()

    # ── OAuth2 token management ───────────────────────────────────────────────

    def _ensure_token(self) -> None:
        with self._token_lock:
            if self.access_token and time.time() < self.token_expires_at - 60:
                return

            token_url = f"{self.base_url}/oauth2/token"
            body = parse.urlencode(
                {"client_id": self.client_id, "client_secret": self.client_secret}
            ).encode()
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            resp = self._send_request("POST", token_url, headers=headers, body=body)
            status = resp.get("status_code", 0)
            rbody = resp.get("body", {})

            if status >= 400:
                raise FalconAPIError(
                    f"Authentication failed (HTTP {status}): "
                    f"{self._format_errors(rbody)}"
                )
            if not isinstance(rbody, dict) or not rbody.get("access_token"):
                raise FalconAPIError(
                    "OAuth2 token request did not return an access_token. "
                    "Check your FALCON_BASE_URL and credentials."
                )

            self.access_token = str(rbody["access_token"])
            expires_in = int(rbody.get("expires_in", 1800) or 1800)
            self.token_expires_at = time.time() + max(expires_in, 60)

    # ── Low-level HTTP ────────────────────────────────────────────────────────

    def _send_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> dict:
        req = request.Request(url, data=body, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=120, context=self.ssl_context) as resp:
                return {"status_code": resp.getcode(), "body": self._decode(resp.read())}
        except error.HTTPError as exc:
            return {"status_code": exc.code, "body": self._decode(exc.read())}
        except error.URLError as exc:
            raise FalconAPIError(f"Request failed: {exc.reason}") from exc

    def _get(self, path: str, params: dict | None = None) -> dict:
        self._ensure_token()
        url = f"{self.base_url}{path}"
        if params:
            qs = parse.urlencode(
                [(k, str(v)) for k, v in params.items() if v is not None],
                doseq=True,
            )
            if qs:
                url = f"{url}?{qs}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        resp = self._send_request("GET", url, headers=headers)
        if resp.get("status_code") == 401:
            self.access_token = ""
            self.token_expires_at = 0.0
            self._ensure_token()
            headers["Authorization"] = f"Bearer {self.access_token}"
            resp = self._send_request("GET", url, headers=headers)
        return resp

    def _post_json(self, path: str, payload: dict) -> dict:
        self._ensure_token()
        url = f"{self.base_url}{path}"
        body = json.dumps(payload).encode()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        resp = self._send_request("POST", url, headers=headers, body=body)
        if resp.get("status_code") == 401:
            self.access_token = ""
            self.token_expires_at = 0.0
            self._ensure_token()
            headers["Authorization"] = f"Bearer {self.access_token}"
            resp = self._send_request("POST", url, headers=headers, body=body)
        return resp

    def _post_multipart(
        self,
        path: str,
        fields: dict[str, str],
        files: dict[str, tuple[str, bytes]],
    ) -> dict:
        self._ensure_token()
        url = f"{self.base_url}{path}"
        body, content_type = _build_multipart(fields, files)
        headers = {
            "Accept": "application/json",
            "Content-Type": content_type,
            "Authorization": f"Bearer {self.access_token}",
        }
        resp = self._send_request("POST", url, headers=headers, body=body)
        if resp.get("status_code") == 401:
            self.access_token = ""
            self.token_expires_at = 0.0
            self._ensure_token()
            headers["Authorization"] = f"Bearer {self.access_token}"
            resp = self._send_request("POST", url, headers=headers, body=body)
        return resp

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _decode(self, payload: bytes) -> dict | list:
        if not payload:
            return {}
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"raw": payload.decode("utf-8", errors="replace")}

    def _format_errors(self, body: object) -> str:
        if isinstance(body, dict):
            errors = body.get("errors") or []
            parts = [
                f"{e.get('code', 'error')}: {e.get('message', 'unknown')}"
                for e in errors
                if isinstance(e, dict) and (e.get("code") or e.get("message"))
            ]
            if parts:
                return "; ".join(parts)
        return "No error details returned"

    def _resources(self, resp: dict) -> list:
        body = resp.get("body", resp)
        if isinstance(body, dict):
            resources = body.get("resources", [])
            if isinstance(resources, list):
                return resources
        return []

    def _check_status(self, resp: dict, operation: str) -> None:
        status = resp.get("status_code", 0)
        body = resp.get("body", {})
        if status and status >= 400:
            raise FalconAPIError(
                f"{operation} failed (HTTP {status}): {self._format_errors(body)}"
            )

    # ── QuickScan Pro API ─────────────────────────────────────────────────────

    def preflight_check(self) -> None:
        """Verify credentials and Quick Scan Pro scope.

        Strategy:
        - _ensure_token() already validates client_id/secret via oauth2/token.
        - Then probe the QSP queries endpoint with no filter.
        - Only 401/403 indicate a real auth or scope problem.
          A 400 would mean the API disliked our query syntax — that is not
          a credential failure, so we let it pass.
        """
        self._ensure_token()
        resp = self._get("/quickscanpro/queries/scans/v1", {"limit": 1})
        status = int(resp.get("status_code", 0) or 0)
        if status in (401, 403):
            body = resp.get("body", {})
            raise FalconAPIError(
                f"QuickScanPro access denied (HTTP {status}): "
                f"{self._format_errors(body)}\n"
                "Make sure the API client has Quick Scan Pro read AND write scope."
            )

    def upload_file(self, file_path: Path) -> str:
        """Upload *file_path* with scan=True and return its SHA256 identifier.

        Passing scan=True tells the API to start scanning immediately on
        ingest -- no separate LaunchScan call is needed.
        """
        file_name = file_path.name
        file_data = file_path.read_bytes()
        resp = self._post_multipart(
            "/quickscanpro/entities/files/v1",
            fields={"file_name": file_name, "scan": "true"},
            files={"file": (file_name, file_data)},
        )
        self._check_status(resp, "UploadFileQuickScanPro")
        resources = self._resources(resp)
        if not resources:
            raise FalconAPIError(
                "Upload succeeded but the response contained no resource info."
            )
        sha256 = resources[0].get("sha256", "")
        if not sha256:
            raise FalconAPIError(
                "Upload succeeded but SHA256 was not present in the response."
            )
        return sha256

    def query_scan_ids_by_sha256(self, sha256: str) -> tuple:
        """Return (ids, error_str) for *sha256* via QueryScanResults.

        The FQL filter colon and quotes must NOT be percent-encoded, so we
        build the query string manually using parse.quote with safe chars
        instead of going through urlencode which encodes : as %3A.
        """
        self._ensure_token()
        filter_fql = f"sha256:'{sha256}'"
        # Keep FQL-special chars literal so the API can parse them correctly.
        safe_chars = ":'"
        qs = (
            "filter="
            + parse.quote(filter_fql, safe=safe_chars)
            + "&limit=1&sort=desc"
        )
        url = f"{self.base_url}/quickscanpro/queries/scans/v1?{qs}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        resp = self._send_request("GET", url, headers=headers)
        status = int(resp.get("status_code", 0) or 0)
        body = resp.get("body", {})
        if status >= 400:
            return [], self._format_errors(body)
        return self._resources(resp), ""

    def get_scan_result(self, scan_id: str) -> dict:
        """Fetch the full scan result entity by ID."""
        resp = self._get("/quickscanpro/entities/scans/v1", {"ids": scan_id})
        self._check_status(resp, "GetScanResult")
        resources = self._resources(resp)
        return resources[0] if resources else {}


# ─── .env helpers ─────────────────────────────────────────────────────────────

def _resolve_dotenv() -> Path:
    return Path.cwd() / ".env"


def _read_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        values[key] = value
    return values


def _load_dotenv(path: Path) -> None:
    for key, value in _read_dotenv(path).items():
        if key:
            os.environ[key] = value


def _write_dotenv(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    merged = _read_dotenv(path)
    merged.update({k: v for k, v in values.items() if v})
    lines = [f"{k}={v}" for k, v in merged.items() if v]
    content = "\n".join(lines) + "\n" if lines else ""
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _has_complete_config(path: Path) -> bool:
    if not path.exists():
        return False
    values = _read_dotenv(path)
    return all(values.get(k, "").strip() for k in FALCON_ENV_KEYS)


# ─── UI helpers ───────────────────────────────────────────────────────────────

def _clear() -> None:
    print("\033[2J\033[H", end="")


def _print_banner() -> None:
    print()
    print(f"  QSPCLI  |  QuickScan Pro CLI  |  Version {APP_VERSION}  |  built on {APP_BUILD_DATE}")
    print()
    print("  Uploads files to CrowdStrike QuickScan Pro and retrieves scan verdicts.")
    print()
    print("  DISCLAIMER: This is not an official CrowdStrike tool.")
    print("  Use at your own risk. CrowdStrike is not responsible for this tool.")
    print()
    print(SEPARATOR)
    print()


def _prompt(message: str) -> str:
    sys.stdout.write(message)
    sys.stdout.flush()
    return input()


def _prompt_non_empty(name: str) -> str:
    while True:
        value = _prompt(f"  Enter {name}: ").strip()
        if value:
            return value
        print(f"  {name} cannot be empty. Please try again.")


def _prompt_secret(name: str) -> str:
    while True:
        if sys.stdin.isatty():
            value = getpass.getpass(f"  Enter {name}: ").strip()
        else:
            value = _prompt(f"  Enter {name}: ").strip()
        if value:
            return value
        print(f"  {name} cannot be empty. Please try again.")


def _prompt_with_default(name: str, default: str) -> str:
    while True:
        value = _prompt(f"  Enter {name} [{default}]: ").strip()
        if value:
            return value
        if default:
            return default
        print(f"  {name} cannot be empty.")


def _prompt_yes_no(message: str, *, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        value = _prompt(f"  {message} {suffix}: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("  Please enter Y or N.")


def _mask_secret(secret: str) -> str:
    if not secret:
        return "(not set)"
    if len(secret) <= 4:
        return "*" * len(secret)
    return "*" * (len(secret) - 4) + secret[-4:]


class _Spinner:
    """Simple CLI spinner that prints to stdout."""

    _FRAMES = ("|", "/", "-", "\\")

    def __init__(self, message: str) -> None:
        self.message = message
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self) -> None:
        idx = 0
        while not self._stop.is_set():
            frame = self._FRAMES[idx % 4]
            print(f"\r  [•] {self.message} {frame}", end="", flush=True)
            idx += 1
            time.sleep(0.1)
        print(f"\r  [✓] {self.message} done{' ' * 10}", flush=True)

    def __enter__(self) -> "_Spinner":
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join()


def _with_spinner(message: str, func, *args, **kwargs):
    with _Spinner(message):
        return func(*args, **kwargs)


# ─── Credential setup ─────────────────────────────────────────────────────────

def _prompt_falcon_values() -> dict[str, str]:
    print("  Enter your CrowdStrike Falcon API credentials.")
    print("  Hint: Falcon console → Support & resources → API clients and keys")
    print("  Required scopes: Quick Scan Pro — read AND write")
    print()
    return {
        "FALCON_CLIENT_ID":     _prompt_non_empty("FALCON_CLIENT_ID"),
        "FALCON_CLIENT_SECRET": _prompt_secret("FALCON_CLIENT_SECRET"),
        "FALCON_BASE_URL":      _prompt_with_default("FALCON_BASE_URL", DEFAULT_FALCON_BASE_URL),
    }


def _build_client(values: dict[str, str]) -> QSPClient:
    return QSPClient(
        client_id=values["FALCON_CLIENT_ID"],
        client_secret=values["FALCON_CLIENT_SECRET"],
        base_url=values["FALCON_BASE_URL"],
    )


def _prompt_valid_credentials(dotenv_path: Path) -> QSPClient:
    """Keep asking for credentials until a successful pre-flight check passes."""
    while True:
        values = _prompt_falcon_values()
        try:
            client = _build_client(values)
            _with_spinner("Validating credentials...", client.preflight_check)
        except (FalconAPIError, RuntimeError) as exc:
            print(f"\n  {_red('[✗]')} Credential validation failed.")
            print(f"       {exc}")
            print(
                "  Possible causes:\n"
                "    • Invalid client ID or secret\n"
                "    • API client missing Quick Scan Pro read/write scope\n"
                "    • Wrong base URL\n"
            )
            continue

        print("  [•] Saving credentials...", end="", flush=True)
        _write_dotenv(dotenv_path, values)
        for k, v in values.items():
            os.environ[k] = v
        print("\r  [✓] Saving credentials... done      ")
        print()
        return client


def _initial_setup(dotenv_path: Path) -> QSPClient:
    print("  [setup] No configuration found — running first-time setup.")
    print()
    return _prompt_valid_credentials(dotenv_path)


def _prompt_for_credential_update(dotenv_path: Path) -> QSPClient | None:
    if not _prompt_yes_no("Would you like to update the API credentials?", default=False):
        return None
    print()
    print("  [setup] Updating saved credentials.")
    print()
    return _prompt_valid_credentials(dotenv_path)


def _startup_with_env(dotenv_path: Path) -> QSPClient:
    """Load existing credentials, run pre-flight check, fall back to setup if needed."""
    values = _read_dotenv(dotenv_path)
    print("  [info] Using saved credentials")
    print(f"  FALCON_CLIENT_ID: {values.get('FALCON_CLIENT_ID', '')}")

    client = _build_client(values)
    try:
        _with_spinner("Running pre-flight access check...", client.preflight_check)
        print(f"  {_green('[✓]')} API client has access to CrowdStrike QuickScan Pro.")
        print()
    except (FalconAPIError, RuntimeError) as exc:
        print(f"\n  {_red('[✗]')} Pre-flight check failed.")
        print(f"       {exc}")
        print()
        print("  Please enter valid credentials.")
        print()
        client = _prompt_valid_credentials(dotenv_path)

    updated_client = _prompt_for_credential_update(dotenv_path)
    if updated_client is not None:
        client = updated_client

    return client


# ─── Scan result display ──────────────────────────────────────────────────────

def _fmt_size(size: int) -> str:
    if not size:
        return "N/A"
    if size < 1024:
        return f"{size} B"
    if size < 1024 ** 2:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 ** 2):.1f} MB"


def _fmt_verdict(verdict: str) -> str:
    v = verdict.lower()
    if v == "clean":
        return _green("CLEAN")
    if v == "no_threats_found":
        return _green("NO THREATS FOUND")
    if v == "malicious":
        return _red("MALICIOUS")
    if v == "suspicious":
        return _yellow("SUSPICIOUS")
    if v == "unknown":
        return _cyan("UNKNOWN")
    return _cyan(verdict.upper())


def _sanitize_report_component(value: str) -> str:
    sanitized = value.replace(".", "_")
    sanitized = "".join(
        character if character.isalnum() or character in {"-", "_"} else "_"
        for character in sanitized
    )
    while "__" in sanitized:
        sanitized = sanitized.replace("__", "_")
    return sanitized.strip("_") or "unknown"


def _report_verdict_label(result: dict) -> str:
    verdict = _safe_str(result.get("verdict"))
    if verdict:
        return _sanitize_report_component(verdict)

    status = _safe_str(result.get("status"))
    if status in {"error", "failed"}:
        return _sanitize_report_component(status)

    return "unknown"


def _scan_report_filename(file_path: Path, result: dict) -> str:
    file_label = _sanitize_report_component(file_path.name)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    verdict_label = _report_verdict_label(result)
    return f"{file_label}_{timestamp}_{verdict_label}.txt"


def _build_scan_report_text(result: dict, file_path: Path) -> str:
    normalized = _normalize_scan_result(result) if result.get("scan") or result.get("result") else result
    lines = [
        "QSPCLI Scan Report",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"File: {file_path.name}",
        f"File Path: {file_path}",
        f"SHA256: {normalized.get('sha256') or 'N/A'}",
        f"Status: {normalized.get('status') or 'N/A'}",
        f"Verdict: {normalized.get('verdict') or 'N/A'}",
        f"File Type: {normalized.get('file_type_short') or 'N/A'}",
        f"File Size: {_fmt_size(normalized.get('file_size', 0))}",
    ]

    verdict_reasons = normalized.get("verdict_reasons") or []
    if verdict_reasons:
        lines.append("")
        lines.append("Verdict Reasons:")
        lines.extend(f"- {reason}" for reason in verdict_reasons)

    artifacts = normalized.get("artifacts") or {}
    url_artifacts = artifacts.get("url_artifacts") or []
    if url_artifacts:
        lines.append("")
        lines.append("URL Artifacts:")
        for artifact in url_artifacts:
            url = artifact.get("url") or "unknown"
            art_verdict = artifact.get("verdict") or "N/A"
            lines.append(f"- {url} | verdict: {art_verdict}")

    return "\n".join(lines) + "\n"


def _write_scan_report(result: dict, file_path: Path, output_dir: Path) -> Path:
    normalized = _normalize_scan_result(result) if result.get("scan") or result.get("result") else result
    report_path = output_dir / _scan_report_filename(file_path, normalized)
    report_path.write_text(_build_scan_report_text(normalized, file_path), encoding="utf-8")
    return report_path


def _update_verdicts_csv(result: dict, file_path: Path, output_dir: Path) -> Path:
    normalized = _normalize_scan_result(result) if result.get("scan") or result.get("result") else result
    csv_path = output_dir / "verdicts.csv"
    file_exists = csv_path.exists()

    with csv_path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        if not file_exists:
            writer.writerow(
                [
                    "timestamp",
                    "filename",
                    "file extension",
                    "file type",
                    "file size",
                    "SHA256",
                    "threat verdict",
                ]
            )
        writer.writerow(
            [
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                file_path.name,
                file_path.suffix,
                normalized.get("file_type_short") or "N/A",
                normalized.get("file_size") or 0,
                normalized.get("sha256") or "N/A",
                normalized.get("verdict") or "N/A",
            ]
        )

    return csv_path


def _display_result(result: dict, file_path: Path) -> None:
    result = _normalize_scan_result(result) if result.get("scan") or result.get("result") else result
    print()
    print(SEPARATOR)
    print(f"  {_bold('SCAN RESULT')}")
    print(SEPARATOR)
    print(f"  File      : {file_path.name}")
    print(f"  SHA256    : {result.get('sha256', 'N/A')}")
    print(f"  File Type : {result.get('file_type_short', 'N/A')}")
    print(f"  File Size : {_fmt_size(result.get('file_size', 0))}")
    print(f"  Status    : {result.get('status', 'N/A')}")
    print()
    verdict = result.get("verdict", "unknown")
    print(f"  VERDICT   : {_fmt_verdict(verdict)}")

    reasons = result.get("verdict_reasons") or []
    if reasons:
        print("  Verdict Reasons:")
        for r in reasons:
            print(f"    • {r}")

    mitre = result.get("mitre_attacks") or []
    if mitre:
        print()
        print("  MITRE ATT&CK Techniques:")
        for attack in mitre:
            aid = attack.get("attack_id", "")
            tactic = attack.get("tactic", "")
            technique = attack.get("technique", "")
            parts = [p for p in (aid, tactic, technique) if p]
            print(f"    • {' / '.join(parts)}")
    artifacts = result.get("artifacts") or {}
    if isinstance(artifacts, dict):
        url_arts = artifacts.get("url_artifacts") or []
        if url_arts:
            shown_urls = url_arts[:10]
            print(f"  URL Artifacts ({len(url_arts)}):")
            for art in shown_urls:
                url = art.get("url", "unknown")
                art_verdict = art.get("verdict", "")
                verdict_str = f"  [{_fmt_verdict(art_verdict)}]" if art_verdict else ""
                print(f"    • {url}{verdict_str}")
            if len(url_arts) > 10:
                print(f"    … and {len(url_arts) - 10} more")

    print(SEPARATOR)


# ─── Scan workflow ────────────────────────────────────────────────────────────

# Statuses that explicitly mean "still working" -- everything else is terminal.
_IN_PROGRESS_STATUSES = {"pending", "running", "queued", "in_progress", "processing"}


def _safe_str(value: object) -> str:
    """Safely coerce a value that may be None/null to a lower-cased string."""
    if value is None:
        return ""
    return str(value).lower()


def _normalize_scan_result(entity: dict) -> dict:
    """Flatten QuickScan Pro entity payloads into the display shape this CLI uses."""
    scan = entity.get("scan") or {}
    result = entity.get("result") or {}

    artifacts: dict[str, list] = {}
    if result.get("file_artifacts"):
        artifacts["file_artifacts"] = result.get("file_artifacts") or []
    if result.get("url_artifacts"):
        artifacts["url_artifacts"] = result.get("url_artifacts") or []

    return {
        "id": entity.get("id", ""),
        "sha256": scan.get("sha256", ""),
        "status": scan.get("status", ""),
        "created_timestamp": scan.get("created_timestamp", ""),
        "updated_timestamp": scan.get("updated_timestamp", ""),
        "verdict": result.get("verdict", ""),
        "verdict_reason": result.get("verdict_reason", ""),
        "verdict_reasons": result.get("verdict_reasons") or [],
        "verdict_source": result.get("verdict_source", ""),
        "file_size": result.get("file_size", 0),
        "file_type": result.get("file_type", ""),
        "file_type_short": result.get("file_type_short", ""),
        "mime_type": result.get("mime_type", ""),
        "artifacts": artifacts,
    }


def _poll_for_result(client: QSPClient, sha256: str) -> dict:
    """Poll until a scan verdict is available for *sha256*.

    Each iteration:
      1. Call QueryScanResults(filter=sha256:'...') to get result IDs.
         - If a filter error occurs, print it once and keep retrying.
         - If IDs are returned, fetch the full entity via GetScanResult.
      2. Check verdict / status. Exit as soon as a verdict appears.
    """
    frames = ("|", "/", "-", "\\")
    filter_error_shown = False

    for attempt in range(MAX_POLL_ATTEMPTS):
        elapsed = attempt * POLL_INTERVAL
        frame = frames[attempt % 4]

        print(
            f"\r  [•] Waiting for scan result... {frame}  ({elapsed}s elapsed)",
            end="",
            flush=True,
        )

        try:
            ids, err = client.query_scan_ids_by_sha256(sha256)
        except FalconAPIError as exc:
            time.sleep(POLL_INTERVAL)
            continue

        if err and not filter_error_shown:
            print(f"\n  [!] QueryScanResults filter error: {err}")
            print(  "      Will keep retrying...")
            filter_error_shown = True

        if ids:
            try:
                result = _normalize_scan_result(client.get_scan_result(ids[0]))
            except FalconAPIError:
                time.sleep(POLL_INTERVAL)
                continue

            verdict = _safe_str(result.get("verdict"))
            status  = _safe_str(result.get("status"))

            is_done = (
                bool(verdict)
                or status in {"error", "failed"}
            )
            if is_done:
                print()
                return result

        time.sleep(POLL_INTERVAL)

    print()
    raise FalconAPIError(
        f"Scan timed out after {MAX_POLL_ATTEMPTS * POLL_INTERVAL}s. "
        "The scan may still be running in the Falcon console."
    )


def _list_directory_files(directory: Path) -> list[Path]:
    try:
        files = [item for item in directory.iterdir() if item.is_file()]
    except OSError:
        return []
    return sorted(files, key=lambda item: item.name.lower())


def _prompt_directory(dotenv_path: Path) -> Path:
    dotenv_values = _read_dotenv(dotenv_path)
    saved_directory = dotenv_values.get(DIRECTORY_ENV_KEY, "").strip()
    explicit_directory = bool(saved_directory)
    directory = Path(saved_directory).expanduser() if saved_directory else Path.cwd()
    directory = directory.resolve()

    if not explicit_directory:
        print(f"  Using this directory:")
        print(f"  {directory}")
    else:
        print(f"  Using saved directory:")
        print(f"  {directory}")

    if _prompt_yes_no("Would you like to change the directory?", default=False):
        while True:
            raw = _prompt("  Enter directory path: ").strip()
            if not raw:
                print("  Directory path cannot be empty.")
                continue
            candidate = Path(os.path.expandvars(os.path.expanduser(raw))).resolve()
            if not candidate.exists():
                print(f"  {_red('[✗]')} Directory not found: {candidate}")
                continue
            if not candidate.is_dir():
                print(f"  {_red('[✗]')} Path is not a directory: {candidate}")
                continue
            directory = candidate
            break

    _write_dotenv(dotenv_path, {DIRECTORY_ENV_KEY: str(directory)})
    os.environ[DIRECTORY_ENV_KEY] = str(directory)
    print()
    return directory


def _print_directory_files(directory: Path, files: list[Path]) -> None:
    print(f"  Files in {directory}:")
    if not files:
        print("  (no files found)")
        print()
        return
    for index, file_path in enumerate(files, start=1):
        print(f"  {index}. {file_path.name}")
    print()


def scan_file(client: QSPClient, file_path: Path, output_dir: Path) -> None:
    """Full scan pipeline: validate → upload (with scan=True) → poll → display."""
    # Validate file
    if not file_path.exists():
        print(f"  {_red('[✗]')} File not found: {file_path}")
        return
    if not file_path.is_file():
        print(f"  {_red('[✗]')} Path is not a regular file: {file_path}")
        return
    file_size = file_path.stat().st_size
    if file_size == 0:
        print(f"  {_red('[✗]')} File is empty: {file_path}")
        return
    if file_size > MAX_FILE_SIZE:
        print(
            f"  {_red('[✗]')} File is too large ({_fmt_size(file_size)}). "
            "QuickScan Pro accepts files up to 256 MB."
        )
        return

    print(f"  [•] File : {file_path}  ({_fmt_size(file_size)})")

    # Step 1 — upload with scan=True (scan starts immediately on ingest)
    try:
        sha256 = _with_spinner(
            "Uploading file to QuickScan Pro (scan=True)...",
            client.upload_file,
            file_path,
        )
    except FalconAPIError as exc:
        print(f"\n  {_red('[✗]')} Upload failed: {exc}")
        return

    print(f"  [•] SHA256 : {sha256}")

    # Step 2 — poll QueryScanResults by SHA256 for the verdict
    try:
        result = _poll_for_result(client, sha256)
    except FalconAPIError as exc:
        print(f"  {_red('[✗]')} {exc}")
        return

    status = _safe_str(result.get("status"))
    report_path = _write_scan_report(result, file_path, output_dir)
    verdicts_path = _update_verdicts_csv(result, file_path, output_dir)
    if status in ("error", "failed"):
        print(f"  {_red('[✗]')} Scan ended with error status: {result.get('status')}")
        print(f"  [•] Report  : {report_path.name}")
        print(f"  [•] Updated : {verdicts_path.name}")
        return

    # Step 3 — display
    _display_result(result, file_path)
    print(f"  [•] Report  : {report_path.name}")
    print(f"  [•] Updated : {verdicts_path.name}")


# ─── Interactive file prompt ───────────────────────────────────────────────────

def _prompt_for_file(directory: Path) -> Path | None:
    while True:
        files = _list_directory_files(directory)
        _print_directory_files(directory, files)
        raw = _prompt("  Select file from list or enter file name (or 'q' to quit): ").strip()
        if raw.lower() in ("q", "quit", "exit"):
            return None
        if not raw:
            continue
        if raw.isdigit() and files:
            selected_index = int(raw)
            if 1 <= selected_index <= len(files):
                return files[selected_index - 1]
            print("  Invalid file number.")
            continue

        path = Path(os.path.expandvars(os.path.expanduser(raw)))
        if not path.is_absolute() and path.parent == Path('.'):
            path = directory / path
        if not path.exists():
            print(f"  {_red('[✗]')} File not found: {path}")
            continue
        if not path.is_file():
            print(f"  {_red('[✗]')} Path is not a regular file: {path}")
            continue
        return path


# ─── Argument parsing ─────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="qspcli",
        description=(
            "Upload files to CrowdStrike QuickScan Pro and retrieve scan verdicts."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {APP_VERSION}",
    )
    parser.add_argument(
        "--file",
        metavar="PATH",
        help="Path to the file to upload and scan (skips interactive prompt).",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Re-run credential setup and overwrite the saved .env file.",
    )
    return parser.parse_args()


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    dotenv_path = _resolve_dotenv()
    args = _parse_args()

    _load_dotenv(dotenv_path)
    _clear()
    _print_banner()

    # ── Credentials ──────────────────────────────────────────────────────────
    if args.setup or not _has_complete_config(dotenv_path):
        client = _initial_setup(dotenv_path)
    else:
        client = _startup_with_env(dotenv_path)

    scan_directory = _prompt_directory(dotenv_path)

    # ── Non-interactive mode (--file) ─────────────────────────────────────────
    if args.file:
        path = Path(os.path.expandvars(os.path.expanduser(args.file)))
        if not path.is_absolute() and path.parent == Path('.'):
            path = scan_directory / path
        scan_file(client, path, scan_directory)
        return 0

    # ── Interactive loop ──────────────────────────────────────────────────────
    while True:
        file_path = _prompt_for_file(scan_directory)
        if file_path is None:
            print()
            print("  Thanks for using QSPCLI. Stay safe out there!")
            print()
            return 0
        scan_file(client, file_path, scan_directory)

        print()
        again = _prompt("  Scan another file? [Y/n]: ").strip().lower()
        if again in ("n", "no"):
            print()
            print("  Thanks for using QSPCLI. Stay safe out there!")
            print()
            return 0
        print()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n  Aborted by user.")
        sys.exit(130)

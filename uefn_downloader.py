#!/usr/bin/env python3
"""
Single-file CLI for:
1. Epic OAuth login / token refresh.
2. Fortnite / UEFN mnemonic resolution.
3. Content Service probing.
4. public island cooked-content download through Content Service v4 + BPS chunks.

This tool does not bypass Epic authentication or authorization. It only uses a
Bearer token from an account that logged in normally.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import struct
import sys
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


ACCOUNT_BASE = "https://account-public-service-prod.ol.epicgames.com"
DEFAULT_MNEMONIC_API = (
    "https://api.fortnitejp.news/api/fortnite/discovery/mnemonic/{namespace}/{map_code}"
)
CONTENT_SERVICE_BASE = "https://content-service.bfda.live.use1a.on.epicgames.com"
CONTENT_GATEWAY_BASE = "https://fngw-svc-ds-livefn.ol.epicgames.com"
MODULE_KEY_BATCH_URL = f"{CONTENT_SERVICE_BASE}/api/content/v4/module/key/batch"
SESSION_FILE = "epic_auth_sessions.json"
DEVICE_AUTH_FILE = "device_auth.json"
JS_DEVICE_AUTH_BASIC = "NzlhOTMxYjM3NTMzNDU3MGFjMzY5MjM0ZjVkYTA1ZWM6ZWU3MzM1ZGYzYzRhNDEyY2I1NzA1NWFiN2FkZTY5M2U="
JS_CONTENT_EXCHANGE_BASIC = "M2UxM2M1YzU3ZjU5NGE1NzhhYmU1MTZlZWNiNjczZmU6NTMwZTMxNmMzMzdlNDA5ODkzYzU1ZWM0NGYyMmNkNjI="
DEFAULT_FORTNITE_USER_AGENT = (
    "Fortnite/++Fortnite+Release-40.40-CL-53683214 Windows/10.0.26100.8162.64bit"
)
DEFAULT_CONTENT_PLATFORM = "Windows"
DEFAULT_CONTENT_ROLE = "client"
BPS_MANIFEST_MAGIC = 0x44BEC00C
BPS_CHUNK_MAGIC = 0xB1FE3AA2
MANIFEST_URL_RE = re.compile(
    r"https://cooked-content-live-cdn\.epicgames\.com/valkyrie/cooked-content/[^\s\"'<>]+/plugin\.manifest(?:\?[^\s\"'<>]*)?",
    re.IGNORECASE,
)

CLIENTS = {
    "android": {
        "client_id": "3f69e56c7649492c8cc29f1af08a8a12",
        "client_secret": "b51ee9cb12234f50a69efa67ef53812e",
    },
    "launcher": {
        "client_id": "34a02cf8f4414e29b15921876da36f9a",
        "client_secret": "daafbccc737745039dffe53d94fc76cf",
    },
}


class AppError(RuntimeError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_epic_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def is_token_fresh(token_data: dict[str, Any], *, margin_seconds: int = 120) -> bool:
    expires_at = parse_epic_time(token_data.get("expires_at"))
    if expires_at is None:
        return False
    return (expires_at - utc_now()).total_seconds() > margin_seconds


def client_basic(client_name: str) -> str:
    try:
        client = CLIENTS[client_name]
    except KeyError as error:
        known = ", ".join(sorted(CLIENTS))
        raise AppError(f"unknown OAuth client '{client_name}'. Use one of: {known}") from error
    raw = f"{client['client_id']}:{client['client_secret']}".encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def client_id(client_name: str) -> str:
    try:
        return CLIENTS[client_name]["client_id"]
    except KeyError as error:
        known = ", ".join(sorted(CLIENTS))
        raise AppError(f"unknown OAuth client '{client_name}'. Use one of: {known}") from error


def read_error_body(error: HTTPError) -> str:
    try:
        return error.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def request_raw(
    url: str,
    *,
    token: str | None = None,
    method: str = "GET",
    body: Any | None = None,
    accept: str = "application/json",
    timeout: float = 30.0,
    user_agent: str = "uefn-downloader/1.0",
) -> tuple[bytes, dict[str, str]]:
    headers = {
        "Accept": accept,
        "User-Agent": user_agent,
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.read(), dict(response.headers.items())
    except HTTPError as error:
        detail = read_error_body(error)
        raise AppError(f"HTTP {error.code} from {url}: {detail}") from error
    except URLError as error:
        raise AppError(f"request failed for {url}: {error.reason}") from error


def request_json(url: str, **kwargs: Any) -> Any:
    raw, _headers = request_raw(url, **kwargs)
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise AppError(f"response from {url} was not JSON") from error


def form_request(
    url: str,
    form: dict[str, str],
    *,
    client_name: str,
    timeout: float = 30.0,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"basic {client_basic(client_name)}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": "uefn-downloader/1.0",
    }
    request = Request(url, data=urlencode(form).encode("utf-8"), headers=headers, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except HTTPError as error:
        detail = read_error_body(error)
        raise AppError(f"HTTP {error.code} from {url}: {detail}") from error
    except URLError as error:
        raise AppError(f"request failed for {url}: {error.reason}") from error

    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise AppError(f"response from {url} was not JSON") from error


def form_request_with_basic(
    url: str,
    form: dict[str, str],
    *,
    basic_value: str,
    timeout: float = 30.0,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Basic {basic_value}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": "uefn-downloader/1.0",
    }
    request = Request(url, data=urlencode(form).encode("utf-8"), headers=headers, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except HTTPError as error:
        detail = read_error_body(error)
        raise AppError(f"HTTP {error.code} from {url}: {detail}") from error
    except URLError as error:
        raise AppError(f"request failed for {url}: {error.reason}") from error

    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise AppError(f"response from {url} was not JSON") from error


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def normalize_map_code(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 12:
        raise AppError("map code must contain exactly 12 digits")
    return f"{digits[:4]}-{digits[4:8]}-{digits[8:]}"


def prompt_map_code(raw: str | None) -> str:
    if raw:
        return normalize_map_code(raw)
    while True:
        value = input("マップコードを入力してください: ").strip()
        try:
            return normalize_map_code(value)
        except AppError as error:
            print(f"error: {error}", file=sys.stderr)


def parse_size(value: str) -> int:
    match = re.fullmatch(r"(\d+)([KkMmGg]?[Bb]?)?", value.strip())
    if not match:
        raise argparse.ArgumentTypeError("Use a byte count, or values like 500MB.")
    number = int(match.group(1))
    unit = (match.group(2) or "").lower().removesuffix("b")
    multiplier = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[unit]
    return number * multiplier


def build_login_url(client_name: str) -> str:
    redirect = (
        "https://www.epicgames.com/id/api/redirect?"
        + urlencode({"clientId": client_id(client_name), "responseType": "code"})
    )
    return "https://www.epicgames.com/id/login?redirectUrl=" + quote(redirect, safe="")


def extract_authorization_code(value: str) -> str:
    match = re.search(r"[A-Za-z0-9]{32}", value)
    if not match:
        raise AppError("authorization code was not found in the pasted text")
    return match.group(0)


def exchange_authorization_code(
    authorization_code: str,
    *,
    client_name: str,
    timeout: float,
) -> dict[str, Any]:
    return form_request(
        f"{ACCOUNT_BASE}/account/api/oauth/token",
        {"grant_type": "authorization_code", "code": authorization_code},
        client_name=client_name,
        timeout=timeout,
    )


def refresh_access_token(
    refresh_token: str,
    *,
    client_name: str,
    timeout: float,
) -> dict[str, Any]:
    return form_request(
        f"{ACCOUNT_BASE}/account/api/oauth/token",
        {"grant_type": "refresh_token", "refresh_token": refresh_token},
        client_name=client_name,
        timeout=timeout,
    )


def verify_access_token(access_token: str, *, timeout: float) -> dict[str, Any]:
    return request_json(
        f"{ACCOUNT_BASE}/account/api/oauth/verify",
        token=access_token,
        timeout=timeout,
    )


def session_path(data_dir: Path) -> Path:
    return data_dir / SESSION_FILE


def load_sessions(data_dir: Path) -> dict[str, Any]:
    path = session_path(data_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise AppError(f"invalid session file: {path}") from error


def save_sessions(data_dir: Path, sessions: dict[str, Any]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    session_path(data_dir).write_text(
        json.dumps(sessions, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def device_auth_path(data_dir: Path) -> Path:
    return data_dir / DEVICE_AUTH_FILE


def load_device_auth(data_dir: Path) -> dict[str, Any] | None:
    path = device_auth_path(data_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    required = ("accountId", "deviceId", "secret")
    if not all(isinstance(data.get(key), str) and data.get(key) for key in required):
        return None
    return data


def save_device_auth(data_dir: Path, data: dict[str, Any]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    write_json(device_auth_path(data_dir), data)


def get_exchange_code(access_token: str, *, timeout: float) -> str:
    data = request_json(
        f"{ACCOUNT_BASE}/account/api/oauth/exchange",
        token=access_token,
        timeout=timeout,
    )
    if not isinstance(data, dict) or not isinstance(data.get("code"), str):
        raise AppError("exchange response did not include code")
    return str(data["code"])


def exchange_code_with_basic(exchange_code: str, *, basic_value: str, timeout: float) -> dict[str, Any]:
    return form_request_with_basic(
        f"{ACCOUNT_BASE}/account/api/oauth/token",
        {"grant_type": "exchange_code", "exchange_code": exchange_code},
        basic_value=basic_value,
        timeout=timeout,
    )


def create_device_auth_record(account_id: str, access_token: str, *, timeout: float) -> dict[str, Any]:
    data = request_json(
        f"{ACCOUNT_BASE}/account/api/public/account/{quote(account_id, safe='')}/deviceAuth",
        token=access_token,
        method="POST",
        body={},
        timeout=timeout,
    )
    if not isinstance(data, dict):
        raise AppError("deviceAuth response was not an object")
    return data


def device_code_login_and_create_device_auth(*, data_dir: Path, timeout: float) -> tuple[dict[str, Any], dict[str, Any]]:
    client_token = form_request_with_basic(
        f"{ACCOUNT_BASE}/account/api/oauth/token",
        {"grant_type": "client_credentials"},
        basic_value=JS_DEVICE_AUTH_BASIC,
        timeout=timeout,
    )
    bearer = client_token.get("access_token")
    if not isinstance(bearer, str):
        raise AppError("client_credentials response did not include access_token")

    device = request_json(
        f"{ACCOUNT_BASE}/account/api/oauth/deviceAuthorization",
        token=bearer,
        method="POST",
        body={"prompt": "login"},
        timeout=timeout,
    )
    if not isinstance(device, dict):
        raise AppError("deviceAuthorization response was not an object")

    verification_uri = device.get("verification_uri_complete")
    if isinstance(verification_uri, str) and verification_uri:
        print(f"Authorize here: {verification_uri}")
    else:
        print("Authorize with Epic device login in your browser.")

    device_code = device.get("device_code")
    expires_in = int(device.get("expires_in") or 300)
    interval = max(1, int(device.get("interval") or 5))
    if not isinstance(device_code, str) or not device_code:
        raise AppError("deviceAuthorization response did not include device_code")

    deadline = time.time() + expires_in
    token: dict[str, Any] | None = None
    while time.time() < deadline:
        time.sleep(interval)
        try:
            token = form_request_with_basic(
                f"{ACCOUNT_BASE}/account/api/oauth/token",
                {"grant_type": "device_code", "device_code": device_code},
                basic_value=JS_DEVICE_AUTH_BASIC,
                timeout=timeout,
            )
            break
        except AppError as error:
            message = str(error)
            if "authorization_pending" in message or "slow_down" in message:
                continue
            raise
    if token is None:
        raise AppError("device-code login timed out")

    access_token = token.get("access_token")
    account_id = token.get("account_id")
    display_name = token.get("displayName") or token.get("display_name")
    if not isinstance(access_token, str) or not access_token:
        raise AppError("device_code token response did not include access_token")
    if not isinstance(account_id, str) or not account_id:
        raise AppError("device_code token response did not include account_id")

    exchange_code = get_exchange_code(access_token, timeout=timeout)
    android_token = exchange_code_with_basic(
        exchange_code,
        basic_value=client_basic("android"),
        timeout=timeout,
    )
    android_access = android_token.get("access_token")
    if not isinstance(android_access, str) or not android_access:
        raise AppError("android exchange response did not include access_token")

    device_auth = create_device_auth_record(account_id, android_access, timeout=timeout)
    output = {
        "displayName": display_name or "<unknown>",
        "accountId": account_id,
        "deviceId": device_auth.get("deviceId"),
        "secret": device_auth.get("secret"),
    }
    if not isinstance(output["deviceId"], str) or not isinstance(output["secret"], str):
        raise AppError("deviceAuth response was missing deviceId/secret")

    save_device_auth(data_dir, output)
    return token, output


def token_from_device_auth_record(device_auth: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    return form_request_with_basic(
        f"{ACCOUNT_BASE}/account/api/oauth/token",
        {
            "grant_type": "device_auth",
            "account_id": str(device_auth.get("accountId")),
            "device_id": str(device_auth.get("deviceId")),
            "secret": str(device_auth.get("secret")),
            "token_type": "eg1",
        },
        basic_value=client_basic("android"),
        timeout=timeout,
    )


def get_content_access_token_via_device_auth(*, data_dir: Path, timeout: float) -> str:
    device_auth = load_device_auth(data_dir)
    if device_auth is None:
        _token, device_auth = device_code_login_and_create_device_auth(data_dir=data_dir, timeout=timeout)

    try:
        auth_token = token_from_device_auth_record(device_auth, timeout=timeout)
    except AppError:
        _token, device_auth = device_code_login_and_create_device_auth(data_dir=data_dir, timeout=timeout)
        auth_token = token_from_device_auth_record(device_auth, timeout=timeout)

    access_token = auth_token.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise AppError("device_auth token response did not include access_token")

    exchange_code = get_exchange_code(access_token, timeout=timeout)
    content_token = exchange_code_with_basic(
        exchange_code,
        basic_value=JS_CONTENT_EXCHANGE_BASIC,
        timeout=timeout,
    )
    final_access = content_token.get("access_token")
    if not isinstance(final_access, str) or not final_access:
        raise AppError("content exchange token response did not include access_token")
    return final_access


def save_session(data_dir: Path, label: str, client_name: str, token_data: dict[str, Any]) -> None:
    sessions = load_sessions(data_dir)
    sessions[label] = {
        "client": client_name,
        "updated_at": utc_now().isoformat(),
        "token": token_data,
    }
    save_sessions(data_dir, sessions)


def load_session(data_dir: Path, label: str) -> dict[str, Any]:
    session = load_sessions(data_dir).get(label)
    if not isinstance(session, dict):
        raise AppError(f"saved auth session '{label}' was not found")
    if not isinstance(session.get("token"), dict):
        raise AppError(f"saved auth session '{label}' is missing token data")
    return session


def get_saved_access_token(
    *,
    data_dir: Path,
    label: str,
    client_name: str | None,
    timeout: float,
) -> str:
    session = load_session(data_dir, label)
    saved_client = str(session.get("client") or "android")
    effective_client = client_name or saved_client
    token = session["token"]

    if is_token_fresh(token):
        access_token = token.get("access_token")
        if not isinstance(access_token, str):
            raise AppError(f"saved auth session '{label}' has no access_token")
        return access_token

    refresh_token = token.get("refresh_token")
    if not isinstance(refresh_token, str):
        raise AppError(f"saved auth session '{label}' has no refresh_token")

    refreshed = refresh_access_token(refresh_token, client_name=effective_client, timeout=timeout)
    save_session(data_dir, label, effective_client, refreshed)
    access_token = refreshed.get("access_token")
    if not isinstance(access_token, str):
        raise AppError("refreshed token response did not contain access_token")
    return access_token


def resolve_content_token(args: argparse.Namespace) -> tuple[str | None, str | None]:
    if getattr(args, "content_token", None):
        return args.content_token, None

    env_token = os.environ.get("EPIC_CONTENT_TOKEN") or os.environ.get("EPIC_ACCESS_TOKEN")
    if env_token:
        return env_token, None

    if getattr(args, "no_saved_auth", False):
        return None, "saved auth is disabled"

    try:
        token = get_saved_access_token(
            data_dir=Path(args.data_dir),
            label=args.label,
            client_name=args.auth_client,
            timeout=args.timeout,
        )
        return token, None
    except AppError as error:
        if getattr(args, "no_interactive_login", False):
            return None, str(error)

        print(f"saved auth is unavailable: {error}")
        print("Starting interactive Epic login now.")
        client_name = args.auth_client or "android"
        print("Open this URL in a browser and log in with your Epic account:")
        print(build_login_url(client_name))
        print()
        pasted = input("Paste the full text shown after login, or the 32-character code: ").strip()
        code = extract_authorization_code(pasted)
        token_data = exchange_authorization_code(code, client_name=client_name, timeout=args.timeout)
        save_session(Path(args.data_dir), args.label, client_name, token_data)
        access_token = token_data.get("access_token")
        if not isinstance(access_token, str):
            return None, "login succeeded but no access_token was returned"
        verify = verify_access_token(access_token, timeout=args.timeout)
        print(f"logged in account_id: {verify.get('account_id', '<unknown>')}")
        return access_token, None


def token_required_error(reason: str | None) -> str:
    message = (
        "Content Service access requires a bearer token. "
        "Run: python .\\uefn_downloader.py login "
        "Then rerun this command, or pass --content-token directly."
    )
    if reason:
        message += f" Saved auth reason: {reason}"
    return message


def login_interactive(args: argparse.Namespace) -> int:
    print("Open this URL in a browser and log in with your Epic account:")
    print(build_login_url(args.client))
    print()
    pasted = input("Paste the full text shown after login, or the 32-character code: ").strip()
    code = extract_authorization_code(pasted)
    token = exchange_authorization_code(code, client_name=args.client, timeout=args.timeout)
    save_session(Path(args.data_dir), args.label, args.client, token)
    verify = verify_access_token(token["access_token"], timeout=args.timeout)

    print(f"saved auth session: {session_path(Path(args.data_dir))}")
    print(f"label: {args.label}")
    print(f"client: {args.client}")
    print(f"account_id: {verify.get('account_id', token.get('account_id', '<unknown>'))}")
    print(f"expires_at: {token.get('expires_at', '<unknown>')}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    token = args.token
    if not token:
        token = get_saved_access_token(
            data_dir=Path(args.data_dir),
            label=args.label,
            client_name=args.auth_client,
            timeout=args.timeout,
        )
    print(json.dumps(verify_access_token(token, timeout=args.timeout), ensure_ascii=False, indent=2))
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    token = get_saved_access_token(
        data_dir=Path(args.data_dir),
        label=args.label,
        client_name=args.auth_client,
        timeout=args.timeout,
    )
    verify = verify_access_token(token, timeout=args.timeout)
    print(f"refreshed/verified session: {args.label}")
    print(f"account_id: {verify.get('account_id', '<unknown>')}")
    print(f"expires_at: {verify.get('expires_at', '<unknown>')}")
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    print(
        get_saved_access_token(
            data_dir=Path(args.data_dir),
            label=args.label,
            client_name=args.auth_client,
            timeout=args.timeout,
        )
    )
    return 0


def cmd_logout(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    sessions = load_sessions(data_dir)
    if args.label not in sessions:
        print(f"auth session was already absent: {args.label}")
        return 0
    del sessions[args.label]
    save_sessions(data_dir, sessions)
    print(f"deleted auth session: {args.label}")
    return 0


def cmd_device_login(args: argparse.Namespace) -> int:
    token, device_auth = device_code_login_and_create_device_auth(
        data_dir=Path(args.data_dir),
        timeout=args.timeout,
    )
    print(f"logged in as account: {device_auth.get('displayName', '<unknown>')}")
    print(f"account_id: {token.get('account_id', '<unknown>')}")
    print(f"saved device auth: {device_auth_path(Path(args.data_dir))}")
    return 0


def cmd_device_token(args: argparse.Namespace) -> int:
    token = get_content_access_token_via_device_auth(
        data_dir=Path(args.data_dir),
        timeout=args.timeout,
    )
    print(token)
    return 0


def resolve_mnemonic(args: argparse.Namespace, map_code: str) -> dict[str, Any]:
    url = args.mnemonic_url.format(namespace=args.namespace, map_code=map_code)
    data = request_json(url, timeout=args.timeout)
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0]
    if isinstance(data, dict):
        return data
    raise AppError(f"unexpected mnemonic response shape: {type(data).__name__}")


def save_and_print_mnemonic(args: argparse.Namespace, map_code: str) -> tuple[dict[str, Any], Path]:
    output_dir = Path(args.out) / map_code
    output_dir.mkdir(parents=True, exist_ok=True)

    mnemonic = resolve_mnemonic(args, map_code)
    write_json(output_dir / "mnemonic.json", mnemonic)

    metadata = mnemonic.get("metadata") if isinstance(mnemonic.get("metadata"), dict) else {}
    project_id = metadata.get("projectId") or mnemonic.get("projectId")
    link_version = mnemonic.get("version")

    print(f"saved mnemonic: {output_dir / 'mnemonic.json'}")
    print(f"linkType: {mnemonic.get('linkType', '<unknown>')}")
    print(f"title: {metadata.get('title', '<unknown>')}")
    print(f"projectId: {project_id or '<missing>'}")
    print(f"link/version: {link_version if link_version is not None else '<missing>'}")

    public_modules = metadata.get("public_modules")
    if public_modules:
        write_json(output_dir / "public_modules.json", public_modules)
        print(f"saved public_modules: {output_dir / 'public_modules.json'}")
    else:
        print("public_modules: empty or missing in mnemonic response")

    return mnemonic, output_dir


def scan_ids(value: Any, path: str = "$") -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            key_lower = key.lower()
            if any(part in key_lower for part in ("module", "artifact", "snapshot", "project")):
                if isinstance(child, (str, int, float, bool)) or child is None:
                    hits.append({"path": child_path, "value": child})
            hits.extend(scan_ids(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            hits.extend(scan_ids(child, f"{path}[{index}]"))
    return hits


def artifact_candidates_from_ids(ids: list[dict[str, Any]]) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for item in ids:
        path = str(item.get("path", "")).lower()
        value = item.get("value")
        if "artifact" not in path or not isinstance(value, str):
            continue
        if value.startswith(("http://", "https://")):
            continue
        cleaned = value.split(":", 1)[0].strip()
        if len(cleaned) < 8:
            continue
        if cleaned not in seen:
            seen.add(cleaned)
            candidates.append(cleaned)
    return candidates


def collect_artifact_candidates(results: list[dict[str, Any]]) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for record in results:
        for candidate in record.get("artifact_candidates", []):
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)
    return candidates


def default_fortnite_log_dir() -> Path | None:
    local_appdata = os.environ.get("LOCALAPPDATA")
    if not local_appdata:
        return None
    return Path(local_appdata) / "FortniteGame" / "Saved" / "Logs"


def default_installed_bundles_dir() -> Path | None:
    local_appdata = os.environ.get("LOCALAPPDATA")
    if not local_appdata:
        return None
    return Path(local_appdata) / "FortniteGame" / "Saved" / "PersistentDownloadDir" / "GameCustom" / "InstalledBundles"


def list_installed_bundle_dirs(installed_bundles_dir: Path) -> list[Path]:
    if not installed_bundles_dir.exists() or not installed_bundles_dir.is_dir():
        return []
    dirs = [path for path in installed_bundles_dir.iterdir() if path.is_dir()]
    return sorted(dirs, key=lambda path: path.stat().st_mtime, reverse=True)


def export_installed_bundle_files(bundle_dir: Path, output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []

    for name in ("plugin.pak", "plugin.sig", "plugin.ucas", "plugin.utoc"):
        src = bundle_dir / name
        if src.exists() and src.is_file():
            dst = output_dir / name
            shutil.copy2(src, dst)
            copied.append(dst)

    manifest_src = bundle_dir / "CachedBPSManifest.manifest"
    if manifest_src.exists() and manifest_src.is_file():
        manifest_dst = output_dir / "plugin.manifest"
        shutil.copy2(manifest_src, manifest_dst)
        copied.append(manifest_dst)

    if not copied:
        raise AppError(f"no installbundle payload files found in: {bundle_dir}")
    return copied


def bundle_export_dir(base_output_dir: Path, bundle_dir: Path) -> Path:
    return base_output_dir / "InstalledBundles" / bundle_dir.name


def discover_manifest_urls_from_logs(
    log_dir: Path,
    *,
    max_files: int = 20,
    max_bytes_per_file: int = 8 * 1024 * 1024,
) -> list[str]:
    if not log_dir.exists() or not log_dir.is_dir():
        return []

    files = sorted(
        log_dir.glob("*.log"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )[: max(1, max_files)]

    urls: list[str] = []
    seen: set[str] = set()
    for log_path in files:
        try:
            with log_path.open("rb") as file:
                file.seek(0, os.SEEK_END)
                size = file.tell()
                start = max(0, size - max_bytes_per_file)
                file.seek(start, os.SEEK_SET)
                text = file.read().decode("utf-8", errors="replace")
        except OSError:
            continue

        for match in MANIFEST_URL_RE.finditer(text):
            url = match.group(0)
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def probe_content_service(
    project_id: str,
    token: str,
    output_dir: Path,
    *,
    timeout: float,
) -> list[dict[str, Any]]:
    endpoints = [
        ("project", f"{CONTENT_SERVICE_BASE}/api/content/v2/project/{project_id}"),
        ("project_meta", f"{CONTENT_SERVICE_BASE}/api/content/v2/project/{project_id}/meta"),
        ("gateway_project", f"{CONTENT_GATEWAY_BASE}/api/content/v2/project/{project_id}"),
        ("gateway_project_meta", f"{CONTENT_GATEWAY_BASE}/api/content/v2/project/{project_id}/meta"),
    ]
    results: list[dict[str, Any]] = []

    for name, url in endpoints:
        record: dict[str, Any] = {"name": name, "url": url, "status": "error"}
        try:
            data = request_json(url, token=token, timeout=timeout)
            ids = scan_ids(data)
            candidates = artifact_candidates_from_ids(ids)
            write_json(output_dir / f"{name}.json", data)
            write_json(output_dir / f"{name}.ids.json", ids)
            record.update(
                {
                    "status": "ok",
                    "file": f"{name}.json",
                    "ids_file": f"{name}.ids.json",
                    "artifact_candidates": candidates,
                }
            )
        except Exception as error:
            record["error"] = str(error)
        results.append(record)

    write_json(output_dir / "content_service_probe.json", results)
    return results


def download_cooked_artifact(
    artifact_id: str,
    platform: str,
    token: str,
    output_dir: Path,
    *,
    timeout: float,
    max_bytes: int,
) -> Path:
    artifact_ref = quote(f"{artifact_id}:{platform}", safe="")
    url = f"{CONTENT_SERVICE_BASE}/api/content/v2/artifact/{artifact_ref}/cooked-content"
    headers = {
        "Accept": "application/octet-stream,*/*",
        "Authorization": f"Bearer {token}",
        "User-Agent": "uefn-downloader/1.0",
    }
    request = Request(url, headers=headers, method="GET")

    try:
        response = urlopen(request, timeout=timeout)
    except HTTPError as error:
        detail = read_error_body(error)
        raise AppError(f"HTTP {error.code} from {url}: {detail}") from error
    except URLError as error:
        raise AppError(f"request failed for {url}: {error.reason}") from error

    response_headers = dict(response.headers.items())
    content_type = (response_headers.get("Content-Type") or "").split(";", 1)[0].lower()
    suffix = ".bin"
    if "zip" in content_type:
        suffix = ".zip"
    elif "json" in content_type:
        suffix = ".json"

    target = output_dir / f"{artifact_id}-{platform}-cooked-content{suffix}"
    total = 0
    try:
        with response, target.open("wb") as file:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    file.close()
                    target.unlink(missing_ok=True)
                    raise AppError(f"download exceeded --max-bytes ({max_bytes} bytes)")
                file.write(chunk)
    except Exception:
        target.unlink(missing_ok=True)
        raise

    write_json(
        output_dir / f"{artifact_id}-{platform}-cooked-content.headers.json",
        {"url": url, "headers": response_headers, "bytes": total},
    )
    return target


def safe_filename(value: str, fallback: str = "download") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return cleaned or fallback


def _fetch_fortnite_build_from_launcher(token: str | None = None) -> str | None:
    url = (
        "https://launcher-public-service-prod06.ol.epicgames.com"
        "/launcher/api/public/assets/Windows"
        "/4fe75bbc5a674f4f9b356b5c90567da5/Fortnite?label=Live"
    )
    try:
        data = request_json(url, token=token, timeout=10)
        build = data.get("buildVersion", "")
        if isinstance(build, str) and build.startswith("++Fortnite+"):
            return build
    except Exception:
        pass
    return None


def latest_fortnite_user_agent(
    log_dir: Path | None = None,
    token: str | None = None,
) -> str:
    api_build = _fetch_fortnite_build_from_launcher(token=token)
    if api_build:
        return f"Fortnite/{api_build} Windows/10.0.26100.8162.64bit"
    return DEFAULT_FORTNITE_USER_AGENT


def content_v4_package_url(
    map_code: str,
    *,
    platform_name: str,
    role: str,
    version: int | str | None = None,
) -> str:
    query: dict[str, str] = {"platform": platform_name, "role": role}
    if version is not None:
        query["version"] = str(version)
    return (
        f"{CONTENT_SERVICE_BASE}/api/content/v4/link/{quote(map_code, safe='')}/"
        f"cooked-content-package?{urlencode(query)}"
    )


def resolve_cooked_content_package(
    map_code: str,
    token: str,
    output_dir: Path,
    *,
    platform_name: str,
    role: str,
    user_agent: str,
    version: int | str | None,
    timeout: float,
) -> dict[str, Any]:
    url = content_v4_package_url(map_code, platform_name=platform_name, role=role, version=version)
    data = request_json(url, token=token, timeout=timeout, user_agent=user_agent)
    write_json(output_dir / "content_v4_client.json", data)

    content = data.get("content") if isinstance(data, dict) else None
    if not isinstance(content, list):
        raise AppError("Content Service v4 response did not contain a content list")

    downloadable: list[dict[str, Any]] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        binaries = item.get("binaries")
        if not isinstance(binaries, dict):
            continue
        base_url = binaries.get("baseUrl")
        if isinstance(base_url, str) and base_url:
            downloadable.append(item)

    if not downloadable:
        status = data.get("status") if isinstance(data, dict) else "<unknown>"
        raise AppError(f"Content Service v4 returned no downloadable GameCustom package. status={status}")

    selected = max(
        downloadable,
        key=lambda item: float((item.get("binaries") or {}).get("totalSizeKb") or 0),
    )
    write_json(output_dir / "cooked_content_package.json", selected)
    return selected


def manifest_url_from_base(base_url: str, *, channel: str) -> str:
    return base_url.rstrip("/") + f"/{quote(channel.strip() or 'alt', safe='')}/plugin.manifest"


class BpsReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def seek(self, offset: int) -> None:
        if offset < 0 or offset > len(self.data):
            raise AppError("BPS reader seek out of range")
        self.offset = offset

    def skip(self, size: int) -> None:
        self.seek(self.offset + size)

    def read(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise AppError("unexpected end of BPS data")
        start = self.offset
        self.offset += size
        return self.data[start:self.offset]

    def uint8(self) -> int:
        return self.read(1)[0]

    def uint32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def int32(self) -> int:
        return struct.unpack("<i", self.read(4))[0]

    def uint64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def boolean(self) -> bool:
        return self.uint8() != 0

    def guid(self) -> tuple[str, str]:
        raw = self.read(16)
        converted = bytearray(16)
        for index in range(4):
            value = struct.unpack(">I", raw[index * 4 : index * 4 + 4])[0]
            converted[index * 4 : index * 4 + 4] = struct.pack("<I", value)
        import uuid

        guid = uuid.UUID(bytes=bytes(converted))
        return str(guid), guid.bytes.hex().upper()

    def fstring(self) -> str:
        size = self.int32()
        if size == 0:
            return ""
        if size > 0:
            raw = self.read(size)
            if raw.endswith(b"\x00"):
                raw = raw[:-1]
            return raw.decode("utf-8", errors="replace")

        raw = self.read(-size * 2)
        if raw.endswith(b"\x00\x00"):
            raw = raw[:-2]
        return raw.decode("utf-16le", errors="replace")

    def fstring_array(self) -> list[str]:
        return [self.fstring() for _ in range(self.uint32())]


def parse_bps_manifest(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    reader = BpsReader(raw)
    magic = reader.uint32()
    if magic != BPS_MANIFEST_MAGIC:
        raise AppError(f"invalid BPS manifest magic: 0x{magic:08x}")

    header_size = reader.int32()
    uncompressed_size = reader.int32()
    compressed_size = reader.int32()
    reader.read(20)
    stored_as = reader.uint8()
    feature_level = reader.int32() if header_size > 37 else 10
    reader.seek(header_size)

    body_raw = reader.read(compressed_size if stored_as & 1 else uncompressed_size)
    if stored_as & 2:
        raise AppError("encrypted BPS manifests are not supported")
    body = zlib.decompress(body_raw) if stored_as & 1 else body_raw
    if len(body) != uncompressed_size:
        raise AppError("BPS manifest decompressed size mismatch")

    reader = BpsReader(body)
    meta_start = reader.offset
    meta_size = reader.uint32()
    meta_version = reader.uint8()
    meta = {
        "feature_level": reader.int32(),
        "is_file_data": reader.boolean(),
        "app_id": reader.int32(),
        "app_name": reader.fstring(),
        "build_version": reader.fstring(),
        "launch_exe": reader.fstring(),
        "launch_command": reader.fstring(),
        "prereq_ids": reader.fstring_array(),
        "prereq_name": reader.fstring(),
        "prereq_path": reader.fstring(),
        "prereq_args": reader.fstring(),
    }
    if meta_version >= 1:
        meta["build_id"] = reader.fstring()
    if meta_version > 1:
        meta["uninstall_action_path"] = reader.fstring()
        meta["uninstall_action_args"] = reader.fstring()
    reader.seek(meta_start + meta_size)

    chunk_start = reader.offset
    chunk_data_size = reader.uint32()
    chunk_data_version = reader.uint8()
    chunk_count = reader.uint32()
    chunks: list[dict[str, Any]] = [{"guid": "", "guid_hex": ""} for _ in range(chunk_count)]
    chunk_lookup: dict[str, dict[str, Any]] = {}
    for chunk in chunks:
        guid, guid_hex = reader.guid()
        chunk["guid"] = guid
        chunk["guid_hex"] = guid_hex
        chunk_lookup[guid] = chunk
    for chunk in chunks:
        chunk["hash"] = reader.uint64()
    for chunk in chunks:
        chunk["sha1"] = reader.read(20).hex()
    for chunk in chunks:
        chunk["group"] = reader.uint8()
    for chunk in chunks:
        chunk["window_size"] = reader.uint32()
    for chunk in chunks:
        chunk["file_size"] = reader.uint64()
    reader.seek(chunk_start + chunk_data_size)

    files_start = reader.offset
    files_data_size = reader.uint32()
    files_data_version = reader.uint8()
    file_count = reader.uint32()
    files: list[dict[str, Any]] = [{} for _ in range(file_count)]
    for file_record in files:
        file_record["filename"] = reader.fstring()
    for file_record in files:
        file_record["symlink_target"] = reader.fstring()
    for file_record in files:
        file_record["sha1"] = reader.read(20).hex()
    for file_record in files:
        file_record["flags"] = reader.uint8()
    for file_record in files:
        file_record["install_tags"] = reader.fstring_array()
    for file_record in files:
        part_count = reader.uint32()
        parts: list[dict[str, Any]] = []
        file_size = 0
        for _ in range(part_count):
            data_size = reader.uint32()
            guid, _guid_hex = reader.guid()
            offset = reader.uint32()
            size = reader.uint32()
            chunk = chunk_lookup.get(guid)
            if chunk is None:
                raise AppError(f"BPS chunk GUID was not found in chunk list: {guid}")
            parts.append(
                {
                    "data_size": data_size,
                    "guid": guid,
                    "offset": offset,
                    "size": size,
                    "chunk": chunk,
                }
            )
            file_size += size
        file_record["chunk_parts"] = parts
        file_record["file_size"] = file_size
    if files_data_version >= 2:
        for _ in range(file_count):
            reader.skip(reader.int32() * 16)
        for file_record in files:
            file_record["mime_type"] = reader.fstring()
        reader.skip(file_count * 32)
    reader.seek(files_start + files_data_size)

    return {
        "header": {
            "feature_level": feature_level,
            "stored_as": stored_as,
            "compressed_size": compressed_size,
            "uncompressed_size": uncompressed_size,
        },
        "meta": meta,
        "chunk_data_version": chunk_data_version,
        "chunks": chunks,
        "files": files,
    }


def parse_bps_chunk(raw: bytes) -> bytes:
    reader = BpsReader(raw)
    magic = reader.uint32()
    if magic != BPS_CHUNK_MAGIC:
        raise AppError(f"invalid BPS chunk magic: 0x{magic:08x}")
    version = reader.uint32()
    header_size = reader.uint32()
    compressed_size = reader.uint32()
    reader.read(16)
    reader.uint64()
    stored_as = reader.uint8()
    reader.seek(header_size)
    payload = reader.read(compressed_size)
    if stored_as & 2:
        raise AppError("encrypted BPS chunks are not supported")
    if stored_as & 1:
        return zlib.decompress(payload)
    return payload


def bps_chunk_url(base_url: str, chunk: dict[str, Any], *, channel: str) -> str:
    return (
        base_url.rstrip("/")
        + f"/{quote(channel.strip() or 'alt', safe='')}/ChunksV4/"
        + f"{int(chunk['group']):02d}/{int(chunk['hash']):016X}_{chunk['guid_hex']}.chunk"
    )


def fetch_bps_chunk(
    base_url: str,
    chunk: dict[str, Any],
    cache_dir: Path,
    *,
    channel: str,
    timeout: float,
    user_agent: str,
) -> bytes:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{int(chunk['group']):02d}_{int(chunk['hash']):016X}_{chunk['guid_hex']}.chunk"
    if not cache_path.exists() or cache_path.stat().st_size != int(chunk["file_size"]):
        url = bps_chunk_url(base_url, chunk, channel=channel)
        download_http_file(
            url,
            cache_path,
            timeout=timeout,
            max_bytes=max(int(chunk["file_size"]) + 1024 * 1024, 8 * 1024 * 1024),
            user_agent=user_agent,
        )
    return parse_bps_chunk(cache_path.read_bytes())


def reconstruct_bps_files(
    manifest_path: Path,
    base_url: str,
    output_dir: Path,
    *,
    channel: str,
    timeout: float,
    max_bytes: int,
    user_agent: str,
) -> list[Path]:
    manifest = parse_bps_manifest(manifest_path)
    files = manifest["files"]
    total_size = sum(int(file_record["file_size"]) for file_record in files)
    if total_size > max_bytes:
        raise AppError(f"BPS payload exceeds --max-bytes ({total_size} > {max_bytes})")

    write_json(
        output_dir / "plugin.manifest.parsed.json",
        {
            "meta": manifest["meta"],
            "file_count": len(files),
            "chunk_count": len(manifest["chunks"]),
            "files": [
                {
                    "filename": file_record["filename"],
                    "bytes": file_record["file_size"],
                    "chunk_parts": len(file_record["chunk_parts"]),
                    "sha1": file_record["sha1"],
                }
                for file_record in files
            ],
        },
    )

    cache_dir = output_dir / ".chunks"
    written: list[Path] = []
    for file_record in files:
        filename = Path(str(file_record["filename"])).name
        target = output_dir / filename
        sha1 = hashlib.sha1()
        with target.open("wb") as file:
            for part in file_record["chunk_parts"]:
                chunk_data = fetch_bps_chunk(
                    base_url,
                    part["chunk"],
                    cache_dir,
                    channel=channel,
                    timeout=timeout,
                    user_agent=user_agent,
                )
                piece = chunk_data[int(part["offset"]) : int(part["offset"]) + int(part["size"])]
                if len(piece) != int(part["size"]):
                    raise AppError(f"chunk part was shorter than expected for {filename}")
                file.write(piece)
                sha1.update(piece)
        digest = sha1.hexdigest()
        expected = str(file_record["sha1"])
        if digest.lower() != expected.lower():
            target.unlink(missing_ok=True)
            raise AppError(f"SHA1 mismatch for {filename}: got {digest}, expected {expected}")
        written.append(target)
        print(f"reconstructed {filename}: {target}")
    return written


def build_manifest_url(
    *,
    module_id: str,
    build_version: str,
    module_version: str,
    bundle_id: str,
    channel: str = "alt",
) -> str:
    module = quote(module_id.strip(), safe="")
    build = quote(build_version.strip(), safe="")
    version = quote(module_version.strip(), safe="")
    bundle = quote(bundle_id.strip(), safe="")
    path_channel = quote(channel.strip() or "alt", safe="")
    return (
        "https://cooked-content-live-cdn.epicgames.com/valkyrie/cooked-content/"
        f"{module}/{build}/v{version}/{bundle}/{path_channel}/plugin.manifest"
    )


def download_http_file(
    url: str,
    output_path: Path,
    *,
    timeout: float,
    max_bytes: int,
    token: str | None = None,
    user_agent: str = "uefn-downloader/1.0",
) -> tuple[Path, dict[str, str], int]:
    headers = {
        "Accept": "application/octet-stream,*/*",
        "User-Agent": user_agent,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(url, headers=headers, method="GET")
    try:
        response = urlopen(request, timeout=timeout)
    except HTTPError as error:
        detail = read_error_body(error)
        raise AppError(f"HTTP {error.code} from {url}: {detail}") from error
    except URLError as error:
        raise AppError(f"request failed for {url}: {error.reason}") from error

    total = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with response, output_path.open("wb") as file:
            response_headers = dict(response.headers.items())
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    file.close()
                    output_path.unlink(missing_ok=True)
                    raise AppError(f"download exceeded --max-bytes ({max_bytes} bytes)")
                file.write(chunk)
    except Exception:
        output_path.unlink(missing_ok=True)
        raise

    return output_path, response_headers, total


def probe_diagnostic(results: list[dict[str, Any]]) -> str:
    if not results:
        return "Content Service was not probed."

    errors = [str(item.get("error", "")) for item in results if item.get("status") != "ok"]
    if any("operation_forbidden" in error for error in errors):
        return (
            "Content Serviceのproject APIが operation_forbidden を返しています。"
            "このAPIは公開島でもproject所有者/チーム権限がないと読めないため、"
            "mnemonicのprojectIdだけではartifact IDを解決できません。"
        )
    if any("Jwt is missing" in error or "invalid_token" in error for error in errors):
        return (
            "fn-gateway側はこのOAuthトークンをJWTとして受け付けていません。"
            "Fortniteクライアント由来の別種トークンが必要な可能性があります。"
        )
    return "Content Serviceレスポンス内にartifact ID候補が見つかりませんでした。"


def map_code_download_blocker(results: list[dict[str, Any]], mnemonic: dict[str, Any]) -> str:
    metadata = mnemonic.get("metadata") if isinstance(mnemonic.get("metadata"), dict) else {}
    public_modules = metadata.get("public_modules") or mnemonic.get("public_modules")
    project_id = metadata.get("projectId") or mnemonic.get("projectId") or "<unknown>"
    version = mnemonic.get("version") or metadata.get("version") or "<unknown>"

    lines = [
        probe_diagnostic(results),
        "",
        "この公開島のダウンロードに必要なのは、UEFNのproject APIではなく Fortnite の GameCustom InstallBundle です。",
        "実体は plugin.manifest からBuildPatchServicesのchunkを取得して plugin.pak / plugin.ucas / plugin.utoc / plugin.sig を復元する形です。",
        "",
        f"mnemonicで分かっている値: projectId={project_id}, link/version={version}",
        "不足している値: root module id / module version / bundle id",
        "",
        "Fortniteクライアントはこの不足分を matchmaking 後の ContentBeacon で解決しています。",
        "mnemonic APIと、権限のないContent Service project APIだけでは manifest URL を組み立てられません。",
        "",
        "現在のdownload本線は Content Service v4 の cooked-content-package resolver を使います。",
    ]
    if not public_modules:
        lines.insert(
            6,
            "mnemonic response の public_modules は空です。ここにmodule情報が入っていれば次の解決に進めますが、この島では返っていません。",
        )
    return "\n".join(lines)


def project_id_from_mnemonic(mnemonic: dict[str, Any]) -> str:
    metadata = mnemonic.get("metadata") if isinstance(mnemonic.get("metadata"), dict) else {}
    project_id = metadata.get("projectId") or mnemonic.get("projectId")
    if not project_id:
        raise AppError("projectId is missing; cannot use Content Service")
    return str(project_id)


def cmd_resolve(args: argparse.Namespace) -> int:
    map_code = prompt_map_code(args.map_code)
    save_and_print_mnemonic(args, map_code)
    return 0


def cmd_scan_logs(args: argparse.Namespace) -> int:
    map_code = prompt_map_code(args.map_code)
    output_dir = Path(args.out) / map_code
    output_dir.mkdir(parents=True, exist_ok=True)

    log_dir = Path(args.log_dir) if args.log_dir else default_fortnite_log_dir()
    if log_dir is None:
        raise AppError("LOCALAPPDATA is not set. Pass --log-dir explicitly.")

    urls = discover_manifest_urls_from_logs(
        log_dir,
        max_files=args.max_log_files,
    )
    write_json(output_dir / "log_cooked_url_candidates.json", urls)
    print(f"log dir: {log_dir}")
    print(f"saved url candidates: {output_dir / 'log_cooked_url_candidates.json'}")
    print(f"manifest url candidates: {len(urls)}")
    if urls:
        print(f"latest candidate: {urls[0]}")
    return 0


def cmd_export_bundle_cache(args: argparse.Namespace) -> int:
    map_code = prompt_map_code(args.map_code)
    output_dir = Path(args.out) / map_code
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.bundle_dir:
        bundle_dir = Path(args.bundle_dir)
    else:
        installed = Path(args.installed_bundles_dir) if args.installed_bundles_dir else default_installed_bundles_dir()
        if installed is None:
            raise AppError("LOCALAPPDATA is not set. Pass --installed-bundles-dir or --bundle-dir.")
        dirs = list_installed_bundle_dirs(installed)
        if not dirs:
            raise AppError(f"no installed bundle directories found under: {installed}")
        bundle_dir = dirs[0]

    target_dir = bundle_export_dir(output_dir, bundle_dir)
    copied = export_installed_bundle_files(bundle_dir, target_dir)
    write_json(
        output_dir / "bundle_cache_export.json",
        {
            "source_bundle_dir": str(bundle_dir),
            "target_dir": str(target_dir),
            "copied_files": [str(path) for path in copied],
        },
    )
    print(f"bundle source: {bundle_dir}")
    print(f"bundle target: {target_dir}")
    print(f"exported files: {len(copied)}")
    for path in copied:
        print(f"- {path}")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    map_code = prompt_map_code(args.map_code)
    mnemonic, output_dir = save_and_print_mnemonic(args, map_code)
    token, token_error = resolve_content_token(args)
    if not token:
        raise AppError(token_required_error(token_error))

    results = probe_content_service(
        project_id_from_mnemonic(mnemonic),
        token,
        output_dir,
        timeout=args.timeout,
    )
    ok_count = sum(1 for item in results if item["status"] == "ok")
    candidates = collect_artifact_candidates(results)
    write_json(output_dir / "artifact_candidates.json", candidates)
    print(f"content service probe ok: {ok_count}/{len(results)}")
    print(f"saved probe summary: {output_dir / 'content_service_probe.json'}")
    print(f"artifact candidates: {', '.join(candidates) if candidates else '<none>'}")
    if not candidates:
        print(probe_diagnostic(results))
    return 0


def cmd_download(args: argparse.Namespace) -> int:
    if args.artifact_id:
        token, token_error = resolve_content_token(args)
        if not token:
            raise AppError(token_required_error(token_error))
        output_dir = Path(args.out) / "artifacts" / safe_filename(args.artifact_id)
        output_dir.mkdir(parents=True, exist_ok=True)
        target = download_cooked_artifact(
            args.artifact_id,
            args.artifact_platform,
            token,
            output_dir,
            timeout=args.timeout,
            max_bytes=args.max_bytes,
        )
        print(f"downloaded cooked artifact: {target}")
        return 0

    map_code = prompt_map_code(args.map_code)
    mnemonic, output_dir = save_and_print_mnemonic(args, map_code)

    token, token_error = resolve_content_token(args)
    if not token:
        raise AppError(token_required_error(token_error))

    if not args.skip_aes_key:
        try:
            v2_major, v2_minor, v2_patch = latest_dilly_version_triplet(timeout=args.timeout)
            v2_data = resolve_v2_cooked_content_package(
                map_code,
                token,
                major=v2_major,
                minor=v2_minor,
                patch=v2_patch,
                role="client",
                platform_name="windows",
                timeout=args.timeout,
            )
            write_json(output_dir / "content_v2_cooked_content_package.json", v2_data)

            if isinstance(v2_data, dict) and v2_data.get("isEncrypted"):
                resolved = v2_data.get("resolved") if isinstance(v2_data.get("resolved"), dict) else {}
                root = resolved.get("root") if isinstance(resolved.get("root"), dict) else {}
                module_id = root.get("moduleId")
                module_version = root.get("version")
                if isinstance(module_id, str) and module_version is not None:
                    key_data = fetch_module_key_batch(
                        token,
                        module_id=module_id,
                        module_version=module_version,
                        timeout=args.timeout,
                    )
                    write_json(output_dir / "module_key_v4.json", key_data)
                    print(f"AES Key: 0x{key_data['aesKeyHex']}")
                    print(f"GUID: {key_data['guid']}")
                else:
                    print("warning: encrypted map but moduleId/moduleVersion was missing in v2 response")
            else:
                print("Map is not encrypted")
        except AppError as error:
            message = str(error)
            if "errors.com.epicgames.content-service.unexpected_link_type" in message:
                print("1.0 maps have no encryption and can't be downloaded")
            else:
                print(f"warning: AES key lookup failed: {error}")

    user_agent = args.fortnite_user_agent or latest_fortnite_user_agent(
        token=token,
    )
    
    package = resolve_cooked_content_package(
        map_code,
        token,
        output_dir,
        platform_name=args.content_platform,
        role=args.content_role,
        user_agent=user_agent,
        version=None,
        timeout=args.timeout,
    )
    binaries = package.get("binaries") if isinstance(package.get("binaries"), dict) else {}
    base_url = binaries.get("baseUrl")
    if not isinstance(base_url, str) or not base_url:
        raise AppError("selected cooked-content package did not include binaries.baseUrl")

    manifest_url = manifest_url_from_base(base_url, channel=args.content_channel)
    manifest_path, headers, total = download_http_file(
        manifest_url,
        output_dir / "plugin.manifest",
        timeout=args.timeout,
        max_bytes=parse_size("25MB"),
        user_agent=user_agent,
    )
    write_json(
        output_dir / "plugin.manifest.headers.json",
        {
            "url": manifest_url,
            "headers": headers,
            "bytes": total,
            "source": "content-service-v4",
            "user_agent": user_agent,
        },
    )
    print(f"downloaded manifest: {manifest_path}")
    written = reconstruct_bps_files(
        manifest_path,
        base_url,
        output_dir,
        channel=args.content_channel,
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        user_agent=user_agent,
    )
    print(f"downloaded cooked content files: {len(written)}")
    return 0


def cmd_download_manifest(args: argparse.Namespace) -> int:
    map_code = prompt_map_code(args.map_code)
    output_dir = Path(args.out) / map_code
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.manifest_url:
        manifest_url = args.manifest_url
    else:
        missing = [
            name
            for name, value in (
                ("module-id", args.module_id),
                ("build-version", args.build_version),
                ("module-version", args.module_version),
                ("bundle-id", args.bundle_id),
            )
            if not value
        ]
        if missing:
            raise AppError(
                "manifest URL direct download requires --manifest-url, or all of "
                f"--module-id/--build-version/--module-version/--bundle-id. Missing: {', '.join(missing)}"
            )
        manifest_url = build_manifest_url(
            module_id=args.module_id,
            build_version=args.build_version,
            module_version=args.module_version,
            bundle_id=args.bundle_id,
            channel=args.channel,
        )

    token = None
    if args.content_token:
        token = args.content_token

    target = output_dir / "plugin.manifest"
    saved, headers, total = download_http_file(
        manifest_url,
        target,
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        token=token,
    )
    write_json(
        output_dir / "plugin.manifest.headers.json",
        {
            "url": manifest_url,
            "headers": headers,
            "bytes": total,
        },
    )
    print(f"manifest url: {manifest_url}")
    print(f"saved manifest: {saved}")
    print(f"bytes: {total}")
    return 0


def latest_dilly_version_triplet(*, timeout: float) -> tuple[str, str, str]:
    data = request_json("https://export-service-new.dillyapis.com/v1/mappings", timeout=timeout)
    if not isinstance(data, dict):
        raise AppError("mappings response from dillyapis was not an object")
    version = data.get("version")
    if not isinstance(version, str):
        raise AppError("mappings response did not include version string")
    match = re.search(r"Release-(\d+)\.(\d+)-CL-(\d+)", version)
    if not match:
        raise AppError(f"could not parse version triplet from mappings version: {version}")
    return match.group(1), match.group(2), match.group(3)


def resolve_v2_cooked_content_package(
    map_code: str,
    token: str,
    *,
    major: str,
    minor: str,
    patch: str,
    role: str,
    platform_name: str,
    timeout: float,
) -> dict[str, Any]:
    url = (
        f"{CONTENT_SERVICE_BASE}/api/content/v2/link/{quote(map_code, safe='')}/cooked-content-package?"
        + urlencode(
            {
                "role": role,
                "platform": platform_name,
                "major": major,
                "minor": minor,
                "patch": patch,
            }
        )
    )
    return request_json(url, token=token, timeout=timeout)


def fetch_module_key_batch(
    token: str,
    *,
    module_id: str,
    module_version: int | str,
    timeout: float,
) -> dict[str, Any]:
    payload = [{"moduleId": str(module_id), "version": module_version}]
    data = request_json(
        MODULE_KEY_BATCH_URL,
        token=token,
        method="POST",
        body=payload,
        timeout=timeout,
    )
    if not isinstance(data, list) or not data:
        raise AppError("module key batch response was empty")

    first = data[0] if isinstance(data[0], dict) else None
    key_info = first.get("key") if isinstance(first, dict) and isinstance(first.get("key"), dict) else None
    if key_info is None:
        raise AppError("module key batch response did not include key data")

    key_b64 = key_info.get("Key")
    guid = key_info.get("Guid")
    if not isinstance(key_b64, str) or not isinstance(guid, str):
        raise AppError("module key payload was missing Key/Guid")

    try:
        aes_key_hex = base64.b64decode(key_b64).hex().upper()
    except Exception as error:
        raise AppError("failed to decode module AES key") from error

    return {
        "moduleId": str(module_id),
        "moduleVersion": module_version,
        "aesKeyHex": aes_key_hex,
        "guid": guid,
        "raw": first,
    }


def cmd_resolve_v2(args: argparse.Namespace) -> int:
    map_code = prompt_map_code(args.map_code)
    output_dir = Path(args.out) / map_code
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.content_token:
        token = args.content_token
    else:
        token = get_content_access_token_via_device_auth(
            data_dir=Path(args.data_dir),
            timeout=args.timeout,
        )

    if args.major and args.minor and args.patch:
        major, minor, patch = str(args.major), str(args.minor), str(args.patch)
    else:
        major, minor, patch = latest_dilly_version_triplet(timeout=args.timeout)

    try:
        data = resolve_v2_cooked_content_package(
            map_code,
            token,
            major=major,
            minor=minor,
            patch=patch,
            role=args.content_role,
            platform_name=args.content_platform,
            timeout=args.timeout,
        )
    except AppError as error:
        message = str(error)
        if "errors.com.epicgames.content-service.unexpected_link_type" in message:
            print("1.0 maps have no encryption and can't be downloaded", file=sys.stderr)
            return 1
        raise

    write_json(output_dir / "content_v2_cooked_content_package.json", data)
    print(f"saved package: {output_dir / 'content_v2_cooked_content_package.json'}")
    if isinstance(data, dict) and data.get("isEncrypted"):
        resolved = data.get("resolved") if isinstance(data.get("resolved"), dict) else {}
        root = resolved.get("root") if isinstance(resolved.get("root"), dict) else {}
        module_id = root.get("moduleId")
        module_version = root.get("version")
        if not isinstance(module_id, str) or module_version is None:
            raise AppError("v2 response is encrypted but resolved.root.moduleId/version is missing")

        key_data = fetch_module_key_batch(
            token,
            module_id=module_id,
            module_version=module_version,
            timeout=args.timeout,
        )
        write_json(output_dir / "module_key_v4.json", key_data)

        print("isEncrypted: true")
        print(f"moduleId: {module_id}")
        print(f"moduleVersion: {module_version}")
        print(f"AES Key: 0x{key_data['aesKeyHex']}")
        print(f"GUID: {key_data['guid']}")
        print(f"saved key data: {output_dir / 'module_key_v4.json'}")
    else:
        print("Map is not encrypted", file=sys.stderr)
    return 0


def add_auth_storage_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data-dir", default="data", help="directory for saved auth sessions")
    parser.add_argument("--label", default="default", help="saved auth label")
    parser.add_argument(
        "--auth-client",
        choices=sorted(CLIENTS),
        help="OAuth client to use when refreshing saved auth. Default: saved client.",
    )
    parser.add_argument("--timeout", type=float, default=30.0)


def add_map_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("map_code", nargs="?", help="12 digits, with or without dashes")
    parser.add_argument("-o", "--out", default="downloads", help="output directory")
    parser.add_argument("--namespace", default="fn", help="mnemonic namespace")
    parser.add_argument(
        "--mnemonic-url",
        default=DEFAULT_MNEMONIC_API,
        help="URL template with {namespace} and {map_code}",
    )
    parser.add_argument("--timeout", type=float, default=30.0)


def add_content_auth_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--content-token",
        help="Epic bearer token for Content Service. Env fallback: EPIC_CONTENT_TOKEN or EPIC_ACCESS_TOKEN",
    )
    parser.add_argument("--data-dir", default="data", help="directory for saved auth sessions")
    parser.add_argument("--label", default="default", help="saved auth label")
    parser.add_argument(
        "--auth-client",
        choices=sorted(CLIENTS),
        help="OAuth client to use when refreshing saved auth. Default: saved client.",
    )
    parser.add_argument(
        "--no-saved-auth",
        action="store_true",
        help="do not load/refresh tokens from the saved session file",
    )
    parser.add_argument(
        "--no-interactive-login",
        action="store_true",
        help="fail instead of prompting for Epic login when saved auth is missing",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Login to Epic and download public UEFN/Fortnite cooked-content artifacts.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    login = subparsers.add_parser("login", help="login and save a local Epic OAuth session")
    login.add_argument("--data-dir", default="data", help="directory for saved auth sessions")
    login.add_argument("--label", default="default", help="saved auth label")
    login.add_argument("--client", choices=sorted(CLIENTS), default="android", help="OAuth client")
    login.add_argument("--timeout", type=float, default=30.0)
    login.set_defaults(func=login_interactive)

    verify = subparsers.add_parser("verify", help="verify a saved or pasted bearer token")
    add_auth_storage_args(verify)
    verify.add_argument("--token", help="bearer token to verify instead of saved auth")
    verify.set_defaults(func=cmd_verify)

    refresh = subparsers.add_parser("refresh", help="refresh and verify saved auth")
    add_auth_storage_args(refresh)
    refresh.set_defaults(func=cmd_refresh)

    token = subparsers.add_parser("token", help="print a saved access token")
    add_auth_storage_args(token)
    token.set_defaults(func=cmd_token)

    logout = subparsers.add_parser("logout", help="delete a saved local auth session")
    add_auth_storage_args(logout)
    logout.set_defaults(func=cmd_logout)

    device_login = subparsers.add_parser(
        "device-login",
        help="login with Epic device-code flow and save device_auth credentials",
    )
    device_login.add_argument("--data-dir", default="data", help="directory for saved auth sessions")
    device_login.add_argument("--timeout", type=float, default=30.0)
    device_login.set_defaults(func=cmd_device_login)

    device_token = subparsers.add_parser(
        "device-token",
        help="print a Content-Service-oriented access token from saved device_auth",
    )
    device_token.add_argument("--data-dir", default="data", help="directory for saved auth sessions")
    device_token.add_argument("--timeout", type=float, default=30.0)
    device_token.set_defaults(func=cmd_device_token)

    resolve = subparsers.add_parser("resolve", help="resolve mnemonic metadata only")
    add_map_args(resolve)
    resolve.set_defaults(func=cmd_resolve)

    scan_logs = subparsers.add_parser(
        "scan-logs",
        help="scan local Fortnite logs for cooked-content plugin.manifest URL candidates",
    )
    add_map_args(scan_logs)
    scan_logs.add_argument(
        "--log-dir",
        help="Fortnite logs directory. Default: %LOCALAPPDATA%\\FortniteGame\\Saved\\Logs",
    )
    scan_logs.add_argument(
        "--max-log-files",
        type=int,
        default=20,
        help="maximum recent log files to scan (default: 20)",
    )
    scan_logs.set_defaults(func=cmd_scan_logs)

    export_bundle = subparsers.add_parser(
        "export-bundle-cache",
        help="export latest local GameCustom InstalledBundle cache to downloads/<map-code>",
    )
    add_map_args(export_bundle)
    export_bundle.add_argument("--bundle-dir", help="specific InstalledBundles/<bundle-id> directory")
    export_bundle.add_argument(
        "--installed-bundles-dir",
        help="InstalledBundles root directory. Default: %LOCALAPPDATA%\\FortniteGame\\Saved\\PersistentDownloadDir\\GameCustom\\InstalledBundles",
    )
    export_bundle.set_defaults(func=cmd_export_bundle_cache)

    probe = subparsers.add_parser("probe", help="resolve mnemonic and probe Content Service")
    add_map_args(probe)
    add_content_auth_args(probe)
    probe.set_defaults(func=cmd_probe)

    resolve_v2 = subparsers.add_parser(
        "resolve-v2",
        help="resolve v2 cooked-content-package using device-auth-based token flow",
    )
    add_map_args(resolve_v2)
    resolve_v2.add_argument("--data-dir", default="data", help="directory for saved auth sessions")
    resolve_v2.add_argument("--content-token", help="optional direct bearer token override")
    resolve_v2.add_argument("--major", help="version major override")
    resolve_v2.add_argument("--minor", help="version minor override")
    resolve_v2.add_argument("--patch", help="version patch(CL) override")
    resolve_v2.add_argument("--content-platform", default="windows", help="v2 platform parameter")
    resolve_v2.add_argument("--content-role", default="client", help="v2 role parameter")
    resolve_v2.set_defaults(func=cmd_resolve_v2)

    download = subparsers.add_parser(
        "download",
        help="download public island cooked-content via Content Service v4 and BPS chunks",
    )
    add_map_args(download)
    add_content_auth_args(download)
    download.add_argument("--artifact-id", help="known Content Service artifact id")
    download.add_argument("--artifact-platform", default="pc", help="artifact platform, default: pc")
    download.add_argument(
        "--max-bytes",
        type=parse_size,
        default=parse_size("2GB"),
        help="maximum bytes for a cooked-content download. Default: 2GB",
    )
    download.add_argument(
        "--content-platform",
        default=DEFAULT_CONTENT_PLATFORM,
        help=f"Content Service v4 platform parameter. Default: {DEFAULT_CONTENT_PLATFORM}",
    )
    download.add_argument(
        "--content-role",
        choices=("client", "server", "editor"),
        default=DEFAULT_CONTENT_ROLE,
        help=f"Content Service v4 role parameter. Default: {DEFAULT_CONTENT_ROLE}",
    )
    download.add_argument(
        "--content-channel",
        default="alt",
        help="CDN channel segment for plugin.manifest and chunks. Default: alt",
    )
    download.add_argument(
        "--fortnite-user-agent",
        help="Fortnite-style User-Agent. Default: auto-detected from local Fortnite logs, then current fallback.",
    )
    download.add_argument(
        "--fortnite-log-dir",
        help="optional Fortnite log directory used only to auto-detect the Fortnite User-Agent build",
    )
    download.add_argument(
        "--skip-aes-key",
        action="store_true",
        help="skip v2 encrypted-map AES key lookup before v4 cooked-content download",
    )
    download.set_defaults(func=cmd_download)

    manifest = subparsers.add_parser(
        "download-manifest",
        help="download plugin.manifest from a direct URL or module/build/version/bundle values",
    )
    add_map_args(manifest)
    manifest.add_argument("--manifest-url", help="direct plugin.manifest URL")
    manifest.add_argument("--module-id", help="root module id for URL construction")
    manifest.add_argument("--build-version", help="build version segment in CDN path")
    manifest.add_argument("--module-version", help="module version value used as v<module-version>")
    manifest.add_argument("--bundle-id", help="bundle id in CDN path")
    manifest.add_argument("--channel", default="alt", help="channel segment in CDN path (default: alt)")
    manifest.add_argument(
        "--content-token",
        help="optional bearer token if the URL requires auth",
    )
    manifest.add_argument("--max-bytes", type=parse_size, default=parse_size("10MB"))
    manifest.set_defaults(func=cmd_download_manifest)

    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["download"]
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except AppError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
"""One scoped, bounded HTTP transport shared by every check."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote

import httpx
from pydantic import Field

from .config import RequestCase, Scenarios
from .models import AuthScheme, Model, Operation
from .spec import InputError

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
AUTH_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-api-key"}


class Unprepared(ValueError):
    """An operation cannot be executed with the supplied fixtures/credentials."""


class Settings(Model):
    concurrency: int = Field(default=8, ge=1, le=50)
    requests_per_second: float = Field(default=5.0, gt=0, le=100)
    max_requests: int = Field(default=500, ge=1, le=100_000)
    request_timeout: float = Field(default=10.0, gt=0, le=120)
    scan_timeout: float = Field(default=300.0, gt=0, le=3600)
    max_response_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    allow_writes: bool = False


@dataclass(frozen=True)
class PreparedRequest:
    method: str
    url: str
    params: dict[str, str]
    headers: dict[str, str]
    cookies: dict[str, str]
    body: Any
    principal_fingerprint: str


@dataclass(frozen=True)
class Observation:
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed_ms: float = 0
    error: str | None = None
    truncated: bool = False

    @property
    def successful(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 300

    def json_value(self) -> Any:
        if self.error or self.truncated or not self.body:
            return None
        media = self.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media != "application/json" and not media.endswith("+json"):
            return None
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeError, RecursionError):
            return None

    def fingerprint(self) -> str | None:
        value = self.json_value()
        if value is None or value == {} or value == [] or value == "":
            return None
        try:
            canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (ValueError, RecursionError):
            return None
        return hashlib.sha256(canonical.encode()).hexdigest()

    def evidence(self) -> dict[str, Any]:
        # No raw URLs, bodies, cookies, authorization headers, or fixture IDs.
        return {
            "status": self.status,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "error": self.error,
            "truncated": self.truncated,
        }


def normalize_base_url(value: str) -> str:
    try:
        url = httpx.URL(value)
    except httpx.InvalidURL as exc:
        raise InputError("Invalid base URL") from exc
    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.userinfo
        or url.query
        or url.fragment
        or "?" in value
        or "#" in value
    ):
        raise InputError("Base URL must be HTTP(S) with no userinfo, query or fragment")
    validate_path(url.path)
    return str(url).rstrip("/")


def validate_path(value: str) -> None:
    # Decode repeatedly to reject path traversal hidden behind nested percent encoding.
    decoded = value
    for _ in range(8):
        candidate = unquote(decoded)
        if candidate == decoded:
            break
        decoded = candidate
    if "\\" in decoded or "//" in decoded or any(p in {".", ".."} for p in decoded.split("/")):
        raise InputError("Ambiguous or traversing request path")


class Context:
    def __init__(
        self,
        base_url: str,
        schemes: dict[str, AuthScheme],
        scenarios: Scenarios,
        credentials: dict[str, dict[str, str]],
        settings: Settings,
        client: httpx.AsyncClient,
    ):
        self.base_url = normalize_base_url(base_url)
        self.schemes = schemes
        self.scenarios = scenarios
        self.credentials = credentials
        self.settings = settings
        self.client = client
        self.semaphore = asyncio.Semaphore(settings.concurrency)
        self.pacing_lock = asyncio.Lock()
        self.next_request_at = 0.0
        self.requests_sent = 0
        self.budget_exhausted = False

    def prepare(
        self,
        op: Operation,
        identity: str | None = "A",
        *,
        overrides: dict[tuple[str, str], Any] | None = None,
    ) -> PreparedRequest:
        if op.method not in SAFE_METHODS and not self.settings.allow_writes:
            raise Unprepared("Write methods need --allow-writes and explicit fixtures")
        if op.method == "TRACE":
            raise Unprepared("TRACE is inventoried but never executed")
        case = self.scenarios.request_case(op.key)
        if op.method not in SAFE_METHODS and not any(
            c.operation == op.key for c in self.scenarios.requests
        ):
            raise Unprepared("Write methods require an explicit request fixture")
        values: dict[str, dict[str, Any]] = {
            loc: {} for loc in ("path", "query", "header", "cookie")
        }
        supplied = deepcopy(case.values)
        for (location, name), value in (overrides or {}).items():
            supplied.setdefault(location, {})[name] = value
        auth_locations = {
            (
                s.location,
                s.wire_name.lower() if s.location == "header" and s.wire_name else s.wire_name,
            )
            for s in self.schemes.values()
            if s.type == "apiKey"
        }
        auth_locations |= {("header", name) for name in AUTH_HEADERS}
        for parameter in op.parameters:
            location, name = parameter.location, parameter.name
            if location in {"body", "formData"}:
                if location == "formData":
                    raise Unprepared("formData serialization is unsupported; use a JSON operation")
                continue
            key = (location, name.lower() if location == "header" else name)
            if key in auth_locations:
                continue  # Credentials are supplied only by the selected principal below.
            value = supplied.get(location, {}).get(name, parameter.example)
            if value is None:
                if parameter.required:
                    raise Unprepared("Required parameter has no fixture or scalar example")
                continue
            if not isinstance(value, (str, int, float, bool)):
                raise Unprepared(
                    "Only scalar parameters are supported; arrays/objects need serializers"
                )
            if parameter.style not in {
                None,
                "simple" if location in {"path", "header"} else "form",
            }:
                raise Unprepared("Unsupported parameter serialization style")
            values[location][name] = str(value).lower() if isinstance(value, bool) else str(value)
        # Prevent a fixture typo from silently testing a different request than intended.
        known = {(p.location, p.name) for p in op.parameters}
        if any((loc, name) not in known for loc, entries in supplied.items() for name in entries):
            raise Unprepared("Request fixture refers to an undeclared parameter")
        headers = {
            "accept": "application/json",
            "accept-encoding": "identity",
            "user-agent": "api-sentry/0.1.0",
            **{k.lower(): v for k, v in values["header"].items()},
        }
        if any(k in headers for k in {"host", "content-length", "transfer-encoding"}):
            raise Unprepared("Routing and framing headers cannot be supplied as parameters")
        chosen = self._select_auth(op, identity)
        applied = []
        auth_slots = set()
        for scheme_name, secret in chosen.items():
            scheme = self.schemes[scheme_name]
            slot = (
                (
                    scheme.location,
                    scheme.wire_name.lower()
                    if scheme.location == "header" and scheme.wire_name
                    else scheme.wire_name,
                )
                if scheme.type == "apiKey"
                else ("header", "authorization")
            )
            if slot in auth_slots:
                raise Unprepared("AND authentication schemes cannot share a wire location")
            auth_slots.add(slot)
            if scheme.type == "apiKey":
                if scheme.location not in {"header", "query", "cookie"} or not scheme.wire_name:
                    raise Unprepared("Unsupported API key location")
                if scheme.location == "header":
                    name = scheme.wire_name.lower()
                    if name in {"host", "content-length", "transfer-encoding"}:
                        raise Unprepared("Authentication cannot replace routing or framing headers")
                    headers[name] = secret
                else:
                    values[scheme.location][scheme.wire_name] = secret
            elif scheme.type in {"oauth2", "openIdConnect"} or scheme.scheme == "bearer":
                headers["authorization"] = f"Bearer {secret}"
            elif scheme.type == "basic" or scheme.scheme == "basic":
                encoded = base64.b64encode(secret.encode()).decode("ascii")
                headers["authorization"] = f"Basic {encoded}"
            else:
                raise Unprepared(
                    "Authentication scheme is inventoried but not supported by transport"
                )
            if scheme.type == "apiKey":
                applied.append((*slot, secret))
            else:
                applied.append(("header", "authorization", headers["authorization"]))
        path = op.path
        for name, value in values["path"].items():
            path = path.replace("{" + name + "}", quote(value, safe=""))
        if re.search(r"[{}]", path):
            raise Unprepared("Unresolved path parameter")
        validate_path(path)
        url = self.base_url + path
        target, base = httpx.URL(url), httpx.URL(self.base_url)
        if (target.scheme, target.host, target.port) != (base.scheme, base.host, base.port):
            raise Unprepared("Request escaped the configured origin")
        if op.request_body and op.request_body.get("required") and case.body is None:
            raise Unprepared("Required JSON request body is missing")
        if any(p.location == "body" and p.required for p in op.parameters) and case.body is None:
            raise Unprepared("Required Swagger JSON request body is missing")
        if case.body is not None and op.request_body:
            if "application/json" not in op.request_body.get("content", {}):
                raise Unprepared("Only application/json request bodies are supported")
        principal = (
            hashlib.sha256(json.dumps(sorted(applied)).encode()).hexdigest() if applied else ""
        )
        return PreparedRequest(
            op.method, url, values["query"], headers, values["cookie"], case.body, principal
        )

    def _select_auth(self, op: Operation, identity: str | None) -> dict[str, str]:
        if identity is None:
            return {}
        available = self.credentials.get(identity, {})
        # OR across requirements, AND within each requirement; do not partially satisfy AND.
        for requirement in op.security:
            if requirement and requirement.keys() <= available.keys():
                return {name: available[name] for name in requirement}
        if op.requires_auth:
            raise Unprepared("No identity satisfies the operation's security requirements")
        return {}

    async def send(
        self,
        request: PreparedRequest,
        *,
        burst: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> Observation:
        async with self.semaphore:
            if not burst:
                async with self.pacing_lock:
                    await asyncio.sleep(max(0, self.next_request_at - time.monotonic()))
                    self.next_request_at = time.monotonic() + 1 / self.settings.requests_per_second
            # No await between budget check and increment: atomic on this event loop.
            if self.requests_sent >= self.settings.max_requests:
                self.budget_exhausted = True
                return Observation(error="request_budget_exhausted")
            started = time.monotonic()
            try:
                headers = {**request.headers, **(extra_headers or {})}
                if extra_headers and set(k.lower() for k in extra_headers) != {"origin"}:
                    return Observation(error="unsupported_header_override")
                # Construct directly: AsyncClient.build_request would merge the client's cookie jar.
                wire = httpx.Request(
                    request.method,
                    request.url,
                    params=request.params,
                    headers=headers,
                    cookies=request.cookies,
                    **({"json": request.body} if request.body is not None else {}),
                )
                wire.extensions["timeout"] = httpx.Timeout(self.settings.request_timeout).as_dict()
                body = bytearray()
                truncated = False
                async with asyncio.timeout(self.settings.request_timeout):
                    self.requests_sent += 1
                    response = await self.client.send(wire, stream=True, follow_redirects=False)
                    try:
                        # Keep the response cap meaningful even for a hostile compressed response.
                        # identity is requested; unsupported encodings are never decompressed.
                        encoding = (
                            response.headers.get("content-encoding", "identity").strip().lower()
                        )
                        if encoding not in {"", "identity"}:
                            return Observation(
                                status=response.status_code,
                                elapsed_ms=(time.monotonic() - started) * 1000,
                                error="unsupported_content_encoding",
                            )
                        async for chunk in response.aiter_bytes(chunk_size=8192):
                            remaining = self.settings.max_response_bytes - len(body)
                            body.extend(chunk[:remaining])
                            if len(chunk) > remaining:
                                truncated = True
                                break
                        # Capture only headers used by checks; exclude Set-Cookie and other secrets.
                        keep = {
                            "content-type",
                            "strict-transport-security",
                            "content-security-policy",
                            "x-frame-options",
                            "access-control-allow-origin",
                            "access-control-allow-credentials",
                        }
                        captured = {k: v for k, v in response.headers.items() if k in keep}
                        return Observation(
                            response.status_code,
                            captured,
                            bytes(body),
                            (time.monotonic() - started) * 1000,
                            truncated=truncated,
                        )
                    finally:
                        await response.aclose()
            except (httpx.HTTPError, TimeoutError, ValueError) as exc:
                return Observation(
                    elapsed_ms=(time.monotonic() - started) * 1000, error=type(exc).__name__
                )

    def baseline(self, op: Operation) -> PreparedRequest:
        case: RequestCase = self.scenarios.request_case(op.key)
        prepared = self.prepare(op, case.identity)
        if case.expect_auth and not prepared.principal_fingerprint:
            raise Unprepared(
                "Expected-protected control needs effective credentials declared in security"
            )
        return prepared

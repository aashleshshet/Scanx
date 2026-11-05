"""Public HTTPS-only egress with DNS pinning and no redirects."""

import asyncio
import ipaddress
import re
import socket

import httpx

from ..transport import normalize_base_url


def validate_credentials(scenarios):
    """Uploaded fixtures cannot reference infrastructure or provider secrets."""
    for schemes in scenarios.identities.values():
        for credential in schemes.values():
            if not re.fullmatch(r"ONESCANX_SCAN_[A-Z0-9_]{1,100}", credential.env):
                raise ValueError("Scan credential references must use ONESCANX_SCAN_ names")


def public_address(value):
    ip = ipaddress.ip_address(value)
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


async def resolve_public(host):
    rows = await asyncio.to_thread(socket.getaddrinfo, host, 443, type=socket.SOCK_STREAM)
    addresses = sorted({row[4][0] for row in rows})
    if not addresses or not all(public_address(ip) for ip in addresses):
        raise ValueError("Target resolves to a non-public address")
    return addresses[0]


def approved_target(value, allowlist):
    target = normalize_base_url(value)
    url = httpx.URL(target)
    if url.scheme != "https" or url.port not in (None, 443) or target not in allowlist:
        raise ValueError("Target must exactly match an operator-approved HTTPS API root")
    return target


class PinnedTransport(httpx.AsyncBaseTransport):
    def __init__(self, base):
        self.base = httpx.URL(base)
        self.inner = httpx.AsyncHTTPTransport(retries=0)

    async def handle_async_request(self, request):
        url = request.url
        if (url.scheme, url.host, url.port) != (self.base.scheme, self.base.host, self.base.port):
            raise ValueError("Request outside approved origin")
        address = await resolve_public(url.host)
        # Connect to the validated IP, retaining original TLS SNI/certificate identity.
        request.url = url.copy_with(host=address)
        request.headers["host"] = url.host
        request.extensions["sni_hostname"] = url.host
        return await self.inner.handle_async_request(request)

    async def aclose(self):
        await self.inner.aclose()


async def verify_challenge(target, token):
    url = httpx.URL(target)
    origin = str(url.copy_with(path="/", query=None))
    async with httpx.AsyncClient(
        transport=PinnedTransport(target), trust_env=False, timeout=8, follow_redirects=False
    ) as client:
        async with client.stream("GET", origin + ".well-known/onescanx-verification.txt") as res:
            if res.status_code != 200:
                return False
            body = bytearray()
            async for part in res.aiter_bytes():
                body.extend(part)
                if len(body) > 256:
                    return False
            return body.decode("utf-8", errors="replace").strip() == token

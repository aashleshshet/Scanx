from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import asynccontextmanager

import httpx

from api_sentry.config import BolaCase, Credential, ParameterRef, RequestCase, Scenarios
from api_sentry.models import AuthScheme, Operation, Parameter
from api_sentry.transport import Context, Settings


def fixtures(location="path", id_a="101", id_b="202"):
    path = "/orders/{order_id}" if location == "path" else "/order"
    op = Operation(
        method="GET",
        path=path,
        security=[{"bearerAuth": []}],
        parameters=[
            Parameter(name="order_id", location=location, required=True, schema={"type": "string"})
        ],
    )
    schemes = {"bearerAuth": AuthScheme(name="bearerAuth", type="http", scheme="bearer")}
    scenarios = Scenarios(
        identities={
            "A": {"bearerAuth": Credential(env="TOKEN_A")},
            "B": {"bearerAuth": Credential(env="TOKEN_B")},
        },
        requests=[RequestCase(operation=op.key, values={location: {"order_id": id_a}})],
        bola=[
            BolaCase(
                operation=op.key,
                parameter=ParameterRef(location=location, name="order_id"),
                object_a=id_a,
                object_b=id_b,
                private_objects=True,
            )
        ],
    )
    return op, schemes, scenarios


def object_api(mode="vulnerable", location="path", id_a="101", id_b="202"):
    def handler(request: httpx.Request) -> httpx.Response:
        object_id = (
            request.url.path.rsplit("/", 1)[-1]
            if location == "path"
            else request.url.params["order_id"]
        )
        token = request.headers.get("authorization")
        if not token:
            return httpx.Response(403)
        own = {"Bearer user-a": id_a, "Bearer user-b": id_b}.get(token)
        if own is None:
            return httpx.Response(401)
        if object_id not in {id_a, id_b}:
            return httpx.Response(404)
        if mode == "protected" and object_id != own:
            return httpx.Response(403)
        if mode == "generic" and object_id != own:
            return httpx.Response(200, json={"ok": True})
        if mode == "different" and object_id != own:
            return httpx.Response(200, json={"id": object_id})
        if mode == "bad-baseline":
            return httpx.Response(200, json={"ok": True})
        if mode == "unstable":
            return httpx.Response(200, json={"id": object_id, "request": str(request)})
        return httpx.Response(200, json={"id": object_id, "private": "synthetic private fixture"})

    return handler


@asynccontextmanager
async def context(
    handler: Callable, *, schemes=None, scenarios=None, settings=None, base="https://api.test"
):
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False) as client:
        yield Context(
            base,
            schemes or {},
            scenarios or Scenarios(),
            {"A": {"bearerAuth": "user-a"}, "B": {"bearerAuth": "user-b"}},
            settings or Settings(requests_per_second=100),
            client,
        )


def run(coroutine):
    return asyncio.run(coroutine)

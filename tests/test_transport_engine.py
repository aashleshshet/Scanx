import asyncio

import httpx
import pytest
from conftest import context, fixtures, object_api, run

from api_sentry.checks.bola import BolaCheck
from api_sentry.config import RequestCase, Scenarios
from api_sentry.engine import scan
from api_sentry.models import AuthScheme, Operation
from api_sentry.spec import InputError
from api_sentry.transport import Settings, Unprepared, normalize_base_url


@pytest.mark.parametrize(
    "url",
    [
        "https://a.test/?token=secret",
        "https://u:p@a.test",
        "file:///tmp/api",
        "https://a.test/#x",
        "https://a.test/api/%252e%252e/admin",
    ],
)
def test_target_validation(url):
    with pytest.raises(InputError):
        normalize_base_url(url)


def test_base_prefix_is_preserved_and_redirects_not_followed():
    async def experiment():
        seen = []

        def handler(request):
            seen.append(str(request.url))
            return httpx.Response(302, headers={"location": "https://other.test"})

        op = Operation(method="GET", path="/orders")
        async with context(handler, base="https://api.test/api/v1") as ctx:
            response = await ctx.send(ctx.prepare(op))
            assert response.status == 302
            assert seen == ["https://api.test/api/v1/orders"]

    run(experiment())


def test_cookie_jar_does_not_cross_identity_or_anonymous_boundary():
    async def experiment():
        seen = []

        def handler(request):
            seen.append(request.headers.get("cookie"))
            return httpx.Response(
                200, headers={"set-cookie": "session=owner-a; Path=/"}, json={"ok": True}
            )

        op = Operation(method="GET", path="/test")
        async with context(handler) as ctx:
            await ctx.send(ctx.prepare(op, "A"))
            await ctx.send(ctx.prepare(op, None))
            assert seen == [None, None]

    run(experiment())


def test_auth_or_and_semantics_and_anonymous_stripping():
    async def experiment():
        schemes = {
            "key": AuthScheme(name="key", type="apiKey", location="query", wire_name="api_key"),
            "bearerAuth": AuthScheme(name="bearerAuth", type="http", scheme="bearer"),
        }
        op = Operation(method="GET", path="/test", security=[{"key": [], "bearerAuth": []}])
        async with context(lambda _: httpx.Response(200), schemes=schemes) as ctx:
            with pytest.raises(Unprepared):
                ctx.prepare(op, "A")
            ctx.credentials["A"]["key"] = "query-secret"
            both = ctx.prepare(op, "A")
            assert both.params["api_key"] == "query-secret"
            assert both.headers["authorization"] == "Bearer user-a"
            anon = ctx.prepare(op, None)
            assert "api_key" not in anon.params
            assert "authorization" not in anon.headers

    run(experiment())


def test_truncated_response_not_used_as_json_evidence():
    async def experiment():
        def handler(_):
            return httpx.Response(200, json={"value": "x" * 5000})

        async with context(
            handler, settings=Settings(max_response_bytes=1024, requests_per_second=100)
        ) as ctx:
            response = await ctx.send(ctx.prepare(Operation(method="GET", path="/test")))
            assert response.truncated
            assert len(response.body) == 1024
            assert response.fingerprint() is None

    run(experiment())


def test_request_budget_yields_partial_report(monkeypatch):
    op, schemes, scenarios = fixtures()
    monkeypatch.setenv("TOKEN_A", "user-a")
    monkeypatch.setenv("TOKEN_B", "user-b")
    report = run(
        scan(
            base_url="https://api.test",
            operations=[op],
            schemes=schemes,
            scenarios=scenarios,
            settings=Settings(max_requests=2, requests_per_second=100),
            checks=[BolaCheck()],
            spec_sha256="a" * 64,
            transport=httpx.MockTransport(object_api()),
        )
    )
    assert report.status == "partial"
    assert report.requests_sent == 2
    assert not report.checks[0].findings


def test_deadline_cancels_and_records_unfinished_checks():
    async def slow(_):
        await asyncio.sleep(1)
        return httpx.Response(200)

    op, schemes, scenarios = fixtures()
    scenarios.identities = {}

    # Credentials missing would skip, so use a deliberately slow generic plugin here.
    class SlowCheck:
        name = "slow"

        async def run(self, ctx, operation):
            await asyncio.sleep(1)
            return []

    report = run(
        scan(
            base_url="https://api.test",
            operations=[op],
            schemes=schemes,
            scenarios=scenarios,
            settings=Settings(scan_timeout=0.02),
            checks=[SlowCheck()],
            spec_sha256="a" * 64,
            transport=httpx.MockTransport(slow),
        )
    )
    assert report.status == "partial"
    assert report.checks[0].status == "inconclusive"


def test_write_methods_require_both_flag_and_fixture():
    async def experiment():
        op = Operation(method="DELETE", path="/orders/101")
        async with context(lambda _: httpx.Response(204)) as ctx:
            with pytest.raises(Unprepared):
                ctx.prepare(op)
            ctx.settings.allow_writes = True
            with pytest.raises(Unprepared):
                ctx.prepare(op)
            ctx.scenarios.requests = [RequestCase(operation=op.key)]
            assert ctx.prepare(op).method == "DELETE"

    run(experiment())


def test_declared_policy_cannot_compare_two_anonymous_requests():
    async def experiment():
        op = Operation(method="GET", path="/private")
        scenarios = Scenarios(requests=[RequestCase(operation=op.key, expect_auth=True)])
        async with context(lambda _: httpx.Response(200), scenarios=scenarios) as ctx:
            with pytest.raises(Unprepared):
                ctx.baseline(op)

    run(experiment())


def test_and_schemes_cannot_silently_overwrite_one_auth_header():
    async def experiment():
        schemes = {
            name: AuthScheme(name=name, type="http", scheme="bearer") for name in ("one", "two")
        }
        op = Operation(method="GET", path="/private", security=[{"one": [], "two": []}])
        async with context(lambda _: httpx.Response(200), schemes=schemes) as ctx:
            ctx.credentials["A"] = {"one": "first-token", "two": "second-token"}
            with pytest.raises(Unprepared):
                ctx.prepare(op)

    run(experiment())


def test_exactly_consumed_budget_does_not_make_complete_work_partial():
    class OneCheck:
        name = "one"

        async def run(self, ctx, operation):
            from api_sentry.models import CheckResult

            await ctx.send(ctx.prepare(operation))
            return [
                CheckResult(
                    module=self.name, operation=operation.key, status="passed", reason="Completed"
                )
            ]

    report = run(
        scan(
            base_url="https://api.test",
            operations=[Operation(method="GET", path="/test")],
            schemes={},
            scenarios=Scenarios(),
            settings=Settings(max_requests=1),
            checks=[OneCheck()],
            spec_sha256="a" * 64,
            transport=httpx.MockTransport(lambda _: httpx.Response(200)),
        )
    )
    assert report.status == "complete"
    assert report.requests_sent == 1


def test_per_request_deadline_is_an_observation_error():
    async def experiment():
        async def slow(_):
            await asyncio.sleep(1)
            return httpx.Response(200)

        async with context(slow, settings=Settings(request_timeout=0.01)) as ctx:
            response = await ctx.send(ctx.prepare(Operation(method="GET", path="/test")))
            assert response.error == "TimeoutError"
            assert response.status is None

    run(experiment())


def test_server_compression_is_rejected_without_decoding():
    async def experiment():
        def compressed(_):
            # Invalid compressed data would throw if a decoder were invoked.
            return httpx.Response(
                200,
                headers={"content-encoding": "gzip"},
                stream=httpx.ByteStream(b"never-decode-this"),
            )

        async with context(compressed) as ctx:
            response = await ctx.send(ctx.prepare(Operation(method="GET", path="/test")))
            assert response.error == "unsupported_content_encoding"
            assert response.body == b""

    run(experiment())

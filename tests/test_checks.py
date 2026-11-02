import asyncio

import httpx
import pytest
from conftest import context, fixtures, run

from api_sentry.checks.auth import AuthenticationCheck
from api_sentry.checks.cors import CorsCheck
from api_sentry.checks.headers import HeadersCheck
from api_sentry.checks.injection import InjectionCheck
from api_sentry.checks.rate_limit import RateLimitCheck
from api_sentry.config import ParameterRef, RequestCase, Scenarios
from api_sentry.models import Operation, Parameter, Severity
from api_sentry.transport import Observation, Settings


def test_generic_200_different_from_owner_is_not_auth_bypass():
    async def experiment():
        op, schemes, scenarios = fixtures()

        def handler(request):
            return httpx.Response(
                200, json={"id": 101} if "authorization" in request.headers else {"login": True}
            )

        async with context(handler, schemes=schemes, scenarios=scenarios) as ctx:
            result = (await AuthenticationCheck().run(ctx, op))[0]
            assert not result.findings
            assert result.status == "inconclusive"

    run(experiment())


def test_public_route_success_is_an_observation():
    async def experiment():
        async with context(lambda _: httpx.Response(200, json={"ok": True})) as ctx:
            result = (
                await AuthenticationCheck().run(ctx, Operation(method="GET", path="/health"))
            )[0]
            assert not result.findings
            assert result.status == "passed"

    run(experiment())


def test_json_header_context_does_not_flag_csp_or_framing():
    async def experiment():
        def handler(_):
            return httpx.Response(
                200, headers={"strict-transport-security": "max-age=300"}, json={"ok": True}
            )

        async with context(handler) as ctx:
            result = (await HeadersCheck().run(ctx, Operation(method="GET", path="/test")))[0]
            assert not result.findings
            assert "content-security-policy" in result.observations["missing_headers"]

    run(experiment())


def test_csp_frame_ancestors_satisfies_framing_control():
    async def experiment():
        def handler(_):
            return httpx.Response(
                200,
                headers={
                    "strict-transport-security": "max-age=300",
                    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
                    "content-type": "text/html",
                },
                text="<html>Example</html>",
            )

        async with context(handler) as ctx:
            result = (await HeadersCheck().run(ctx, Operation(method="GET", path="/test")))[0]
            assert not result.findings

    run(experiment())


@pytest.mark.parametrize("reflection,severity", [(False, Severity.LOW), (True, Severity.MEDIUM)])
def test_cors_classification(reflection, severity):
    async def experiment():
        def handler(request):
            return httpx.Response(
                200,
                json={"ok": True},
                headers={
                    "access-control-allow-origin": request.headers["origin"] if reflection else "*",
                    "access-control-allow-credentials": "true",
                },
            )

        async with context(handler) as ctx:
            result = (await CorsCheck().run(ctx, Operation(method="GET", path="/test")))[0]
            assert result.findings[0].severity == severity
            assert result.findings[0].verification == "needs_review"

    run(experiment())


@pytest.mark.parametrize("throttle", [False, True])
def test_burst_exact_count_concurrency_and_bounded_claim(throttle):
    async def experiment():
        active, peak, calls = 0, 0, 0

        async def handler(_):
            nonlocal active, peak, calls
            calls += 1
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.001)
            active -= 1
            return httpx.Response(429 if throttle and calls > 20 else 200, json={"ok": True})

        op = Operation(method="GET", path="/search")
        scenarios = Scenarios(requests=[RequestCase(operation=op.key, rate_limit=True)])
        async with context(
            handler, scenarios=scenarios, settings=Settings(concurrency=8, requests_per_second=100)
        ) as ctx:
            result = (await RateLimitCheck().run(ctx, op))[0]
            assert calls == 51  # One control plus exactly 50 burst requests.
            assert peak <= 8
            assert result.observations["burst_size"] == 50
            assert result.status == ("passed" if throttle else "inconclusive")
            assert bool(result.findings) is not throttle

    run(experiment())


def test_sql_syntax_signal_is_a_candidate_without_response_body_leak():
    async def experiment():
        op = Operation(
            method="GET",
            path="/search",
            parameters=[
                Parameter(name="q", location="query", example="notebook", schema={"type": "string"})
            ],
        )
        scenarios = Scenarios(
            requests=[
                RequestCase(
                    operation=op.key,
                    injection_parameters=[ParameterRef(location="query", name="q")],
                )
            ]
        )

        def handler(request):
            if "'" in request.url.params["q"]:
                return httpx.Response(
                    500, text="You have an error in your SQL syntax; secret database detail"
                )
            return httpx.Response(200, json={"items": []})

        async with context(handler, scenarios=scenarios) as ctx:
            result = (await InjectionCheck().run(ctx, op))[0]
            assert len(result.findings) == 1
            assert result.findings[0].verification == "needs_review"
            assert "secret database detail" not in result.model_dump_json()

    run(experiment())


def test_timing_requires_repeatability_and_rejects_timeout_evidence():
    controls = [Observation(status=200, elapsed_ms=100 + i) for i in range(3)]
    probes = [Observation(status=200, elapsed_ms=2100 + i) for i in range(3)]
    assert InjectionCheck._timing_evidence(controls, probes)["repeatable_delay"]
    probes[1] = Observation(error="ReadTimeout", elapsed_ms=5000)
    assert not InjectionCheck._timing_evidence(controls, probes)["repeatable_delay"]
    noisy = [Observation(status=200, elapsed_ms=100 + i * 600) for i in range(3)]
    assert not InjectionCheck._timing_evidence(noisy, probes)["repeatable_delay"]

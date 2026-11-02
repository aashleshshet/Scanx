import httpx
import pytest
from conftest import context, fixtures, object_api, run

from api_sentry.checks.bola import BolaCheck


@pytest.mark.parametrize("location", ["path", "query"])
@pytest.mark.parametrize(
    "ids",
    [
        ("101", "202"),
        ("d1161545-f987-4ba0-98c7-d6e416f5bac5", "286055bd-c422-4ac5-9ec4-bf56fd40b5dd"),
    ],
)
def test_cross_principal_disclosure_is_confirmed(location, ids):
    async def experiment():
        op, schemes, scenarios = fixtures(location, *ids)
        async with context(
            object_api(location=location, id_a=ids[0], id_b=ids[1]),
            schemes=schemes,
            scenarios=scenarios,
        ) as ctx:
            result = (await BolaCheck().run(ctx, op))[0]
            assert result.status == "failed"
            assert len(result.findings) == 2
            assert all(f.verification == "confirmed" for f in result.findings)
            assert ctx.requests_sent == 8
            serialized = result.model_dump_json()
            assert "synthetic private fixture" not in serialized
            assert "user-a" not in serialized

    run(experiment())


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("protected", "passed"),
        ("generic", "inconclusive"),
        ("different", "inconclusive"),
        ("bad-baseline", "inconclusive"),
    ],
)
def test_status_alone_does_not_prove_bola(mode, expected):
    async def experiment():
        op, schemes, scenarios = fixtures()
        async with context(object_api(mode), schemes=schemes, scenarios=scenarios) as ctx:
            result = (await BolaCheck().run(ctx, op))[0]
            assert result.status == expected
            assert not result.findings

    run(experiment())


def test_same_effective_credentials_are_rejected():
    async def experiment():
        op, schemes, scenarios = fixtures()
        async with context(object_api(), schemes=schemes, scenarios=scenarios) as ctx:
            ctx.credentials["B"] = ctx.credentials["A"].copy()
            result = (await BolaCheck().run(ctx, op))[0]
            assert result.status == "inconclusive"
            assert ctx.requests_sent == 0

    run(experiment())


def test_public_objects_do_not_become_confirmed_bola():
    async def experiment():
        op, schemes, scenarios = fixtures()

        def public(request):
            return httpx.Response(200, json={"id": request.url.path.rsplit("/", 1)[-1]})

        async with context(public, schemes=schemes, scenarios=scenarios) as ctx:
            result = (await BolaCheck().run(ctx, op))[0]
            assert result.status == "inconclusive"
            assert not result.findings

    run(experiment())


def test_mutating_operation_is_never_used_for_bola():
    async def experiment():
        op, schemes, scenarios = fixtures()
        op.method = "DELETE"
        async with context(object_api(), schemes=schemes, scenarios=scenarios) as ctx:
            assert (await BolaCheck().run(ctx, op))[0].status == "skipped"
            assert ctx.requests_sent == 0

    run(experiment())

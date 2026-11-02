"""Thin argparse adapter; test modules never depend on CLI state."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from .checks.auth import AuthenticationCheck
from .checks.bola import BolaCheck
from .checks.cors import CorsCheck
from .checks.headers import HeadersCheck
from .checks.injection import InjectionCheck
from .checks.rate_limit import RateLimitCheck
from .config import Scenarios, load_scenarios
from .engine import scan
from .models import AuthScheme, Operation, Severity
from .reporting import atomic_write, report_schema, write_reports
from .spec import InputError, inventory, parse_spec
from .transport import Settings, normalize_base_url


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="api-sentry", description="Bounded REST API security checks"
    )
    commands = root.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="Parse the spec without making network requests")
    inspect.add_argument("--spec", type=Path, required=True)
    schema = commands.add_parser("schema", help="Print the versioned JSON reporting schema")
    schema.add_argument("--output", type=Path)
    run = commands.add_parser("scan", help="Scan an API you are authorized to test")
    run.add_argument(
        "--base-url", required=True, help="Exact API root, including any /api/v1 prefix"
    )
    run.add_argument("--spec", type=Path, required=True)
    run.add_argument("--scenarios", type=Path)
    run.add_argument("--output-dir", type=Path, default=Path("reports"))
    run.add_argument(
        "--checks",
        default="bola,auth,headers,cors",
        help="Comma-separated selection: bola,auth,headers,cors,injection,rate_limit",
    )
    run.add_argument(
        "--injection", action="store_true", help="Enable syntax probes on selected parameters"
    )
    run.add_argument(
        "--timing", action="store_true", help="Also enable repeated 2-second SQL/shell delay probes"
    )
    run.add_argument("--sql-dialect", choices=("postgres", "mysql"), default="postgres")
    run.add_argument(
        "--rate-limit", action="store_true", help="Enable configured 50-request bursts"
    )
    run.add_argument(
        "--allow-writes",
        action="store_true",
        help="Allow explicitly configured POST/PUT/PATCH/DELETE",
    )
    run.add_argument("--concurrency", type=int, default=8)
    run.add_argument("--rps", type=float, default=5)
    run.add_argument("--max-requests", type=int, default=500)
    run.add_argument("--request-timeout", type=float, default=10)
    run.add_argument("--scan-timeout", type=float, default=300)
    run.add_argument("--fail-on", choices=[s.value for s in Severity], help="CI severity threshold")
    return root


def validate_scenarios(
    scenarios: Scenarios, operations: list[Operation], schemes: dict[str, AuthScheme]
) -> None:
    known = {op.key for op in operations}
    if any(case.operation not in known for case in [*scenarios.requests, *scenarios.bola]):
        raise InputError("Scenario refers to an operation absent from the specification")
    if any(not sources.keys() <= schemes.keys() for sources in scenarios.identities.values()):
        raise InputError("An identity references an undefined security scheme")


def main(argv: list[str] | None = None) -> int:
    root = parser()
    args = root.parse_args(argv)
    try:
        if args.command == "schema":
            content = json.dumps(report_schema(), indent=2) + "\n"
            atomic_write(args.output, content) if args.output else print(content, end="")
            return 0
        operations, schemes, digest = parse_spec(args.spec)
        if args.command == "inspect":
            print(inventory(operations, schemes))
            return 0
        target = normalize_base_url(args.base_url)
        scenarios = load_scenarios(args.scenarios)
        validate_scenarios(scenarios, operations, schemes)
        settings = Settings(
            concurrency=args.concurrency,
            requests_per_second=args.rps,
            max_requests=args.max_requests,
            request_timeout=args.request_timeout,
            scan_timeout=args.scan_timeout,
            allow_writes=args.allow_writes,
        )
        if args.timing and not args.injection:
            raise InputError("--timing requires --injection")
        if args.timing and args.request_timeout < 5:
            raise InputError("Timing experiments require a request timeout of at least 5 seconds")
        registry = {
            check.name: check
            for check in (
                BolaCheck(),
                AuthenticationCheck(),
                HeadersCheck(),
                CorsCheck(),
                InjectionCheck(args.timing, args.sql_dialect),
                RateLimitCheck(),
            )
        }
        requested = list(dict.fromkeys(name.strip() for name in args.checks.split(",")))
        if not requested or any(name not in registry for name in requested):
            raise InputError("Unknown or empty check selection")
        if args.injection and "injection" not in requested:
            requested.append("injection")
        if args.rate_limit and "rate_limit" not in requested:
            requested.append("rate_limit")
        if "injection" in requested and not args.injection:
            raise InputError("Selecting injection also requires --injection")
        if "rate_limit" in requested and not args.rate_limit:
            raise InputError("Selecting rate_limit also requires --rate-limit")
        report = asyncio.run(
            scan(
                base_url=target,
                operations=operations,
                schemes=schemes,
                scenarios=scenarios,
                settings=settings,
                checks=[registry[name] for name in requested],
                spec_sha256=digest,
            )
        )
        secrets = [
            value for values in scenarios.credentials().values() for value in values.values()
        ]
        files = write_reports(report, args.output_dir, secrets)
        print(
            f"Scan {report.status}: {report.requests_sent} requests; "
            + ", ".join(f"{severity.value}={report.summary[severity]}" for severity in Severity)
        )
        for file in files:
            print(file.resolve())
        if report.status == "partial":
            return 2
        if args.fail_on:
            levels = list(Severity)
            if any(
                report.summary[level]
                for level in levels[: levels.index(Severity(args.fail_on)) + 1]
            ):
                return 1
        return 0
    except (OSError, InputError, ValidationError, KeyError, TypeError, ValueError) as exc:
        # InputError strings are scanner-owned. Other exception strings may contain input secrets.
        print(
            f"Input/output error: {exc if isinstance(exc, InputError) else type(exc).__name__}",
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        print("Scan interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

"""A bounded local-document OpenAPI 3.0/3.1 and Swagger 2.0 normalizer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import yaml

from .models import AuthScheme, Operation, Parameter

METHODS = {"get", "head", "options", "post", "put", "patch", "delete", "trace"}
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024


class InputError(ValueError):
    """An unsupported or invalid specification/configuration."""


class BoundedSafeLoader(yaml.SafeLoader):
    """Reject aliases and duplicate keys instead of silently accepting ambiguous input."""

    def __init__(self, stream: Any):
        super().__init__(stream)
        self.node_count = 0
        self.node_depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise InputError("YAML aliases are unsupported; expand anchors before scanning")
        self.node_count += 1
        if self.node_count > 100_000 or self.node_depth >= 64:
            raise InputError("Document exceeds the node-count or nesting-depth limit")
        self.node_depth += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self.node_depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> dict:
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise InputError("Mapping keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_document(file: Path) -> tuple[dict[str, Any], str]:
    with file.open("rb") as stream:
        data = stream.read(MAX_DOCUMENT_BYTES + 1)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise InputError("Document exceeds the 4 MiB input limit")
    try:
        # JSON is a YAML subset; a single loader enforces duplicate-key policy for both.
        document = yaml.load(data.decode("utf-8"), Loader=BoundedSafeLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
        raise InputError("Invalid or excessively nested JSON/YAML document") from exc
    if not isinstance(document, dict):
        raise InputError("Document root must be a mapping")
    return document, hashlib.sha256(data).hexdigest()


def resolve(document: dict, node: Any) -> dict:
    seen = set()
    for _ in range(32):
        if not isinstance(node, dict):
            raise InputError("Expected a specification object")
        if "$ref" not in node:
            return node
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise InputError(
                "Only local #/... references are supported; bundle external refs first"
            )
        if ref in seen:
            raise InputError("Cyclic reference in a request definition")
        seen.add(ref)
        target: Any = document
        try:
            for part in unquote(ref[2:]).split("/"):
                key = part.replace("~1", "/").replace("~0", "~")
                target = target[int(key)] if isinstance(target, list) else target[key]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise InputError("Unresolvable local reference") from exc
        node = target
    raise InputError("Reference chain exceeds 32 levels")


def parse_spec(file: Path) -> tuple[list[Operation], dict[str, AuthScheme], str]:
    document, digest = load_document(file)
    version = str(document.get("openapi", ""))
    swagger = document.get("swagger") == "2.0"
    if not swagger and not version.startswith(("3.0.", "3.1.")):
        raise InputError("Supported versions: Swagger 2.0, OpenAPI 3.0.x and 3.1.x")
    raw_schemes = (
        document.get("securityDefinitions", {})
        if swagger
        else document.get("components", {}).get("securitySchemes", {})
    )
    schemes = {}
    for name, raw in raw_schemes.items():
        item = resolve(document, raw)
        schemes[name] = AuthScheme(
            name=name,
            type=item["type"],
            location=item.get("in"),
            wire_name=item.get("name"),
            scheme=item["scheme"].lower() if item.get("scheme") else None,
        )
    operations = []
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise InputError("paths must be a mapping")
    for path, raw_item in paths.items():
        if path.startswith("x-"):
            continue
        if not path.startswith("/") or path.startswith("//") or any(c in path for c in "?#\\"):
            raise InputError("Paths must be relative API paths without query/fragment components")
        item = resolve(document, raw_item)
        for method, raw_op in item.items():
            if method not in METHODS:
                continue
            op = resolve(document, raw_op)
            merged = {}
            for raw_parameter in [*item.get("parameters", []), *op.get("parameters", [])]:
                parameter = resolve(document, raw_parameter)
                schema = resolve(document, parameter.get("schema", {}))
                if swagger and not schema:
                    schema = {
                        key: parameter[key]
                        for key in ("type", "format", "enum", "default")
                        if key in parameter
                    }
                example = parameter.get("example", schema.get("example", schema.get("default")))
                if example is None and schema.get("enum"):
                    example = schema["enum"][0]
                location = parameter["in"]
                name = parameter["name"]
                # Header field names are case insensitive.
                key = (location, name.lower() if location == "header" else name)
                merged[key] = Parameter(
                    name=name,
                    location=location,
                    required=parameter.get("required", False) or location == "path",
                    schema=schema,
                    example=example,
                    style=parameter.get("style"),
                    explode=parameter.get("explode"),
                )
            security = op.get("security", document.get("security", []))
            if not isinstance(security, list):
                raise InputError("security must be an array")
            for requirement in security:
                if not isinstance(requirement, dict) or not set(requirement) <= schemes.keys():
                    raise InputError("Security requirement references an undefined scheme")
            body = op.get("requestBody")
            operations.append(
                Operation(
                    method=method.upper(),
                    path=path,
                    operation_id=op.get("operationId"),
                    parameters=list(merged.values()),
                    security=security,
                    request_body=resolve(document, body) if body else None,
                )
            )
    if not operations:
        raise InputError("Specification has no HTTP operations")
    return operations, schemes, digest


def inventory(operations: list[Operation], schemes: dict[str, AuthScheme]) -> str:
    """An explicit, credential-free view of the normalized specification."""
    return json.dumps(
        {
            "operations": [op.model_dump(mode="json", by_alias=True) for op in operations],
            "auth_schemes": {name: s.model_dump() for name, s in schemes.items()},
        },
        indent=2,
    )

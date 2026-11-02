import pytest

from api_sentry.spec import InputError, parse_spec


def test_swagger_operation_overrides_and_public_security(tmp_path):
    spec = tmp_path / "swagger.yaml"
    spec.write_text("""swagger: '2.0'
info: {title: Example, version: '1'}
securityDefinitions:
  key: {type: apiKey, in: header, name: X-Api-Key}
security: [{key: []}]
parameters:
  Shared: {name: q, in: query, type: string, default: shared}
paths:
  /search:
    parameters: [{$ref: '#/parameters/Shared'}]
    get:
      parameters: [{name: q, in: query, type: string, default: local}]
      security: []
      responses: {'200': {description: OK}}
    post:
      responses: {'200': {description: OK}}
""")
    ops, schemes, digest = parse_spec(spec)
    assert len(digest) == 64
    assert schemes["key"].wire_name == "X-Api-Key"
    assert ops[0].parameters[0].example == "local"
    assert not ops[0].requires_auth
    assert ops[1].requires_auth
    assert ops[1].parameters[0].example == "shared"


@pytest.mark.parametrize(
    "payload",
    [
        "openapi: 3.1.0\npaths: {}\npaths: {}",
        "a: &anchor {}\nb: *anchor",
        "openapi: 3.1.0\npaths:\n  /test: {$ref: 'https://untrusted.test/spec'}",
        "openapi: 3.1.0\npaths:\n  /test: {$ref: '#/paths/~1test'}",
        "openapi: 3.1.0\npaths:\n  '//untrusted.test/': {get: {}}",
    ],
)
def test_ambiguous_unsafe_or_external_input_rejected(tmp_path, payload):
    file = tmp_path / "bad.yaml"
    file.write_text(payload)
    with pytest.raises(InputError):
        parse_spec(file)


def test_optional_auth_requirement_is_public(tmp_path):
    file = tmp_path / "spec.json"
    file.write_text("""{"openapi":"3.1.0","components":{"securitySchemes":{
      "token":{"type":"http","scheme":"bearer"}}},"security":[{"token":[]},{}],
      "paths":{"/test":{"get":{"responses":{"200":{"description":"OK"}}}}}}""")
    ops, _, _ = parse_spec(file)
    assert not ops[0].requires_auth


def test_deeply_nested_document_is_rejected_before_construction(tmp_path):
    file = tmp_path / "deep.json"
    file.write_text('{"value":' + "[" * 80 + "0" + "]" * 80 + "}")
    with pytest.raises(InputError, match="nesting-depth"):
        parse_spec(file)

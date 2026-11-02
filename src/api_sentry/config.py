"""Scan scenarios contain fixture IDs and environment-variable names, never token literals."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from .models import Model
from .spec import InputError, load_document


class Credential(Model):
    env: str


class ParameterRef(Model):
    location: Literal["path", "query"]
    name: str


class RequestCase(Model):
    operation: str
    identity: str = "A"
    values: dict[str, dict[str, JsonValue]] = Field(default_factory=dict)
    body: JsonValue = None
    expect_auth: bool | None = None
    injection_parameters: list[ParameterRef] = Field(default_factory=list)
    rate_limit: bool = False


class BolaCase(Model):
    operation: str
    parameter: ParameterRef
    object_a: str
    object_b: str
    identity_a: str = "A"
    identity_b: str = "B"
    identity_pointer: str = "/id"
    private_objects: Literal[True]

    @model_validator(mode="after")
    def distinct(self) -> BolaCase:
        if self.object_a == self.object_b or self.identity_a == self.identity_b:
            raise ValueError("BOLA needs two distinct objects and identities")
        if not self.identity_pointer.startswith("/"):
            raise ValueError("identity_pointer must be a nonempty JSON Pointer")
        return self


class Scenarios(Model):
    identities: dict[str, dict[str, Credential]] = Field(default_factory=dict)
    requests: list[RequestCase] = Field(default_factory=list)
    bola: list[BolaCase] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_requests(self) -> Scenarios:
        keys = [case.operation for case in self.requests]
        if len(set(keys)) != len(keys):
            raise ValueError("Only one baseline request fixture per operation is supported")
        return self

    def request_case(self, operation: str) -> RequestCase:
        return next(
            (case for case in self.requests if case.operation == operation),
            RequestCase(operation=operation),
        )

    def credentials(self) -> dict[str, dict[str, str]]:
        result = {}
        for identity, schemes in self.identities.items():
            result[identity] = {}
            for scheme, source in schemes.items():
                value = os.environ.get(source.env)
                if not value or any(char in value for char in "\r\n"):
                    raise InputError(
                        "A credential environment variable is absent, empty or invalid"
                    )
                result[identity][scheme] = value
        return result


def load_scenarios(file: Path | None) -> Scenarios:
    return Scenarios.model_validate(load_document(file)[0]) if file else Scenarios()

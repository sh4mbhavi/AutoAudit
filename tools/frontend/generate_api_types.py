#!/usr/bin/env python3
"""Generate the frontend's scan API types from the backend's own OpenAPI schema.

The frontend's scan calls were declared ``Promise<any>``, so every response
flowed into components untyped and ``tsc --noEmit`` could not see a mismatch
between what the API returns and what a page reads. Hand-writing the types would
only move the problem: a hand-written type agrees with the API until someone
edits a Pydantic model.

So the types are generated from the schema FastAPI itself publishes, and
``--check`` fails when the committed file no longer matches -- the same shape as
``tools/docs/generate_control_status.py --check``, which is already the repo's
gate for "generated artefact must equal its source".

Scope is deliberately narrow: the response models of the scan endpoints Phase 9
touches, plus whatever they reference. Widening it is a one-line change to
``ENDPOINTS``; doing so without also typing the call sites would only add
unreferenced code.

Usage:
    python tools/frontend/generate_api_types.py            # write
    python tools/frontend/generate_api_types.py --check    # verify, exit 1 on drift

Must run in the backend-api environment, because it imports the application to
ask it for its schema:
    uv run --frozen --project backend-api python tools/frontend/generate_api_types.py --check
"""

import argparse
import difflib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "frontend" / "src" / "api" / "generated" / "scans.ts"

# (method, path) of every response whose type the frontend consumes.
ENDPOINTS = (
    ("get", "/v1/scans/"),
    ("get", "/v1/scans/{scan_id}"),
    ("get", "/v1/scans/{scan_id}/summary"),
    ("get", "/v1/scans/{scan_id}/results"),
    ("get", "/v1/scans/{scan_id}/provenance"),
    ("post", "/v1/scans/"),
)

HEADER = """// GENERATED FILE -- DO NOT EDIT.
//
// Produced from the backend's own OpenAPI schema by
// tools/frontend/generate_api_types.py. CI runs that script with --check, so an
// edit here, or a change to a backend response model that is not regenerated,
// fails the build rather than drifting silently.
//
// Regenerate with:
//   uv run --frozen --project backend-api python tools/frontend/generate_api_types.py
"""


def load_schema() -> dict:
    sys.path.insert(0, str(ROOT / "backend-api"))
    from app.main import create_app  # noqa: PLC0415 - import needs the path above

    return create_app().openapi()


def _ref_name(ref: str) -> str:
    return ref.rsplit("/", 1)[-1]


def _type_of(schema: dict, required: bool = True) -> str:
    """Render one OpenAPI schema node as a TypeScript type expression."""
    if "$ref" in schema:
        return _ref_name(schema["$ref"])
    if "anyOf" in schema or "oneOf" in schema:
        options = schema.get("anyOf") or schema["oneOf"]
        rendered = []
        for option in options:
            if option.get("type") == "null":
                rendered.append("null")
            else:
                rendered.append(_type_of(option))
        # Deduplicate while preserving order so a union reads the way the model
        # declared it.
        seen: dict[str, None] = {}
        for value in rendered:
            seen.setdefault(value, None)
        return " | ".join(seen)
    if "enum" in schema:
        return " | ".join(json.dumps(value) for value in schema["enum"])
    kind = schema.get("type")
    if kind == "array":
        return f"{_type_of(schema.get('items', {}))}[]"
    if kind == "object" or (kind is None and "additionalProperties" in schema):
        extra = schema.get("additionalProperties")
        if isinstance(extra, dict) and extra:
            return f"Record<string, {_type_of(extra)}>"
        return "Record<string, unknown>"
    return {
        "string": "string",
        "integer": "number",
        "number": "number",
        "boolean": "boolean",
        "null": "null",
    }.get(kind, "unknown")


def _reachable(components: dict, roots: list[str]) -> list[str]:
    """Every component schema reachable from ``roots``, in stable order."""
    seen: dict[str, None] = {}
    pending = list(roots)
    while pending:
        name = pending.pop(0)
        if name in seen or name not in components:
            continue
        seen[name] = None
        text = json.dumps(components[name])
        for candidate in components:
            if f'"#/components/schemas/{candidate}"' in text:
                pending.append(candidate)
    return sorted(seen)


def _render(name: str, schema: dict) -> str:
    if "enum" in schema:
        options = " | ".join(json.dumps(value) for value in schema["enum"])
        return f"export type {name} = {options};\n"
    properties = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    lines = [f"export interface {name} {{"]
    for field, definition in properties.items():
        optional = "" if field in required else "?"
        description = definition.get("description")
        if description:
            lines.append(f"  /** {description.strip()} */")
        lines.append(f"  {field}{optional}: {_type_of(definition)};")
    lines.append("}\n")
    return "\n".join(lines)


def render(schema: dict) -> str:
    components = schema.get("components", {}).get("schemas", {})
    roots: list[str] = []
    for method, path in ENDPOINTS:
        operation = schema.get("paths", {}).get(path, {}).get(method)
        if operation is None:
            raise SystemExit(f"OpenAPI schema has no {method.upper()} {path}")
        for status_code, response in operation.get("responses", {}).items():
            if not str(status_code).startswith("2"):
                continue
            body = response.get("content", {}).get("application/json", {}).get("schema")
            if not body:
                continue
            if "$ref" in body:
                roots.append(_ref_name(body["$ref"]))
            elif body.get("type") == "array" and "$ref" in body.get("items", {}):
                roots.append(_ref_name(body["items"]["$ref"]))
    blocks = [_render(name, components[name]) for name in _reachable(components, roots)]
    return HEADER + "\n" + "\n".join(blocks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed file matches; do not write",
    )
    arguments = parser.parse_args()
    rendered = render(load_schema())
    if arguments.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else ""
        if current == rendered:
            print(f"{OUTPUT.relative_to(ROOT)} matches the backend OpenAPI schema.")
            return 0
        print(f"{OUTPUT.relative_to(ROOT)} is stale. Regenerate it.\n")
        sys.stdout.writelines(
            difflib.unified_diff(
                current.splitlines(keepends=True),
                rendered.splitlines(keepends=True),
                fromfile="committed",
                tofile="generated",
            )
        )
        return 1
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

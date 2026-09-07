"""Phase 7 manual / inherited evidence approval workflow (plan item 15.1.5, EVI-03).

Two halves:

* pure unit checks over the state machine, the evidence digest and the auditor
  instruction templates, which need no database;
* integration checks against a disposable PostgreSQL 16 migrated to head, which
  drive the real routes through ASGI with a real session so the database
  triggers and CHECK constraints participate.

The load-bearing assertion is ``test_approval_changes_no_scan_counter_or_score``:
approving manual evidence must leave every scan counter, the compliance score
and the coverage score byte-identical. Manual evidence is a residual assurance
stream, never automated configuration coverage.
"""

import ast
import asyncio
import itertools
import json
import os
import subprocess  # nosec B404 # controlled Alembic subprocess in disposable database tests
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.v1 import manual_evidence as routes
from app.schemas import manual_evidence as schemas
from app.services import manual_evidence as workflow

BACKEND = Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent

SUBMITTER = SimpleNamespace(id=101, role="viewer")
REVIEWER = SimpleNamespace(id=102, role="auditor")
STRANGER = SimpleNamespace(id=103, role="viewer")
ADMIN = SimpleNamespace(id=104, role="admin")

SUBMITTER_SCAN = 301
REVIEWER_SCAN = 302

_scan_result_ids = itertools.count(4001)
_object_ids = itertools.count(1)


# ---------------------------------------------------------------------------
# Unit: the transition table.
# ---------------------------------------------------------------------------


def test_transition_table_is_exactly_the_documented_state_machine():
    assert set(workflow.TRANSITIONS) == {
        "submit",
        "amend",
        "approve",
        "reject",
        "withdraw",
        "expire",
    }
    assert workflow.TRANSITIONS["submit"][:2] == (frozenset({"draft"}), "submitted")
    assert workflow.TRANSITIONS["approve"][:2] == (
        frozenset({"submitted"}),
        "approved",
    )
    assert workflow.TRANSITIONS["reject"][:2] == (frozenset({"submitted"}), "rejected")
    assert workflow.TRANSITIONS["expire"][:2] == (frozenset({"approved"}), "expired")
    # Withdrawal is available from every non-terminal state and nothing else.
    assert workflow.TRANSITIONS["withdraw"][0] == frozenset(
        {"draft", "submitted", "approved", "rejected"}
    )
    assert workflow.TERMINAL_STATUSES == frozenset({"withdrawn", "expired"})
    for _, status_after, _ in workflow.TRANSITIONS.values():
        assert status_after != "not_applicable"


FORBIDDEN_WRITES = {
    "compliance_score",
    "coverage_score",
    "total_controls",
    "selected_count",
    "passed_count",
    "failed_count",
    "skipped_count",
    "error_count",
    "indeterminate_count",
    "not_assessable_count",
    "reason_code",
    "evidence",
}


@pytest.mark.parametrize("module", [workflow, routes])
def test_no_scan_or_result_field_is_ever_assigned(module):
    """The workflow may read scan identity; it may never write scan outcomes."""
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    assigned = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
    }
    assert not assigned & FORBIDDEN_WRITES, sorted(assigned & FORBIDDEN_WRITES)
    # The scan result model is never even imported into the workflow service.
    assert not hasattr(workflow, "ScanResult")


def test_no_rating_and_no_invented_result_state_anywhere_in_the_contract():
    """D01's proposed not_applicable is not in the stored vocabulary."""
    for module in (workflow, routes, schemas):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "not_applicable" not in source
    fields = set()
    for name in dir(schemas):
        candidate = getattr(schemas, name)
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            fields |= set(candidate.model_fields)
    assert not any("rating" in field for field in fields)
    assert "affects_automated_score" in fields
    assert "assurance_stream" in fields


# ---------------------------------------------------------------------------
# Unit: the evidence digest.
# ---------------------------------------------------------------------------


def test_evidence_digest_is_order_independent_and_set_sensitive():
    first, references = workflow.normalise_evidence_set(
        ["bbbbbbbbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaaaaaaaa"],
        [{"label": "Policy", "uri": "https://example.invalid/p", "note": None}],
    )
    second, same_references = workflow.normalise_evidence_set(
        ["aaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbb"],
        [{"label": "Policy", "uri": "https://example.invalid/p"}],
    )
    assert workflow.compute_evidence_sha256(
        first, references
    ) == workflow.compute_evidence_sha256(second, same_references)

    extra, _ = workflow.normalise_evidence_set(
        ["aaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccc"],
        [],
    )
    assert workflow.compute_evidence_sha256(
        extra, references
    ) != workflow.compute_evidence_sha256(first, references)
    assert len(workflow.compute_evidence_sha256([], [])) == 64


@pytest.mark.parametrize(
    "object_ids",
    [["../../etc/passwd"], ["short"], ["a" * 44], [123], ["ok id with spaces"]],
)
def test_attachment_ids_must_be_opaque_object_ids(object_ids):
    with pytest.raises(workflow.InvalidEvidenceSet):
        workflow.normalise_evidence_set(object_ids, [])


@pytest.mark.parametrize(
    "reference",
    [
        {"label": None, "uri": "https://example.invalid"},
        {
            "label": "Creds",
            "uri": "https://user:secret@example.invalid/doc",  # pragma: allowlist secret - synthetic URL proving credentials are not echoed
        },
        {"label": "Local", "uri": "file:///etc/passwd"},
        {"label": "Bare", "uri": "javascript:alert(1)"},
        "not-an-object",
    ],
)
def test_external_references_are_validated(reference):
    with pytest.raises(workflow.InvalidEvidenceSet):
        workflow.normalise_evidence_set([], [reference])


def test_evidence_set_sizes_are_bounded():
    with pytest.raises(workflow.InvalidEvidenceSet):
        workflow.normalise_evidence_set(
            [f"{index:022d}" for index in range(workflow.MAX_ATTACHMENTS + 1)], []
        )
    with pytest.raises(workflow.InvalidEvidenceSet):
        workflow.normalise_evidence_set(
            [],
            [
                {"label": f"reference {index}"}
                for index in range(workflow.MAX_EXTERNAL_REFERENCES + 1)
            ],
        )


def test_request_id_is_sanitised_before_it_reaches_provenance():
    assert workflow.safe_request_id("abc-123.:_") == "abc-123.:_"
    for bad in ("a b", "a\nb", "x" * 129, None, 5, "<script>"):
        assert workflow.safe_request_id(bad) is None


# ---------------------------------------------------------------------------
# Unit: auditor instruction templates.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_template_cache():
    workflow.clear_template_cache()
    yield
    workflow.clear_template_cache()


def test_shipped_template_file_is_the_source_of_auditor_instructions():
    templates = workflow.load_manual_control_templates(
        "cis", "microsoft-365-foundations", "v6.0.0"
    )
    shipped = json.loads(
        (
            REPOSITORY
            / "docs"
            / "compliance"
            / "templates"
            / "manual_controls_v6.0.0.json"
        ).read_text(encoding="utf-8")
    )
    assert set(templates) == {entry["control_id"] for entry in shipped}
    assert len(templates) == 24
    manual = workflow.get_manual_control_template(
        "cis", "microsoft-365-foundations", "v6.0.0", "1.1.2"
    )
    assert manual["instructions"].startswith("Emergency access accounts")
    assert manual["evidence_type"] == "screenshot"


def test_an_automated_control_has_no_manual_template():
    # 1.1.1 is is_manual=false in the engine metadata.
    assert (
        workflow.get_manual_control_template(
            "cis", "microsoft-365-foundations", "v6.0.0", "1.1.1"
        )
        is None
    )


@pytest.mark.parametrize(
    "framework,benchmark,version",
    [
        ("../cis", "microsoft-365-foundations", "v6.0.0"),
        ("cis", "../../etc", "v6.0.0"),
        ("cis", "microsoft-365-foundations", "../../../etc/passwd"),
        ("cis", "microsoft-365-foundations", "v6.0.0/../.."),
    ],
)
def test_template_lookup_rejects_traversal(framework, benchmark, version):
    with pytest.raises(workflow.InvalidEvidenceSet):
        workflow.template_search_paths(framework, benchmark, version)


def test_template_directory_override_is_honoured(tmp_path, monkeypatch):
    payload = [
        {
            "framework": "cis",
            "benchmark": "microsoft-365-foundations",
            "version": "v9.9.9",
            "control_id": "1.2.3",
            "title": "Overridden",
            "instructions": "Deployment supplied instructions.",
        }
    ]
    (tmp_path / "manual_controls_v9.9.9.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    monkeypatch.setenv(workflow.TEMPLATE_DIR_ENV, str(tmp_path))
    workflow.clear_template_cache()
    template = workflow.get_manual_control_template(
        "cis", "microsoft-365-foundations", "v9.9.9", "1.2.3"
    )
    assert template["title"] == "Overridden"


def test_missing_template_file_reads_as_no_instructions(monkeypatch, tmp_path):
    monkeypatch.setenv(workflow.TEMPLATE_DIR_ENV, str(tmp_path))
    workflow.clear_template_cache()
    assert (
        workflow.load_manual_control_templates(
            "cis", "microsoft-365-foundations", "v0.0.1"
        )
        == {}
    )


# ---------------------------------------------------------------------------
# Integration: disposable PostgreSQL migrated to head.
# ---------------------------------------------------------------------------


async def _sql(url, statement, *parameters, fetch=True):
    connection = await asyncpg.connect(url)
    try:
        if fetch:
            return [dict(row) for row in await connection.fetch(statement, *parameters)]
        return await connection.execute(statement, *parameters)
    finally:
        await connection.close()


def _alembic(url, *arguments):
    environment = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": url.replace("postgresql://", "postgresql+asyncpg://", 1),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
    }
    result = subprocess.run(  # nosec B603 # fixed interpreter and Alembic arguments from this test
        [sys.executable, "-m", "alembic", *arguments],
        cwd=BACKEND,
        env=environment,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


SEED = """
INSERT INTO "user" (id, role, email, hashed_password, is_active, is_superuser, is_verified)
VALUES (101, 'viewer', 'submitter@example.invalid', 'synthetic-not-a-password', true, false, true),
       (102, 'auditor', 'reviewer@example.invalid', 'synthetic-not-a-password', true, false, true),
       (103, 'viewer', 'stranger@example.invalid', 'synthetic-not-a-password', true, false, true),
       (104, 'admin', 'admin@example.invalid', 'synthetic-not-a-password', true, false, true);
INSERT INTO m365_connection (id, user_id, name, tenant_id, client_id, encrypted_client_secret)
VALUES (201, 101, 'Submitter tenant', 'synthetic-tenant-a', 'synthetic-client', 'synthetic-ciphertext'),
       (202, 102, 'Reviewer tenant', 'synthetic-tenant-b', 'synthetic-client', 'synthetic-ciphertext');
INSERT INTO scan (id, user_id, m365_connection_id, framework, benchmark, version, status,
                  compliance_score, total_controls, passed_count, failed_count, skipped_count,
                  error_count, selected_count, coverage_score, indeterminate_count,
                  not_assessable_count, semantics_version, metadata_digest, correlation_id,
                  mapping_id, mapping_version, mapping_digest, policy_corpus_digest,
                  evidence_version, lifecycle_version)
VALUES (301, 101, 201, 'cis', 'microsoft-365-foundations', 'v6.0.0', 'completed',
        62.50, 10, 5, 3, 1, 0, 9, 88.89, 1, 0, 'phase3-v1',
        '0000000000000000000000000000000000000000000000000000000000000001',
        'fixture-correlation-a', 'soc2-common-criteria-to-cis-m365', 'v1.0.0',
        '0000000000000000000000000000000000000000000000000000000000000002',
        '0000000000000000000000000000000000000000000000000000000000000003',
        'phase7-v1', 'phase6-v1'),
       (302, 102, 202, 'cis', 'microsoft-365-foundations', 'v6.0.0', 'completed',
        100.00, 4, 4, 0, 0, 0, 4, 100.00, 0, 0, 'phase3-v1',
        '0000000000000000000000000000000000000000000000000000000000000004',
        'fixture-correlation-b', 'soc2-common-criteria-to-cis-m365', 'v1.0.0',
        '0000000000000000000000000000000000000000000000000000000000000002',
        '0000000000000000000000000000000000000000000000000000000000000003',
        'phase7-v1', 'phase6-v1');
"""


@pytest.fixture(scope="module")
def database_url():
    """A fresh migrated database; never migrate the configured admin database."""
    admin_url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not admin_url:
        pytest.skip(
            "Set MIGRATION_TEST_ADMIN_URL to a disposable local PostgreSQL server"
        )
    parsed = urlsplit(admin_url)
    if parsed.scheme != "postgresql" or parsed.hostname not in {"127.0.0.1", "::1"}:
        pytest.fail("MIGRATION_TEST_ADMIN_URL must be a loopback postgresql:// URL")
    name = "autoaudit_phase7_manual_" + uuid4().hex
    asyncio.run(_sql(admin_url, f'CREATE DATABASE "{name}"', fetch=False))
    url = urlunsplit(parsed._replace(path="/" + name))
    try:
        _alembic(url, "upgrade", "head")
        asyncio.run(_sql(url, SEED, fetch=False))
        yield url
    finally:
        asyncio.run(
            _sql(admin_url, f'DROP DATABASE "{name}" WITH (FORCE)', fetch=False)
        )


async def _new_scan_result(url, scan_id=SUBMITTER_SCAN, status="failed"):
    identifier = next(_scan_result_ids)
    await _sql(
        url,
        "INSERT INTO scan_result (id, scan_id, control_id, status, selected, message)"
        " VALUES ($1, $2, $3, $4, true, 'Synthetic fixture result')",
        identifier,
        scan_id,
        f"9.1.{identifier}",
        status,
        fetch=False,
    )
    return identifier


async def _new_artifact(url, user_id=SUBMITTER.id, status="available"):
    object_id = f"phase7test{next(_object_ids):032d}"
    await _sql(
        url,
        "INSERT INTO evidence_artifact (object_id, user_id, kind, display_filename,"
        " media_type, byte_size, content_sha256, storage_backend, storage_key, status,"
        " retention_policy_version)"
        " VALUES ($1, $2, 'upload', 'synthetic.png', 'image/png', 12, $3, 'local', $4,"
        " $5, 'phase7-draft-1')",
        object_id,
        user_id,
        "f" * 64,
        f"synthetic/{object_id}",
        status,
        fetch=False,
    )
    return object_id


def _run(url, scenario):
    """Drive the real routes with a real session inside one event loop."""

    async def main():
        engine = create_async_engine(
            url.replace("postgresql://", "postgresql+asyncpg://", 1)
        )
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                actor = {"user": SUBMITTER}
                app = FastAPI()
                app.include_router(routes.router)
                app.dependency_overrides[routes.get_current_user] = lambda: actor[
                    "user"
                ]
                app.dependency_overrides[routes.get_async_session] = lambda: session
                transport = ASGITransport(app=app)
                async with AsyncClient(
                    transport=transport, base_url="http://api.invalid"
                ) as client:
                    context = SimpleNamespace(
                        session=session,
                        client=client,
                        url=url,
                        act_as=lambda user: actor.__setitem__("user", user),
                    )
                    return await scenario(context)
        finally:
            await engine.dispose()

    return asyncio.run(main())


async def _create_draft(context, *, scan_result_id=None, **payload):
    if scan_result_id is None:
        scan_result_id = await _new_scan_result(context.url)
    body = {"scan_result_id": scan_result_id, **payload}
    response = await context.client.post("/manual-evidence/", json=body)
    assert response.status_code == 201, response.text
    return response.json()


async def _record_row(url, record_id):
    return (
        await _sql(url, "SELECT * FROM manual_evidence_record WHERE id=$1", record_id)
    )[0]


def _provenance(revision):
    """asyncpg returns JSONB as text; the ORM returns it already decoded."""
    value = revision["provenance"]
    return json.loads(value) if isinstance(value, str) else value


async def _revisions(url, record_id):
    return await _sql(
        url,
        "SELECT * FROM manual_evidence_revision WHERE record_id=$1"
        " ORDER BY revision_number",
        record_id,
    )


# -------------------- the happy paths --------------------


def test_every_legal_transition_writes_exactly_one_revision(database_url):
    async def scenario(context):
        record = await _create_draft(
            context,
            comment="Collected the quarterly access review pack.",
            control_owner="Head of Security",
            evidence_owner="IT Operations",
            cadence="quarterly",
            external_references=[
                {"label": "Access review", "uri": "https://example.invalid/review"}
            ],
        )
        assert record["status"] == "draft"
        assert record["current_revision_number"] == 1
        assert record["assurance_stream"] == "manual_residual"
        assert record["affects_automated_score"] is False

        submitted = await context.client.post(
            f"/manual-evidence/{record['id']}/submit", json={"comment": "Ready"}
        )
        assert submitted.status_code == 200, submitted.text
        assert submitted.json()["status"] == "submitted"

        context.act_as(REVIEWER)
        rejected = await context.client.post(
            f"/manual-evidence/{record['id']}/reject",
            json={"reason": "The screenshot omits the tenant name."},
        )
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["status"] == "rejected"
        assert rejected.json()["reviewer_user_id"] == REVIEWER.id

        context.act_as(SUBMITTER)
        amended = await context.client.post(
            f"/manual-evidence/{record['id']}/amend",
            json={"comment": "Recaptured with the tenant name visible."},
        )
        assert amended.status_code == 200, amended.text
        assert amended.json()["status"] == "draft"

        assert (
            await context.client.post(f"/manual-evidence/{record['id']}/submit")
        ).status_code == 200

        context.act_as(ADMIN)
        approved = await context.client.post(
            f"/manual-evidence/{record['id']}/approve", json={"comment": "Accepted."}
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"
        assert approved.json()["reviewer_user_id"] == ADMIN.id

        history = await _revisions(context.url, record["id"])
        assert [row["revision_number"] for row in history] == [1, 2, 3, 4, 5, 6]
        assert [row["action"] for row in history] == [
            "created",
            "submitted",
            "rejected",
            "amended",
            "submitted",
            "approved",
        ]
        assert [row["status_after"] for row in history] == [
            "draft",
            "submitted",
            "rejected",
            "draft",
            "submitted",
            "approved",
        ]
        assert history[2]["rejection_reason"] == "The screenshot omits the tenant name."
        assert all(
            row["rejection_reason"] is None
            for row in history
            if row["action"] != "rejected"
        )
        assert history[5]["actor_user_id"] == ADMIN.id
        assert history[5]["actor_role"] == "admin"

        # The API history endpoint returns the same immutable list.
        listed = await context.client.get(f"/manual-evidence/{record['id']}/revisions")
        assert listed.status_code == 200, listed.text
        assert [item["revision_number"] for item in listed.json()["revisions"]] == [
            1,
            2,
            3,
            4,
            5,
            6,
        ]

    _run(database_url, scenario)


def test_withdraw_is_available_from_every_non_terminal_state(database_url):
    async def scenario(context):
        for prepare in ("draft", "submitted", "approved", "rejected"):
            record = await _create_draft(context)
            record_id = record["id"]
            if prepare != "draft":
                assert (
                    await context.client.post(f"/manual-evidence/{record_id}/submit")
                ).status_code == 200
            if prepare in {"approved", "rejected"}:
                context.act_as(REVIEWER)
                decision = (
                    f"/manual-evidence/{record_id}/approve"
                    if prepare == "approved"
                    else f"/manual-evidence/{record_id}/reject"
                )
                body = {} if prepare == "approved" else {"reason": "Not enough"}
                assert (
                    await context.client.post(decision, json=body)
                ).status_code == 200
                context.act_as(SUBMITTER)
            withdrawn = await context.client.post(
                f"/manual-evidence/{record_id}/withdraw", json={"comment": "Retracted"}
            )
            assert withdrawn.status_code == 200, withdrawn.text
            assert withdrawn.json()["status"] == "withdrawn"
            history = await _revisions(context.url, record_id)
            assert history[-1]["action"] == "withdrawn"
            # A withdrawn record is terminal.
            again = await context.client.post(f"/manual-evidence/{record_id}/withdraw")
            assert again.status_code == 409, again.text

    _run(database_url, scenario)


# -------------------- illegal transitions --------------------


# (state, action, actor, expected status). A reviewer acting on a draft gets 404
# rather than 409, because someone else's draft is not visible to them at all.
ILLEGAL = [
    ("draft", "approve", REVIEWER, 404),
    ("draft", "reject", REVIEWER, 404),
    ("submitted", "submit", SUBMITTER, 409),
    ("submitted", "amend", SUBMITTER, 409),
    ("approved", "submit", SUBMITTER, 409),
    ("approved", "approve", REVIEWER, 409),
    ("approved", "reject", REVIEWER, 409),
    ("rejected", "reject", REVIEWER, 409),
    ("rejected", "approve", REVIEWER, 409),
    ("rejected", "submit", SUBMITTER, 409),
    ("withdrawn", "submit", SUBMITTER, 409),
    ("withdrawn", "amend", SUBMITTER, 409),
    ("withdrawn", "approve", REVIEWER, 409),
]


async def _drive_to(context, state):
    record = await _create_draft(context)
    record_id = record["id"]
    if state == "draft":
        return record_id
    assert (
        await context.client.post(f"/manual-evidence/{record_id}/submit")
    ).status_code == 200
    if state == "submitted":
        return record_id
    if state == "withdrawn":
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/withdraw")
        ).status_code == 200
        return record_id
    context.act_as(REVIEWER)
    if state == "approved":
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/approve")
        ).status_code == 200
    elif state == "rejected":
        assert (
            await context.client.post(
                f"/manual-evidence/{record_id}/reject", json={"reason": "Insufficient"}
            )
        ).status_code == 200
    context.act_as(SUBMITTER)
    return record_id


@pytest.mark.parametrize("state,action,actor,expected", ILLEGAL)
def test_illegal_transitions_are_refused_and_write_no_revision(
    database_url, state, action, actor, expected
):
    async def scenario(context):
        record_id = await _drive_to(context, state)
        before = await _revisions(context.url, record_id)
        record_before = await _record_row(context.url, record_id)
        context.act_as(actor)
        body = {"reason": "Not good enough"} if action == "reject" else {}
        response = await context.client.post(
            f"/manual-evidence/{record_id}/{action}", json=body
        )
        assert response.status_code == expected, response.text
        if expected == 409:
            assert response.json()["detail"]["code"] == "illegal_transition"
        assert await _revisions(context.url, record_id) == before
        assert await _record_row(context.url, record_id) == record_before

    _run(database_url, scenario)


def test_expiring_a_record_that_is_not_approved_is_refused(database_url):
    async def scenario(context):
        record_id = (await _create_draft(context))["id"]
        with pytest.raises(workflow.IllegalTransition):
            await workflow.apply_transition(
                context.session,
                record_id=record_id,
                action="expire",
                actor_user_id=None,
                actor_role="system",
            )
        await context.session.rollback()
        assert len(await _revisions(context.url, record_id)) == 1

    _run(database_url, scenario)


# -------------------- append-only history --------------------


def test_a_revision_can_never_be_updated_or_deleted(database_url):
    async def scenario(context):
        record_id = await _drive_to(context, "approved")
        history = await _revisions(context.url, record_id)
        target = history[-1]["id"]

        with pytest.raises(asyncpg.PostgresError) as update_error:
            await _sql(
                context.url,
                "UPDATE manual_evidence_revision SET comment='rewritten' WHERE id=$1",
                target,
                fetch=False,
            )
        assert "append-only" in str(update_error.value)

        with pytest.raises(asyncpg.PostgresError) as delete_error:
            await _sql(
                context.url,
                "DELETE FROM manual_evidence_revision WHERE id=$1",
                target,
                fetch=False,
            )
        assert "append-only" in str(delete_error.value)

        assert await _revisions(context.url, record_id) == history

    _run(database_url, scenario)


def test_amending_after_approval_preserves_the_approved_revision_verbatim(
    database_url,
):
    async def scenario(context):
        record_id = await _drive_to(context, "approved")
        approved = (await _revisions(context.url, record_id))[-1]
        assert approved["action"] == "approved"

        amended = await context.client.post(
            f"/manual-evidence/{record_id}/amend",
            json={"comment": "New evidence for the next period."},
        )
        assert amended.status_code == 200, amended.text
        assert amended.json()["status"] == "draft"
        assert (
            amended.json()["current_revision_number"] == approved["revision_number"] + 1
        )

        history = await _revisions(context.url, record_id)
        assert history[approved["revision_number"] - 1] == approved
        assert history[-1]["action"] == "amended"
        assert len(history) == approved["revision_number"] + 1

    _run(database_url, scenario)


# -------------------- independent review --------------------


def test_self_approval_is_refused_by_the_service_and_by_the_database(database_url):
    async def scenario(context):
        record_id = await _drive_to(context, "submitted")
        # The submitter happens to hold a reviewer role; review is still not theirs.
        context.act_as(SimpleNamespace(id=SUBMITTER.id, role="admin"))
        approve = await context.client.post(f"/manual-evidence/{record_id}/approve")
        assert approve.status_code == 403, approve.text
        assert approve.json()["detail"]["code"] == "independent_review_required"
        reject = await context.client.post(
            f"/manual-evidence/{record_id}/reject", json={"reason": "Mine looks fine"}
        )
        assert reject.status_code == 403, reject.text
        assert len(await _revisions(context.url, record_id)) == 2

        with pytest.raises(asyncpg.PostgresError) as constraint:
            await _sql(
                context.url,
                "UPDATE manual_evidence_record SET reviewer_user_id=user_id,"
                " status='approved', current_revision_number=current_revision_number+1"
                " WHERE id=$1",
                record_id,
                fetch=False,
            )
        assert "independent_reviewer" in str(constraint.value)

        row = (
            await _sql(
                context.url,
                "SELECT status, reviewer_user_id FROM manual_evidence_record"
                " WHERE id=$1",
                record_id,
            )
        )[0]
        assert row == {"status": "submitted", "reviewer_user_id": None}

    _run(database_url, scenario)


def test_rejection_requires_a_reason_and_records_it(database_url):
    async def scenario(context):
        record_id = await _drive_to(context, "submitted")
        context.act_as(REVIEWER)
        for body in ({}, {"reason": ""}, {"reason": "   "}, {"comment": "no reason"}):
            response = await context.client.post(
                f"/manual-evidence/{record_id}/reject", json=body
            )
            assert response.status_code == 422, response.text
        assert len(await _revisions(context.url, record_id)) == 2

        accepted = await context.client.post(
            f"/manual-evidence/{record_id}/reject",
            json={"reason": "The evidence covers the wrong collection period."},
        )
        assert accepted.status_code == 200, accepted.text
        latest = (await _revisions(context.url, record_id))[-1]
        assert latest["action"] == "rejected"
        assert (
            latest["rejection_reason"]
            == "The evidence covers the wrong collection period."
        )

    _run(database_url, scenario)


def test_a_viewer_cannot_review_and_the_queue_hides_their_own_submissions(
    database_url,
):
    async def scenario(context):
        record_id = await _drive_to(context, "submitted")

        # A plain viewer holds no review authority at all.
        context.act_as(SimpleNamespace(id=999, role="viewer"))
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/approve")
        ).status_code == 403
        assert (
            await context.client.get("/manual-evidence/review-queue")
        ).status_code == 403

        # The reviewer's own submission never appears in their queue.
        context.act_as(REVIEWER)
        own = await _create_draft(
            context,
            scan_result_id=await _new_scan_result(context.url, REVIEWER_SCAN),
        )
        assert (
            await context.client.post(f"/manual-evidence/{own['id']}/submit")
        ).status_code == 200

        queue = await context.client.get("/manual-evidence/review-queue")
        assert queue.status_code == 200, queue.text
        identifiers = {item["id"] for item in queue.json()}
        assert record_id in identifiers
        assert own["id"] not in identifiers
        assert all(item["user_id"] != REVIEWER.id for item in queue.json())

    _run(database_url, scenario)


# -------------------- tenant isolation --------------------


def test_another_tenant_can_neither_read_nor_drive_the_record(database_url):
    async def scenario(context):
        record = await _create_draft(context)
        record_id = record["id"]
        scan_result_id = record["scan_result_id"]

        context.act_as(STRANGER)
        for path in (
            f"/manual-evidence/{record_id}",
            f"/manual-evidence/{record_id}/revisions",
            f"/manual-evidence/by-scan-result/{scan_result_id}",
        ):
            response = await context.client.get(path)
            assert response.status_code == 404, (path, response.text)
            assert response.json()["detail"] == "Manual evidence record not found"

        # Identical answer for a record that genuinely does not exist.
        missing = await context.client.get("/manual-evidence/99999999")
        assert missing.status_code == 404
        assert missing.json()["detail"] == "Manual evidence record not found"

        for action in ("submit", "amend", "withdraw"):
            response = await context.client.post(
                f"/manual-evidence/{record_id}/{action}", json={}
            )
            assert response.status_code == 404, (action, response.text)
        approve = await context.client.post(f"/manual-evidence/{record_id}/approve")
        assert approve.status_code == 403, approve.text

        # And they cannot open a record against someone else's scan result.
        created = await context.client.post(
            "/manual-evidence/", json={"scan_result_id": scan_result_id}
        )
        assert created.status_code == 404, created.text

        assert len(await _revisions(context.url, record_id)) == 1

    _run(database_url, scenario)


def test_one_record_per_scan_result(database_url):
    async def scenario(context):
        record = await _create_draft(context)
        duplicate = await context.client.post(
            "/manual-evidence/", json={"scan_result_id": record["scan_result_id"]}
        )
        assert duplicate.status_code == 409, duplicate.text
        assert duplicate.json()["detail"]["code"] == "manual_evidence_exists"

    _run(database_url, scenario)


# -------------------- the semantic guard --------------------


# The whole query is a literal. Interpolating even a fixed column list makes
# this read as SQL string-building to a scanner, and the columns never vary.
SCAN_SNAPSHOT_SQL = (
    "SELECT status, compliance_score, coverage_score, total_controls,"
    " passed_count, failed_count, skipped_count, error_count,"
    " indeterminate_count, not_assessable_count, selected_count,"
    " metadata_digest, mapping_digest FROM scan WHERE id=$1"
)


def test_approval_changes_no_scan_counter_or_score(database_url):
    """Plan section 2 rule 5: a document is not a configuration assessment."""

    async def scenario(context):
        scan_result_id = await _new_scan_result(context.url)
        scan_before = (
            await _sql(
                context.url,
                SCAN_SNAPSHOT_SQL,
                SUBMITTER_SCAN,
            )
        )[0]
        result_before = (
            await _sql(
                context.url,
                "SELECT status, message, evidence, reason_code, selected"
                " FROM scan_result WHERE id=$1",
                scan_result_id,
            )
        )[0]

        record = await _create_draft(context, scan_result_id=scan_result_id)
        assert (
            await context.client.post(f"/manual-evidence/{record['id']}/submit")
        ).status_code == 200
        context.act_as(REVIEWER)
        approved = await context.client.post(
            f"/manual-evidence/{record['id']}/approve",
            json={"comment": "Governance evidence accepted as residual assurance."},
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"

        scan_after = (
            await _sql(
                context.url,
                SCAN_SNAPSHOT_SQL,
                SUBMITTER_SCAN,
            )
        )[0]
        result_after = (
            await _sql(
                context.url,
                "SELECT status, message, evidence, reason_code, selected"
                " FROM scan_result WHERE id=$1",
                scan_result_id,
            )
        )[0]

        assert scan_after == scan_before
        assert result_after == result_before
        # The failing control is still failing; approval did not promote it.
        assert result_after["status"] == "failed"
        # And the record says so in its own contract and provenance.
        assert approved.json()["affects_automated_score"] is False
        provenance = _provenance((await _revisions(context.url, record["id"]))[-1])
        assert provenance["assurance_stream"] == "manual_residual"
        assert provenance["automated_coverage_effect"] == "none"
        assert "rating" not in provenance

    _run(database_url, scenario)


def test_the_approved_envelope_survives_a_later_amendment(database_url):
    """A later amendment cannot erase the period an approval was granted for."""

    async def scenario(context):
        record = await _create_draft(
            context,
            collection_period_start="2026-01-01T00:00:00+00:00",
            collection_period_end="2026-03-31T00:00:00+00:00",
            expires_at="2027-01-01T00:00:00+00:00",
            cadence="quarterly",
            control_owner="Head of Security",
        )
        record_id = record["id"]
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/submit")
        ).status_code == 200
        context.act_as(REVIEWER)
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/approve")
        ).status_code == 200
        context.act_as(SUBMITTER)

        approved = (await _revisions(context.url, record_id))[-1]
        envelope = _provenance(approved)["evidence_envelope"]
        assert envelope["collection_period_start"].startswith("2026-01-01")
        assert envelope["collection_period_end"].startswith("2026-03-31")
        assert envelope["expires_at"].startswith("2027-01-01")
        assert envelope["cadence"] == "quarterly"
        # Free text a caller typed never enters provenance.
        assert "control_owner" not in envelope
        assert "evidence_owner" not in envelope

        # Amend is a full replacement of the mutable envelope on the record...
        cleared = await context.client.post(
            f"/manual-evidence/{record_id}/amend", json={"comment": "Next period"}
        )
        assert cleared.status_code == 200, cleared.text
        assert cleared.json()["collection_period_start"] is None
        assert cleared.json()["expires_at"] is None

        # ...and the approved revision still says exactly what was approved.
        history = await _revisions(context.url, record_id)
        assert history[approved["revision_number"] - 1] == approved
        assert _provenance(history[-1])["evidence_envelope"]["cadence"] is None

    _run(database_url, scenario)


def test_provenance_pins_the_scan_mapping_identity(database_url):
    async def scenario(context):
        record = await _create_draft(context)
        revision = (await _revisions(context.url, record["id"]))[0]
        provenance = _provenance(revision)
        assert provenance["framework"] == "cis"
        assert provenance["benchmark"] == "microsoft-365-foundations"
        assert provenance["benchmark_version"] == "v6.0.0"
        assert provenance["mapping_version"] == "v1.0.0"
        assert provenance["mapping_digest"] == "0" * 63 + "2"
        assert provenance["metadata_digest"] == "0" * 63 + "1"
        assert provenance["correlation_id"] == "fixture-correlation-a"
        assert provenance["retention_policy_version"] == "phase7-draft-1"
        assert provenance["evidence_sha256"] == revision["evidence_sha256"]
        blob = json.dumps(provenance)
        for secret in ("password", "secret", "token", "ciphertext"):
            assert secret not in blob.lower()

    _run(database_url, scenario)


# -------------------- attachments and the evidence digest --------------------


def test_evidence_digest_tracks_the_attachment_set(database_url):
    async def scenario(context):
        first = await _new_artifact(context.url)
        second = await _new_artifact(context.url)
        record = await _create_draft(context, attachment_object_ids=[first])
        record_id = record["id"]
        original = (await _revisions(context.url, record_id))[-1]["evidence_sha256"]

        added = await context.client.post(
            f"/manual-evidence/{record_id}/amend",
            json={"attachment_object_ids": [first, second]},
        )
        assert added.status_code == 200, added.text
        with_two = (await _revisions(context.url, record_id))[-1]["evidence_sha256"]
        assert with_two != original

        # Same set, different order and a duplicate: the digest is unchanged.
        again = await context.client.post(
            f"/manual-evidence/{record_id}/amend",
            json={"attachment_object_ids": [second, first, first]},
        )
        assert again.status_code == 200, again.text
        assert (await _revisions(context.url, record_id))[-1][
            "evidence_sha256"
        ] == with_two

        # An approval carries the reviewed bundle forward verbatim.
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/submit")
        ).status_code == 200
        context.act_as(REVIEWER)
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/approve")
        ).status_code == 200
        approved = (await _revisions(context.url, record_id))[-1]
        assert approved["evidence_sha256"] == with_two
        stored = approved["attachment_object_ids"]
        stored = json.loads(stored) if isinstance(stored, str) else stored
        assert stored == sorted([first, second])

    _run(database_url, scenario)


def test_unknown_or_foreign_attachments_are_refused_identically(database_url):
    async def scenario(context):
        foreign = await _new_artifact(context.url, user_id=STRANGER.id)
        deleted = await _new_artifact(context.url, status="failed")
        scan_result_id = await _new_scan_result(context.url)
        for object_ids in ([foreign], [deleted], ["phase7testabsent" + "0" * 22]):
            response = await context.client.post(
                "/manual-evidence/",
                json={
                    "scan_result_id": scan_result_id,
                    "attachment_object_ids": object_ids,
                },
            )
            assert response.status_code == 422, (object_ids, response.text)
            assert response.json()["detail"]["code"] == "unknown_attachment"
            assert "object_id" not in json.dumps(response.json()["detail"])
        assert (
            await _sql(
                context.url,
                "SELECT count(*) AS total FROM manual_evidence_record"
                " WHERE scan_result_id=$1",
                scan_result_id,
            )
        )[0]["total"] == 0

    _run(database_url, scenario)


# -------------------- expiry --------------------


def test_expiry_marks_approved_records_expired_and_deletes_nothing(database_url):
    async def scenario(context):
        past = datetime.now(timezone.utc) - timedelta(days=1)
        future = datetime.now(timezone.utc) + timedelta(days=30)
        stale = await _create_draft(
            context, expires_at=past.isoformat(), cadence="annual"
        )
        fresh = await _create_draft(context, expires_at=future.isoformat())
        for record in (stale, fresh):
            assert (
                await context.client.post(f"/manual-evidence/{record['id']}/submit")
            ).status_code == 200
            context.act_as(REVIEWER)
            assert (
                await context.client.post(f"/manual-evidence/{record['id']}/approve")
            ).status_code == 200
            context.act_as(SUBMITTER)

        before = await _revisions(context.url, stale["id"])
        expired = await workflow.expire_due_records(context.session)
        assert stale["id"] in expired
        assert fresh["id"] not in expired

        after = await _revisions(context.url, stale["id"])
        assert len(after) == len(before) + 1
        assert after[: len(before)] == before
        assert after[-1]["action"] == "expired"
        assert after[-1]["status_after"] == "expired"
        assert after[-1]["actor_user_id"] is None
        assert after[-1]["actor_role"] == "system"
        assert after[-1]["evidence_sha256"] == before[-1]["evidence_sha256"]

        record_row = (
            await _sql(
                context.url,
                "SELECT status, reviewer_user_id FROM manual_evidence_record"
                " WHERE id=$1",
                stale["id"],
            )
        )[0]
        assert record_row["status"] == "expired"
        # The reviewer that approved it is still recorded.
        assert record_row["reviewer_user_id"] == REVIEWER.id

        # Running it again is a no-op.
        assert await workflow.expire_due_records(context.session) == []
        assert await _revisions(context.url, stale["id"]) == after

    _run(database_url, scenario)


# -------------------- templates through the API --------------------


def test_template_route_serves_manual_instructions_and_404s_automated_controls(
    database_url,
):
    async def scenario(context):
        manual = await context.client.get("/manual-evidence/controls/1.1.2/template")
        assert manual.status_code == 200, manual.text
        body = manual.json()
        assert body["control_id"] == "1.1.2"
        assert body["version"] == "v6.0.0"
        assert body["evidence_type"] == "screenshot"
        assert (
            "break-glass" in body["instructions"]
            or "break glass" in body["instructions"]
        )
        assert body["keywords"]

        automated = await context.client.get("/manual-evidence/controls/1.1.1/template")
        assert automated.status_code == 404, automated.text
        assert "template" in automated.json()["detail"].lower()

        # Resolved from a scan's pinned benchmark identity.
        pinned = await context.client.get(
            f"/manual-evidence/controls/9.1.1/template?scan_id={SUBMITTER_SCAN}"
        )
        assert pinned.status_code == 200, pinned.text
        assert pinned.json()["framework"] == "cis"

        # Another tenant's scan is not a lookup key.
        context.act_as(STRANGER)
        foreign = await context.client.get(
            f"/manual-evidence/controls/9.1.1/template?scan_id={SUBMITTER_SCAN}"
        )
        assert foreign.status_code == 404, foreign.text

    _run(database_url, scenario)


def test_authentication_is_required_on_every_route():
    app = FastAPI()
    app.include_router(routes.router)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        for method, path in (
            ("GET", "/manual-evidence/1"),
            ("GET", "/manual-evidence/1/revisions"),
            ("GET", "/manual-evidence/by-scan-result/1"),
            ("GET", "/manual-evidence/review-queue"),
            ("GET", "/manual-evidence/controls/1.1.2/template"),
            ("POST", "/manual-evidence/"),
            ("POST", "/manual-evidence/1/submit"),
            ("POST", "/manual-evidence/1/amend"),
            ("POST", "/manual-evidence/1/approve"),
            ("POST", "/manual-evidence/1/reject"),
            ("POST", "/manual-evidence/1/withdraw"),
        ):
            response = client.request(method, path, json={})
            assert response.status_code == 401, (method, path, response.text)


# -------------------- hardening found in independent review --------------------


def test_a_reviewer_cannot_see_someone_elses_draft(database_url):
    """Drafts are private working state until they enter review."""

    async def scenario(context):
        record = await _create_draft(context)
        record_id = record["id"]

        context.act_as(REVIEWER)
        assert (
            await context.client.get(f"/manual-evidence/{record_id}")
        ).status_code == 404
        assert (
            await context.client.get(f"/manual-evidence/{record_id}/revisions")
        ).status_code == 404
        assert (
            await context.client.get(
                f"/manual-evidence/by-scan-result/{record['scan_result_id']}"
            )
        ).status_code == 404

        context.act_as(SUBMITTER)
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/submit")
        ).status_code == 200
        context.act_as(REVIEWER)
        assert (
            await context.client.get(f"/manual-evidence/{record_id}")
        ).status_code == 200

    _run(database_url, scenario)


def test_hostile_free_text_never_reaches_provenance(database_url):
    """Provenance holds identifiers and digests; free text stays in its column."""

    async def scenario(context):
        record = await _create_draft(
            context,
            control_owner="token=synthetic-not-a-secret",
            evidence_owner="payroll-export.csv",
            comment="Bearer synthetic-not-a-token",
        )
        revision = (await _revisions(context.url, record["id"]))[0]
        blob = json.dumps(_provenance(revision))
        for leaked in ("synthetic-not-a-secret", "payroll-export.csv", "Bearer"):
            assert leaked not in blob
        # The owner fields are still readable where they belong.
        assert record["control_owner"] == "token=synthetic-not-a-secret"

    _run(database_url, scenario)


def test_control_characters_are_stripped_rather_than_crashing_the_write(database_url):
    async def scenario(context):
        record = await _create_draft(
            context,
            comment="line one \x00 line two",
            control_owner="Head \x01of Security",
            external_references=[{"label": "Ref\x00erence"}],
        )
        assert record["control_owner"] == "Head of Security"
        stored = (await _revisions(context.url, record["id"]))[0]["comment"]
        assert "\x00" not in stored and "\x01" not in stored
        assert stored == "line one  line two"

    _run(database_url, scenario)


@pytest.mark.parametrize(
    "period",
    [
        {
            "collection_period_start": "2026-01-01T00:00:00Z",
            "collection_period_end": "2025-03-31T00:00:00",
        },
        {
            "collection_period_start": "2026-05-01T00:00:00",
            "collection_period_end": "2026-01-01T00:00:00Z",
        },
    ],
)
def test_a_mixed_aware_and_naive_period_is_422_not_500(database_url, period):
    async def scenario(context):
        scan_result_id = await _new_scan_result(context.url)
        response = await context.client.post(
            "/manual-evidence/", json={"scan_result_id": scan_result_id, **period}
        )
        assert response.status_code == 422, response.text

    _run(database_url, scenario)


def test_evidence_that_stopped_being_available_cannot_be_submitted_or_approved(
    database_url,
):
    """Fail closed: a missing artifact must never be reviewed as if it were there."""

    async def scenario(context):
        object_id = await _new_artifact(context.url)
        record = await _create_draft(context, attachment_object_ids=[object_id])
        record_id = record["id"]

        await _sql(
            context.url,
            "UPDATE evidence_artifact SET status='deleted', deleted_at=now()"
            " WHERE object_id=$1",
            object_id,
            fetch=False,
        )
        blocked = await context.client.post(f"/manual-evidence/{record_id}/submit")
        assert blocked.status_code == 422, blocked.text
        assert blocked.json()["detail"]["code"] == "unknown_attachment"
        assert len(await _revisions(context.url, record_id)) == 1

        # Restoring it lets the submission through, and approval revalidates too.
        await _sql(
            context.url,
            "UPDATE evidence_artifact SET status='available', deleted_at=NULL"
            " WHERE object_id=$1",
            object_id,
            fetch=False,
        )
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/submit")
        ).status_code == 200
        await _sql(
            context.url,
            "UPDATE evidence_artifact SET status='failed' WHERE object_id=$1",
            object_id,
            fetch=False,
        )
        context.act_as(REVIEWER)
        refused = await context.client.post(f"/manual-evidence/{record_id}/approve")
        assert refused.status_code == 422, refused.text
        assert (await _record_row(context.url, record_id))["status"] == "submitted"

        # A withdrawal is still possible, so a record can always be closed out.
        context.act_as(SUBMITTER)
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/withdraw")
        ).status_code == 200

    _run(database_url, scenario)


def test_expiry_rechecks_the_due_date_under_the_lock(database_url, monkeypatch):
    """A record renewed between selection and locking must not be expired."""

    async def scenario(context):
        record = await _create_draft(
            context,
            expires_at=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        )
        record_id = record["id"]
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/submit")
        ).status_code == 200
        context.act_as(REVIEWER)
        assert (
            await context.client.post(f"/manual-evidence/{record_id}/approve")
        ).status_code == 200

        before = await _revisions(context.url, record_id)

        async def stale_selection(db, *, now=None, limit=100):
            return [record_id]

        monkeypatch.setattr(workflow, "due_for_expiry", stale_selection)
        assert await workflow.expire_due_records(context.session) == []
        assert await _revisions(context.url, record_id) == before
        assert (await _record_row(context.url, record_id))["status"] == "approved"

    _run(database_url, scenario)


def test_a_template_file_is_not_reused_for_another_benchmark(tmp_path, monkeypatch):
    payload = [
        {
            "framework": "cis",
            "benchmark": "microsoft-365-foundations",
            "version": "v6.0.0",
            "control_id": "1.1.2",
            "instructions": "CIS M365 instructions.",
        }
    ]
    (tmp_path / "manual_controls_v6.0.0.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    monkeypatch.setenv(workflow.TEMPLATE_DIR_ENV, str(tmp_path))
    workflow.clear_template_cache()
    assert (
        workflow.get_manual_control_template(
            "cis", "microsoft-365-foundations", "v6.0.0", "1.1.2"
        )
        is not None
    )
    for framework, benchmark in (
        ("essential-eight", "microsoft-365-foundations"),
        ("cis", "asd-essential-eight"),
    ):
        assert (
            workflow.get_manual_control_template(
                framework, benchmark, "v6.0.0", "1.1.2"
            )
            is None
        )


def test_a_driver_level_rejection_is_422_with_a_clean_session(monkeypatch):
    """The last-resort net: no database error may reach a caller as a 500."""
    from unittest.mock import AsyncMock, MagicMock

    from fastapi.testclient import TestClient
    from sqlalchemy.exc import DBAPIError

    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.execute.return_value.scalar_one_or_none.return_value = SimpleNamespace(
        id=1, scan_id=1, control_id="9.1.1", user_id=SUBMITTER.id
    )
    db.rollback = AsyncMock()

    async def explode(*args, **kwargs):
        raise DBAPIError("INSERT", None, Exception("driver rejected the value"))

    monkeypatch.setattr(routes.workflow, "create_draft", explode)

    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[routes.get_current_user] = lambda: SUBMITTER
    app.dependency_overrides[routes.get_async_session] = lambda: db
    with TestClient(app) as client:
        response = client.post("/manual-evidence/", json={"scan_result_id": 1})
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "manual_evidence_not_storable"
    assert "driver rejected" not in response.text
    db.rollback.assert_awaited()

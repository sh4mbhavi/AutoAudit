# PowerShell collection boundary

`POST /execute` accepts `operation_id`, `collector_id`, `params`, `tenant_id` and
module-specific authentication fields. It rejects `module`, `cmdlet`, script text,
raw certificate paths, and every unknown field. The immutable registry in
`service/operations.py` defines 25 fixed read operations for all 22 registered
PowerShell collectors. Two mailbox pipelines live in reviewed service code.
`Get-User` permits one strictly typed, restricted-grammar UPN `Identity` parameter;
all other operation parameters are fixed in source.

The worker sends `X-Service-Secret`. Set `POWERSHELL_SERVICE_SECRET` to a randomly
generated secret of at least 32 non-whitespace ASCII characters. Service startup
fails when it is missing or invalid; comparisons use `hmac.compare_digest`.
`/health` is public and never executes an operation. Production must use the
private HTTPS deployment configuration. The optional worker `POWERSHELL_CA_FILE`
adds its private CA to default TLS trust roots and never disables verification.

The worker's `run_operation(operation_id, collector_id, **params)` API replaces
`run_cmdlet`; there is no compatibility endpoint accepting arbitrary commands.
Validation happens before token acquisition and again at the executor boundary.
Local Docker uses the same registry and script builder, sends tokens via process
environment and the script via stdin, and fails SharePoint operations closed.
SharePoint runs only in the service, where `SHAREPOINT_CERT_ALIASES` resolves
request aliases to mounted PFX and password files. Requests cannot supply paths.

Worker and service must be updated together. Pending Teams and Compliance
collectors are deliberately unregistered and have no executable operations; a
future enablement requires reviewed registry entries and contract tests. Strict
UPN validation rejects unusual addresses containing apostrophes or other shell
metacharacters instead of attempting to execute them. The shared service key
identifies a trusted worker; the caller's collector ID selects a permitted
operation and is not an independent end-user authorization mechanism.

Tests in `engine/tests/test_phase5_powershell_boundary.py` cover operation/module
substitution, parameter injection and types, tenant and certificate fields,
authentication/startup, credential-safe errors, both execution transports, and
coverage of every registered PowerShell collector. They use mocked Microsoft
and process boundaries; live Microsoft 365 acceptance requires deployed
credentials, certificates, and read-only tenant permission checks.

# Runtime deployment contract

Use `docker-compose.production.yml` as a standalone reviewed template, not as
an override on the development Compose file. It publishes only the API on
loopback for an owner-operated HTTPS ingress proxy. Redis, PostgreSQL and
PowerShell have no published ports. Database and Redis attach only to an
internal network; API, worker and PowerShell also have egress for identity and
M365 collection. Production settings require the exact environment and URLs;
local development retains `APP_ENV=dev` defaults. Every non-dev environment
is validated strictly; production manifests explicitly set `APP_ENV=production`.

Provision independent random signing, encryption, service and database secrets
with the deployment's secret manager. Preserve existing encryption keys during
upgrade: changing the key without re-encrypting stored M365 credentials makes
those credentials unreadable. This patch does not rotate external credentials
or delete existing database volumes. Provision API/worker database URLs with
URL-encoded credentials and the same database, and set `POSTGRES_PASSWORD`
consistently. Never print rendered Compose configuration in shared logs because
it contains resolved environment secrets.

Redis must use an authenticated URL with **both** explicit TLS options:

```text
rediss://worker:<URL-encoded-secret>@redis:6379/0?ssl_cert_reqs=required&ssl_check_hostname=true&ssl_ca_certs=%2Frun%2Fsecrets%2Fruntime_ca
```

Literal semicolon broker lists, URL fragments, omitted certificate/hostname
verification, anonymous URLs and development passwords fail startup. TLS
material must match the `redis` hostname and be readable by the Redis runtime
user. `REDIS_ACL_FILE` is a secret-manager-generated ACL file that disables the
default user and authorizes the worker with a password hash; it must never allow
`nopass`. API and worker require Celery broker permissions. The deployment
owner must review the ACL and restrict it to the agreed queues/key prefixes and
operational requirements. Verify anonymous and wrong-password rejection after
provisioning; a mounted filename alone is not proof of its contents.

The template disables Redis RDB/AOF persistence and uses temporary storage;
there is no Celery result backend or stored error/event payload. Queue messages
contain identifiers only. Broker visibility timeout is one hour, and completed
results remain in PostgreSQL. Broker loss can still require recovery of pending
scans; the transactional outbox/reconciler belongs to Phase 6. Do not describe
this ephemeral queue as durable or configure Redis as an evidence archive.

PowerShell requires an independent `POWERSHELL_SERVICE_SECRET` of at least 32
random ASCII characters in worker and service. The service fails startup if it
is missing even in development. `POWERSHELL_CERT_FILE`/`POWERSHELL_KEY_FILE`
terminate HTTPS at the service; the certificate must match `powershell-service`.
`POWERSHELL_CA_FILE` adds the private CA to the worker's public trust roots,
without globally replacing Graph HTTPS trust. Review certificate permissions
for the non-root service user. Use a CA bundle suitable for both internal
services at `RUNTIME_CA_FILE`; private keys are never mounted into the worker.

SharePoint PnP continues to require tenant-specific admin URL and mounted
certificate-alias configuration described in `engine/powershell/README.md`.
Use the reviewed `docker-compose.sharepoint.yml` overlay for PnP-enabled deployments,
including ready controls 7.2.5 and 7.3.1. Supply `SHAREPOINT_ADMIN_URL`,
`SHAREPOINT_PFX_FILE` and `SHAREPOINT_PASSWORD_FILE`; Compose mounts these
only into the service and binds the worker to the fixed `default` alias.
there is no fallback to arbitrary certificate paths from request bodies. Full
selected-tenant binding of SharePoint configuration remains Phase 6 work.

The PowerShell contract is a breaking internal API change. Upgrade all callers
and the service together; drain/revoke old broker messages before starting the
new identifier-only task consumers. Existing queued task bodies may still
contain credentials from previous releases: handle the old queue and its
backups under the prior credential incident process. The patch cannot erase
historical broker or external log contents. Older callers fail closed rather
than falling back to generic execution.

Local verification uses only synthetic, disposable services. The TLS smoke
script generates short-lived test material, proves verified TLS succeeds,
rejects anonymous/wrong-password/untrusted-CA/plaintext connections, checks
persistence is disabled, and removes its container and temporary files. It does
not provision or verify a production deployment.

References used to verify configuration: [Celery configuration](https://docs.celeryq.dev/en/stable/userguide/configuration.html),
[Redis security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/),
and [Redis TLS](https://redis.io/docs/latest/operate/oss_and_stack/management/security/encryption/).

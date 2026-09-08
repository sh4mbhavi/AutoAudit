# Browser authentication contract

Phase 5 replaces browser bearer JWTs with the `autoaudit_session` HttpOnly,
host-only, SameSite=Lax cookie. Production requires HTTPS and Secure cookies. Deploy the frontend and API
on the same site (for example, app.example.com and api.example.com) so the
SameSite=Lax cookie is sent on API fetches; unrelated site domains are not a
supported deployment topology.
The backend stores only a SHA-256 digest of a random opaque session credential
in `auth_session`, with user ownership, idle expiration and absolute expiration.
The signing key remains required for account-lifecycle tokens and CSRF signatures;
there is no browser bearer-header authentication fallback.

Password login and Google sign-in create the same session contract. Successful
password login returns 204; Google redirects to the frontend callback without an
application token in the URL. The frontend confirms `/v1/auth/users/me` before
showing authenticated content. It neither stores session credentials in browser
storage nor sends Authorization headers. Old token/user/callback caches are
removed during startup. Existing browser bearer sessions will require sign-in
again after this upgrade.

All unsafe API methods, including login, registration, refresh and logout,
require the exact configured frontend Origin and a signed, session-bound CSRF
cookie/header pair. Fetch `/v1/auth/csrf` with credentials first and copy its
`csrf_token` JSON value into `X-CSRF-Token` on the unsafe request. The CSRF cookie
is itself HttpOnly; scripts receive the header value through the response body.
Both CSRF and session responses use `Cache-Control: no-store`. Credentialed CORS
allows only the configured frontend origin. Command-line clients must explicitly
use this cookie/Origin/CSRF contract; bearer-only clients fail authentication.

`POST /v1/auth/refresh` requires a currently valid session and atomically rotates
the stored token digest. Old tokens cannot mint another session. Expiration is
bounded by the configured session lifetime (30 minutes by default) and an
absolute lifetime (eight hours by default), anchored to original login. Expired
sessions require sign-in again. The frontend renews only for recent user activity
in a visible tab, and handles competing refreshes without treating another
tab's successful rotation as an expired login.

Logout deletes the authenticated database session and clears the cookie;
replaying the previous token fails. The frontend waits for server logout and
reports failure rather than pretending it deleted an HttpOnly cookie itself.
A single session logout does not claim to revoke independent sessions on other
devices. The session table contains credential hashes only; expired rows are
removed opportunistically when new sessions are created.

Forward-only migration `d5f02b84c731` creates session storage and removes unused
Google access/refresh credentials while preserving provider account links.
New Google account linking also discards those credentials; the product uses
them only during the callback for identity, not for subsequent Google API
access. This deliberate purge is irreversible credential minimization, not a
claim to revoke already-issued Google tokens or erase historical database
backups. Deploy the migration before new API containers, review backups under
the prior retention/incident process, and do not restore the old bearer frontend
against this API.

Google callback tests use synthetic provider responses. Production Google
redirect URI registration, real account-linking acceptance, HTTPS ingress and
cookie behavior at the deployed domains remain owner verification tasks.

Reference: [FastAPI Users cookie transport](https://fastapi-users.github.io/fastapi-users/latest/configuration/authentication/transports/cookie/).

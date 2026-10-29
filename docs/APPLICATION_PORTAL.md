# Online application portal

Employees open `/apply`, sign in with the configured identity provider, submit
application details, and follow review, publication and acceptance in one place.
The administrator console remains at `/` with its existing independent login.
The portal replaces the offline application form; the authentication integration
requirements still apply.

## Employee login configuration

Register one confidential OIDC client for this manager itself. Use authorization
code, PKCE S256, scopes `openid profile email`, and `client_secret_basic`.
Set its exact redirect URI to:

```text
https://manager.example.com/api/applicant/callback
```

Store its client secret in a private file readable only by the web container
identity, normally `/data/applicant-oidc.secret`. Set these private deployment
environment variables and recreate the web container:

```text
ACM_OIDC_ISSUER=https://auth.example.com
ACM_OIDC_CLIENT_ID=manager-application-portal
ACM_OIDC_SECRET_FILE=/data/applicant-oidc.secret
```

The issuer must use HTTPS. The manager callback uses the exact `ACM_ORIGIN`;
configure an HTTPS manager origin and Secure cookies for normal deployment.
The explicit trusted-LAN HTTP profile uses an HTTP callback and non-Secure
cookies, and is suitable only within its operator-approved network boundary.
Do not silently change callback origins or infer them from forwarded headers.
Secrets and actual deployment values must never enter this repository.

The provider discovery document, token endpoint and JWKS must be reachable from
the web container. Signing keys are fetched for each login, so provider key
rotation does not require a manager restart. State is stored server-side,
expires after ten minutes, and is bound to a temporary HttpOnly browser cookie.
The callback validates state, PKCE, signature, issuer, audience, nonce, expiry,
issued-at and authorized party. Raw tokens and authorization codes are not
persisted. UserInfo is fetched over HTTPS and its subject must match the verified
ID token before profile claims are used. Existing employees must sign in again to refresh their name.
Keep HTTP access logs disabled or redact callback queries.

An identity is associated by issuer and subject, never by email or display name.
Its account is assigned only the applicant role. Employee login never grants
administrator access or links to an existing administrator by email.

## Workflow

1. The applicant submits an application for one environment. Required details
   include owners, department, technical contact, application type, framework,
   access URL and exact callback URLs. All required fields are marked with an asterisk.
   Callback paths depend on the application OIDC component; no universal path is inferred.
   Production URLs require HTTPS. Web SPA and mobile applications are public
   clients and receive no client secret.
2. An administrator approves, returns for more information, or rejects the
   application. Returns and rejections require a reason. Department scope is currently unavailable for new or resubmitted applications and approvals.
   Historical registrations and stored application fields remain readable.
   The administrator can require two-factor authentication.
3. Approval freezes the reviewed configuration. Publication is a separate
   deliberate action requiring recent administrator password/TOTP verification
   and acknowledgement of provider restart impact.
4. Publication validates the current provider revision, stores a draft, generates
   encrypted credentials, and submits the existing guarded agent operation.
   Applied jobs and current provider state gate credential availability.
5. Only the original applicant can claim a confidential client's secret.
   Secrets expire 24 hours after generation, are claimed atomically once, and
   are deleted from the delivery table. Normal connection parameters remain
   available in the application detail.
6. The applicant records acceptance results covering login, protocol and token
   validation, permissions, employee suspension, logout, provider outages and
   sensitive data handling. An administrator confirms completion.

Application-generated deliveries are excluded from the administrator's anonymous
delivery-link list. Both anonymous claim endpoints and the administrator claim
endpoint reject them. Historical direct administrator-created deliveries retain
their existing behavior.

## Failure and reissue

Publication retries preserve an uncertain job ID rather than creating another
provider change. If validation rejects a draft before the agent accepts it, the
next explicit retry can obtain a new provider revision. Failed or compensated
jobs can be retried after checking their record. Attention states require
operator investigation. Provider revision checks prevent silent overwrite.

If a secret expires or is lost, the administrator can reissue it from the
application detail after arranging the application cutover and acknowledging
the provider restart. This rotates the secret: the old credential stops working
once the new configuration is applied. The new delivery is again bound to the
same applicant. Reissue clears the prior claim and acceptance results, requiring
the updated integration to be checked again.

Claims fail closed if the related job has been rolled back, the client is
disabled, or its live configuration or credential no longer matches the approved
registration. The private agent checks the credential hash and exact job receipt;
it returns no hash or secret to the browser. Claims also fail if the job record
is missing. The administrator can arrange a reviewed rotation when an old receipt
cannot be verified.

## Upgrade and recovery

Back up the SQLite database using SQLite's backup API and protect the master
key before upgrading. New workflow tables are created automatically; existing
administrator accounts, TOTP, applications and provider clients are preserved.
Deploying the web upgrade does not itself modify or restart the identity provider.
Registering the manager's own OIDC client is a separate provider publication.

The local tests use fictional identities and a disposable provider configuration.
Never add QA login routes, test sessions, or test applications to production.
`tests/test_applications.py` covers ownership, review races, concurrent claims,
scope restrictions, public clients, reissue, CSRF and rollback behavior.
`tests/test_oidc.py` covers browser binding, replay, PKCE and invalid ID tokens.

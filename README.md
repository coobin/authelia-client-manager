# Authelia Client Manager

A self-hosted administrator console for registering OIDC applications with Authelia. 中文界面，独立管理员登录，通过检查、备份和受控发布管理客户端。

## Status

Initial release targeting **Authelia 4.39.1**, a single YAML configuration and a single provider instance. Other versions, template filters, configuration overrides and advanced client types are blocked for writes until tested. This console is not an Authelia project or an identity provider.

## Features

- Import a redacted client inventory without sending original provider configuration to the web service.
- Create application drafts, validate redirect URIs and use Code + PKCE S256 defaults.
- Generate hashed client credentials with encrypted, expiring, single-claim delivery.
- Validate with the actual provider version; publish with revision checks, backups and atomic replacement.
- Restart only the configured target, record durable outcomes and compensate failed deployments.
- Independent Argon2id + TOTP administrator login, CSRF protection and audit records.
- View and copy application connection parameters.

Saving a draft does not publish it. Publishing restarts the target provider and can interrupt in-flight login. Disabling a client does not end existing application sessions. Secret rotation requires coordination with the application owner.

## Local demo

Python 3.11 or newer and Node.js are required. The demo uses fictional data and never connects to a real provider.

```sh
python3 -m venv .venv
.venv/bin/pip install -e .
npm ci --prefix frontend
npm run build --prefix frontend
./scripts/demo.sh
```

Open `http://localhost:8098`. Initial private credentials and the authenticator setup URI are written to `runtime/web/initial-login.txt` with owner-only permissions. Add the TOTP account to your authenticator and protect the initial file. The `runtime` directory is ignored by Git and excluded from Docker builds.

## Production deployment

Read [deployment instructions](docs/DEPLOYMENT.md) and [security boundaries](SECURITY.md). Build the frontend locally, then build the Docker image:

```sh
npm ci --prefix frontend
npm run build --prefix frontend
docker build -t authelia-client-manager:0.1.0 .
```

The web container has no Docker socket or original provider configuration. The separate agent container has Docker access and must be treated as a high-privilege component. It uses fixed local target settings and has no TCP network. Start in read-only mode and verify imported applications before enabling writes.

Only access the loopback HTTP profile through an authenticated SSH tunnel. A directly exposed production deployment requires a trusted HTTPS reverse proxy, correct origin, Secure cookies and network restrictions.

## Tests

```sh
.venv/bin/pip install pytest pytest-asyncio
.venv/bin/pytest -q
npm run build --prefix frontend
python3 scripts/privacy_check.py
```

See [the integration procedure](docs/TESTING.md) for validation against a disposable provider. Never attach integration tests to production directory, storage, Redis or employee accounts.

## Privacy and limitations

No telemetry is configured. Real deployment settings, employee information, client inventories, credentials, databases, backups and screenshots belong outside the source repository. `.gitignore` is not a substitute for reviewing the complete history and release artifacts.

The first release publishes one draft per transaction. It deliberately does not merge client arrays from multiple configuration files. Latest-release rollback is supported; arbitrary historical restores must be reviewed as new changes. Imported clients with unsupported schemas are read-only.

License: MIT. Contributions must use fictional examples and include appropriate regression tests.

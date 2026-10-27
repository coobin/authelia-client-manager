# Security

## Trust boundaries

The agent has Docker daemon access. This is effectively host-administrator authority, even though its HTTP interface exposes only fixed configuration operations. Protect the agent image, deployment configuration, runtime directory and Unix socket accordingly. The web container has no Docker socket, provider mount or agent state mount.

All provider YAML, old client credentials and full configuration backups stay on the agent side. API validation errors omit supplied values and native validator output is not relayed to browsers because it can contain secrets.

New secrets use PBKDF2-SHA512 for provider storage and AES-GCM for temporary delivery. The independent master key is stored in the web data directory, never in the database, image or source. Back up that key securely with the data. Logical deletion of a delivered secret does not guarantee physical erasure from SQLite, WAL, backups or storage media.

Use trusted HTTPS for exposed access. The explicit loopback HTTP profile is intended only for local demonstration or an SSH tunnel. Do not trust arbitrary forwarded identity headers. Proxy and application logs must not record cookies, credentials, authorization codes, tokens or request bodies.

Publishing is a privileged operation that restarts the provider. Version conflicts block publication. Automatic recovery stops if a third party changed the configuration. Separate directory/Redis outages may require manual recovery; never advertise all failures as automatically recoverable.

## Reporting

Do not disclose credentials or production details in public issues. Use the repository owner's private vulnerability reporting mechanism when available. Until configured, request a private contact without posting exploit details or sensitive files.

## Release checklist

Review source and full history, run privacy and secret scans, inspect image layers and build context, and use fictional screenshots. Public CI never receives production SSH keys or deployment access. Review dependency locks and provider compatibility before updating either.

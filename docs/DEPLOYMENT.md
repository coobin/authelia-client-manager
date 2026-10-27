# Deployment and recovery

Store all runtime settings outside the source checkout. The examples below use generic paths; replace them privately.

1. Build the frontend and runtime image. Record the built image ID or use a published digest. The provider is not upgraded by this tool.
2. Prepare private `web`, `agent` and `socket` directories. Web data is owned by the configured web UID; agent state is root-owned; socket directory is root-owned with the web GID and mode 0770. The agent container runs as root with capabilities dropped and Docker-group access. Its fixed provider mount must permit preserving original file ownership.
3. Copy `.env.example` outside the repository. Set the exact provider directory, container, issuer, Docker socket GID and access origin. Keep `ACM_WRITABLE=0` initially. The provider must use `X_AUTHELIA_CONFIG` for the exact single-file path. Unsupported overrides stop publication.
4. Start the web service with the private writable data volume. It initializes its master key and database automatically. A missing key for an existing database blocks startup instead of silently replacing it.
5. Through the intended HTTPS entry or SSH tunnel, open the web page and create your account and password. TOTP is off by default; optionally enable it in Settings and verify the generated code. Once the account exists, browser setup is closed.
6. Start the supplied Compose file with an absolute external env-file. Verify `/api/health`, password-only administrator login and the imported client count. No provider restart occurs on tool startup.
7. Validate publication and recovery against a disposable provider before setting `ACM_WRITABLE=1` for production. Recreate only the manager agent when changing that flag; restarting the manager does not restart the provider.

## Access

The default binding is loopback. Use an SSH forward during initial acceptance, with the configured origin matching the local browser address. For normal network use, place a trusted HTTPS proxy in front of the loopback web port, set `ACM_ORIGIN` to that exact origin and set `ACM_SECURE_COOKIE=1`. Do not expose loopback HTTP through an unauthenticated tunnel.

## Emergency recovery

Stop or disable the manager's write access. Read the private agent job records and identify the nearest known-good backup. Verify that no other administrator has changed the provider. Restore the chosen backup preserving owner and permissions, restart only the designated provider and inspect its native health result. Do not delete provider storage or change signing keys.

The agent automatically examines interrupted jobs on startup. It restores only when current file content matches its recorded candidate. If file content differs, it records an attention state instead of overwriting an external change.

Keep backups and agent state protected and make an independent encrypted backup. The initial release does not automatically prune historical configuration backups: administrators must monitor free space and apply a documented retention policy. Never delete a backup referenced by an active recovery task.

## Administrator recovery

Use the same bootstrap container with `python -m acm.cli reset-admin --data /data --username admin --bundle /data/new-private-login.txt` to reset a known account and invalidate its sessions. Transfer the new private file securely. `create-admin --role viewer --username auditor` creates a read-only account; the CLI asks for a password unless a private output bundle is selected.

To intentionally return a deployment with exactly one designated administrator to browser setup, back up its database first, then run `python -m acm.cli prepare-setup --data /data --username admin` through the host. It clears that account's TOTP and sessions but preserves application records. Normal upgrades preserve existing enrollment. This recovery action has no web endpoint.

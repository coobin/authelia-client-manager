# Isolated integration testing

Use the same immutable provider image as the production compatibility target, but create a fresh configuration directory, fake file-backed users, independent SQLite storage and a filesystem notifier. Never mount production directory or session storage. Do not publish the test provider directly to the network.

The integration harness should verify:

- Native configuration validation succeeds for a new client using the generated PBKDF2-SHA512 format.
- Provider restart loads the new client and discovery yields the expected issuer.
- A real authorization-code flow with S256 completes using a fictional account.
- Existing fictional clients still work after publication.
- The previous file is restored after an injected restart or health failure.
- No unrelated configuration subtree changes.
- Repeated job IDs do not cause a second restart; an external edit causes a conflict.

The unit/API tests cover guards, authentication and secret lifecycle without connecting to Docker. Browser acceptance covers the login screen, inventory, draft validation and publication controls, including responsive layouts.

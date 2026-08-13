# Contributing

Issues and pull requests are welcome. Before submitting a change:

1. Keep the filesystem read-only and preserve pruning as a fail-closed boundary.
2. Add focused tests for behavior changes and security-sensitive edge cases.
3. Run `cargo fmt -- --check`, `cargo test --locked --all-targets`, and
   `cargo clippy --locked --all-targets -- -D warnings`.
4. Run `./tests/linux_e2e.sh` on Linux with `/dev/fuse` when changing OSS or FUSE behavior.
5. Do not commit credentials, private endpoints, bucket contents, or local configuration.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not through a public
issue.

By contributing, you agree that your contribution is licensed under GPL-3.0-only.

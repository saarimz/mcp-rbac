# Releasing

Nothing in this repository publishes on its own: a release is a pushed `v*` tag (or a manual run of
`.github/workflows/release.yml` with `dry_run: false`). Every publish job authenticates with OIDC trusted publishing,
so no long-lived registry token is stored in GitHub.

| Registry | Package | Job | How it authenticates |
|----------|---------|-----|----------------------|
| npm | `mcp-rbac` | `npm-publish` (environment `npm`) | npm trusted publishing (OIDC), npm CLI >= 11.5.1 on Node 24; provenance attestation is generated automatically |
| PyPI | `mcp-rbac-core` (abi3 wheels: Linux x86_64/aarch64, macOS arm64/x86_64, Windows x64 + sdist) | `pypi-publish` (environment `pypi`) | PyPI trusted publisher via `pypa/gh-action-pypi-publish` (attestations on by default) |
| PyPI | `mcp-rbac` (pure Python wheel + sdist; depends on `mcp-rbac-core==<same version>`) | `pypi-publish` | same |
| crates.io | `mcp-rbac-core` | `crates-publish` (environment `crates`) | crates.io trusted publishing via `rust-lang/crates-io-auth-action` |

Not published in 0.5: the Go module (`go/` embeds `mcp_rbac_abi.wasm`, which is built, not committed, so a
`go get` consumer could not build it; it needs a repository that commits the built module) and the Rust MCP SDK
decorator `mcp-rbac-rmcp` (`publish = false`).

## Before every release

1. Bump the version in `package.json`, `python/pyproject.toml` (and its `mcp-rbac-core==` pin),
   `core/mcp-rbac-py/pyproject.toml`, `core/Cargo.toml` (workspace), and the `INSTRUMENTATION_VERSION` constants
   (`src/core-otel.ts`, `python/src/mcp_rbac/core_otel.py`, `core/mcp-rbac-rmcp/src/otel.rs`, `go/otel.go`).
   The release workflow's `check-version` job fails if the tag and the four manifests disagree.
2. Update `CHANGELOG.md`.
3. `npm run build:wasm && tools/release-dry-run.sh`: builds every artifact, runs `twine check --strict`,
   `cargo publish --dry-run`, and installs the npm tarball and both wheels into clean projects. Uploads nothing.
4. Run the release workflow by hand with `dry_run: true` (the default): it builds everything on the real runners
   and runs `npm publish --dry-run`; the PyPI and crates.io upload steps are skipped.
5. Tag `vX.Y.Z` and push the tag.

## One-time setup (needs the maintainer's accounts)

These steps cannot be done from CI and are listed in the order they must happen.

1. **GitHub**: create the `mcp-rbac/mcp-rbac` repository (the URL in every manifest). Create three environments,
   `npm`, `pypi`, `crates`, each with a required reviewer so a tag alone cannot publish. Enable private vulnerability
   reporting (SECURITY.md points to it).
2. **npm**: trusted publishing can only be configured on a package that already exists, so the first version is
   published by hand from a maintainer machine with 2FA:
   `npm publish --access public --provenance=false` (provenance needs a CI OIDC token; `publishConfig.provenance`
   is `true` for CI). Then on npmjs.com: package settings, Trusted publisher, GitHub Actions, organization
   `mcp-rbac`, repository `mcp-rbac`, workflow `release.yml`, environment `npm`. Afterwards set "require two-factor
   authentication and disallow tokens".
3. **PyPI**: for each of `mcp-rbac-core` and `mcp-rbac`, add a *pending* trusted publisher (pypi.org, Account,
   Publishing): owner `mcp-rbac`, repository `mcp-rbac`, workflow `release.yml`, environment `pypi`. A pending
   publisher creates the project on its first upload, so no manual first upload is needed. Publish
   `mcp-rbac-core` before (or in the same run as) `mcp-rbac`, since `mcp-rbac` pins it.
4. **crates.io**: like npm, trusted publishing is configured on an existing crate, so publish `mcp-rbac-core` once
   by hand (`cargo login`, then `cargo publish -p mcp-rbac-core` from `core/`), then add the trusted publisher
   (crate settings: repository `mcp-rbac/mcp-rbac`, workflow `release.yml`, environment `crates`).

## Name status

Checked against the public registry APIs on 2026-11-15 at about 17:35 ET (HTTP 404 = no such package): PyPI
`mcp-rbac`, `mcp-rbac-core`; npm `mcp-rbac`, `mcp-rbac-core`; crates.io `mcp-rbac-core`, `mcp-rbac-rmcp`; GitHub
user/organization `mcp-rbac`. Nothing is reserved until it is published or created.

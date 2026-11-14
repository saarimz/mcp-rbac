# Support and deprecation policy

- **Versioning**: SemVer. Before 1.0, a minor bump (0.3 → 0.4) may break APIs; patches never do.
- **Supported**: the latest minor gets features and fixes; the previous minor gets security fixes for 6 months after the next minor ships.
- **Deprecation**: deprecated APIs are marked `@deprecated` (TS) / `DeprecationWarning` (Python), listed in the
  CHANGELOG, and kept for at least one minor release (and at least 3 months) before removal. Security-motivated
  removals may be faster, and are called out explicitly.
- **Protocol versions**: MCP 2026-07-28 (stateless) and the legacy session-based versions (2025-06-18, 2025-03-26,
  2024-11-05) are served side by side. A legacy version is dropped no earlier than 6 months after the official SDKs drop it.
- **Runtimes**: Node ≥ 22.13 (TS); Python ≥ 3.11 with `mcp>=2.3,<3` (Python).
- **Wire compatibility**: the JSON policy format, audit-chain hashing, Redis keys/scripts and Postgres tables are shared
  by TS and Python and versioned together; a change there is a breaking change for both.
- **Channels**: issues for bugs and questions; private reporting for security (SECURITY.md).

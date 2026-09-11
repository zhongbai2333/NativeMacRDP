# Contributing to NativeMacRDP

NativeMacRDP is experimental systems software at the intersection of macOS,
FreeRDP, and several RDP virtual channels. Small, testable changes are easier to
review than broad rewrites.

## Before opening an issue

- Check the status and known gaps in [`docs/TESTING.md`](docs/TESTING.md).
- Search existing issues for the client, macOS version, and error code.
- Do not post passwords, certificates, tunnel tokens, public server addresses,
  full home-directory paths, or unredacted logs.
- Report security problems privately according to [`SECURITY.md`](SECURITY.md).

For a bug report, include the Mac model and architecture, macOS version, RDP
client and version, connection path (loopback, LAN, VPN, or tunnel), display
resolution, enabled optional channels, minimal reproduction steps, and a short
redacted log excerpt.

## Development workflow

1. Fork the repository and create a focused branch.
2. Install the dependencies listed in [`README.md`](README.md).
3. Build and run the full protocol suite:

   ```bash
   ./scripts/build.sh
   ```

4. Check patch formatting and repository whitespace:

   ```bash
   git diff --check
   ```

5. Explain the behavior change, tests, and real-client validation separately in
   the pull request. Unit tests do not substitute for a Windows App or mstsc
   interoperability check.

Changes to the patched FreeRDP surface should update the pinned patch files and
include a focused regression test where possible. Avoid adding unpinned network
downloads, machine-specific paths, generated binaries, certificates, or local
runtime configuration.

## Licensing

By submitting a contribution, you agree that it is licensed under the
repository's [MIT License](LICENSE). Code copied or adapted from FreeRDP remains
subject to Apache-2.0; identify such changes clearly so attribution and license
notices can be preserved.

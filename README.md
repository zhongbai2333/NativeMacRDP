# NativeMacRDP

[![CI](https://github.com/zhongbai2333/NativeMacRDP/actions/workflows/ci.yml/badge.svg)](https://github.com/zhongbai2333/NativeMacRDP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

NativeMacRDP is an experimental native RDP server for macOS. It exposes the
logged-in Mac desktop directly to standard RDP clients without passing through
a VNC server. The most-tested client is Microsoft Windows App on iPad.

The supported profile uses RDPGFX Progressive over TCP, ScreenCaptureKit for
capture, CGEvent for input, and a BetterDisplay virtual screen sized to the RDP
client. H.264/AVC and reliable UDP code are retained for research, but neither
is part of the default deployment.

> [!WARNING]
> NativeMacRDP is pre-release software. It uses some undocumented macOS APIs,
> has not received an independent security audit, and currently runs with NLA
> disabled. Keep the listener on loopback or a trusted LAN and use a VPN or an
> authenticated tunnel for remote access. Do not expose it directly to the
> public Internet.

## Highlights

- Native RDP/TLS server built on a pinned FreeRDP 3.30.0 source release
- RDPGFX Progressive transport with dirty-region coalescing and frame shedding
- ACK/QoE-driven TCP pacing and motion-aware quality reduction
- BetterDisplay virtual-screen lifecycle and MS-RDPEDISP dynamic resizing
- Unicode keyboard, pointer, high-resolution wheel, text/PNG clipboard, and
  bounded regular-file clipboard implementations
- Short reconnect grace, standard auto-reconnect cookies, client liveness
  detection, and in-place RDPGFX surface recovery
- Optional system audio, microphone, drive redirection, AVC, and reliable UDP
  paths, all disabled in the stable installer unless explicitly enabled

The detailed implementation and trust boundaries are documented in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). The live feature matrix is in
[`docs/TESTING.md`](docs/TESTING.md).

## Requirements

- macOS 14 or newer; currently tested on macOS 26 and Apple silicon
- Xcode Command Line Tools
- [Homebrew](https://brew.sh/)
- [BetterDisplay](https://github.com/waydabber/BetterDisplay) for the tested
  virtual-display path
- A logged-in Aqua session; ScreenCaptureKit and BetterDisplay cannot provide
  this desktop from a system LaunchDaemon

Install the build dependencies:

```bash
brew install cmake pkg-config openssl@3 ffmpeg uriparser jansson
```

## Build and test

```bash
./scripts/build.sh
```

The script downloads the pinned FreeRDP archive, verifies its SHA-256, applies
the patches in [`patches`](patches), builds FreeRDP and NativeMacRDP, and runs
the protocol tests. Generated files stay under the ignored `work/` directory.
The daemon is written to:

```text
work/build-patched/daemon-build/macos-rdp-daemon
```

## Install for one macOS user

The default installation listens only on loopback:

```bash
./scripts/install-user.sh \
  work/build-patched/daemon-build/macos-rdp-daemon
```

For a trusted LAN, opt in to a non-loopback listener:

```bash
RDP_BIND_ADDRESS=0.0.0.0 RDP_PORT=3389 \
  ./scripts/install-user.sh \
  work/build-patched/daemon-build/macos-rdp-daemon
```

The installer creates a per-user LaunchAgent, generates a local RDP TLS
certificate, installs the BetterDisplay lifecycle helper, and signs the daemon
with a stable identity. It does not require `sudo`.

On first use, approve the installed `NativeMacRDP` executable in:

- System Settings → Privacy & Security → Screen & System Audio Recording
- System Settings → Privacy & Security → Accessibility

Restart the service after granting access. Reusing the same signing identity is
important because changing the executable identity can make macOS request the
permissions again.

With FileVault enabled, user LaunchAgents cannot start after a cold boot until
someone unlocks the Mac. This is a macOS platform boundary, not an RDP setting.

## Remote access

Secret-free FRP examples are provided in [`deploy/tunnel`](deploy/tunnel). The
supported tunnel profile forwards TCP only. Keep tokens, TLS private keys, real
server addresses, and machine-specific paths outside this repository.

For LAN clients, prefer the Mac's `<LocalHostName>.local` Bonjour name or a DHCP
reservation instead of assuming that its numeric address will not change.

## Default runtime profile

| Setting | Default | Purpose |
|---|---:|---|
| `RDP_NETWORK_AUTO_DETECT` | `1` | Seed pacing from measured bandwidth and RTT |
| `RDP_PROGRESSIVE_MBIT` | `60` in installer | Progressive transport ceiling |
| `RDP_PROGRESSIVE_MIN_MBIT` | `2` | Minimum automatic low-bandwidth target |
| `RDP_RECONNECT_GRACE_SECONDS` | `30` in installer | Retain the desktop briefly after link loss |
| `RDP_CLIENT_LIVENESS_TIMEOUT_SECONDS` | `20` | Close a half-open client transport |
| `RDP_CURSOR_SHAPES` | `1` in installer | Send sanitized native cursor shapes |
| `RDP_CURSOR_POSITION_ECHO` | `buttons` | Echo click positions without WAN motion lag |
| `RDP_UNICODE_INPUT` | `1` | Accept RDP Unicode input events |
| `RDP_SCROLL_PIXEL_SCALE` | `1.0` | Scale high-resolution wheel input |
| `RDP_AUDIO_OUTPUT` | `0` | Opt in to Mac system-audio redirection |
| `RDP_AUDIO_INPUT` | `0` | Opt in to microphone redirection |
| `RDP_RDPDR_ENABLED` | `0` | Opt in to drive redirection |
| `RDP_UDP_ENABLED` | `0` | Opt in to the experimental reliable-UDP path |
| `RDP_UPDATE_ENABLED` | `0` | No unattended binary replacement |

See [`docs/TESTING.md`](docs/TESTING.md) for the complete environment-variable
reference and for the distinction between implemented, live-tested, and
untested behavior.

## Service management

```bash
# Inspect the user service
launchctl print "gui/$(id -u)/com.nativemacrdp.agent"

# Restart it
launchctl kickstart -k "gui/$(id -u)/com.nativemacrdp.agent"

# Follow errors
tail -f "$HOME/Library/Logs/native-mac-rdp.error.log"
```

## Known limitations

- The tested Windows App path is TCP Progressive, not H.264/AVC or UDP.
- BetterDisplay is an external dependency and its command-line interface may
  change between releases.
- The fallback virtual-display and cursor paths use undocumented macOS APIs and
  can change without notice in a macOS update.
- Secure login-window input is not supported. The server controls an already
  logged-in Aqua session.
- iPadOS and Windows App can reserve some Command-key shortcuts before the
  remote Mac receives them.
- Only one active retained desktop/session is supported.
- Intel Macs, independent multi-monitor displays, long soak tests, image
  clipboard interoperability, folder clipboard copy, and drive mounting need
  more validation or implementation.

## Contributing and security

Contributions are welcome; start with [`CONTRIBUTING.md`](CONTRIBUTING.md).
Please report vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md), not in a public issue.

## Origin and license

NativeMacRDP is derived from
[`grioghar/macos-rdp-server`](https://github.com/grioghar/macos-rdp-server),
whose original Git history and copyright notice are retained. NativeMacRDP is
available under the same permissive [MIT License](LICENSE).

The build also links FreeRDP under Apache-2.0. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for dependency and
redistribution details.

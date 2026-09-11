# Architecture

NativeMacRDP is a single-user, single-desktop RDP server. It operates inside the
logged-in macOS Aqua session so ScreenCaptureKit, CGEvent injection, TCC grants,
and BetterDisplay all refer to the same desktop the user sees.

## Supported data path

```text
RDP client
    │ RDP over TLS/TCP
    ▼
FreeRDP server peer
    ├── RDPGFX Progressive graphics
    ├── MS-RDPEDISP dynamic display control
    ├── CLIPRDR clipboard and regular-file transfer
    ├── input and sanitized pointer shapes
    └── optional RDPSND, AUDIN, and RDPDR channels
            │
            ▼
macOS session
    ├── BetterDisplay virtual screen
    ├── ScreenCaptureKit frames and damage metadata
    ├── CGEvent input injection
    └── pasteboard, CoreAudio, and optional FileProvider bridge
```

The stable installer selects RDPGFX Progressive over TCP. ScreenCaptureKit
delivers frames and damage regions on its capture queues. Frames are serialized
onto the RDP peer path, where tile comparison, latest-frame coalescing, motion
quality, ACK/QoE feedback, and an unrendered-byte budget prevent a slow client
from building an unbounded queue.

## Display lifecycle

At connection time the client desktop size is given to
`scripts/betterdisplay-session.sh`. The helper reuses one named BetterDisplay
virtual screen, applies the requested non-HiDPI mode, and makes it the main
display for the session. MS-RDPEDISP requests resize that display without
deliberately rebuilding the macOS desktop.

If the configured helper cannot prepare a display, the server falls back to the
current main display. A separate fallback implementation can call undocumented
`CGVirtualDisplay` classes at runtime, but it is not the tested deployment path.

## Session and reconnect model

Only one authenticated client owns the desktop. A replacement client must
authenticate before it can take over. On an unexpected transport loss, the
BetterDisplay desktop can remain alive for a bounded grace period while an RDP
auto-reconnect cookie is valid. Client liveness checks close half-open sessions,
and foreground recovery can rebuild only the client-side RDPGFX surface while
retaining the macOS desktop.

This is not an independent macOS login session: applications, notifications,
clipboard state, and user privileges belong to the already logged-in account.

## Security boundaries

The transport uses TLS and macOS account authentication, but NLA is disabled.
The listener is therefore loopback-only by default. Remote access belongs behind
a VPN or authenticated tunnel and a firewall; tunnel credentials and RDP private
keys are runtime state outside the repository.

Screen recording and input injection require explicit TCC approval for the
installed, stably signed executable. A new signing identity can cause macOS to
request those permissions again.

## Experimental paths

The source retains VideoToolbox AVC420, reliable RDPUDP2/RDPEMT, microphone,
system-audio, RDPDR, and WebDAV/FileProvider experiments. They are useful for
protocol research but do not share the same interoperability or soak-test status
as the default TCP Progressive path. Their current status is tracked in
[`TESTING.md`](TESTING.md).

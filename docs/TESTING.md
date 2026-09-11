# macOS RDP Server — Feature & Stability Test Plan

Goal: a responsive and recoverable Microsoft Windows App experience on macOS.

Status legend: ✅ working · ⚠️ partial / needs work · ❌ not implemented · ❓ untested

Primary tested client: Microsoft Windows App on iPad → macOS 26 arm64 over TCP.
Auto-update remains disabled. Reliable UDP is experimental and is not part of
the supported deployment profile.

---

## 1. Connection & Security
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 1.1 | TCP connect | Connect Windows App to the configured endpoint | Session opens | ✅ |
| 1.2 | TLS negotiation | Connect; accept cert | Encrypted session | ✅ |
| 1.3 | Self-signed cert prompt | First connect | Cert warning, then connects | ✅ |
| 1.4 | Auth — correct creds | Enter Mac username+password | Authenticates, session starts | ✅ |
| 1.5 | Auth — wrong creds | Enter wrong password | Rejected, no session | ✅ |
| 1.6 | Auth — session takeover | Connect 2nd client with correct creds | Old socket is interrupted, its shared BetterDisplay is released, then the 2nd client takes over; abort instead of overlapping displays on timeout | ✅ (fast replacement path implemented) |
| 1.7 | Auth — takeover with wrong creds | Connect 2nd client with bad creds | Rejected, 1st session undisturbed | ❓ |
| 1.8 | NLA disabled | Try NLA-required client | NLA is off server-side (document) | ⚠️ |
| 1.9 | Durable TCC grant across rebuilds | Reinstall with the same signing identity | Screen Recording remains granted | ✅ |
| 1.10 | Grant across reboot | Reboot Mac, reconnect | TBD — non-notarized binary | ❓ |
| 1.11 | Multi-monitor client | Connect mstsc with "Use all my monitors" | Single combined virtual display | ❓ |
| 1.12 | Direct LAN endpoint | Connect to the configured Mac port using its Bonjour name or current DHCP address | TCP connects; no stale address after reboot | ✅ (TCP; DHCP address is not fixed) |
| 1.13 | FRP endpoint | Connect through a private TCP tunnel configured from the examples | TCP reaches the same local RDP listener without publishing real endpoints or tokens | ✅ (TCP on the development deployment) |
| 1.14 | FileVault cold boot | Reboot with FileVault enabled, then unlock the console account | User LaunchAgents start only after the graphical login exists | ✅ (documented platform boundary) |

## 2. Display
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 2.1 | Desktop renders (RDPGFX Progressive) | Connect | Live desktop, correct content | ✅ |
| 2.2 | Virtual display at client resolution | Connect at 3440×1440 | No pillarbox, native 1:1 | ✅ |
| 2.3 | Correct colors | View photos / gradients | Accurate color | ❓ |
| 2.4 | Refresh after background/restore | Background then restore Windows App | Refresh Rect/focus/input repaints immediately; long pauses rebuild only the client RDPGFX surface; missing restore signal gets one full repaint probe after 1.5s; stale transport closes after 20s | ✅ (Windows App on iPad; 1.0s, 2.8s and 19.5s pauses recovered in place) |
| 2.5 | Frame rate / smoothness | Drag a window, scroll | Up to 60 fps at iPad-sized resolutions | ✅ (Windows App on iPad, 2252×1473) |
| 2.6 | Dynamic resolution change | Change Windows App client size | Session adapts without replacing the desktop | ✅ (MS-RDPEDISP) |
| 2.7 | Non-ultrawide client (1920×1080) | Connect from 16:9 | Correct proportions | ❓ |
| 2.8 | Privacy blank on connect | Set RDP_PRIVACY_BLANK=1 | Local display dims/blanks | ⚠️ (DisplayServices brightness only) |
| 2.9 | Shared mode | Set RDP_SHARED_MODE=1 | Remote + local see same screen | ❓ |
| 2.10 | Wake Mac on connect | Mac display asleep, then connect | Display wakes, capture starts | ✅ (IOPMAssertion) |

## 3. Input
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 3.1 | Mouse move (1:1 position) | Move across whole screen | Tracks accurately | ✅ |
| 3.2 | Stable client-side cursor | Hover text / window edge | Arrow, I-beam, resize, hand and crosshair remain visible and uncorrupted | ✅ (`RDP_CURSOR_SHAPES=1`, fixed 64×64 compatibility canvas) |
| 3.3 | Left/right/middle click | Click around | Registers correctly | ❓ |
| 3.4 | Click-drag | Drag a window / select text | Works | ❓ |
| 3.5 | Scroll wheel (vert/horiz) | Slow and fast scroll in both directions | Pixel speed follows signed RDP delta without event backlog; horizontal RDP rotation is inverted for Quartz axis semantics | ✅ direction conversion unit-tested; iPad Windows App live-tested at scale 1.0 |
| 3.6 | Keyboard — letters/numbers/symbols | Type in TextEdit | Correct chars | ✅ (including prior `d`/`e` regression) |
| 3.7 | Modifiers (⌘ ⌥ ⌃ ⇧) + shortcuts | Exercise local and remote shortcuts, then type quickly after releasing them | Remote modifiers are applied atomically to the associated key event without Ctrl remapping or a persistent macOS modifier state | ⚠️ Windows App/iPad reserves some Command shortcuts; atomic server path implemented |
| 3.8 | Special keys (F1-F12, Esc, arrows, Del) | Press them | Work | ❓ |

## 4. Clipboard (CLIPRDR)
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 4.1 | Text Mac → Windows | Copy on Mac, paste on Win | Pastes correctly | ✅ |
| 4.2 | Text Windows → Mac | Copy on Win, paste on Mac | Pastes correctly | ✅ |
| 4.3 | Unicode / emoji / RTL text | Copy/paste 非ASCII 🎉 | Preserved | ✅ |
| 4.4 | Large text | Copy a large block | No truncation | ✅ |
| 4.5 | Image (PNG) Mac → Windows | Copy a screenshot on Mac, paste in Paint | Image appears | ❓ (`PNG` registered format wired) |
| 4.6 | Image Windows → Mac | Copy image on Win, paste in Preview | Image appears | ❓ |
| 4.7 | File clipboard Mac → Windows | Copy one or more regular files in Finder, paste in Explorer | Desktop client pulls each file lazily in bounded chunks | ⚠️ implemented with a FreeRDP 3.30 static-channel chunk compatibility workaround; needs mstsc live validation (Windows App on iOS/iPadOS exposes only text/images) |
| 4.8 | File clipboard Windows → Mac | Copy one or more regular files in Explorer, wait for the transfer log, then paste in Finder | Client files are downloaded sequentially to an isolated staging directory and published only after every advertised byte arrives | ⚠️ implemented with a FreeRDP 3.30 static-channel chunk compatibility workaround; needs mstsc live validation (maximum 256 files, 2 GiB each, 4 GiB total) |
| 4.9 | Folder clipboard | Copy a folder in either direction | Directory tree is preserved | ❌ intentionally rejected by initial safe implementation |

## 5. Audio
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 5.1 | System audio out (Mac → client) | Play music on Mac | Hear it on Windows headphones | ✅ (CATap, 44.1 kHz) |
| 5.2 | Audio pitch / rate | Play a 440 Hz tone | Correct pitch | ✅ |
| 5.3 | Audio + local speakers | RDP_AUDIO_LOCAL=1 | Plays on both Mac+client | ✅ |
| 5.4 | Audio quality / sync | Play a video | Clear, in sync | ❓ |
| 5.5 | Mic input (Windows → Mac speakers) | RDP_AUDIO_INPUT=1, Win "Record from this computer" | Mac plays Windows mic | ✅ (MS-RDPEAI, 16kHz PCM) |

## 6. Drive Redirection (RDPDR / WebDAV)
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 6.1 | Channel open | Connect with Drives enabled in mstsc | Log shows "rdpdr: channel open" | ✅ |
| 6.2 | Drive enumeration | Connect with C: shared | Log shows "rdpdr: client drive C" | ✅ |
| 6.3 | WebDAV server starts | See above | Log shows "webdav: listening on :876x" | ❓ needs test |
| 6.4 | Volume mounts in Finder | See above | /Volumes/RDP-C appears in Finder | ❓ needs hardware test |
| 6.5 | Browse files (PROPFIND) | Open /Volumes/RDP-C in Finder | Windows files visible | ❓ |
| 6.6 | Read file (GET) | Open a text file | Contents correct | ❓ |
| 6.7 | Write file (PUT) | Save a file to /Volumes/RDP-C | File appears on Windows | ❓ |
| 6.8 | Delete file | Trash a file | Deleted on Windows | ❓ |
| 6.9 | Unmount on disconnect | Disconnect mstsc | /Volumes/RDP-C disappears | ❓ |
| 6.10 | Printer / serial / USB | — | Not built | ❌ |

**How to enable:** set `RDP_RDPDR_ENABLED=1` in the LaunchAgent plist (disabled by default).
**mstsc setup:** Options → Local Resources → More → Drives → check your Windows drives.

## 7. Auto-Update (not part of the verified profile)
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 7.1 | Disabled by default | Inspect LaunchAgent | No unattended network or binary replacement | ✅ |
| 7.2 | Automatic binary replacement | — | Not included in the current target | ❌ |

## 8. Session management
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 8.1 | Clean disconnect | Close mstsc | Server tears down, no leak | ✅ |
| 8.2 | Reconnect after disconnect | Reconnect | Fresh session works | ✅ |
| 8.3 | Graphics liveness watchdog | Stop ACK/QoE feedback, or leave output suppressed without restore | Repaint probe, then same-session RDPGFX surface resync on real foreground evidence; otherwise drop after 20s and retain desktop for reconnect. One omitted final frame ACK alone is not treated as a dead client | ✅ (unit coverage plus live stale-transport timeout) |
| 8.4 | Multiple sequential sessions | Connect/disconnect ×10 | Each works, no leak | ❓ |
| 8.5 | Two simultaneous clients | Connect from 2 machines | 2nd must auth; takeover or reject | ✅ |
| 8.6 | Idle session (10 min) | Leave idle | Stays up, low CPU | ❓ |
| 8.7 | Display restore on disconnect | Disconnect | Built-in display restored | ❓ |

## 9. Performance
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 9.1 | Idle CPU | Connected, static screen | Fixed refresh stays responsive; measure CPU separately | ❓ |
| 9.2 | Active CPU | Drag windows / play video | Reasonable | ❓ |
| 9.3 | Input latency | Move mouse / type | Snappy (<50ms) | ✅ (cursor) / ❓ (keys) |
| 9.4 | Memory (no leak) | Watch RSS over 1h | Flat | ❓ |

## 10. Stability / soak
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 10.1 | Long soak (1–8 h) | Keep session open | No drop, no leak, no crash | ❓ |
| 10.2 | Rapid reconnect ×20 | Connect/disconnect fast | No crash / port stuck | ❓ |
| 10.3 | Network blip | Briefly drop Wi-Fi | Recovers or clean fail | ❓ |
| 10.4 | Mac sleep/wake | Sleep the Mac, wake, reconnect | Recovers (IOPMAssertion prevents sleep during session) | ❓ |
| 10.5 | Agent auto-restart | Stop `gui/$UID/com.nativemacrdp.agent` | launchd restarts it in 5s | ✅ |

## 11. Install & configuration
| # | Item | How to test | Expected | Status |
|---|------|-------------|----------|--------|
| 11.1 | User installer | Run scripts/install-user.sh on Mac | Installs, signs, loads | ⚠️ untested end-to-end |
| 11.2 | Stable signing | Reinstall with the same identity | TCC association remains stable | ✅ on the development Mac |
| 11.3 | Grant permissions | Use System Settings | Screen Recording + Accessibility granted | ✅ manual macOS step |
| 11.4 | Clean uninstall | Remove the user agent and application-support directory | No service remains | ❓ helper script not yet packaged |

---

### Environment variable reference

| Variable | Default | Description |
|---|---:|---|
| `RDP_LOG_LEVEL` | info | Log verbosity: error / info / verbose / debug |
| `RDP_CERT_DIR` | *required* | Directory containing server.crt + server.key |
| `RDP_CURSOR_SHAPES` | 0 | Enable normalized Mac cursor semantics as cached 24bpp RDP pointers; set to 1 for the verified Windows App profile |
| `RDP_CURSOR_POSITION_ECHO` | buttons | `buttons` synchronizes click/tap coordinates without round-tripping ordinary mouse motion; `all` retains legacy iOS touch movement; `off` never sends server pointer-position updates |
| `RDP_FRAME_RATE` | resolution/transport-aware | Hard override (8–60). The deployed TCP-only 2560×1600 profile sets 60; byte pacing and latest-frame coalescing still shed work under pressure |
| `RDP_ADAPTIVE_FRAME_RATE` | 0 | Experimental idle-rate switching; disabled because Windows App for iPad did not reliably wake it from ordinary interaction |
| `RDP_IDLE_FRAME_RATE` | 15 | Capture rate after the adaptive idle timeout (2–active FPS) |
| `RDP_IDLE_AFTER_MS` | 2000 | Time without input/meaningful visual motion before idle capture rate (250–10000 ms) |
| `RDP_PROGRESSIVE_MBIT` | 20 in code; installer sets 60 | Hard Progressive pacing ceiling. Connect-time detection seeds the target and TCP rendered-frame QoE continuously adapts it |
| `RDP_PROGRESSIVE_MIN_MBIT` | 2 | Lowest automatic TCP fallback rate when the active link remains congested |
| `RDP_PROGRESSIVE_MOTION_QUALITY` | 1 | Temporarily reduce only luma high-frequency detail during large motion (chroma and low-frequency color remain full quality), then refine only tiles sent at reduced quality |
| `RDP_PROGRESSIVE_MOTION_QUANT_STEP` | 1 | Base motion quantization increase (1–3); links below 16 Mbit/s use at least +2 and links below 8 Mbit/s use +3 |
| `RDP_PROGRESSIVE_MOTION_EXIT_MS` | 1200 | Quiet time before returning to normal quality; motion starts at 12.5% changed tiles, requires two consecutive frames, and enters immediately when at least half the screen changes (250–3000 ms) |
| `RDP_PROGRESSIVE_REFINE_TILES` | 96 | Maximum full-quality tiles added to one refinement frame; the actual batch is reduced further by the current byte budget (8–256) |
| `RDP_RECONNECT_GRACE_SECONDS` | 20 in code; installer sets 30 | Keep the BetterDisplay desktop alive after an unexpected transport loss while a standard auto-reconnect cookie is valid (5–120 s) |
| `RDP_QOE_MAX_INFLIGHT` | byte-aware; 8-frame safety cap | Compatibility override for the absolute sent-minus-rendered frame safety cap (2–60). Normal backpressure uses an RTT-derived 128 KiB–1 MiB unrendered-byte window |
| `RDP_AUDIO_OUTPUT` | 0 | Stream Mac system audio to the client over RDPSND |
| `RDP_AUDIO_LATENCY_MS` | 100 | RDPSND packet/jitter window in milliseconds (40–250) |
| `RDP_SCROLL_PIXEL_SCALE` | 1.0 | Scale signed high-resolution RDP wheel units to macOS pixel deltas (0.25–8.0); events arriving in one network burst are coalesced for 4 ms |
| `RDP_SHOW_CURSOR` | 0 | Overlay Mac cursor in the video stream |
| `RDP_SHARED_MODE` | 0 | Allow local+remote to interact simultaneously |
| `RDP_PRIVACY_BLANK` | 0 | Dim built-in display brightness on connect |
| `RDP_RDPDR_ENABLED` | 0 in installer | Enable Windows drive redirection |
| `RDP_AUDIO_LOCAL` | 1 | Also play audio on local Mac speakers |
| `RDP_AUDIO_INPUT` | 0 | Receive Windows mic → Mac speakers (MS-RDPEAI) |
| `RDP_ALLOW_IDLE_SLEEP` | 0 | Allow Mac to idle-sleep (breaks remote access) |
| `RDP_UPDATE_ENABLED` | 0 | Reserved; automatic binary replacement is not included in the current target |
| `RDP_SIGN_IDENTITY` | — | Installer code-signing identity SHA-1 or name |
| `RDP_UDP_ENABLED` | 0 | Installer switch that enables the UDP listener, multitransport advertisement and full reliable-UDP path together |
| `RDP_UDP_PROBE` | 0 | Bind UDP on the same local port as TCP; normally set through `RDP_UDP_ENABLED` |
| `RDP_UDP_MULTITRANSPORT` | 0 | Advertise reliable UDP plus TCP-to-UDP Soft-Sync to the RDP client |
| `RDP_UDP_REQUIRE_COOKIE` | 1 in installer | Reject UDP SYNs unless their SHA-256 cookie matches a live TCP session |
| `RDP_UDP_FULL_STACK` | 0 | Enable RDPUDP2, TLS, RDPEMT and the selected-DVC UDP data path |

### Reliable UDP

Reliable UDP is currently **disabled and unsupported in the stable profile**.
The default installer creates no UDP listener and the supplied FRP templates
expose only TCP.

The patched FreeRDP build contains an RDPUDP2/RDPEMT research path. The installer
keeps it opt-in through `RDP_UDP_ENABLED=1`; when enabled, TCP and UDP share the
same local port. It has completed parts of Soft-Sync negotiation with mstsc in
development testing, but reconnect behavior and sustained graphics stability
are not reliable enough for the supported profile. Windows App has not selected
this path in the tested non-Azure environment.

A connection has actually switched graphics to UDP only after the log contains
all of these markers, in order:

1. `RDPUDP SYN securely matched TCP multitransport request`
2. `RDPUDP2 TLS handshake complete`
3. `RDPEMT reliable UDP tunnel authenticated and created`
4. `Soft-Sync requested: GFX DVC`
5. `Soft-Sync active: GFX traffic is now using reliable UDP`

Seeing only a UDP listener or SYN/SYN+ACK is not evidence that graphics data is
using UDP. Keyboard, mouse, clipboard, authentication and the main session stay
on TCP by design.

If a reliable UDP tunnel fails after Soft-Sync, the daemon opens a two-minute
per-address circuit breaker. The failed session is disconnected because there
is no in-place reverse Soft-Sync; the next automatic reconnect is advertised as
TCP-only so mstsc cannot enter a UDP failure loop.

For the supported FRP deployment, define only a TCP proxy. Direct LAN clients
reach the same daemon without FRP. The old
RD Gateway and custom datagram-relay experiments are not part of the supported
deployment topology.

### Known issues / in progress
1. **Drive mounting needs hardware test** — WebDAV bridge is built; test by connecting mstsc with Drives enabled.
2. **Image clipboard** — PNG support is wired (0xC004), but needs verification against real mstsc.
3. **Stability soak** — §10 scenarios not run yet. Adaptive frame-rate switching remains opt-in after the iPad latency regression.
4. **Multi-monitor per-display** — MS-RDPEDISP dynamic span sizing is implemented as one retained BetterDisplay desktop; independent macOS virtual displays per client monitor are not built.
5. **Printer/USB redirection** — out of scope for personal use.
6. **UDP client compatibility** — the reliable-UDP path remains experimental; mstsc stability and fallback need more work, and Windows App did not switch graphics away from TCP in the tested non-Azure environment.

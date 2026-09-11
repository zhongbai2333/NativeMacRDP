#!/bin/zsh

# Install NativeMacRDP as a per-user LaunchAgent in the Aqua session. This is
# intentionally sudo-free: ScreenCaptureKit and CGEvent permissions belong to
# the logged-in user session, not a system LaunchDaemon.

set -euo pipefail

if (( EUID == 0 )); then
    /bin/echo "Run as the normal desktop user, not root." >&2
    exit 1
fi

repo_root="${0:A:h:h}"
port="${RDP_PORT:-3389}"
bind_address="${RDP_BIND_ADDRESS:-127.0.0.1}"
audio_output="${RDP_AUDIO_OUTPUT:-0}"
audio_local="${RDP_AUDIO_LOCAL:-1}"
audio_latency="${RDP_AUDIO_LATENCY_MS:-100}"
udp_enabled="${RDP_UDP_ENABLED:-0}"
install_root="${NATIVE_MAC_RDP_ROOT:-$HOME/Library/Application Support/NativeMacRDP}"
bin_dir="$install_root/bin"
binary="$bin_dir/NativeMacRDP"
display_helper="$bin_dir/betterdisplay-session.sh"
agent="$HOME/Library/LaunchAgents/com.nativemacrdp.agent.plist"
label="com.nativemacrdp.agent"
gui="gui/$(/usr/bin/id -u)"
log_dir="$HOME/Library/Logs"
source_binary="${1:-$repo_root/work/build-patched/daemon-build/macos-rdp-daemon}"
betterdisplay="${RDP_BETTERDISPLAY_BIN:-/Applications/BetterDisplay.app/Contents/MacOS/BetterDisplay}"

if [[ "$port" != <-> ]] || (( port < 1 || port > 65535 )); then
    /bin/echo "Invalid RDP_PORT: $port" >&2
    exit 64
fi
if ! /bin/echo "$bind_address" | /usr/bin/grep -Eq '^[0-9A-Fa-f:.]+$'; then
    /bin/echo "RDP_BIND_ADDRESS must be a literal IPv4 or IPv6 address" >&2
    exit 64
fi
for setting in audio_output audio_local udp_enabled; do
    value="${(P)setting}"
    if [[ "$value" != "0" && "$value" != "1" ]]; then
        /bin/echo "${setting:u} must be 0 or 1" >&2
        exit 64
    fi
done
if [[ "$audio_latency" != <-> ]] ||
        (( audio_latency < 40 || audio_latency > 250 )); then
    /bin/echo "RDP_AUDIO_LATENCY_MS must be between 40 and 250" >&2
    exit 64
fi
[[ -x "$source_binary" ]] || {
    /bin/echo "Missing executable: $source_binary" >&2
    /bin/echo "Run ./scripts/build.sh first, or pass the binary path." >&2
    exit 1
}
[[ -x "$betterdisplay" ]] || {
    /bin/echo "BetterDisplay is required for the verified virtual-display profile." >&2
    /bin/echo "Expected executable: $betterdisplay" >&2
    exit 1
}

/bin/mkdir -p "$bin_dir" "$install_root/signing" \
    "$HOME/Library/LaunchAgents" "$log_dir"

# Ask an existing instance to leave through the normal RDP disconnect path,
# then wait briefly before replacing the executable.
old_pid="$(/bin/launchctl print "$gui/$label" 2>/dev/null |
    /usr/bin/awk '/^[[:space:]]*pid = / { print $3; exit }')"
/bin/launchctl bootout "$gui/$label" 2>/dev/null || true
if [[ -n "$old_pid" ]]; then
    for _attempt in {1..50}; do
        /bin/kill -0 "$old_pid" 2>/dev/null || break
        /bin/sleep 0.1
    done
fi

/usr/bin/install -m 0755 "$source_binary" "$binary"
/usr/bin/install -m 0755 "$repo_root/scripts/betterdisplay-session.sh" \
    "$display_helper"

# Prefer a caller-selected or existing Apple Development identity. If neither
# exists, create one stable local identity and reuse it across upgrades so TCC
# permissions stay associated with the same designated requirement.
sign_identity="${RDP_SIGN_IDENTITY:-$(
    /usr/bin/security find-identity -v -p codesigning 2>/dev/null |
        /usr/bin/awk -F'"' '/Apple Development:/ { print $2; exit }'
)}"

if [[ -n "$sign_identity" ]]; then
    /usr/bin/codesign --force --sign "$sign_identity" --timestamp=none \
        --identifier com.nativemacrdp.daemon "$binary"
else
    openssl_bin="${commands[openssl]:-}"
    [[ -n "$openssl_bin" ]] || {
        /bin/echo "openssl is required to create the stable signing identity" >&2
        exit 1
    }
    sign_dir="$install_root/signing"
    keychain="$sign_dir/native-mac-rdp.keychain-db"
    password_file="$sign_dir/keychain-password"
    signing_name="NativeMacRDP Local Signing"

    if [[ ! -f "$password_file" ]]; then
        "$openssl_bin" rand -hex 24 > "$password_file"
        /bin/chmod 600 "$password_file"
    fi
    keychain_password="$(<"$password_file")"

    if [[ ! -f "$sign_dir/cert.p12" ]]; then
        "$openssl_bin" req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout "$sign_dir/signing.key" \
            -out "$sign_dir/signing.crt" \
            -subj "/CN=$signing_name" \
            -addext "basicConstraints=critical,CA:false" \
            -addext "keyUsage=critical,digitalSignature" \
            -addext "extendedKeyUsage=critical,codeSigning"
        "$openssl_bin" pkcs12 -export -name "$signing_name" \
            -inkey "$sign_dir/signing.key" -in "$sign_dir/signing.crt" \
            -out "$sign_dir/cert.p12" \
            -passout "pass:$keychain_password"
        /bin/chmod 600 "$sign_dir/signing.key" "$sign_dir/cert.p12"
    fi

    if [[ ! -f "$keychain" ]]; then
        /usr/bin/security create-keychain -p "$keychain_password" "$keychain"
        /usr/bin/security set-keychain-settings "$keychain"
        /usr/bin/security import "$sign_dir/cert.p12" -k "$keychain" \
            -P "$keychain_password" -T /usr/bin/codesign -A
    fi
    /usr/bin/security unlock-keychain -p "$keychain_password" "$keychain"
    /usr/bin/security set-key-partition-list \
        -S apple-tool:,apple:,codesign: -s -k "$keychain_password" \
        "$keychain" >/dev/null 2>&1 || true
    /usr/bin/codesign --force --sign "$signing_name" --keychain "$keychain" \
        --timestamp=none --identifier com.nativemacrdp.daemon "$binary"
fi

/usr/bin/codesign --verify --deep --strict "$binary"

# The RDP transport certificate is separate from the executable signature.
if [[ ! -f "$install_root/server.key" || ! -f "$install_root/server.crt" ]]; then
    openssl_bin="${commands[openssl]:-}"
    [[ -n "$openssl_bin" ]] || {
        /bin/echo "openssl is required to generate the RDP TLS certificate" >&2
        exit 1
    }
    "$openssl_bin" req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$install_root/server.key" \
        -out "$install_root/server.crt" \
        -subj "/CN=$(/bin/hostname)"
    /bin/chmod 600 "$install_root/server.key"
fi

# Generate the user-specific plist at install time; no home paths or signing
# identities are committed to the repository.
/bin/cat > "$agent" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$label</string>
    <key>ProgramArguments</key>
    <array>
        <string>$binary</string>
        <string>--bind-address</string><string>$bind_address</string>
        <string>--port</string><string>$port</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>LimitLoadToSessionType</key><string>Aqua</string>
    <key>ProcessType</key><string>Interactive</string>
    <key>ThrottleInterval</key><integer>5</integer>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RDP_CERT_DIR</key><string>$install_root</string>
        <key>RDP_LOG_LEVEL</key><string>info</string>
        <key>RDP_DISPLAY_HELPER</key><string>$display_helper</string>
        <key>RDP_BETTERDISPLAY_NAME</key><string>NativeMacRDP</string>
        <key>RDP_NETWORK_AUTO_DETECT</key><string>1</string>
        <key>RDP_CODEC_POLICY</key><string>progressive</string>
        <key>RDP_PROGRESSIVE_MBIT</key><string>60</string>
        <key>RDP_PROGRESSIVE_MIN_MBIT</key><string>2</string>
        <key>RDP_RECONNECT_GRACE_SECONDS</key><string>30</string>
        <key>RDP_CLIENT_LIVENESS_TIMEOUT_SECONDS</key><string>20</string>
        <key>RDP_CURSOR_SHAPES</key><string>1</string>
        <key>RDP_CURSOR_MODE</key><string>sanitized-native</string>
        <key>RDP_CURSOR_POSITION_ECHO</key><string>buttons</string>
        <key>RDP_SHOW_CURSOR</key><string>0</string>
        <key>RDP_UNICODE_INPUT</key><string>1</string>
        <key>RDP_SCROLL_PIXEL_SCALE</key><string>1.0</string>
        <key>RDP_SHARED_MODE</key><string>1</string>
        <key>RDP_ALLOW_IDLE_SLEEP</key><string>0</string>
        <key>RDP_ADAPTIVE_FRAME_RATE</key><string>0</string>
        <key>RDP_AUDIO_OUTPUT</key><string>$audio_output</string>
        <key>RDP_AUDIO_LOCAL</key><string>$audio_local</string>
        <key>RDP_AUDIO_LATENCY_MS</key><string>$audio_latency</string>
        <key>RDP_AUDIO_INPUT</key><string>0</string>
        <key>RDP_RDPDR_ENABLED</key><string>0</string>
        <key>RDP_UDP_PROBE</key><string>$udp_enabled</string>
        <key>RDP_UDP_MULTITRANSPORT</key><string>$udp_enabled</string>
        <key>RDP_UDP_REQUIRE_COOKIE</key><string>1</string>
        <key>RDP_UDP_FULL_STACK</key><string>$udp_enabled</string>
        <key>RDP_UDP_HEXDUMP</key><string>0</string>
        <key>RDP_UPDATE_ENABLED</key><string>0</string>
    </dict>
    <key>StandardOutPath</key><string>$log_dir/native-mac-rdp.log</string>
    <key>StandardErrorPath</key><string>$log_dir/native-mac-rdp.error.log</string>
</dict>
</plist>
PLIST

/usr/bin/plutil -lint "$agent" >/dev/null
/bin/launchctl enable "$gui/$label"
/bin/launchctl bootstrap "$gui" "$agent"

/bin/echo
/bin/echo "NativeMacRDP is running on $bind_address:$port"
/bin/echo "Transport:    TCP$([[ "$udp_enabled" == "1" ]] && /bin/echo ' + reliable UDP' || true)"
/bin/echo "LaunchAgent: $label"
/bin/echo "Executable:  $binary"
/bin/echo
/bin/echo "Approve Screen Recording and Accessibility for NativeMacRDP once,"
/bin/echo "then restart with: launchctl kickstart -k $gui/$label"

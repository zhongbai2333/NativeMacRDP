#!/bin/zsh

# Dedicated BetterDisplay lifecycle for the isolated native-RDP prototype.
# It never disconnects the physical display and never touches the existing
# "Sunshine" virtual screen used by the XRDP/VNC fallback.

set -u

BETTERDISPLAY="${RDP_BETTERDISPLAY_BIN:-/Applications/BetterDisplay.app/Contents/MacOS/BetterDisplay}"
VIRTUAL_NAME="${RDP_BETTERDISPLAY_NAME:-NativeMacRDP}"
PHYSICAL_TAG="${RDP_PHYSICAL_DISPLAY_TAG:-}"
DEFAULT_RESOLUTION="1920x1080"
LEGACY_VIRTUAL_NAMES=("Native RDP Test" "Native RDP UDP Probe")

bd() {
    "$BETTERDISPLAY" "$@"
}

discard_legacy_virtual_screens() {
    local legacy_name
    local tag

    # Earlier test services used separate BetterDisplay profiles. They are no
    # longer referenced by any supported launch profile, so migrate them away
    # before resolving the single canonical NativeMacRDP screen. Sunshine is
    # deliberately not included in this list.
    for legacy_name in "${LEGACY_VIRTUAL_NAMES[@]}"; do
        tag="$(bd get -name="$legacy_name" -identifier=tagID 2>/dev/null | \
            /usr/bin/tr ',' '\n' | \
            /usr/bin/awk '/^[0-9]+$/{tag=$1} END{if (tag > 0) print tag}')"
        if [[ "$tag" == <-> ]]; then
            bd set -tagID="$tag" -connected=off >/dev/null 2>&1 || true
            bd discard -tagID="$tag" >/dev/null 2>&1 || true
        fi
    done
}

virtual_tag() {
    # When connected, BetterDisplay returns "<display-tag>,<virtual-tag>" for
    # this name; when disconnected it returns only the virtual tag. The virtual
    # screen tag is therefore the last positive integer.
    bd get -name="$VIRTUAL_NAME" -identifier=tagID 2>/dev/null | \
        /usr/bin/tr ',' '\n' | \
        /usr/bin/awk '/^[0-9]+$/{tag=$1} END{if (tag > 0) print tag}'
}

display_id() {
    local tag
    tag="$(virtual_tag)"
    [[ "$tag" == <-> ]] || return 1
    bd get -tagID="$tag" -identifier=displayID 2>/dev/null | \
        /usr/bin/tr ',' '\n' | \
        /usr/bin/awk '/^[0-9]+$/{if ($1 > 0) {print; exit}}'
}

ensure_virtual_screen() {
    local tag

    discard_legacy_virtual_screens
    tag="$(virtual_tag)"
    if [[ "$tag" == <-> ]]; then
        /bin/echo "$tag"
        return 0
    fi

    bd create -type=VirtualScreen \
        -virtualScreenName="$VIRTUAL_NAME" \
        -virtualScreenSerial=18523391 \
        -useResolutionList=on \
        -resolutionList="$DEFAULT_RESOLUTION" \
        -virtualScreenHiDPI=off >/dev/null || return 1

    for _ in {1..20}; do
        tag="$(virtual_tag)"
        if [[ "$tag" == <-> ]]; then
            bd set -tagID="$tag" -connected=off >/dev/null 2>&1 || true
            /bin/echo "$tag"
            return 0
        fi
        /bin/sleep 0.2
    done
    return 1
}

prepare() {
    local width="$1"
    local height="$2"
    local resolution
    local tag
    local did
    local apply_output=""
    local apply_rc=1

    if [[ "$width" != <-> || "$height" != <-> ]] ||
       (( width < 960 || width > 7680 || height < 600 || height > 4320 )); then
        /bin/echo "unsafe BetterDisplay size: ${width}x${height}" >&2
        return 2
    fi
    resolution="${width}x${height}"
    tag="$(ensure_virtual_screen)" || {
        /bin/echo "unable to create/find BetterDisplay virtual screen '$VIRTUAL_NAME'" >&2
        return 3
    }

    bd set -tagID="$tag" -useResolutionList=on \
        -resolutionList="$resolution" -virtualScreenHiDPI=off >/dev/null || return 4
    bd set -tagID="$tag" -connected=on >/dev/null || return 5

    # BetterDisplay can publish a displayID before the newly connected virtual
    # screen is ready to accept mode/main-display changes.  Treat that ID as a
    # discovery signal, not as proof that the display is fully configured, and
    # retry the final operation during the same bounded readiness window.
    for _ in {1..40}; do
        did="$(display_id)"
        if [[ "$did" == <-> ]] && (( did > 0 )); then
            apply_output="$(bd set -displayID="$did" -resolution="$resolution" \
                -hiDPI=off -main=on 2>&1)"
            apply_rc=$?
            if (( apply_rc == 0 )) && [[ "$apply_output" != *"Failed."* ]]; then
                /bin/echo "$did"
                return 0
            fi
        fi
        /bin/sleep 0.2
    done

    if [[ "$did" == <-> ]] && (( did > 0 )); then
        /bin/echo "BetterDisplay display $did never became ready for $resolution" >&2
        [[ -n "$apply_output" ]] && /bin/echo "$apply_output" >&2
        return 6
    fi
    /bin/echo "BetterDisplay did not expose a displayID for '$VIRTUAL_NAME'" >&2
    return 7
}

restore() {
    local tag
    # Keep the physical framebuffer alive throughout the session; on teardown,
    # make it main before disconnecting only our dedicated virtual screen.
    if [[ "$PHYSICAL_TAG" == <-> ]]; then
        bd set -tagID="$PHYSICAL_TAG" -connected=on >/dev/null 2>&1 || true
        bd set -tagID="$PHYSICAL_TAG" -main=on >/dev/null 2>&1 || true
    fi
    tag="$(virtual_tag)"
    if [[ "$tag" == <-> ]]; then
        bd set -tagID="$tag" -connected=off >/dev/null 2>&1 || true
    fi
}

case "${1:-}" in
    ensure)
        ensure_virtual_screen
        ;;
    prepare)
        [[ $# -eq 3 ]] || { /bin/echo "usage: $0 prepare WIDTH HEIGHT" >&2; exit 64; }
        prepare "$2" "$3"
        ;;
    restore)
        restore
        ;;
    status)
        /bin/echo "virtual_tag=$(virtual_tag)"
        /bin/echo "display_id=$(display_id)"
        ;;
    *)
        /bin/echo "usage: $0 {ensure|prepare WIDTH HEIGHT|restore|status}" >&2
        exit 64
        ;;
esac

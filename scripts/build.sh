#!/bin/zsh

# Build NativeMacRDP against a pinned, privately patched FreeRDP. Nothing is
# installed system-wide; all generated files stay below work/build-patched.

set -euo pipefail

repo_root="${0:A:h:h}"
build_root="${NATIVE_MAC_RDP_BUILD_ROOT:-$repo_root/work/build-patched}"
freerdp_version="3.30.0"
freerdp_archive="$build_root/freerdp-$freerdp_version.tar.gz"
freerdp_source="$build_root/FreeRDP-$freerdp_version"
freerdp_build="$build_root/freerdp-build"
freerdp_install="$build_root/freerdp-install"
daemon_build="$build_root/daemon-build"
freerdp_patch="$repo_root/patches/freerdp-3.30.0-macos-rdp-udp.patch"
quality_patch="$repo_root/patches/freerdp-3.30.0-progressive-quality.patch"
expected_sha256="21b3f72bd688fcd1dbbef37b7129bfc9701906705572fce2a5a80b1e85ecc0ee"

cmake_bin="${commands[cmake]:-}"
ctest_bin="${commands[ctest]:-}"
brew_bin="${commands[brew]:-}"
[[ -n "$cmake_bin" ]] || { /bin/echo "cmake is required" >&2; exit 1; }
[[ -n "$ctest_bin" ]] || { /bin/echo "ctest is required" >&2; exit 1; }
[[ -n "$brew_bin" ]] || { /bin/echo "Homebrew is required" >&2; exit 1; }
[[ -f "$freerdp_patch" ]] || { /bin/echo "missing patch: $freerdp_patch" >&2; exit 1; }
[[ -f "$quality_patch" ]] || { /bin/echo "missing patch: $quality_patch" >&2; exit 1; }

brew_prefix="${NATIVE_MAC_RDP_HOMEBREW_PREFIX:-$($brew_bin --prefix)}"
openssl_root="${OPENSSL_ROOT_DIR:-$($brew_bin --prefix openssl@3)}"
[[ -d "$openssl_root" ]] || { /bin/echo "missing OpenSSL: $openssl_root" >&2; exit 1; }

/bin/mkdir -p "$build_root"
if [[ ! -f "$freerdp_archive" ]]; then
    /usr/bin/curl --fail --location --retry 3 \
        "https://github.com/FreeRDP/FreeRDP/archive/refs/tags/$freerdp_version.tar.gz" \
        --output "$freerdp_archive"
fi

actual_sha256="$(/usr/bin/shasum -a 256 "$freerdp_archive" | /usr/bin/awk '{print $1}')"
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    /bin/echo "FreeRDP archive checksum mismatch" >&2
    /bin/echo "expected: $expected_sha256" >&2
    /bin/echo "actual:   $actual_sha256" >&2
    exit 1
fi

if [[ ! -d "$freerdp_source" ]]; then
    /usr/bin/tar -xzf "$freerdp_archive" -C "$build_root"
fi

if ! /usr/bin/grep -q "WTSVirtualChannelManagerStartSoftSync" \
        "$freerdp_source/include/freerdp/channels/wtsvc.h"; then
    /usr/bin/patch --forward -p1 -d "$freerdp_source" < "$freerdp_patch"
fi
if ! /usr/bin/grep -q "progressive_context_set_quantization" \
        "$freerdp_source/include/freerdp/codec/progressive.h"; then
    /usr/bin/patch --forward -p1 -d "$freerdp_source" < "$quality_patch"
fi

pkg_config_path="$brew_prefix/lib/pkgconfig:$openssl_root/lib/pkgconfig"
if [[ -n "${PKG_CONFIG_PATH:-}" ]]; then
    pkg_config_path="$pkg_config_path:$PKG_CONFIG_PATH"
fi
export PKG_CONFIG_PATH="$pkg_config_path"

"$cmake_bin" -S "$freerdp_source" -B "$freerdp_build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$freerdp_install" \
    -DCMAKE_OSX_ARCHITECTURES="$(/usr/bin/uname -m)" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTING=OFF \
    -DWITH_CLIENT=OFF \
    -DWITH_CLIENT_COMMON=OFF \
    -DWITH_SERVER=ON \
    -DWITH_PROXY=OFF \
    -DWITH_SERVER_CHANNELS=ON \
    -DWITH_CHANNELS=ON \
    -DWITH_OPENSSL=ON \
    -DOPENSSL_ROOT_DIR="$openssl_root" \
    -DWITH_FFMPEG=OFF \
    -DWITH_OPUS=OFF \
    -DWITH_X11=OFF \
    -DWITH_CUPS=OFF \
    -DWITH_PCSC=OFF \
    -DWITH_MANPAGES=OFF \
    -DWITH_SAMPLE=OFF

"$cmake_bin" --build "$freerdp_build" --parallel
"$cmake_bin" --install "$freerdp_build"

"$cmake_bin" -S "$repo_root" -B "$daemon_build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES="$(/usr/bin/uname -m)" \
    -DOPENSSL_ROOT_DIR="$openssl_root" \
    -DMACOS_RDP_STATIC=ON \
    -DFREERDP_STATIC_INSTALL="$freerdp_install" \
    -DMACOS_RDP_UDP_PATCHED_FREERDP=ON \
    -DBUILD_TESTING=ON

"$cmake_bin" --build "$daemon_build" --parallel
"$ctest_bin" --test-dir "$daemon_build" --output-on-failure

/bin/echo "NativeMacRDP ready: $daemon_build/macos-rdp-daemon"

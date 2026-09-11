cmake_minimum_required(VERSION 3.22)
project(macos-rdp-daemon LANGUAGES C CXX OBJC OBJCXX)

find_package(OpenSSL REQUIRED)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# When cross-compiling in CI the arch is passed explicitly; otherwise default
# to the host arch so local builds stay fast (no universal overhead).
if(NOT CMAKE_OSX_ARCHITECTURES)
    execute_process(COMMAND uname -m OUTPUT_VARIABLE HOST_ARCH
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(CMAKE_OSX_ARCHITECTURES "${HOST_ARCH}")
endif()
set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0")

# ── Build version stamping ────────────────────────────────────────────────
# Stamp the binary with the short Git SHA for diagnostics. Falls back to a UTC
# timestamp, then "dev", when Git is unavailable. CI may override the value
# with -DMACOS_RDP_BUILD_VERSION=<version>.
if(NOT MACOS_RDP_BUILD_VERSION)
    execute_process(
        COMMAND git rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE MACOS_RDP_BUILD_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
endif()
if(NOT MACOS_RDP_BUILD_VERSION)
    string(TIMESTAMP MACOS_RDP_BUILD_VERSION "dev-%Y%m%d%H%M%S" UTC)
endif()
message(STATUS "macos-rdp-daemon build version: ${MACOS_RDP_BUILD_VERSION}")

# ── Static vs dynamic FreeRDP ─────────────────────────────────────────────
option(MACOS_RDP_STATIC
       "Link FreeRDP/WinPR as static libraries (used in CI release builds)"
       OFF)
option(MACOS_RDP_UDP_PATCHED_FREERDP
       "Use the private FreeRDP bootstrap-cookie callback extension"
       OFF)

if(MACOS_RDP_STATIC)
    # CI passes -DFREERDP_STATIC_INSTALL=<path> pointing at the cmake-installed
    # FreeRDP tree built with BUILD_SHARED_LIBS=OFF.
    if(NOT FREERDP_STATIC_INSTALL)
        message(FATAL_ERROR "MACOS_RDP_STATIC=ON requires -DFREERDP_STATIC_INSTALL=<path>")
    endif()

    set(FREERDP_ROOT "${FREERDP_STATIC_INSTALL}")
    set(FREERDP_INCLUDE "${FREERDP_ROOT}/include/freerdp3")
    set(WINPR_INCLUDE   "${FREERDP_ROOT}/include/winpr3")

    # Collect all static libs from the install tree.
    file(GLOB_RECURSE FREERDP_STATIC_LIBS
         "${FREERDP_ROOT}/lib/*.a"
         "${FREERDP_ROOT}/lib64/*.a")

    # OpenSSL static libs must come after FreeRDP on the link line.
    if(OPENSSL_ROOT_DIR)
        file(GLOB OPENSSL_STATIC_LIBS
             "${OPENSSL_ROOT_DIR}/lib/libssl.a"
             "${OPENSSL_ROOT_DIR}/lib/libcrypto.a")
    endif()

    # FreeRDP's static archives do not carry their private dependency link
    # line. Resolve the small set enabled in our private server build while
    # keeping FreeRDP/WinPR themselves isolated from Homebrew's shared copy.
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(FREERDP_STATIC_DEPS REQUIRED IMPORTED_TARGET
        libswscale libavutil liburiparser jansson)

    set(FREERDP_LINK_LIBS
        ${FREERDP_STATIC_LIBS}
        ${OPENSSL_STATIC_LIBS}
        PkgConfig::FREERDP_STATIC_DEPS
        z   # zlib — always present on macOS
    )
else()
    find_package(PkgConfig REQUIRED)
    # The daemon uses the server-side WTS/channel implementation in addition to
    # the core protocol library. Homebrew does not link that transitively, so
    # request the server pkg-config module explicitly and preserve its libdir.
    pkg_check_modules(FREERDP_SERVER REQUIRED freerdp-server3)
    pkg_check_modules(WINPR          REQUIRED winpr3)
    set(FREERDP_INCLUDE "${FREERDP_SERVER_INCLUDE_DIRS}")
    set(WINPR_INCLUDE   "${WINPR_INCLUDE_DIRS}")
    set(FREERDP_LINK_LIBS ${FREERDP_SERVER_LIBRARIES} ${WINPR_LIBRARIES})
endif()

# ── Target ────────────────────────────────────────────────────────────────
add_executable(macos-rdp-daemon
    logging/RDPLog.c
    daemon/main.m
    daemon/RDPServer.m
    daemon/RDPSession.m
    daemon/Authenticator.m
    daemon/DisplayControl.m
    daemon/FileProvider/RDPFileProvider.m
    protocol/RDPPeer.c
    protocol/RDPClientLiveness.c
    protocol/RDPTCPLatency.c
    protocol/RDPProgressiveQuality.c
    protocol/RDPUDPProbe.m
    protocol/RDPUDP2.c
    protocol/RDPUDPBootstrap.c
    protocol/RDPEMT.c
    protocol/RDPWebDAV.c
    protocol/RDPDriveMount.m
    display/VirtualDisplay.m
    display/ScreenCapture.m
    display/FrameEncoder.m
    display/CursorCapture.m
    input/InputInjector.m
    input/RDPCursorPositionPolicy.c
    input/RDPScroll.c
    input/ClipboardSync.m
    audio/AudioCapture.m
    audio/AudioInput.m
    audio/AudioRedirect.c
)

if(NOT MACOS_RDP_STATIC)
    target_link_directories(macos-rdp-daemon PRIVATE
        ${FREERDP_SERVER_LIBRARY_DIRS}
        ${WINPR_LIBRARY_DIRS}
    )
endif()

target_include_directories(macos-rdp-daemon PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${FREERDP_INCLUDE}
    ${WINPR_INCLUDE}
    # Static build: FreeRDP installs headers under include/freerdp3 and include/winpr3
    $<$<BOOL:${MACOS_RDP_STATIC}>:${FREERDP_STATIC_INSTALL}/include>
)

target_link_libraries(macos-rdp-daemon PRIVATE
    ${FREERDP_LINK_LIBS}
    OpenSSL::SSL
    OpenSSL::Crypto
    "-framework Foundation"
    "-framework CoreGraphics"
    "-framework CoreVideo"
    "-framework VideoToolbox"
    "-framework CoreMedia"
    "-framework ScreenCaptureKit"
    "-framework CoreAudio"
    "-framework AudioToolbox"
    "-framework AppKit"
    "-framework ApplicationServices"
    "-framework OpenDirectory"
    "-framework IOKit"
    "-framework IOSurface"
    "-framework Security"
    # FileProvider: NSFileProviderDomain / NSFileProviderManager for RDPDR drive mounting.
    # Available since macOS 12; deployment target is 14.0 so no weak-link needed.
    "-framework FileProvider"
    pam
)

target_compile_options(macos-rdp-daemon PRIVATE
    -fobjc-arc
    -Os
    -Wall -Wextra -Wno-unused-parameter
)

# Raw datagram-preserving reverse relay used by the isolated RDPUDP2 endpoint.
# It intentionally remains a separate process so its public/tunnel sockets and
# credentials cannot affect the established TCP RDP service.
add_executable(rdp-udp-relay relay/rdp_udp_relay.c)
target_compile_options(rdp-udp-relay PRIVATE -O2 -Wall -Wextra -Werror)

# Link-time optimisation — dead-strips unused code across translation units.
set_property(TARGET macos-rdp-daemon PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

# ── Protocol tests ───────────────────────────────────────────────────────
# These are pure-C, network-free tests for the UDP2 reliability layer and
# RDPEMT stream framing.  Keeping them independent from FreeRDP makes packet
# compatibility failures reproducible before a live iPad session is involved.
include(CTest)
if(BUILD_TESTING)
    add_executable(rdp-udp-protocol-tests
        tests/test_udp_protocol.c
        protocol/RDPUDP2.c
        protocol/RDPUDPBootstrap.c
        protocol/RDPEMT.c
    )
    target_include_directories(rdp-udp-protocol-tests PRIVATE ${CMAKE_SOURCE_DIR})
    target_compile_options(rdp-udp-protocol-tests PRIVATE
        # The test harness deliberately uses assert() as its fail-fast check.
        # Release/MinSizeRel normally define NDEBUG, which would erase every
        # check and even turn their inputs into unused-variable build errors.
        -UNDEBUG -Wall -Wextra -Werror
    )
    add_test(NAME rdp-udp-protocol COMMAND rdp-udp-protocol-tests)

    add_executable(rdp-tcp-latency-tests
        tests/test_tcp_latency.c
        protocol/RDPTCPLatency.c
    )
    target_include_directories(rdp-tcp-latency-tests PRIVATE ${CMAKE_SOURCE_DIR})
    target_compile_options(rdp-tcp-latency-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Werror
    )
    add_test(NAME rdp-tcp-latency COMMAND rdp-tcp-latency-tests)

    add_executable(rdp-client-liveness-tests
        tests/test_client_liveness.c
        protocol/RDPClientLiveness.c
    )
    target_include_directories(rdp-client-liveness-tests PRIVATE
        ${CMAKE_SOURCE_DIR})
    target_compile_options(rdp-client-liveness-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Werror
    )
    add_test(NAME rdp-client-liveness COMMAND rdp-client-liveness-tests)

    add_executable(rdp-scroll-tests
        tests/test_scroll.c
        input/RDPScroll.c
    )
    target_include_directories(rdp-scroll-tests PRIVATE ${CMAKE_SOURCE_DIR})
    target_compile_options(rdp-scroll-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Werror
    )
    add_test(NAME rdp-scroll COMMAND rdp-scroll-tests)

    add_executable(rdp-cursor-position-policy-tests
        tests/test_cursor_position_policy.c
        input/RDPCursorPositionPolicy.c
    )
    target_include_directories(rdp-cursor-position-policy-tests PRIVATE
        ${CMAKE_SOURCE_DIR})
    target_compile_options(rdp-cursor-position-policy-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Werror
    )
    add_test(NAME rdp-cursor-position-policy
             COMMAND rdp-cursor-position-policy-tests)

    add_executable(rdp-progressive-quality-tests
        tests/test_progressive_quality.c
        protocol/RDPProgressiveQuality.c
    )
    target_include_directories(rdp-progressive-quality-tests PRIVATE
        ${CMAKE_SOURCE_DIR})
    target_compile_options(rdp-progressive-quality-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Werror
    )
    add_test(NAME rdp-progressive-quality COMMAND rdp-progressive-quality-tests)

    if(MACOS_RDP_UDP_PATCHED_FREERDP)
        add_executable(rdp-progressive-quantization-tests
            tests/test_progressive_quantization.c
        )
        target_include_directories(rdp-progressive-quantization-tests PRIVATE
            ${CMAKE_SOURCE_DIR}
            ${FREERDP_INCLUDE}
            ${WINPR_INCLUDE}
            ${FREERDP_STATIC_INSTALL}/include
        )
        target_link_libraries(rdp-progressive-quantization-tests PRIVATE
            ${FREERDP_LINK_LIBS}
            OpenSSL::SSL
            OpenSSL::Crypto
            "-framework Foundation"
            "-framework CoreFoundation"
            "-framework Security"
            z
        )
        target_compile_options(rdp-progressive-quantization-tests PRIVATE
            -UNDEBUG -Wall -Wextra -Werror
        )
        add_test(NAME rdp-progressive-quantization
                 COMMAND rdp-progressive-quantization-tests)
    endif()

    add_executable(rdp-udp-relay-integration-tests
        tests/test_udp_relay_integration.c
    )
    target_compile_options(rdp-udp-relay-integration-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Werror
    )
    add_test(NAME rdp-udp-relay-integration
             COMMAND rdp-udp-relay-integration-tests
                     $<TARGET_FILE:rdp-udp-relay>)
    set_tests_properties(rdp-udp-relay-integration PROPERTIES TIMEOUT 25)
endif()

# MACOS_RDP_VIRTUAL_DISPLAY: create a CGVirtualDisplay sized to the RDP client
# (no pillarbox / 1:1 input). Falls back to the main display if the private API fails.
# ── Feature flags ─────────────────────────────────────────────────────────
# RDP_RDPDR_ENABLED: compile-in the RDPDR drive-redirection channel handler.
# Default OFF — the feature is new and unverified on hardware. Enable at
# runtime with the env-var RDP_RDPDR_ENABLED=1 (checked at peer-connect time).
option(RDP_RDPDR_ENABLED
       "Include MS-RDPEFS (rdpdr) drive-redirection channel handler"
       OFF)

target_compile_definitions(macos-rdp-daemon PRIVATE
    MACOS_RDP_VERSION="0.1.0-dev"
    MACOS_RDP_BUILD_VERSION="${MACOS_RDP_BUILD_VERSION}"
    MACOS_RDP_VIRTUAL_DISPLAY=1
    $<$<BOOL:${MACOS_RDP_UDP_PATCHED_FREERDP}>:MACOS_RDP_UDP_PATCHED_FREERDP=1>
)

# ── Install ───────────────────────────────────────────────────────────────
install(TARGETS macos-rdp-daemon DESTINATION /usr/local/sbin)

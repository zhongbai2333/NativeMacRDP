# Third-party notices

NativeMacRDP is distributed under the [MIT License](LICENSE) and retains the
copyright notice and Git history of the MIT-licensed
[`grioghar/macos-rdp-server`](https://github.com/grioghar/macos-rdp-server)
project from which it is derived.

The build downloads and statically links
[`FreeRDP`](https://github.com/FreeRDP/FreeRDP) 3.30.0, with the in-tree patches
under [`patches`](patches). FreeRDP and WinPR are licensed under Apache License
2.0. A copy is included at [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).
Redistributors of NativeMacRDP binaries must preserve all notices required by
that license.

BetterDisplay is an external runtime dependency for the tested virtual-screen
path. It is not copied, linked, or redistributed by this repository; obtain it
separately under its own license and terms.

Apple frameworks are supplied by macOS and the Xcode SDK and are not included
in this repository.

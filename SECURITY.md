# Security Policy

## Project status

NativeMacRDP is pre-release software and currently supports only the latest
`main` branch. No release is considered production-hardened.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting flow:

<https://github.com/zhongbai2333/NativeMacRDP/security/advisories/new>

Do not include exploit details, credentials, server addresses, certificates, or
unredacted logs in a public issue. A useful report includes the affected commit,
client and macOS versions, reachable transport, impact, and minimal reproduction
steps. You can expect an initial acknowledgement within seven days, but there is
currently no guaranteed support or remediation SLA.

## Deployment assumptions

- The default installer binds to `127.0.0.1`. Treat a non-loopback bind as an
  explicit trust decision.
- TLS is enabled, but Network Level Authentication is not implemented. Do not
  expose the RDP listener directly to the public Internet. Prefer a VPN or an
  authenticated, encrypted tunnel and restrict the endpoint with a firewall.
- Keep `RDP_ALLOW_NO_AUTH` unset. Setting it to `1` disables macOS account
  authentication and is intended only for isolated development.
- The generated RDP private key, signing material, tunnel tokens, and LaunchAgent
  configuration are local runtime state. Never commit or share them.
- Clipboard, file-transfer, audio, drive, AVC, and UDP paths increase attack
  surface. Optional channels are disabled by default and should be enabled one
  at a time only when needed.
- The server controls the currently logged-in Aqua session. It is not a secure
  login-window or multi-user isolation boundary.
- BetterDisplay and undocumented macOS APIs are outside this project's control
  and may change behavior after an update.

Self-signed RDP certificates protect the transport only when the client verifies
the expected certificate. Accepting a changed certificate without checking its
fingerprint permits interception by an attacker who can reach the connection
path.

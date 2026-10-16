# Security policy

## Supported versions

We correct security problems on `main`. The next release contains the correction.
Use the latest release.

## Deployment

`ghidra-mcp` gives its clients full read and write access to the binaries and the Ghidra projects that it opens.
It also starts Ghidra for them.
For this reason, access to the daemon is the same as access to the analysis data of your user account.

- **Keep the daemon on loopback.** `--listen` accepts only loopback addresses.
  The daemon does not authenticate MCP clients.
  For remote access, put a TLS reverse proxy with authentication in front of `http://127.0.0.1:<port>/mcp` and `/upload`.
- **Treat browser access to `/mcp` as trusted access.** For client compatibility,
  `/mcp` accepts any valid HTTP or HTTPS Origin. Thus, a web page can call the
  local MCP endpoint while the daemon runs. Do not use untrusted web pages at
  the same time, or put a proxy with authentication in front of the endpoint.
- **Do not share the runtime directory or the persistent home** with other users.
  The daemon does not start with a runtime directory that is not private to the current user.
- **Think of the analyzed binaries as hostile input to Ghidra.**
  `ghidra-mcp` does not execute them. But it uses Ghidra to read them.
  For hostile files, run Ghidra in an isolated environment.

[docs/architecture.md](docs/architecture.md#security-model) describes the protections of the daemon.

## Report a vulnerability

Report a vulnerability privately. Do not report it in a public issue.
Use one of these methods:

- The GitHub [private vulnerability report](https://github.com/ByteLandTechnology/ghidra-mcp/security/advisories/new) form.
- An email to `github@byteland.app`.

Give the affected version, your platform, the steps to reproduce the problem, and its effect.
Do not include real credentials or sensitive program data.

The maintainers answer as soon as possible. They tell you about the correction.
The advisory gives your name, if you agree.

For a vulnerability in the Java bridge, use the [ghidra-bridge security policy](https://github.com/ByteLandTechnology/ghidra-bridge/security).

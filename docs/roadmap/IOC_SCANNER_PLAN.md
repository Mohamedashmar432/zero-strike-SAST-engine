# IOC scanner

Planned 8 November 2026. Planner: Opus 5.5. Builder: Sonnet 5.5.

## What it is

An indicator-of-compromise (IOC) scanner looks for signs that a repository has already been tampered with or carries
malicious code, rather than for weaknesses a developer wrote by mistake. SAST asks "could an attacker exploit this?"; the
IOC scanner asks "has an attacker already been here?". Typical targets are supply-chain attacks (a dependency or install
script that downloads and runs code), planted backdoors and web shells, crypto miners, and code that ships credentials
to a collection endpoint.

## Scope

Offline and deterministic. No new network calls: the only live data is what SCA already fetches from OSV. Off by default,
enabled with `--enable-ioc`, so existing scans and CI gates are unchanged.

| Rule | Detects | Where | Severity |
|---|---|---|---|
| ZS-IOC-001 | Install-time hook that downloads or runs remote code, or runs a credential harvester: `preinstall`, `install`, `postinstall`, `prepare` in `package.json`; `setup.py` install commands; `composer.json` `post-install-cmd`/`post-update-cmd`. Fires on `curl`, `wget`, `Invoke-WebRequest`/`iwr`, `node -e`/`python -c` with an encoded argument, piping to `sh`/`bash`/`powershell`, or `trufflehog`/`gitleaks` invoked from an install hook. A local build step (`tsc`, `node-gyp rebuild`, `husky install`) does not fire. | Manifests | Critical |
| ZS-IOC-002 | Encoded payload executed: `eval`, `exec`, `Function`/`new Function`, `assert`, `create_function` or `vm.runIn*Context` applied to `atob`, `Buffer.from(…, 'base64'|'hex')`, `base64_decode`, `gzinflate`, `gzuncompress`, `str_rot13`, `b64decode`, `zlib.decompress`, `marshal.loads`, with a literal argument of 200 or more characters, or nested decode chains. | JS, TS, PHP, Python | High |
| ZS-IOC-003 | Classic web shell: request data passed straight to `eval`, `assert`, `system`, `passthru`, `shell_exec` or `preg_replace` with `/e` in a file that is short (under 60 lines) or has no other functions. One-line shapes such as `<?php @eval($_POST['x']);?>`. | PHP, ASP/ASPX, JSP | Critical |
| ZS-IOC-004 | Reverse shell: `/dev/tcp/` redirection, `nc -e`/`ncat -e`, `socat … exec:`, `bash -i >&`, Python `socket` + `pty.spawn`/`subprocess` with `dup2`, PowerShell `Net.Sockets.TCPClient` with a stream loop. | Scripts, Dockerfiles, any source | Critical |
| ZS-IOC-005 | Crypto mining: `stratum+tcp://`, `stratum+ssl://`, `stratum2+tcp://` pool URLs, `xmrig`/`minerd`/`cpuminer` binaries or configs, `"donate-level"` with `"pools"`. | Any text file | High |
| ZS-IOC-006 | Exfiltration endpoint in shipped code: `webhook.site`, `*.ngrok.io`/`*.ngrok-free.app`, `*.pipedream.net`, `requestbin`, `*.oast.*`/`interact.sh`, `burpcollaborator.net`, Discord or Telegram bot webhooks, used as a request target. Test, fixture and docs paths do not fire. | Source | Medium |
| ZS-IOC-007 | Organization IOC feed match: `--ioc-feed <file>` with one indicator per line, `domain:`, `ip:`, `url:` or `sha256:`. Domains, IPs and URLs match string literals and config values; `sha256:` matches the hash of any scanned file. Lines starting with `#` are comments. | Any file | Critical |
| ZS-IOC-008 | GitHub Actions workflow using an action version with a published compromise and no pinned commit SHA. Initial data, each with its advisory: `tj-actions/changed-files` (CVE-2025-30066), `reviewdog/action-setup` (CVE-2025-30154). Entries live in a data file and every entry must cite an advisory id. | `.github/workflows/*.yml` | High |

Known malicious packages are already reported by SCA, because OSV includes the OpenSSF malicious-packages records
(advisory ids beginning `MAL-`). SCA marks those findings Critical and adds `Metadata["ioc"] = "malicious-package"`, so
they appear in the IOC summary without a second lookup.

## Design

- New package `internal/scanner/ioc` implementing the existing `Scanner` interface, registered next to secrets and SCA.
  Rules 001 to 006 and 008 are coded matchers over file text or parsed manifests (no taint analysis needed); their data
  (domains, action list, decoder names) lives in embedded YAML so it can change without code.
- Findings use a new `FindingKind` value `ioc` and category `indicator-of-compromise`, with CWE-506 (embedded malicious
  code) or CWE-912 (hidden functionality) as appropriate. No existing report key moves; `TestReportLayoutContract` must
  stay green. The JSON report summary gains an additive `ByKind` count for `ioc`.
- Test, vendor, `node_modules` and documentation paths are excluded for 002, 004, 005 and 006, except when the match is
  inside an install hook or a workflow.
- The portal accepts `kind: "ioc"` before any build that emits it is released (backend `Literal` and the frontend kind
  label), so an IOC-enabled CI upload never fails ingestion.

## Measurement

1. Corpus: `benchmark/corpus/ioc/` with at least five positive and five negative cases per rule (for example a
   `postinstall` running `node-gyp rebuild` must not fire, a `postinstall` piping `curl` into `sh` must). Positive samples
   are written as inert fixtures: shapes only, non-routable hosts (`attacker.invalid`), no working payloads.
2. False-alarm check: the 32 RealVuln applications and the seven labeled applications contain no planted IOCs, so every
   IOC finding there is reviewed by hand. Target: zero, and at most two that are defensible (a vulnerable training app
   that deliberately includes a web shell counts as a true indicator).
3. Gates: internal corpus at 0 false positives and 0 misses, `go test ./...`, `TestReportLayoutContract`.

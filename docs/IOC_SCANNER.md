# IOC scanner

The indicator-of-compromise scanner looks for signs that a repository already carries malicious code, rather than for
weaknesses a developer wrote by mistake. SAST asks whether an attacker could exploit the code; this scanner asks whether
an attacker has already been here. It is offline and deterministic: it makes no network calls of its own. Findings have
`Kind` `ioc`, category `indicator-of-compromise` and CWE-506 (embedded malicious code) or CWE-912 (hidden functionality).

## Flags

`--enable-ioc` turns the scanner on. It is off by default, so a scan that does not pass the flag produces no `ioc`
findings and its output is unchanged. `--ioc-feed <file>` supplies an organisation indicator feed for ZS-IOC-007 and
requires `--enable-ioc`; passing a feed without the flag is an error rather than being silently ignored.

## What it detects

Each rule is a tight textual or manifest shape. Test, fixture, documentation, vendor and `node_modules` paths are skipped
by rules 002, 004, 005 and 006 (and the walker already skips vendor and `node_modules`); rules 001 and 008 apply wherever
the manifest or workflow is.

ZS-IOC-001 (Critical, CWE-506) flags an install hook that fetches or runs remote code. Hooks are `preinstall`, `install`,
`postinstall` and `prepare` in `package.json`, install commands in `setup.py`, and `post-install-cmd` and
`post-update-cmd` in `composer.json`. It fires on `curl`, `wget` or `Invoke-WebRequest` with a URL, on piping into
`sh`, `bash` or PowerShell, on `node -e` or `python -c` with an encoded argument, on an encoded PowerShell command, and on
`trufflehog` or `gitleaks` run from the hook. `node-gyp rebuild`, `husky install`, `tsc` and `node scripts/x.js` do not
fire, and the scanner does not follow a hook into the script file it runs.

ZS-IOC-002 (High, CWE-506) flags an encoded payload given to an executor: `eval`, `exec`, `Function`, `assert`,
`create_function` or `vm.runIn*Context` applied to a decoder (`atob`, `Buffer.from` with base64 or hex, `base64_decode`,
`gzinflate`, `gzuncompress`, `str_rot13`, `b64decode`, `zlib.decompress`, `marshal.loads`) with literals totalling 200
characters or more, or to a chain of two or more decoders. The two-step form (a variable assigned a decoded long literal,
then executed) is also matched. Member calls such as `re.exec(...)` and `child_process.exec(...)` are not executors.
Applies to JS, TS, PHP and Python.

ZS-IOC-003 (Critical, CWE-912) flags a classic web shell in PHP, ASP/ASPX or JSP: request data passed directly to `eval`,
`assert`, `system`, `passthru`, `shell_exec`, `exec` or a `preg_replace` `/e` pattern, or a variable function called with
request data. For command functions the request value must be the command, not a part of a longer one. Only files under 60
non-empty lines, or that declare no functions, are considered, so a shell hidden in a large application is a known miss.

ZS-IOC-004 (Critical, CWE-912) flags a reverse shell: an interactive shell with `/dev/tcp` redirection, `nc -e` or
`ncat -e`, `mkfifo` piped through a shell and `nc`, `socat` with `exec:` and a TCP address, a Python socket with
`pty.spawn` or `dup2` plus a shell launch, or a PowerShell `TCPClient` stream executed with `iex`. `/dev/tcp` port checks
and `nc -z` probes do not fire.

ZS-IOC-005 (High, CWE-506) flags crypto mining: `stratum+tcp`, `stratum+ssl` and `stratum2+tcp` pool URLs, `xmrig`,
`minerd` or `cpuminer` run with pool arguments, an xmrig release download, `chmod +x` on a miner binary, or a miner
config with `donate-level` and `pools`.

ZS-IOC-006 (Medium, CWE-912) flags an exfiltration or request-capture endpoint written as a URL literal in source:
webhook.site, ngrok, pipedream, requestbin, interact.sh, oast hosts, burpcollaborator.net, and Discord and Telegram bot
endpoints. The URL must be inside a string literal (or be a bare argument in a shell script); comment lines, config and
markup files do not fire. Bot tokens are redacted from the evidence.

ZS-IOC-007 (Critical, CWE-506) matches the organisation feed, described below.

ZS-IOC-008 (High, CWE-506) flags a workflow `uses:` line for an action with a published compromise whose ref is not a
40-character commit SHA. The list is `compromised_actions` in `internal/scanner/ioc/data/ioc.yaml`; every entry must cite
an advisory id (a test enforces it). It holds `tj-actions/changed-files` (CVE-2025-30066) and `reviewdog/action-setup`
(CVE-2025-30154).

SCA is related: OSV includes the OpenSSF malicious-packages records (advisory ids starting `MAL-`). When `--enable-sca`
reports one, the finding is Critical and carries `Metadata["ioc"] = "malicious-package"`. It stays an `sca` finding.

## Feed file format

One indicator per line; blank lines and lines starting with `#` are ignored.

    domain:evil.example
    ip:203.0.113.7
    url:https://evil.example/payload.sh
    sha256:<64 hex digits>

A domain matches the host itself and its subdomains, not a longer name (`evil.example.org`) or a name that merely ends
the same way (`notevil.example`). Domains, IPs and URLs match inside string literals, URLs and configuration values.
`sha256:` matches the hash of any scanned file. A malformed line, an unknown prefix or an unreadable file fails the scan
at startup, because silently dropping an indicator would read as a clean result. The feed file itself is never matched
against.

## Limits

The scanner reads text. It does not follow a hook into a script file, does not decode payloads to inspect them, and does
not detect a web shell inside a large file with many functions. Files the walker skips (binary extensions such as `.exe`
and `.zip`, files over 1 MB, minified JS) are never seen, so a feed hash cannot match them. The feed check does a
substring search per indicator and per file, which is fine for feeds of thousands of entries and not designed for
millions. Findings are indicators for human review, not verdicts; rules 005 and 006 in particular can describe a
legitimate but unusual use (a mining pool client library, a Discord notification), which is why they are not Critical.

Corpus fixtures under `benchmark/corpus/ioc/` are inert shapes: hosts are `.invalid`, filler payloads decode to repeated
`ABC`, and the PHP, ASP and JSP web-shell samples omit the opening tag so no server would execute them. Endpoint
antivirus may still flag the shell shapes on disk.

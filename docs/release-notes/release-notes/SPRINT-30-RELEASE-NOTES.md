# Sprint 30 Release Notes — v0.23.0

## Summary

A pure release-infrastructure sprint, triggered by the `zero-strike-portal`
web scan flagging that this repo had never shipped a single release binary:
no goreleaser config, no CI job building for any OS (not even macOS, ever),
and a hardcoded `Version` constant instead of one tied to git tags. No
detection rules changed this sprint; benchmark corpus is unchanged from
Sprint 28's 140/0/0.

Real detection needs `CGO_ENABLED=1` (tree-sitter grammars are CGo — a
`CGO_ENABLED=0` build registers zero parsers and silently finds nothing,
the same failure mode already documented across several prior sprints'
QA incidents). That rules out cross-compiling Windows/macOS binaries from
one Linux runner, so this sprint builds natively on one runner per OS.

## Repo identity reconciled

`go.mod`'s module path (`github.com/zerostrike/scanner`) never matched the
actual GitHub remote (`Mohamedashmar432/zero-strike-SAST-engine`) — nothing
in the codebase ever cross-referenced the two. Renamed the module path to
match the real remote: `go.mod`, `Makefile`'s `MODULE` var, and the import
prefix in all 122 `.go` files that import an `internal/...` package
(mechanical, one literal string, verified by `go build ./...` failing
loudly on any missed site — none were). This also makes the sibling
`zero-strike-portal` repo's `backend/Dockerfile` `SCANNER_REPO` build arg
(already pointing at the real remote) correct with zero changes needed on
that side.

## Tag-driven version injection

`internal/version.Version` was `const Version = "v0.22.0"` — a `const`
can never be overridden by `-ldflags -X`, only a `var` can. Changed to
`var Version = "dev"`, defaulting to `"dev"` for local/untagged builds and
overridden at release-build time via
`-ldflags "-X .../internal/version.Version=$TAG"`. No caller changed
(`main.go`'s `--version` wiring, `upload.go`/`scan.go`'s portal payloads,
`zerostrike-bench`, and the pipeline cache's `EngineVersion` all reference
`version.Version` by name and don't care that it's now a `var`). Also fixed
`Makefile`'s `build-release` target, which had been silently dead since it
was written — it pointed `-X` at `main.version`, a symbol that has never
existed (the real one lives in `internal/version`, and was a `const`
besides).

## New: `.goreleaser.yml`

Five CGO-enabled build targets — `linux/amd64`, `linux/arm64`,
`windows/amd64`, `darwin/amd64`, `darwin/arm64` — each with its own `CC`
where cross-arch needs one (`aarch64-linux-gnu-gcc` for `linux/arm64`;
Windows/macOS builds run natively so no override needed). `archives:
format: binary` skips tar/zip wrapping entirely, naming each binary
`zerostrike_{os}_{arch}` (goreleaser appends `.exe` for Windows
automatically) plus a `checksums.txt`.

## New: `.github/workflows/release.yml` (additive — `ci.yml` untouched)

Triggered on `v*.*.*` tag pushes. One native-runner build job per OS —
`ubuntu-latest` (installs `gcc-aarch64-linux-gnu` via apt for the arm64
cross build), `windows-latest` (explicit MinGW-w64 setup via
`egor-tensin/setup-mingw`, so `gcc` is on `PATH` before the build — no CGO
build has ever run on Windows in this project's CI before this sprint),
and `macos-latest` (no extra setup — Xcode's bundled clang already
supports both `amd64`/`arm64` via `-arch`) — then a final job that
merges all three and publishes the release.

**Real finding, not assumed:** GoReleaser's "Split & Merge" feature —
built for exactly this "native build on N machines, merge into one
release" scenario — turned out to be gated to GoReleaser Pro, confirmed
by fetching `goreleaser.com/cookbooks/cgo-and-crosscompiling/` directly
rather than trusting a half-remembered CLI flag. The two OSS-tier
alternatives that doc page does list (Docker cross-compiler images, using
Zig as the C compiler) both cross-compile from a single host, which this
task's own constraint already ruled out. Worked around it: each OS job
runs only `goreleaser build --id <target> --clean` (an OSS-tier command,
just the build pipe, no merge needed), and the final job skips
goreleaser's release/publish pipe entirely — it downloads all five
binaries, runs `sha256sum` itself for `checksums.txt`, and publishes via
`gh release create`. Functionally identical end result (one GitHub
Release, five named binaries, one checksums file); the only cost is
goreleaser doesn't orchestrate the last step. Documented as the upgrade
path if this project ever buys Pro: swap the final job for
`goreleaser continue --merge`.

## Cleanup: tracked build artifacts

`git ls-files` showed three ad hoc compiled binaries committed by
accident over time — `zerostrike-new.exe`, `zerostrike-bench.exe`,
`zerostrike-cgo-disabled.exe` (added in commit `8343b23`, one re-added in
`c775dab`). `.gitignore` only ever covered the canonical `/zerostrike.exe`
name, not these. Untracked all three via `git rm --cached` (kept on disk),
and broadened `.gitignore`'s rule from `/zerostrike.exe` to `/*.exe` so
this can't silently recur.

## Verification

- `go build ./...` / `go vet ./...` — clean, confirms all 122 import-path
  rewrite sites resolved correctly (a missed one would have failed the
  build immediately, not silently).
- `CGO_ENABLED=0 go test ./... -count=1` — clean, every package.
- `git diff --stat .github/workflows/ci.yml` — empty, confirming the
  existing lint/test/scan-e2e/accuracy/cache-perf workflow is untouched.

## QA: how to test the release pipeline end-to-end

This sprint's actual payoff (a tagged push producing five real binaries)
can't be verified without pushing a real tag, which wasn't done as part
of this sprint — that's a shared, hard-to-reverse action (triggers real
GitHub Actions runners across three OSes and creates a public-facing
GitHub Release) and needs sign-off first. To QA it:

1. Push a throwaway tag, e.g. `git tag v0.23.0-rc1 && git push origin v0.23.0-rc1`.
2. Watch the `release` workflow run in the Actions tab — four jobs
   (`build-linux`, `build-windows`, `build-macos`, `release`) should all
   go green.
3. Confirm the resulting GitHub Release has exactly five binaries
   (`zerostrike_linux_amd64`, `zerostrike_linux_arm64`,
   `zerostrike_windows_amd64.exe`, `zerostrike_darwin_amd64`,
   `zerostrike_darwin_arm64`) plus `checksums.txt`.
4. Download one binary (ideally the Windows one, since that's the OS
   this project has never successfully CGO-built in CI before) and run
   `zerostrike --version` — should print the pushed tag, not `dev`.
5. `sha256sum -c checksums.txt` against the downloaded binaries to
   confirm they match.
6. Delete the throwaway tag and its Release afterward if this was only a
   dry run.

Locally, without pushing anything: `go build -ldflags "-X
github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/version.Version=v0.23.0-test"
-o zerostrike-test ./cmd/zerostrike/` then `./zerostrike-test --version`
confirms the `-X` injection itself works, independent of CI.

## Deferred / out of scope (documented, not silently dropped)

- The `zero-strike-portal` repo's `backend/Dockerfile` lives outside this
  repo and wasn't touched — already correct once this repo's module path
  agrees with the real remote (see above).
- Wiring CI to auto-upload release artifacts to the portal's `POST
  /api/v1/admin/downloads/zerostrike` endpoint — confirmed that endpoint
  doesn't exist yet in this repo's client code at all; stays a manual
  per-release upload for now.
- `internal/scanner/sca/osv.go`'s hardcoded `userAgent =
  "zerostrike/0.5.0"` — a separate, pre-existing version-drift bug found
  while auditing every `version.Version` call site this sprint, but out
  of scope for a release-pipeline task; left untouched.

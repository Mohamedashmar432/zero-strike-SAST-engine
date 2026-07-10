# Sprint 29 Release Notes — v0.22.0

## Summary

A pure engine-capability sprint — no new detection rules. A sibling repo,
`zero-strike-portal` (Next.js + FastAPI + MongoDB), is being built to
orchestrate ZeroStrike scans in three modes for end users: local (a user
runs the CLI with a project token), CI/CD (a pipeline runs the identical
CLI command), and cloud (the portal backend clones a repo into an isolated
location, scans it, then destroys the clone). All three are mechanically
identical from the engine's point of view — this sprint implements the one
client-side contract that unlocks all three; which mode triggered a given
run is entirely the portal's concern, not the engine's.

The portal repo's own architecture doc (`docs/ZeroStrike_Phase1_Architecture_and_Engineering_Plan.md`
in that repo, §5) already specified the exact contract as a hand-off,
written after reading this repo's real `scan.go`/`report.go`/`json.go`. This
sprint implements that spec. Scope was deliberately kept to this repo only —
the portal's own real backend endpoints (its "Sprint 3," currently
mock-only) are a separate, later, parallel track in that repo.

## New: `zerostrike scan` upload mode

Four new flags, all additive and all-or-nothing: `--server`, `--token`,
`--project-id`, `--scan-label`. Passing none of them behaves exactly as
before — v0.22.0 is fully backward compatible with every existing `scan`
invocation. Passing only some of the three required ones (`--server`,
`--token`, `--project-id`) is now a fail-fast flag-validation error, on the
theory that a partial set is almost always a forgotten flag.

When all three are set:

1. Before the pipeline runs, the scanner calls `POST /api/v1/scans` on the
   portal with the project token as a Bearer credential. A 401 (invalid,
   expired, or revoked token) makes the scanner exit immediately with code
   `2`, *without running the scan* — there's no point spending the time on a
   report nobody authenticated to receive.
2. The scan pipeline runs completely unchanged — no network during
   scanning.
3. The local `--output` file (or stdout) is written exactly as before,
   completely unaffected by anything upload-related.
4. The JSON report is then uploaded via `POST /scans/{id}/upload/json`,
   forced to `GroupBy: none` regardless of the `--group-by` flag (which
   still applies to the local file) — the portal's ingestion expects a flat
   `Findings` array, not the grouped shape. The HTML report is also
   generated and uploaded via `POST /scans/{id}/upload/html`, best-effort —
   per the portal's contract, only the JSON upload flips a scan's status,
   so an HTML failure only warns.
5. If the pipeline itself fails while in upload mode, the scanner
   best-effort reports `status: failed` back to the portal (`PUT
   /scans/{id}/status`) before returning its usual error — so the portal
   doesn't show a permanently-"pending" scan with no explanation. This
   doesn't introduce a new exit code; a pipeline failure still funnels
   through the pre-existing error-return path.

**New exit code: `2`.** Verified directly against the current code (there's
no pre-existing "2 = generic error" convention for `scan` to repurpose — that
only exists on the unrelated `zerostrike-bench` binary): `scan` previously
only ever exited `0` or `1`. `2` now means "the create-scan call or the JSON
upload failed" and takes precedence over `1` (findings-found) — the local
report already shows any findings either way, so `1` alone would mask the
one outcome the user has no other way to notice: the portal never heard
about this run.

## New subcommand: `zerostrike upload`

`zerostrike upload --report ./report.json [--html ./report.html]
--project-id <id> --server <url> --token <token> [--scan-label <label>]` —
for CI steps that want scan and upload decoupled, or for retrying an upload
after a network failure without re-running the scan. It registers its own
scan with the portal (it has no live scan result of its own) and
re-transmits the on-disk report bytes unchanged.

One deliberate limitation, documented rather than engineered around:
`upload` only has bytes on disk, not a live `*report.Report`, so unlike
`scan`'s upload path it cannot cheaply force a grouped report back to the
flat shape the portal expects (the grouped JSON drops the `Findings` array
entirely in favor of `Groups`). Reports intended for later `upload` should
be generated with `--group-by` unset — called out in the flag help text and
marked with a `ponytail:` comment in the code naming the ceiling (pass-through
only) and the upgrade path (reparse-and-reflatten) if this ever bites someone.

## New package: `internal/portal`

A small stdlib-only HTTP client (`net/http`, no new go.mod dependency),
directly modeled on this repo's only other real HTTP client,
`internal/scanner/sca`'s OSV.dev client — same "retry exactly once on a 5xx,
2s backoff, no retry on 4xx/transport errors" `doRequest` shape, same
"constructor takes an overridable base URL so tests point at
`httptest.Server`" pattern. `CreateScan`/`UploadJSON`/`UploadHTML`/
`UpdateStatus`, plus an `HTTPError{StatusCode,URL,Body}` type so callers can
tell a 401 apart from a 500 or a network error in the message shown to the
user.

## Also populated: `Report.GitCommit` / `Report.Branch`

These fields existed on `report.Report` since early sprints but were never
set by any caller — always empty. Now populated unconditionally (not just in
upload mode) via a best-effort `git rev-parse HEAD` / `git rev-parse
--abbrev-ref HEAD` shelled out from the scan root; any failure (not a git
checkout, git not on PATH, detached HEAD) yields empty strings and never
fails the scan. Free, and useful even for local-only scans.

## Verification

- `go build ./...` / `go vet ./...` — clean, `CGO_ENABLED=1 CC=gcc`.
- `go test ./... -count=1` — clean, including the new `internal/portal` and
  `cmd/zerostrike` test files.
- New tests cover: `CreateScan` success/401/retry-on-500/persistent-500,
  `UploadJSON`/`UploadHTML`/`UpdateStatus` success and failure paths, the
  upload-flags all-or-nothing validation over all 8 set/unset combinations,
  the 401-vs-other-error message differentiation, the exit-code precedence
  table, `buildUploadJSON`'s `GroupByNone` forcing (verified by unmarshalling
  the rendered body and asserting no `Groups` key), `gitInfo` in a real temp
  git repo vs. a non-repo temp dir, and one success-flow test driving
  `uploadCmd()` end-to-end against `httptest` mocks.
- No live end-to-end test against a running portal instance — out of scope
  per the confirmed engine-repo-only decision for this sprint; `httptest`
  contract mocks against the documented shapes are the ceiling here. The
  portal's own real ingestion endpoints (its "Sprint 3") don't exist yet
  either (mock-only today), so there is nothing live to test against.
- No new detection rules; benchmark corpus (TP/FP/FN) unchanged from
  Sprint 28's 140/0/0.

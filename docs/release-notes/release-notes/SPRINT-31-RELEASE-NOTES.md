# Sprint 31 Release Notes

## Summary

Drops the redundant `--project-id` flag from `zerostrike scan`/`zerostrike
upload`. The portal already resolves which project a scan belongs to from
the `--token` alone (a hash lookup server-side) — `--project-id` was pure
client-supplied confirmation of something the token already implied. No
detection/rules changes this sprint.

## `--project-id` deprecated, not removed

`--project-id` is still accepted by both commands (so already-committed CI
pipeline YAML keeps working unchanged) but is now silently ignored — a
stderr warning fires if it's set. It's kept as a **permanent** no-op flag
rather than scheduled for removal: this CLI is fetched fresh per CI run from
the portal's `/downloads/zerostrike/latest/...` endpoint with no client-side
version pinning, so there's no safe window between "deprecate" and "remove"
during which every already-deployed pipeline could be expected to update its
YAML. A no-op flag costs nothing to keep indefinitely; a hard removal risks
breaking CI runs the moment a new `latest` is published.

- `cmd/zerostrike/portal_support.go`: `uploadFlagsError`/`uploadEnabled` now
  take only `server, token` — `--project-id` no longer participates in the
  all-or-nothing upload-flags check.
- `internal/portal/client.go`: `CreateScanRequest.ProjectID` field removed
  (no call site ever populated it once the flag stopped feeding it in).
  `CreateScanResponse` gained `ProjectID`/`ProjectName` — the portal now
  echoes back which project a scan was registered under, since a required
  `--project-id` used to be the only client-side confirmation of that.
- `cmd/zerostrike/scan.go`/`upload.go`: print `scan registered for project
  "<name>" (<id>)` to stderr on successful scan registration, using the
  new response fields.

## Verification

- `go build ./...` — clean.
- `go vet ./cmd/zerostrike/... ./internal/portal/...` — clean.
- `go test ./cmd/zerostrike/... ./internal/portal/...` — all passing,
  including a new `TestUploadCmd_SuccessFlow_NoProjectID` proving the
  shorter invocation works, alongside the existing `--project-id`-passing
  test proving backward compatibility.

## Deferred / out of scope

- No config-file or env-var support added for `--token`/`--server` — still
  flags-only, unchanged from prior sprints.
- Client-side version pinning (so a CI pipeline could pin a specific
  scanner release instead of always fetching `latest`) is a real gap this
  sprint's "no clean deprecation window" reasoning depends on, but building
  it is out of scope here — flagged for whoever picks up the download/
  distribution story next.

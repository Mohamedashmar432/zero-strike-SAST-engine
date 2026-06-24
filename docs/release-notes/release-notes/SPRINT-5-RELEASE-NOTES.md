# ZeroStrike SAST Engine — Sprint 5 Release Notes

**Release:** Sprint 5 — Multi-Scanner Architecture  
**Date:** 2026-06-23  
**Version:** pre-release v0.5.0  
**Prepared for:** QA Engineers

---

## Executive Summary

Sprint 5 refactors the monolithic SAST pipeline into a composable multi-scanner architecture and introduces two new scanning modalities: a **Secrets scanner** and an **SCA/OSV dependency scanner**.

**Before Sprint 5:**
- One pipeline, one scanner type — SAST only
- `core.Finding` had no way to distinguish a code vulnerability from a leaked credential or a vulnerable dependency
- No detection of hardcoded secrets beyond the basic ZS-PY-006 AST rule
- No dependency vulnerability scanning

**After Sprint 5:**
- All scanners implement a common `Scanner` interface; SAST, Secrets, and SCA run composably in one pipeline pass
- `core.Finding` carries a `Kind` field (`sast` | `secret` | `sca`) and typed sub-payloads (`SecretFinding`, `DependencyFinding`)
- Five secret detector patterns with Shannon entropy filtering to suppress false positives
- SCA scanner parses `requirements.txt` and `package-lock.json` and queries the OSV vulnerability database
- Three new CLI flags: `--enable-secrets`, `--enable-sca`, `--sca-on-error`
- **48 tests pass** across 8 packages; **zero new external dependencies**

---

## What Sprint 5 Delivers

### 1. Scanner Interface

A new `Scanner` interface lives in `internal/scanner/scanner.go`. Every scanning modality implements it:

```go
type Scanner interface {
    Name() string
    Accepts(entry walker.FileEntry) bool
    Scan(ctx context.Context, files []walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic, error)
}
```

The pipeline builds an ordered `[]scanner.Scanner` slice. SAST is always first. Secrets and SCA are appended when their flags are enabled.

---

### 2. FindingKind Enum

`core.Finding` gains three new fields:

| Field | Type | Purpose |
|-------|------|---------|
| `Kind` | `FindingKind` | Discriminates scanner origin |
| `Secret` | `*SecretFinding` | Non-nil for Kind == secret |
| `Dependency` | `*DependencyFinding` | Non-nil for Kind == sca |

`FindingKind` values:

| Value | Origin |
|-------|--------|
| `sast` | AST pattern-match rule (SAST engine) |
| `secret` | Regex + entropy detector (Secrets scanner) |
| `sca` | OSV advisory match (SCA scanner) |

All existing SAST findings are now stamped `Kind: "sast"`. JSON output will include this field.

---

### 3. Typed Sub-Payloads

**`SecretFinding`** (on Kind == secret):

| Field | Description |
|-------|-------------|
| `DetectorID` | Detector name e.g. `aws-access-key` |
| `Entropy` | Shannon entropy of the captured value |
| `Redacted` | First 4 chars + `****` — display only, never fingerprinted |

**`DependencyFinding`** (on Kind == sca):

| Field | Description |
|-------|-------------|
| `Ecosystem` | `PyPI` or `npm` |
| `Package` | Package name |
| `InstalledVersion` | Pinned version found in the lock file |
| `VulnerableRange` | Affected version range from OSV e.g. `>=1.0.0, <1.2.0` |
| `FixedVersion` | First fixed version, empty if none published |
| `AdvisoryIDs` | All IDs: primary + aliases (CVE, GHSA, PYSEC, OSV) |
| `Manifest` | Path to the lock file that contained this dependency |
| `Direct` | `true` if a direct dependency |

---

### 4. Secrets Scanner (`--enable-secrets`)

File: `internal/scanner/secrets/scanner.go`

Regex-based detection across all non-binary text files. Pure Go — no CGo, testable on Windows without gcc.

#### Detector Table

| Rule ID | Detector | Pattern | Severity | Entropy Min |
|---------|----------|---------|----------|-------------|
| ZS-SEC-001 | aws-access-key | `AKIA[0-9A-Z]{16}` | Critical | — |
| ZS-SEC-002 | github-token | `ghp_<36chars>` / `github_pat_...` | Critical | — |
| ZS-SEC-003 | generic-api-key | `api_key = "<value>"` | High | 3.0 |
| ZS-SEC-004 | hardcoded-password | `password = "<value>"` | High | 3.0 |
| ZS-SEC-005 | private-key-pem | `-----BEGIN * PRIVATE KEY-----` | Critical | — |

**Entropy filtering:** ZS-SEC-003 and ZS-SEC-004 skip values with Shannon entropy < 3.0 to suppress placeholder strings like `password = "changeme"`.

**Fingerprinting:** `sha256(detectorID + "|" + sha256(rawSecret[:32]))[:16]` — stable across files, raw secret never stored.

**Binary skip:** Files with a null byte in the first 512 bytes are skipped (new `FileEntry.IsBinary` flag).

---

### 5. IsBinary Detection

`internal/walker/walker.go`: `FileEntry` gains `IsBinary bool`.

`internal/walker/fswalker.go`: After the file size check, the walker opens and reads up to 512 bytes. If any null byte is found, `IsBinary` is set to `true`. Both the Secrets scanner and SAST scanner call `!entry.IsBinary` in their `Accepts()` method.

---

### 6. SCA / OSV Scanner (`--enable-sca`)

Files: `internal/scanner/sca/lockfile.go`, `internal/scanner/sca/osv.go`, `internal/scanner/sca/scanner.go`

Parses lock files and queries the OSV vulnerability database. Pure Go — stdlib `net/http` + `encoding/json` only.

#### Supported Manifests

| File | Ecosystem | Notes |
|------|-----------|-------|
| `requirements.txt` | PyPI | Pinned lines only (`==`); unpinned specs skipped |
| `package-lock.json` | npm | lockfileVersion 1, 2, and 3 |

#### OSV Integration

- Batch `POST https://api.osv.dev/v1/querybatch` — up to 1,000 packages per request
- Advisory hydration via `GET https://api.osv.dev/v1/vulns/{id}`
- Severity resolved from `database_specific.severity` → ZeroStrike `core.Severity`
- Single retry on HTTP 5xx; `--sca-on-error warn` (default) continues with a diagnostic on failure; `--sca-on-error fail` aborts the scan

---

### 7. New CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-secrets` | off | Enable the Secrets scanner |
| `--enable-sca` | off | Enable the SCA/OSV scanner |
| `--sca-on-error` | `warn` | Network error behaviour: `warn` (continue + diagnostic) or `fail` (abort) |

---

### 8. Pipeline Refactor

`internal/pipeline/scanner.go` is refactored to compose scanners:

**Before:**
```go
type ScanPipeline struct {
    config    ScanConfig
    walker    walker.Walker
    detector  detector.Detector
    eng       engine.Engine
    ruleIndex *engine.RuleIndex
    collector findings.Collector
    dedup     findings.Deduplicator
}
```

**After:**
```go
type ScanPipeline struct {
    config    ScanConfig
    walker    walker.Walker
    scanners  []scanner.Scanner   // SAST always first; Secrets + SCA opt-in
    collector findings.Collector
    dedup     findings.Deduplicator
}
```

The `processFile` and `buildIR` logic moves from `pipeline/scanner.go` into `internal/scanner/sast/sast.go`. The external API (`pipeline.New()` / `pipeline.Run()`) is unchanged.

---

### 9. SAST Scanner Wrapper

`internal/scanner/sast/sast.go` wraps the existing engine, rule index, and detector as a `Scanner` implementation. The logic is identical to the old `processFile` — only the packaging changed.

---

### 10. Report Stats

`internal/report/report.go` — `ScanStats` gains two new fields:

```go
ByScanner map[string]int           // "sast" | "secret" | "sca" → count
ByKind    map[core.FindingKind]int // FindingKindSAST | ... → count
```

These are populated in `cmd/zerostrike/scan.go` after `Run()` and included in JSON output.

---

## Updated Rule Inventory

### Python Rules (10 — unchanged)

| Rule ID | Name | Severity |
|---------|------|----------|
| ZS-PY-001 | Dangerous eval() Usage | High |
| ZS-PY-002 | Insecure pickle.loads Deserialization | Critical |
| ZS-PY-003 | subprocess shell=True Command Injection | High |
| ZS-PY-004 | SQL String Formatting (Potential SQLi) | High |
| ZS-PY-005 | os.system() Command Injection | High |
| ZS-PY-006 | Hardcoded Password or Secret Literal | High |
| ZS-PY-007 | Weak Cryptographic Hash (MD5/SHA1) | Medium |
| ZS-PY-008 | open() with Potentially User-Controlled Path | High |
| ZS-PY-009 | assert Used for Security Check | Medium |
| ZS-PY-010 | yaml.load Without safe_load | High |

### JavaScript Rules (3 — unchanged)

| Rule ID | Name | Severity |
|---------|------|----------|
| ZS-JS-001 | eval() Usage | High |
| ZS-JS-002 | innerHTML Assignment (DOM XSS) | High |
| ZS-JS-003 | document.write() (DOM XSS) | High |

### Secrets Detectors (5 — new)

| Rule ID | Detector | Severity |
|---------|----------|----------|
| ZS-SEC-001 | aws-access-key | Critical |
| ZS-SEC-002 | github-token | Critical |
| ZS-SEC-003 | generic-api-key | High |
| ZS-SEC-004 | hardcoded-password | High |
| ZS-SEC-005 | private-key-pem | Critical |

---

## Test Coverage

### New Tests Added in Sprint 5

#### `internal/scanner/secrets/scanner_test.go` — 8 tests (no CGo)

| Test | What it verifies |
|------|-----------------|
| `TestSecretsScanner_AWSKey` | ZS-SEC-001 fires on `AKIA...` pattern; Kind == secret |
| `TestSecretsScanner_GitHubToken` | ZS-SEC-002 fires on `ghp_<36>` |
| `TestSecretsScanner_PrivateKeyPEM` | ZS-SEC-005 fires on PEM header |
| `TestSecretsScanner_BinaryFileSkipped` | `Accepts` returns false for IsBinary entries |
| `TestSecretsFingerprint_SameSecretSameFingerprint` | Same secret in two files → same fingerprint |
| `TestSecretsFingerprint_DiffSecretDiffFingerprint` | Two distinct AWS keys → distinct fingerprints |
| `TestSecretsScanner_LowEntropyNotFlagged` | Low-entropy value not flagged by ZS-SEC-003 |
| `TestSecretsScanner_Scan` | Empty file list returns nil error |

#### `internal/scanner/sca/lockfile_test.go` — 5 tests (no CGo)

| Test | What it verifies |
|------|-----------------|
| `TestParseRequirementsTxt_Pinned` | Two pinned deps parsed, Direct=true, Ecosystem=PyPI |
| `TestParseRequirementsTxt_Unpinned` | `>=` specifier skipped (0 deps) |
| `TestParseRequirementsTxt_Comments` | `#` lines skipped |
| `TestParsePackageLockJSON_V2` | v2 format: node_modules/ prefix stripped |
| `TestParsePackageLockJSON_V1` | v1 format: `dependencies` key parsed |

#### `internal/scanner/sca/osv_test.go` — 4 tests (no CGo, httptest mock)

| Test | What it verifies |
|------|-----------------|
| `TestOSVClient_MatchFound` | Match returns advisory with correct ID and severity |
| `TestOSVClient_NetworkError_WarnMode` | 5xx → 0 findings, 1 diagnostic, nil error |
| `TestOSVClient_NetworkError_FailMode` | 5xx → non-nil error returned |
| `TestOSVClient_BatchSplit` | 1001 deps → 2 HTTP POST requests |

#### `internal/findings/builder_test.go` — 2 new tests

| Test | What it verifies |
|------|-----------------|
| `TestBuildSecretFinding_Fingerprint` | Same raw secret → same fingerprint; Kind=secret; Secret payload populated |
| `TestBuildDependencyFinding_Fingerprint` | Same dep+advisory → same fingerprint; Kind=sca; Dependency payload populated |

### Total Test Count

| Sprint | Tests | Pass |
|--------|-------|------|
| Sprint 1 | 64 | 64 |
| Sprint 2 | 71 | 71 |
| Sprint 3 | 85 | 85 (non-CGo) + 8 CGo integration |
| Sprint 4 | 88 | 88 (non-CGo) + 8 CGo integration |
| **Sprint 5** | **48 non-CGo** | **48 PASS** (CGo packages unchanged) |

> Sprint 5 test count is 48 for the non-CGo packages only (the CGo packages — engine, pipeline, parser — cannot build on this Windows machine without gcc and are excluded from local testing).

---

## Known Issues

### KI-006: CGo Required for SAST Scanner and Pipeline Tests (pre-existing)

`internal/scanner/sast/sast.go` imports `pythonparser` and `jsparser`, both of which are CGo packages. The SAST scanner and pipeline therefore cannot be built or tested locally on this Windows machine without gcc.

**QA action:** Run `go test ./...` in a Linux CI environment with gcc installed to cover the CGo packages.

---

### KI-007: ZS-PY-006 Still Active Alongside Secrets Scanner (by design)

ZS-PY-006 (Hardcoded Password AST rule) and ZS-SEC-004 (hardcoded-password regex detector) both cover hardcoded credentials. On a Python scan with `--enable-secrets`, both may fire on the same line (different fingerprints — one is `sast`, one is `secret`).

**Plan:** Retire ZS-PY-006 in Sprint 6 after the Secrets allowlist UX is validated and QA confirms ZS-SEC-004 has acceptable false-positive rates.

---

### KI-008: SCA Limited to requirements.txt and package-lock.json

Pipfile.lock, yarn.lock, and pnpm-lock.yaml are not yet supported.

**Planned for:** Sprint 6.

---

### KI-009: OSV Network Retry Adds 2s to Test Suite

`TestOSVClient_NetworkError_WarnMode` and `TestOSVClient_NetworkError_FailMode` each sleep 2 seconds (the retry delay on HTTP 5xx). Total test time for `internal/scanner/sca` is ~6 seconds as a result.

**Impact:** Acceptable for Sprint 5. The retry sleep can be made injectable in Sprint 6 to reduce test time.

---

## Files Changed

### New Files

| File | Purpose |
|------|---------|
| `internal/scanner/scanner.go` | `Scanner` interface |
| `internal/scanner/sast/sast.go` | SAST scanner wrapper (moved from pipeline) |
| `internal/scanner/secrets/scanner.go` | Secrets scanner — 5 detectors, entropy guard |
| `internal/scanner/secrets/scanner_test.go` | 8 tests |
| `internal/scanner/sca/lockfile.go` | requirements.txt + package-lock.json parsers |
| `internal/scanner/sca/osv.go` | OSV batch API client |
| `internal/scanner/sca/scanner.go` | SCA scanner + `scanDeps` testable helper |
| `internal/scanner/sca/lockfile_test.go` | 5 tests |
| `internal/scanner/sca/osv_test.go` | 4 tests (httptest mock) |

### Modified Files

| File | Change |
|------|--------|
| `internal/walker/walker.go` | `FileEntry.IsBinary bool` added |
| `internal/walker/fswalker.go` | 512-byte null-byte sniff sets `IsBinary` |
| `internal/core/finding.go` | `FindingKind`, `SecretFinding`, `DependencyFinding`; `Finding.Kind/.Secret/.Dependency` |
| `internal/findings/builder.go` | `BuildSecretFinding`, `BuildDependencyFinding`, `DependencyInput`; SAST stamped `Kind: FindingKindSAST` |
| `internal/pipeline/config.go` | `EnableSecrets`, `EnableSCA`, `SCAOnError` |
| `internal/pipeline/scanner.go` | Refactored to `[]scanner.Scanner` orchestration; `processFile`+`buildIR` removed (moved to sast package) |
| `cmd/zerostrike/scan.go` | `--enable-secrets`, `--enable-sca`, `--sca-on-error` flags |
| `internal/report/report.go` | `ScanStats.ByScanner`, `ScanStats.ByKind` |
| `internal/findings/builder_test.go` | 2 new fingerprint tests |

---

## How to Verify (QA Steps)

### Prerequisites

- Go 1.21+ installed
- `gcc` in PATH for CGo tests (MSYS2/TDM-GCC on Windows, or Linux CI)
- Built binary: `go build -o zerostrike ./cmd/zerostrike/`

---

### Step 1 — Run non-CGo tests

```bash
go test ./internal/core/... ./internal/findings/... ./internal/walker/... \
    ./internal/scanner/secrets/... ./internal/scanner/sca/... \
    ./internal/rules/... ./internal/ir/... ./internal/symboltable/... \
    -v -count=1
```

**Expected:** 48 tests pass, 0 fail. Confirm Sprint 5 tests appear:
- `TestSecretsScanner_AWSKey — PASS`
- `TestOSVClient_MatchFound — PASS`
- `TestParseRequirementsTxt_Pinned — PASS`
- `TestBuildSecretFinding_Fingerprint — PASS`

---

### Step 2 — Verify SAST scan is unchanged (no regression)

```bash
./zerostrike scan testdata/python/
```

**Expected:** Same findings as Sprint 4. All Python rules fire correctly. Exit code 1.

```bash
./zerostrike scan testdata/js/
```

**Expected:** ZS-JS-001, ZS-JS-002, ZS-JS-003 findings. Exit code 1.

---

### Step 3 — Verify Secrets scanner (AWS key)

Create a fixture:

```bash
echo 'aws_key = "AKIAIOSFODNN7EXAMPLE"' > /tmp/test_secret.py
./zerostrike scan --enable-secrets /tmp/test_secret.py
```

**Expected:** JSON output contains a finding with `"RuleID": "ZS-SEC-001"`, `"Kind": "secret"`, `"Severity": "critical"`. Exit code 1.

---

### Step 4 — Verify Secrets scanner (GitHub token)

```bash
echo 'token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' > /tmp/gh_token.py
./zerostrike scan --enable-secrets /tmp/gh_token.py
```

**Expected:** Finding with `"RuleID": "ZS-SEC-002"`, `"Kind": "secret"`.

---

### Step 5 — Verify entropy guard suppresses low-entropy values

```bash
echo 'api_key = "aaaaaaaaaaaaaaaaaaaaaa"' > /tmp/low_entropy.py
./zerostrike scan --enable-secrets /tmp/low_entropy.py
```

**Expected:** No ZS-SEC-003 finding. Exit code 0.

---

### Step 6 — Verify binary files are skipped

```bash
# Create a binary file with null bytes
python3 -c "open('/tmp/binary.bin','wb').write(b'hello\x00world')"
./zerostrike scan --enable-secrets /tmp/binary.bin
```

**Expected:** No findings. Exit code 0. No errors.

---

### Step 7 — Verify SCA scanner (requirements.txt)

Create a fixture with a known-vulnerable package:

```bash
echo "requests==2.6.0" > /tmp/requirements.txt
./zerostrike scan --enable-sca /tmp/
```

**Expected:** If OSV has advisories for requests 2.6.0, findings with `"Kind": "sca"` and `"Dependency"` payload present. At minimum, the scan completes without error.

---

### Step 8 — Verify SCA warn mode on network failure

```bash
./zerostrike scan --enable-sca --sca-on-error warn /tmp/requirements.txt
```

Disconnect from network or use a host that refuses connections.

**Expected:** Exit code 0. JSON output includes a diagnostic with message `SCA scan skipped: ...`. No crash.

---

### Step 9 — Verify SCA fail mode on network failure

```bash
./zerostrike scan --enable-sca --sca-on-error fail /tmp/requirements.txt
```

**Expected:** Non-zero exit code. Error message in stderr.

---

### Step 10 — Verify JSON stats include ByScanner and ByKind

```bash
echo 'aws_key = "AKIAIOSFODNN7EXAMPLE"' > /tmp/secret.py
./zerostrike scan --enable-secrets /tmp/secret.py | python3 -m json.tool | grep -A5 '"Stats"'
```

**Expected:** `Stats` block contains `"ByScanner"` and `"ByKind"` maps. `"ByScanner": {"secret": 1}`, `"ByKind": {"secret": 1}`.

---

### Step 11 — Verify same-secret same-fingerprint across files

```bash
echo 'key = "AKIAIOSFODNN7EXAMPLE"' > /tmp/f1.py
echo 'key = "AKIAIOSFODNN7EXAMPLE"' > /tmp/f2.py
./zerostrike scan --enable-secrets /tmp/ | python3 -c "
import json, sys
data = json.load(sys.stdin)
fps = [f['Fingerprint'] for f in data['Findings'] if f['RuleID']=='ZS-SEC-001']
print('Fingerprints:', fps)
print('Match:', len(set(fps)) == 1)
"
```

**Expected:** Both findings have identical `Fingerprint` values. Output: `Match: True`.

---

### Step 12 — Verify Kind=sast on SAST findings in mixed scan

```bash
./zerostrike scan --enable-secrets testdata/python/vuln_eval.py | \
    python3 -c "import json,sys; [print(f['Kind'],f['RuleID']) for f in json.load(sys.stdin)['Findings']]"
```

**Expected:** All SAST findings show `Kind: sast`.

---

### Step 13 — Run full integration tests (CGo required)

```bash
go test ./... -v -count=1
```

**Expected:** All tests pass, including CGo packages on a Linux environment with gcc.

---

## What's Next — Sprint 6 Preview

- **Secrets allowlist** — YAML-based suppression file (`--allow-secrets-file`) to mark known-safe values
- **Retire ZS-PY-006** — once allowlist UX is validated, remove the AST-based hardcoded password rule to avoid duplicate findings with ZS-SEC-004
- **SCA: additional manifests** — Pipfile.lock, yarn.lock, pnpm-lock.yaml
- **TypeScript parser** — replace stub with tree-sitter TypeScript grammar
- **SARIF and HTML reporters** — currently empty stubs
- **Bounded fan-out concurrency** — parallel scanner execution in `pipeline.Run()`

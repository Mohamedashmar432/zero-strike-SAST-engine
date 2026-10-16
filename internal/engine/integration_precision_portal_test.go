//go:build cgo

package engine_test

import (
	"testing"
)

// Precision tests for the false-positive classes verified against the portal's
// own scan (see the portal's docs/SAST_FINDINGS_REMEDIATION_PLAN.md, workstream
// B). Every negative has a positive twin so recall is pinned in the same place.
// All values are synthetic.

// --- ZS-PY-020 ---

// ZS-PY-020 matched on the variable name alone. Each source is the shape of a
// portal false positive: scheme names, endpoint constants, token_type, a
// placeholder value, a leading-underscore sentinel.
func TestPrecision_CredentialShapedNamesNotHardcodedCredential(t *testing.T) {
	_, idx := loadPythonRules(t)
	for _, src := range []string{
		"BEARER_SCHEME = \"bearer\"\n",
		"token_scheme = \"Bearer\"\n",
		"TOKEN_URL = \"/api/v1/auth/token\"\n",
		"REFRESH_TOKEN_URL = \"/api/v1/auth/refresh\"\n",
		"token_type = \"bearer\"\n",
		"repo_token_auth_scheme = \"basic\" if use_basic else \"bearer\"\n",
		"api_key = \"not-needed\"\n",
		"_PLACEHOLDER_API_KEY = \"synthetic-value-0000\"\n",
		"secret = \"secret\"\n",
	} {
		if hasRule(matchSource(t, idx, src), "ZS-PY-020") {
			t.Errorf("ZS-PY-020 must not fire on %q", src)
		}
	}
}

// Recall half: a leading underscore or a plain name alone does not suppress.
func TestPrecision_RealHardcodedCredentialsStillFirePY020(t *testing.T) {
	_, idx := loadPythonRules(t)
	for _, src := range []string{
		"api_token = \"Zk3Qp9Lm2Xv7Bn4Tr8Wc1Yd6Hs5Jf0Ga\"\n",
		"_SECRET_TOKEN = \"Qw8Er3Ty6Ui1Op4As7Df0Gh2Jk5Lz9Xc\"\n",
		"password = \"hunter2\"\n",
	} {
		if !hasRule(matchSource(t, idx, src), "ZS-PY-020") {
			t.Errorf("expected ZS-PY-020 to fire on %q", src)
		}
	}
}

// ZS-PY-146 (hardcoded encryption key) is a true-positive class and must be
// untouched by the credential-name filtering above.
func TestPrecision_HardcodedFernetKeyStillFiresPY146(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "ENCRYPTION_KEY = \"Zk3Qp9Lm2Xv7Bn4Tr8Wc1Yd6Hs5Jf0GaQw8Er3Ty6Ui=\"\n"
	if !hasRule(matchSource(t, idx, src), "ZS-PY-146") {
		t.Error("expected ZS-PY-146 to keep firing on a hardcoded Fernet-style key")
	}
}

// --- ZS-PY-141 / ZS-TS-141 / ZS-JS-141 ---

func TestPrecision_LabelMapNotHardcodedCredentialKwarg(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "LABELS = {\"secret\": \"Secrets\", \"password\": \"Passwords\", \"token\": \"Tokens\"}\n"
	if hasRule(matchSource(t, idx, src), "ZS-PY-141") {
		t.Error("ZS-PY-141 must not fire on a plural label map")
	}
}

func TestPrecision_SeedPasswordStillFiresPY141(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "SEED = {\"password\": \"Zk3Qp9Lm2Xv7\"}\n"
	if !hasRule(matchSource(t, idx, src), "ZS-PY-141") {
		t.Error("expected ZS-PY-141 to still fire on a seed-style password literal")
	}
}

func TestPrecision_LabelMapNotHardcodedCredentialTSAndJS(t *testing.T) {
	src := "const labels = { secret: 'Secrets', password: 'Passwords' };\n"
	if hasRule(matchTSSource(t, loadTSRules(t), src), "ZS-TS-141") {
		t.Error("ZS-TS-141 must not fire on a plural label map")
	}
	if hasRule(matchJSSource(t, loadJSRules(t), src), "ZS-JS-141") {
		t.Error("ZS-JS-141 must not fire on a plural label map")
	}
	pos := "const seed = { password: 'Zk3Qp9Lm2Xv7' };\n"
	if !hasRule(matchTSSource(t, loadTSRules(t), pos), "ZS-TS-141") {
		t.Error("expected ZS-TS-141 to still fire on a seed-style password")
	}
	if !hasRule(matchJSSource(t, loadJSRules(t), pos), "ZS-JS-141") {
		t.Error("expected ZS-JS-141 to still fire on a seed-style password")
	}
}

// --- ZS-TS-055 / ZS-JS-057 setInterval ---

func TestPrecision_ArrowFunctionSetIntervalSuppressed(t *testing.T) {
	src := "function QueueTag(props: { tick: number }) {\n" +
		"  const id = setInterval(() => setNow(Date.now()), 1000);\n" +
		"  return id;\n}\n"
	if hasRule(matchTSSource(t, loadTSRules(t), src), "ZS-TS-055") {
		t.Error("ZS-TS-055 must not fire on setInterval(arrow, delay)")
	}
	if hasRule(matchJSSource(t, loadJSRules(t), "function f(){ setInterval(() => tick(), 1000); }\n"), "ZS-JS-057") {
		t.Error("ZS-JS-057 must not fire on setInterval(arrow, delay)")
	}
}

func TestPrecision_RealSourceStillFiresSetInterval(t *testing.T) {
	src := "const code: string = location.hash.slice(1);\nsetInterval(code, 100);\n"
	if !hasRule(matchTSSource(t, loadTSRules(t), src), "ZS-TS-055") {
		t.Error("expected ZS-TS-055 to fire for a real source reaching argument 0")
	}
	jsSrc := "var code = location.hash.slice(1);\nsetInterval(code, 100);\n"
	if !hasRule(matchJSSource(t, loadJSRules(t), jsSrc), "ZS-JS-057") {
		t.Error("expected ZS-JS-057 to fire for a real source reaching argument 0")
	}
}

// --- ZS-PY-065 rmtree ---

func TestPrecision_RmtreeHelperParameterNotFlagged(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import shutil, tempfile\n\n" +
		"def rmtree_logged(path):\n    shutil.rmtree(path, ignore_errors=True)\n\n" +
		"def run():\n    workdir = tempfile.mkdtemp()\n    rmtree_logged(workdir)\n"
	if hasRule(matchSource(t, idx, src), "ZS-PY-065") {
		t.Error("ZS-PY-065 must not fire on a helper parameter")
	}
}

func TestPrecision_RmtreeRealSourceStillFires(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import shutil\nfrom flask import request\n\n" +
		"def drop():\n    target = request.args.get('dir')\n    shutil.rmtree(target)\n"
	if !hasRule(matchSource(t, idx, src), "ZS-PY-065") {
		t.Error("expected ZS-PY-065 to fire when request data reaches rmtree")
	}
}

// Known interprocedural gap probe (recorded in benchmark/README.md): logs the
// behaviour so a future change to it is visible, without failing the build.
func TestPrecision_RmtreeInterproceduralVariantProbe(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import shutil\nfrom flask import request\n\n" +
		"def rmtree_logged(path):\n    shutil.rmtree(path)\n\n" +
		"def handler():\n    d = request.args.get('dir')\n    rmtree_logged(d)\n"
	t.Logf("two-function rmtree, graphs on: fires ZS-PY-065 = %v", hasRule(matchSourceWithGraphs(t, idx, src, true), "ZS-PY-065"))
	t.Logf("two-function rmtree, graphs off: fires ZS-PY-065 = %v", hasRule(matchSource(t, idx, src), "ZS-PY-065"))
}

// --- ZS-PY-022 logged secret ---

func TestPrecision_LoggingMetadataNotSensitiveValue(t *testing.T) {
	_, idx := loadPythonRules(t)
	for _, src := range []string{
		"logger.warning(\"missing\", secret_name=name)\n",
		"logger.warning(\"missing %s\", config.api_key_secret_name)\n",
		"logger.error(\"clone failed: %s\", git_workspace.sanitize(str(exc), token))\n",
	} {
		if hasRule(matchSource(t, idx, src), "ZS-PY-022") {
			t.Errorf("ZS-PY-022 must not fire on %q", src)
		}
	}
}

func TestPrecision_LoggedSecretStillFiresPY022(t *testing.T) {
	_, idx := loadPythonRules(t)
	for _, src := range []string{
		"logging.info(password)\n",
		"logger.warning(\"x\", token=token)\n",
		"logger.info(\"x\", user_name=u, password=pw)\n",
		"logger.info(\"x\", secret_name=n, token=token)\n",
		"logger.error(f\"bad {api_key}\")\n",
	} {
		if !hasRule(matchSource(t, idx, src), "ZS-PY-022") {
			t.Errorf("expected ZS-PY-022 to fire on %q", src)
		}
	}
}

// --- ZS-PY-057 / ZS-PY-147 Popen severity split ---

func TestPrecision_PopenParameterArgvRegradedToPY147(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import subprocess\n\ndef run_git(cmd):\n    return subprocess.Popen(cmd, stdout=subprocess.PIPE)\n"
	res := matchSource(t, idx, src)
	if hasRule(res, "ZS-PY-057") {
		t.Error("ZS-PY-057 must not fire on a parameter-only argv with shell unset")
	}
	if !hasRule(res, "ZS-PY-147") {
		t.Error("expected ZS-PY-147 to report the parameter argv")
	}
}

func TestPrecision_PopenRealSourceOrShellStillFiresPY057(t *testing.T) {
	_, idx := loadPythonRules(t)
	real := "import subprocess\nfrom flask import request\n\n" +
		"def view():\n    host = request.args.get('h')\n    subprocess.Popen('ping ' + host, shell=True)\n"
	res := matchSource(t, idx, real)
	if !hasRule(res, "ZS-PY-057") {
		t.Error("expected ZS-PY-057 for a real source")
	}
	if hasRule(res, "ZS-PY-147") {
		t.Error("ZS-PY-147 must not repeat what ZS-PY-057 reports")
	}
	shell := "import subprocess\n\ndef run(cmd):\n    subprocess.Popen(cmd, shell=True)\n"
	if !hasRule(matchSource(t, idx, shell), "ZS-PY-057") {
		t.Error("expected ZS-PY-057 for shell=True")
	}
}

// --- ZS-PY-011 / ZS-PY-007 usedforsecurity ---

func TestPrecision_UsedForSecurityFalseNotWeakHash(t *testing.T) {
	_, idx := loadPythonRules(t)
	res := matchSource(t, idx, "import hashlib\nk = hashlib.sha1(data, usedforsecurity=False).hexdigest()\nm = hashlib.md5(data, usedforsecurity=False)\n")
	if hasRule(res, "ZS-PY-011") || hasRule(res, "ZS-PY-007") {
		t.Error("weak-hash rules must not fire when usedforsecurity=False")
	}
}

func TestPrecision_WeakHashStillFires(t *testing.T) {
	_, idx := loadPythonRules(t)
	for _, src := range []string{
		"import hashlib\nh = hashlib.sha1(data)\n",
		"import hashlib\nh = hashlib.sha1(data, usedforsecurity=True)\n",
	} {
		if !hasRule(matchSource(t, idx, src), "ZS-PY-011") {
			t.Errorf("expected ZS-PY-011 on %q", src)
		}
	}
	if !hasRule(matchSource(t, idx, "import hashlib\nh = hashlib.md5(data)\n"), "ZS-PY-007") {
		t.Error("expected ZS-PY-007 on plain md5")
	}
}

//go:build cgo

package engine_test

import "testing"

// Integration tests for the Python rule expansion ZS-PY-045..ZS-PY-056.
// Helpers (loadPythonRules, matchSource, hasRule) live in integration_test.go.

func TestIntegration_TarfileExtractallFiresZSPY045(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import tarfile\ntar = tarfile.open(\"upload.tar.gz\")\ntar.extractall(\"/srv/data\")\n"
	results := matchSource(t, idx, src)
	if !hasRule(results, "ZS-PY-045") {
		t.Error("expected ZS-PY-045 to fire on tar.extractall() call")
	}
}

func TestIntegration_ZipfileExtractallFiresZSPY046(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import zipfile\nzip_ref = zipfile.ZipFile(\"upload.zip\", \"r\")\nzip_ref.extractall(\"/srv/data\")\n"
	results := matchSource(t, idx, src)
	if !hasRule(results, "ZS-PY-046") {
		t.Error("expected ZS-PY-046 to fire on zip_ref.extractall() call")
	}
}

func TestIntegration_MarshalLoadsFiresZSPY047(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import marshal\nobj = marshal.loads(blob)\n")
	if !hasRule(results, "ZS-PY-047") {
		t.Error("expected ZS-PY-047 to fire on marshal.loads() call")
	}
}

func TestIntegration_DillLoadsFiresZSPY048(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import dill\nobj = dill.loads(payload)\n")
	if !hasRule(results, "ZS-PY-048") {
		t.Error("expected ZS-PY-048 to fire on dill.loads() call")
	}
}

func TestIntegration_PickleLoadFiresZSPY049(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import pickle\nobj = pickle.load(fh)\n")
	if !hasRule(results, "ZS-PY-049") {
		t.Error("expected ZS-PY-049 to fire on pickle.load() call")
	}
}

// ZS-PY-049 matches the exact callee pickle.load; pickle.loads is ZS-PY-002's
// territory and must not double-fire the file-object rule.
func TestIntegration_PickleLoadsDoesNotFireZSPY049(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import pickle\nobj = pickle.loads(data)\n")
	if hasRule(results, "ZS-PY-049") {
		t.Error("expected ZS-PY-049 to NOT fire on pickle.loads() call")
	}
}

func TestIntegration_YamlUnsafeLoadFiresZSPY050(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import yaml\ncfg = yaml.unsafe_load(stream)\n")
	if !hasRule(results, "ZS-PY-050") {
		t.Error("expected ZS-PY-050 to fire on yaml.unsafe_load() call")
	}
}

func TestIntegration_SslUnverifiedContextFiresZSPY051(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import ssl\nctx = ssl._create_unverified_context()\n")
	if !hasRule(results, "ZS-PY-051") {
		t.Error("expected ZS-PY-051 to fire on ssl._create_unverified_context() call")
	}
}

func TestIntegration_ParamikoAutoAddPolicyFiresZSPY052(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import paramiko\nssh = paramiko.SSHClient()\nssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
	results := matchSource(t, idx, src)
	if !hasRule(results, "ZS-PY-052") {
		t.Error("expected ZS-PY-052 to fire on set_missing_host_key_policy(AutoAddPolicy())")
	}
}

func TestIntegration_ParamikoRejectPolicyDoesNotFireZSPY052(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import paramiko\nssh = paramiko.SSHClient()\nssh.set_missing_host_key_policy(paramiko.RejectPolicy())\n"
	results := matchSource(t, idx, src)
	if hasRule(results, "ZS-PY-052") {
		t.Error("expected ZS-PY-052 to NOT fire on set_missing_host_key_policy(RejectPolicy())")
	}
}

func TestIntegration_LxmlFromstringTaintedFiresZSPY053(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "from lxml import etree\nxml_data = request.form['xml']\netree.fromstring(xml_data)\n"
	results := matchSource(t, idx, src)
	if !hasRule(results, "ZS-PY-053") {
		t.Error("expected ZS-PY-053 to fire when etree.fromstring() argument is tainted")
	}
}

func TestIntegration_LxmlFromstringConstantDoesNotFireZSPY053(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "from lxml import etree\nxml_data = \"<root/>\"\netree.fromstring(xml_data)\n"
	results := matchSource(t, idx, src)
	if hasRule(results, "ZS-PY-053") {
		t.Error("expected ZS-PY-053 to NOT fire when etree.fromstring() argument is a constant")
	}
}

func TestIntegration_MarkupTaintedFiresZSPY054(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "from markupsafe import Markup\ncomment = request.args.get('comment')\nhtml = Markup(comment)\n"
	results := matchSource(t, idx, src)
	if !hasRule(results, "ZS-PY-054") {
		t.Error("expected ZS-PY-054 to fire when Markup() argument is tainted")
	}
}

func TestIntegration_MarkupConstantDoesNotFireZSPY054(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "from markupsafe import Markup\nhtml = Markup(\"<b>static</b>\")\n"
	results := matchSource(t, idx, src)
	if hasRule(results, "ZS-PY-054") {
		t.Error("expected ZS-PY-054 to NOT fire when Markup() argument is a constant")
	}
}

func TestIntegration_LogInjectionTaintedFiresZSPY055(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import logging\nusername = request.args.get('user')\nlogging.info(username)\n"
	results := matchSource(t, idx, src)
	if !hasRule(results, "ZS-PY-055") {
		t.Error("expected ZS-PY-055 to fire when logging.info() argument is tainted")
	}
}

func TestIntegration_LogInjectionConstantDoesNotFireZSPY055(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import logging\nlogging.info(\"server started\")\n")
	if hasRule(results, "ZS-PY-055") {
		t.Error("expected ZS-PY-055 to NOT fire when logging.info() argument is a constant")
	}
}

func TestIntegration_HashlibNewWeakFiresZSPY056(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import hashlib\nh = hashlib.new(\"md5\")\n")
	if !hasRule(results, "ZS-PY-056") {
		t.Error("expected ZS-PY-056 to fire on hashlib.new(\"md5\")")
	}
}

func TestIntegration_HashlibNewStrongDoesNotFireZSPY056(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import hashlib\nh = hashlib.new(\"sha256\")\n")
	if hasRule(results, "ZS-PY-056") {
		t.Error("expected ZS-PY-056 to NOT fire on hashlib.new(\"sha256\")")
	}
}

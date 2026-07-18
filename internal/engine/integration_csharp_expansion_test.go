//go:build cgo

package engine_test

import (
	"testing"
)

// TestIntegration_DtdProcessingParseFiresZSCS020 verifies XXE-configuration detection.
func TestIntegration_DtdProcessingParseFiresZSCS020(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var settings = new XmlReaderSettings();\n" +
		"settings.DtdProcessing = DtdProcessing.Parse; } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-020") {
		t.Error("expected ZS-CS-020 to fire on DtdProcessing = DtdProcessing.Parse")
	}
}

// TestIntegration_DtdProcessingProhibitDoesNotFireZSCS020 verifies the negative case.
func TestIntegration_DtdProcessingProhibitDoesNotFireZSCS020(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var settings = new XmlReaderSettings();\n" +
		"settings.DtdProcessing = DtdProcessing.Prohibit; } }"
	if hasRule(matchCSharpSource(t, idx, src), "ZS-CS-020") {
		t.Error("expected ZS-CS-020 to NOT fire on DtdProcessing.Prohibit")
	}
}

// TestIntegration_CertValidationCallbackFiresZSCS021 verifies TLS-bypass detection.
func TestIntegration_CertValidationCallbackFiresZSCS021(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true; } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-021") {
		t.Error("expected ZS-CS-021 to fire on ServerCertificateValidationCallback assignment")
	}
}

// TestIntegration_DesCreateFiresZSCS022 verifies weak-cipher detection.
func TestIntegration_DesCreateFiresZSCS022(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var des = DES.Create(); } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-022") {
		t.Error("expected ZS-CS-022 to fire on DES.Create()")
	}
}

// TestIntegration_TypeNameHandlingAllFiresZSCS023 verifies insecure-deserialization-setting detection.
func TestIntegration_TypeNameHandlingAllFiresZSCS023(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var settings = new JsonSerializerSettings();\n" +
		"settings.TypeNameHandling = TypeNameHandling.All; } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-023") {
		t.Error("expected ZS-CS-023 to fire on TypeNameHandling.All")
	}
}

// TestIntegration_TypeNameHandlingNoneDoesNotFireZSCS023 verifies the negative case.
func TestIntegration_TypeNameHandlingNoneDoesNotFireZSCS023(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var settings = new JsonSerializerSettings();\n" +
		"settings.TypeNameHandling = TypeNameHandling.None; } }"
	if hasRule(matchCSharpSource(t, idx, src), "ZS-CS-023") {
		t.Error("expected ZS-CS-023 to NOT fire on TypeNameHandling.None")
	}
}

// TestIntegration_TaintedDirectorySearcherFilterFiresZSCS024 verifies LDAP-injection detection.
func TestIntegration_TaintedDirectorySearcherFilterFiresZSCS024(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var uid = Request.QueryString[\"uid\"];\n" +
		"var searcher = new DirectorySearcher();\n" +
		"searcher.Filter = \"(uid=\" + uid + \")\"; } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-024") {
		t.Error("expected ZS-CS-024 to fire when DirectorySearcher.Filter is assigned a tainted value")
	}
}

// TestIntegration_ConstantDirectorySearcherFilterDoesNotFireZSCS024 verifies the negative case.
func TestIntegration_ConstantDirectorySearcherFilterDoesNotFireZSCS024(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var searcher = new DirectorySearcher();\n" +
		"searcher.Filter = \"(objectClass=user)\"; } }"
	if hasRule(matchCSharpSource(t, idx, src), "ZS-CS-024") {
		t.Error("expected ZS-CS-024 to NOT fire for a constant filter")
	}
}

// TestIntegration_TaintedSelectNodesFiresZSCS025 verifies XPath-injection detection.
func TestIntegration_TaintedSelectNodesFiresZSCS025(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var login = Request.QueryString[\"login\"];\n" +
		"var doc = new XmlDocument();\n" +
		"var nodes = doc.SelectNodes(\"//user[login='\" + login + \"']\"); } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-025") {
		t.Error("expected ZS-CS-025 to fire when doc.SelectNodes argument is tainted")
	}
}

// TestIntegration_ConstantSelectNodesDoesNotFireZSCS025 verifies the negative case.
func TestIntegration_ConstantSelectNodesDoesNotFireZSCS025(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var doc = new XmlDocument();\n" +
		"var nodes = doc.SelectNodes(\"//user[login='admin']\"); } }"
	if hasRule(matchCSharpSource(t, idx, src), "ZS-CS-025") {
		t.Error("expected ZS-CS-025 to NOT fire for a constant XPath expression")
	}
}

// TestIntegration_TaintedWriteAllTextFiresZSCS026 verifies arbitrary-file-write detection.
func TestIntegration_TaintedWriteAllTextFiresZSCS026(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var destination = Request.QueryString[\"dest\"];\n" +
		"File.WriteAllText(destination, \"report body\"); } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-026") {
		t.Error("expected ZS-CS-026 to fire when File.WriteAllText path is tainted")
	}
}

// TestIntegration_ConstantWriteAllTextDoesNotFireZSCS026 verifies the negative case.
func TestIntegration_ConstantWriteAllTextDoesNotFireZSCS026(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { File.WriteAllText(\"C:/logs/report.txt\", \"report body\"); } }"
	if hasRule(matchCSharpSource(t, idx, src), "ZS-CS-026") {
		t.Error("expected ZS-CS-026 to NOT fire for a constant path and content")
	}
}

// TestIntegration_TaintedDownloadStringFiresZSCS027 verifies SSRF detection.
func TestIntegration_TaintedDownloadStringFiresZSCS027(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var url = Request.QueryString[\"url\"];\n" +
		"var client = new WebClient();\n" +
		"var body = client.DownloadString(url); } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-027") {
		t.Error("expected ZS-CS-027 to fire when client.DownloadString URL is tainted")
	}
}

// TestIntegration_ConstantDownloadStringDoesNotFireZSCS027 verifies the negative case.
func TestIntegration_ConstantDownloadStringDoesNotFireZSCS027(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var client = new WebClient();\n" +
		"var body = client.DownloadString(\"https://status.example.com/healthz\"); } }"
	if hasRule(matchCSharpSource(t, idx, src), "ZS-CS-027") {
		t.Error("expected ZS-CS-027 to NOT fire for a constant URL")
	}
}

// TestIntegration_RequireSignedTokensFalseFiresZSCS028 verifies JWT-bypass detection.
func TestIntegration_RequireSignedTokensFalseFiresZSCS028(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var parameters = new TokenValidationParameters();\n" +
		"parameters.RequireSignedTokens = false; } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-028") {
		t.Error("expected ZS-CS-028 to fire on RequireSignedTokens = false")
	}
}

// TestIntegration_ValidateIssuerSigningKeyFalseFiresZSCS028 verifies the second identifier alternation.
func TestIntegration_ValidateIssuerSigningKeyFalseFiresZSCS028(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var parameters = new TokenValidationParameters();\n" +
		"parameters.ValidateIssuerSigningKey = false; } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-028") {
		t.Error("expected ZS-CS-028 to fire on ValidateIssuerSigningKey = false")
	}
}

// TestIntegration_RequireSignedTokensTrueDoesNotFireZSCS028 verifies the negative case.
func TestIntegration_RequireSignedTokensTrueDoesNotFireZSCS028(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var parameters = new TokenValidationParameters();\n" +
		"parameters.RequireSignedTokens = true; } }"
	if hasRule(matchCSharpSource(t, idx, src), "ZS-CS-028") {
		t.Error("expected ZS-CS-028 to NOT fire on RequireSignedTokens = true")
	}
}

// TestIntegration_Sha1CreateFiresZSCS029 verifies weak-hash detection.
func TestIntegration_Sha1CreateFiresZSCS029(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var sha = SHA1.Create(); } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-029") {
		t.Error("expected ZS-CS-029 to fire on SHA1.Create()")
	}
}

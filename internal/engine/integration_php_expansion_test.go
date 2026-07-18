//go:build cgo

package engine_test

import (
	"testing"
)

// Tests for the PHP rule expansion ZS-PHP-018..026. Helpers loadPhpRules,
// matchPhpSource (integration_php_test.go) and hasRule (integration_test.go)
// are reused from the existing integration tests in this package.

// TestIntegration_TaintedEvalFiresZSPHP018 verifies eval() code-injection detection.
func TestIntegration_TaintedEvalFiresZSPHP018(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$expr = $_GET['expr'];\neval($expr);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-018") {
		t.Error("expected ZS-PHP-018 to fire when eval() argument is tainted")
	}
}

// TestIntegration_ConstantEvalDoesNotFireZSPHP018 verifies the negative case.
func TestIntegration_ConstantEvalDoesNotFireZSPHP018(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\neval('return 1 + 1;');\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-018") {
		t.Error("expected ZS-PHP-018 to NOT fire for a constant eval() argument")
	}
}

// TestIntegration_TaintedExecFiresZSPHP019 verifies exec() command-injection detection.
func TestIntegration_TaintedExecFiresZSPHP019(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$host = $_GET['host'];\nexec(\"ping -c 1 \" . $host);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-019") {
		t.Error("expected ZS-PHP-019 to fire when exec() argument is tainted")
	}
}

// TestIntegration_ConstantExecDoesNotFireZSPHP019 verifies the negative case.
func TestIntegration_ConstantExecDoesNotFireZSPHP019(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\nexec(\"ls -la\");\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-019") {
		t.Error("expected ZS-PHP-019 to NOT fire for a constant command")
	}
}

// TestIntegration_TaintedPassthruFiresZSPHP020 verifies passthru() command-injection detection.
func TestIntegration_TaintedPassthruFiresZSPHP020(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$target = $_POST['target'];\npassthru(\"nslookup \" . $target);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-020") {
		t.Error("expected ZS-PHP-020 to fire when passthru() argument is tainted")
	}
}

// TestIntegration_ConstantPassthruDoesNotFireZSPHP020 verifies the negative case.
func TestIntegration_ConstantPassthruDoesNotFireZSPHP020(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\npassthru(\"uptime\");\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-020") {
		t.Error("expected ZS-PHP-020 to NOT fire for a constant command")
	}
}

// TestIntegration_TaintedAssertFiresZSPHP021 verifies assert() code-execution detection.
func TestIntegration_TaintedAssertFiresZSPHP021(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$check = $_GET['check'];\nassert($check);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-021") {
		t.Error("expected ZS-PHP-021 to fire when assert() argument is tainted")
	}
}

// TestIntegration_ConstantAssertDoesNotFireZSPHP021 verifies the negative case.
func TestIntegration_ConstantAssertDoesNotFireZSPHP021(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\nassert(1 === 1);\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-021") {
		t.Error("expected ZS-PHP-021 to NOT fire for a constant assertion")
	}
}

// TestIntegration_ExtractSuperglobalFiresZSPHP022 verifies mass-assignment detection.
func TestIntegration_ExtractSuperglobalFiresZSPHP022(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\nextract($_POST);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-022") {
		t.Error("expected ZS-PHP-022 to fire on extract($_POST)")
	}
}

// TestIntegration_ExtractGetSuperglobalFiresZSPHP022 verifies the $_GET variant.
func TestIntegration_ExtractGetSuperglobalFiresZSPHP022(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\nextract($_GET);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-022") {
		t.Error("expected ZS-PHP-022 to fire on extract($_GET)")
	}
}

// TestIntegration_ExtractLocalArrayDoesNotFireZSPHP022 verifies the negative case.
func TestIntegration_ExtractLocalArrayDoesNotFireZSPHP022(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$row = array('a' => 1);\nextract($row);\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-022") {
		t.Error("expected ZS-PHP-022 to NOT fire for extract() on a local array")
	}
}

// TestIntegration_TaintedFopenFiresZSPHP023 verifies path-traversal detection.
func TestIntegration_TaintedFopenFiresZSPHP023(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$filename = $_GET['file'];\n$handle = fopen($filename, 'r');\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-023") {
		t.Error("expected ZS-PHP-023 to fire when fopen() path is tainted")
	}
}

// TestIntegration_ConstantFopenDoesNotFireZSPHP023 verifies the negative case.
func TestIntegration_ConstantFopenDoesNotFireZSPHP023(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$handle = fopen('/var/app/data.txt', 'r');\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-023") {
		t.Error("expected ZS-PHP-023 to NOT fire for a constant path")
	}
}

// TestIntegration_TaintedFilePutContentsFiresZSPHP024 verifies arbitrary-file-write detection.
func TestIntegration_TaintedFilePutContentsFiresZSPHP024(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$dest = $_POST['dest'];\nfile_put_contents($dest, \"log entry\");\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-024") {
		t.Error("expected ZS-PHP-024 to fire when file_put_contents() path is tainted")
	}
}

// TestIntegration_ConstantFilePutContentsDoesNotFireZSPHP024 verifies the negative case.
func TestIntegration_ConstantFilePutContentsDoesNotFireZSPHP024(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\nfile_put_contents('/var/app/app.log', \"started\");\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-024") {
		t.Error("expected ZS-PHP-024 to NOT fire for constant path and content")
	}
}

// TestIntegration_PregReplaceEModifierFiresZSPHP025 verifies /e-modifier detection.
func TestIntegration_PregReplaceEModifierFiresZSPHP025(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$name = $_GET['name'];\n$result = preg_replace('/^(.*)$/e', 'ucwords(\"\\1\")', $name);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-025") {
		t.Error("expected ZS-PHP-025 to fire on a preg_replace() pattern with the /e modifier")
	}
}

// TestIntegration_PregReplaceWithoutEModifierDoesNotFireZSPHP025 verifies the negative case:
// an /i modifier (no e) must not match.
func TestIntegration_PregReplaceWithoutEModifierDoesNotFireZSPHP025(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$name = $_GET['name'];\n$result = preg_replace('/x/i', 'y', $name);\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-025") {
		t.Error("expected ZS-PHP-025 to NOT fire for a pattern without the /e modifier")
	}
}

// TestIntegration_WeakCipherOpensslEncryptFiresZSPHP026 verifies weak-cipher detection.
func TestIntegration_WeakCipherOpensslEncryptFiresZSPHP026(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$data = \"record\";\n$out = openssl_encrypt($data, 'des-ede3', $enc_key, 0, $iv);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-026") {
		t.Error("expected ZS-PHP-026 to fire for openssl_encrypt() with des-ede3")
	}
}

// TestIntegration_Rc4CipherOpensslEncryptFiresZSPHP026 verifies another weak cipher.
func TestIntegration_Rc4CipherOpensslEncryptFiresZSPHP026(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$data = \"record\";\n$out = openssl_encrypt($data, 'rc4', $enc_key, 0, $iv);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-026") {
		t.Error("expected ZS-PHP-026 to fire for openssl_encrypt() with rc4")
	}
}

// TestIntegration_StrongCipherOpensslEncryptDoesNotFireZSPHP026 verifies the negative case.
func TestIntegration_StrongCipherOpensslEncryptDoesNotFireZSPHP026(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$data = \"record\";\n$out = openssl_encrypt($data, 'aes-256-gcm', $enc_key, 0, $iv, $tag);\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-026") {
		t.Error("expected ZS-PHP-026 to NOT fire for aes-256-gcm")
	}
}

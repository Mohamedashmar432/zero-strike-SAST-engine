package secrets

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

func findRule(fs []core.Finding, ruleID string) *core.Finding {
	for i := range fs {
		if fs[i].RuleID == ruleID {
			return &fs[i]
		}
	}
	return nil
}

func cweOf(f *core.Finding) string {
	if f == nil || len(f.CWE) != 1 {
		return ""
	}
	return f.CWE[0]
}

// Every detector must carry exactly one CWE. Secret findings used to ship with
// none, which made them invisible to SARIF consumers and CWE-keyed policy.
func TestDetectors_EveryDetectorHasCWE(t *testing.T) {
	for _, d := range detectors {
		if w := d.weakness(); w != cweHardcodedCredential && w != cweHardcodedKey {
			t.Errorf("%s (%s): weakness %q, want CWE-798 or CWE-321", d.ruleID, d.detectorID, w)
		}
	}
}

func TestSecretFinding_CarriesDetectorCWE(t *testing.T) {
	pw := scanContent("app.py", []byte(`password = "Sup3r`+`Secret!9"`))
	if got := cweOf(findRule(pw, "ZS-SEC-004")); got != "CWE-798" {
		t.Errorf("hardcoded-password CWE = %q, want CWE-798", got)
	}
	pem := scanContent("key.pem", []byte("-----BEGIN RSA PRIVATE"+" KEY-----"))
	if got := cweOf(findRule(pem, "ZS-SEC-005")); got != "CWE-321" {
		t.Errorf("private-key-pem CWE = %q, want CWE-321", got)
	}
}

func TestSecrets_RejectsRuntimeReferences(t *testing.T) {
	for _, line := range []string{
		"models.sequelize.query(`SELECT * FROM Users WHERE password = '${security.hash(req.body.password || '')}'`)",
		`TOKEN="$(cat $TOKEN_FILE)"`,
		`password: "{{ .Values.dbPassword }}"`,
		`<code>SELECT * FROM t WHERE user='admin' AND password='<b>anything' OR '1' ='1</b>'</code>`,
		`{"no_secret": "Only admin.localhost:8000 can access, Your X-Host is "}`,
		`"INVALID_TOKEN": "Ungueltiges Token angegeben"`,
	} {
		if fs := scanContent("x.txt", []byte(line)); len(fs) != 0 {
			t.Errorf("expected no finding for %q, got %s", line, fs[0].RuleID)
		}
	}
}

func TestSecrets_PasswordComparison(t *testing.T) {
	cases := []string{
		`if (req.body.email === 'admin@x.io' && req.body.password === 'adm` + `in123') {`,
		`    if password == "jackthe` + `ripper":`,
		`if request.form['password'] != 'hun` + `ter2x':`,
	}
	for _, c := range cases {
		f := findRule(scanContent("x.js", []byte(c)), "ZS-SEC-027")
		if f == nil || cweOf(f) != "CWE-798" {
			t.Errorf("expected ZS-SEC-027 CWE-798 for %q", c)
		}
	}
	for _, c := range []string{
		`assert password == "s3cr` + `etvalue"`,
		`expect(user.password === 'whatever1')`,
		`if password == "":`,
		`if (password === '${pw}') {}`,
		`if password == "changeme":`,
	} {
		if f := findRule(scanContent("x.js", []byte(c)), "ZS-SEC-027"); f != nil {
			t.Errorf("unexpected ZS-SEC-027 for %q", c)
		}
	}
}

func TestSecrets_XMLCredential(t *testing.T) {
	fs := scanContent("config.xml", []byte("\t\t\t<password>mysecret"+"password</password>"))
	if f := findRule(fs, "ZS-SEC-028"); f == nil || cweOf(f) != "CWE-798" {
		t.Fatalf("expected ZS-SEC-028, got %+v", fs)
	}
	for _, line := range []string{"<password></password>", "<password>${DB_PASSWORD}</password>", "<password>changeme</password>"} {
		if f := findRule(scanContent("c.xml", []byte(line)), "ZS-SEC-028"); f != nil {
			t.Errorf("unexpected ZS-SEC-028 for %q", line)
		}
	}
}

func TestSecrets_RPCURLKey(t *testing.T) {
	key := "Ab12Cd34" + "Ef56Gh78Ij90Kl12"
	fs := scanContent("mint.ts", []byte(`const provider = new WebSocketProvider('wss://eth-sepolia.g.alchemy.com/v2/`+key+`')`))
	if f := findRule(fs, "ZS-SEC-029"); f == nil || cweOf(f) != "CWE-798" {
		t.Fatalf("expected ZS-SEC-029, got %+v", fs)
	}
	if f := findRule(scanContent("a.ts", []byte(`'https://eth-mainnet.g.alchemy.com/v2/demo'`)), "ZS-SEC-029"); f != nil {
		t.Error("the public 'demo' key must not be reported")
	}
}

func TestSecrets_TOTPSeed(t *testing.T) {
	seed := "IFTXE3SPOEYV" + "URT2MRYGI52T"
	fs := scanContent("users.yml", []byte("  totpSecret: "+seed))
	if f := findRule(fs, "ZS-SEC-030"); f == nil || cweOf(f) != "CWE-321" {
		t.Fatalf("expected ZS-SEC-030 CWE-321, got %+v", fs)
	}
	if f := findRule(scanContent("users.yml", []byte("  totpSecret: ''")), "ZS-SEC-030"); f != nil {
		t.Error("empty seed must not be reported")
	}
}

func TestSecrets_Dotenv(t *testing.T) {
	env := "PORT=80\nJWT_SECRET=acc" + "ess\nSQL_USERNAME=root\nSQL_PASSWORD=mysecret" + "password\n" +
		"TOKEN_EXPIRES_IN=3600\nAPI_KEY=${API_KEY}\nSMTP_PASSWORD=\nSESSION_TOKEN=changeme\n"
	fs := scanContent("/repo/.env", []byte(env))
	var got []string
	for _, f := range fs {
		got = append(got, f.RuleID+"@"+string(rune('0'+f.Location.StartLine))+":"+cweOf(&f))
	}
	want := []string{"ZS-SEC-031@2:CWE-321", "ZS-SEC-031@4:CWE-798"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
	if fs := scanContent("/repo/.env.example", []byte(env)); findRule(fs, "ZS-SEC-031") != nil {
		t.Error(".env.example is a template and must not be reported")
	}
}

func TestSecrets_ComposeEnvironment(t *testing.T) {
	compose := "version: '3'\nservices:\n  db:\n    image: mysql:8\n    environment:\n" +
		"      MYSQL_ROOT_PASSWORD: mysecret" + "password\n      MYSQL_DATABASE: app\n" +
		"  web:\n    environment:\n      - API_TOKEN=tok" + "en1234value\n      - DB_PASSWORD=${DB_PASSWORD}\n" +
		"      - SECRET_KEY=${SECRET_KEY:-dev}\n"
	fs := scanContent("docker-compose.yml", []byte(compose))
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(fs), fs)
	}
	if fs[0].RuleID != "ZS-SEC-032" || fs[0].Location.StartLine != 6 || cweOf(&fs[0]) != "CWE-798" {
		t.Errorf("first finding: %+v", fs[0])
	}
	if fs[1].Location.StartLine != 10 {
		t.Errorf("second finding at line %d, want 10", fs[1].Location.StartLine)
	}
}

func TestSecretsScanner_AcceptsAssetData(t *testing.T) {
	if !New().Accepts(walker.FileEntry{Path: "static/users.yml", AssetData: true}) {
		t.Error("secrets scanner must accept AssetData entries")
	}
}

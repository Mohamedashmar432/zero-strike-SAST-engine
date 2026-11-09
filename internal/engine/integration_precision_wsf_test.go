//go:build cgo

package engine_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
)

// Precision tests for workstream F: rules whose findings production users
// tagged false positive. Each suppressed shape has a twin proving the real
// shape still fires. All values are synthetic.

type wsfCase struct {
	name string
	rule string
	src  string
	fire bool
}

func runWSF(t *testing.T, match func(string) []engine.MatchResult, cases []wsfCase) {
	t.Helper()
	for _, c := range cases {
		if got := hasRule(match(c.src), c.rule); got != c.fire {
			t.Errorf("%s: %s fired=%v, want %v", c.name, c.rule, got, c.fire)
		}
	}
}

func TestPrecisionF_SSRFHostFixedJS(t *testing.T) {
	idx := loadJSRules(t)
	runWSF(t, func(s string) []engine.MatchResult { return matchJSSource(t, idx, s) }, []wsfCase{
		{"const base template", "ZS-JS-035", "const axios = require('axios');\nfunction h(req, res) {\n  const id = req.params.id;\n  axios.get(`https://api.service.test/users/${id}`);\n}\n", false},
		{"const base concat", "ZS-JS-035", "const axios = require('axios');\nfunction h(req, res) {\n  const id = req.query.id;\n  axios.get('https://api.service.test/users/' + id);\n}\n", false},
		{"env base template", "ZS-JS-035", "const axios = require('axios');\nfunction h(req, res) {\n  const id = req.query.id;\n  axios.get(`${process.env.USER_API}/users/${id}`);\n}\n", false},
		{"module const base", "ZS-JS-035", "const axios = require('axios');\nconst BASE_URL = 'https://api.service.test';\nfunction h(req, res) {\n  const id = req.query.id;\n  axios.get(`${BASE_URL}/users/${id}`);\n}\n", false},
		{"local url built from fixed base", "ZS-JS-035", "const axios = require('axios');\nfunction h(req, res) {\n  const id = req.query.id;\n  const url = `https://api.service.test/users/${id}`;\n  axios.get(url);\n}\n", false},
		{"same-origin path", "ZS-JS-036", "const axios = require('axios');\nfunction h(req, res) {\n  axios.post('/internal/items/' + req.body.id, {});\n}\n", false},
		{"helper parameter url", "ZS-JS-035", "const axios = require('axios');\nfunction get(url) {\n  return axios.get(url);\n}\n", false},
		{"tainted url", "ZS-JS-035", "const axios = require('axios');\nfunction h(req, res) {\n  const target = req.query.url;\n  axios.get(target);\n}\n", false},
		{"tainted first operand", "ZS-JS-035", "const axios = require('axios');\nfunction h(req, res) {\n  const host = req.query.host;\n  axios.get(host + '/status');\n}\n", false},
		{"scheme only literal", "ZS-JS-035", "const axios = require('axios');\nfunction h(req, res) {\n  const host = req.query.host;\n  axios.get('https://' + host + '/status');\n}\n", false},
		{"host end then tainted suffix", "ZS-JS-036", "const axios = require('axios');\nfunction h(req, res) {\n  axios.post('https://api.service.test' + req.body.suffix, {});\n}\n", true},
		{"template tainted lead", "ZS-JS-036", "const axios = require('axios');\nfunction h(req, res) {\n  const t = req.body.endpoint;\n  axios.post(`${t}/items`, {});\n}\n", true},
	})
}

func TestPrecisionF_SSRFHostFixedTS(t *testing.T) {
	idx := loadTSRules(t)
	runWSF(t, func(s string) []engine.MatchResult { return matchTSSource(t, idx, s) }, []wsfCase{
		{"fixed host", "ZS-TS-080", "import https from 'https';\nexport function h(req: any) {\n  const id = req.query.id;\n  https.get(`https://api.service.test/v1/${id}`);\n}\n", false},
		{"helper parameter", "ZS-TS-080", "import https from 'https';\nexport function fetchPage(url: string) {\n  https.get(url);\n}\n", false},
		{"tainted url", "ZS-TS-080", "import https from 'https';\nexport function h(req: any) {\n  const url = req.query.url;\n  https.get(url);\n}\n", false},
	})
}

func TestPrecisionF_SSRFHostFixedCSharp(t *testing.T) {
	idx := loadCSharpRules(t)
	runWSF(t, func(s string) []engine.MatchResult { return matchCSharpSource(t, idx, s) }, []wsfCase{
		{"fixed host interpolated", "ZS-CS-016", "class A { async void M() { var id = Request.QueryString[\"id\"]; await httpClient.GetAsync($\"https://api.service.test/users/{id}\"); } }", false},
		{"fixed host concat", "ZS-CS-016", "class A { async void M() { var id = Request.QueryString[\"id\"]; await httpClient.GetAsync(\"https://api.service.test/users/\" + id); } }", false},
		{"config base", "ZS-CS-016", "class A { async void M() { var id = Request.QueryString[\"id\"]; await httpClient.GetAsync($\"{baseUrl}/users/{id}\"); } }", false},
		{"helper parameter", "ZS-CS-016", "class A { async void M(string url) { await httpClient.GetAsync(url); } }", false},
		{"tainted url", "ZS-CS-016", "class A { async void M() { var url = Request.QueryString[\"url\"]; await httpClient.GetAsync(url); } }", false},
		{"tainted interpolated host", "ZS-CS-016", "class A { async void M() { var host = Request.QueryString[\"h\"]; await httpClient.GetAsync($\"https://{host}/status\"); } }", false},
	})
}

func TestPrecisionF_BareParameterWrappers(t *testing.T) {
	jsIdx := loadJSRules(t)
	runWSF(t, func(s string) []engine.MatchResult { return matchJSSource(t, jsIdx, s) }, []wsfCase{
		{"sequelize wrapper", "ZS-JS-011", "function run(sql) {\n  return db.sequelize.query(sql);\n}\n", false},
		{"sequelize built from param", "ZS-JS-011", "function find(login) {\n  return db.sequelize.query(\"SELECT * FROM users WHERE login='\" + login + \"'\");\n}\n", false},
		{"sequelize built in local", "ZS-JS-011", "function find(login) {\n  const q = \"SELECT * FROM users WHERE login='\" + login + \"'\";\n  return db.sequelize.query(q);\n}\n", false},
		{"sequelize from request", "ZS-JS-011", "const login = req.body.login;\ndb.sequelize.query(\"SELECT * FROM users WHERE login='\" + login + \"'\");\n", false},
		{"exec wrapper", "ZS-JS-012", "const { exec } = require('child_process');\nfunction run(cmd) {\n  exec(cmd, function (err, out) {});\n}\n", false},
		{"exec built from param", "ZS-JS-012", "const { exec } = require('child_process');\nfunction ping(host) {\n  const cmd = 'ping -c 2 ' + host;\n  exec(cmd, function (err, out) {});\n}\n", false},
		{"exec from request", "ZS-JS-012", "const { exec } = require('child_process');\nconst address = req.body.address;\nexec('ping -c 2 ' + address, function (err, out) {});\n", false},
	})
	_, pyIdx := loadPythonRules(t)
	runWSF(t, func(s string) []engine.MatchResult { return matchSource(t, pyIdx, s) }, []wsfCase{
		{"execute wrapper", "ZS-PY-004", "def run(sql):\n    cursor.execute(sql)\n", false},
		{"execute formatted param", "ZS-PY-004", "def find(name):\n    q = \"SELECT * FROM t WHERE n = '%s'\" % name\n    cursor.execute(q)\n", false},
		{"execute inline format", "ZS-PY-004", "def find(name):\n    cursor.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)\n", false},
		{"execute request", "ZS-PY-004", "user_id = request.args.get('id')\nquery = \"SELECT \" + user_id\ncursor.execute(query)\n", false},
		{"fromstring wrapper", "ZS-PY-032", "import xml.etree.ElementTree as ET\ndef parse(xml):\n    return ET.fromstring(xml)\n", false},
		{"fromstring request", "ZS-PY-032", "import xml.etree.ElementTree as ET\nfrom flask import request\nxml_data = request.form['xml']\nET.fromstring(xml_data)\n", false},
	})
	csIdx := loadCSharpRules(t)
	runWSF(t, func(s string) []engine.MatchResult { return matchCSharpSource(t, csIdx, s) }, []wsfCase{
		{"format wrapper", "ZS-CS-019", "class A { string Log(string format, object a) { return string.Format(format, a); } }", false},
		{"format from request", "ZS-CS-019", "class A { string M() { var f = Request.QueryString[\"f\"]; return string.Format(f, 1); } }", true},
	})
}

func TestPrecisionF_ExecCallbackParametersAreNotTheCommand(t *testing.T) {
	idx := loadJSRules(t)
	runWSF(t, func(s string) []engine.MatchResult { return matchJSSource(t, idx, s) }, []wsfCase{
		{"constant command with callback", "ZS-JS-012", "const { exec } = require('child_process');\nexec('ls -l', (error, stdout, stderr) => {\n  console.log(stdout);\n});\n", false},
		{"tainted command with callback", "ZS-JS-012", "const { exec } = require('child_process');\nconst dir = req.query.dir;\nexec('ls ' + dir, (error, stdout, stderr) => {\n  console.log(stdout);\n});\n", false},
	})
}

func TestPrecisionF_CSharpCredentialNamesAndMessages(t *testing.T) {
	idx := loadCSharpRules(t)
	runWSF(t, func(s string) []engine.MatchResult { return matchCSharpSource(t, idx, s) }, []wsfCase{
		{"field name constant", "ZS-CS-006", "class A { void M() { var passwordFieldName = \"Password\"; } }", false},
		{"endpoint constant", "ZS-CS-006", "class A { void M() { var tokenEndpoint = \"connect-token\"; } }", false},
		{"header name", "ZS-CS-006", "class A { void M() { var apiKeyHeader = \"X-Api-Key\"; } }", false},
		{"message sentence", "ZS-CS-006", "class A { void M() { var passwordError = \"Invalid user name or password\"; } }", false},
		{"route", "ZS-CS-006", "class A { void M() { var tokenRoute = \"/connect/token\"; } }", false},
		{"literal password", "ZS-CS-006", "class A { void M() { var password = \"hunter2\"; } }", true},
		{"literal api key", "ZS-CS-006", "class A { void M() { var apiKey = \"sk-1234567890abcdef\"; } }", true},
		{"secret key field", "ZS-CS-006", "class A { void M() { var secretKey = \"Zx9-Qw4-Lm2\"; } }", true},
	})
}

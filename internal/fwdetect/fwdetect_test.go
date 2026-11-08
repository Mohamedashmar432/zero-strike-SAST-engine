package fwdetect

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

func detectOne(t *testing.T, d *Detector, path string, lang core.Language, src string) map[string]Detected {
	t.Helper()
	out := map[string]Detected{}
	for _, x := range d.Detect(path, lang, []byte(src)) {
		out[x.Framework] = x
	}
	return out
}

func TestProfilesLoad(t *testing.T) {
	want := []string{"aspnet-framework", "aspnetcore", "django", "echo", "express", "fastapi", "fastify", "flask", "gin", "laravel", "nestjs", "nextjs", "php-plain", "spring"}
	if got := Names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for _, name := range want {
		p := ProfileFor(name)
		if len(p.Sources) == 0 && name != "" {
			t.Errorf("%s: no request sources", name)
		}
	}
}

func TestFileEvidence(t *testing.T) {
	d := New(nil)
	cases := []struct {
		name  string
		lang  core.Language
		src   string
		want  string // framework expected high
		label string // substring of an evidence label
	}{
		{"aspnetcore using", core.LangCSharp, "using Microsoft.AspNetCore.Mvc;\nclass A {}", "aspnetcore", "using Microsoft.AspNetCore"},
		{"aspnetcore ApiController", core.LangCSharp, "[ApiController]\npublic class A {}", "aspnetcore", "ApiController"},
		{"aspnetcore ControllerBase", core.LangCSharp, "public class A : ControllerBase {}", "aspnetcore", "ControllerBase"},
		{"aspnetcore PageModel", core.LangCSharp, "public class A : PageModel {}", "aspnetcore", "PageModel"},
		{"aspnetcore minimal api", core.LangCSharp, "var app = WebApplication.CreateBuilder(args).Build();", "aspnetcore", "CreateBuilder"},
		{"mvc5 using", core.LangCSharp, "using System.Web.Mvc;\nclass A : Controller {}", "aspnet-framework", "System.Web.Mvc"},
		{"webapi using", core.LangCSharp, "using System.Web.Http;\nclass A : ApiController {}", "aspnet-framework", "System.Web.Http"},
		{"webforms page", core.LangCSharp, "using System.Web.UI;\npublic partial class P : Page {}", "aspnet-framework", "System.Web.UI"},
		{"fastify require", core.LangJavaScript, "const fastify = require('fastify')({ logger: true })", "fastify", "imports fastify"},
		{"fastify import ts", core.LangTypeScript, "import Fastify from \"fastify\"", "fastify", "imports fastify"},
		{"fastify scoped package", core.LangJavaScript, "const cors = require('@fastify/cors')", "fastify", "@fastify"},
		{"fastify plugin signature", core.LangJavaScript, "module.exports = async function (fastify, opts) { fastify.get('/', h) }", "fastify", "plugin function"},
		{"express require", core.LangJavaScript, "const express = require('express')", "express", "imports express"},
		{"laravel use", core.LangPHP, "<?php\nuse Illuminate\\Http\\Request;", "laravel", "Illuminate"},
		{"laravel namespace", core.LangPHP, "<?php\nnamespace App\\Http\\Controllers;", "laravel", "Controllers"},
		{"laravel route", core.LangPHP, "<?php\nRoute::get('/x', 'C@a');", "laravel", "Route::"},
		{"php-plain superglobal", core.LangPHP, "<?php\n$x = $_GET['x'];", "php-plain", "superglobal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := detectOne(t, d, "f.src", c.lang, c.src)[c.want]
			if !ok || got.Confidence != High {
				t.Fatalf("want %s high, got %+v", c.want, got)
			}
			if !strings.Contains(strings.Join(got.Evidence, "|"), c.label) {
				t.Errorf("evidence %v lacks %q", got.Evidence, c.label)
			}
		})
	}
}

func TestNoEvidenceNoDetection(t *testing.T) {
	d := New(nil)
	for lang, src := range map[core.Language]string{
		core.LangCSharp:     "public class Plain { public void Run(string s) {} }",
		core.LangJavaScript: "function run(a) { return a + 1 }",
		core.LangPHP:        "<?php\nfunction run($a) { return $a; }",
	} {
		if got := d.Detect("f.src", lang, []byte(src)); len(got) != 0 {
			t.Errorf("%s: unexpected detection %+v", lang, got)
		}
	}
	// A framework only counts for the languages its profile names.
	if got := d.Detect("f.php", core.LangPHP, []byte("using Microsoft.AspNetCore.Mvc;")); len(got) != 0 {
		t.Errorf("C# evidence detected in PHP: %+v", got)
	}
}

func writeFiles(t *testing.T, files map[string]string) (string, []string) {
	t.Helper()
	root := t.TempDir()
	var paths []string
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	return root, paths
}

func TestManifestEvidenceIsMedium(t *testing.T) {
	root, paths := writeFiles(t, map[string]string{
		"core/App.csproj":      `<Project Sdk="Microsoft.NET.Sdk.Web"></Project>`,
		"core/Svc/Helper.cs":   "class Helper {}",
		"mvc/packages.config":  `<package id="Microsoft.AspNet.Mvc" version="5.2.9" />`,
		"mvc/Models/Thing.cs":  "class Thing {}",
		"web/package.json":     `{"dependencies": {"fastify": "^4.0.0"}}`,
		"web/src/util.js":      "module.exports = function () {}",
		"shop/composer.json":   `{"require": {"laravel/framework": "^10"}}`,
		"shop/app/Model.php":   "<?php class Model {}",
		"other/package.json":   `{"dependencies": {"left-pad": "1"}}`,
		"other/src/lib.js":     "module.exports = 1",
		"api/package.json":     `{"dependencies": {"express": "4"}}`,
		"api/routes/index.js":  "module.exports = 1",
		"net/Legacy.csproj":    `<Project><ItemGroup><Reference Include="System.Web.Mvc" /></ItemGroup></Project>`,
		"net/Controllers/A.cs": "class A {}",
	})
	d := New(paths)
	cases := []struct {
		rel  string
		lang core.Language
		want string
	}{
		{"core/Svc/Helper.cs", core.LangCSharp, "aspnetcore"},
		{"mvc/Models/Thing.cs", core.LangCSharp, "aspnet-framework"},
		{"net/Controllers/A.cs", core.LangCSharp, "aspnet-framework"},
		{"web/src/util.js", core.LangJavaScript, "fastify"},
		{"shop/app/Model.php", core.LangPHP, "laravel"},
		{"api/routes/index.js", core.LangJavaScript, "express"},
	}
	for _, c := range cases {
		t.Run(c.rel, func(t *testing.T) {
			p := filepath.Join(root, filepath.FromSlash(c.rel))
			src, _ := os.ReadFile(p)
			got, ok := detectOne(t, d, p, c.lang, string(src))[c.want]
			if !ok || got.Confidence != Medium {
				t.Fatalf("want %s medium, got %+v", c.want, got)
			}
			if len(got.Evidence) == 0 {
				t.Error("medium detection carries no evidence")
			}
		})
	}
	// A manifest naming no known framework, and a sibling project's manifest,
	// contribute nothing.
	p := filepath.Join(root, "other/src/lib.js")
	if got := d.Detect(p, core.LangJavaScript, []byte("module.exports = 1")); len(got) != 0 {
		t.Errorf("unrelated package.json produced %+v", got)
	}
}

func TestFileEvidenceUpgradesManifestToHigh(t *testing.T) {
	root, paths := writeFiles(t, map[string]string{
		"web/package.json": `{"dependencies": {"fastify": "^4.0.0"}}`,
		"web/app.js":       "const f = require('fastify')()",
	})
	d := New(paths)
	p := filepath.Join(root, "web", "app.js")
	got := detectOne(t, d, p, core.LangJavaScript, "const f = require('fastify')()")["fastify"]
	if got.Confidence != High {
		t.Fatalf("confidence = %s, want high", got.Confidence)
	}
	if !strings.Contains(strings.Join(got.Evidence, "|"), "package.json") {
		t.Errorf("manifest label missing from evidence %v", got.Evidence)
	}
}

func TestSummaries(t *testing.T) {
	d := New(nil)
	d.Detect("a.cs", core.LangCSharp, []byte("using Microsoft.AspNetCore.Mvc;"))
	d.Detect("b.cs", core.LangCSharp, []byte("[ApiController] class B {}"))
	d.Detect("c.php", core.LangPHP, []byte("<?php $a = $_GET['a'];"))
	got := d.Summaries()
	want := []Summary{{"aspnetcore", High, 2}, {"php-plain", High, 1}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Summaries() = %+v, want %+v", got, want)
	}
}

func TestConditionalSources(t *testing.T) {
	p := ProfileFor("aspnet-framework")
	plain := p.SourcesFor([]string{"using System.Web.Mvc"})
	forms := p.SourcesFor([]string{"using System.Web.UI"})
	if len(forms) <= len(plain) {
		t.Fatalf("Web Forms evidence should add the .Text source (plain=%d forms=%d)", len(plain), len(forms))
	}
}

func TestSourcePatterns(t *testing.T) {
	match := func(framework, text string) bool {
		for _, re := range ProfileFor(framework).Sources {
			if re.MatchString(text) {
				return true
			}
		}
		return false
	}
	yes := map[string][]string{
		"aspnetcore":       {`Request.Query["q"]`, `HttpContext.Request.Form["a"]`, `Request.Headers["X"]`, `Request.Cookies["c"]`, `Request.RouteValues["id"]`},
		"aspnet-framework": {`Request.QueryString["q"]`, `Request.Params["p"]`, `Request.Form["f"]`, `Request["k"]`},
		"fastify":          {`request.query.id`, `request.body`, `req.params.name`, `request.headers.host`, `request.cookies.sid`},
		"laravel":          {`$request->input('q')`, `$request->query('q')`, `$request->all()`, `$request->cookie('c')`, `$request->header('h')`, `$request->route('r')`, `request('q')`, `Request::input('q')`, `$request->name`},
		"php-plain":        {`$_GET['a']`, `$_POST`, `$_COOKIE['c']`},
	}
	for fw, texts := range yes {
		for _, text := range texts {
			if !match(fw, text) {
				t.Errorf("%s: %q should be a source", fw, text)
			}
		}
	}
	no := map[string][]string{
		"aspnetcore": {`Response.Headers["X"]`, `_logger.Query`},
		"fastify":    {`reply.send`, `this.queryCache`},
		"laravel":    {`$request->user()`, `$this->input('q')`},
	}
	for fw, texts := range no {
		for _, text := range texts {
			if match(fw, text) {
				t.Errorf("%s: %q should not be a source", fw, text)
			}
		}
	}
}

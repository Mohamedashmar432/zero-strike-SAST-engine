package fwdetect

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// File-level evidence for the round-5 framework profiles: each case must give
// "high" and name the evidence.
func TestFileEvidenceWebFrameworks(t *testing.T) {
	d := New(nil)
	cases := []struct {
		name  string
		lang  core.Language
		src   string
		want  string
		label string
	}{
		{"spring import", core.LangJava, "import org.springframework.web.bind.annotation.GetMapping;\nclass A {}", "spring", "Spring web"},
		{"spring rest controller", core.LangJava, "@RestController\nclass A {}", "spring", "RestController"},
		{"spring controller", core.LangJava, "@Controller\nclass A {}", "spring", "RestController"},
		{"spring mapping", core.LangJava, "class A { @PostMapping(\"/x\") void m() {} }", "spring", "request mapping"},
		{"django http", core.LangPython, "from django.http import HttpResponse\n", "django", "django.http"},
		{"django shortcuts", core.LangPython, "from django.shortcuts import render\n", "django", "django.shortcuts"},
		{"django views", core.LangPython, "from django.views.generic import View\n", "django", "django.views"},
		{"django urls", core.LangPython, "from django.urls import path\n", "django", "django.urls"},
		{"django drf", core.LangPython, "from rest_framework.decorators import api_view\n", "django", "rest_framework"},
		{"flask import", core.LangPython, "from flask import Flask, request\n", "flask", "imports flask"},
		{"flask plain import", core.LangPython, "import flask\n", "flask", "imports flask"},
		{"fastapi import", core.LangPython, "from fastapi import FastAPI\n", "fastapi", "imports fastapi"},
		{"fastapi submodule", core.LangPython, "from fastapi.responses import JSONResponse\n", "fastapi", "imports fastapi"},
		{"nestjs import", core.LangTypeScript, "import { Controller } from '@nestjs/common';", "nestjs", "@nestjs"},
		{"nextjs server", core.LangTypeScript, "import { NextResponse } from 'next/server';", "nextjs", "next/server"},
		{"nextjs headers", core.LangTypeScript, "import { cookies } from \"next/headers\";", "nextjs", "next/headers"},
		{"nextjs api type", core.LangTypeScript, "import type { NextApiRequest } from 'next'", "nextjs", "Next API"},
		{"nextjs gssp", core.LangJavaScript, "export async function getServerSideProps(ctx) {}", "nextjs", "getServerSideProps"},
		{"nextjs use server", core.LangTypeScript, "'use server'\nexport async function save() {}", "nextjs", "use server"},
		{"gin import", core.LangGo, "import \"github.com/gin-gonic/gin\"", "gin", "imports gin"},
		{"echo import", core.LangGo, "import \"github.com/labstack/echo/v4\"", "echo", "imports echo"},
		{"echo v3 import", core.LangGo, "import \"github.com/labstack/echo\"", "echo", "imports echo"},
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

func TestNoEvidenceNoDetectionWebFrameworks(t *testing.T) {
	d := New(nil)
	for lang, src := range map[core.Language]string{
		core.LangJava:       "class Plain { void run(String s) {} }",
		core.LangPython:     "def run(a):\n    return a\n",
		core.LangGo:         "package main\nfunc run(a string) string { return a }\n",
		core.LangTypeScript: "export function run(a: string) { return a }",
	} {
		if got := d.Detect("f.src", lang, []byte(src)); len(got) != 0 {
			t.Errorf("%s: unexpected detection %+v", lang, got)
		}
	}
	// django models and settings are not web-facing: no detection on the bare
	// django import, so a models helper keeps default seeding.
	if got := d.Detect("models.py", core.LangPython, []byte("from django.db import models\n")); len(got) != 0 {
		t.Errorf("django.db import detected: %+v", got)
	}
	// Evidence for one language does not leak into another.
	if got := d.Detect("f.java", core.LangJava, []byte("from flask import Flask")); len(got) != 0 {
		t.Errorf("python evidence detected in Java: %+v", got)
	}
}

func TestManifestEvidenceWebFrameworks(t *testing.T) {
	root, paths := writeFiles(t, map[string]string{
		"mvn/pom.xml":             "<dependency><artifactId>spring-boot-starter-web</artifactId></dependency>",
		"mvn/src/Svc.java":        "class Svc {}",
		"gradle/build.gradle":     "implementation 'org.springframework.boot:spring-boot-starter-web'",
		"gradle/src/Svc.java":     "class Svc {}",
		"dj/requirements.txt":     "Django==4.2\nrequests\n",
		"dj/app/util.py":          "def f(): pass\n",
		"fl/requirements-dev.txt": "flask>=2.0\n",
		"fl/app.py":               "def f(): pass\n",
		"fa/pyproject.toml":       "[project]\ndependencies = [\"fastapi>=0.100\"]\n",
		"fa/main.py":              "def f(): pass\n",
		"nest/package.json":       `{"dependencies": {"@nestjs/core": "^10"}}`,
		"nest/src/svc.ts":         "export const x = 1",
		"next/package.json":       `{"dependencies": {"next": "14.0.0"}}`,
		"next/lib/util.ts":        "export const x = 1",
		"gin/go.mod":              "module x\n\nrequire github.com/gin-gonic/gin v1.9.0\n",
		"gin/util.go":             "package main\n",
		"ech/go.mod":              "module x\n\nrequire github.com/labstack/echo/v4 v4.11.0\n",
		"ech/util.go":             "package main\n",
		"plain/requirements.txt":  "requests\n",
		"plain/util.py":           "def f(): pass\n",
		"plain2/requirements.txt": "django-extensions\n",
		"plain2/util.py":          "def f(): pass\n",
	})
	d := New(paths)
	cases := []struct {
		rel  string
		lang core.Language
		want string
	}{
		{"mvn/src/Svc.java", core.LangJava, "spring"},
		{"gradle/src/Svc.java", core.LangJava, "spring"},
		{"dj/app/util.py", core.LangPython, "django"},
		{"fl/app.py", core.LangPython, "flask"},
		{"fa/main.py", core.LangPython, "fastapi"},
		{"nest/src/svc.ts", core.LangTypeScript, "nestjs"},
		{"next/lib/util.ts", core.LangTypeScript, "nextjs"},
		{"gin/util.go", core.LangGo, "gin"},
		{"ech/util.go", core.LangGo, "echo"},
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
	for _, rel := range []string{"plain/util.py", "plain2/util.py"} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if got := d.Detect(p, core.LangPython, []byte("def f(): pass\n")); len(got) != 0 {
			t.Errorf("%s: unrelated requirements produced %+v", rel, got)
		}
	}
	// File evidence upgrades a manifest-only detection to high.
	p := filepath.Join(root, "gin/util.go")
	got := detectOne(t, d, p, core.LangGo, "package main\nimport \"github.com/gin-gonic/gin\"\n")["gin"]
	if got.Confidence != High || !strings.Contains(strings.Join(got.Evidence, "|"), "go.mod") {
		t.Errorf("gin with import and go.mod = %+v, want high with the manifest label", got)
	}
}

func TestWebFrameworkSourcePatterns(t *testing.T) {
	match := func(framework, text string) bool {
		for _, re := range ProfileFor(framework).Sources {
			if re.MatchString(text) {
				return true
			}
		}
		return false
	}
	yes := map[string][]string{
		"spring":  {`request.getParameter("q")`, `req.getHeader("X")`, `r.getCookies()`, `request.getQueryString()`},
		"django":  {`request.GET.get('q')`, `request.POST['a']`, `request.body`, `request.COOKIES['c']`, `request.META['X']`, `request.FILES['f']`},
		"flask":   {`request.args.get('q')`, `request.form['a']`, `request.get_json()`, `request.cookies.get('c')`, `request.files['f']`, `request.values['v']`, `request.path`},
		"fastapi": {`request.query_params['q']`, `await request.json()`, `request.headers['h']`},
		"nestjs":  {`req.query.id`, `request.body`, `req.params.id`},
		"nextjs":  {`request.nextUrl.searchParams.get('q')`, `await request.json()`, `req.query.id`, `formData.get('a')`, `cookies().get('c')`, `req.body`},
		"gin":     {`c.Query("q")`, `ctx.Param("id")`, `c.PostForm("a")`, `c.GetHeader("h")`, `c.Cookie("c")`, `c.DefaultQuery("q", "d")`},
		"echo":    {`c.QueryParam("q")`, `ctx.Param("id")`, `c.FormValue("a")`, `c.Request().Header.Get("h")`},
	}
	for fw, texts := range yes {
		for _, text := range texts {
			if !match(fw, text) {
				t.Errorf("%s: %q should be a source", fw, text)
			}
		}
	}
	no := map[string][]string{
		"django": {`request.user`, `self.request_count`},
		"flask":  {`request.method`, `app.config['X']`},
		"gin":    {`c.JSON(200, x)`, `c.String(200, s)`},
		"echo":   {`c.JSON(200, x)`},
		"spring": {`model.addAttribute("a", b)`},
	}
	for fw, texts := range no {
		for _, text := range texts {
			if match(fw, text) {
				t.Errorf("%s: %q should not be a source", fw, text)
			}
		}
	}
}

func fnNode(parent *ir.IRNode, attrs map[string]any) *ir.IRNode {
	n := &ir.IRNode{Kind: ir.NodeKindFunction, Attrs: attrs, Parent: parent}
	if parent != nil {
		parent.Children = append(parent.Children, n)
	}
	return n
}

// An entry point's request-bound parameters are strong when an annotation binds
// them and weak when only the entry point's position does.
func TestParamsSplitStrength(t *testing.T) {
	root := &ir.IRNode{Kind: ir.NodeKindModule, Attrs: map[string]any{}}

	flask := ProfileFor("flask").Index(root)
	route := fnNode(root, map[string]any{"parameters": []string{"uid"}, "decorators": []string{"app.route"}})
	strong, weak := flask.ParamsSplit(route)
	if len(strong) != 0 || !reflect.DeepEqual(weak, []string{"uid"}) {
		t.Errorf("flask route variable: strong=%v weak=%v, want weak [uid]", strong, weak)
	}
	helper := fnNode(root, map[string]any{"parameters": []string{"x"}})
	if s, w := flask.ParamsSplit(helper); len(s)+len(w) != 0 {
		t.Errorf("undecorated helper bound %v %v", s, w)
	}

	spring := ProfileFor("spring").Index(root)
	class := &ir.IRNode{Kind: ir.NodeKindClass, Attrs: map[string]any{"attributes": []string{"RestController"}, "class_name": "C"}, Parent: root}
	root.Children = append(root.Children, class)
	method := fnNode(class, map[string]any{
		"function_name": "m",
		"attributes":    []string{"GetMapping"},
		"parameters":    []string{"id", "name", "req", "user"},
		"param_types":   []string{"String", "String", "HttpServletRequest", "WebGoatUser"},
		"param_attrs":   []string{"RequestParam", "", "", "AuthenticationPrincipal"},
	})
	strong, weak = spring.ParamsSplit(method)
	if !reflect.DeepEqual(strong, []string{"id"}) || !reflect.DeepEqual(weak, []string{"name"}) {
		t.Errorf("spring: strong=%v weak=%v, want strong [id] weak [name] (request object and principal excluded)", strong, weak)
	}
	unmapped := fnNode(class, map[string]any{"function_name": "n", "parameters": []string{"id"}, "param_types": []string{"String"}, "param_attrs": []string{""}})
	if s, w := spring.ParamsSplit(unmapped); len(s)+len(w) != 0 {
		t.Errorf("unmapped controller method bound %v %v", s, w)
	}
	// An annotated parameter is bound wherever its method sits.
	free := fnNode(root, map[string]any{"parameters": []string{"q"}, "param_types": []string{"String"}, "param_attrs": []string{"RequestParam"}})
	if s, _ := spring.ParamsSplit(free); !reflect.DeepEqual(s, []string{"q"}) {
		t.Errorf("annotated parameter outside an entry point: %v", s)
	}
}

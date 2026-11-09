//go:build cgo

package pipeline_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/pipeline"
)

// scanFiles writes files (relative path -> content) under a temp root, scans
// them with the full pipeline and returns the result.
func scanFiles(t *testing.T, files map[string]string) *pipeline.ScanResult {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pipe, err := pipeline.New(pipeline.ScanConfig{RootPath: root, WorkerCount: 1, NoCache: true})
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	res, err := pipe.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

// firedAt reports whether ruleID produced a finding on the first source line
// containing marker.
func firedAt(t *testing.T, res *pipeline.ScanResult, src, ruleID, marker string) bool {
	t.Helper()
	line := 0
	for i, l := range strings.Split(src, "\n") {
		if strings.Contains(l, marker) {
			line = i + 1
			break
		}
	}
	if line == 0 {
		t.Fatalf("marker %q not in source", marker)
	}
	for _, f := range res.Findings {
		if f.RuleID == ruleID && f.Location.StartLine == line {
			return true
		}
	}
	return false
}

func expect(t *testing.T, res *pipeline.ScanResult, src, ruleID, marker string, want bool) {
	t.Helper()
	if got := firedAt(t, res, src, ruleID, marker); got != want {
		t.Errorf("%s at %q: fired=%v, want %v", ruleID, marker, got, want)
	}
}

// Every case below has the same three sinks: a controller/handler sink fed by
// a request-bound value, a helper sink fed by the helper's parameter, and (in
// the "called with tainted" variants) a helper that a handler passes request
// data to.

const coreController = `using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

public class RunController : ControllerBase
{
    [HttpGet("run")]
    public IActionResult Run(string cmd)
    {
        Process.Start(cmd); // SINK_ACTION
        Spawn("ls");
        return Ok();
    }

    private void Spawn(string exe)
    {
        Process.Start(exe); // SINK_HELPER
    }
}
`

func TestFramework_AspNetCore(t *testing.T) {
	res := scanFiles(t, map[string]string{"RunController.cs": coreController})
	expect(t, res, coreController, "ZS-CS-001", "SINK_ACTION", true)
	expect(t, res, coreController, "ZS-CS-001", "SINK_HELPER", false)
}

func TestFramework_AspNetCoreHelperCalledWithTaint(t *testing.T) {
	src := strings.Replace(coreController, `Spawn("ls");`, `Spawn(cmd);`, 1)
	res := scanFiles(t, map[string]string{"RunController.cs": src})
	expect(t, res, src, "ZS-CS-001", "SINK_ACTION", true)
	expect(t, res, src, "ZS-CS-001", "SINK_HELPER", true)
}

func TestFramework_AspNetCoreInlineSourceAndHelper(t *testing.T) {
	src := `using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

public class RunController : ControllerBase
{
    [HttpGet("run")]
    public IActionResult Run()
    {
        Spawn(Request.Query["cmd"]);
        Process.Start(Request.Query["cmd2"]); // SINK_INLINE
        return Ok();
    }

    private void Spawn(string exe)
    {
        Process.Start(exe); // SINK_HELPER
    }
}
`
	res := scanFiles(t, map[string]string{"RunController.cs": src})
	expect(t, res, src, "ZS-CS-001", "SINK_INLINE", true)
	expect(t, res, src, "ZS-CS-001", "SINK_HELPER", true)
}

func TestFramework_AspNetCoreMinimalApiLambda(t *testing.T) {
	src := `using Microsoft.AspNetCore.Builder;
using System.Diagnostics;

var app = WebApplication.CreateBuilder(args).Build();
app.MapGet("/run", (string cmd) =>
{
    Process.Start(cmd); // SINK_LAMBDA
    return "ok";
});
static void Spawn(string exe)
{
    Process.Start(exe); // SINK_HELPER
}
app.Run();
`
	res := scanFiles(t, map[string]string{"Program.cs": src})
	expect(t, res, src, "ZS-CS-001", "SINK_LAMBDA", true)
	expect(t, res, src, "ZS-CS-001", "SINK_HELPER", false)
}

func TestFramework_AspNetCoreBoundParameterOutsideEntryPoint(t *testing.T) {
	src := `using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

public class Svc
{
    public void Spawn([FromQuery] string exe)
    {
        Process.Start(exe); // SINK_BOUND
    }
    // A different name: the taint map is keyed by name for the whole file, so
    // a second "exe" would share the bound one's verdict.
    public void Other(string other)
    {
        Process.Start(other); // SINK_PLAIN
    }
}
`
	res := scanFiles(t, map[string]string{"Svc.cs": src})
	expect(t, res, src, "ZS-CS-001", "SINK_BOUND", true)
	expect(t, res, src, "ZS-CS-001", "SINK_PLAIN", false)
}

func TestFramework_AspNetCoreInjectedServiceNotTainted(t *testing.T) {
	src := `using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

[ApiController]
public class RunController : ControllerBase
{
    public IActionResult Run(string cmd, [FromServices] Launcher launcher)
    {
        launcher.Go(); // not a sink
        return Ok();
    }

    public RunController(string baseDir)
    {
        Process.Start(baseDir); // SINK_CTOR
    }
}
`
	res := scanFiles(t, map[string]string{"RunController.cs": src})
	expect(t, res, src, "ZS-CS-001", "SINK_CTOR", false)
}

func TestFramework_NoFrameworkKeepsParameterSeeding(t *testing.T) {
	// The same code with no framework evidence: both sinks fire as before.
	src := strings.NewReplacer(
		"using Microsoft.AspNetCore.Mvc;\n", "",
		"public class RunController : ControllerBase", "public class RunController",
		`[HttpGet("run")]`, "",
		"IActionResult", "string",
		"return Ok();", `return "ok";`,
	).Replace(coreController)
	res := scanFiles(t, map[string]string{"RunController.cs": src})
	expect(t, res, src, "ZS-CS-001", "SINK_ACTION", true)
	expect(t, res, src, "ZS-CS-001", "SINK_HELPER", true)
}

func TestFramework_ManifestOnlyKeepsParameterSeeding(t *testing.T) {
	// A .csproj vouches for ASP.NET Core (medium) but the file itself has no
	// evidence, so seeding is unchanged.
	src := `using System.Diagnostics;
public class Svc
{
    public void Spawn(string exe)
    {
        Process.Start(exe); // SINK_HELPER
    }
}
`
	res := scanFiles(t, map[string]string{
		"App.csproj": `<Project Sdk="Microsoft.NET.Sdk.Web"></Project>`,
		"Svc.cs":     src,
	})
	expect(t, res, src, "ZS-CS-001", "SINK_HELPER", true)
}

const mvc5Controller = `using System.Diagnostics;
using System.Web.Mvc;

public class RunController : Controller
{
    public ActionResult Run(string cmd)
    {
        var raw = Request.QueryString["raw"];
        Process.Start(raw); // SINK_SOURCE
        Process.Start(cmd); // SINK_ACTION
        Spawn("ls");
        return Content("ok");
    }

    private void Spawn(string exe)
    {
        Process.Start(exe); // SINK_HELPER
    }
}
`

func TestFramework_AspNetFrameworkMvc5(t *testing.T) {
	res := scanFiles(t, map[string]string{"RunController.cs": mvc5Controller})
	expect(t, res, mvc5Controller, "ZS-CS-001", "SINK_SOURCE", true)
	expect(t, res, mvc5Controller, "ZS-CS-001", "SINK_ACTION", true)
	expect(t, res, mvc5Controller, "ZS-CS-001", "SINK_HELPER", false)
}

func TestFramework_AspNetFrameworkWebForms(t *testing.T) {
	src := `using System;
using System.Diagnostics;
using System.Web.UI;

public partial class RunPage : Page
{
    protected void Button_Click(object sender, EventArgs e)
    {
        Process.Start(CmdBox.Text); // SINK_TEXT
        Spawn("ls");
    }

    private void Spawn(string exe)
    {
        Process.Start(exe); // SINK_HELPER
    }
}
`
	res := scanFiles(t, map[string]string{"Run.aspx.cs": src})
	expect(t, res, src, "ZS-CS-001", "SINK_TEXT", true)
	expect(t, res, src, "ZS-CS-001", "SINK_HELPER", false)
}

const laravelController = `<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class RunController extends Controller
{
    public function run(Request $request, $id)
    {
        $cmd = $request->input('cmd');
        system($cmd); // SINK_INPUT
        system($id); // SINK_ROUTE_PARAM
        $this->spawn('ls');
    }

    private function spawn($exe)
    {
        system($exe); // SINK_HELPER
    }
}

Route::get('/closure', function (Request $request) {
    system($request->input('c')); // SINK_CLOSURE
});
`

func TestFramework_Laravel(t *testing.T) {
	res := scanFiles(t, map[string]string{"app/Http/Controllers/RunController.php": laravelController})
	expect(t, res, laravelController, "ZS-PHP-001", "SINK_INPUT", true)
	expect(t, res, laravelController, "ZS-PHP-001", "SINK_ROUTE_PARAM", true)
	expect(t, res, laravelController, "ZS-PHP-001", "SINK_CLOSURE", true)
	expect(t, res, laravelController, "ZS-PHP-001", "SINK_HELPER", false)
}

func TestFramework_LaravelHelperCalledWithTaint(t *testing.T) {
	src := strings.Replace(laravelController, `$this->spawn('ls');`, `$this->spawn($cmd);`, 1)
	res := scanFiles(t, map[string]string{"app/Http/Controllers/RunController.php": src})
	expect(t, res, src, "ZS-PHP-001", "SINK_HELPER", true)
}

func TestFramework_LaravelInjectedServiceNotTainted(t *testing.T) {
	src := `<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class RunController extends Controller
{
    public function run(Request $request, Runner $runner)
    {
        system($runner); // SINK_DI
    }
}
`
	res := scanFiles(t, map[string]string{"app/Http/Controllers/RunController.php": src})
	expect(t, res, src, "ZS-PHP-001", "SINK_DI", false)
}

func TestFramework_PhpPlainSuperglobals(t *testing.T) {
	src := `<?php
function run_tool($exe) {
    system($exe); // SINK_HELPER
}
run_tool('ls');
$c = $_GET['c'];
system($c); // SINK_TOP
`
	res := scanFiles(t, map[string]string{"run.php": src})
	expect(t, res, src, "ZS-PHP-001", "SINK_TOP", true)
	expect(t, res, src, "ZS-PHP-001", "SINK_HELPER", false)

	withTaint := strings.Replace(src, "run_tool('ls');", "run_tool($_GET['x']);", 1)
	res = scanFiles(t, map[string]string{"run.php": withTaint})
	expect(t, res, withTaint, "ZS-PHP-001", "SINK_HELPER", true)
}

func TestFramework_PhpWithoutEvidenceKeepsParameterSeeding(t *testing.T) {
	src := `<?php
function run_tool($exe) {
    system($exe); // SINK_HELPER
}
run_tool('ls');
`
	res := scanFiles(t, map[string]string{"run.php": src})
	expect(t, res, src, "ZS-PHP-001", "SINK_HELPER", true)
}

const fastifyApp = `const fastify = require('fastify')();
const { exec } = require('child_process');

function runTool(arg) {
  eval('tool ' + arg); // SINK_HELPER
}

fastify.get('/ping', async (request, reply) => {
  runTool('--version');
  const host = request.query.host;
  eval('ping ' + host); // SINK_HANDLER
  return 'ok';
});
`

func TestFramework_Fastify(t *testing.T) {
	res := scanFiles(t, map[string]string{"app.js": fastifyApp})
	expect(t, res, fastifyApp, "ZS-JS-001", "SINK_HANDLER", true)
	expect(t, res, fastifyApp, "ZS-JS-001", "SINK_HELPER", false)
}

func TestFramework_FastifyHelperCalledWithTaint(t *testing.T) {
	src := strings.Replace(fastifyApp, `runTool('--version');`, `runTool(request.query.tool);`, 1)
	res := scanFiles(t, map[string]string{"app.js": src})
	expect(t, res, src, "ZS-JS-001", "SINK_HELPER", true)
}

func TestFramework_FastifyPluginAndRouteObject(t *testing.T) {
	src := `module.exports = async function (fastify, opts) {
  const { exec } = require('child_process');
  fastify.register(async function (instance) {
    instance.post('/a', async (req, reply) => {
      eval('a ' + req.body.cmd); // SINK_NESTED
    });
  });
  fastify.route({
    method: 'GET',
    url: '/b',
    handler: async function (request, reply) {
      eval('b ' + request.query.cmd); // SINK_ROUTE
    },
  });
  function named(request, reply) {
    const c = request.params.c;
    eval('c ' + c); // SINK_NAMED
  }
  fastify.get('/c/:c', named);
  function notAHandler(value) {
    eval('d ' + value); // SINK_OTHER
  }
};
`
	res := scanFiles(t, map[string]string{"plugin.js": src})
	expect(t, res, src, "ZS-JS-001", "SINK_NESTED", true)
	expect(t, res, src, "ZS-JS-001", "SINK_ROUTE", true)
	expect(t, res, src, "ZS-JS-001", "SINK_NAMED", true)
	expect(t, res, src, "ZS-JS-001", "SINK_OTHER", false)
}

func TestFramework_FastifyHandlerParameterIsTheRequest(t *testing.T) {
	src := `const fastify = require('fastify')();
const { exec } = require('child_process');
fastify.get('/x', async (request, reply) => {
  eval('x ' + request); // SINK_REQUEST
});
fastify.get('/y', async (request, reply) => {
  eval('y ' + reply); // SINK_REPLY
});
`
	res := scanFiles(t, map[string]string{"app.js": src})
	expect(t, res, src, "ZS-JS-001", "SINK_REQUEST", true)
	expect(t, res, src, "ZS-JS-001", "SINK_REPLY", false)
}

func TestFramework_JsWithoutEvidenceKeepsParameterSeeding(t *testing.T) {
	src := strings.Replace(fastifyApp, "require('fastify')()", "makeServer()", 1)
	res := scanFiles(t, map[string]string{"app.js": src})
	expect(t, res, src, "ZS-JS-001", "SINK_HELPER", true)
}

func TestFramework_ReportTally(t *testing.T) {
	res := scanFiles(t, map[string]string{
		"RunController.cs": coreController,
		"App.csproj":       `<Project Sdk="Microsoft.NET.Sdk.Web"></Project>`,
		"Helper.cs":        "public class Helper { }\n",
		"app.js":           fastifyApp,
	})
	got := map[string]int{}
	for _, f := range res.Frameworks {
		got[f.Framework+"/"+f.Confidence] = f.Files
	}
	want := map[string]int{"aspnetcore/high": 1, "aspnetcore/medium": 1, "fastify/high": 1}
	b1, _ := json.Marshal(got)
	b2, _ := json.Marshal(want)
	if string(b1) != string(b2) {
		t.Errorf("Frameworks = %s, want %s", b1, b2)
	}
}

const frameworkRuleYAML = `id: ZS-CUSTOM-FW1
name: Fastify Marker Call
version: "1.0.0"
language: javascript
category: dangerous-functions
severity: high
confidence: high
lifecycle: released
frameworks: [fastify]
description: |
  Flags calls to marker_danger in fastify files only.
message: "marker_danger call"
match:
  kind: call
  callee: marker_danger
fix_suggestion: "Do not call marker_danger."
rationale: |
  marker_danger is forbidden by local policy.
`

func scanWithRule(t *testing.T, files map[string]string, ruleYAML string) bool {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := scanExtra(t, root, writeExtra(t, "ZS-CUSTOM-FW1.yaml", ruleYAML))
	if err != nil {
		t.Fatal(err)
	}
	return ids["ZS-CUSTOM-FW1"]
}

func TestFrameworksRule_AppliesOnlyWhereDetected(t *testing.T) {
	call := "marker_danger();\n"
	if !scanWithRule(t, map[string]string{"app.js": "const f = require('fastify')();\n" + call}, frameworkRuleYAML) {
		t.Error("rule did not fire in a file with fastify file evidence")
	}
	if !scanWithRule(t, map[string]string{"package.json": `{"dependencies": {"fastify": "4"}}`, "util.js": call}, frameworkRuleYAML) {
		t.Error("rule did not fire in a file with fastify manifest evidence")
	}
	if scanWithRule(t, map[string]string{"util.js": call}, frameworkRuleYAML) {
		t.Error("rule fired in a file with no framework detected")
	}
	if scanWithRule(t, map[string]string{"app.js": "const e = require('express')();\n" + call}, frameworkRuleYAML) {
		t.Error("rule fired in an express file")
	}
	// Without the list the rule is framework-agnostic, as before.
	agnostic := strings.Replace(frameworkRuleYAML, "frameworks: [fastify]\n", "", 1)
	if !scanWithRule(t, map[string]string{"util.js": call}, agnostic) {
		t.Error("a rule with no frameworks list stopped firing")
	}
}

func TestFrameworksRule_UnknownFrameworkRejected(t *testing.T) {
	bad := strings.Replace(frameworkRuleYAML, "[fastify]", "[nope]", 1)
	root := t.TempDir()
	_, err := scanExtra(t, root, writeExtra(t, "ZS-CUSTOM-FW1.yaml", bad))
	if err == nil || !strings.Contains(err.Error(), "unknown framework") {
		t.Fatalf("want an unknown-framework error, got %v", err)
	}
}

//go:build cgo

package pipeline_test

import "testing"

// Round-5 profiles (Spring, Django, Flask, FastAPI, NestJS, Next.js, Gin,
// Echo). Every source has the same shape: an entry point whose request-bound
// parameter (or request accessor) reaches a sink, and a helper whose parameter
// is not request-bound. In a file with high-confidence framework evidence the
// helper must stay clean until a same-file call passes it tainted data; an
// accessor inside the helper still fires.

type webCase struct {
	name, file, src, rule string
	fires, quiet          []string // markers on lines that must / must not fire
}

func runWebCases(t *testing.T, cases []webCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := scanFiles(t, map[string]string{c.file: c.src})
			for _, m := range c.fires {
				expect(t, res, c.src, c.rule, m, true)
			}
			for _, m := range c.quiet {
				expect(t, res, c.src, c.rule, m, false)
			}
		})
	}
}

func TestFramework_Spring(t *testing.T) {
	const head = `package demo;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    private Connection conn;
`
	runWebCases(t, []webCase{
		{"annotated parameter", "UserController.java", head + `
    @GetMapping("/user")
    public String user(@RequestParam String id) throws SQLException {
        conn.createStatement().executeQuery("SELECT 1 WHERE id = " + id); // SINK_ENTRY
        lookup("admin");
        return "ok";
    }

    private void lookup(String role) throws SQLException {
        conn.createStatement().executeQuery("SELECT 1 WHERE r = " + role); // SINK_HELPER
    }
}
`, "ZS-JAVA-001", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
		{"helper called with tainted", "UserController.java", head + `
    @GetMapping("/user")
    public String user(@RequestParam String id) throws SQLException {
        lookup(id);
        return "ok";
    }

    private void lookup(String role) throws SQLException {
        conn.createStatement().executeQuery("SELECT 1 WHERE r = " + role); // SINK_HELPER
    }
}
`, "ZS-JAVA-001", []string{"SINK_HELPER"}, nil},
		{"request accessor in helper", "UserController.java", head + `
    @GetMapping("/user")
    public String user() { return "ok"; }

    private void lookup(javax.servlet.http.HttpServletRequest req) throws SQLException {
        String r = req.getParameter("r");
        conn.createStatement().executeQuery("SELECT 1 WHERE r = " + r); // SINK_HELPER
    }
}
`, "ZS-JAVA-001", []string{"SINK_HELPER"}, nil},
		{"unmapped method of a controller", "UserController.java", head + `
    @GetMapping("/user")
    public String user() { return "ok"; }

    public void internal(String id) throws SQLException {
        conn.createStatement().executeQuery("SELECT 1 WHERE id = " + id); // SINK_INTERNAL
    }
}
`, "ZS-JAVA-001", nil, []string{"SINK_INTERNAL"}},
	})
}

func TestFramework_Django(t *testing.T) {
	const head = `from django.http import HttpResponse
from django.db import connection

`
	runWebCases(t, []webCase{
		{"function view", "views.py", head + `def user(request, uid):
    cursor = connection.cursor()
    cursor.executescript("SELECT 1 WHERE id = '" + uid + "'")  # SINK_ENTRY
    lookup("admin")
    return HttpResponse("ok")


def lookup(role):
    cursor = connection.cursor()
    cursor.executescript("SELECT 1 WHERE r = '" + role + "'")  # SINK_HELPER
`, "ZS-PY-058", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
		{"request accessor", "views.py", head + `def search(request):
    cursor = connection.cursor()
    q = request.GET.get("q")
    cursor.executescript("SELECT 1 WHERE n = '" + q + "'")  # SINK_ENTRY
    return HttpResponse("ok")
`, "ZS-PY-058", []string{"SINK_ENTRY"}, nil},
		{"class-based view method", "views.py", head + `from django.views import View


class UserView(View):
    def get(self, request, uid):
        cursor = connection.cursor()
        cursor.executescript("SELECT 1 WHERE id = '" + uid + "'")  # SINK_ENTRY
        return HttpResponse("ok")

    def build(self, name):
        cursor = connection.cursor()
        cursor.executescript("SELECT 1 WHERE n = '" + name + "'")  # SINK_HELPER
`, "ZS-PY-058", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
	})
}

func TestFramework_Flask(t *testing.T) {
	const head = `import sqlite3

from flask import Flask, request

app = Flask(__name__)
cursor = sqlite3.connect("app.db").cursor()


`
	runWebCases(t, []webCase{
		{"route variable", "app.py", head + `@app.route("/user/<uid>")
def user(uid):
    cursor.executescript("SELECT 1 WHERE id = '" + uid + "'")  # SINK_ENTRY
    return lookup("admin")


def lookup(role):
    cursor.executescript("SELECT 1 WHERE r = '" + role + "'")  # SINK_HELPER
    return "ok"
`, "ZS-PY-058", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
		{"blueprint route and accessor", "app.py", head + `@bp.get("/search")
def search():
    q = request.args.get("q")
    cursor.executescript("SELECT 1 WHERE n = '" + q + "'")  # SINK_ENTRY
    return "ok"
`, "ZS-PY-058", []string{"SINK_ENTRY"}, nil},
		{"helper called with tainted", "app.py", head + `@app.route("/user/<uid>")
def user(uid):
    return lookup(uid)


def lookup(role):
    cursor.executescript("SELECT 1 WHERE r = '" + role + "'")  # SINK_HELPER
    return "ok"
`, "ZS-PY-058", []string{"SINK_HELPER"}, nil},
	})
}

func TestFramework_FastAPI(t *testing.T) {
	const head = `import sqlite3

from fastapi import Depends, FastAPI, Query

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


def get_db():
    return cursor


`
	runWebCases(t, []webCase{
		{"typed parameter", "main.py", head + `@app.get("/user")
def user(uid: str, db=Depends(get_db)):
    cursor.executescript("SELECT 1 WHERE id = '" + uid + "'")  # SINK_ENTRY
    return lookup("admin")


def lookup(role):
    cursor.executescript("SELECT 1 WHERE r = '" + role + "'")  # SINK_HELPER
    return "ok"
`, "ZS-PY-058", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
		{"dependency is not request data", "main.py", head + `@app.get("/user")
def user(db=Depends(get_db)):
    cursor.executescript("SELECT 1 WHERE d = '" + db + "'")  # SINK_DEP
    return "ok"
`, "ZS-PY-058", nil, []string{"SINK_DEP"}},
		{"router decorator", "main.py", head + `@router.post("/search")
async def search(q: str = Query(None)):
    cursor.executescript("SELECT 1 WHERE n = '" + q + "'")  # SINK_ENTRY
    return "ok"
`, "ZS-PY-058", []string{"SINK_ENTRY"}, nil},
	})
}

func TestFramework_NestJS(t *testing.T) {
	const head = `import { Controller, Get, Query } from '@nestjs/common';
import { exec } from 'child_process';

@Controller('ping')
export class PingController {
`
	runWebCases(t, []webCase{
		{"decorated parameter", "ping.controller.ts", head + `  @Get()
  ping(@Query('host') host: string) {
    exec('ping ' + host, function (err, out) {}); // SINK_ENTRY
    this.run('-V');
    return 'ok';
  }

  run(flag: string) {
    exec('tool ' + flag, function (err, out) {}); // SINK_HELPER
  }
}
`, "ZS-TS-016", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
		{"request accessor in helper", "ping.controller.ts", head + `  @Get()
  ping() { return 'ok'; }

  run(req: any) {
    exec('tool ' + req.query.flag, function (err, out) {}); // SINK_HELPER
  }
}
`, "ZS-TS-016", []string{"SINK_HELPER"}, nil},
	})
}

func TestFramework_NextJS(t *testing.T) {
	runWebCases(t, []webCase{
		{"route handler", "app/api/ping/route.ts", `import { NextRequest, NextResponse } from 'next/server';
import { exec } from 'child_process';

export async function GET(request: NextRequest) {
  const host = request.nextUrl.searchParams.get('host');
  exec('ping ' + host, function (err, out) {}); // SINK_ENTRY
  launch('-V');
  return NextResponse.json({ ok: true });
}

function launch(flag: string) {
  exec('tool ' + flag, function (err, out) {}); // SINK_HELPER
}
`, "ZS-TS-016", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
		{"server action", "app/actions.ts", `'use server'
import { exec } from 'child_process';

export async function run(cmd: string) {
  exec('tool ' + cmd, function (err, out) {}); // SINK_ACTION
}
`, "ZS-TS-016", []string{"SINK_ACTION"}, nil},
		{"pages api handler", "pages/api/ping.ts", `import type { NextApiRequest, NextApiResponse } from 'next';
import { exec } from 'child_process';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  exec('ping ' + req.query.host, function (err, out) {}); // SINK_ENTRY
  res.status(200).end();
}

function other(flag: string) {
  exec('tool ' + flag, function (err, out) {}); // SINK_HELPER
}
`, "ZS-TS-016", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
	})
}

func TestFramework_Gin(t *testing.T) {
	runWebCases(t, []webCase{
		{"registered literal and helper", "main.go", `package main

import (
	"os/exec"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/run", func(c *gin.Context) {
		exec.Command("sh", "-c", c.Query("cmd")).Run() // SINK_ENTRY
		launch("--version")
	})
	r.Run()
}

func launch(flag string) {
	exec.Command("tool", flag).Run() // SINK_HELPER
}
`, "ZS-GO-001", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
		{"named handler parameter", "main.go", `package main

import (
	"os/exec"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.POST("/run", runHandler)
}

func runHandler(c *gin.Context) {
	cmd := c.PostForm("cmd")
	exec.Command(cmd).Run() // SINK_ENTRY
}

func other(flag string) {
	exec.Command(flag).Run() // SINK_HELPER
}
`, "ZS-GO-001", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
	})
}

func TestFramework_Echo(t *testing.T) {
	runWebCases(t, []webCase{
		{"registered handler and helper", "main.go", `package main

import (
	"os/exec"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	e.GET("/run", func(c echo.Context) error {
		exec.Command("sh", "-c", c.QueryParam("cmd")).Run() // SINK_ENTRY
		launch("--version")
		return nil
	})
	e.Start(":8080")
}

func launch(flag string) {
	exec.Command("tool", flag).Run() // SINK_HELPER
}
`, "ZS-GO-001", []string{"SINK_ENTRY"}, []string{"SINK_HELPER"}},
	})
}

// Without file-level evidence nothing narrows: a Go helper keeps seeding.
func TestFramework_GoWithoutEvidenceKeepsDefaultSeeding(t *testing.T) {
	src := `package main

import "os/exec"

func launch(flag string) {
	exec.Command("tool", flag).Run() // SINK_HELPER
}
`
	res := scanFiles(t, map[string]string{"main.go": src})
	expect(t, res, src, "ZS-GO-001", "SINK_HELPER", true)
}

// A manifest alone (medium) must not narrow seeding, but its accessors become
// explicit sources.
func TestFramework_MediumKeepsSeedingAndAddsAccessors(t *testing.T) {
	src := `package main

import "os/exec"

func launch(flag string) {
	exec.Command("tool", flag).Run() // SINK_HELPER
}

func read(c Ctx) {
	exec.Command(c.Query("cmd")).Run() // SINK_ACCESSOR
}
`
	res := scanFiles(t, map[string]string{
		"go.mod":  "module x\n\nrequire github.com/gin-gonic/gin v1.9.0\n",
		"main.go": src,
	})
	expect(t, res, src, "ZS-GO-001", "SINK_HELPER", true)
	expect(t, res, src, "ZS-GO-001", "SINK_ACCESSOR", true)
}

// A call on another object shares only a name with a same-file function: it
// must not seed that function's parameters.
func TestFramework_ForeignReceiverDoesNotSeedSameNameFunction(t *testing.T) {
	src := `import sqlite3

from flask import Flask, request

app = Flask(__name__)
cursor = sqlite3.connect("app.db").cursor()


@app.route("/save")
def save():
    store.lookup(request.args.get("q"))
    return "ok"


def lookup(role):
    cursor.executescript("SELECT 1 WHERE r = '" + role + "'")  # SINK_HELPER
`
	res := scanFiles(t, map[string]string{"app.py": src})
	expect(t, res, src, "ZS-PY-058", "SINK_HELPER", false)

	src2 := `import sqlite3

from flask import Flask, request

app = Flask(__name__)
cursor = sqlite3.connect("app.db").cursor()


@app.route("/save")
def save():
    lookup(request.args.get("q"))
    return "ok"


def lookup(role):
    cursor.executescript("SELECT 1 WHERE r = '" + role + "'")  # SINK_HELPER
`
	res2 := scanFiles(t, map[string]string{"app.py": src2})
	expect(t, res2, src2, "ZS-PY-058", "SINK_HELPER", true)
}

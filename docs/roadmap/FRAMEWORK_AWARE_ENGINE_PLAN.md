# Framework-aware engine and PHP, C#, HTML measurement

Planned 8 November 2026. Planner: Opus 5.5. Builders: Sonnet 5.5 agents, one per workstream.

## Problem

`internal/analyzer/taint/taint.go: BuildContext` treats every parameter of every function as attacker-controlled
("parameter seeding"; the code comment marks it as a shortcut to narrow later). A helper `FormatName(string s)` is treated
like a controller action receiving a query string. That one behavior is the largest single source of false positives, and
it is why frameworks the scanner does not know (ASP.NET Core, Fastify, Laravel) produce noisy, low-confidence results.

Separately, PHP, C# and HTML templates have no precision figure: the RealVuln benchmark has no labeled applications in them.

## Goal

1. Measure precision and recall for PHP, C#, HTML templates and Fastify on a labeled set.
2. Detect, per file, which framework the code uses, with stated evidence and confidence.
3. When the framework is known, treat as user input only what that framework actually delivers from a request:
   handler parameters that the framework binds from the request, and the framework's request accessors. Stop seeding
   every other function parameter in that file. When no framework is detected, keep today's behavior so recall on
   unknown code does not drop.
4. Fix the PHP, C# and HTML false positives the measurement exposes.

## Workstream M: labeled measurement set (Sonnet, independent of the engine)

Builds `benchmark/labeled/`, one folder per application, each with source code and a `ground-truth.json` in the RealVuln
format (fields used by the scorer: `id`, `is_vulnerable`, `vulnerability_class`, `primary_cwe`, `acceptable_cwes`,
`file`, `location.start_line/end_line`). The agent must not read `internal/rules`, `internal/analyzer` or
`internal/engine`, so the applications are written from OWASP weakness classes, not from what the scanner happens to match.

| Application | Language and framework | Source | Use |
|---|---|---|---|
| dvwa | PHP (plain) | Third party: DVWA at a pinned commit. Each module's `low`, `medium` and `high` source is labeled vulnerable for its class; `impossible` is labeled safe | Verify |
| php-app | PHP, Laravel-style controllers plus plain PHP pages | Self-built | Tune |
| aspnetcore-a | C#, ASP.NET Core MVC controllers and Razor views | Self-built | Tune |
| aspnetcore-b | C#, ASP.NET Core minimal APIs and Razor Pages | Self-built | Verify |
| aspnet-mvc5 | C#, .NET Framework 4.8 MVC 5 and Web API 2 with `web.config` | Self-built | Tune |
| fastify-a | TypeScript, Fastify with route schemas | Self-built | Tune |
| fastify-b | JavaScript, Fastify plugins and hooks | Self-built | Verify |

Every self-built application has 15 to 25 labeled vulnerabilities across injection, XSS, path traversal, SSRF, open
redirect, deserialization, weak crypto, hardcoded secrets and misconfiguration, plus at least 10 labeled safe look-alikes
(parameterized query next to a concatenated one, encoded output next to raw output, a helper function whose parameter is
never request data). Templates (Razor, Blade-style PHP views, EJS or Handlebars for Fastify) carry the HTML measurement.

Verify applications are frozen once written: nobody tunes against them, and their per-finding results stay closed until the
final report. `scripts/realvuln/evallocal.py` scores the folders without cloning.

## Workstream E: framework detection in the engine (Sonnet, must not read `benchmark/labeled`)

1. New package `internal/fwdetect`. Input: the scan's file list. Evidence, strongest first:
   - manifest: `.csproj` (`Microsoft.NET.Sdk.Web`, `Microsoft.AspNetCore.*` package references mean ASP.NET Core;
     `packages.config` or `<TargetFrameworkVersion>v4.x` with `System.Web.Mvc`, `Microsoft.AspNet.WebApi` means .NET
     Framework), `package.json` dependencies (`fastify`, `express`, `koa`, `@nestjs/core`, `next`), `composer.json`
     (`laravel/framework`, `symfony/*`), `go.mod`, `pom.xml`, `build.gradle`, `requirements*.txt` and `pyproject.toml`;
   - file: imports and usings (`require('fastify')`, `using Microsoft.AspNetCore.Mvc;`, `using System.Web.Mvc;`,
     `use Illuminate\Http\Request;`), base classes (`ControllerBase`, `Controller`, `PageModel`, `ApiController`),
     attributes (`[ApiController]`, `[HttpGet]`, `[Route]`, `[FromQuery]`, `[FromBody]`), registration calls
     (`app.MapGet`, `fastify.get/post/route`, `Route::get`).
   Output per file: frameworks with confidence `high` (file-level evidence) or `medium` (manifest only), and the evidence.
2. Framework profiles as data, one YAML per framework under `internal/fwdetect/profiles/`: request accessor sources and
   entry-point shapes. First profiles: `aspnetcore` (controller actions, Razor Page handlers `OnGet*`/`OnPost*`, minimal
   API lambdas, `Request.Query/Form/Headers/Cookies/RouteValues`, `[From*]` parameters), `aspnet-framework` (MVC 5 and Web
   API 2 actions, `Request.QueryString/Form/Params`, Web Forms control `.Text`), `fastify` (`request.query/body/params/
   headers/cookies` in handlers registered on the instance or in plugins), `laravel` (controller actions with
   `Request $request`, `$request->input/query/get/all/post/cookie`, `request()` helper), `php-plain` (superglobals).
   Express, Koa and NestJS profiles follow the same shape and are added if time allows.
3. Taint change in `BuildContext`: when a file has a `high` confidence framework, seed only entry-point parameters and add
   the profile's sources; parameters of other functions stay clean unless data flows into them. Without a detected
   framework, seeding is unchanged.
4. Rule YAML gains an optional `frameworks:` list; a rule with it runs only when one of those frameworks is detected for
   the file. No existing rule changes behavior unless it opts in.
5. The JSON report gains an additive `Frameworks` array (framework, confidence, evidence count). No existing key moves.
6. Tests: detection unit tests per framework and per evidence type, plus engine tests showing a helper parameter no
   longer fires in a framework file while a controller parameter still does.

## Workstream F: PHP, C# and HTML fixes (Sonnet, after M and E)

Runs on the tune applications only. Fixes false positives and adds missing sources or sinks, with fixtures.

## Gates

Internal corpus at 0 false positives and 0 missed; `go test ./...`; `TestReportLayoutContract`; the 32-application
RealVuln benchmark must not lose more than 5 true positives and must not gain false positives.

## Report

One executive report with one table per language: precision, recall and false positives before and after, on the
labeled set (verify applications reported separately because they were not tuned on) and on the RealVuln benchmark.

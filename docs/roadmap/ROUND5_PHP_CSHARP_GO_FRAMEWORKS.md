# Round 5: PHP precision, third-party C# and Go measurement, more frameworks

Planned 8 November 2026. Planner: Opus 5.5. Builders: Sonnet 5.5, one agent per workstream. Follows
`docs/benchmarks/EXECUTIVE_REPORT_2026-11-08-frameworks.md`. The IOC scanner runs in parallel; see `IOC_SCANNER_PLAN.md`.

## Goals

1. PHP precision above 65 percent on an independent PHP application nobody tuned on.
2. C# and Go measured on third-party applications, so their figures can be quoted.
3. Framework detection and request sources for Spring, Django, Flask, FastAPI, NestJS, Next.js, Gin and Echo, the
   frameworks behind the weakest numbers (Java 34 percent, TypeScript 53 percent precision).

## Workstream M2: third-party labeled apps (must not read `internal/rules`, `internal/analyzer`, `internal/engine`)

| Application | Language | Use |
|---|---|---|
| XVWA (or bWAPP if XVWA cannot be pinned) | PHP | Sealed |
| WebGoat.NET | C# (.NET Framework) | Sealed |
| govwa | Go | Sealed |
| DVWA | PHP | Moves from sealed to tune |

Each app is pinned to a commit in `SOURCE.txt` and fetched by `benchmark/labeled/fetch.sh`, which grows a per-app entry.
Labels come from the application's own documented vulnerability list, one entry per vulnerable location with file, line,
CWE and acceptable CWEs, plus safe look-alikes where the app ships a fixed version. Every label points at a line that
exists at the pinned commit; nothing is labeled from memory. Third-party apps are scored only on labeled files, as DVWA is.

## Workstream P: PHP precision (tune on DVWA and php-app only)

DVWA's 35 false alarms concentrate in ZS-PHP-002 (`mysqli_query`), ZS-PHP-015 (`header()`), ZS-PHP-010 (MD5) and
ZS-PHP-012 (`setcookie`). For each, read the false positives, find the shared safe shape and tighten (for example a query
built only from literals and `intval`/`(int)`/prepared values, a `header()` whose value is a literal or a fixed
`Location`, `md5` used on non-secret data, `setcookie` with secure flags set). Retire only with evidence. Also check PHP
recall gaps on DVWA's missed labels.

## Workstream E2: framework profiles (must not read `benchmark/labeled`)

Add profiles in `internal/fwdetect/profiles/` and the matching taint sources:

| Framework | Entry points | Request sources |
|---|---|---|
| Spring MVC / Boot | `@RestController`/`@Controller` methods with `@*Mapping` | `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `HttpServletRequest.get*` |
| Django | views referenced from `urls.py`, class-based view methods | `request.GET/POST/body/COOKIES/META/FILES`, URL kwargs |
| Flask | `@app.route`/`@bp.route` functions | `request.args/form/values/json/get_json()/cookies/headers/files`, route variables |
| FastAPI | `@app.get/post/...`/`@router.*` functions | typed path, query and body parameters, `Request` accessors |
| NestJS | controller methods with `@Get/@Post/...` | `@Body`, `@Query`, `@Param`, `@Headers`, `@Req()` accessors |
| Next.js | route handlers, `getServerSideProps`, server actions, pages API | `searchParams`, `params`, `req.query/body`, `request.json()/formData()`, `NextRequest.nextUrl.searchParams` |
| Gin | handlers registered on `gin.Engine`/`RouterGroup` | `c.Query`, `c.Param`, `c.PostForm`, `c.GetHeader`, `c.Cookie`, `c.Bind*`/`ShouldBind*` |
| Echo | handlers registered on `echo.Echo`/`Group` | `c.QueryParam`, `c.Param`, `c.FormValue`, `c.Bind`, `c.Request()` |

Same rules as round 4: high file-level evidence narrows parameter seeding to entry points; medium or none keeps today's
behavior.

## Gates (every workstream)

Internal corpus at 0 false positives and 0 misses; `go test ./...`; `TestReportLayoutContract`; the 32 RealVuln apps may
not lose more than 5 true positives and may not gain false positives.

## Report

One executive report: precision and found per language on the sealed third-party apps, the labeled set and RealVuln, the
framework detection table, and the IOC scanner's corpus result and false-alarm count on the 39 benchmark apps.

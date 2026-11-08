# thinkShield scanner: framework detection, PHP, C# and HTML

8 November 2026. Branch `feat/precision-75`, not yet released.

## Summary

The scanner now works out which web framework each file uses and treats as user input only what that framework actually
receives from a request. It identified the framework correctly in all seven test applications and in every Express
application of the main benchmark. C# moved from finding about a third of known vulnerabilities to nearly all of them
with almost no false alarms, HTML templates are now fully covered, and the main benchmark held at 60 percent precision.
PHP did not improve on the one independent PHP application, DVWA, and is the open problem.

## How it was measured

PHP, C# and HTML templates had no labeled benchmark, so a labeled set was built: DVWA, a well-known third-party PHP
application whose vulnerable and safe versions of each exercise are labeled, plus six purpose-built applications in ASP.NET
Core, .NET Framework MVC 5 and Web API 2, Fastify and Laravel-style PHP. Together they hold 199 known vulnerabilities and
119 safe look-alikes. Three applications (DVWA, one ASP.NET Core app and one Fastify app) were sealed: no fix was written
while looking at them, so they show how the changes behave on unseen code. JavaScript, TypeScript, Python and Java continue
to be measured on the 32-application RealVuln benchmark from the previous report.

## Results on the labeled set

| Language | Precision before | Precision now | Found before | Found now | False alarms before → now |
|---|---|---|---|---|---|
| C# (ASP.NET Core and .NET Framework) | 90.0% | 98.0% | 35% | 94% | 2 → 1 |
| HTML templates (Razor, Blade, EJS, Handlebars) | 85.7% | 93.8% | 40% | 100% | 1 → 1 |
| TypeScript and JavaScript (Fastify) | 83.3% | 81.5% | 56% | 61% | 4 → 5 |
| PHP | 46.2% | 54.4% | 41% | 49% | 42 → 36 |
| All seven applications | 62.3% | 75.0% | 41% | 65% | 49 → 43 |

"Found" is recall: the share of known vulnerabilities the scanner reported.

## Check on the sealed applications

| Language | Before | Now |
|---|---|---|
| C#, unseen ASP.NET Core app | 7 found, 0 false alarms | 14 found, 0 false alarms |
| HTML templates | 2 found, 1 false alarm | 4 found, 1 false alarm |
| Fastify, unseen app | 9 found, 3 false alarms | 9 found, 3 false alarms |
| PHP, DVWA | 30 found, 35 false alarms | 30 found, 35 false alarms |
| All sealed applications | 55.2% precision, 44% found | 59.4% precision, 53% found |

The C# and template gains carried over to unseen code. The PHP gains did not: every PHP improvement came from the
purpose-built Laravel application and none reached DVWA.

## Main benchmark (32 RealVuln applications)

| Measure | Before | Now |
|---|---|---|
| Real findings | 411 | 410 |
| False alarms | 279 | 273 |
| Precision | 59.6% | 60.0% |

Framework detection removed six false alarms and lost one real finding. The PHP, C# and template rules do not touch these
applications, which are JavaScript, TypeScript, Python and Java.

## Framework detection

| Framework | How it is recognized | Result |
|---|---|---|
| ASP.NET Core | Web SDK project file, `Microsoft.AspNetCore` usings, `ControllerBase`, `[ApiController]`, `app.MapGet` | 2 of 2 apps correct |
| .NET Framework | `packages.config`, `System.Web.Mvc` and `System.Web.Http` usings, `Controller`/`ApiController`/`Page` base classes | 1 of 1 correct |
| Fastify | `fastify` dependency and imports, plugin functions, `fastify.get/post/route` | 2 of 2 correct |
| Laravel | `laravel/framework`, `Illuminate\` usings, `App\Http\Controllers`, `Route::` | 1 of 1 correct |
| Plain PHP | Superglobals | DVWA correct |
| Express | `express` dependency and imports | All 8 Express benchmark apps correct; 1 juice-shop file also tagged Fastify |

When a file's framework is known from its own code, only the request handlers' parameters and the framework's request
accessors count as user input. Helper functions no longer count as attacker-controlled unless the same file passes them
request data. When no framework is detected, the scanner behaves as before, so unknown code keeps its recall. Every report
now lists the frameworks it detected.

## Where we stand

| Language | Precision | Found | Measured on |
|---|---|---|---|
| C# | 98% | 94% | Labeled set (one unseen app confirms) |
| HTML templates | 94% | 100% | Labeled set |
| JavaScript | 67% | 53% | RealVuln (previous report) |
| Python | 69% | 34% | RealVuln (previous report) |
| TypeScript | 53% | 41% | RealVuln (previous report) |
| PHP | 54% | 49% | Labeled set; 46% on DVWA |
| Java | 34% | 12% | RealVuln (previous report) |
| Go | not measured | not measured | No labeled set yet |

The C# and HTML figures come mostly from applications written for this test, which are smaller and cleaner than production
code. Treat them as an upper bound until confirmed on a third-party .NET application.

## Next move

1. PHP. DVWA's 35 false alarms concentrate in four rules (`mysqli_query`, `header()` redirects, MD5, `setcookie`). Unseal
   DVWA for tuning and bring in a second independent PHP application (bWAPP or XVWA) as the new sealed check. Target: PHP
   precision above 65 percent on the sealed app.
2. Confirm C# on third-party code, for example OWASP WebGoat.NET, before quoting the C# figures externally.
3. Extend framework detection to Spring, Django and Flask, FastAPI, NestJS, Next.js and Gin, the frameworks behind the
   weakest numbers above (Java 34 percent, TypeScript 53 percent).
4. Build a labeled Go set so Go can be measured at all.

Guardrails stay as before: no real finding lost without a stated reason, internal corpus at zero false alarms and zero
misses (now 633 cases), unit tests green, report format unchanged apart from the new framework list.

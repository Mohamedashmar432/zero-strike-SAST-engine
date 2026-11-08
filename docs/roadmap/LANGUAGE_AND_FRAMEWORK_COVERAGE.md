# Language and framework coverage

8 November 2026, branch `feat/precision-75`. Facts come from the code: `internal/parser` (parsers),
`internal/rules/data` (released rules), `internal/analyzer/taint/patterns.go` (where user input is recognized),
`internal/scanner/framework` (config checks), `internal/scanner/sca` (dependency files) and the pinned
`github.com/smacker/go-tree-sitter` module (grammars available to add).

## How framework support works today

A code rule fires when user input reaches a dangerous call. The scanner recognizes user input in two ways. Explicit
sources are named in `patterns.go`, such as `req.query` for Express or `request.args` for Flask. These are precise.
Parameter seeding treats every function parameter as possibly user-controlled. It gives any framework rough coverage, but
it is the main cause of false positives, so several rules now switch it off. A framework is covered well only when its
input calls are explicit sources.

## Supported languages

Precision and recall are from the 32-application RealVuln benchmark on 8 November. Go, C# and PHP have no labeled
applications in that benchmark, so their quality is unmeasured.

| Language | Active rules | Data-flow rules | Precision | Recall | Explicit user-input sources |
|---|---|---|---|---|---|
| TypeScript | 128 | 68 | 52.6% | 41.1% | Express `req.*`, browser DOM, Next.js `searchParams`/`useParams`/`router.query` |
| JavaScript | 123 | 66 | 67.4% | 53.4% | Express `req.*`, browser DOM |
| Python | 93 | 32 | 69.1% | 34.3% | Flask and Django `request.args/form/GET/POST`, `sys.argv` |
| Go | 46 | 25 | not measured | not measured | `net/http` only (`URL.Query()`, `FormValue`) |
| Java | 38 | 19 | 33.7% | 11.8% | Servlet `getParameter`, `getHeader`, `getQueryString`, file-upload name |
| PHP | 32 | 18 | not measured | not measured | Superglobals `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` |
| C# | 31 | 16 | not measured | not measured | Classic ASP.NET `Request.QueryString/Form/Cookies` |
| HTML templates | 16 | 0 | (counted with JS/TS) | | EJS, Handlebars, Jinja, Django templates |

Secrets scanning covers every text file. Framework config checks cover Django, Flask, Express, Spring properties,
ASP.NET `web.config`, Laravel, `php.ini`, Dockerfile, docker-compose, GitHub Actions and CORS settings.

## Framework coverage per language

Explicit means the framework's input calls are named sources. Generic means it is reached only through parameter seeding
or shared rules. None means nothing framework-specific exists.

| Language | Explicit | Generic only | None |
|---|---|---|---|
| JavaScript and TypeScript | Express, Next.js (client and route params), browser DOM, Sequelize, Prisma, TypeORM, Mongoose sinks | NestJS (`@Body`, `@Query`), Remix loaders and actions, React | Koa (`ctx.request`), Fastify (`request.query`), Hapi, Vue and Svelte single-file components |
| Python | Flask, Django | FastAPI (typed parameters), SQLAlchemy | aiohttp, Tornado, Starlette |
| Java | Servlet and JSP | Spring MVC (`@RequestParam`, `@PathVariable`, `@RequestBody`) | JAX-RS, Struts, Micronaut, Quarkus, Hibernate queries, Thymeleaf, FreeMarker |
| Go | `net/http` | | Gin, Echo, Fiber, Chi, Gorilla mux, GORM |
| PHP | Plain PHP superglobals | | Laravel (`$request->input`), Symfony, CodeIgniter, WordPress, Blade, Twig |
| C# | Classic ASP.NET Web Forms and MVC 5 | | ASP.NET Core (`Request.Query`, `[FromQuery]`, `[FromBody]`), Razor `Html.Raw`, Blazor, Entity Framework raw SQL |

The gaps that matter most commercially: Spring (most Java services), ASP.NET Core (all modern C#), Gin and Echo (most Go
web services), Laravel (most PHP), FastAPI and NestJS. Each of these runs today on generic coverage, which is both noisier
and blind to the framework's own input calls.

## Dependency scanning (SCA)

| Ecosystem | Files read | Missing |
|---|---|---|
| npm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | |
| PyPI | `requirements*.txt`, `Pipfile.lock` | `poetry.lock`, `uv.lock`, `pyproject.toml` |
| Go | `go.mod` | |
| Maven | `pom.xml` | Gradle (`build.gradle`, `build.gradle.kts`, `gradle.lockfile`) |
| NuGet | `.csproj`, `packages.lock.json` | |
| PHP | none | `composer.lock` |

PHP is supported for code scanning but has no dependency scanning. Gradle covers most Android and Kotlin projects and a
large share of Java ones.

## Languages that can be added

Every grammar below is already inside the pinned tree-sitter module, so adding a language needs a parser adapter, an
IR builder, sources and sinks, and rules, but no new dependency. Effort is an estimate in engineer-weeks for a first
release with about 30 rules and explicit sources for the main framework.

| Priority | Language or format | Main frameworks | Why | Estimated effort |
|---|---|---|---|---|
| 1 | Kotlin | Spring Boot, Ktor, Android | Shares Java's libraries and sinks, so most Java rules port directly | 2 to 3 weeks |
| 1 | Ruby | Rails, Sinatra | Large web install base; Rails conventions make sources and sinks predictable | 3 to 4 weeks |
| 1 | Terraform (HCL), Dockerfile, Kubernetes YAML | Infrastructure as code | Config-only checks, no data flow needed; Dockerfile checks already exist as text rules | 2 weeks for a first pack |
| 2 | Vue and Svelte single-file components | Vue, Nuxt, Svelte, SvelteKit | Script blocks reuse the JS/TS engine; templates need `v-html` and `{@html}` sinks | 1 to 2 weeks |
| 2 | Rust | Actix, Axum, Rocket | Growing for backend services; injection and unsafe-block rules | 3 weeks |
| 2 | Scala | Play, Akka HTTP | Runs on the JVM; can reuse Java sinks | 3 weeks |
| 2 | Bash | Scripts and CI steps | Command injection in build and deploy scripts | 1 week |
| 3 | Swift | iOS, Vapor | Mobile; different weakness classes (keychain, transport) | 3 to 4 weeks |
| 3 | C and C++ | Native code | Memory-safety rules are a different discipline from web rules | 6 weeks or more |
| 3 | Elixir, Groovy, Lua | Phoenix, Jenkins pipelines, embedded | Niche demand | 2 to 3 weeks each |

Not available in the pinned module: Dart and Flutter, and a dedicated Vue grammar (Vue can be handled by splitting the file
and reusing the HTML and TypeScript grammars).

## Measurement gap

Three supported languages (Go, C#, PHP) have no precision or recall figure because RealVuln has no labeled applications in
them. Before tuning those languages, build a labeled set from known-vulnerable applications with documented findings, for
example DVWA and bWAPP for PHP, WebGoat.NET and a vulnerable ASP.NET Core sample for C#, and a vulnerable Gin or Echo
sample for Go, labeling each documented vulnerability with file, line and CWE in the RealVuln format so `eval.sh` can
score them.

## Recommended order

1. Explicit sources for the big frameworks the scanner already parses: Spring, ASP.NET Core, Gin and Echo, Laravel,
   FastAPI, NestJS. This raises recall and cuts the parameter-seeding noise at the same time, and needs no new language.
2. Labeled benchmarks for Go, C# and PHP, so those languages can be measured at all.
3. Dependency gaps: Gradle, Poetry and uv, Composer.
4. New languages in priority order: Kotlin, Ruby, infrastructure as code, then Vue and Svelte.

# Spring Boot Analyzer

[![CI](https://github.com/RobbanHoglund/spring-boot-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/RobbanHoglund/spring-boot-analyzer/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/java-25-orange.svg)](build.gradle)
[![Spring Boot](https://img.shields.io/badge/spring--boot-3.5-brightgreen.svg)](build.gradle)

A static analysis tool for Spring Boot projects. Point it at any Git repository and get a structured report of findings, component inventory, HTTP surface, configuration risks, and anti-patterns — without running the analyzed application. 199 rules across 19 categories out of the box.

**Safe by default.** The default `STATIC_ONLY` mode clones the repository into a temporary workspace and performs static analysis only. It does not run Gradle tasks, Maven goals, tests, or the analyzed Spring Boot application. See [SECURITY.md](SECURITY.md) for the full security model.

![Spring Boot Analyzer](docs/screenshot.png)

---

## What it does

Spring Boot Analyzer clones a repository into a temporary workspace and inspects it using [JGit](https://www.eclipse.org/jgit/), [JavaParser](https://javaparser.org/), and optionally the Gradle Tooling API. It produces a prioritized list of findings across security, configuration, persistence, transactions, HTTP surface, and code quality.

**Default mode (`STATIC_ONLY`)** performs purely static analysis. It does not execute any code from the analyzed repository — no Gradle tasks, no Maven goals, no application startup, no test runs.

**Extended mode (`EXTENDED`)** is opt-in. It includes all static analysis and may use the Gradle Tooling API to resolve a richer Gradle model. This can evaluate repository-controlled Gradle build configuration logic. Use `EXTENDED` only for repositories you trust or inside an isolated sandbox.

See [docs/RULES.md](docs/RULES.md) for the full rule catalog.

---

## Features

### Component inventory
Detects Spring stereotypes and maps the application's component structure:
`@SpringBootApplication`, `@RestController`, `@Controller`, `@ControllerAdvice`, `@RestControllerAdvice`, `@Service`, `@Repository`, `@Component`, `@Configuration`, `@Entity`, `@ConfigurationProperties`

### HTTP surface analysis
- Inbound REST endpoints via Spring MVC (`@GetMapping`, `@PostMapping`, `@PutMapping`, `@PatchMapping`, `@DeleteMapping`, `@RequestMapping`)
- WebFlux functional routes (`route()`, `GET()`, `POST()`, etc.)
- Outbound HTTP calls via `RestTemplate`, `WebClient`, `HttpClient`, and `@FeignClient`
- Actuator endpoint exposure (`management.endpoints.web.exposure.*`)
- Base URL resolution from property placeholders

### Scheduling & messaging inventory
- `@Scheduled` methods: cron, fixedRate, fixedDelay, zone
- `@Async` methods (non-private)
- `@EnableScheduling` / `@EnableAsync` presence
- Message listener endpoints via `@KafkaListener`, `@RabbitListener`, `@JmsListener`, `@SqsListener` — destinations, group IDs, source locations

### Build analysis
- Gradle and Maven support
- Spring Boot version detection with confidence level
- Java version hint extraction
- Full dependency inventory

### Configuration analysis
- `application.properties` and `application.yml` parsing including profile-specific files
- Property placeholder resolution and cross-profile drift detection
- Sensitive value identification and redaction
- Spring configuration metadata catalog integration
- `@ConfigurationProperties` class extraction

### Gradle model analysis *(extended mode)*
- Resolved dependency tree via Gradle Tooling API
- Plugin declarations and version catalog support
- Java toolchain detection

---

## Findings

The analyzer produces **199 rules** across 19 categories. Each finding includes severity, confidence, why it matters, recommended action, evidence, and — for Gradle-model-backed rules — the exact resolved library versions involved.

| Category | Rules | Highest severity |
|----------|------:|-----------------|
| Security | 43 | ERROR |
| Maintainability | 21 | ERROR |
| Persistence | 19 | ERROR |
| Transaction | 15 | ERROR |
| Configuration | 13 | ERROR |
| Exception handling | 11 | ERROR |
| Scheduling | 11 | ERROR |
| Caching | 9 | ERROR |
| Observability | 9 | WARNING |
| Profile drift | 8 | WARNING |
| Spring Boot 3 migration | 8 | WARNING |
| HTTP clients | 7 | WARNING |
| API surface | 6 | ERROR |
| Startup | 5 | ERROR |
| Testing practice | 5 | WARNING |
| Validation | 3 | INFO |
| Actuator | 2 | WARNING |
| Conditional beans | 2 | WARNING |
| Dependency compatibility | 2 | ERROR |

See [docs/RULES.md](docs/RULES.md) for the complete rule catalog including detection logic, recommendations, and false-positive guidance.

---

## Requirements

| Component | Version |
|-----------|---------|
| Java | 25 |
| Go | 1.26 |
| Node.js | 22 |
| Gradle | via wrapper (`./gradlew`) |

---

## CLI mode

Spring Boot Analyzer can run without the web server — useful for CI pipelines
and scripted workflows.

**Basic usage**

```bash
java -jar spring-boot-analyzer.jar --repo https://github.com/owner/repo.git
```

**All options**

| Option | Default | Description |
|--------|---------|-------------|
| `--repo` | *(required)* | Repository URL to analyze (HTTPS or SSH) |
| `--branch` | repo default | Branch to check out |
| `--username` | — | Username for HTTPS authentication |
| `--token` | `$ANALYZER_TOKEN` | Personal access token (or set env var `ANALYZER_TOKEN`) |
| `--mode` | `STATIC_ONLY` | Analysis mode: `STATIC_ONLY` or `EXTENDED` |
| `--format` | `text` | Output format: `text`, `json`, or `sarif` |
| `--output` / `-o` | stdout | Write output to a file instead of stdout |
| `--fail-on` | `error` | Exit 1 when findings at this severity or above exist: `never`, `info`, `warning`, `error` |
| `--quiet` / `-q` | false | Suppress progress messages written to stderr |

**Exit codes**

| Code | Meaning |
|------|---------|
| 0 | Analysis completed; no findings at or above `--fail-on` threshold |
| 1 | Analysis completed; at least one finding at or above the threshold |
| 2 | Analysis failed (clone error, auth failure, I/O error) |
| 4 | Invalid arguments |

**Examples**

Analyze a public repo and print a human-readable report:
```bash
java -jar spring-boot-analyzer.jar \
  --repo https://github.com/spring-projects/spring-petclinic.git \
  --branch main
```

Output SARIF for GitHub Code Scanning, fail on warnings:
```bash
java -jar spring-boot-analyzer.jar \
  --repo https://github.com/owner/repo.git \
  --token "$GITHUB_TOKEN" \
  --format sarif \
  --output results.sarif \
  --fail-on warning
```

Output raw JSON silently:
```bash
java -jar spring-boot-analyzer.jar \
  --repo https://github.com/owner/repo.git \
  --format json \
  --quiet \
  > analysis.json
```

## Go control plane: `springmaster`

`springmaster` is a small Go coordinator around the existing Java analyzer. It
keeps Java analyzer workers alive, assigns repository snapshots to a bounded
worker pool, and combines JSONL responses. The Java analyzer remains the source
of finding rules and report shape; Go owns discovery, scheduling, cache lookup,
and process supervision.

The coordinator takes an explicit **master root**. It recursively discovers
Git repositories below that root, applies optional include/exclude/depth
filters, and snapshots each one for a worker. It does not clone, checkout,
reset, clean, or otherwise prepare them. A dirty worktree is valid input: the
files on disk are the input and their content is included in the snapshot
identity. Keep the master root dedicated to repositories and put the cache
outside it when possible.

### Install, build, and run

Build the Java worker jar and Go binary from the repository checkout:

```bash
./scripts/build.sh
```

The stable local artifacts are `dist/springmaster` and `dist/analyzer.jar`.
Git hooks are never installed by a build; install the repository hook only when
you explicitly want it and no hook of that name already exists:

```bash
./gradlew installGitHooks
```

Run a read-only scan of a master folder. `ROOT` is a positional argument; the
command has no implicit current-directory scan. The benchmark harness below
requires `ROOT` to be an existing absolute directory.

```bash
./dist/springmaster scan /srv/spring-repositories \
  --worker-command "java -jar $PWD/dist/analyzer.jar --worker" \
  --cache-dir "$PWD/.springmaster-cache" \
  --workers 4 \
  --mode STATIC_ONLY
```

`STATIC_ONLY` is the default and is suitable for dirty or untrusted source
trees. Use `EXTENDED` only after explicitly trusting every repository and its
Gradle build logic:

```bash
./dist/springmaster scan /srv/trusted-spring-repositories \
  --worker-command "java -jar $PWD/dist/analyzer.jar --worker" \
  --workers 2 \
  --mode EXTENDED \
  --trust-extended
```

`EXTENDED` can invoke the Gradle Tooling API. Repository-controlled settings,
init scripts, plugins, and build logic may execute during model resolution. Run
that mode in a disposable, network-restricted sandbox when trust is not
complete. The Go coordinator does not make `EXTENDED` safe, and master-folder
EXTENDED scans are limited to exactly one discovered repository.

### Release assets

Each GitHub Release includes an archive per supported OS/architecture. Every
archive contains the matching `springmaster` binary, `analyzer.jar`, and a
component `SHA256SUMS`; the standalone `analyzer.jar` remains available for the
original Java CLI. The top-level `SHA256SUMS` verifies every released asset.

```bash
# Linux
sha256sum -c SHA256SUMS

# macOS
shasum -a 256 -c SHA256SUMS

tar -xzf springmaster_vX.Y.Z_darwin_arm64.tar.gz
./springmaster scan /absolute/master/root \
  --worker-command "java -jar $PWD/analyzer.jar --worker"
```

### Architecture and worker boundary

```text
master root
    │ discover repositories + compute content identity
    ▼
Go coordinator ── bounded jobs ──► Java worker 1 ─┐
      │                         Java worker 2 ─┼─ JSONL result/error
      │                         Java worker N ─┘
      └─ cache lookup/write, ordering, exit status
```

Each Java worker is a long-lived JVM. The coordinator sends one JSON object per
line on worker stdin and reads one response per line from stdout; diagnostics
stay on stderr. Requests contain `schemaVersion`, `requestId`,
`repositoryPath`, `repositoryId`, `contentHash`, and `mode`. A malformed request
or an analyzer failure is reported for that request and does not require the
worker to exit. See [docs/WORKER_PROTOCOL.md](docs/WORKER_PROTOCOL.md).

Maven/Gradle modules with Java sources are analyzed separately. A static
cross-repository graph orders local dependencies first and propagates dependency
content into cache identities, while unresolved dynamic build logic is reported
without executing the target build.

Cache entries are content-addressed. The logical key is:

```text
(protocol schema version, worker command and artifact identity, repository ID,
 dependency-aware content hash, analysis mode, rule-configuration identity)
```

The absolute repository path, worker count, wall-clock timestamp, and queue
position are not cache inputs. A dirty change therefore produces a new key
without changing or cleaning the worktree. Local Maven/Gradle dependencies are
folded into an effective hash, so a dependency repository change invalidates
its dependents. Regular files named by the worker command (including the
analyzer JAR) are content-hashed. See [docs/MASTER_FOLDER.md](docs/MASTER_FOLDER.md) and
[docs/PERFORMANCE.md](docs/PERFORMANCE.md).

### Control-plane exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no finding met configured failure threshold |
| `1` | Scan completed; at least one finding met threshold |
| `2` | Operational failure: invalid master root at runtime, worker startup/protocol failure, or I/O error |
| `4` | Invalid command-line arguments or configuration |

An individual worker failure is included in the run result and causes the
control plane to use an operational-failure status if the run cannot complete.
The existing Java analyzer and its Go control plane are distributed under the
repository's [Apache-2.0 license](LICENSE), with the Java analyzer based on the
upstream `RobbanHoglund/spring-boot-analyzer` project. Preserve upstream license
and attribution notices in redistributed builds.

In Docker (no web server started):
```bash
docker run --rm \
  -e ANALYZER_TOKEN="$GITHUB_TOKEN" \
  spring-boot-analyzer \
  --repo https://github.com/owner/repo.git \
  --format sarif \
  --output /dev/stdout
```

---

## Docker

Build and run with Docker (no local Java or Node.js required):

```bash
docker build -t spring-boot-analyzer .
docker run -p 8085:8085 spring-boot-analyzer
```

Open `http://localhost:8085/` for the UI.

**Pass custom configuration** (e.g. to configure workspace cleanup):

```bash
docker run -p 8085:8085 \
  -e ANALYZER_WORKSPACE_CLEANUP_MAX_AGE_DAYS=3 \
  spring-boot-analyzer
```

**Mount a workspace directory** if you want cloned repositories to persist across restarts:

```bash
docker run -p 8085:8085 \
  -v /tmp/analyzer-workspaces:/tmp/spring-boot-analyzer \
  spring-boot-analyzer
```

---

## Quick start

**Requirements:** Java 25, Node 22, Git.

**1. Start the backend**

macOS / Linux:
```bash
./gradlew bootRun
```

Windows (PowerShell):
```powershell
.\gradlew.bat bootRun
```

**2. Open the UI**

```
http://localhost:8085/
```

The UI is served by Spring Boot from `frontend/dist`. A pre-built frontend is included; run the full build below if you need to rebuild it.

---

## Building

**Build everything (frontend + backend)**

macOS / Linux:
```bash
cd frontend && npm install && npm run build && cd ..
./gradlew bootRun
```

Windows (PowerShell):
```powershell
cd frontend; npm install; npm run build; cd ..
.\gradlew.bat bootRun
```

**Run backend tests**

```bash
./gradlew clean test        # macOS / Linux
.\gradlew.bat clean test    # Windows
```

The default `test` task runs the fast, offline unit and component suite. Two
network-dependent Gradle Tooling API integration tests are tagged `integration`
and excluded by default — they download a real Gradle distribution and resolve
dependencies over the network. Run them explicitly when needed (CI runs them
automatically):

```bash
./gradlew integrationTest        # macOS / Linux
.\gradlew.bat integrationTest    # Windows
```

### Building behind a corporate proxy

Gradle resolves the Spring Boot plugin from `plugins.gradle.org` during *configuration*, before
any project code runs, so a blocked or TLS-intercepting proxy fails the build with
`Could not download spring-boot-gradle-plugin` / `Got socket exception during request. It might be
caused by SSL misconfiguration`.

Gradle does not read `HTTP_PROXY`/`HTTPS_PROXY`; it needs JVM system properties. Put them in
`~/.gradle/gradle.properties` (user-level, so they apply to every project and stay out of the
repository):

```properties
systemProp.https.proxyHost=proxy.corp.example.com
systemProp.https.proxyPort=8080
systemProp.http.proxyHost=proxy.corp.example.com
systemProp.http.proxyPort=8080
systemProp.http.nonProxyHosts=localhost|127.0.0.1|*.corp.example.com
```

If the proxy terminates TLS with its own root certificate, also import that certificate into a
truststore and point the JVM at it:

```properties
systemProp.javax.net.ssl.trustStore=C:/certs/corp-truststore.jks
systemProp.javax.net.ssl.trustStorePassword=changeit
```

**If the proxy or bypass does not answer HTTP `HEAD`** (symptom: `Could not HEAD '…'` followed by
`Connection reset`), no Gradle setting can work around it. Gradle issues a `HEAD` before every
download to check the artifact's existence and metadata, and there is no supported flag to make it
use `GET` instead —
[gradle/gradle#5322](https://github.com/gradle/gradle/issues/5322) was closed as *not planned*.
(`--no-validate-url` only affects the `gradle wrapper` task's distribution-URL check, not plugin or
dependency resolution.) Either have `HEAD` allowed for `plugins.gradle.org` and `repo1.maven.org`,
or route through a repository mirror that terminates HTTP itself.

**Using an internal Artifactory/Nexus mirror** — this build supports one without any repository
change. Set `corpRepoUrl` in `~/.gradle/gradle.properties` (never in this repository, so CI and
external contributors keep using the public repositories):

```properties
corpRepoUrl=https://artifactory.example.com/artifactory/gradle-remote
corpRepoUsername=your-user
corpRepoPassword=your-api-token
```

`settings.gradle` (`pluginManagement`) and `build.gradle` (`repositories`) both prepend that
repository when the property is present, keeping `gradlePluginPortal()`/`mavenCentral()` as
fallbacks. Username and password are optional, but they must be provided together; omit both for
an anonymous mirror. If the mirror URL is unreachable the build fails and lists every repository
it searched, rather than silently falling back.

**Analyzing repositories behind the same proxy** — the analyzer runs Gradle against the projects
it inspects, so it has its own proxy settings (see `src/main/resources/application.properties`):
`analyzer.gradle.proxy.enabled`/`host`/`port`/`username`/`password` inject explicit JVM proxy
settings, `analyzer.gradle.copy-host-gradle-proxy-properties=true` (the default) reuses the proxy
entries from your own `~/.gradle/gradle.properties`, and `analyzer.gradle.pass-through-environment`
forwards `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`. If a target project still cannot resolve, run the
analysis in `STATIC_ONLY` mode — it then never invokes Gradle.

**Run frontend tests**

```bash
cd frontend && npm test
```

---

## Frontend development

The Vite dev server proxies `/api` requests to `http://localhost:8085`.

macOS / Linux:
```bash
# Terminal 1 — backend
./gradlew bootRun

# Terminal 2 — frontend
cd frontend
npm install
npm run dev
```

Windows (PowerShell):
```powershell
# Terminal 1 — backend
.\gradlew.bat bootRun

# Terminal 2 — frontend
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173/` for the dev UI with hot reload.

---

## API

### Analyze a repository

```
POST /api/analyze
Content-Type: application/json
```

**Public repository**
```bash
curl -X POST http://localhost:8085/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "repositoryUrl": "https://github.com/example/my-spring-app.git",
    "branch": "main"
  }'
```

**Private HTTPS repository**
```bash
curl -X POST http://localhost:8085/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "repositoryUrl": "https://github.com/example/private-app.git",
    "branch": "main",
    "credentials": {
      "username": "octocat",
      "token": "ghp_..."
    }
  }'
```

**Extended analysis** *(includes Gradle dependency resolution)*
```bash
curl -X POST http://localhost:8085/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "repositoryUrl": "https://github.com/example/my-spring-app.git",
    "branch": "main",
    "analysisMode": "EXTENDED"
  }'
```

**`analysisMode` values**

| Value | Description |
|-------|-------------|
| `STATIC_ONLY` | Default. Build file parsing, Java source analysis, configuration analysis. |
| `EXTENDED` | All of `STATIC_ONLY` plus Gradle Tooling API dependency resolution. |

### Fetch a source snippet

```
GET /api/analyses/{analysisId}/source-snippet?path=src/main/java/...&startLine=10&endLine=20&context=4
```

Returns a source snippet around a finding location. Used by the UI to render inline code previews.

---

## UI

The browser UI has three top-level views:

**Analyze** — Enter a repository URL and branch, optionally select a token profile, choose `STATIC_ONLY` or `EXTENDED` analysis mode, and run. Progress is streamed in real time.

**Results** — The report is divided into named sections accessible via a jump navigation bar (Runtime, Findings, HTTP, Scheduling, Configuration, Spring API, Components, Dependencies, Build model). Within the report:

- **Runtime stack** — detected web stack (Servlet MVC / WebFlux / unknown), Spring Boot version, Java version, virtual-threads status, and scheduling signals.
- **Findings** — filterable by severity (clickable toggle buttons for ERROR, WARNING, INFO), by category (dropdown with per-category counts), by runtime-detection confidence, and by free-text search. Findings can be grouped by rule. Each finding shows the rule ID, severity, confidence, explanation, recommendation, evidence, and an inline source preview with a direct link to the file on GitHub.
- **Dependencies** — summary cards, a managed-stack version grid (Spring Boot, Hibernate, Flyway, …), declared-dependency table, and a **collapsible dependency tree** grouped by Maven group ID. Spring groups are pinned to the top; groups with direct dependencies expand automatically. Existing filters (search, configuration selector, direct-only) apply before the tree is built.
- **Export** — copy findings as SARIF 2.1.0, download as JSON, or download a plain-text summary from the report header.

**Settings** — Manage HTTPS token profiles and saved repository profiles. Both are stored in browser `localStorage` and never sent to the backend except as part of an active analysis request.

---

## Suppressing findings

Add a `.analyzer-suppress.yml` file to the **root of the analyzed repository** to silence findings you've reviewed and accepted:

```yaml
suppress:
  - ruleId: SPRING_FIELD_INJECTION
    reason: "Legacy code — tracked for constructor-injection refactor in Q3"
  - ruleId: SPRING_JPA_OPEN_IN_VIEW
    reason: "Intentional: lazy loading required in view layer for this project"
```

Each entry requires a `ruleId` (the stable identifier shown in the UI and in SARIF output). The `reason` field is optional but recommended for auditability. Suppressed findings are removed from the report entirely; the count of suppressed findings is logged at INFO level on the server.

Rule IDs are listed in [docs/RULES.md](docs/RULES.md).

---

## Security model

- **No server-side credential storage.** HTTPS tokens are held in browser `localStorage` and transmitted only as part of an `/api/analyze` request. The backend does not persist them.
- **`STATIC_ONLY` mode (default) does not execute repository code.** It performs purely static analysis — no Gradle tasks, no Maven goals, no shell scripts, no application startup.
- **`EXTENDED` mode uses the Gradle Tooling API** to resolve dependency information. This may evaluate repository-controlled Gradle build configuration logic. Use it only for repositories you trust or inside an isolated sandbox. See [SECURITY.md](SECURITY.md).
- **Temporary workspaces.** Cloned repositories are written to a temporary workspace directory and cleaned up after analysis.
- **SSH repositories** use the SSH configuration of the server running the backend (e.g., `~/.ssh/known_hosts`, agent forwarding).

---

## Limitations

Spring Boot Analyzer is a static analysis tool. Its findings are advisory — not every finding is an actionable bug, and not every bug will be found.

- **Dynamic behavior is not visible.** Runtime decisions, reflection, and dynamic proxies cannot be fully analyzed statically.
- **Generated code is partially supported.** Lombok, MapStruct, and similar annotation processors generate bytecode that is not in the source tree. The analyzer reports this when the Gradle model confirms processors are present.
- **Multi-module projects have partial support.** Dependency resolution across modules requires `EXTENDED` mode and a working Gradle build.
- **Unconventional build setups may produce fewer findings.** The analyzer is optimized for standard Spring Boot projects.
- **All findings require human review.** Use the analyzer to focus attention, not to replace code review or testing.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a deeper look at how analysis works.

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Backend | Spring Boot 3.5, Java 25 |
| Git operations | JGit 7.6 |
| Java source parsing | JavaParser 3.28 |
| Build introspection | Gradle Tooling API 9.5 |
| Frontend | TypeScript, Vite |

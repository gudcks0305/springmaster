---
name: springmaster
description: "Scan an explicitly selected master root of local Spring/Java repositories with springmaster, find Spring bad patterns, compare repositories, or interpret its reports without uploading source."
---

# Springmaster

Use this skill when the user asks to use `springmaster`, scan or analyze many local
Spring/Java repositories, find Spring bad patterns, compare repository findings,
or interpret a springmaster report. Keep the workflow local and read-only.

## Scope and safety

- Require one explicit, user-selected **master root**: an existing absolute
  directory containing the repositories to inspect. Canonicalize it before use.
  There is no implicit current-directory scan. Do not scan `/`, `$HOME`, or a
  broad parent containing unrelated source unless the user explicitly narrows
  and authorizes that scope; use `--include`, `--exclude`, and `--max-depth` to
  keep discovery bounded.
- Never clean, reset, checkout, pull, clone, rewrite, build, or delete anything
  in a target repository. Dirty, staged, and untracked files are valid inputs:
  the coordinator copies them into a bounded private snapshot (skipping `.git`,
  `.gradle`, `.springmaster`, `build`, `target`, `dist`, `node_modules`, and IDE
  caches). Cache identity comes from the exact deterministic snapshot manifest,
  including copied ignored files. If a source changes while it is copied, that
  repository fails instead of caching a mixed snapshot; rerun after writes stop.
- Use the local worker JSONL boundary only. Do not start or call the analyzer's
  web/API surface, expose its API, send source to a remote service, or upload
  reports containing source paths/evidence. Keep reports and caches local.

## Locate the runtime

Resolve the runtime in this order; stop at the first complete pair. Do not run
a broad `find` over the filesystem or infer a checkout from an unrelated
directory.

1. If `command -v springmaster` succeeds, use it. A standard installation
   resolves the real executable symlink and its sibling `analyzer.jar`
   automatically.
2. If `SPRINGMASTER_HOME` is set, check only these exact layouts:
   `"$SPRINGMASTER_HOME/springmaster"` + `"$SPRINGMASTER_HOME/analyzer.jar"`,
   or the checkout layout `"$SPRINGMASTER_HOME/dist/springmaster"` +
   `"$SPRINGMASTER_HOME/dist/analyzer.jar"`.
3. Otherwise require an explicit checkout path, for example
   `SPRINGMASTER_CHECKOUT=/absolute/path/to/go-practice`, and use only its
   `dist/springmaster` and `dist/analyzer.jar` paths. Ask for the path if it is
   not supplied; do not search `$HOME`, `/Users`, `/`, or other broad roots.

Set `SPRINGMASTER_BIN` to the selected executable. If the PATH candidate is not
a paired installation, continue with the explicit `SPRINGMASTER_HOME` or
`SPRINGMASTER_CHECKOUT` candidates; never guess another analyzer JAR.

Verify the selected binary is executable and the JAR is a regular file. If
the explicit checkout pair is missing, build only that checkout with
`./scripts/build.sh` (or `make build`), then verify both paths; do not silently
substitute a remote binary or HTTP analyzer. The paired JAR is automatic:

```bash
"$SPRINGMASTER_BIN" scan "$MASTER_ROOT" \
  --mode STATIC_ONLY \
  --workers 2 \
  --format json
# No --cache-dir: uses the OS user cache directory under springmaster.
```

Use `SPRINGMASTER_ANALYZER_JAR=/absolute/path/analyzer.jar` or
`--worker-command COMMAND` only as an explicit advanced override.

Choose a finite, small `--workers N` value (start at `1` or `2`, then increase
only when memory/CPU allow it). Workers are persistent JVMs; an unbounded or
blindly large count makes results slower or less reliable.

`STATIC_ONLY` is the default and must remain the mode for untrusted or merely
unreviewed repositories. It parses source/build/configuration files without
running repository Gradle tasks, Maven goals, tests, scripts, or the app.

`EXTENDED` is a trust boundary. It also requires the CLI's
`--trust-extended` consent flag and exactly one discovered repository. Use it
only after the user explicitly authorizes `EXTENDED` for the named master root,
confirms that repository's Gradle logic is trusted, and permits execution in a
disposable sandbox with restricted network, credentials, and filesystem access.
Gradle Tooling API resolution can execute repository-controlled settings,
plugins, init scripts, and build logic; the Go coordinator does not sandbox that
JVM. If explicit trust, the required flag, or isolation are absent, stay in
`STATIC_ONLY` or ask for them.

## Cache and output

- Prefer a dedicated cache outside the master root, passed with `--cache-dir`.
  The default is the operating-system user cache directory under
  `springmaster`. Cache and report paths inside a discovered source repository
  are rejected unless the user explicitly passes `--allow-source-write`.
- Use `--no-cache` for a fresh measurement, whenever cache provenance is
  unclear, or when validating a changed analyzer. The current key includes
  protocol schema, worker command plus regular artifact contents, repository
  ID, exact snapshot/dependency-overlay hashes, mode, the local rule-config
  content state, and result-affecting worker environment fingerprints; it
  excludes worker count. A copied dirty,
  untracked, ignored, nested-repository, or statically resolved local dependency
  change therefore gets a new key.
- Keep the cache enabled for ordinary branch switching. A fully clean, tracked
  `STATIC_ONLY` workspace can print `cache replay:` after securely confirming the exact source
  bytes and reuse prior exact result keys without writing snapshots or starting
  the Java worker. Dirty, staged, untracked, relevant ignored, sparse, filtered,
  submodule, `EXTENDED`, or otherwise uncertain Git states automatically use
  the normal snapshot path. Replay is workspace-wide, so one ineligible repository makes
  that scan fall back; never describe it as file-level incremental indexing.
- Use `--format json` for aggregation/comparison and `--format text` for a
  human-readable one-off review. Use `--output PATH` when the report must be
  retained; treat it as local potentially sensitive output.

## Interpret and compare

Check repository statuses and the summary, not only process output. Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Scan completed with no finding at/above `--fail-on`. |
| `1` | Scan completed and at least one finding met the threshold; inspect the report. |
| `2` | Operational/incomplete result: discovery, worker, protocol, snapshot, or I/O failure. |
| `4` | Invalid command-line arguments or configuration. |

Do not call code `2` a clean scan. For cross-repository comparison, hold
analyzer JAR/command identity, mode, rule configuration, scope, and cache policy
constant. Raw finding counts are not size- or architecture-normalized: compare
severity/rule/category and inspect file evidence while accounting for repository
size, modules, language mix, and failed/omitted repositories. A finding is a
review signal, not proof of a production vulnerability.

Once the explicit master root is canonicalized, the coordinator analyzes each
discovered Git repository once; modules are not accidentally submitted as
separate repositories. Within one repository, Java analysis shares source
context and statically parsed build metadata across nested Maven/Gradle modules,
while independent deployable applications remain separately scoped for global
rules. Across repositories in that confirmed root, statically resolved local
Maven/Gradle dependency edges provide dependency-first ordering,
dependency-aware cache invalidation, and a bounded Java-source-only dependency
overlay for static semantic context. Dependency build scripts/resources are not
injected, and findings owned by the overlay are excluded from the target
repository's report. Treat unresolved, dynamic, external, or ambiguous graph
diagnostics as a limit: classpath binary resolution and arbitrary build/runtime
effects are not implied.

## Install this repo-native skill

From this checkout:

```bash
./scripts/install-skill.sh
# replace only an existing exact target:
./scripts/install-skill.sh --force
```

The helper copies to exactly `${CODEX_HOME:-$HOME/.codex}/skills/springmaster`.
It rejects an existing destination unless `--force`, validates the target, and
never removes sibling skills or unrelated files.

Install the paired CLI runtime separately:

```bash
./scripts/install-cli.sh --build
# update only an existing managed installation:
./scripts/install-cli.sh --build --force
```

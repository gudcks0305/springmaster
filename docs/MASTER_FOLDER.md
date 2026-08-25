# Master-folder operation

`springmaster` scans a user-selected directory containing Spring repositories.
The directory is called the **master root** in the CLI and the **master folder**
in this document. It is an input boundary, not a workspace that the tool owns.

## Layout

The usual layout is one repository per child directory, though discovery can
walk nested directories:

```text
/srv/spring-repositories/       # explicit ROOT (or harness --master-root)
├── billing-service/             # may be clean or dirty
├── catalog-service/
└── team/shipping-service/       # nested Git repository is also discoverable
```

Repository discovery is deterministic. Non-project files and unsupported
entries are skipped or reported as discovery results; they are never treated as
permission to scan an unrelated parent directory. Use a separate master root
for unrelated source trees.

The root must be supplied explicitly as an existing absolute directory:

```bash
./springmaster scan /srv/spring-repositories \
  --mode STATIC_ONLY
```

The coordinator canonicalizes the root before discovery. The CLI accepts a
positional `ROOT`; the benchmark harness additionally requires it to be an
explicit absolute path. Missing paths and regular files are errors. A path
containing spaces is fine when quoted.

## Dirty repositories are supported

A repository does not need a clean Git status. `springmaster` reads the files
that exist at scan time and does not run any preparation command:

- no `git reset`, `git clean`, checkout, pull, or clone;
- no generated-file deletion or source rewrite;
- no Gradle/Maven/application execution in `STATIC_ONLY`;
- no assumption that `HEAD` describes all files in the snapshot.

Tracked edits, staged edits, untracked files, and copied Git-ignored files are
represented by the exact deterministic snapshot manifest hash. If a dirty
repository changes while it is copied, the coordinator rejects the mixed
snapshot rather than caching it. Rerun after writers stop; do not edit a
repository while it is being benchmarked.

The scanner must not follow a symlink outside the selected boundary as a way to
expand the scan. Mount or copy a repository into the master root when a
different filesystem boundary is required.

## Modules and repository relationships

`springmaster` statically reads Maven and Gradle descriptors across the selected
repositories. Each Git repository is snapshotted and analyzed exactly once at
its repository root. The Java analyzer discovers nested module source roots and
builds one project-wide source index, preserving parent build files, sibling
modules, composed annotations, and cross-module calls. Findings remain attached
to their source paths; modules are not isolated worker requests.

Local artifact and project dependencies determine dependency-first ordering and
are folded into effective snapshot hashes; changing a library repository
therefore invalidates cached results for statically resolved dependents. Before
a dependent is analyzed, the coordinator also materializes a bounded
Java-source-only overlay of its transitive local dependencies. This exposes
dependency annotations, base types, and source contracts to static rules while
excluding dependency-owned findings from the dependent repository report.

This graph never executes Maven or Gradle. Dynamic Gradle code, external parent
POMs/BOMs, composite builds, binary-only classpaths, and ambiguous coordinates
remain diagnostics, not invented edges. Dependency build scripts and resources
are not injected, so their runtime effect is not claimed as resolved.

## Cache and identity

Cache storage is separate from repository input. The default is the platform
user cache directory returned by Go's `os.UserCacheDir`, below a `springmaster`
child. It is never `ROOT/.springmaster`. Supply a dedicated location, for
example:

```bash
./springmaster scan /srv/spring-repositories \
  --cache-dir /var/tmp/springmaster-cache \
  --workers 4
```

An explicit cache or report output path inside a discovered source repository is
rejected. `--allow-source-write` overrides this guard for an intentional local
artifact, but is discouraged because it changes the next snapshot. Report files
are written through a private `0600` temporary file and atomically renamed;
symlink destinations are rejected.

`--cache-dir` must name a dedicated leaf. Filesystem roots, the user home,
the system temporary root, and any ancestor of a discovered source repository
are always rejected; `--allow-source-write` does not override these broad-target
guards.

Each cache entry is keyed by the protocol schema, worker command and regular
artifact contents, repository identity, dependency-aware deterministic snapshot content hash, analysis mode, and rule
configuration identity. In notation:

```text
K = (schemaVersion, workerArtifacts, repositoryId, effectiveContentHash, mode, ruleConfig)
```

`repositoryId` distinguishes projects with identical source; the effective
hash distinguishes clean and dirty snapshots and incorporates statically
resolved local Maven/Gradle dependency repositories. Absolute paths, worker
count, timing, and discovery order do not change `K`. Changing the
protocol schema invalidates old results rather than reusing a possibly
incompatible payload. Cache writes belong under `--cache-dir` only; target
repositories remain input data.

The rule/config identity hashes the content or missing state of
`~/.spring-boot-analyzer/rule-config.json`, including candidate homes supplied
through JVM `-Duser.home` options. Files larger than 8 MiB are rejected rather
than partially fingerprinted. In `STATIC_ONLY`, the runtime fingerprint covers
`ANALYZER_*`, `SPRING_*`, JVM option, home/JDK, locale, and timezone environment
variables. In `EXTENDED`, it covers the complete inherited environment because
the configured Gradle pass-through list can name arbitrary variables. Values,
secrets, and absolute config paths feed only SHA-256 identity material; reports
and cache diagnostics do not expose them.

A scan accepts at most 128 discovered repositories and holds at most 200,000
snapshot manifest entries or 1 GiB of copied bytes across the run. Per-repository
snapshot limits still apply. After the exact dependency graph and required
semantic context are materialized, cache-hit snapshots are removed immediately;
miss snapshots are removed as soon as their worker response completes.

## Security boundary

`STATIC_ONLY` is safe default for source trees that are not trusted. The Java
worker parses Java and build/configuration files without running repository
Gradle tasks, Maven goals, tests, shell scripts, or the application.

`EXTENDED` is a trust boundary, not a performance toggle. It is rejected unless
both `--mode EXTENDED` and `--trust-extended` are supplied. The CLI prints a
warning when this mode starts. An EXTENDED scan must discover exactly one
repository; scan repositories separately so repository-controlled build logic
cannot inspect sibling snapshots. The trust flag records explicit consent; it does
not create a sandbox. Gradle Tooling API
resolution can evaluate repository-controlled Gradle settings, plugins, and
build logic. Use only for repositories you own or have reviewed, preferably in
a disposable sandbox with restricted credentials, network, and filesystem
access. A Go flag or worker pool does not sandbox a JVM.

Workers communicate through the JSONL contract in
[WORKER_PROTOCOL.md](WORKER_PROTOCOL.md). Worker stderr is diagnostic only;
secrets and source contents must not be copied into error messages. A request
failure is scoped to its request so another repository can still be processed.

## Exit status

The control plane uses the same threshold-oriented status convention as the
Java CLI:

| Code | Meaning |
|------|---------|
| `0` | Completed with no finding at/above threshold |
| `1` | Completed with at least one finding at/above threshold |
| `2` | Clone-free scan could not complete: worker, protocol, or I/O failure |
| `4` | Invalid arguments, including an invalid or omitted ROOT/worker command |

Always inspect the report when code `1` is returned. Code `2` means the report
is incomplete and should not be used as a clean result.

## Upstream and licensing

The Java analyzer and its findings model come from the upstream
`RobbanHoglund/spring-boot-analyzer` project. `springmaster` adds a Go control
plane and worker protocol around that analyzer; it does not remove or replace
the upstream Apache License 2.0 grant. Keep [LICENSE](../LICENSE) and any
upstream attribution notices with source and binary distributions.

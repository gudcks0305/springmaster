# Performance and benchmark method

`springmaster` performance is dominated by source parsing, JVM startup, cache
reuse, repository size, and worker contention. This document defines a small,
repeatable benchmark rather than promising a universal throughput number.

## Cache model

One logical result key is:

```text
(protocol schema version, worker command and artifact identity, repository ID,
 dependency-aware content hash, analysis mode, rule-configuration identity)
```

The key excludes absolute path, worker count, queue order, and timestamp. A
clean snapshot and a dirty snapshot therefore never alias accidentally. A new
worker count can be compared against the same cached result, but it does not
measure analyzer work on a cache hit.

The worker command, regular files named by it (including the analyzer JAR), and
protocol schema are part of the key. Benchmark reports should still record the
Git revision and JAR digest
alongside wall times when results are kept outside this repository.

## Cold versus warm

- **Cold:** every iteration receives a new empty cache directory. This includes
  cache-miss work and any worker/JVM startup cost exposed by the invocation.
- **Warm:** the same private cache directory is reused for all iterations in a
  phase. The first iteration populates it; later iterations show hit behavior.
- **Workers:** `--workers N` controls the bounded Java worker pool. Keep master
  root, repository contents, mode, jar, and iteration count fixed when comparing
  worker values.

Run the repository-owned harness from the checkout:

```bash
./scripts/benchmark.sh \
  --master-root /srv/spring-repositories \
  --java-jar "$PWD/build/libs/spring-boot-analyzer.jar" \
  --iterations 5 \
  --workers 4 \
  --mode STATIC_ONLY
```

Optional binary override:

```bash
./scripts/benchmark.sh \
  --binary ./springmaster \
  --master-root /srv/spring-repositories \
  --java-jar ./build/libs/spring-boot-analyzer.jar \
  --iterations 3 \
  --workers 2
```

The harness options `--master-root` and `--java-jar` are wrapper options. Each
run invokes the actual CLI as `springmaster scan ROOT --worker-command ...
--cache-dir PRIVATE_TEMP`. Use `--worker-command` instead of `--java-jar` when
the worker needs a custom executable or JVM flags; it is passed as one argv
value and is never evaluated by a shell.

The script prints tab-separated rows with phase, iteration, worker count,
wall-clock seconds, and process exit status. It intentionally collects wall
time only; it does not claim CPU, memory, disk, or network measurements.
Analyzer code `0` (no findings) and `1` (findings reached threshold) both count
as completed scans. Startup, protocol, I/O, or argument failures (`2` or `4`)
are reported and make the harness exit non-zero.

## Safety contract

The harness is read-only with respect to the target master root and its child
repositories:

- `--master-root` is mandatory, absolute, canonicalized, and must be a
  directory; there is no default target;
- all user values are passed as shell array arguments; no `eval`, shell string
  interpolation, or `sh -c` is used;
- mode defaults to `STATIC_ONLY`; `EXTENDED` requires an explicit trust opt-in;
- cold and warm caches live below a private `mktemp` directory owned by the
  harness, never below a target repository;
- no `git clean`, checkout, reset, build, or delete command targets a
  repository; the only cleanup removes the harness-owned temporary directory;
- output is discarded except for timing and failure status, so benchmark runs
  do not retain source contents or analyzer reports.

Do not benchmark a repository while another process is writing it. A changing
worktree changes its content hash and makes both cache and timing comparisons
ambiguous.

## Interpreting results

Compare medians or distributions, not a single run. Report cold and warm phases
separately. Note Java version, OS, filesystem, repository count and approximate
size, worker count, analyzer jar identity, mode, and cache state. A warm run can
be dramatically faster because it measures cache hits; it is not evidence that
the analyzer's cold path became faster. More workers can reduce wall time until
CPU, memory, file descriptors, or JVM startup contention dominates.

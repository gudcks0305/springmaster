#!/usr/bin/env bash

# Read-only springmaster benchmark harness.
# Target repositories are never used as scratch space and never deleted.

set -Eeuo pipefail
IFS=$' \t\n'
CDPATH=

SCRIPT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
BINARY_RAW="${SPRINGMASTER_BINARY:-$SCRIPT_ROOT/dist/springmaster}"
MASTER_ROOT_RAW=''
JAVA_JAR_RAW="${SPRINGMASTER_JAVA_JAR:-}"
WORKER_COMMAND_RAW="${SPRINGMASTER_WORKER_COMMAND:-}"
ITERATIONS=3
WORKERS=1
MODE=STATIC_ONLY
TRUST_EXTENDED=0

# These are single argv entries, never shell fragments. They make the harness
# usable with a compatible flag spelling without introducing eval/shell code.
WORKER_FLAG="${SPRINGMASTER_WORKER_FLAG:---worker-command}"
CACHE_FLAG="${SPRINGMASTER_CACHE_FLAG:---cache-dir}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmark.sh --master-root ABS_DIR (--java-jar JAR | --worker-command COMMAND) [options]

Required:
  --master-root PATH       Existing absolute master folder (read-only input)
  --java-jar PATH          Analyzer worker jar; harness builds a worker command
  --worker-command COMMAND Explicit worker command passed as one argument

Options:
  --binary PATH            springmaster executable (default: ./dist/springmaster)
  --iterations N           Cold and warm iterations, positive integer (default: 3)
  --workers N              Java worker count, positive integer (default: 1)
  --mode MODE              STATIC_ONLY (default) or EXTENDED
  --trust-extended         Required together with --mode EXTENDED
  -h, --help               Show this help

Environment overrides (each is one long option, not shell code):
  SPRINGMASTER_BINARY, SPRINGMASTER_JAVA_JAR, SPRINGMASTER_WORKER_COMMAND
  SPRINGMASTER_WORKER_FLAG, SPRINGMASTER_CACHE_FLAG
USAGE
}

die() {
  printf 'benchmark: %s\n' "$*" >&2
  exit 4
}

is_positive_int() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

is_long_flag() {
  [[ "$1" =~ ^--[A-Za-z0-9][A-Za-z0-9-]*$ ]]
}

resolve_existing_file() {
  local raw=$1
  local parent name
  if [[ "$raw" == /* ]]; then
    parent=${raw%/*}
    name=${raw##*/}
    [[ -n "$parent" ]] || parent=/
  else
    parent=${raw%/*}
    name=${raw##*/}
    [[ "$parent" != "$raw" ]] || parent=.
  fi
  local canonical_parent
  if ! canonical_parent=$(cd -- "$parent" && pwd -P); then
    return 1
  fi
  local result="$canonical_parent/$name"
  [[ -f "$result" ]] || return 1
  printf '%s\n' "$result"
}

resolve_executable() {
  local raw=$1
  local candidate
  if [[ "$raw" == */* ]]; then
    candidate=$(resolve_existing_file "$raw") || return 1
    [[ -x "$candidate" ]] || return 1
    printf '%s\n' "$candidate"
    return 0
  fi
  candidate=$(command -v "$raw") || return 1
  [[ -x "$candidate" ]] || return 1
  printf '%s\n' "$candidate"
}

validate_flag() {
  local flag=$1
  is_long_flag "$flag" || die "invalid option override: $flag"
}

while (($# > 0)); do
  case "$1" in
    --master-root)
      (($# >= 2)) || die "--master-root requires a value"
      MASTER_ROOT_RAW=$2
      shift 2
      ;;
    --java-jar)
      (($# >= 2)) || die "--java-jar requires a value"
      JAVA_JAR_RAW=$2
      shift 2
      ;;
    --worker-command)
      (($# >= 2)) || die "--worker-command requires a value"
      WORKER_COMMAND_RAW=$2
      shift 2
      ;;
    --binary)
      (($# >= 2)) || die "--binary requires a value"
      BINARY_RAW=$2
      shift 2
      ;;
    --iterations)
      (($# >= 2)) || die "--iterations requires a value"
      ITERATIONS=$2
      shift 2
      ;;
    --workers)
      (($# >= 2)) || die "--workers requires a value"
      WORKERS=$2
      shift 2
      ;;
    --mode)
      (($# >= 2)) || die "--mode requires a value"
      MODE=$2
      shift 2
      ;;
    --trust-extended)
      TRUST_EXTENDED=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$MASTER_ROOT_RAW" ]] || die "--master-root is required; no implicit target"
[[ "$MASTER_ROOT_RAW" == /* ]] || die "--master-root must be an absolute path"
if [[ -n "$JAVA_JAR_RAW" && -n "$WORKER_COMMAND_RAW" ]]; then
  die "use exactly one of --java-jar or --worker-command"
fi
[[ -n "$JAVA_JAR_RAW" || -n "$WORKER_COMMAND_RAW" ]] \
  || die "--java-jar or --worker-command is required"
is_positive_int "$ITERATIONS" || die "--iterations must be a positive integer"
is_positive_int "$WORKERS" || die "--workers must be a positive integer"
case "$MODE" in
  STATIC_ONLY) ;;
  EXTENDED)
    ((TRUST_EXTENDED == 1)) || die "EXTENDED requires --trust-extended"
    ;;
  *)
    die "--mode must be STATIC_ONLY or EXTENDED"
    ;;
esac
validate_flag "$WORKER_FLAG"
validate_flag "$CACHE_FLAG"

if ! MASTER_ROOT=$(cd -- "$MASTER_ROOT_RAW" && pwd -P); then
  die "cannot access --master-root: $MASTER_ROOT_RAW"
fi
[[ -d "$MASTER_ROOT" && -r "$MASTER_ROOT" && -x "$MASTER_ROOT" ]] \
  || die "--master-root is not a readable directory: $MASTER_ROOT"
[[ "$MASTER_ROOT" != / ]] || die "refusing filesystem root as benchmark target"

if ! BINARY=$(resolve_executable "$BINARY_RAW"); then
  die "executable not found or not executable: $BINARY_RAW"
fi
if [[ -n "$JAVA_JAR_RAW" ]]; then
  if ! JAVA_JAR=$(resolve_existing_file "$JAVA_JAR_RAW"); then
    die "Java worker jar not found: $JAVA_JAR_RAW"
  fi
  # Go's worker-command parser treats backslash and double quote as syntax.
  # Reject those path bytes instead of trying to synthesize shell-like quoting.
  case "$JAVA_JAR" in
    *\\*|*\"*|*$'\n'*)
      die "Java worker jar path contains unsupported quoting characters"
      ;;
  esac
  WORKER_COMMAND_RAW="java -jar \"$JAVA_JAR\" --worker"
fi
WORKER_COMMAND=$WORKER_COMMAND_RAW

TIME_BIN=/usr/bin/time
[[ -x "$TIME_BIN" ]] || die "required wall-clock timer missing: $TIME_BIN"

RUN_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/springmaster-benchmark.XXXXXX")
OWNER_MARKER="$RUN_ROOT/.springmaster-benchmark-owned"
: > "$OWNER_MARKER"

cleanup() {
  # Only remove the private directory created above, identified by its marker.
  if [[ -n "${RUN_ROOT:-}" && -f "${RUN_ROOT:-}/.springmaster-benchmark-owned" ]]; then
    rm -rf -- "$RUN_ROOT"
  fi
}
trap cleanup EXIT

COMMON_ARGS=(
  scan "$MASTER_ROOT"
  "$WORKER_FLAG" "$WORKER_COMMAND"
  --workers "$WORKERS"
  --mode "$MODE"
)

failures=0
printf 'phase\titeration\tworkers\tmode\twall_seconds\texit_code\n'

run_once() {
  local phase=$1
  local iteration=$2
  local cache_root=$3
  local timing_file="$RUN_ROOT/${phase}-${iteration}.time"
  local stderr_file="$RUN_ROOT/${phase}-${iteration}.stderr"
  local status wall

  set +e
  SPRINGMASTER_READ_ONLY=1 SPRINGMASTER_BENCHMARK=1 \
    "$TIME_BIN" -p -o "$timing_file" \
    "$BINARY" "${COMMON_ARGS[@]}" "$CACHE_FLAG" "$cache_root" \
    > /dev/null 2> "$stderr_file"
  status=$?
  set -e

  wall=$(awk '$1 == "real" { print $2; exit }' "$timing_file" 2>/dev/null || true)
  [[ -n "$wall" ]] || wall=NA
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$phase" "$iteration" "$WORKERS" "$MODE" "$wall" "$status"

  # Java CLI code 1 means completed with findings; codes 2/4 are failures.
  if ((status > 1)); then
    failures=$((failures + 1))
    printf 'benchmark: %s iteration %s failed with exit %s\n' \
      "$phase" "$iteration" "$status" >&2
    if [[ -s "$stderr_file" ]]; then
      tail -20 "$stderr_file" >&2 || true
    fi
  fi
}

for ((iteration = 1; iteration <= ITERATIONS; iteration++)); do
  cold_cache=$(mktemp -d "$RUN_ROOT/cold-${iteration}.XXXXXX")
  run_once cold "$iteration" "$cold_cache"
done

warm_cache="$RUN_ROOT/warm-cache"
mkdir -- "$warm_cache"
for ((iteration = 1; iteration <= ITERATIONS; iteration++)); do
  run_once warm "$iteration" "$warm_cache"
done

if ((failures > 0)); then
  exit 2
fi

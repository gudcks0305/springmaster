#!/usr/bin/env bash

# Install only the repository-native springmaster skill.
# The destination is intentionally fixed; do not turn this into a general copier.
set -Eeuo pipefail
IFS=$'\n\t'
CDPATH=

usage() {
  cat <<'USAGE'
Usage: scripts/install-skill.sh [--force]

Copy this checkout's skills/springmaster to exactly:
  ${CODEX_HOME:-$HOME/.codex}/skills/springmaster

The destination must not already exist unless --force is supplied.
USAGE
}

die() {
  printf 'install-skill: %s\n' "$*" >&2
  exit 1
}

canonical_dir() {
  local directory=$1
  (
    CDPATH=
    cd -- "$directory" || exit 1
    pwd -P
  )
}

force=0
while (($# > 0)); do
  case "$1" in
    --force)
      force=1
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

script_dir=$(canonical_dir "$(dirname -- "${BASH_SOURCE[0]}")") \
  || die 'cannot resolve script directory'
checkout_root=$(canonical_dir "$script_dir/..") \
  || die 'cannot resolve checkout root'
source_skill="$checkout_root/skills/springmaster"

[[ -d "$source_skill" ]] || die "source skill directory missing: $source_skill"
[[ -f "$source_skill/SKILL.md" ]] || die "source SKILL.md missing: $source_skill/SKILL.md"
[[ -f "$source_skill/agents/openai.yaml" ]] \
  || die "source agents/openai.yaml missing: $source_skill/agents/openai.yaml"

if [[ -n "${CODEX_HOME:-}" ]]; then
  codex_home_raw=$CODEX_HOME
else
  [[ -n "${HOME:-}" ]] || die 'HOME or CODEX_HOME is required'
  codex_home_raw="$HOME/.codex"
fi
[[ -n "$codex_home_raw" ]] || die 'HOME or CODEX_HOME is required'
[[ "$codex_home_raw" == /* ]] \
  || die "CODEX_HOME/HOME must be an absolute path: $codex_home_raw"
[[ "$codex_home_raw" != / ]] || die 'refusing filesystem root as CODEX_HOME/HOME'

# Create only the user-selected Codex home if it does not exist, then resolve
# symlinks before validating the exact skill target.
if [[ -L "$codex_home_raw" ]]; then
  codex_home=$(canonical_dir "$codex_home_raw") \
    || die "cannot resolve CODEX_HOME/HOME: $codex_home_raw"
else
  mkdir -p -- "$codex_home_raw" \
    || die "cannot create CODEX_HOME/HOME: $codex_home_raw"
  codex_home=$(canonical_dir "$codex_home_raw") \
    || die "cannot resolve CODEX_HOME/HOME: $codex_home_raw"
fi
[[ "$codex_home" != / ]] || die 'refusing filesystem root as resolved CODEX_HOME/HOME'

skills_dir="$codex_home/skills"
if [[ -L "$skills_dir" ]]; then
  die "refusing symlink skills directory: $skills_dir"
fi
mkdir -p -- "$skills_dir" || die "cannot create skills directory: $skills_dir"
skills_dir=$(canonical_dir "$skills_dir") \
  || die 'cannot resolve skills directory'

target="$skills_dir/springmaster"
expected_target="$codex_home/skills/springmaster"
[[ "$target" == "$expected_target" ]] \
  || die "internal target validation failed: $target"
[[ "$target" == /* && "$(basename -- "$target")" == springmaster ]] \
  || die "refusing non-exact skill target: $target"
[[ "$target" != / && "$target" != "$skills_dir" ]] \
  || die "refusing broad target: $target"

target_exists=0
if [[ -e "$target" || -L "$target" ]]; then
  target_exists=1
  ((force == 1)) || die "destination exists: $target (use --force to replace it)"
  [[ -L "$target" ]] \
    && die "refusing to replace symlink destination: $target"
fi

staging_root=$(mktemp -d "$skills_dir/.springmaster-install.XXXXXX") \
  || die "cannot create staging directory below $skills_dir"
replacement_root=''
preserve_replacement=0
cleanup() {
  if [[ -n "${staging_root:-}" && -d "$staging_root" ]]; then
    rm -rf -- "$staging_root"
  fi
  if [[ "$preserve_replacement" -eq 0 \
    && -n "${replacement_root:-}" && -d "$replacement_root" ]]; then
    rm -rf -- "$replacement_root"
  fi
}
trap cleanup EXIT

staged_skill="$staging_root/springmaster"
cp -R "$source_skill" "$staged_skill" \
  || die 'failed to copy source skill into staging'
[[ -f "$staged_skill/SKILL.md" && -f "$staged_skill/agents/openai.yaml" ]] \
  || die 'staged skill failed exact-content validation'

if ((target_exists == 1)); then
  # Move the exact old target into a private sibling first. This keeps --force
  # bounded to one validated destination and permits restoration if install
  # fails; no recursive delete ever names a parent or sibling skill.
  replacement_root=$(mktemp -d "$skills_dir/.springmaster-replace.XXXXXX") \
    || die "cannot create replacement staging directory below $skills_dir"
  replacement_target="$replacement_root/springmaster"
  mv -- "$target" "$replacement_target" \
    || die "cannot stage existing destination for replacement: $target"
  if ! mv -- "$staged_skill" "$target"; then
    if mv -- "$replacement_target" "$target"; then
      rm -rf -- "$replacement_root" || true
      replacement_root=''
      die "cannot install skill at $target; original destination restored"
    fi
    preserve_replacement=1
    die "cannot install skill at $target and could not restore original; backup: $replacement_root"
  fi
  rm -rf -- "$replacement_root" \
    || die "installed skill but could not remove private replacement backup: $replacement_root"
  replacement_root=''
else
  mv -- "$staged_skill" "$target" || die "cannot install skill at: $target"
fi

printf 'Installed springmaster skill at %s\n' "$target"

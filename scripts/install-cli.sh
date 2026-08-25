#!/usr/bin/env bash

# Install the paired springmaster binary and analyzer JAR for one local user.
set -Eeuo pipefail
IFS=$'\n\t'
CDPATH=

readonly marker_name='.springmaster-cli-install-v1'
readonly marker_contents='springmaster-cli-install-v1'

usage() {
  cat <<'USAGE'
Usage: scripts/install-cli.sh [--build] [--force]

Install the paired runtime to:
  ${XDG_DATA_HOME:-$HOME/.local/share}/springmaster/{springmaster,analyzer.jar}

Create this PATH entry:
  ${SPRINGMASTER_BIN_DIR:-$HOME/.local/bin}/springmaster

Options:
  --build  build dist/springmaster and dist/analyzer.jar first
  --force  replace an existing installation created by this script
USAGE
}

die() {
  printf 'install-cli: %s\n' "$*" >&2
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
build=0
while (($# > 0)); do
  case "$1" in
    --build)
      build=1
      ;;
    --force)
      force=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
  shift
done

script_dir=$(canonical_dir "$(dirname -- "${BASH_SOURCE[0]}")") \
  || die 'cannot resolve script directory'
checkout_root=$(canonical_dir "$script_dir/..") \
  || die 'cannot resolve checkout root'

if ((build == 1)); then
  "$checkout_root/scripts/build.sh" || die 'build failed'
fi

source_binary="$checkout_root/dist/springmaster"
source_jar="$checkout_root/dist/analyzer.jar"
[[ -f "$source_binary" && ! -L "$source_binary" && -x "$source_binary" ]] \
  || die "executable source binary missing; run with --build: $source_binary"
[[ -f "$source_jar" && ! -L "$source_jar" ]] \
  || die "source analyzer JAR missing; run with --build: $source_jar"

[[ -n "${HOME:-}" && "$HOME" == /* && "$HOME" != / ]] \
  || die 'HOME must be an absolute non-root directory'
data_home_raw=${XDG_DATA_HOME:-"$HOME/.local/share"}
bin_dir_raw=${SPRINGMASTER_BIN_DIR:-"$HOME/.local/bin"}
[[ "$data_home_raw" == /* && "$data_home_raw" != / ]] \
  || die "XDG_DATA_HOME must be an absolute non-root path: $data_home_raw"
[[ "$bin_dir_raw" == /* && "$bin_dir_raw" != / ]] \
  || die "SPRINGMASTER_BIN_DIR must be an absolute non-root path: $bin_dir_raw"

mkdir -p -- "$data_home_raw" "$bin_dir_raw" \
  || die 'cannot create user install directories'
data_home=$(canonical_dir "$data_home_raw") \
  || die "cannot resolve data directory: $data_home_raw"
bin_dir=$(canonical_dir "$bin_dir_raw") \
  || die "cannot resolve binary directory: $bin_dir_raw"
[[ "$data_home" != / && "$bin_dir" != / ]] || die 'refusing filesystem root'

target="$data_home/springmaster"
command_link="$bin_dir/springmaster"
expected_binary="$target/springmaster"
[[ "$(basename -- "$target")" == springmaster && "$target" != "$data_home" ]] \
  || die "refusing non-exact install target: $target"

target_exists=0
if [[ -e "$target" || -L "$target" ]]; then
  target_exists=1
  ((force == 1)) || die "destination exists: $target (use --force to replace it)"
  [[ -d "$target" && ! -L "$target" ]] \
    || die "refusing non-directory or symlink destination: $target"
  [[ -f "$target/$marker_name" && ! -L "$target/$marker_name" ]] \
    || die "refusing unowned destination without marker: $target"
  [[ "$(<"$target/$marker_name")" == "$marker_contents" ]] \
    || die "refusing destination with invalid marker: $target"
fi

if [[ -e "$command_link" || -L "$command_link" ]]; then
  [[ -L "$command_link" ]] \
    || die "refusing to replace non-symlink command: $command_link"
  existing_link=$(readlink -- "$command_link") \
    || die "cannot read existing command symlink: $command_link"
  [[ "$existing_link" == "$expected_binary" ]] \
    || die "refusing unrelated command symlink: $command_link -> $existing_link"
fi

staging_root=$(mktemp -d "$data_home/.springmaster-cli-stage.XXXXXX") \
  || die "cannot create staging directory below $data_home"
backup_root=''
link_temporary=''
preserve_backup=0
cleanup() {
  if [[ -n "${link_temporary:-}" && (-e "$link_temporary" || -L "$link_temporary") ]]; then
    rm -f -- "$link_temporary"
  fi
  if [[ -n "${staging_root:-}" && -d "$staging_root" ]]; then
    rm -rf -- "$staging_root"
  fi
  if [[ "$preserve_backup" -eq 0 && -n "${backup_root:-}" && -d "$backup_root" ]]; then
    rm -rf -- "$backup_root"
  fi
}
trap cleanup EXIT

staged_target="$staging_root/springmaster"
mkdir -- "$staged_target" || die 'cannot create staged package'
cp -- "$source_binary" "$staged_target/springmaster" \
  || die 'cannot copy springmaster binary'
cp -- "$source_jar" "$staged_target/analyzer.jar" \
  || die 'cannot copy analyzer JAR'
chmod 0755 "$staged_target" "$staged_target/springmaster" \
  || die 'cannot set executable package permissions'
chmod 0644 "$staged_target/analyzer.jar" \
  || die 'cannot set analyzer JAR permissions'
printf '%s\n' "$marker_contents" > "$staged_target/$marker_name" \
  || die 'cannot write package ownership marker'
chmod 0644 "$staged_target/$marker_name" \
  || die 'cannot set marker permissions'
"$staged_target/springmaster" --help >/dev/null \
  || die 'staged springmaster smoke test failed'

link_temporary=$(mktemp "$bin_dir/.springmaster-link.XXXXXX") \
  || die "cannot create command staging path below $bin_dir"
rm -f -- "$link_temporary" || die 'cannot prepare command symlink'
ln -s -- "$expected_binary" "$link_temporary" \
  || die 'cannot create staged command symlink'

if ((target_exists == 1)); then
  backup_root=$(mktemp -d "$data_home/.springmaster-cli-backup.XXXXXX") \
    || die "cannot create replacement backup below $data_home"
  mv -- "$target" "$backup_root/springmaster" \
    || die 'cannot stage existing installation for replacement'
fi

if ! mv -- "$staged_target" "$target"; then
  if ((target_exists == 1)) && mv -- "$backup_root/springmaster" "$target"; then
    die 'cannot install package; previous installation restored'
  fi
  preserve_backup=1
  die "cannot install package; recovery backup: $backup_root"
fi

if ! mv -f -- "$link_temporary" "$command_link"; then
  rm -rf -- "$target"
  if ((target_exists == 1)); then
    mv -- "$backup_root/springmaster" "$target" \
      || { preserve_backup=1; die "cannot install command link or restore package; backup: $backup_root"; }
  fi
  die 'cannot install command symlink; package rollback completed'
fi
link_temporary=''

if [[ -n "$backup_root" ]]; then
  rm -rf -- "$backup_root" || die "cannot remove replacement backup: $backup_root"
  backup_root=''
fi

printf 'Installed springmaster package at %s\n' "$target"
printf 'Installed command symlink at %s\n' "$command_link"

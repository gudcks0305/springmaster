#!/bin/sh

# Build both runtime components into one stable, container-friendly directory.
# This script intentionally does not clean caches or source/build trees.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)

DIST_DIR=${DIST_DIR:-"$ROOT_DIR/dist"}
GO=${GO:-go}
GO_PACKAGE=${GO_PACKAGE:-./cmd/springmaster}
CGO_ENABLED=${CGO_ENABLED:-0}
GO_BUILD_FLAGS=${GO_BUILD_FLAGS:--trimpath}
GO_LDFLAGS=${GO_LDFLAGS:--s -w}
GRADLEW=${GRADLEW:-"$ROOT_DIR/gradlew"}

case "$DIST_DIR" in
	/*) ;;
	*) DIST_DIR="$ROOT_DIR/$DIST_DIR" ;;
esac

mkdir -p "$DIST_DIR"

(
	cd "$ROOT_DIR"

	# GO_BUILD_FLAGS intentionally supports a caller-provided list of Go flags.
	# shellcheck disable=SC2086
	CGO_ENABLED="$CGO_ENABLED" "$GO" build $GO_BUILD_FLAGS -buildvcs=false -ldflags "$GO_LDFLAGS" -o "$DIST_DIR/springmaster" "$GO_PACKAGE"
	chmod +x "$DIST_DIR/springmaster"

	command -v npm >/dev/null 2>&1 || {
		echo 'npm is required to build frontend before bootJar' >&2
		exit 1
	}
	npm ci --prefix frontend
	npm run build --prefix frontend

	sh "$GRADLEW" bootJar --no-daemon --console=plain
	cp "$ROOT_DIR/build/libs/spring-boot-analyzer.jar" "$DIST_DIR/analyzer.jar"
)

printf '%s\n' "Built $DIST_DIR/springmaster and $DIST_DIR/analyzer.jar"

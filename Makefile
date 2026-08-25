SHELL := /bin/sh

GO ?= go
GO_PACKAGE ?= ./cmd/springmaster
CGO_ENABLED ?= 0
GO_BUILD_FLAGS ?= -trimpath
GO_BUILD_FLAGS += -buildvcs=false
GO_LDFLAGS ?= -s -w
GRADLEW ?= ./gradlew
GRADLE_FLAGS ?= --no-daemon --console=plain
DIST_DIR ?= dist
SPRINGMASTER_BIN ?= $(DIST_DIR)/springmaster
ANALYZER_JAR ?= $(DIST_DIR)/analyzer.jar
ANALYZER_JAR_SOURCE ?= build/libs/spring-boot-analyzer.jar

.PHONY: all fmt go-fmt gofmt vet go-vet govet test go-test race go-race build go-build \
	gradle-test java-test bootJar gradle-bootJar java-bootJar java-build frontend-build package clean

all: test build

# Go quality gates. Keep aliases for callers that use either Go-prefixed or
# language-neutral target names.
fmt go-fmt gofmt:
	$(GO) fmt ./...

vet go-vet govet:
	$(GO) vet ./...

go-test:
	$(GO) test ./...

go-race race:
	$(GO) test -race ./...

# Build control-plane binary with stable paths and no VCS/build-machine data.
go-build:
	mkdir -p "$(DIST_DIR)"
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" -o "$(SPRINGMASTER_BIN)" "$(GO_PACKAGE)"

gradle-test java-test:
	$(SHELL) "$(GRADLEW)" test $(GRADLE_FLAGS)

# bootJar requires the frontend bundle configured by build.gradle. Build it
# here when npm is available so a clean checkout remains packageable.
frontend-build:
	npm ci --prefix frontend
	npm run build --prefix frontend

gradle-bootJar bootJar java-bootJar java-build: frontend-build
	$(SHELL) "$(GRADLEW)" bootJar $(GRADLE_FLAGS)
	mkdir -p "$(DIST_DIR)"
	cp "$(ANALYZER_JAR_SOURCE)" "$(ANALYZER_JAR)"

test: go-test gradle-test

# Reproducible mixed-language package. Existing Gradle bootJar output is copied
# to the stable dist/analyzer.jar name consumed by the Go worker manager.
build: go-build gradle-bootJar

package: build

# Narrow, opt-in cleanup only. Never remove source trees, caches, or workspace
# data from this target.
clean:
	rm -rf "$(DIST_DIR)"

# Stage 1 — Frontend builder
FROM node:22-alpine AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2 — Go control-plane builder
FROM golang:1.26-alpine AS go-builder

WORKDIR /app

ARG TARGETOS=linux
ARG TARGETARCH=amd64

# Keep module download in its own layer. go.sum is optional for this module,
# but is copied when present so dependency additions remain cache-friendly.
COPY go.mod go.sum* ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/springmaster ./cmd/springmaster

# Stage 3 — Java analyzer builder (Java 25 is required by build.gradle)
FROM eclipse-temurin:25-jdk-alpine AS backend-builder

WORKDIR /app

COPY gradlew settings.gradle build.gradle gradle.properties ./
COPY gradle/ gradle/
RUN chmod +x ./gradlew

COPY src/ src/
COPY --from=frontend-builder /app/frontend/dist src/main/resources/static/

RUN ./gradlew bootJar --no-daemon -x test

# Stage 4 — Runtime. Keep Java 25 because analyzer bytecode/toolchain targets
# Java 25; the Go entrypoint starts the configured Java worker command.
FROM eclipse-temurin:25-jre-alpine

WORKDIR /app

RUN apk add --no-cache git \
    && addgroup -S springmaster \
    && adduser -S springmaster -G springmaster
RUN mkdir -p /workspace && chown springmaster:springmaster /workspace

COPY --from=go-builder --chown=springmaster:springmaster /out/springmaster /usr/local/bin/springmaster
COPY --from=backend-builder --chown=springmaster:springmaster \
    /app/build/libs/spring-boot-analyzer.jar /app/analyzer.jar

USER springmaster

EXPOSE 8085

# CMD is a replaceable default. Callers can provide another master root or
# worker command, e.g. `docker run image scan /repos --worker-command '...'`.
ENTRYPOINT ["springmaster"]
CMD ["scan", "/workspace", "--worker-command", "java -jar /app/analyzer.jar --worker"]

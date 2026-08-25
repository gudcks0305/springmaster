# Worker protocol v1

`springmaster` keeps one or more Java analyzer workers alive and exchanges one JSON object per
line over standard input/output. Worker logs go to standard error. Requests are processed in input
order by each worker process.

## Request

```json
{"schemaVersion":1,"requestId":"repo-1","repositoryPath":"/absolute/snapshot","repositoryId":"repo-1","repositoryUrl":"https://github.com/acme/repo.git","branch":"main","contentHash":"sha256:...","mode":"STATIC_ONLY"}
```

Required fields: `schemaVersion`, `requestId`, `repositoryPath`, `repositoryId`, `contentHash`, and
`mode`. Schema v1 allows no other fields. Each request must be one UTF-8 line no larger than 65,536
bytes. String fields are scalars: `requestId` and `repositoryId` are ASCII opaque identifiers up to
256 characters; `repositoryPath` is up to 4,096 characters; `contentHash` must be
`sha256:` followed by 64 lowercase hexadecimal characters; and `mode` is `STATIC_ONLY` or
`EXTENDED`.

`repositoryPath` must be an absolute, existing directory. It is canonicalized with `toRealPath()`
before analysis, resolving symlinks.

## Repository path policy

By default, worker accepts any absolute existing repository directory for backward compatibility.
When an allowed root is configured, it fails closed: canonical request paths must be at or below the
canonical configured root. A request that escapes through a symlink is rejected.

Configure allowed root with one of these values. Startup option takes precedence; environment is a
fallback only. Both values must name an absolute existing directory.

```text
--allowed-root=/absolute/snapshot-root
SPRINGMASTER_WORKER_ALLOWED_ROOT=/absolute/snapshot-root
```

Optional snapshot marker enforcement uses startup option first, then environment fallback. The bare
startup option means `true`; assigned option and environment values must be exactly `true` or
`false`. Invalid policy configuration terminates worker startup without echoing configured paths.

```text
--require-snapshot-marker
--require-snapshot-marker=true
SPRINGMASTER_WORKER_REQUIRE_SNAPSHOT_MARKER=true
```

Marker enforcement requires an allowed root. With no allowed root, enabling it is invalid startup
configuration. When marker enforcement is enabled, `repositoryPath` must contain one direct child
regular file (not a symlink) named `.snapshot-marker-<token>`, where `<token>` is 64 lowercase
hexadecimal characters. Its exact UTF-8 bytes must be:

```text
springmaster-snapshot-v1
<same-token>

```

The marker is checked after canonical path and allowed-root checks. A missing or malformed marker
returns `SNAPSHOT_MARKER_REQUIRED`; an allowed-root violation returns `REPOSITORY_PATH_DENIED`.

## Response framing

Every normal response, including a request-scoped failure, is first serialized as the existing
`WorkerResponse` JSON object. Its UTF-8 bytes are then framed over one or more JSONL lines. This
removes any whole-response line-size limit while preserving the existing response payload for the
parent to parse after reassembly.

```json
{"schemaVersion":1,"type":"response-start","requestId":"repo-1","responseId":"b84a4f4c-4d75-4788-8985-b66f8aa5a495","encoding":"base64","totalBytes":1234,"totalChunks":1,"sha256":"sha256:<64-lowercase-hex>"}
{"schemaVersion":1,"type":"response-chunk","requestId":"repo-1","responseId":"b84a4f4c-4d75-4788-8985-b66f8aa5a495","sequence":0,"data":"<base64-payload-bytes>"}
{"schemaVersion":1,"type":"response-end","requestId":"repo-1","responseId":"b84a4f4c-4d75-4788-8985-b66f8aa5a495","totalBytes":1234,"totalChunks":1,"sha256":"sha256:<64-lowercase-hex>"}
```

All frames for a response carry the same `requestId` and random `responseId`. `sequence` is
zero-based and contiguous. The parent must accept a response only when it receives exactly
`totalChunks`, decodes exactly `totalBytes`, and verifies that the `response-end` totals and hash
match `response-start`; then it must verify `sha256` against the assembled bytes before parsing
the enclosed `WorkerResponse`.

Each output frame is at most 65,536 UTF-8 bytes. A chunk carries at most 46,080 raw payload bytes
before Base64 encoding. Worker permits at most 67,108,864 response payload bytes by default.
`SPRINGMASTER_WORKER_MAX_RESPONSE_BYTES` can set a strict decimal byte limit from `1` through
`268435456`; invalid values terminate worker startup without echoing configuration. Use the same
limit in the parent reassembler.

If serializing a response exceeds that limit or fails before `response-start` is emitted, worker
emits one compact legacy `WorkerResponse` failure line instead:

```json
{"schemaVersion":1,"requestId":"repo-1","status":"failed","error":{"code":"RESPONSE_TOO_LARGE","message":"Response exceeds the maximum permitted size."}}
```

Unknown schema versions and malformed requests become a framed `WorkerResponse` failure and do not
terminate worker. Secrets and source contents must never appear in error messages. Lines above the
input size limit return recoverable `REQUEST_TOO_LARGE`; worker discards that line and continues
with next line.

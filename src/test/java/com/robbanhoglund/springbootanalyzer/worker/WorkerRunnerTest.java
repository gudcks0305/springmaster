package com.robbanhoglund.springbootanalyzer.worker;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildTool;
import com.robbanhoglund.springbootanalyzer.api.dto.AnalysisMode;
import com.robbanhoglund.springbootanalyzer.api.dto.AnalyzeRepositoryResponse;
import com.robbanhoglund.springbootanalyzer.application.LocalRepositoryAnalysisService;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.DefaultApplicationArguments;

class WorkerRunnerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir Path tempDir;

    @Test
    void processesRequestsInOrderAndContinuesAfterInvalidRequest() throws Exception {
        LocalRepositoryAnalysisService analysisService = mock(LocalRepositoryAnalysisService.class);
        given(analysisService.analyze(any(), any(), any(), any(), any())).willReturn(response());
        WorkerRunner runner = new WorkerRunner(analysisService, MAPPER);
        String input =
                """
                {"schemaVersion":1,"requestId":"first","repositoryPath":"%s","repositoryId":"repo-1","contentHash":"%s","mode":"STATIC_ONLY"}
                {"schemaVersion":2,"requestId":"bad","repositoryPath":"%s","repositoryId":"repo-1","contentHash":"%s","mode":"STATIC_ONLY"}
                {"schemaVersion":1,"requestId":"last","repositoryPath":"%s","repositoryId":"repo-1","contentHash":"%s","mode":"EXTENDED"}
                """
                        .formatted(tempDir, hash('1'), tempDir, hash('2'), tempDir, hash('3'));
        StringWriter output = new StringWriter();

        runner.process(input(input), output);

        List<JsonNode> responses = responses(output);
        assertThat(responses).hasSize(3);
        assertThat(responses.get(0).path("status").asText()).isEqualTo("completed");
        assertThat(responses.get(0).path("requestId").asText()).isEqualTo("first");
        assertThat(responses.get(1).path("status").asText()).isEqualTo("failed");
        assertThat(responses.get(1).path("error").path("code").asText())
                .isEqualTo("UNSUPPORTED_SCHEMA_VERSION");
        assertThat(responses.get(2).path("status").asText()).isEqualTo("completed");
        assertThat(responses.get(2).path("requestId").asText()).isEqualTo("last");
        verify(analysisService, times(2))
                .analyze(any(), eq("repo-1"), any(), any(), any(AnalysisMode.class));
        verify(analysisService)
                .analyze(
                        eq(tempDir.toRealPath()),
                        eq("repo-1"),
                        eq(null),
                        eq(null),
                        eq(AnalysisMode.EXTENDED));
    }

    @Test
    void rejectsBadPathWithoutLeakingRequestContentAndKeepsWorkerAlive() throws Exception {
        LocalRepositoryAnalysisService analysisService = mock(LocalRepositoryAnalysisService.class);
        given(analysisService.analyze(any(), any(), any(), any(), any())).willReturn(response());
        WorkerRunner runner = new WorkerRunner(analysisService, MAPPER);
        String input =
                """
                {"schemaVersion":1,"requestId":"bad","repositoryPath":"not-absolute-super-secret","repositoryId":"repo-1","contentHash":"%s","mode":"STATIC_ONLY"}
                {"schemaVersion":1,"requestId":"good","repositoryPath":"%s","repositoryId":"repo-1","contentHash":"%s","mode":"STATIC_ONLY"}
                """
                        .formatted(hash('4'), tempDir, hash('5'));
        StringWriter output = new StringWriter();

        runner.process(input(input), output);

        List<JsonNode> responses = responses(output);
        assertThat(responses).hasSize(2);
        assertThat(responses.get(0).path("error").path("code").asText())
                .isEqualTo("INVALID_REQUEST");
        assertThat(responses.get(0).path("error").path("message").asText())
                .doesNotContain("super-secret");
        assertThat(output.toString()).doesNotContain("super-secret");
        assertThat(responses.get(1).path("status").asText()).isEqualTo("completed");
    }

    @Test
    void rejectsMissingModeUnderSchemaVersionOne() throws Exception {
        WorkerRunner runner = new WorkerRunner(mock(LocalRepositoryAnalysisService.class), MAPPER);
        String input =
                """
                {"schemaVersion":1,"requestId":"missing-mode","repositoryPath":"%s","repositoryId":"repo-1","contentHash":"%s"}
                """
                        .formatted(tempDir, hash('6'));
        StringWriter output = new StringWriter();

        runner.process(input(input), output);

        JsonNode response = onlyResponse(output);
        assertThat(response.path("status").asText()).isEqualTo("failed");
        assertThat(response.path("error").path("code").asText()).isEqualTo("INVALID_REQUEST");
        assertThat(response.path("error").path("message").asText())
                .isEqualTo("mode must be a non-blank string.");
    }

    @Test
    void rejectsOversizedLineThenProcessesFollowingValidRequest() throws Exception {
        LocalRepositoryAnalysisService analysisService = mock(LocalRepositoryAnalysisService.class);
        given(analysisService.analyze(any(), any(), any(), any(), any())).willReturn(response());
        WorkerRunner runner = new WorkerRunner(analysisService, MAPPER);
        String valid = request("valid", tempDir, "repo-1", hash('7'), "STATIC_ONLY");
        String oversized = "x".repeat(BoundedJsonlReader.MAX_LINE_BYTES + 1);
        StringWriter output = new StringWriter();

        runner.process(input(oversized + "\n" + valid + "\n"), output);

        List<JsonNode> responses = responses(output);
        assertThat(responses).hasSize(2);
        assertThat(responses.get(0).path("error").path("code").asText())
                .isEqualTo("REQUEST_TOO_LARGE");
        assertThat(responses.get(1).path("status").asText()).isEqualTo("completed");
        verify(analysisService).analyze(any(), eq("repo-1"), any(), any(), any());
    }

    @Test
    void rejectsOversizedOrComplexFieldsThenProcessesFollowingValidRequest() throws Exception {
        LocalRepositoryAnalysisService analysisService = mock(LocalRepositoryAnalysisService.class);
        given(analysisService.analyze(any(), any(), any(), any(), any())).willReturn(response());
        WorkerRunner runner = new WorkerRunner(analysisService, MAPPER);
        String longRequestId = "x".repeat(WorkerRequest.MAX_REQUEST_ID_LENGTH + 1);
        String longPath = "/" + "x".repeat(WorkerRequest.MAX_REPOSITORY_PATH_LENGTH);
        String input =
                String.join(
                                "\n",
                                request(longRequestId, tempDir, "repo-1", hash('8'), "STATIC_ONLY"),
                                request("bad-repo", tempDir, "[]", hash('9'), "STATIC_ONLY")
                                        .replace("\"repositoryId\":\"[]\"", "\"repositoryId\":[]"),
                                request(
                                        "bad-hash",
                                        tempDir,
                                        "repo-1",
                                        "sha256:" + "a".repeat(65),
                                        "STATIC_ONLY"),
                                request("bad-mode", tempDir, "repo-1", hash('a'), "X".repeat(17)),
                                request(
                                        "bad-path",
                                        Path.of(longPath),
                                        "repo-1",
                                        hash('b'),
                                        "STATIC_ONLY"),
                                request("valid", tempDir, "repo-1", hash('c'), "STATIC_ONLY"))
                        + "\n";
        StringWriter output = new StringWriter();

        runner.process(input(input), output);

        List<JsonNode> responses = responses(output);
        assertThat(responses).hasSize(6);
        assertThat(responses.subList(0, 5))
                .allSatisfy(
                        response ->
                                assertThat(response.path("error").path("code").asText())
                                        .isEqualTo("INVALID_REQUEST"));
        assertThat(responses.getLast().path("status").asText()).isEqualTo("completed");
        verify(analysisService).analyze(any(), eq("repo-1"), any(), any(), any());
    }

    @Test
    void deniesSymlinkEscapeFromConfiguredAllowedRoot() throws Exception {
        Path allowedRoot = Files.createDirectory(tempDir.resolve("allowed"));
        Path outside = Files.createDirectory(tempDir.resolve("outside"));
        Files.createSymbolicLink(allowedRoot.resolve("escape"), outside);
        WorkerPathPolicy policy =
                WorkerPathPolicy.from(
                        new DefaultApplicationArguments("--allowed-root=" + allowedRoot), Map.of());
        LocalRepositoryAnalysisService analysisService = mock(LocalRepositoryAnalysisService.class);
        WorkerRunner runner = new WorkerRunner(analysisService, MAPPER);
        StringWriter output = new StringWriter();

        runner.process(
                input(
                        request(
                                "escape",
                                allowedRoot.resolve("escape"),
                                "repo-1",
                                hash('d'),
                                "STATIC_ONLY")),
                output,
                policy);

        assertThat(onlyResponse(output).path("error").path("code").asText())
                .isEqualTo("REPOSITORY_PATH_DENIED");
        verifyNoInteractions(analysisService);
    }

    @Test
    void acceptsRepositoryWithinConfiguredAllowedRootFromEnvironment() throws Exception {
        Path allowedRoot = Files.createDirectory(tempDir.resolve("allowed"));
        Path repository = Files.createDirectory(allowedRoot.resolve("repository"));
        WorkerPathPolicy policy =
                WorkerPathPolicy.from(
                        new DefaultApplicationArguments(),
                        Map.of(WorkerPathPolicy.ALLOWED_ROOT_ENV, allowedRoot.toString()));
        LocalRepositoryAnalysisService analysisService = mock(LocalRepositoryAnalysisService.class);
        given(analysisService.analyze(any(), any(), any(), any(), any())).willReturn(response());
        WorkerRunner runner = new WorkerRunner(analysisService, MAPPER);
        StringWriter output = new StringWriter();

        runner.process(
                input(request("good", repository, "repo-1", hash('e'), "STATIC_ONLY")),
                output,
                policy);

        assertThat(onlyResponse(output).path("status").asText()).isEqualTo("completed");
        verify(analysisService)
                .analyze(
                        eq(repository.toRealPath()),
                        eq("repo-1"),
                        eq(null),
                        eq(null),
                        eq(AnalysisMode.STATIC_ONLY));
    }

    @Test
    void requiresExpectedSnapshotMarkerWhenConfigured() throws Exception {
        Path repository = Files.createDirectory(tempDir.resolve("repository"));
        WorkerPathPolicy policy =
                WorkerPathPolicy.from(
                        new DefaultApplicationArguments(
                                "--allowed-root=" + tempDir, "--require-snapshot-marker"),
                        Map.of());
        LocalRepositoryAnalysisService analysisService = mock(LocalRepositoryAnalysisService.class);
        given(analysisService.analyze(any(), any(), any(), any(), any())).willReturn(response());
        WorkerRunner runner = new WorkerRunner(analysisService, MAPPER);
        String request = request("snapshot", repository, "repo-1", hash('f'), "STATIC_ONLY");
        StringWriter output = new StringWriter();

        runner.process(input(request), output, policy);
        writeMarker(repository, 'a');
        runner.process(input(request), output, policy);

        List<JsonNode> responses = responses(output);
        assertThat(responses.get(0).path("error").path("code").asText())
                .isEqualTo("SNAPSHOT_MARKER_REQUIRED");
        assertThat(responses.get(1).path("status").asText()).isEqualTo("completed");
        verify(analysisService).analyze(any(), any(), any(), any(), any());
    }

    @Test
    void rejectsInvalidPathPolicyConfiguration() {
        assertThatThrownBy(
                        () ->
                                WorkerPathPolicy.from(
                                        new DefaultApplicationArguments("--allowed-root=relative"),
                                        Map.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Worker path policy configuration is invalid.");
        assertThatThrownBy(
                        () ->
                                WorkerPathPolicy.from(
                                        new DefaultApplicationArguments(),
                                        Map.of(
                                                WorkerPathPolicy.REQUIRE_SNAPSHOT_MARKER_ENV,
                                                "yes")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Worker path policy configuration is invalid.");
        assertThatThrownBy(
                        () ->
                                WorkerPathPolicy.from(
                                        new DefaultApplicationArguments(),
                                        Map.of(
                                                WorkerPathPolicy.REQUIRE_SNAPSHOT_MARKER_ENV,
                                                "true")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Worker path policy configuration is invalid.");
    }

    @Test
    void framesResponsesLargerThanSixteenMiB() throws Exception {
        LocalRepositoryAnalysisService analysisService = mock(LocalRepositoryAnalysisService.class);
        String largeRepositoryUrl = "x".repeat(17 * 1024 * 1024);
        given(analysisService.analyze(any(), any(), any(), any(), any()))
                .willReturn(response(largeRepositoryUrl));
        WorkerRunner runner = new WorkerRunner(analysisService, MAPPER);
        StringWriter output = new StringWriter();

        runner.process(
                input(request("large", tempDir, "repo-1", hash('f'), "STATIC_ONLY")), output);

        List<String> frames = output.toString().lines().toList();
        assertThat(frames).hasSizeGreaterThan(3);
        assertThat(frames)
                .allSatisfy(
                        frame ->
                                assertThat(frame.getBytes(StandardCharsets.UTF_8).length)
                                        .isLessThanOrEqualTo(WorkerResponseFramer.MAX_FRAME_BYTES));
        JsonNode start = read(frames.getFirst());
        assertThat(start.path("type").asText()).isEqualTo("response-start");
        assertThat(start.path("totalBytes").asLong()).isGreaterThan(16L * 1024 * 1024);
        assertThat(start.path("totalChunks").asInt()).isGreaterThan(1);

        JsonNode response = onlyResponse(output);
        assertThat(response.path("status").asText()).isEqualTo("completed");
        assertThat(response.path("result").path("repositoryUrl").asText())
                .hasSize(largeRepositoryUrl.length());
    }

    @Test
    void returnsCompactLegacyFailureForResponseOverflowThenContinues() throws Exception {
        LocalRepositoryAnalysisService analysisService = mock(LocalRepositoryAnalysisService.class);
        given(analysisService.analyze(any(), any(), any(), any(), any()))
                .willReturn(response("x".repeat(2048)), response());
        WorkerRunner runner = new WorkerRunner(analysisService, MAPPER);
        StringWriter output = new StringWriter();
        String input =
                request("overflow", tempDir, "repo-1", hash('1'), "STATIC_ONLY")
                        + request("next", tempDir, "repo-1", hash('2'), "STATIC_ONLY");

        runner.process(
                input(input),
                output,
                WorkerPathPolicy.unrestricted(),
                WorkerResponseFramingPolicy.forTests(1024));

        List<JsonNode> responses = responses(output);
        assertThat(responses).hasSize(2);
        assertThat(responses.getFirst().path("status").asText()).isEqualTo("failed");
        assertThat(responses.getFirst().path("error").path("code").asText())
                .isEqualTo("RESPONSE_TOO_LARGE");
        assertThat(responses.getLast().path("status").asText()).isEqualTo("completed");
        verify(analysisService, times(2)).analyze(any(), any(), any(), any(), any());
    }

    @Test
    void rejectsInvalidResponseFramingConfiguration() {
        assertThatThrownBy(
                        () ->
                                WorkerResponseFramingPolicy.from(
                                        Map.of(
                                                WorkerResponseFramingPolicy.MAX_RESPONSE_BYTES_ENV,
                                                "0")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Worker response framing configuration is invalid.");
        assertThatThrownBy(
                        () ->
                                WorkerResponseFramingPolicy.from(
                                        Map.of(
                                                WorkerResponseFramingPolicy.MAX_RESPONSE_BYTES_ENV,
                                                "268435457")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Worker response framing configuration is invalid.");
    }

    private static JsonNode read(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception exception) {
            throw new AssertionError(exception);
        }
    }

    private static ByteArrayInputStream input(String value) {
        return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
    }

    private static List<JsonNode> responses(StringWriter output) {
        List<JsonNode> responses = new ArrayList<>();
        FrameAccumulator accumulator = null;
        for (String line : output.toString().lines().toList()) {
            assertThat(line.getBytes(StandardCharsets.UTF_8).length)
                    .isLessThanOrEqualTo(WorkerResponseFramer.MAX_FRAME_BYTES);
            JsonNode frame = read(line);
            if (!frame.has("type")) {
                assertThat(accumulator).isNull();
                responses.add(frame);
                continue;
            }
            String type = frame.path("type").asText();
            if ("response-start".equals(type)) {
                assertThat(accumulator).isNull();
                accumulator = FrameAccumulator.start(frame);
            } else if ("response-chunk".equals(type)) {
                assertThat(accumulator).isNotNull();
                accumulator.append(frame);
            } else if ("response-end".equals(type)) {
                assertThat(accumulator).isNotNull();
                responses.add(accumulator.finish(frame));
                accumulator = null;
            } else {
                throw new AssertionError("Unexpected worker response frame type: " + type);
            }
        }
        assertThat(accumulator).isNull();
        return responses;
    }

    private static JsonNode onlyResponse(StringWriter output) {
        List<JsonNode> responses = responses(output);
        assertThat(responses).hasSize(1);
        return responses.getFirst();
    }

    private static final class FrameAccumulator {

        private final String requestId;
        private final String responseId;
        private final long totalBytes;
        private final int totalChunks;
        private final String sha256;
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private int nextSequence;

        private FrameAccumulator(
                String requestId,
                String responseId,
                long totalBytes,
                int totalChunks,
                String sha256) {
            this.requestId = requestId;
            this.responseId = responseId;
            this.totalBytes = totalBytes;
            this.totalChunks = totalChunks;
            this.sha256 = sha256;
        }

        static FrameAccumulator start(JsonNode frame) {
            assertThat(frame.path("encoding").asText()).isEqualTo("base64");
            assertThat(frame.path("responseId").asText()).isNotBlank();
            assertThat(frame.path("totalBytes").asLong()).isPositive();
            assertThat(frame.path("totalChunks").asInt()).isPositive();
            assertThat(frame.path("sha256").asText()).matches("sha256:[0-9a-f]{64}");
            return new FrameAccumulator(
                    nullableText(frame, "requestId"),
                    frame.path("responseId").asText(),
                    frame.path("totalBytes").asLong(),
                    frame.path("totalChunks").asInt(),
                    frame.path("sha256").asText());
        }

        void append(JsonNode frame) {
            assertThat(nullableText(frame, "requestId")).isEqualTo(requestId);
            assertThat(frame.path("responseId").asText()).isEqualTo(responseId);
            assertThat(frame.path("sequence").asInt()).isEqualTo(nextSequence++);
            bytes.writeBytes(Base64.getDecoder().decode(frame.path("data").asText()));
            assertThat((long) bytes.size()).isLessThanOrEqualTo(totalBytes);
        }

        JsonNode finish(JsonNode frame) {
            assertThat(nullableText(frame, "requestId")).isEqualTo(requestId);
            assertThat(frame.path("responseId").asText()).isEqualTo(responseId);
            assertThat(frame.path("totalBytes").asLong()).isEqualTo(totalBytes);
            assertThat(frame.path("totalChunks").asInt()).isEqualTo(totalChunks);
            assertThat(frame.path("sha256").asText()).isEqualTo(sha256);
            assertThat(nextSequence).isEqualTo(totalChunks);
            assertThat(bytes.size()).isEqualTo(totalBytes);
            assertThat(sha256(bytes.toByteArray())).isEqualTo(sha256);
            return read(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
        }
    }

    private static String request(
            String requestId,
            Path repositoryPath,
            String repositoryId,
            String contentHash,
            String mode) {
        return """
        {"schemaVersion":1,"requestId":"%s","repositoryPath":"%s","repositoryId":"%s","contentHash":"%s","mode":"%s"}
        """
                .formatted(requestId, repositoryPath, repositoryId, contentHash, mode);
    }

    private static String hash(char value) {
        return "sha256:" + String.valueOf(value).repeat(64);
    }

    private static String nullableText(JsonNode node, String fieldName) {
        JsonNode value = node.get(fieldName);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static String sha256(byte[] payload) {
        try {
            return "sha256:"
                    + HexFormat.of()
                            .formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        } catch (NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }

    private static void writeMarker(Path repository, char tokenCharacter) throws Exception {
        String token = String.valueOf(tokenCharacter).repeat(64);
        Files.writeString(
                repository.resolve(".snapshot-marker-" + token),
                "springmaster-snapshot-v1\n" + token + "\n",
                StandardCharsets.UTF_8);
    }

    private static AnalyzeRepositoryResponse response() {
        return response(null);
    }

    private static AnalyzeRepositoryResponse response(String repositoryUrl) {
        return new AnalyzeRepositoryResponse(
                repositoryUrl,
                null,
                "repo-1",
                "analysis-1",
                null,
                BuildTool.GRADLE,
                "25",
                true,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                null,
                null,
                null,
                null,
                null,
                null);
    }
}

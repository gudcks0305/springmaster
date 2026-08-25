package com.robbanhoglund.springbootanalyzer.worker;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.robbanhoglund.springbootanalyzer.api.dto.AnalyzeRepositoryResponse;
import com.robbanhoglund.springbootanalyzer.application.LocalRepositoryAnalysisService;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Long-lived JSONL stdin/stdout worker for local repository analysis.
 *
 * <p>Each input line produces one response, framed over one or more bounded output lines. Request
 * errors are isolated so a caller can reuse the same process after malformed or failed analysis
 * requests.
 */
@Component
@Profile("worker")
public class WorkerRunner implements ApplicationRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkerRunner.class);
    private static final StreamReadConstraints REQUEST_CONSTRAINTS =
            StreamReadConstraints.builder()
                    .maxDocumentLength(BoundedJsonlReader.MAX_LINE_BYTES)
                    .maxTokenCount(32)
                    .maxNestingDepth(4)
                    .maxNumberLength(32)
                    .maxStringLength(WorkerRequest.MAX_REPOSITORY_PATH_LENGTH)
                    .maxNameLength(64)
                    .build();

    private final LocalRepositoryAnalysisService localRepositoryAnalysisService;
    private final ObjectMapper objectMapper;

    public WorkerRunner(
            LocalRepositoryAnalysisService localRepositoryAnalysisService,
            ObjectMapper objectMapper) {
        this.localRepositoryAnalysisService = localRepositoryAnalysisService;
        this.objectMapper = objectMapper.copy();
        this.objectMapper.getFactory().setStreamReadConstraints(REQUEST_CONSTRAINTS);
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        WorkerPathPolicy pathPolicy = WorkerPathPolicy.from(args, System.getenv());
        WorkerResponseFramingPolicy framingPolicy =
                WorkerResponseFramingPolicy.from(System.getenv());
        process(
                System.in,
                new OutputStreamWriter(System.out, StandardCharsets.UTF_8),
                pathPolicy,
                framingPolicy);
    }

    void process(InputStream input, Writer output) throws IOException {
        process(
                input,
                output,
                WorkerPathPolicy.unrestricted(),
                WorkerResponseFramingPolicy.defaults());
    }

    void process(InputStream input, Writer output, WorkerPathPolicy pathPolicy) throws IOException {
        process(input, output, pathPolicy, WorkerResponseFramingPolicy.defaults());
    }

    void process(
            InputStream input,
            Writer output,
            WorkerPathPolicy pathPolicy,
            WorkerResponseFramingPolicy framingPolicy)
            throws IOException {
        WorkerResponseFramer responseFramer = new WorkerResponseFramer(objectMapper, framingPolicy);
        BoundedJsonlReader reader = new BoundedJsonlReader(input);
        BoundedJsonlReader.Line inputLine;
        while ((inputLine = reader.readLine()) != null) {
            if (inputLine.oversized()) {
                responseFramer.write(
                        output,
                        WorkerResponse.failed(
                                null,
                                "REQUEST_TOO_LARGE",
                                "Request line exceeds the maximum permitted size."));
                continue;
            }
            String line = inputLine.value();
            if (line.isBlank()) {
                continue;
            }
            responseFramer.write(output, handle(line, pathPolicy));
        }
    }

    private WorkerResponse handle(String line, WorkerPathPolicy pathPolicy) {
        String requestId = null;
        try {
            JsonNode document = objectMapper.readTree(line);
            requestId = WorkerRequest.requestIdFrom(document);
            WorkerRequest request = WorkerRequest.from(document, pathPolicy);
            AnalyzeRepositoryResponse result =
                    localRepositoryAnalysisService.analyze(
                            request.repositoryPath(),
                            request.repositoryId(),
                            request.repositoryUrl(),
                            request.branch(),
                            request.mode());
            return WorkerResponse.completed(request.requestId(), result);
        } catch (WorkerProtocolException exception) {
            return WorkerResponse.failed(requestId, exception.code(), exception.getMessage());
        } catch (JsonProcessingException exception) {
            return WorkerResponse.failed(
                    requestId, "INVALID_REQUEST", "Request is not valid JSON.");
        } catch (Exception exception) {
            LOGGER.warn(
                    "Local worker request failed (exceptionType={})",
                    exception.getClass().getSimpleName());
            return WorkerResponse.failed(
                    requestId, "ANALYSIS_FAILED", "Analysis could not be completed.");
        }
    }
}

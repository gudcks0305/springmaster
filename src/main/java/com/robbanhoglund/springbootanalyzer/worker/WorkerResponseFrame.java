package com.robbanhoglund.springbootanalyzer.worker;

import com.fasterxml.jackson.annotation.JsonInclude;

/** One bounded JSONL envelope containing part of a serialized {@link WorkerResponse}. */
@JsonInclude(JsonInclude.Include.NON_NULL)
record WorkerResponseFrame(
        int schemaVersion,
        String type,
        String requestId,
        String responseId,
        String encoding,
        Long totalBytes,
        Integer totalChunks,
        String sha256,
        Integer sequence,
        String data) {

    static WorkerResponseFrame start(
            String requestId, String responseId, long totalBytes, int totalChunks, String sha256) {
        return new WorkerResponseFrame(
                WorkerRequest.SCHEMA_VERSION,
                "response-start",
                requestId,
                responseId,
                "base64",
                totalBytes,
                totalChunks,
                sha256,
                null,
                null);
    }

    static WorkerResponseFrame chunk(
            String requestId, String responseId, int sequence, String data) {
        return new WorkerResponseFrame(
                WorkerRequest.SCHEMA_VERSION,
                "response-chunk",
                requestId,
                responseId,
                null,
                null,
                null,
                null,
                sequence,
                data);
    }

    static WorkerResponseFrame end(
            String requestId, String responseId, long totalBytes, int totalChunks, String sha256) {
        return new WorkerResponseFrame(
                WorkerRequest.SCHEMA_VERSION,
                "response-end",
                requestId,
                responseId,
                null,
                totalBytes,
                totalChunks,
                sha256,
                null,
                null);
    }
}

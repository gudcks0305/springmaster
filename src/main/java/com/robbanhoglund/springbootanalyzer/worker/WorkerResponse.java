package com.robbanhoglund.springbootanalyzer.worker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.robbanhoglund.springbootanalyzer.api.dto.AnalyzeRepositoryResponse;

/** Existing analyzer response payload transported inside bounded worker-response frames. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record WorkerResponse(
        int schemaVersion,
        String requestId,
        String status,
        AnalyzeRepositoryResponse result,
        WorkerError error) {

    static WorkerResponse completed(String requestId, AnalyzeRepositoryResponse result) {
        return new WorkerResponse(
                WorkerRequest.SCHEMA_VERSION, requestId, "completed", result, null);
    }

    static WorkerResponse failed(String requestId, String code, String message) {
        return new WorkerResponse(
                WorkerRequest.SCHEMA_VERSION,
                requestId,
                "failed",
                null,
                new WorkerError(code, message));
    }
}

package com.robbanhoglund.springbootanalyzer.worker;

import java.util.Map;

/** Startup configuration for the bounded worker-response framing protocol. */
final class WorkerResponseFramingPolicy {

    static final String MAX_RESPONSE_BYTES_ENV = "SPRINGMASTER_WORKER_MAX_RESPONSE_BYTES";
    static final int DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
    static final int MAX_CONFIGURED_RESPONSE_BYTES = 256 * 1024 * 1024;

    private final int maximumResponseBytes;

    private WorkerResponseFramingPolicy(int maximumResponseBytes) {
        this.maximumResponseBytes = maximumResponseBytes;
    }

    static WorkerResponseFramingPolicy defaults() {
        return new WorkerResponseFramingPolicy(DEFAULT_MAX_RESPONSE_BYTES);
    }

    static WorkerResponseFramingPolicy from(Map<String, String> environment) {
        String value = environment.get(MAX_RESPONSE_BYTES_ENV);
        if (value == null) {
            return defaults();
        }
        if (!value.matches("[1-9][0-9]*")) {
            throw invalidConfiguration();
        }
        try {
            long parsed = Long.parseLong(value);
            if (parsed > MAX_CONFIGURED_RESPONSE_BYTES) {
                throw invalidConfiguration();
            }
            return new WorkerResponseFramingPolicy((int) parsed);
        } catch (NumberFormatException exception) {
            throw invalidConfiguration();
        }
    }

    static WorkerResponseFramingPolicy forTests(int maximumResponseBytes) {
        if (maximumResponseBytes < 1 || maximumResponseBytes > MAX_CONFIGURED_RESPONSE_BYTES) {
            throw new IllegalArgumentException(
                    "maximumResponseBytes must be within worker limits.");
        }
        return new WorkerResponseFramingPolicy(maximumResponseBytes);
    }

    int maximumResponseBytes() {
        return maximumResponseBytes;
    }

    private static IllegalArgumentException invalidConfiguration() {
        return new IllegalArgumentException("Worker response framing configuration is invalid.");
    }
}

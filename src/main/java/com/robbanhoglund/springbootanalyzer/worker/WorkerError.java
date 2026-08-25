package com.robbanhoglund.springbootanalyzer.worker;

/** Error body returned for one failed worker request. */
public record WorkerError(String code, String message) {}

package com.robbanhoglund.springbootanalyzer.worker;

/** A request-level protocol validation failure that is safe to return to a worker client. */
final class WorkerProtocolException extends Exception {

    private final String code;

    WorkerProtocolException(String code, String message) {
        super(message);
        this.code = code;
    }

    String code() {
        return code;
    }
}

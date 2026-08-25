package com.robbanhoglund.springbootanalyzer.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

/** Writes each response as bounded JSONL frames whose payload is an existing WorkerResponse JSON. */
final class WorkerResponseFramer {

    static final int MAX_FRAME_BYTES = 64 * 1024;
    private static final int MAX_RAW_CHUNK_BYTES = 45 * 1024;

    private final ObjectMapper objectMapper;
    private final int maximumResponseBytes;

    WorkerResponseFramer(ObjectMapper objectMapper, WorkerResponseFramingPolicy policy) {
        this.objectMapper = objectMapper;
        this.maximumResponseBytes = policy.maximumResponseBytes();
    }

    void write(Writer output, WorkerResponse response) throws IOException {
        byte[] payload;
        String sha256;
        try {
            payload = serialize(response);
            sha256 = sha256(payload);
        } catch (ResponseLimitExceededException exception) {
            writeLegacyFailure(
                    output,
                    response.requestId(),
                    "RESPONSE_TOO_LARGE",
                    "Response exceeds the maximum permitted size.");
            return;
        } catch (IOException exception) {
            writeLegacyFailure(
                    output,
                    response.requestId(),
                    "RESPONSE_SERIALIZATION_FAILED",
                    "Analysis response could not be encoded.");
            return;
        }

        String responseId = UUID.randomUUID().toString();
        int totalChunks = (payload.length + MAX_RAW_CHUNK_BYTES - 1) / MAX_RAW_CHUNK_BYTES;
        writeFrame(
                output,
                WorkerResponseFrame.start(
                        response.requestId(), responseId, payload.length, totalChunks, sha256));
        for (int sequence = 0; sequence < totalChunks; sequence++) {
            int offset = sequence * MAX_RAW_CHUNK_BYTES;
            int length = Math.min(MAX_RAW_CHUNK_BYTES, payload.length - offset);
            String data =
                    Base64.getEncoder()
                            .encodeToString(Arrays.copyOfRange(payload, offset, offset + length));
            writeFrame(
                    output,
                    WorkerResponseFrame.chunk(response.requestId(), responseId, sequence, data));
        }
        writeFrame(
                output,
                WorkerResponseFrame.end(
                        response.requestId(), responseId, payload.length, totalChunks, sha256));
    }

    private byte[] serialize(WorkerResponse response) throws IOException {
        BoundedResponseBuffer output = new BoundedResponseBuffer(maximumResponseBytes);
        try {
            objectMapper.writeValue(output, response);
            return output.toByteArray();
        } catch (IOException exception) {
            if (hasCause(exception, ResponseLimitExceededException.class)) {
                throw new ResponseLimitExceededException();
            }
            throw exception;
        }
    }

    private void writeFrame(Writer output, WorkerResponseFrame frame) throws IOException {
        String json = objectMapper.writeValueAsString(frame);
        if (json.getBytes(StandardCharsets.UTF_8).length > MAX_FRAME_BYTES) {
            throw new IOException("Worker response frame exceeds the configured protocol limit.");
        }
        output.write(json);
        output.write(System.lineSeparator());
        output.flush();
    }

    private void writeLegacyFailure(Writer output, String requestId, String code, String message)
            throws IOException {
        output.write(
                objectMapper.writeValueAsString(WorkerResponse.failed(requestId, code, message)));
        output.write(System.lineSeparator());
        output.flush();
    }

    private static String sha256(byte[] payload) throws IOException {
        try {
            return "sha256:"
                    + HexFormat.of()
                            .formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        } catch (NoSuchAlgorithmException exception) {
            throw new IOException("SHA-256 is unavailable.", exception);
        }
    }

    private static boolean hasCause(Throwable exception, Class<? extends Throwable> type) {
        Throwable current = exception;
        while (current != null) {
            if (type.isInstance(current)) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private static final class BoundedResponseBuffer extends OutputStream {

        private final ByteArrayOutputStream delegate = new ByteArrayOutputStream();
        private final int maximumBytes;

        private BoundedResponseBuffer(int maximumBytes) {
            this.maximumBytes = maximumBytes;
        }

        @Override
        public void write(int value) throws IOException {
            requireCapacity(1);
            delegate.write(value);
        }

        @Override
        public void write(byte[] bytes, int offset, int length) throws IOException {
            requireCapacity(length);
            delegate.write(bytes, offset, length);
        }

        @Override
        public void close() {
            // ObjectMapper closes its target after serialization; response bytes remain available.
        }

        byte[] toByteArray() {
            return delegate.toByteArray();
        }

        private void requireCapacity(int requestedBytes) throws ResponseLimitExceededException {
            if (requestedBytes > maximumBytes - delegate.size()) {
                throw new ResponseLimitExceededException();
            }
        }
    }

    private static final class ResponseLimitExceededException extends IOException {}
}

package com.robbanhoglund.springbootanalyzer.worker;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Reads UTF-8 JSONL records without allocating an unbounded line buffer. */
final class BoundedJsonlReader {

    static final int MAX_LINE_BYTES = 64 * 1024;

    private final InputStream input;

    BoundedJsonlReader(InputStream input) {
        this.input = input instanceof BufferedInputStream ? input : new BufferedInputStream(input);
    }

    Line readLine() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.min(MAX_LINE_BYTES, 1024));
        boolean oversized = false;
        boolean sawInput = false;
        int nextByte;
        while ((nextByte = input.read()) != -1) {
            sawInput = true;
            if (nextByte == '\n') {
                return line(bytes, oversized);
            }
            if (!oversized) {
                if (bytes.size() == MAX_LINE_BYTES) {
                    oversized = true;
                } else {
                    bytes.write(nextByte);
                }
            }
        }
        if (!sawInput) {
            return null;
        }
        return line(bytes, oversized);
    }

    private static Line line(ByteArrayOutputStream bytes, boolean oversized) {
        if (oversized) {
            return Line.tooLarge();
        }
        byte[] value = bytes.toByteArray();
        int length = value.length;
        if (length > 0 && value[length - 1] == '\r') {
            length--;
        }
        return new Line(new String(value, 0, length, StandardCharsets.UTF_8), false);
    }

    record Line(String value, boolean oversized) {

        static Line tooLarge() {
            return new Line(null, true);
        }
    }
}

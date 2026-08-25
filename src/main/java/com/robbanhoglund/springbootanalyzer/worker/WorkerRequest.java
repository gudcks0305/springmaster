package com.robbanhoglund.springbootanalyzer.worker;

import com.fasterxml.jackson.databind.JsonNode;
import com.robbanhoglund.springbootanalyzer.api.dto.AnalysisMode;
import java.nio.file.Path;
import java.util.Set;
import java.util.regex.Pattern;

/** Validated schema-v1 input accepted by the local analyzer worker. */
record WorkerRequest(
        String requestId,
        Path repositoryPath,
        String repositoryId,
        String contentHash,
        String repositoryUrl,
        String branch,
        AnalysisMode mode) {

    static final int SCHEMA_VERSION = 1;
    static final int MAX_REQUEST_ID_LENGTH = 256;
    static final int MAX_REPOSITORY_PATH_LENGTH = 4096;
    static final int MAX_REPOSITORY_ID_LENGTH = 256;
    static final int MAX_CONTENT_HASH_LENGTH = 96;
    static final int MAX_MODE_LENGTH = 16;

    private static final int MAX_REQUEST_FIELDS = 8;
    private static final int MAX_REPOSITORY_URL_LENGTH = 2048;
    private static final int MAX_BRANCH_LENGTH = 256;
    private static final Pattern OPAQUE_IDENTIFIER =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:/@+=-]*");
    private static final Pattern SHA256_CONTENT_HASH = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final Set<String> ALLOWED_FIELDS =
            Set.of(
                    "schemaVersion",
                    "requestId",
                    "repositoryPath",
                    "repositoryId",
                    "contentHash",
                    "repositoryUrl",
                    "branch",
                    "mode");

    static WorkerRequest from(JsonNode document, WorkerPathPolicy pathPolicy)
            throws WorkerProtocolException {
        if (document == null || !document.isObject()) {
            throw invalid("Request must be a JSON object.");
        }

        validateFields(document);
        validateSchemaVersion(document);
        String requestId = requiredIdentifier(document, "requestId", MAX_REQUEST_ID_LENGTH);
        Path repositoryPath = repositoryDirectory(document, pathPolicy);
        String repositoryId =
                requiredIdentifier(document, "repositoryId", MAX_REPOSITORY_ID_LENGTH);
        String contentHash = requiredContentHash(document);
        AnalysisMode mode = requiredMode(document);

        return new WorkerRequest(
                requestId,
                repositoryPath,
                repositoryId,
                contentHash,
                optionalText(document, "repositoryUrl", MAX_REPOSITORY_URL_LENGTH),
                optionalText(document, "branch", MAX_BRANCH_LENGTH),
                mode);
    }

    static String requestIdFrom(JsonNode document) {
        if (document == null || !document.isObject()) {
            return null;
        }
        JsonNode requestId = document.get("requestId");
        if (requestId == null || !requestId.isTextual()) {
            return null;
        }
        String value = requestId.textValue();
        if (value.length() > MAX_REQUEST_ID_LENGTH) {
            return null;
        }
        value = value.trim();
        return value.isEmpty() || !OPAQUE_IDENTIFIER.matcher(value).matches() ? null : value;
    }

    private static void validateFields(JsonNode document) throws WorkerProtocolException {
        if (document.size() > MAX_REQUEST_FIELDS) {
            throw invalid("Request contains unsupported fields.");
        }
        java.util.Iterator<String> fieldNames = document.fieldNames();
        while (fieldNames.hasNext()) {
            if (!ALLOWED_FIELDS.contains(fieldNames.next())) {
                throw invalid("Request contains unsupported fields.");
            }
        }
    }

    private static void validateSchemaVersion(JsonNode document) throws WorkerProtocolException {
        JsonNode schemaVersion = document.get("schemaVersion");
        if (schemaVersion == null
                || !schemaVersion.isIntegralNumber()
                || !schemaVersion.canConvertToInt()) {
            throw invalid("schemaVersion must be an integer.");
        }
        if (schemaVersion.intValue() != SCHEMA_VERSION) {
            throw new WorkerProtocolException(
                    "UNSUPPORTED_SCHEMA_VERSION", "Unsupported schema version.");
        }
    }

    private static String requiredIdentifier(JsonNode document, String fieldName, int maximumLength)
            throws WorkerProtocolException {
        JsonNode value = document.get(fieldName);
        if (value == null
                || !value.isTextual()
                || value.textValue().length() > maximumLength
                || value.textValue().trim().isEmpty()
                || !OPAQUE_IDENTIFIER.matcher(value.textValue().trim()).matches()) {
            throw invalid(fieldName + " must be a non-blank string.");
        }
        return value.textValue().trim();
    }

    private static String requiredText(JsonNode document, String fieldName, int maximumLength)
            throws WorkerProtocolException {
        JsonNode value = document.get(fieldName);
        if (value == null
                || !value.isTextual()
                || value.textValue().length() > maximumLength
                || value.textValue().trim().isEmpty()) {
            throw invalid(fieldName + " must be a non-blank string.");
        }
        return value.textValue().trim();
    }

    private static String optionalText(JsonNode document, String fieldName, int maximumLength)
            throws WorkerProtocolException {
        JsonNode value = document.get(fieldName);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual() || value.textValue().length() > maximumLength) {
            throw invalid(fieldName + " must be a string when present.");
        }
        String text = value.textValue().trim();
        return text.isEmpty() ? null : text;
    }

    private static Path repositoryDirectory(JsonNode document, WorkerPathPolicy pathPolicy)
            throws WorkerProtocolException {
        return pathPolicy.validateRepositoryPath(
                requiredText(document, "repositoryPath", MAX_REPOSITORY_PATH_LENGTH));
    }

    private static String requiredContentHash(JsonNode document) throws WorkerProtocolException {
        String contentHash = requiredText(document, "contentHash", MAX_CONTENT_HASH_LENGTH);
        if (!SHA256_CONTENT_HASH.matcher(contentHash).matches()) {
            throw invalid("contentHash must be a SHA-256 hash.");
        }
        return contentHash;
    }

    private static AnalysisMode requiredMode(JsonNode document) throws WorkerProtocolException {
        String mode = requiredText(document, "mode", MAX_MODE_LENGTH);
        try {
            return AnalysisMode.valueOf(mode);
        } catch (IllegalArgumentException exception) {
            throw invalid("mode must be STATIC_ONLY or EXTENDED.");
        }
    }

    private static WorkerProtocolException invalid(String message) {
        return new WorkerProtocolException("INVALID_REQUEST", message);
    }
}

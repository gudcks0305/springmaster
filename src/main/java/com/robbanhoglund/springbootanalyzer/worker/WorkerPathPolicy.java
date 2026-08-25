package com.robbanhoglund.springbootanalyzer.worker;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.boot.ApplicationArguments;

/** Immutable repository-path guard configured at worker startup. */
final class WorkerPathPolicy {

    static final String ALLOWED_ROOT_ENV = "SPRINGMASTER_WORKER_ALLOWED_ROOT";
    static final String REQUIRE_SNAPSHOT_MARKER_ENV = "SPRINGMASTER_WORKER_REQUIRE_SNAPSHOT_MARKER";

    private static final String ALLOWED_ROOT_OPTION = "allowed-root";
    private static final String REQUIRE_SNAPSHOT_MARKER_OPTION = "require-snapshot-marker";
    private static final String MARKER_FILE_GLOB = ".snapshot-marker-*";
    private static final Pattern MARKER_FILE_NAME =
            Pattern.compile("\\.snapshot-marker-([0-9a-f]{64})");
    private static final Pattern MARKER_CONTENT =
            Pattern.compile("\\Aspringmaster-snapshot-v1\\n([0-9a-f]{64})\\n\\z");
    private static final long MAX_MARKER_BYTES = 128;

    private final Path allowedRoot;
    private final boolean requireSnapshotMarker;

    private WorkerPathPolicy(Path allowedRoot, boolean requireSnapshotMarker) {
        this.allowedRoot = allowedRoot;
        this.requireSnapshotMarker = requireSnapshotMarker;
    }

    static WorkerPathPolicy unrestricted() {
        return new WorkerPathPolicy(null, false);
    }

    static WorkerPathPolicy from(ApplicationArguments arguments, Map<String, String> environment) {
        String configuredRoot =
                optionOrEnvironment(arguments, environment, ALLOWED_ROOT_OPTION, ALLOWED_ROOT_ENV);
        boolean markerRequired =
                booleanOptionOrEnvironment(
                        arguments,
                        environment,
                        REQUIRE_SNAPSHOT_MARKER_OPTION,
                        REQUIRE_SNAPSHOT_MARKER_ENV);
        Path allowedRoot = canonicalAllowedRoot(configuredRoot);
        if (markerRequired && allowedRoot == null) {
            throw invalidConfiguration();
        }
        return new WorkerPathPolicy(allowedRoot, markerRequired);
    }

    Path validateRepositoryPath(String rawPath) throws WorkerProtocolException {
        Path repositoryPath = realDirectory(rawPath);
        if (allowedRoot != null && !repositoryPath.startsWith(allowedRoot)) {
            throw new WorkerProtocolException(
                    "REPOSITORY_PATH_DENIED", "repositoryPath is not permitted.");
        }
        if (requireSnapshotMarker && !hasValidSnapshotMarker(repositoryPath)) {
            throw new WorkerProtocolException(
                    "SNAPSHOT_MARKER_REQUIRED", "repositoryPath is not an approved snapshot.");
        }
        return repositoryPath;
    }

    private static String optionOrEnvironment(
            ApplicationArguments arguments,
            Map<String, String> environment,
            String optionName,
            String environmentName) {
        if (arguments.containsOption(optionName)) {
            List<String> values = arguments.getOptionValues(optionName);
            if (values == null || values.size() != 1 || isBlank(values.getFirst())) {
                throw invalidConfiguration();
            }
            return values.getFirst().trim();
        }
        String value = environment.get(environmentName);
        if (value == null) {
            return null;
        }
        if (isBlank(value)) {
            throw invalidConfiguration();
        }
        return value.trim();
    }

    private static boolean booleanOptionOrEnvironment(
            ApplicationArguments arguments,
            Map<String, String> environment,
            String optionName,
            String environmentName) {
        if (arguments.containsOption(optionName)) {
            List<String> values = arguments.getOptionValues(optionName);
            if (values == null || values.isEmpty()) {
                return true;
            }
            if (values.size() != 1) {
                throw invalidConfiguration();
            }
            return parseBoolean(values.getFirst());
        }
        String value = environment.get(environmentName);
        return value == null ? false : parseBoolean(value);
    }

    private static boolean parseBoolean(String value) {
        if ("true".equals(value)) {
            return true;
        }
        if ("false".equals(value)) {
            return false;
        }
        throw invalidConfiguration();
    }

    private static Path canonicalAllowedRoot(String configuredRoot) {
        if (configuredRoot == null) {
            return null;
        }
        try {
            Path root = Path.of(configuredRoot);
            if (!root.isAbsolute() || !Files.isDirectory(root)) {
                throw invalidConfiguration();
            }
            return root.toRealPath();
        } catch (InvalidPathException | SecurityException | IOException exception) {
            throw invalidConfiguration();
        }
    }

    private static Path realDirectory(String rawPath) throws WorkerProtocolException {
        try {
            Path path = Path.of(rawPath);
            if (!path.isAbsolute() || !Files.isDirectory(path)) {
                throw invalidRequestPath();
            }
            return path.toRealPath();
        } catch (InvalidPathException | SecurityException | IOException exception) {
            throw invalidRequestPath();
        }
    }

    private static boolean hasValidSnapshotMarker(Path repositoryPath) {
        try (DirectoryStream<Path> entries =
                Files.newDirectoryStream(repositoryPath, MARKER_FILE_GLOB)) {
            for (Path marker : entries) {
                if (Files.isRegularFile(marker, LinkOption.NOFOLLOW_LINKS)
                        && hasExpectedMarkerContents(marker)) {
                    return true;
                }
            }
        } catch (IOException | SecurityException exception) {
            return false;
        }
        return false;
    }

    private static boolean hasExpectedMarkerContents(Path marker) throws IOException {
        if (Files.size(marker) > MAX_MARKER_BYTES) {
            return false;
        }
        Matcher fileName = MARKER_FILE_NAME.matcher(marker.getFileName().toString());
        if (!fileName.matches()) {
            return false;
        }
        String content = Files.readString(marker, StandardCharsets.UTF_8);
        Matcher markerContent = MARKER_CONTENT.matcher(content);
        return markerContent.matches() && fileName.group(1).equals(markerContent.group(1));
    }

    private static WorkerProtocolException invalidRequestPath() {
        return new WorkerProtocolException(
                "INVALID_REQUEST", "repositoryPath must be an absolute existing directory.");
    }

    private static IllegalArgumentException invalidConfiguration() {
        return new IllegalArgumentException("Worker path policy configuration is invalid.");
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}

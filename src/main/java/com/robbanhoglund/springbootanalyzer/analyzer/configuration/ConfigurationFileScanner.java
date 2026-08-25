package com.robbanhoglund.springbootanalyzer.analyzer.configuration;

import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.PropertySourceType;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class ConfigurationFileScanner {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigurationFileScanner.class);

    private static final Set<String> EXCLUDED_DIRECTORY_NAMES =
            Set.of(".git", ".gradle", "build", "target", "node_modules", "_springmaster_deps");
    private static final Pattern PROFILE_PATTERN =
            Pattern.compile("application-([^.]+)\\.(?:properties|ya?ml)", Pattern.CASE_INSENSITIVE);

    public List<ConfigurationCandidate> scan(Path repositoryRoot) {
        List<ConfigurationCandidate> candidates = new ArrayList<>();
        for (Path start : configurationRoots(repositoryRoot)) {
            if (Files.notExists(start) || !Files.isDirectory(start)) {
                continue;
            }
            int maxDepth = start.equals(repositoryRoot) ? 1 : Integer.MAX_VALUE;
            try (var stream = Files.walk(start, maxDepth)) {
                stream.filter(Files::isRegularFile)
                        .filter(path -> isConfigurationFile(path.getFileName().toString()))
                        .sorted(Comparator.naturalOrder())
                        .forEach(path -> candidates.add(toCandidate(repositoryRoot, path)));
            } catch (IOException exception) {
                LOGGER.warn(
                        "Failed to scan configuration files under {}; skipping this root",
                        start,
                        exception);
            }
        }
        return candidates.stream().distinct().toList();
    }

    private List<Path> configurationRoots(Path repositoryRoot) {
        Path normalizedRoot = repositoryRoot.toAbsolutePath().normalize();
        Set<Path> roots = new LinkedHashSet<>();
        roots.add(normalizedRoot);
        addDirectoryIfPresent(roots, normalizedRoot.resolve("config"));
        try {
            Files.walkFileTree(
                    normalizedRoot,
                    new SimpleFileVisitor<>() {
                        @Override
                        public FileVisitResult preVisitDirectory(
                                Path directory, BasicFileAttributes attributes) {
                            if (!directory.equals(normalizedRoot)
                                    && EXCLUDED_DIRECTORY_NAMES.contains(
                                            directory.getFileName().toString())) {
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            if (isStandardResourceRoot(normalizedRoot, directory)) {
                                roots.add(directory);
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            return FileVisitResult.CONTINUE;
                        }
                    });
        } catch (IOException exception) {
            LOGGER.warn(
                    "Failed to discover nested configuration roots under {}; using partial"
                            + " results",
                    normalizedRoot,
                    exception);
        }
        return roots.stream()
                .sorted(
                        Comparator.comparing(
                                path ->
                                        normalizedRoot
                                                .relativize(path)
                                                .toString()
                                                .replace('\\', '/')))
                .toList();
    }

    private boolean isStandardResourceRoot(Path repositoryRoot, Path directory) {
        Path relativePath = repositoryRoot.relativize(directory);
        int count = relativePath.getNameCount();
        return count >= 3
                && relativePath.getName(count - 3).toString().equals("src")
                && (relativePath.getName(count - 2).toString().equals("main")
                        || relativePath.getName(count - 2).toString().equals("test"))
                && relativePath.getName(count - 1).toString().equals("resources");
    }

    private void addDirectoryIfPresent(Set<Path> roots, Path directory) {
        if (Files.isDirectory(directory)) {
            roots.add(directory);
        }
    }

    private ConfigurationCandidate toCandidate(Path repositoryRoot, Path path) {
        String filename = path.getFileName().toString();
        return new ConfigurationCandidate(
                normalizePath(repositoryRoot, path),
                path,
                detectProfile(filename),
                detectSourceType(filename));
    }

    private boolean isConfigurationFile(String filename) {
        String normalized = filename.toLowerCase(Locale.ROOT);
        return normalized.matches("(application(?:-[^.]+)?|bootstrap)\\.(properties|ya?ml)");
    }

    private String detectProfile(String filename) {
        String normalized = filename.toLowerCase(Locale.ROOT);
        Matcher matcher = PROFILE_PATTERN.matcher(normalized);
        if (matcher.matches()) {
            return matcher.group(1);
        }
        if (normalized.startsWith("application.")) {
            return "default";
        }
        return "bootstrap";
    }

    private PropertySourceType detectSourceType(String filename) {
        String normalized = filename.toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".properties")) {
            return PropertySourceType.PROPERTIES;
        }
        if (normalized.endsWith(".yml") || normalized.endsWith(".yaml")) {
            return PropertySourceType.YAML;
        }
        return PropertySourceType.UNKNOWN;
    }

    private String normalizePath(Path repositoryRoot, Path sourceFile) {
        return repositoryRoot.relativize(sourceFile).toString().replace('\\', '/');
    }

    public record ConfigurationCandidate(
            String relativePath,
            Path absolutePath,
            String profile,
            PropertySourceType sourceType) {}
}

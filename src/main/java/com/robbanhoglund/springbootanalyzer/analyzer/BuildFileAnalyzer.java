package com.robbanhoglund.springbootanalyzer.analyzer;

import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildInfo;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildModuleInfo;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildTool;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Reads the project's build files and extracts metadata used by the rest of the analysis
 * pipeline: build tool, Spring Boot presence, Spring Boot version, Java version, and the
 * raw dependency set.
 *
 * <p>The analyzer reads standard Maven/Gradle descriptors at the repository root and statically
 * follows Maven {@code <modules>} and Gradle {@code include(...)} declarations. Repositories with
 * no root descriptor are treated as collections of independent build roots. No build script is
 * executed. Each discovered root is retained in {@link BuildInfo#modules()}, while the legacy
 * top-level fields remain a deterministic aggregate.
 *
 * <p>Spring Boot version detection uses ordered patterns: Gradle plugin
 * declarations and Maven parent/BOM {@code <version>} tags are rated {@code HIGH},
 * {@code gradle.properties} and version catalog entries {@code MEDIUM}, and a generic
 * dependency coordinate match {@code LOW}. Java version is detected from
 * {@code JavaLanguageVersion.of()}, {@code VERSION_*} constants, {@code sourceCompatibility},
 * Maven {@code <java.version>}, and Maven compiler properties.
 */
@Component
public class BuildFileAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(BuildFileAnalyzer.class);
    private static final Set<String> EXCLUDED_DIRECTORY_NAMES =
            Set.of(".git", ".gradle", "build", "target", "node_modules", "_springmaster_deps");

    private static final List<String> SPRING_BOOT_MARKERS =
            List.of("org.springframework.boot", "spring-boot-starter", "spring-boot-maven-plugin");

    private static final Pattern GRADLE_DEPENDENCY_PATTERN =
            Pattern.compile("['\"]([a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+(?::[^'\"]+)?)['\"]");

    private static final Pattern MAVEN_DEPENDENCY_PATTERN =
            Pattern.compile(
                    "<dependency>.*?<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>(?:.*?<version>([^<]+)</version>)?.*?</dependency>",
                    Pattern.DOTALL);
    private static final Pattern MAVEN_MODULE_PATTERN =
            Pattern.compile("<module>\\s*([^<]+?)\\s*</module>", Pattern.DOTALL);
    private static final Pattern GRADLE_INCLUDE_CALL_PATTERN =
            Pattern.compile("(?m)\\binclude\\s*\\(([^)]*)\\)");
    private static final Pattern GRADLE_INCLUDE_STATEMENT_PATTERN =
            Pattern.compile("(?m)\\binclude\\s+([^\\r\\n]+)");
    private static final Pattern QUOTED_VALUE_PATTERN = Pattern.compile("['\"]([^'\"]+)['\"]");

    private static final List<Pattern> JAVA_VERSION_PATTERNS =
            List.of(
                    Pattern.compile("JavaLanguageVersion\\.of\\((\\d+)\\)"),
                    Pattern.compile("VERSION_(\\d+)"),
                    Pattern.compile(
                            "(?:sourceCompatibility|targetCompatibility)\\s*=\\s*['\"]?(\\d+)"),
                    Pattern.compile("<java\\.version>(\\d+)</java\\.version>"),
                    Pattern.compile(
                            "<maven\\.compiler\\.(?:source|target|release)>(\\d+)</maven\\.compiler\\.(?:source|target|release)>"));
    private static final List<VersionPattern> SPRING_BOOT_VERSION_PATTERNS =
            List.of(
                    new VersionPattern(
                            Pattern.compile(
                                    "id\\s*['\"]org\\.springframework\\.boot['\"]\\s*version\\s*['\"]([^'\"]+)['\"]"),
                            "Gradle plugins",
                            "HIGH"),
                    new VersionPattern(
                            Pattern.compile(
                                    "org\\.springframework\\.boot['\"]?\\)\\s*version\\s*['\"]([^'\"]+)['\"]"),
                            "Gradle plugins",
                            "HIGH"),
                    new VersionPattern(
                            Pattern.compile("springBoot\\s*=\\s*['\"]([^'\"]+)['\"]"),
                            "gradle.properties",
                            "MEDIUM"),
                    new VersionPattern(
                            Pattern.compile("spring-boot\\s*=\\s*['\"]?([^\\s'\"]+)"),
                            "version catalog",
                            "MEDIUM"),
                    new VersionPattern(
                            Pattern.compile(
                                    "<artifactId>spring-boot-starter-parent</artifactId>\\s*<version>([^<]+)</version>",
                                    Pattern.DOTALL),
                            "Maven parent",
                            "HIGH"),
                    new VersionPattern(
                            Pattern.compile(
                                    "<artifactId>spring-boot-dependencies</artifactId>\\s*<version>([^<]+)</version>",
                                    Pattern.DOTALL),
                            "Maven BOM",
                            "HIGH"),
                    new VersionPattern(
                            Pattern.compile(
                                    "<artifactId>spring-boot-maven-plugin</artifactId>\\s*<version>([^<]+)</version>",
                                    Pattern.DOTALL),
                            "Maven plugin",
                            "HIGH"),
                    new VersionPattern(
                            Pattern.compile(
                                    "org\\.springframework\\.boot:[^:'\"]+[:\"]([^'\"]+)['\"]"),
                            "Dependency declaration",
                            "LOW"));

    /**
     * Scans all detectable build files under {@code repositoryRoot} and assembles a
     * {@link BuildInfo} summary.
     *
     * <p>Detection is purely textual (regex-based); no build system is invoked. Missing files
     * are silently skipped. I/O errors on individual files are silently ignored so that a
     * corrupt or inaccessible file does not abort the entire analysis.
     *
     * @param repositoryRoot root directory of the project being analysed
     * @return the assembled {@link BuildInfo}; never null
     */
    public BuildInfo analyze(Path repositoryRoot) {
        Path normalizedRoot = repositoryRoot.toAbsolutePath().normalize();
        List<Path> buildRoots = detectBuildRoots(normalizedRoot);
        List<BuildModuleInfo> modules =
                buildRoots.stream()
                        .map(buildRoot -> analyzeBuildRoot(normalizedRoot, buildRoot))
                        .toList();
        BuildTool buildTool =
                modules.stream()
                        .filter(module -> module.path().equals("."))
                        .map(BuildModuleInfo::buildTool)
                        .filter(tool -> tool != BuildTool.UNKNOWN)
                        .findFirst()
                        .orElseGet(
                                () ->
                                        modules.stream()
                                                .map(BuildModuleInfo::buildTool)
                                                .filter(tool -> tool != BuildTool.UNKNOWN)
                                                .findFirst()
                                                .orElse(BuildTool.UNKNOWN));

        boolean springBootDetected = false;
        String javaVersionHint = null;
        String springBootVersion = null;
        String springBootVersionSource = null;
        String springBootVersionConfidence = null;
        LinkedHashSet<String> dependencies = new LinkedHashSet<>();

        for (BuildModuleInfo module : modules) {
            springBootDetected = springBootDetected || module.springBootDetected();
            if (javaVersionHint == null && module.javaVersionHint() != null) {
                javaVersionHint = module.javaVersionHint();
            }
            if (isBetterVersion(module, springBootVersionConfidence)) {
                springBootVersion = module.springBootVersion();
                springBootVersionSource = module.springBootVersionSource();
                springBootVersionConfidence = module.springBootVersionConfidence();
            }
            dependencies.addAll(module.dependencies());
        }

        return new BuildInfo(
                buildTool,
                springBootDetected,
                javaVersionHint,
                List.copyOf(dependencies),
                springBootVersion,
                springBootVersionSource,
                springBootVersionConfidence,
                modules);
    }

    private BuildModuleInfo analyzeBuildRoot(Path repositoryRoot, Path buildRoot) {
        List<Path> buildFiles = detectBuildFiles(buildRoot);
        BuildTool buildTool = detectBuildTool(buildRoot);
        boolean springBootDetected = false;
        String javaVersionHint = null;
        String springBootVersion = null;
        String springBootVersionSource = null;
        String springBootVersionConfidence = null;
        LinkedHashSet<String> dependencies = new LinkedHashSet<>();

        for (Path buildFile : buildFiles) {
            String content = readFile(buildFile);
            springBootDetected = springBootDetected || containsSpringBootMarker(content);
            if (javaVersionHint == null) {
                javaVersionHint = detectJavaVersionHint(content);
            }
            SpringBootVersion candidate = detectSpringBootVersion(content);
            if (isBetterVersion(candidate, springBootVersionConfidence)) {
                springBootVersion = candidate.version();
                springBootVersionSource = candidate.source();
                springBootVersionConfidence = candidate.confidence();
            }
            dependencies.addAll(extractDependencies(buildFile, content));
        }

        String relativePath = repositoryRoot.relativize(buildRoot).toString().replace('\\', '/');
        return new BuildModuleInfo(
                relativePath.isBlank() ? "." : relativePath,
                buildTool,
                springBootDetected,
                javaVersionHint,
                List.copyOf(dependencies),
                springBootVersion,
                springBootVersionSource,
                springBootVersionConfidence);
    }

    private BuildTool detectBuildTool(Path buildRoot) {
        if (Files.exists(buildRoot.resolve("build.gradle"))
                || Files.exists(buildRoot.resolve("build.gradle.kts"))
                || Files.exists(buildRoot.resolve("settings.gradle"))
                || Files.exists(buildRoot.resolve("settings.gradle.kts"))) {
            return BuildTool.GRADLE;
        }
        if (Files.exists(buildRoot.resolve("pom.xml"))) {
            return BuildTool.MAVEN;
        }
        return BuildTool.UNKNOWN;
    }

    private List<Path> detectBuildRoots(Path normalizedRoot) {
        Set<Path> buildRoots = new LinkedHashSet<>();
        buildRoots.add(normalizedRoot);
        if (hasBuildDescriptor(normalizedRoot)) {
            discoverMavenModules(normalizedRoot, buildRoots);
            discoverGradleModules(normalizedRoot, buildRoots);
        } else {
            Set<Path> standaloneRoots = discoverStandaloneBuildRoots(normalizedRoot);
            buildRoots.addAll(standaloneRoots);
            for (Path standaloneRoot : standaloneRoots) {
                discoverMavenModules(standaloneRoot, buildRoots);
                discoverGradleModules(standaloneRoot, buildRoots);
            }
        }

        return buildRoots.stream()
                .sorted(
                        Comparator.comparing(
                                path ->
                                        normalizedRoot
                                                .relativize(path)
                                                .toString()
                                                .replace('\\', '/')))
                .toList();
    }

    private Set<Path> discoverStandaloneBuildRoots(Path repositoryRoot) {
        Set<Path> buildRoots = new LinkedHashSet<>();
        try {
            Files.walkFileTree(
                    repositoryRoot,
                    new SimpleFileVisitor<>() {
                        @Override
                        public FileVisitResult preVisitDirectory(
                                Path directory, BasicFileAttributes attributes) {
                            if (!directory.equals(repositoryRoot)
                                    && EXCLUDED_DIRECTORY_NAMES.contains(
                                            directory.getFileName().toString())) {
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFile(
                                Path file, BasicFileAttributes attributes) {
                            if (attributes.isRegularFile() && isPrimaryBuildDescriptor(file)) {
                                buildRoots.add(file.getParent().toAbsolutePath().normalize());
                            }
                            return FileVisitResult.CONTINUE;
                        }
                    });
        } catch (IOException exception) {
            LOGGER.warn(
                    "Failed to fully discover standalone build roots under {}; using partial"
                            + " results",
                    repositoryRoot,
                    exception);
        }
        return buildRoots;
    }

    private boolean hasBuildDescriptor(Path buildRoot) {
        return Files.isRegularFile(buildRoot.resolve("pom.xml"))
                || Files.isRegularFile(buildRoot.resolve("build.gradle"))
                || Files.isRegularFile(buildRoot.resolve("build.gradle.kts"))
                || Files.isRegularFile(buildRoot.resolve("settings.gradle"))
                || Files.isRegularFile(buildRoot.resolve("settings.gradle.kts"));
    }

    private boolean isPrimaryBuildDescriptor(Path file) {
        String name = file.getFileName().toString();
        return name.equals("pom.xml")
                || name.equals("build.gradle")
                || name.equals("build.gradle.kts")
                || name.equals("settings.gradle")
                || name.equals("settings.gradle.kts");
    }

    private List<Path> detectBuildFiles(Path buildRoot) {
        List<Path> buildFiles = new ArrayList<>();
        addIfExists(buildFiles, buildRoot.resolve("build.gradle"));
        addIfExists(buildFiles, buildRoot.resolve("build.gradle.kts"));
        addIfExists(buildFiles, buildRoot.resolve("pom.xml"));
        addIfExists(buildFiles, buildRoot.resolve("settings.gradle"));
        addIfExists(buildFiles, buildRoot.resolve("settings.gradle.kts"));
        addIfExists(buildFiles, buildRoot.resolve("gradle.properties"));
        addIfExists(buildFiles, buildRoot.resolve("gradle/libs.versions.toml"));
        return List.copyOf(buildFiles);
    }

    private void discoverMavenModules(Path repositoryRoot, Set<Path> buildRoots) {
        Deque<Path> pending = new ArrayDeque<>();
        Set<Path> visited = new HashSet<>();
        pending.add(repositoryRoot);

        while (!pending.isEmpty()) {
            Path currentRoot = pending.removeFirst();
            if (!visited.add(currentRoot)) {
                continue;
            }
            Path pom = currentRoot.resolve("pom.xml");
            if (!Files.isRegularFile(pom)) {
                continue;
            }
            Matcher matcher = MAVEN_MODULE_PATTERN.matcher(readFile(pom));
            while (matcher.find()) {
                Path moduleRoot = resolveModuleRoot(repositoryRoot, currentRoot, matcher.group(1));
                if (moduleRoot != null && Files.isRegularFile(moduleRoot.resolve("pom.xml"))) {
                    if (buildRoots.add(moduleRoot)) {
                        pending.addLast(moduleRoot);
                    }
                }
            }
        }
    }

    private void discoverGradleModules(Path repositoryRoot, Set<Path> buildRoots) {
        for (String settingsFileName : List.of("settings.gradle", "settings.gradle.kts")) {
            Path settingsFile = repositoryRoot.resolve(settingsFileName);
            if (!Files.isRegularFile(settingsFile)) {
                continue;
            }
            String content = readFile(settingsFile);
            collectGradleIncludes(content, GRADLE_INCLUDE_CALL_PATTERN)
                    .forEach(
                            module -> {
                                Path moduleRoot = resolveGradleModuleRoot(repositoryRoot, module);
                                if (moduleRoot != null) {
                                    buildRoots.add(moduleRoot);
                                }
                            });
            collectGradleIncludes(content, GRADLE_INCLUDE_STATEMENT_PATTERN)
                    .forEach(
                            module -> {
                                Path moduleRoot = resolveGradleModuleRoot(repositoryRoot, module);
                                if (moduleRoot != null) {
                                    buildRoots.add(moduleRoot);
                                }
                            });
        }
    }

    private List<String> collectGradleIncludes(String content, Pattern includePattern) {
        LinkedHashSet<String> modules = new LinkedHashSet<>();
        Matcher includeMatcher = includePattern.matcher(content);
        while (includeMatcher.find()) {
            Matcher valueMatcher = QUOTED_VALUE_PATTERN.matcher(includeMatcher.group(1));
            while (valueMatcher.find()) {
                modules.add(valueMatcher.group(1));
            }
        }
        return List.copyOf(modules);
    }

    private Path resolveGradleModuleRoot(Path repositoryRoot, String notation) {
        String relativePath = notation.trim();
        while (relativePath.startsWith(":")) {
            relativePath = relativePath.substring(1);
        }
        relativePath = relativePath.replace(':', '/');
        return resolveModuleRoot(repositoryRoot, repositoryRoot, relativePath);
    }

    private Path resolveModuleRoot(Path repositoryRoot, Path declaringRoot, String modulePath) {
        String trimmedPath = modulePath.trim();
        if (trimmedPath.isBlank() || trimmedPath.contains("${") || trimmedPath.contains("$")) {
            return null;
        }
        Path candidate = declaringRoot.resolve(trimmedPath).toAbsolutePath().normalize();
        if (candidate.getFileName() != null
                && candidate.getFileName().toString().equals("pom.xml")) {
            candidate = candidate.getParent();
        }
        if (candidate == null
                || !candidate.startsWith(repositoryRoot)
                || !Files.isDirectory(candidate)) {
            return null;
        }
        try {
            if (!candidate.toRealPath().startsWith(repositoryRoot.toRealPath())) {
                return null;
            }
        } catch (IOException exception) {
            return null;
        }
        return candidate;
    }

    private void addIfExists(List<Path> buildFiles, Path path) {
        if (Files.isRegularFile(path)) {
            buildFiles.add(path);
        }
    }

    private String readFile(Path path) {
        try {
            return Files.readString(path);
        } catch (IOException exception) {
            // Per the class contract, an individual unreadable build file is skipped rather than
            // aborting the whole analysis.
            LOGGER.debug("Failed to read build file {}; skipping", path, exception);
            return "";
        }
    }

    private boolean containsSpringBootMarker(String content) {
        return SPRING_BOOT_MARKERS.stream().anyMatch(content::contains);
    }

    private String detectJavaVersionHint(String content) {
        for (Pattern pattern : JAVA_VERSION_PATTERNS) {
            Matcher matcher = pattern.matcher(content);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return null;
    }

    private SpringBootVersion detectSpringBootVersion(String content) {
        for (VersionPattern versionPattern : SPRING_BOOT_VERSION_PATTERNS) {
            Matcher matcher = versionPattern.pattern().matcher(content);
            if (matcher.find()) {
                return new SpringBootVersion(
                        matcher.group(1), versionPattern.source(), versionPattern.confidence());
            }
        }
        return null;
    }

    private boolean isBetterVersion(SpringBootVersion candidate, String currentConfidence) {
        return candidate != null
                && (currentConfidence == null
                        || confidenceRank(candidate.confidence())
                                > confidenceRank(currentConfidence));
    }

    private boolean isBetterVersion(BuildModuleInfo candidate, String currentConfidence) {
        return candidate.springBootVersion() != null
                && (currentConfidence == null
                        || confidenceRank(candidate.springBootVersionConfidence())
                                > confidenceRank(currentConfidence));
    }

    private int confidenceRank(String confidence) {
        return switch (confidence) {
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }

    private List<String> extractDependencies(Path buildFile, String content) {
        if (buildFile.getFileName().toString().equals("pom.xml")) {
            return extractMavenDependencies(content);
        }
        return extractGradleDependencies(content);
    }

    private List<String> extractGradleDependencies(String content) {
        List<String> dependencies = new ArrayList<>();
        Matcher matcher = GRADLE_DEPENDENCY_PATTERN.matcher(content);
        while (matcher.find()) {
            dependencies.add(matcher.group(1));
        }
        return dependencies;
    }

    private List<String> extractMavenDependencies(String content) {
        List<String> dependencies = new ArrayList<>();
        Matcher matcher = MAVEN_DEPENDENCY_PATTERN.matcher(content);
        while (matcher.find()) {
            String version = matcher.group(3);
            if (version == null || version.isBlank()) {
                dependencies.add(matcher.group(1) + ":" + matcher.group(2));
            } else {
                dependencies.add(matcher.group(1) + ":" + matcher.group(2) + ":" + version);
            }
        }
        return dependencies;
    }

    private record VersionPattern(Pattern pattern, String source, String confidence) {}

    private record SpringBootVersion(String version, String source, String confidence) {}
}

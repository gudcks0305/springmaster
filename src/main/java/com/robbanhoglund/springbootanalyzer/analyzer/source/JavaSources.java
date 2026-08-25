package com.robbanhoglund.springbootanalyzer.analyzer.source;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An immutable snapshot of all nested {@code src/main/java} source trees in a repository, parsed
 * exactly once.
 *
 * <p>Historically every finding analyzer walked {@code src/main/java} and re-parsed every file with
 * its own {@link JavaParser}, so a single analysis parsed each {@code .java} file many times over.
 * The orchestrator now builds one {@code JavaSources} via {@link #from(Path)} and hands the same
 * instance to each analyzer, which iterates {@link #files()} instead of walking and parsing again.
 *
 * <p>All analyzers use the same parser configuration (Java 25 language level, UTF-8), so a single
 * shared parse is equivalent to the per-analyzer parses it replaces. Files that cannot be read are
 * skipped; files that fail to parse are retained with a {@code null} {@link JavaFile#compilationUnit()}
 * so that content-based heuristics still see them — mirroring the per-analyzer behaviour, which kept
 * raw-text checks working even when JavaParser could not produce an AST.
 */
public final class JavaSources {

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaSources.class);
    private static final Set<String> EXCLUDED_DIRECTORY_NAMES =
            Set.of(".git", ".gradle", "build", "target", "node_modules");

    public enum SourceOrigin {
        PRIMARY,
        DEPENDENCY
    }

    /**
     * A single parsed Java source file.
     *
     * @param path the absolute path on disk
     * @param relativePath the repository-relative path with forward slashes, as used in findings
     * @param compilationUnit the parsed AST, or {@code null} if the file could not be parsed
     * @param content the raw file text (never null)
     */
    public record JavaFile(
            Path path,
            String relativePath,
            CompilationUnit compilationUnit,
            String content,
            SourceOrigin origin) {}

    private final Path repositoryRoot;
    private final List<JavaFile> files;
    private final List<JavaFile> primaryFiles;
    private final List<JavaFile> dependencyFiles;

    private JavaSources(Path repositoryRoot, List<JavaFile> files) {
        this.repositoryRoot = repositoryRoot;
        this.files = files;
        this.primaryFiles =
                files.stream().filter(file -> file.origin() == SourceOrigin.PRIMARY).toList();
        this.dependencyFiles =
                files.stream().filter(file -> file.origin() == SourceOrigin.DEPENDENCY).toList();
    }

    /** Returns the repository root the sources were read from. */
    public Path repositoryRoot() {
        return repositoryRoot;
    }

    /** Returns the parsed files in stable (path-sorted) order; never null. */
    public List<JavaFile> files() {
        return files;
    }

    /** Returns only source owned by the analyzed repository, excluding dependency overlays. */
    public List<JavaFile> primaryFiles() {
        return primaryFiles;
    }

    /** Returns semantic dependency-overlay sources below the exact top-level overlay directory. */
    public List<JavaFile> dependencyFiles() {
        return dependencyFiles;
    }

    /** Returns {@code true} when no nested {@code src/main/java} tree contains Java source files. */
    public boolean isEmpty() {
        return files.isEmpty();
    }

    /**
     * Discovers every bounded {@code src/main/java} tree below {@code repositoryRoot}, reading
     * and parsing every {@code .java} file exactly once.
     *
     * <p>Repository metadata and generated/dependency trees ({@code .git}, {@code .gradle},
     * {@code build}, {@code target}, and {@code node_modules}) are pruned before traversal. Symbolic
     * links are not followed. Files are exposed in deterministic repository-relative path order.
     */
    public static JavaSources from(Path repositoryRoot) {
        if (Files.notExists(repositoryRoot) || !Files.isDirectory(repositoryRoot)) {
            return new JavaSources(repositoryRoot, List.of());
        }
        JavaParser parser =
                new JavaParser(
                        new ParserConfiguration()
                                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_25)
                                .setCharacterEncoding(StandardCharsets.UTF_8));
        List<Path> sourceFiles = discoverSourceFiles(repositoryRoot);
        List<JavaFile> files = new ArrayList<>(sourceFiles.size());
        for (Path path : sourceFiles) {
            try {
                String content = Files.readString(path, StandardCharsets.UTF_8);
                // Only expose a CompilationUnit when the parse fully succeeded. JavaParser's
                // error recovery can return a partial AST for invalid input, but the
                // per-analyzer code this replaces skipped files whose parse was not successful,
                // so mirror that to keep findings identical.
                var parseResult = parser.parse(content);
                CompilationUnit compilationUnit =
                        parseResult.isSuccessful() ? parseResult.getResult().orElse(null) : null;
                String relativePath = repositoryRoot.relativize(path).toString().replace('\\', '/');
                files.add(
                        new JavaFile(
                                path,
                                relativePath,
                                compilationUnit,
                                content,
                                sourceOrigin(repositoryRoot, path)));
            } catch (IOException exception) {
                // Skip an individual unreadable file rather than aborting the whole analysis.
                LOGGER.debug("Failed to read Java source {}; skipping", path, exception);
            }
        }
        return new JavaSources(repositoryRoot, List.copyOf(files));
    }

    private static List<Path> discoverSourceFiles(Path repositoryRoot) {
        List<Path> sourceFiles = new ArrayList<>();
        try {
            Files.walkFileTree(
                    repositoryRoot,
                    new SimpleFileVisitor<>() {
                        @Override
                        public FileVisitResult preVisitDirectory(
                                Path directory, BasicFileAttributes attributes) {
                            if (!directory.equals(repositoryRoot)
                                    && EXCLUDED_DIRECTORY_NAMES.contains(
                                            directory.getFileName().toString())
                                    && !isInsideMainJavaSource(repositoryRoot, directory)) {
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFile(
                                Path file, BasicFileAttributes attributes) {
                            if (attributes.isRegularFile()
                                    && file.getFileName().toString().endsWith(".java")
                                    && isUnderMainJavaSource(repositoryRoot, file)) {
                                sourceFiles.add(file);
                            }
                            return FileVisitResult.CONTINUE;
                        }
                    });
        } catch (IOException exception) {
            LOGGER.warn(
                    "Failed to fully discover Java sources under {}; using partial results",
                    repositoryRoot,
                    exception);
        }
        sourceFiles.sort(
                Comparator.comparing(
                        path -> repositoryRoot.relativize(path).toString().replace('\\', '/')));
        return List.copyOf(sourceFiles);
    }

    private static boolean isUnderMainJavaSource(Path repositoryRoot, Path file) {
        Path relativePath = repositoryRoot.relativize(file);
        for (int index = 0; index + 2 < relativePath.getNameCount(); index++) {
            if (relativePath.getName(index).toString().equals("src")
                    && relativePath.getName(index + 1).toString().equals("main")
                    && relativePath.getName(index + 2).toString().equals("java")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isInsideMainJavaSource(Path repositoryRoot, Path path) {
        Path relativePath = repositoryRoot.relativize(path);
        for (int index = 0; index + 2 < relativePath.getNameCount(); index++) {
            if (relativePath.getName(index).toString().equals("src")
                    && relativePath.getName(index + 1).toString().equals("main")
                    && relativePath.getName(index + 2).toString().equals("java")) {
                return true;
            }
        }
        return false;
    }

    private static SourceOrigin sourceOrigin(Path repositoryRoot, Path file) {
        Path relativePath = repositoryRoot.relativize(file);
        return relativePath.getNameCount() > 0
                        && relativePath.getName(0).toString().equals("_springmaster_deps")
                ? SourceOrigin.DEPENDENCY
                : SourceOrigin.PRIMARY;
    }
}

package com.robbanhoglund.springbootanalyzer.analyzer.source;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JavaSourcesTest {

    @TempDir Path repoRoot;

    private void writeSource(String relativePath, String content) throws IOException {
        Path file = repoRoot.resolve(relativePath);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }

    @Test
    void isEmptyWhenNoSourceRoot() {
        JavaSources sources = JavaSources.from(repoRoot);
        assertThat(sources.isEmpty()).isTrue();
        assertThat(sources.files()).isEmpty();
        assertThat(sources.repositoryRoot()).isEqualTo(repoRoot);
    }

    @Test
    void parsesEachFileOnceExposingCompilationUnitAndContent() throws IOException {
        writeSource(
                "src/main/java/com/example/Foo.java",
                """
                package com.example;
                class Foo {}
                """);
        writeSource(
                "src/main/java/com/example/Bar.java",
                """
                package com.example;
                class Bar {}
                """);

        JavaSources sources = JavaSources.from(repoRoot);

        assertThat(sources.files()).hasSize(2);
        // Stable, path-sorted order: Bar before Foo.
        assertThat(sources.files())
                .extracting(JavaSources.JavaFile::relativePath)
                .containsExactly(
                        "src/main/java/com/example/Bar.java", "src/main/java/com/example/Foo.java");
        JavaSources.JavaFile bar = sources.files().get(0);
        assertThat(bar.compilationUnit()).isNotNull();
        assertThat(bar.compilationUnit().getType(0).getNameAsString()).isEqualTo("Bar");
        assertThat(bar.content()).contains("class Bar");
    }

    @Test
    void retainsUnparseableFilesWithNullCompilationUnitButKeepsContent() throws IOException {
        writeSource("src/main/java/com/example/Broken.java", "this is not valid java @@@");

        JavaSources sources = JavaSources.from(repoRoot);

        assertThat(sources.files()).hasSize(1);
        JavaSources.JavaFile broken = sources.files().get(0);
        assertThat(broken.compilationUnit()).isNull();
        assertThat(broken.content()).contains("not valid java");
    }

    @Test
    void discoversAllMavenModuleSourcesAndPrunesGeneratedTrees() throws IOException {
        Files.writeString(
                repoRoot.resolve("pom.xml"),
                """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>parent</artifactId>
                  <version>1.0.0</version>
                  <packaging>pom</packaging>
                  <modules><module>app</module><module>worker</module></modules>
                </project>
                """);
        writeSource(
                "app/src/main/java/com/example/app/App.java",
                """
                package com.example.app;
                class App {}
                """);
        writeSource(
                "worker/src/main/java/com/example/worker/Worker.java",
                """
                package com.example.worker;
                class Worker {}
                """);
        writeSource(
                "worker/target/generated/src/main/java/com/example/IgnoredTarget.java",
                "class IgnoredTarget {}\n");
        writeSource(
                "app/build/generated/src/main/java/com/example/IgnoredBuild.java",
                "class IgnoredBuild {}\n");
        writeSource(
                "node_modules/vendor/src/main/java/com/example/IgnoredDependency.java",
                "class IgnoredDependency {}\n");
        writeSource(
                ".gradle/cache/src/main/java/com/example/IgnoredGradleCache.java",
                "class IgnoredGradleCache {}\n");
        writeSource(
                ".git/worktrees/copy/src/main/java/com/example/IgnoredGitMetadata.java",
                "class IgnoredGitMetadata {}\n");

        JavaSources sources = JavaSources.from(repoRoot);

        assertThat(sources.files())
                .extracting(JavaSources.JavaFile::relativePath)
                .containsExactly(
                        "app/src/main/java/com/example/app/App.java",
                        "worker/src/main/java/com/example/worker/Worker.java");
    }

    @Test
    void tagsOnlyExactTopLevelDependencyOverlayAsDependencySource() throws IOException {
        writeSource(
                "src/main/java/com/example/Primary.java",
                "package com.example; class Primary {}\n");
        writeSource(
                "_springmaster_deps/shared/src/main/java/com/example/Dependency.java",
                "package com.example; class Dependency {}\n");
        writeSource(
                "nested/_springmaster_deps/not-overlay/src/main/java/com/example/Nested.java",
                "package com.example; class Nested {}\n");

        JavaSources sources = JavaSources.from(repoRoot);

        assertThat(sources.primaryFiles())
                .extracting(JavaSources.JavaFile::relativePath)
                .containsExactly(
                        "nested/_springmaster_deps/not-overlay/src/main/java/com/example/Nested.java",
                        "src/main/java/com/example/Primary.java");
        assertThat(sources.dependencyFiles())
                .extracting(JavaSources.JavaFile::relativePath)
                .containsExactly(
                        "_springmaster_deps/shared/src/main/java/com/example/Dependency.java");
    }
}

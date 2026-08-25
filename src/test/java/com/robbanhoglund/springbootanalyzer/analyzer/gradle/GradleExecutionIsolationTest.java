package com.robbanhoglund.springbootanalyzer.analyzer.gradle;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleExecutionMode;
import com.robbanhoglund.springbootanalyzer.config.AnalyzerProperties;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GradleExecutionIsolationTest {

    @TempDir Path tempDir;

    @Test
    void timeoutDrainsOutputConcurrentlyAndTerminatesChildProcesses() throws Exception {
        assumePosix();
        Path repository = Files.createDirectory(tempDir.resolve("timeout-repository"));
        Path script =
                executableScript(
                        repository.resolve("fake-gradle"),
                        """
                        #!/bin/sh
                        trap '' TERM
                        (
                          trap '' TERM
                          while :; do sleep 30; done
                        ) &
                        child=$!
                        printf '%s' "$child" > child.pid
                        printf 'token=must-not-leak\\n'
                        while :; do printf '0123456789abcdef'; done
                        """);

        GradleExecutionResult result =
                assertTimeoutPreemptively(
                        Duration.ofSeconds(3),
                        () ->
                                executionService()
                                        .execute(
                                                repository,
                                                GradleExecutionMode.SYSTEM_GRADLE,
                                                null,
                                                "9.5.0",
                                                Runtime.version().feature(),
                                                properties(
                                                        script,
                                                        Duration.ofMillis(150),
                                                        List.of("EXPLICIT_PROXY"))));

        assertThat(result.timedOut()).isTrue();
        assertThat(result.output()).doesNotContain("must-not-leak");
        assertThat(result.output()).contains("token=[redacted]");
        assertThat(result.output().getBytes(java.nio.charset.StandardCharsets.UTF_8))
                .hasSizeLessThanOrEqualTo(256);

        long childPid = Long.parseLong(Files.readString(repository.resolve("child.pid")));
        assertThat(awaitNotAlive(childPid, Duration.ofSeconds(2))).isTrue();
    }

    @Test
    void successfulParentCannotHangOutputDrainWhenChildKeepsStdoutOpen() throws Exception {
        assumePosix();
        Path repository = Files.createDirectory(tempDir.resolve("held-stdout-repository"));
        Path script =
                executableScript(
                        repository.resolve("fake-gradle"),
                        """
                        #!/bin/sh
                        sleep 30 &
                        child=$!
                        printf '%s' "$child" > child.pid
                        printf 'parent-complete\\n'
                        exit 0
                        """);

        long started = System.nanoTime();
        GradleExecutionResult result =
                assertTimeoutPreemptively(
                        Duration.ofSeconds(3),
                        () ->
                                executionService()
                                        .execute(
                                                repository,
                                                GradleExecutionMode.SYSTEM_GRADLE,
                                                null,
                                                "9.5.0",
                                                Runtime.version().feature(),
                                                properties(
                                                        script,
                                                        Duration.ofSeconds(2),
                                                        List.of("EXPLICIT_PROXY"))));
        Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

        try {
            assertThat(result.successful()).isTrue();
            assertThat(result.output()).contains("parent-complete");
            assertThat(elapsed).isLessThan(Duration.ofSeconds(2));
        } finally {
            long childPid = Long.parseLong(Files.readString(repository.resolve("child.pid")));
            ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
        }
    }

    @Test
    void toolingApiEnvironmentUsesAllowlistAndIsolatedHomes() throws Exception {
        Path repository = Files.createDirectory(tempDir.resolve("environment-repository"));
        AnalyzerProperties.GradleProperties properties =
                properties(
                        tempDir.resolve("unused-gradle"),
                        Duration.ofSeconds(1),
                        List.of("EXPLICIT_PROXY"));
        GradleExecutionSupport.ExecutionFiles files =
                GradleExecutionSupport.prepareExecutionFiles(repository, properties);
        GradleToolingApiExecutionService service =
                new GradleToolingApiExecutionService(
                        new GradleJavaCompatibilityService(), failureClassifier());

        Map<String, String> environment =
                service.launcherEnvironment(
                        Map.of(
                                "PATH", "/safe/bin",
                                "HOME", "/real/home",
                                "USERPROFILE", "C:\\Users\\real",
                                "GITHUB_TOKEN", "must-not-leak",
                                "AWS_SECRET_ACCESS_KEY", "must-not-leak",
                                "EXPLICIT_PROXY", "http://proxy.example"),
                        files,
                        properties);

        assertThat(environment)
                .containsEntry("PATH", "/safe/bin")
                .containsEntry("EXPLICIT_PROXY", "http://proxy.example")
                .containsEntry("GRADLE_USER_HOME", files.gradleUserHome().toString())
                .containsEntry("HOME", files.executionHome().toString())
                .containsEntry("USERPROFILE", files.executionHome().toString())
                .doesNotContainKeys("GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY");
        assertThat(environment.get("HOME")).isNotEqualTo(environment.get("GRADLE_USER_HOME"));

        Files.writeString(files.executionHome().resolve("created-by-build"), "temporary");
        GradleExecutionSupport.cleanupExecutionHome(files);
        assertThat(files.executionHome()).doesNotExist();
        assertThat(files.initScript()).exists();
    }

    private GradleExecutionService executionService() {
        return new GradleExecutionService(
                new GradleCommandBuilder(),
                new GradleExecutableLocator(),
                new GradleJavaCompatibilityService(),
                failureClassifier());
    }

    private GradleFailureClassifier failureClassifier() {
        return new GradleFailureClassifier(new GradlePluginResolutionFailureParser());
    }

    private AnalyzerProperties.GradleProperties properties(
            Path executable, Duration timeout, List<String> passThroughEnvironment) {
        return new AnalyzerProperties.GradleProperties(
                true,
                timeout,
                GradleExecutionMode.SYSTEM_GRADLE,
                "9.5.0",
                tempDir.resolve("gradle-cache"),
                passThroughEnvironment,
                null,
                null,
                false,
                List.of("https://plugins.gradle.org/m2/"),
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                null,
                null,
                false,
                false,
                false,
                executable,
                null,
                256,
                100);
    }

    private Path executableScript(Path path, String content) throws IOException {
        Files.writeString(path, content);
        assertThat(path.toFile().setExecutable(true)).isTrue();
        return path;
    }

    private boolean awaitNotAlive(long pid, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            if (ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) {
                Thread.sleep(10);
                continue;
            }
            return true;
        }
        return !ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false);
    }

    private void assumePosix() {
        Assumptions.assumeFalse(
                System.getProperty("os.name", "").toLowerCase().contains("win"),
                "POSIX shell process-tree test");
    }
}

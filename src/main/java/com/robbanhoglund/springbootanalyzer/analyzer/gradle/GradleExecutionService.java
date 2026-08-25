package com.robbanhoglund.springbootanalyzer.analyzer.gradle;

import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleExecutionFailureType;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleExecutionMode;
import com.robbanhoglund.springbootanalyzer.config.AnalyzerProperties;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class GradleExecutionService {

    private static final Logger LOGGER = LoggerFactory.getLogger(GradleExecutionService.class);
    private static final Duration OUTPUT_DRAIN_GRACE = Duration.ofMillis(250);
    private static final Duration PROCESS_TERMINATION_GRACE = Duration.ofMillis(500);

    private final GradleCommandBuilder gradleCommandBuilder;
    private final GradleExecutableLocator gradleExecutableLocator;
    private final GradleJavaCompatibilityService gradleJavaCompatibilityService;
    private final GradleFailureClassifier gradleFailureClassifier;

    public GradleExecutionService(
            GradleCommandBuilder gradleCommandBuilder,
            GradleExecutableLocator gradleExecutableLocator,
            GradleJavaCompatibilityService gradleJavaCompatibilityService,
            GradleFailureClassifier gradleFailureClassifier) {
        this.gradleCommandBuilder = gradleCommandBuilder;
        this.gradleExecutableLocator = gradleExecutableLocator;
        this.gradleJavaCompatibilityService = gradleJavaCompatibilityService;
        this.gradleFailureClassifier = gradleFailureClassifier;
    }

    public GradleExecutionResult execute(
            Path repositoryRoot,
            GradleExecutionMode executionMode,
            Path wrapperScript,
            String gradleVersion,
            int javaFeatureVersion,
            AnalyzerProperties.GradleProperties properties) {
        return execute(
                repositoryRoot,
                executionMode,
                wrapperScript,
                gradleVersion,
                javaFeatureVersion,
                properties,
                null);
    }

    public GradleExecutionResult execute(
            Path repositoryRoot,
            GradleExecutionMode executionMode,
            Path wrapperScript,
            String gradleVersion,
            int javaFeatureVersion,
            AnalyzerProperties.GradleProperties properties,
            Path localPluginRepository) {
        String executionLabel = GradleExecutionSupport.executionModeLabel("PROCESS", executionMode);
        Path executable = resolveExecutable(executionMode, wrapperScript, properties);
        if (executable == null) {
            return new GradleExecutionResult(
                    false,
                    false,
                    -1,
                    null,
                    null,
                    null,
                    executionLabel,
                    gradleVersion,
                    String.valueOf(javaFeatureVersion),
                    GradleExecutionFailureType.EXECUTABLE_NOT_FOUND,
                    "External Gradle fallback was skipped because no Gradle executable was"
                            + " configured or found on PATH.",
                    null);
        }
        GradleExecutionSupport.ExecutionFiles files = null;
        Process process = null;
        ExecutorService outputExecutor = null;
        Future<?> outputFuture = null;
        CappedOutputStream output = new CappedOutputStream(properties.maxOutputBytes());
        try {
            files =
                    GradleExecutionSupport.prepareExecutionFiles(
                            repositoryRoot, properties, localPluginRepository);

            List<String> command =
                    new ArrayList<>(
                            gradleCommandBuilder.buildCommand(
                                    executable.toString(),
                                    files.initScript(),
                                    files.reportFile(),
                                    properties.maxResolvedDependencies(),
                                    properties.allowNetwork(),
                                    properties));
            command.add(1, "-Duser.home=" + files.executionHome());
            LOGGER.info(
                    "Executing Gradle diagnostic task: executionMode={}, workspaceId={},"
                            + " reportFile={}, timeout={}, useWrapper={}",
                    executionMode,
                    workspaceId(repositoryRoot),
                    fileName(files.reportFile()),
                    properties.timeout(),
                    executionMode == GradleExecutionMode.WRAPPER);

            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.directory(repositoryRoot.toFile());
            processBuilder.redirectErrorStream(true);
            processBuilder.environment().clear();
            processBuilder
                    .environment()
                    .putAll(
                            GradleExecutionSupport.safeEnvironment(
                                    System.getenv(),
                                    files.gradleUserHome(),
                                    files.executionHome(),
                                    properties));
            if (properties.javaHome() != null) {
                processBuilder.environment().put("JAVA_HOME", properties.javaHome().toString());
            }

            process = processBuilder.start();
            outputExecutor = Executors.newSingleThreadExecutor(outputDaemonFactory());
            InputStream processOutput = process.getInputStream();
            outputFuture = outputExecutor.submit(() -> drainOutput(processOutput, output));
            boolean finished =
                    process.waitFor(properties.timeout().toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                terminateProcessTree(process);
                closeProcessStreams(process);
                awaitOutputDrain(outputFuture, OUTPUT_DRAIN_GRACE);
                LOGGER.warn("Gradle diagnostic task timed out after {}", properties.timeout());
                return new GradleExecutionResult(
                        false,
                        true,
                        -1,
                        files.reportFile(),
                        files.initScript(),
                        GradleExecutionSupport.redact(output.asString()),
                        executionLabel,
                        gradleVersion,
                        String.valueOf(javaFeatureVersion),
                        GradleExecutionFailureType.TIMED_OUT,
                        "Gradle diagnostic task timed out.",
                        null);
            }

            awaitOutputDrain(outputFuture, OUTPUT_DRAIN_GRACE);
            if (!outputFuture.isDone()) {
                // A repository-controlled descendant can outlive the launcher while retaining its
                // stdout pipe. Closing our side keeps a successful parent exit from hanging.
                closeProcessStreams(process);
                outputFuture.cancel(true);
            }
            String outputMessage = output.asString();
            LOGGER.info("Gradle diagnostic task exited with code {}", process.exitValue());
            return new GradleExecutionResult(
                    process.exitValue() == 0,
                    false,
                    process.exitValue(),
                    files.reportFile(),
                    files.initScript(),
                    GradleExecutionSupport.redact(outputMessage),
                    executionLabel,
                    gradleVersion,
                    String.valueOf(javaFeatureVersion),
                    process.exitValue() == 0
                            ? GradleExecutionFailureType.NONE
                            : GradleExecutionSupport.classifyFailure(
                                            outputMessage,
                                            gradleVersion,
                                            javaFeatureVersion,
                                            gradleJavaCompatibilityService,
                                            gradleFailureClassifier)
                                    .failureType(),
                    process.exitValue() == 0
                            ? null
                            : conciseErrorMessage(outputMessage, gradleVersion, javaFeatureVersion),
                    process.exitValue() == 0
                            ? null
                            : GradleExecutionSupport.classifyFailure(
                                            outputMessage,
                                            gradleVersion,
                                            javaFeatureVersion,
                                            gradleJavaCompatibilityService,
                                            gradleFailureClassifier)
                                    .pluginResolutionFailure());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            terminateProcessTree(process);
            closeProcessStreams(process);
            LOGGER.warn("Gradle diagnostic task interrupted");
            LOGGER.debug("Gradle diagnostic task interrupted", exception);
            return new GradleExecutionResult(
                    false,
                    false,
                    -1,
                    null,
                    null,
                    GradleExecutionSupport.redact(exception.getMessage()),
                    executionLabel,
                    gradleVersion,
                    String.valueOf(javaFeatureVersion),
                    GradleExecutionFailureType.UNKNOWN,
                    "Gradle diagnostic task was interrupted.",
                    null);
        } catch (IOException exception) {
            String message = GradleExecutionSupport.redact(exception.getMessage());
            GradleFailureClassifier.ClassifiedGradleFailure classifiedFailure =
                    GradleExecutionSupport.classifyFailure(
                            message,
                            gradleVersion,
                            javaFeatureVersion,
                            gradleJavaCompatibilityService,
                            gradleFailureClassifier);
            GradleExecutionFailureType failureType = classifiedFailure.failureType();
            logFailure(
                    "Failed to execute Gradle diagnostic task",
                    failureType,
                    message,
                    gradleVersion,
                    javaFeatureVersion,
                    exception);
            return new GradleExecutionResult(
                    false,
                    false,
                    -1,
                    null,
                    null,
                    message,
                    executionLabel,
                    gradleVersion,
                    String.valueOf(javaFeatureVersion),
                    failureType,
                    conciseErrorMessage(message, gradleVersion, javaFeatureVersion),
                    classifiedFailure.pluginResolutionFailure());
        } finally {
            if (outputFuture != null && !outputFuture.isDone()) {
                outputFuture.cancel(true);
            }
            if (outputExecutor != null) {
                outputExecutor.shutdownNow();
            }
            GradleExecutionSupport.cleanupExecutionHome(files);
        }
    }

    private void drainOutput(InputStream inputStream, CappedOutputStream output) {
        try (inputStream) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                // Keep draining after the capture cap is reached. Stopping at the cap can fill the
                // native pipe and deadlock the Gradle process.
                output.write(buffer, 0, read);
            }
        } catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    private void awaitOutputDrain(Future<?> future, Duration grace) throws InterruptedException {
        if (future == null || future.isDone()) {
            return;
        }
        try {
            future.get(grace.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException exception) {
            // The caller closes the process streams and cancels the daemon drainer.
        } catch (ExecutionException exception) {
            LOGGER.debug("Failed while draining Gradle process output", exception.getCause());
        }
    }

    private void terminateProcessTree(Process process) {
        if (process == null) {
            return;
        }
        List<ProcessHandle> descendants = new ArrayList<>();
        try {
            descendants.addAll(process.descendants().toList());
        } catch (SecurityException | UnsupportedOperationException exception) {
            LOGGER.debug("Unable to enumerate Gradle process descendants", exception);
        }
        // Request termination from leaves toward the launcher, then force any survivors. Process
        // discovery is inherently racy, so the host sandbox remains the hard security boundary.
        Collections.reverse(descendants);
        descendants.forEach(this::destroyBestEffort);
        destroyBestEffort(process.toHandle());
        try {
            process.waitFor(PROCESS_TERMINATION_GRACE.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
        descendants.stream().filter(ProcessHandle::isAlive).forEach(this::destroyBestEffort);
        if (process.isAlive()) {
            destroyBestEffort(process.toHandle());
        }
    }

    private void destroyBestEffort(ProcessHandle processHandle) {
        try {
            if (processHandle.isAlive()) {
                processHandle.destroyForcibly();
            }
        } catch (IllegalStateException
                | SecurityException
                | UnsupportedOperationException exception) {
            LOGGER.debug("Unable to terminate Gradle process {}", processHandle.pid(), exception);
        }
    }

    private void closeProcessStreams(Process process) {
        if (process == null) {
            return;
        }
        try {
            process.getInputStream().close();
        } catch (IOException exception) {
            LOGGER.debug("Failed to close Gradle stdout", exception);
        }
        try {
            process.getErrorStream().close();
        } catch (IOException exception) {
            LOGGER.debug("Failed to close Gradle stderr", exception);
        }
        try {
            process.getOutputStream().close();
        } catch (IOException exception) {
            LOGGER.debug("Failed to close Gradle stdin", exception);
        }
    }

    private ThreadFactory outputDaemonFactory() {
        return runnable -> {
            Thread thread = new Thread(runnable, "gradle-process-output-drainer");
            thread.setDaemon(true);
            return thread;
        };
    }

    private static final class CappedOutputStream extends java.io.OutputStream {
        private final ByteArrayOutputStream delegate = new ByteArrayOutputStream();
        private final int maxBytes;
        private int written;

        private CappedOutputStream(int maxBytes) {
            this.maxBytes = maxBytes;
        }

        @Override
        public synchronized void write(int value) {
            if (written < maxBytes) {
                delegate.write(value);
                written++;
            }
        }

        @Override
        public synchronized void write(byte[] buffer, int offset, int length) {
            if (written >= maxBytes) {
                return;
            }
            int allowed = Math.min(length, maxBytes - written);
            delegate.write(buffer, offset, allowed);
            written += allowed;
        }

        private synchronized String asString() {
            return delegate.toString(StandardCharsets.UTF_8);
        }
    }

    private Path resolveExecutable(
            GradleExecutionMode executionMode,
            Path wrapperScript,
            AnalyzerProperties.GradleProperties properties) {
        if (executionMode == GradleExecutionMode.WRAPPER && wrapperScript != null) {
            return wrapperScript;
        }
        return gradleExecutableLocator.findSystemGradleExecutable(properties);
    }

    private String conciseErrorMessage(
            String message, String gradleVersion, int javaFeatureVersion) {
        GradleExecutionFailureType failureType =
                GradleExecutionSupport.classifyFailure(
                                message,
                                gradleVersion,
                                javaFeatureVersion,
                                gradleJavaCompatibilityService,
                                gradleFailureClassifier)
                        .failureType();
        return switch (failureType) {
            case INCOMPATIBLE_JAVA_AND_GRADLE ->
                    "Diagnostic Gradle %s is not compatible with Java %d. Use Gradle 9.1.0+ or configure analyzer.gradle.java-home."
                            .formatted(gradleVersion, javaFeatureVersion);
            case EXECUTABLE_NOT_FOUND ->
                    "External Gradle fallback was skipped because no Gradle executable was"
                            + " configured or found on PATH.";
            case TIMED_OUT -> "Gradle diagnostic task timed out.";
            case INIT_SCRIPT_COMPILATION_FAILED -> helperScopeMessage(message);
            case SETTINGS_PLUGIN_RESOLUTION_FAILED ->
                    "Settings plugin could not be resolved before the analyzer diagnostic task"
                            + " could run.";
            case BUILD_LOGIC_FAILED -> "Gradle diagnostic task failed during build configuration.";
            default ->
                    message == null || message.isBlank()
                            ? "Gradle diagnostic task failed."
                            : message;
        };
    }

    private void logFailure(
            String prefix,
            GradleExecutionFailureType failureType,
            String message,
            String gradleVersion,
            int javaFeatureVersion,
            Exception exception) {
        if (failureType == GradleExecutionFailureType.INCOMPATIBLE_JAVA_AND_GRADLE) {
            LOGGER.warn(
                    "Gradle model analysis skipped: diagnostic Gradle {} is not compatible with"
                            + " Java {}. Use Gradle 9.1.0+.",
                    gradleVersion,
                    javaFeatureVersion);
            LOGGER.debug(prefix, exception);
            return;
        }
        if (failureType == GradleExecutionFailureType.EXECUTABLE_NOT_FOUND) {
            LOGGER.warn(message);
            LOGGER.debug(prefix, exception);
            return;
        }
        if (failureType == GradleExecutionFailureType.SETTINGS_PLUGIN_RESOLUTION_FAILED
                || failureType == GradleExecutionFailureType.PLUGIN_RESOLUTION_FAILED) {
            LOGGER.warn("Gradle diagnostic task failed during plugin resolution: {}", message);
            LOGGER.debug(prefix, exception);
            return;
        }
        if (failureType == GradleExecutionFailureType.INIT_SCRIPT_COMPILATION_FAILED) {
            LOGGER.warn(
                    "Gradle diagnostic task failed because the analyzer generated an invalid init"
                            + " script: {}",
                    message);
            LOGGER.debug(prefix, exception);
            return;
        }
        LOGGER.warn(prefix);
        LOGGER.debug(prefix, exception);
    }

    private String helperScopeMessage(String message) {
        String normalized = message == null ? "" : message.toLowerCase();
        if (normalized.contains("could not find method sanitizevalue()")
                || normalized.contains("could not find method sbasanitizevalue()")) {
            return "Gradle model analysis failed because the generated init script called helper"
                    + " method sanitizeValue from a Gradle task closure. This is an analyzer"
                    + " init-script scoping bug.";
        }
        return "Gradle model analysis failed because the analyzer generated an invalid Gradle init"
                + " script. This is likely a path escaping or helper scoping issue.";
    }

    private String workspaceId(Path repositoryRoot) {
        Path parent = repositoryRoot == null ? null : repositoryRoot.getParent();
        return fileName(parent);
    }

    private String fileName(Path path) {
        return path == null || path.getFileName() == null ? null : path.getFileName().toString();
    }
}

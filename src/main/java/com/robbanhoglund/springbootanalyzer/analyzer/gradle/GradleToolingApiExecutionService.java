package com.robbanhoglund.springbootanalyzer.analyzer.gradle;

import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleExecutionFailureType;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleExecutionMode;
import com.robbanhoglund.springbootanalyzer.config.AnalyzerProperties;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeoutException;
import org.gradle.tooling.BuildLauncher;
import org.gradle.tooling.CancellationTokenSource;
import org.gradle.tooling.GradleConnectionException;
import org.gradle.tooling.GradleConnector;
import org.gradle.tooling.ProjectConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class GradleToolingApiExecutionService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(GradleToolingApiExecutionService.class);
    private final GradleJavaCompatibilityService gradleJavaCompatibilityService;
    private final GradleFailureClassifier gradleFailureClassifier;

    public GradleToolingApiExecutionService(
            GradleJavaCompatibilityService gradleJavaCompatibilityService,
            GradleFailureClassifier gradleFailureClassifier) {
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
        String executionLabel =
                GradleExecutionSupport.executionModeLabel("TOOLING_API", executionMode);
        GradleExecutionSupport.ExecutionFiles files = null;
        GradleConnector connector = null;
        try {
            files =
                    GradleExecutionSupport.prepareExecutionFiles(
                            repositoryRoot, properties, localPluginRepository);
            CappedOutputStream output = new CappedOutputStream(properties.maxOutputBytes());
            List<String> arguments = arguments(files, properties);

            LOGGER.info(
                    "Executing Gradle diagnostic task via Tooling API: executionMode={},"
                            + " workspaceId={}, reportFile={}, timeout={}, useWrapper={}",
                    executionMode,
                    workspaceId(repositoryRoot),
                    fileName(files.reportFile()),
                    properties.timeout(),
                    executionMode == GradleExecutionMode.WRAPPER);

            connector =
                    GradleConnector.newConnector()
                            .forProjectDirectory(repositoryRoot.toFile())
                            .useGradleUserHomeDir(files.gradleUserHome().toFile());
            configureConnector(connector, executionMode, wrapperScript, gradleVersion);

            CancellationTokenSource cancellationTokenSource =
                    GradleConnector.newCancellationTokenSource();
            ExecutorService executorService = Executors.newSingleThreadExecutor(daemonFactory());
            try (ProjectConnection connection = connector.connect()) {
                BuildLauncher launcher = connection.newBuild().forTasks("springBootAnalyzerModel");
                launcher.withArguments(arguments);
                launcher.withCancellationToken(cancellationTokenSource.token());
                launcher.setColorOutput(false);
                launcher.setStandardOutput(output);
                launcher.setStandardError(output);
                launcher.setEnvironmentVariables(
                        launcherEnvironment(System.getenv(), files, properties));
                launcher.addJvmArguments("-Duser.home=" + files.executionHome());
                if (properties.javaHome() != null) {
                    launcher.setJavaHome(properties.javaHome().toFile());
                }

                Future<?> future = executorService.submit(() -> launcher.run());
                return awaitResult(
                        future,
                        executorService,
                        cancellationTokenSource,
                        properties.timeout(),
                        files.reportFile(),
                        files.initScript(),
                        output,
                        executionLabel,
                        gradleVersion,
                        javaFeatureVersion);
            } finally {
                executorService.shutdownNow();
            }
        } catch (IOException | GradleConnectionException exception) {
            String message = GradleExecutionSupport.redact(exception.getMessage());
            GradleFailureClassifier.ClassifiedGradleFailure classifiedFailure =
                    GradleExecutionSupport.classifyFailure(
                            message,
                            gradleVersion,
                            javaFeatureVersion,
                            gradleJavaCompatibilityService,
                            gradleFailureClassifier);
            GradleExecutionFailureType failureType = classifiedFailure.failureType();
            logFailure(failureType, message, gradleVersion, javaFeatureVersion, exception);
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
                    conciseErrorMessage(
                            failureType,
                            gradleVersion,
                            javaFeatureVersion,
                            message,
                            classifiedFailure.pluginResolutionFailure()),
                    classifiedFailure.pluginResolutionFailure());
        } finally {
            if (connector != null) {
                // Cancellation is best effort. Disconnect after closing the ProjectConnection so
                // the connector can release any remaining Tooling API resources before HOME
                // cleanup.
                try {
                    connector.disconnect();
                } catch (RuntimeException exception) {
                    LOGGER.debug("Failed to disconnect Gradle Tooling API connector", exception);
                }
            }
            GradleExecutionSupport.cleanupExecutionHome(files);
        }
    }

    Map<String, String> launcherEnvironment(
            Map<String, String> currentEnvironment,
            GradleExecutionSupport.ExecutionFiles files,
            AnalyzerProperties.GradleProperties properties) {
        Map<String, String> environment =
                new LinkedHashMap<>(
                        GradleExecutionSupport.safeEnvironment(
                                currentEnvironment,
                                files.gradleUserHome(),
                                files.executionHome(),
                                properties));
        if (properties.javaHome() != null) {
            environment.put("JAVA_HOME", properties.javaHome().toString());
        }
        return Map.copyOf(environment);
    }

    private void configureConnector(
            GradleConnector connector,
            GradleExecutionMode executionMode,
            Path wrapperScript,
            String gradleVersion) {
        if (executionMode == GradleExecutionMode.WRAPPER && wrapperScript != null) {
            connector.useBuildDistribution();
            return;
        }
        connector.useGradleVersion(gradleVersion);
    }

    private List<String> arguments(
            GradleExecutionSupport.ExecutionFiles files,
            AnalyzerProperties.GradleProperties properties) {
        List<String> arguments = new ArrayList<>();
        arguments.add("--console=plain");
        arguments.addAll(GradleExecutionSupport.joinJvmArgs(properties));
        arguments.add("--init-script");
        arguments.add(files.initScript().toString());
        arguments.add("-PsbaReportFile=" + files.reportFile());
        arguments.add("-PsbaMaxResolvedDependencies=" + properties.maxResolvedDependencies());
        if (!properties.allowNetwork()) {
            arguments.add("--offline");
        }
        return List.copyOf(arguments);
    }

    private GradleExecutionResult awaitResult(
            Future<?> future,
            ExecutorService executorService,
            CancellationTokenSource cancellationTokenSource,
            Duration timeout,
            Path reportFile,
            Path initScript,
            CappedOutputStream output,
            String executionLabel,
            String gradleVersion,
            int javaFeatureVersion) {
        try {
            future.get(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
            LOGGER.info("Tooling API Gradle diagnostic task completed successfully");
            return new GradleExecutionResult(
                    true,
                    false,
                    0,
                    reportFile,
                    initScript,
                    GradleExecutionSupport.redact(output.asString()),
                    executionLabel,
                    gradleVersion,
                    String.valueOf(javaFeatureVersion),
                    GradleExecutionFailureType.NONE,
                    null,
                    null);
        } catch (TimeoutException exception) {
            cancellationTokenSource.cancel();
            future.cancel(true);
            LOGGER.warn("Tooling API Gradle diagnostic task timed out after {}", timeout);
            return new GradleExecutionResult(
                    false,
                    true,
                    -1,
                    reportFile,
                    initScript,
                    GradleExecutionSupport.redact(output.asString()),
                    executionLabel,
                    gradleVersion,
                    String.valueOf(javaFeatureVersion),
                    GradleExecutionFailureType.TIMED_OUT,
                    "Gradle diagnostic task timed out.",
                    null);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            cancellationTokenSource.cancel();
            LOGGER.warn("Tooling API Gradle diagnostic task interrupted");
            LOGGER.debug("Tooling API Gradle diagnostic task interrupted", exception);
            return new GradleExecutionResult(
                    false,
                    false,
                    -1,
                    reportFile,
                    initScript,
                    GradleExecutionSupport.redact(output.asString()),
                    executionLabel,
                    gradleVersion,
                    String.valueOf(javaFeatureVersion),
                    GradleExecutionFailureType.UNKNOWN,
                    "Gradle diagnostic task was interrupted.",
                    null);
        } catch (ExecutionException exception) {
            String outputMessage = GradleExecutionSupport.redact(output.asString());
            String exceptionMessage =
                    exception.getCause() == null
                            ? exception.getMessage()
                            : exception.getCause().getMessage();
            String combinedMessage =
                    (outputMessage == null || outputMessage.isBlank())
                            ? GradleExecutionSupport.redact(exceptionMessage)
                            : outputMessage;
            GradleFailureClassifier.ClassifiedGradleFailure classifiedFailure =
                    GradleExecutionSupport.classifyFailure(
                            combinedMessage,
                            gradleVersion,
                            javaFeatureVersion,
                            gradleJavaCompatibilityService,
                            gradleFailureClassifier);
            GradleExecutionFailureType failureType = classifiedFailure.failureType();
            logFailure(failureType, combinedMessage, gradleVersion, javaFeatureVersion, exception);
            return new GradleExecutionResult(
                    false,
                    false,
                    -1,
                    reportFile,
                    initScript,
                    combinedMessage,
                    executionLabel,
                    gradleVersion,
                    String.valueOf(javaFeatureVersion),
                    failureType,
                    conciseErrorMessage(
                            failureType,
                            gradleVersion,
                            javaFeatureVersion,
                            combinedMessage,
                            classifiedFailure.pluginResolutionFailure()),
                    classifiedFailure.pluginResolutionFailure());
        } finally {
            executorService.shutdownNow();
        }
    }

    private String conciseErrorMessage(
            GradleExecutionFailureType failureType,
            String gradleVersion,
            int javaFeatureVersion,
            String message,
            com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradlePluginResolutionFailure
                    pluginResolutionFailure) {
        return switch (failureType) {
            case INCOMPATIBLE_JAVA_AND_GRADLE ->
                    "Diagnostic Gradle %s cannot run on Java %d. Use Gradle 9.1.0+ or configure analyzer.gradle.java-home."
                            .formatted(gradleVersion, javaFeatureVersion);
            case TIMED_OUT -> "Gradle diagnostic task timed out.";
            case INIT_SCRIPT_COMPILATION_FAILED -> helperScopeMessage(message);
            case SETTINGS_PLUGIN_RESOLUTION_FAILED ->
                    pluginResolutionFailure == null
                            ? "Settings plugin could not be resolved before the analyzer diagnostic"
                                    + " task could run."
                            : "Settings plugin could not be resolved: %s:%s"
                                    .formatted(
                                            pluginResolutionFailure.pluginId(),
                                            pluginResolutionFailure.version());
            case PLUGIN_RESOLUTION_FAILED ->
                    "Build plugin could not be resolved before the analyzer diagnostic task could"
                            + " run.";
            case BUILD_LOGIC_FAILED -> "Gradle diagnostic task failed during build configuration.";
            default ->
                    message == null || message.isBlank()
                            ? "Gradle diagnostic task failed."
                            : message;
        };
    }

    private void logFailure(
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
            LOGGER.debug("Tooling API Gradle diagnostic task failed", exception);
            return;
        }
        if (failureType == GradleExecutionFailureType.SETTINGS_PLUGIN_RESOLUTION_FAILED
                || failureType == GradleExecutionFailureType.PLUGIN_RESOLUTION_FAILED) {
            LOGGER.warn(
                    "Tooling API Gradle diagnostic task failed during plugin resolution: {}",
                    message);
            LOGGER.debug("Tooling API Gradle diagnostic task failed", exception);
            return;
        }
        if (failureType == GradleExecutionFailureType.INIT_SCRIPT_COMPILATION_FAILED) {
            LOGGER.warn(
                    "Tooling API Gradle diagnostic task failed because the analyzer generated an"
                            + " invalid init script: {}",
                    message);
            LOGGER.debug("Tooling API Gradle diagnostic task failed", exception);
            return;
        }
        LOGGER.warn("Tooling API Gradle diagnostic task failed: {}", message);
        LOGGER.debug("Tooling API Gradle diagnostic task failed", exception);
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

    private ThreadFactory daemonFactory() {
        return runnable -> {
            Thread thread = new Thread(runnable, "gradle-tooling-api-executor");
            thread.setDaemon(true);
            return thread;
        };
    }

    private String workspaceId(Path repositoryRoot) {
        Path parent = repositoryRoot == null ? null : repositoryRoot.getParent();
        return fileName(parent);
    }

    private String fileName(Path path) {
        return path == null || path.getFileName() == null ? null : path.getFileName().toString();
    }

    private static final class CappedOutputStream extends OutputStream {
        private final ByteArrayOutputStream delegate = new ByteArrayOutputStream();
        private final int maxBytes;
        private int written;

        private CappedOutputStream(int maxBytes) {
            this.maxBytes = maxBytes;
        }

        @Override
        public synchronized void write(int value) {
            if (written >= maxBytes) {
                return;
            }
            delegate.write(value);
            written++;
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
}

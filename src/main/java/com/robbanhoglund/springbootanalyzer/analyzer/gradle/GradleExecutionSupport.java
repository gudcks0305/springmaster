package com.robbanhoglund.springbootanalyzer.analyzer.gradle;

import com.robbanhoglund.springbootanalyzer.config.AnalyzerProperties;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class GradleExecutionSupport {

    private static final Logger LOGGER = LoggerFactory.getLogger(GradleExecutionSupport.class);
    private static final List<String> SAFE_ENV_KEYS =
            List.of(
                    "PATH",
                    "JAVA_HOME",
                    "SYSTEMROOT",
                    "TMP",
                    "TEMP",
                    "COMSPEC",
                    "PATHEXT",
                    "OS",
                    "PROCESSOR_ARCHITECTURE");
    private static final List<Pattern> UNSAFE_WINDOWS_URI_PATTERNS =
            List.of(
                    Pattern.compile("uri\\(['\"]?[A-Za-z]:\\\\"),
                    Pattern.compile("url\\s*=\\s*uri\\(['\"]?[A-Za-z]:\\\\"),
                    Pattern.compile("file\\(['\"]?[A-Za-z]:\\\\"),
                    Pattern.compile("uri\\(\"file:[^\"]*\\\\"),
                    Pattern.compile("uri\\('file:[^']*\\\\"));

    private GradleExecutionSupport() {}

    public static ExecutionFiles prepareExecutionFiles(
            Path repositoryRoot, AnalyzerProperties.GradleProperties properties)
            throws IOException {
        return prepareExecutionFiles(repositoryRoot, properties, null);
    }

    public static ExecutionFiles prepareExecutionFiles(
            Path repositoryRoot,
            AnalyzerProperties.GradleProperties properties,
            Path localPluginRepository)
            throws IOException {
        GradleScriptValueRenderer renderer = new GradleScriptValueRenderer();
        Path tempDir = Files.createTempDirectory(repositoryRoot, "sba-gradle-");
        Path reportFile = tempDir.resolve("sba-gradle-model.json");
        Path initScript = tempDir.resolve("spring-boot-analyzer.init.gradle");
        Path executionHome = Files.createDirectory(tempDir.resolve("home"));
        String script = initScriptContent(properties, localPluginRepository, renderer);
        validateInitScript(script);
        Files.writeString(initScript, script, StandardCharsets.UTF_8);
        Path gradleUserHome = properties.distributionCache();
        Files.createDirectories(gradleUserHome);
        writeIsolatedGradleProperties(gradleUserHome, properties);
        return new ExecutionFiles(tempDir, reportFile, initScript, gradleUserHome, executionHome);
    }

    public static Map<String, String> safeEnvironment(
            Map<String, String> currentEnvironment,
            Path gradleUserHome,
            Path executionHome,
            AnalyzerProperties.GradleProperties properties) {
        Map<String, String> environment = new LinkedHashMap<>();
        for (String key : SAFE_ENV_KEYS) {
            if (currentEnvironment.containsKey(key)) {
                environment.put(key, currentEnvironment.get(key));
            }
        }
        for (String key : properties.passThroughEnvironment()) {
            if (currentEnvironment.containsKey(key)) {
                environment.put(key, currentEnvironment.get(key));
            }
        }
        environment.put("GRADLE_USER_HOME", gradleUserHome.toString());
        // Never expose the analyzer account's real home directory to repository-controlled
        // Gradle logic. USERPROFILE is set as well so the same isolation applies on Windows.
        environment.put("HOME", executionHome.toString());
        environment.put("USERPROFILE", executionHome.toString());
        return environment;
    }

    public static void cleanupExecutionHome(ExecutionFiles files) {
        if (files == null || files.executionHome() == null) {
            return;
        }
        Path executionHome = files.executionHome().toAbsolutePath().normalize();
        Path tempDir = files.tempDir().toAbsolutePath().normalize();
        if (!executionHome.startsWith(tempDir) || executionHome.equals(tempDir)) {
            LOGGER.warn("Refusing to clean Gradle execution home outside its exact temp directory");
            return;
        }
        try {
            Files.walkFileTree(
                    executionHome,
                    new java.nio.file.SimpleFileVisitor<>() {
                        @Override
                        public java.nio.file.FileVisitResult visitFile(
                                Path file, java.nio.file.attribute.BasicFileAttributes attributes)
                                throws IOException {
                            Files.deleteIfExists(file);
                            return java.nio.file.FileVisitResult.CONTINUE;
                        }

                        @Override
                        public java.nio.file.FileVisitResult postVisitDirectory(
                                Path directory, IOException exception) throws IOException {
                            if (exception != null) {
                                throw exception;
                            }
                            Files.deleteIfExists(directory);
                            return java.nio.file.FileVisitResult.CONTINUE;
                        }
                    });
        } catch (IOException exception) {
            LOGGER.debug(
                    "Failed to clean isolated Gradle execution home {}", executionHome, exception);
        }
    }

    public static String readBounded(InputStream inputStream, int maxBytes) throws IOException {
        try (inputStream;
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int total = 0;
            int read;
            while ((read = inputStream.read(buffer)) != -1 && total < maxBytes) {
                int allowed = Math.min(read, maxBytes - total);
                outputStream.write(buffer, 0, allowed);
                total += allowed;
            }
            return outputStream.toString(StandardCharsets.UTF_8);
        }
    }

    public static String redact(String value) {
        if (value == null) {
            return null;
        }
        return value.replaceAll(
                        "(?i)(password|token|secret|credential)\\s*[=:]\\s*[^\\s]+",
                        "$1=[redacted]")
                .replaceAll(
                        "(?i)(proxy(password)?|https?\\.proxy(password)?|proxyUser|proxyPassword)\\s*[=:]\\s*[^\\s]+",
                        "$1=[redacted]")
                .replaceAll("(?i)(https?://)([^/@\\s]+)@", "$1[redacted]@");
    }

    public static String executionModeLabel(
            String runner,
            com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleExecutionMode
                    executionMode) {
        return executionMode.name();
    }

    public static String extractWrapperGradleVersion(Path repositoryRoot) {
        Path wrapperProperties =
                repositoryRoot
                        .resolve("gradle")
                        .resolve("wrapper")
                        .resolve("gradle-wrapper.properties");
        if (Files.notExists(wrapperProperties)) {
            return null;
        }
        Properties properties = new Properties();
        try (var inputStream = Files.newInputStream(wrapperProperties)) {
            properties.load(inputStream);
            String distributionUrl = properties.getProperty("distributionUrl");
            if (distributionUrl == null) {
                return null;
            }
            return extractGradleVersionFromDistributionUrl(distributionUrl);
        } catch (IOException exception) {
            return null;
        }
    }

    public static String extractGradleVersionFromDistributionUrl(String distributionUrl) {
        if (distributionUrl == null || distributionUrl.isBlank()) {
            return null;
        }
        java.util.regex.Matcher matcher =
                java.util.regex.Pattern.compile("gradle-([0-9][^-/]*)-").matcher(distributionUrl);
        return matcher.find() ? matcher.group(1) : null;
    }

    public static GradleFailureClassifier.ClassifiedGradleFailure classifyFailure(
            String message,
            String gradleVersion,
            int javaFeatureVersion,
            GradleJavaCompatibilityService compatibilityService,
            GradleFailureClassifier failureClassifier) {
        return failureClassifier.classify(
                message, gradleVersion, javaFeatureVersion, compatibilityService);
    }

    public static List<String> proxySystemProperties(
            AnalyzerProperties.GradleProperties properties) {
        AnalyzerProperties.ProxyProperties proxy = properties.proxy();
        if (proxy == null
                || !proxy.enabled()
                || proxy.host() == null
                || proxy.host().isBlank()
                || proxy.port() == null) {
            return List.of();
        }
        List<String> arguments = new ArrayList<>();
        arguments.add("-Dhttp.proxyHost=" + proxy.host());
        arguments.add("-Dhttp.proxyPort=" + proxy.port());
        arguments.add("-Dhttps.proxyHost=" + proxy.host());
        arguments.add("-Dhttps.proxyPort=" + proxy.port());
        if (proxy.username() != null && !proxy.username().isBlank()) {
            arguments.add("-Dhttp.proxyUser=" + proxy.username());
            arguments.add("-Dhttps.proxyUser=" + proxy.username());
        }
        if (proxy.password() != null && !proxy.password().isBlank()) {
            arguments.add("-Dhttp.proxyPassword=" + proxy.password());
            arguments.add("-Dhttps.proxyPassword=" + proxy.password());
        }
        return List.copyOf(arguments);
    }

    public static List<String> sslSystemProperties(AnalyzerProperties.GradleProperties properties) {
        AnalyzerProperties.SslProperties ssl = properties.ssl();
        if (ssl == null || ssl.trustStore() == null) {
            return List.of();
        }
        List<String> arguments = new ArrayList<>();
        arguments.add("-Djavax.net.ssl.trustStore=" + ssl.trustStore());
        if (ssl.trustStorePassword() != null && !ssl.trustStorePassword().isBlank()) {
            arguments.add("-Djavax.net.ssl.trustStorePassword=" + ssl.trustStorePassword());
        }
        return List.copyOf(arguments);
    }

    public static Map<String, String> hostGradleProxyProperties() {
        Path gradlePropertiesPath =
                Path.of(System.getProperty("user.home"), ".gradle", "gradle.properties");
        if (Files.notExists(gradlePropertiesPath)) {
            return Map.of();
        }
        Properties properties = new Properties();
        try (InputStream inputStream = Files.newInputStream(gradlePropertiesPath)) {
            properties.load(inputStream);
        } catch (IOException exception) {
            return Map.of();
        }
        List<String> allowedKeys =
                List.of(
                        "systemProp.http.proxyHost",
                        "systemProp.http.proxyPort",
                        "systemProp.http.proxyUser",
                        "systemProp.http.proxyPassword",
                        "systemProp.https.proxyHost",
                        "systemProp.https.proxyPort",
                        "systemProp.https.proxyUser",
                        "systemProp.https.proxyPassword",
                        "systemProp.http.nonProxyHosts",
                        "systemProp.https.nonProxyHosts");
        Map<String, String> collected = new LinkedHashMap<>();
        for (String key : allowedKeys) {
            String value = properties.getProperty(key);
            if (value != null && !value.isBlank()) {
                collected.put(key, value);
            }
        }
        String jvmArgs = properties.getProperty("org.gradle.jvmargs");
        if (jvmArgs != null && jvmArgs.contains("proxy")) {
            collected.put("org.gradle.jvmargs", extractProxyJvmArgs(jvmArgs));
        }
        return Map.copyOf(collected);
    }

    public static String pluginMarkerUrl(String repositoryUrl, String pluginId, String version) {
        String base = repositoryUrl.replaceAll("/+$", "");
        String markerPath =
                pluginId.replace('.', '/')
                        + "/"
                        + pluginId
                        + ".gradle.plugin/"
                        + version
                        + "/"
                        + pluginId
                        + ".gradle.plugin-"
                        + version
                        + ".pom";
        return base + "/" + markerPath;
    }

    public static String externalCommandHint(
            Path initScript, Path reportFile, AnalyzerProperties.GradleProperties properties) {
        String executable =
                properties.executable() != null ? properties.executable().toString() : "gradle";
        String proxyArgs = String.join(" ", joinJvmArgs(properties));
        return ("%s --console=plain --stacktrace %s --init-script %s -PsbaReportFile=%s"
                        + " -PsbaMaxResolvedDependencies=%d springBootAnalyzerModel")
                .formatted(
                        executable,
                        proxyArgs,
                        initScript,
                        reportFile,
                        properties.maxResolvedDependencies())
                .replaceAll("\\s+", " ")
                .trim();
    }

    public static List<String> joinJvmArgs(AnalyzerProperties.GradleProperties properties) {
        List<String> arguments = new ArrayList<>();
        arguments.addAll(proxySystemProperties(properties));
        arguments.addAll(sslSystemProperties(properties));
        return List.copyOf(arguments);
    }

    static String initScriptContent(
            AnalyzerProperties.GradleProperties properties,
            Path localPluginRepository,
            GradleScriptValueRenderer renderer) {
        String pluginRepositoriesBlock =
                pluginRepositoriesBlock(properties, localPluginRepository, renderer);
        return
"""
import groovy.json.JsonOutput
import org.gradle.api.artifacts.result.ResolvedDependencyResult
import org.gradle.api.artifacts.result.UnresolvedDependencyResult
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.ExternalDependency
import org.gradle.api.artifacts.ModuleDependency
import org.gradle.api.artifacts.repositories.MavenArtifactRepository
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.tasks.SourceSetContainer
import groovy.lang.Closure

def reportFilePath = gradle.startParameter.projectProperties['sbaReportFile']
def maxResolvedDependencies = (gradle.startParameter.projectProperties['sbaMaxResolvedDependencies'] ?: '10000') as int
final Closure<String> sbaSanitizeValue = { Object value ->
    if (value == null) {
        return null
    }
    String text = String.valueOf(value)
    text
            .replaceAll(/(?i)(password|token|secret|credential)=([^&\\s]+)/, '$1=[redacted]')
            .replaceAll(/(?i)(https?:\\/\\/)([^\\/@\\s]+)@/, '$1[redacted]@')
}
final Closure<String> sbaNormalizePath = { Object value ->
    if (value == null) {
        return null
    }
    return String.valueOf(value).replace('\\\\', '/')
}
final Closure<String> sbaRelativePath = { project, Object value ->
    if (value == null) {
        return null
    }
    try {
        def basePath = project.projectDir.toPath().toAbsolutePath().normalize()
        def targetPath = (value instanceof File ? value.toPath() : new File(String.valueOf(value)).toPath())
                .toAbsolutePath()
                .normalize()
        if (targetPath.startsWith(basePath)) {
            def relativePath = sbaNormalizePath.call(basePath.relativize(targetPath).toString())
            return relativePath == null || relativePath.isBlank() ? '.' : relativePath
        }
    } catch (Throwable ignored) {
    }
    return sbaNormalizePath.call(String.valueOf(value))
}
final Closure<String> sbaSelectionReason = { Object selectionReason ->
    try {
        def descriptions = selectionReason?.descriptions
        if (descriptions == null) {
            return null
        }
        return descriptions
                .collect { it.description }
                .findAll { it != null && !it.toString().isBlank() }
                .join(', ')
    } catch (Throwable ignored) {
        return null
    }
}
final Closure<String> sbaModuleKey = { Object group, Object artifact, Object version ->
    return "${group ?: ''}:${artifact ?: ''}:${version ?: ''}"
}
final Closure<String> sbaGroupArtifactKey = { Object group, Object artifact ->
    return "${group ?: ''}:${artifact ?: ''}"
}
final Closure<Boolean> sbaIsModuleComponentId = { Object id ->
    if (id == null) {
        return false
    }
    if (id instanceof ModuleComponentIdentifier) {
        return true
    }
    return id.hasProperty('group')
            && id.hasProperty('module')
            && id.hasProperty('version')
            && id.group != null
            && id.module != null
            && id.version != null
}
final Closure<String> sbaModuleKeyIfPresent = { Object id ->
    return sbaIsModuleComponentId.call(id)
            ? sbaModuleKey.call(id.group, id.module, id.version)
            : null
}
final Closure<String> sbaGroupArtifactKeyIfPresent = { Object id ->
    return sbaIsModuleComponentId.call(id)
            ? sbaGroupArtifactKey.call(id.group, id.module)
            : null
}
final Closure<String> sbaRequestedKeyIfPresent = { Object requested ->
    if (requested == null) {
        return null
    }
    def group = requested.hasProperty('group') ? requested.group : null
    def module = requested.hasProperty('module')
            ? requested.module
            : (requested.hasProperty('name') ? requested.name : null)
    return (group != null && module != null)
            ? sbaGroupArtifactKey.call(group, module)
            : null
}
final Closure<Boolean> sbaHasExternalRequestedDependencies = { configuration ->
    try {
        return configuration.allDependencies.any { dependency ->
            dependency instanceof ExternalDependency
                    || (dependency.group != null && dependency.name != null)
        }
    } catch (Throwable ignored) {
        return false
    }
}
final Closure<Void> sbaAddResolvedModule = { String projectPath, String configurationName, Object id, boolean direct, String selectedReason, List bucket, java.util.concurrent.atomic.AtomicInteger remaining ->
    if (id == null || remaining.get() <= 0 || !sbaIsModuleComponentId.call(id)) {
        return null
    }
    def existing = bucket.find { entry ->
        entry.projectPath == projectPath
                && entry.configuration == configurationName
                && entry.group == String.valueOf(id.group)
                && entry.artifact == String.valueOf(id.module)
                && entry.version == String.valueOf(id.version)
    }
    if (existing != null) {
        existing.direct = ((existing.direct == true) || direct)
        if ((existing.selectedReason == null || existing.selectedReason.toString().isBlank())
                && selectedReason != null
                && !selectedReason.isBlank()) {
            existing.selectedReason = selectedReason
        }
        return null
    }
    remaining.decrementAndGet()
    bucket << [
        projectPath: projectPath,
        configuration: configurationName,
        group: String.valueOf(id.group),
        artifact: String.valueOf(id.module),
        version: String.valueOf(id.version),
        direct: direct,
        selectedReason: selectedReason
    ]
    return null
}
final Closure<String> sbaUnresolvedMessage = { String projectPath, String configurationName, Object requested, Object from, Object failure ->
    def pieces = []
    if (requested != null) {
        pieces << "requested=" + sbaSanitizeValue.call(requested.displayName ?: requested.toString())
    }
    if (from != null) {
        pieces << "from=" + sbaSanitizeValue.call(from.displayName ?: from.toString())
    }
    if (failure != null) {
        pieces << "failure=" + sbaSanitizeValue.call(failure.message ?: failure.toString())
    }
    return pieces.isEmpty() ? null : pieces.join(', ')
}
final Closure<String> sbaFailureDetails = { Object throwable ->
    if (throwable == null) {
        return null
    }
    def pieces = []
    def current = throwable
    int depth = 0
    while (current != null && depth < 5) {
        def text = sbaSanitizeValue.call(current.message ?: current.toString())
        if (text != null && !text.isBlank() && !pieces.contains(text)) {
            pieces << text
        }
        current = current.cause
        depth++
    }
    return pieces.join(' | ')
}

%s

gradle.projectsLoaded {
    gradle.rootProject {
        tasks.register('springBootAnalyzerModel') {
            group = 'verification'
            description = 'Writes Spring Boot Analyzer Gradle model JSON.'
            doLast {
                def resolvedLimit = new java.util.concurrent.atomic.AtomicInteger(maxResolvedDependencies)
                def report = [
                    gradleVersion: gradle.gradleVersion,
                    projects: [],
                    plugins: [],
                    repositories: [],
                    configurations: [],
                    declaredDependencies: [],
                    resolvedDependencies: [],
                    resolutionResults: [],
                    dependencyConflicts: [],
                    sourceSets: [],
                    tasks: [],
                    javaToolchains: []
                ]

                allprojects.each { project ->
                    report.projects << [
                        path: project.path,
                        name: project.name,
                        projectDir: sbaRelativePath.call(rootProject, project.projectDir)
                    ]

                    project.plugins.each { plugin ->
                        report.plugins << [
                            projectPath: project.path,
                            pluginId: plugin.class.name,
                            implementationClass: plugin.class.name
                        ]
                    }

                    project.repositories.each { repo ->
                        def url = null
                        if (repo instanceof MavenArtifactRepository) {
                            url = repo.url?.toString()
                        } else if (repo.hasProperty('url')) {
                            url = repo.url?.toString()
                        }
                        report.repositories << [
                            projectPath: project.path,
                            name: repo.name,
                            type: repo.class.simpleName,
                            url: sbaSanitizeValue.call(url)
                        ]
                    }

                    project.configurations.each { configuration ->
                        report.configurations << [
                            projectPath: project.path,
                            name: configuration.name,
                            resolvable: configuration.canBeResolved,
                            consumable: configuration.canBeConsumed,
                            dependencyCount: configuration.allDependencies.size(),
                            declaredDependencyCount: configuration.dependencies.size(),
                            allDependencyCount: configuration.allDependencies.size(),
                            extendsFrom: configuration.extendsFrom.collect { it.name }
                        ]

                        configuration.dependencies.each { dependency ->
                            report.declaredDependencies << [
                                projectPath: project.path,
                                configuration: configuration.name,
                                notation: dependency.group && dependency.name ? "${dependency.group}:${dependency.name}:${dependency.version ?: ''}".replaceAll(':$','') : dependency.toString(),
                                group: dependency.group,
                                artifact: dependency.name,
                                version: dependency.version
                            ]
                        }
                    }

                    if (project.extensions.findByType(JavaPluginExtension) != null) {
                        def sourceSets = project.extensions.findByName('sourceSets')
                        if (sourceSets instanceof SourceSetContainer) {
                            sourceSets.each { sourceSet ->
                                report.sourceSets << [
                                    projectPath: project.path,
                                    name: sourceSet.name,
                                    javaDirs: sourceSet.allJava.srcDirs.collect { sbaRelativePath.call(project, it) },
                                    resourceDirs: sourceSet.resources.srcDirs.collect { sbaRelativePath.call(project, it) }
                                ]
                            }
                        }
                        def toolchain = project.extensions.getByType(JavaPluginExtension).toolchain
                        report.javaToolchains << [
                            projectPath: project.path,
                            languageVersion: toolchain.languageVersion.present ? toolchain.languageVersion.get().toString() : null,
                            vendor: toolchain.vendor.present ? toolchain.vendor.get().toString() : null,
                            implementation: toolchain.implementation.present ? toolchain.implementation.get().toString() : null
                        ]
                    }

                    project.tasks.each { task ->
                        report.tasks << [
                            projectPath: project.path,
                            name: task.name,
                            group: task.group,
                            description: task.description
                        ]
                    }

                    ['compileClasspath', 'runtimeClasspath', 'testCompileClasspath', 'testRuntimeClasspath', 'annotationProcessor', 'testAnnotationProcessor', 'productionRuntimeClasspath', 'developmentOnly']
                            .findAll { project.configurations.findByName(it) != null }
                            .each { configurationName ->
                                def configuration = project.configurations.getByName(configurationName)
                                if (!configuration.canBeResolved || resolvedLimit.get() <= 0) {
                                    return
                                }
                                def requestedVersions = [:].withDefault { [] }
                                def declaredKeys = [] as Set
                                configuration.allDependencies.each { dep ->
                                    if (dep.group && dep.name) {
                                        declaredKeys << sbaGroupArtifactKey.call(dep.group, dep.name)
                                    }
                                    if (dep.group && dep.name && dep.version) {
                                        requestedVersions["${dep.group}:${dep.name}"] << dep.version
                                    }
                                }
                                def configurationResolvedDependencies = []
                                boolean fallbackUsed = false
                                boolean dependencyBearing = sbaHasExternalRequestedDependencies.call(configuration)
                                def unresolvedMessages = [] as Set
                                try {
                                    def resolutionResult = configuration.incoming.resolutionResult
                                    def directKeys = [] as Set
                                    def componentTypes = [] as Set
                                    resolutionResult.root.dependencies.each { dep ->
                                        if (dep instanceof ResolvedDependencyResult) {
                                            def selectedId = dep.selected?.id
                                            componentTypes << selectedId?.class?.name
                                            def requestedKey = sbaRequestedKeyIfPresent.call(dep.requested)
                                            def selectedGaKey = sbaGroupArtifactKeyIfPresent.call(selectedId)
                                            if (sbaIsModuleComponentId.call(selectedId)
                                                    && ((requestedKey != null && declaredKeys.contains(requestedKey))
                                                    || (selectedGaKey != null && declaredKeys.contains(selectedGaKey)))) {
                                                directKeys << sbaModuleKey.call(selectedId.group, selectedId.module, selectedId.version)
                                            }
                                        } else if (dep instanceof UnresolvedDependencyResult) {
                                            unresolvedMessages << sbaUnresolvedMessage.call(
                                                    project.path,
                                                    configurationName,
                                                    dep.requested,
                                                    dep.from?.id,
                                                    dep.failure
                                            )
                                        }
                                    }
                                    resolutionResult.allDependencies.each { dep ->
                                        if (dep instanceof ResolvedDependencyResult) {
                                            def selectedId = dep.selected?.id
                                            componentTypes << selectedId?.class?.name
                                            sbaAddResolvedModule.call(
                                                    project.path,
                                                    configurationName,
                                                    selectedId,
                                                    directKeys.contains(sbaModuleKeyIfPresent.call(selectedId)),
                                                    sbaSelectionReason.call(dep.selected?.selectionReason),
                                                    configurationResolvedDependencies,
                                                    resolvedLimit
                                            )
                                        } else if (dep instanceof UnresolvedDependencyResult) {
                                            unresolvedMessages << sbaUnresolvedMessage.call(
                                                    project.path,
                                                    configurationName,
                                                    dep.requested,
                                                    dep.from?.id,
                                                    dep.failure
                                            )
                                        }
                                    }
                                    def seen = [] as Set
                                    resolutionResult.allComponents.each { component ->
                                        def id = component.id
                                        componentTypes << id?.class?.name
                                        if (resolvedLimit.get() <= 0) {
                                            return
                                        }
                                        if (sbaIsModuleComponentId.call(id)) {
                                            def key = sbaModuleKey.call(id.group, id.module, id.version)
                                            if (seen.add(key)) {
                                                sbaAddResolvedModule.call(
                                                        project.path,
                                                        configurationName,
                                                        id,
                                                        directKeys.contains(key),
                                                        sbaSelectionReason.call(component.selectionReason),
                                                        configurationResolvedDependencies,
                                                        resolvedLimit
                                                )
                                            }
                                        }
                                    }
                                    if (configurationResolvedDependencies.isEmpty() && dependencyBearing) {
                                        fallbackUsed = true
                                        try {
                                            configuration.resolve()
                                        } catch (Throwable forceResolveFailure) {
                                            unresolvedMessages << ("resolve(): " + sbaSanitizeValue.call(forceResolveFailure.message ?: forceResolveFailure.class.name))
                                        }
                                        def forcedResult = configuration.incoming.resolutionResult
                                        forcedResult.allDependencies.each { dep ->
                                            if (dep instanceof ResolvedDependencyResult) {
                                                def selectedId = dep.selected?.id
                                                componentTypes << selectedId?.class?.name
                                                sbaAddResolvedModule.call(
                                                        project.path,
                                                        configurationName,
                                                        selectedId,
                                                        directKeys.contains(sbaModuleKey.call(selectedId?.group, selectedId?.module, selectedId?.version)),
                                                        sbaSelectionReason.call(dep.selected?.selectionReason),
                                                        configurationResolvedDependencies,
                                                        resolvedLimit
                                                )
                                            } else if (dep instanceof UnresolvedDependencyResult) {
                                                unresolvedMessages << sbaUnresolvedMessage.call(
                                                        project.path,
                                                        configurationName,
                                                        dep.requested,
                                                        dep.from?.id,
                                                        dep.failure
                                                )
                                            }
                                        }
                                        forcedResult.allComponents.each { component ->
                                            def forcedId = component.id
                                            componentTypes << forcedId?.class?.name
                                            sbaAddResolvedModule.call(
                                                    project.path,
                                                    configurationName,
                                                    forcedId,
                                                    directKeys.contains(sbaModuleKeyIfPresent.call(forcedId)),
                                                    sbaSelectionReason.call(component.selectionReason),
                                                    configurationResolvedDependencies,
                                                    resolvedLimit
                                            )
                                        }
                                    }
                                    if (configurationResolvedDependencies.isEmpty() && dependencyBearing) {
                                        def artifacts = configuration.incoming.artifactView {
                                            lenient(true)
                                        }.artifacts
                                        artifacts.artifacts.each { artifact ->
                                            def artifactId = artifact.id?.componentIdentifier ?: artifact.variant?.owner
                                            componentTypes << artifactId?.class?.name
                                            sbaAddResolvedModule.call(
                                                    project.path,
                                                    configurationName,
                                                    artifactId,
                                                    false,
                                                    'artifactView',
                                                    configurationResolvedDependencies,
                                                    resolvedLimit
                                            )
                                        }
                                        try {
                                            artifacts.failures.each { failure ->
                                            unresolvedMessages << sbaFailureDetails.call(failure)
                                        }
                                    } catch (Throwable ignoredArtifactFailure) {
                                    }
                                    }
                                    if (configurationResolvedDependencies.isEmpty() && dependencyBearing) {
                                        fallbackUsed = true
                                        try {
                                            configuration.resolvedConfiguration.lenientConfiguration.allModuleDependencies.each { dep ->
                                                def lenientKey = sbaModuleKey.call(dep.moduleGroup, dep.moduleName, dep.moduleVersion)
                                                sbaAddResolvedModule.call(
                                                        project.path,
                                                        configurationName,
                                                        [
                                                            group: dep.moduleGroup,
                                                            module: dep.moduleName,
                                                            version: dep.moduleVersion
                                                        ],
                                                        directKeys.contains(lenientKey),
                                                        'lenientConfiguration',
                                                        configurationResolvedDependencies,
                                                        resolvedLimit
                                                )
                                            }
                                        } catch (Throwable fallbackFailure) {
                                            unresolvedMessages << ("fallback: " + sbaFailureDetails.call(fallbackFailure))
                                        }
                                    }
                                    requestedVersions.each { ga, versions ->
                                        def unique = versions.findAll { it != null }.unique()
                                        if (unique.size() > 1) {
                                            def parts = ga.split(':')
                                            report.dependencyConflicts << [
                                                projectPath: project.path,
                                                configuration: configurationName,
                                                group: parts[0],
                                                artifact: parts[1],
                                                requestedVersions: unique.join(', '),
                                                selectedVersion: null
                                            ]
                                        }
                                    }
                                    int resolvedCount = configurationResolvedDependencies.size()
                                    if (!dependencyBearing) {
                                        if (resolvedCount > 0) {
                                            report.resolvedDependencies.addAll(configurationResolvedDependencies)
                                        }
                                        report.resolutionResults << [
                                            projectPath: project.path,
                                            configuration: configurationName,
                                            attempted: true,
                                            successful: true,
                                            fallbackUsed: fallbackUsed,
                                            errorType: null,
                                            errorMessage: null,
                                            resolvedDependencyCount: resolvedCount
                                        ]
                                    } else if (resolvedCount > 0) {
                                        report.resolvedDependencies.addAll(configurationResolvedDependencies)
                                        report.resolutionResults << [
                                            projectPath: project.path,
                                            configuration: configurationName,
                                            attempted: true,
                                            successful: true,
                                            fallbackUsed: fallbackUsed,
                                            errorType: null,
                                            errorMessage: null,
                                            resolvedDependencyCount: resolvedCount
                                        ]
                                    } else {
                                        report.resolutionResults << [
                                            projectPath: project.path,
                                            configuration: configurationName,
                                            attempted: true,
                                            successful: false,
                                            fallbackUsed: fallbackUsed,
                                            errorType: 'DEPENDENCY_RESOLUTION_FAILED',
                                            errorMessage: unresolvedMessages.findAll { it != null && !it.isBlank() }.join('; ')
                                                    ?: "No resolved external module components were collected. Component IDs seen: " + componentTypes.findAll { it != null }.unique().take(10).join(', '),
                                            resolvedDependencyCount: 0
                                        ]
                                    }
                                } catch (Throwable primaryEx) {
                                    report.resolutionResults << [
                                        projectPath: project.path,
                                        configuration: configurationName,
                                        attempted: true,
                                        successful: false,
                                        fallbackUsed: fallbackUsed,
                                        errorType: primaryEx.class.name,
                                        errorMessage: sbaFailureDetails.call(primaryEx),
                                        resolvedDependencyCount: 0
                                    ]
                                }
                            }
                }

                new File(reportFilePath).text = JsonOutput.prettyPrint(JsonOutput.toJson(report))
            }
        }
    }
}
"""
                .formatted(pluginRepositoriesBlock);
    }

    static void validateInitScript(String script) throws InvalidGradleInitScriptException {
        for (Pattern pattern : UNSAFE_WINDOWS_URI_PATTERNS) {
            if (pattern.matcher(script).find()) {
                throw new InvalidGradleInitScriptException(
                        "Generated Gradle init script contains an unsafe Windows path. This is an"
                                + " analyzer bug.");
            }
        }
    }

    private static String pluginRepositoriesBlock(
            AnalyzerProperties.GradleProperties properties,
            Path localPluginRepository,
            GradleScriptValueRenderer renderer) {
        if (!properties.injectPluginRepositories()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        builder.append("beforeSettings { settings ->\n");
        builder.append("    settings.pluginManagement {\n");
        builder.append("        repositories {\n");
        if (localPluginRepository != null) {
            builder.append("            maven {\n");
            builder.append("                name = ")
                    .append(
                            renderer.groovyStringLiteral(
                                    properties.pluginResolutionBridge() == null
                                            ? "Spring Boot Analyzer plugin cache"
                                            : properties
                                                    .pluginResolutionBridge()
                                                    .localRepositoryName()))
                    .append("\n");
            builder.append("                url = uri(")
                    .append(renderer.groovyFileUriLiteral(localPluginRepository))
                    .append(")\n");
            builder.append("            }\n");
        }
        builder.append("            gradlePluginPortal()\n");
        for (String repositoryUrl : properties.pluginRepositoryUrls()) {
            builder.append("            maven { url = uri(")
                    .append(renderer.groovyStringLiteral(repositoryUrl))
                    .append(") }\n");
        }
        if (properties.addMavenCentralForPluginResolution()) {
            builder.append("            mavenCentral()\n");
        }
        builder.append("        }\n");
        builder.append("    }\n");
        builder.append("}\n");
        if (localPluginRepository != null) {
            builder.append("allprojects {\n");
            builder.append("    repositories {\n");
            builder.append("        maven {\n");
            builder.append("            name = ")
                    .append(
                            renderer.groovyStringLiteral(
                                    properties.pluginResolutionBridge() == null
                                            ? "Spring Boot Analyzer plugin cache"
                                            : properties
                                                    .pluginResolutionBridge()
                                                    .localRepositoryName()))
                    .append("\n");
            builder.append("            url = uri(")
                    .append(renderer.groovyFileUriLiteral(localPluginRepository))
                    .append(")\n");
            builder.append("        }\n");
            if (properties.pluginResolutionBridge() != null) {
                for (String repositoryUrl : properties.pluginResolutionBridge().repositories()) {
                    builder.append("        maven {\n");
                    builder.append("            url = uri(")
                            .append(renderer.groovyStringLiteral(repositoryUrl))
                            .append(")\n");
                    builder.append("        }\n");
                }
            }
            if (properties.addMavenCentralForPluginResolution()) {
                builder.append("        mavenCentral()\n");
            }
            builder.append("    }\n");
            builder.append("}\n");
        }
        return builder.toString();
    }

    private static void writeIsolatedGradleProperties(
            Path gradleUserHome, AnalyzerProperties.GradleProperties properties)
            throws IOException {
        Properties fileProperties = new Properties();
        // Ask Gradle not to retain a reusable daemon after build-aware (EXTENDED) runs. Tooling API
        // cancellation and daemon shutdown are still best effort; the host sandbox remains
        // required.
        fileProperties.setProperty("org.gradle.daemon", "false");
        if (properties.copyHostGradleProxyProperties()) {
            Map<String, String> hostProxyProperties = hostGradleProxyProperties();
            fileProperties.putAll(hostProxyProperties);
            if (!hostProxyProperties.isEmpty()) {
                LOGGER.info(
                        "Copied host Gradle proxy settings into isolated Gradle user home: {}",
                        redact(hostProxyProperties.toString()));
            }
        }
        AnalyzerProperties.ProxyProperties proxy = properties.proxy();
        if (proxy != null && proxy.enabled() && proxy.host() != null && proxy.port() != null) {
            fileProperties.setProperty("systemProp.http.proxyHost", proxy.host());
            fileProperties.setProperty("systemProp.http.proxyPort", String.valueOf(proxy.port()));
            fileProperties.setProperty("systemProp.https.proxyHost", proxy.host());
            fileProperties.setProperty("systemProp.https.proxyPort", String.valueOf(proxy.port()));
            if (proxy.username() != null && !proxy.username().isBlank()) {
                fileProperties.setProperty("systemProp.http.proxyUser", proxy.username());
                fileProperties.setProperty("systemProp.https.proxyUser", proxy.username());
            }
            if (proxy.password() != null && !proxy.password().isBlank()) {
                fileProperties.setProperty("systemProp.http.proxyPassword", proxy.password());
                fileProperties.setProperty("systemProp.https.proxyPassword", proxy.password());
            }
        }
        Path gradlePropertiesFile = gradleUserHome.resolve("gradle.properties");
        Path temporaryProperties =
                Files.createTempFile(gradleUserHome, ".sba-gradle-properties-", ".tmp");
        try {
            try (var outputStream = Files.newOutputStream(temporaryProperties)) {
                fileProperties.store(outputStream, "Spring Boot Analyzer isolated Gradle settings");
            }
            try {
                Files.move(
                        temporaryProperties,
                        gradlePropertiesFile,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException exception) {
                Files.move(
                        temporaryProperties,
                        gradlePropertiesFile,
                        StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporaryProperties);
        }
    }

    private static String extractProxyJvmArgs(String jvmArgs) {
        return Arrays.stream(jvmArgs.split("\\s+"))
                .filter(token -> token.toLowerCase().contains("proxy"))
                .collect(Collectors.joining(" "));
    }

    public record ExecutionFiles(
            Path tempDir,
            Path reportFile,
            Path initScript,
            Path gradleUserHome,
            Path executionHome) {}
}

package com.robbanhoglund.springbootanalyzer.analyzer.runtime;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildInfo;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildModuleInfo;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildModuleResolver;
import com.robbanhoglund.springbootanalyzer.analyzer.model.DetectedClass;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.ApplicationProperty;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.ConfigurationAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleJavaToolchainModel;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleModelAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleResolvedDependencyModel;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.ModuleRuntimeStackAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.RuntimeStackAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.VirtualThreadAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.WebStack;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class RuntimeStackAnalyzer {

    public Result analyze(
            Path repositoryRoot,
            BuildInfo buildInfo,
            GradleModelAnalysis gradleModelAnalysis,
            ConfigurationAnalysis configurationAnalysis,
            List<DetectedClass> detectedComponents,
            List<String> mainApplicationClasses) {
        return analyze(
                JavaSources.from(repositoryRoot),
                buildInfo,
                gradleModelAnalysis,
                configurationAnalysis,
                detectedComponents,
                mainApplicationClasses);
    }

    public Result analyze(
            JavaSources javaSources,
            BuildInfo buildInfo,
            GradleModelAnalysis gradleModelAnalysis,
            ConfigurationAnalysis configurationAnalysis,
            List<DetectedClass> detectedComponents,
            List<String> mainApplicationClasses) {
        // Resolve versions first so that analyzeVirtualThreads and finding rules use the
        // most accurate values — Gradle model data takes precedence over static build-file hints.
        String springBootVersion = gradleResolvedSpringBootVersion(gradleModelAnalysis);
        String springBootVersionSource;
        if (springBootVersion != null) {
            springBootVersionSource = "Gradle resolved";
        } else {
            springBootVersion = buildInfo.springBootVersion();
            springBootVersionSource = buildInfo.springBootVersionSource();
        }

        String javaVersion = gradleToolchainJavaVersion(gradleModelAnalysis);
        if (javaVersion == null) {
            javaVersion = buildInfo.javaVersionHint();
        }

        RuntimeEvidence evidence =
                collectRuntimeEvidence(javaSources, detectedComponents, buildInfo, null);
        List<String> dependencyCoordinates = runtimeDependencies(buildInfo, gradleModelAnalysis);
        String configuredWebApplicationType =
                configuredPropertyValue(configurationAnalysis, "spring.main.web-application-type");

        WebStack webStack =
                determineWebStack(
                        dependencyCoordinates,
                        buildInfo,
                        configuredWebApplicationType,
                        evidence,
                        detectedComponents);
        String webStackReason =
                determineWebStackReason(
                        dependencyCoordinates,
                        buildInfo,
                        configuredWebApplicationType,
                        evidence,
                        webStack);

        VirtualThreadAnalysis virtualThreads =
                analyzeVirtualThreads(javaVersion, configurationAnalysis, evidence);

        List<ModuleRuntimeResult> moduleResults =
                analyzeModuleRuntimeStacks(
                        javaSources, buildInfo, configurationAnalysis, detectedComponents);
        List<ModuleRuntimeStackAnalysis> moduleAnalyses =
                moduleResults.stream().map(ModuleRuntimeResult::analysis).toList();
        List<Finding> findings = new ArrayList<>();
        if (moduleResults.size() > 1) {
            for (ModuleRuntimeResult moduleResult : moduleResults) {
                addModuleRuntimeFindings(moduleResult, findings);
            }
        } else {
            addVirtualThreadFindings(virtualThreads, findings);
            addWebStackFindings(
                    dependencyCoordinates,
                    configuredWebApplicationType,
                    webStack,
                    evidence,
                    findings);
            addJavaVersionFindings(
                    springBootVersion, javaVersion, virtualThreads.enabledByProperty(), findings);
        }

        String mainClass = mainApplicationClasses.isEmpty() ? null : mainApplicationClasses.get(0);

        RuntimeStackAnalysis analysis =
                new RuntimeStackAnalysis(
                        springBootVersion,
                        springBootVersionSource,
                        javaVersion,
                        webStack,
                        webStackReason,
                        virtualThreads,
                        mainClass,
                        moduleAnalyses);
        return new Result(analysis, List.copyOf(findings));
    }

    private RuntimeEvidence collectRuntimeEvidence(
            JavaSources javaSources,
            List<DetectedClass> detectedComponents,
            BuildInfo buildInfo,
            String modulePath) {
        boolean scheduledDetected = false;
        boolean enableSchedulingDetected = false;
        boolean directVirtualThreadUsage = false;
        boolean reactiveSignalDetected = false;
        boolean webFluxRoutingDetected = false;
        Set<String> evidence = new LinkedHashSet<>();

        for (JavaSources.JavaFile file : javaSources.primaryFiles()) {
            String relativePath = file.relativePath();
            if (modulePath != null
                    && !modulePath.equals(
                            BuildModuleResolver.modulePathFor(relativePath, buildInfo))) {
                continue;
            }
            String content = file.content();
            CompilationUnit compilationUnit = file.compilationUnit();
            if (hasAnnotation(compilationUnit, "Scheduled")) {
                scheduledDetected = true;
                evidence.add("@Scheduled in " + relativePath);
            }
            if (hasAnnotation(compilationUnit, "EnableScheduling")) {
                enableSchedulingDetected = true;
                evidence.add("@EnableScheduling in " + relativePath);
            }
            if (content.contains("Thread.ofVirtual(")
                    || content.contains("Thread.startVirtualThread(")
                    || content.contains("Executors.newVirtualThreadPerTaskExecutor(")) {
                directVirtualThreadUsage = true;
                evidence.add("Virtual thread API usage in " + relativePath);
            }
            if (content.contains("reactor.core.publisher.Mono")
                    || content.contains("reactor.core.publisher.Flux")
                    || content.contains("Mono<")
                    || content.contains("Flux<")) {
                reactiveSignalDetected = true;
                evidence.add("Reactive types in " + relativePath);
            }
            if (usesWebFluxServerApi(compilationUnit)) {
                webFluxRoutingDetected = true;
                evidence.add("WebFlux routing API in " + relativePath);
            }
        }

        boolean controllerDetected =
                detectedComponents.stream()
                        .filter(
                                component ->
                                        modulePath == null
                                                || modulePath.equals(
                                                        BuildModuleResolver.modulePathFor(
                                                                component.filePath(), buildInfo)))
                        .anyMatch(
                                component ->
                                        "REST_CONTROLLER"
                                                        .equalsIgnoreCase(
                                                                component.componentType().name())
                                                || "CONTROLLER"
                                                        .equalsIgnoreCase(
                                                                component.componentType().name()));

        return new RuntimeEvidence(
                scheduledDetected,
                enableSchedulingDetected,
                directVirtualThreadUsage,
                reactiveSignalDetected,
                webFluxRoutingDetected,
                controllerDetected,
                List.copyOf(evidence));
    }

    private List<ModuleRuntimeResult> analyzeModuleRuntimeStacks(
            JavaSources javaSources,
            BuildInfo buildInfo,
            ConfigurationAnalysis configurationAnalysis,
            List<DetectedClass> detectedComponents) {
        Set<String> modulePaths = new LinkedHashSet<>();
        for (JavaSources.JavaFile file : javaSources.primaryFiles()) {
            modulePaths.add(BuildModuleResolver.modulePathFor(file.relativePath(), buildInfo));
        }

        List<ModuleRuntimeResult> analyses = new ArrayList<>();
        for (String modulePath : modulePaths) {
            Optional<BuildModuleInfo> moduleInfo =
                    buildInfo.modules().stream()
                            .filter(module -> module.path().equals(modulePath))
                            .findFirst();
            BuildInfo scopedBuildInfo =
                    moduleInfo
                            .map(
                                    module ->
                                            new BuildInfo(
                                                    module.buildTool(),
                                                    module.springBootDetected(),
                                                    module.javaVersionHint(),
                                                    module.dependencies(),
                                                    module.springBootVersion(),
                                                    module.springBootVersionSource(),
                                                    module.springBootVersionConfidence(),
                                                    List.of(module)))
                            .orElseGet(
                                    () ->
                                            new BuildInfo(
                                                    buildInfo.buildTool(),
                                                    false,
                                                    null,
                                                    List.of(),
                                                    null,
                                                    null,
                                                    null));
            RuntimeEvidence moduleEvidence =
                    collectRuntimeEvidence(javaSources, detectedComponents, buildInfo, modulePath);
            String configuredWebApplicationType =
                    configuredPropertyValue(
                            configurationAnalysis,
                            "spring.main.web-application-type",
                            modulePath,
                            buildInfo);
            WebStack moduleWebStack =
                    determineWebStack(
                            scopedBuildInfo.dependencies(),
                            scopedBuildInfo,
                            configuredWebApplicationType,
                            moduleEvidence,
                            detectedComponents.stream()
                                    .filter(
                                            component ->
                                                    modulePath.equals(
                                                            BuildModuleResolver.modulePathFor(
                                                                    component.filePath(),
                                                                    buildInfo)))
                                    .toList());
            String reason =
                    determineWebStackReason(
                            scopedBuildInfo.dependencies(),
                            scopedBuildInfo,
                            configuredWebApplicationType,
                            moduleEvidence,
                            moduleWebStack);
            VirtualThreadAnalysis moduleVirtualThreads =
                    analyzeVirtualThreads(
                            scopedBuildInfo.javaVersionHint(),
                            configuredPropertyValue(
                                    configurationAnalysis,
                                    "spring.threads.virtual.enabled",
                                    modulePath,
                                    buildInfo),
                            configuredPropertyValue(
                                    configurationAnalysis,
                                    "spring.main.keep-alive",
                                    modulePath,
                                    buildInfo),
                            moduleEvidence);
            String sourcePath =
                    javaSources.primaryFiles().stream()
                            .map(JavaSources.JavaFile::relativePath)
                            .filter(
                                    path ->
                                            modulePath.equals(
                                                    BuildModuleResolver.modulePathFor(
                                                            path, buildInfo)))
                            .findFirst()
                            .orElse(null);
            analyses.add(
                    new ModuleRuntimeResult(
                            new ModuleRuntimeStackAnalysis(
                                    modulePath,
                                    scopedBuildInfo.springBootVersion(),
                                    scopedBuildInfo.javaVersionHint(),
                                    moduleWebStack,
                                    reason),
                            scopedBuildInfo,
                            configuredWebApplicationType,
                            moduleEvidence,
                            moduleVirtualThreads,
                            sourcePath));
        }
        return List.copyOf(analyses);
    }

    private boolean hasAnnotation(CompilationUnit compilationUnit, String annotationSimpleName) {
        if (compilationUnit == null) {
            return false;
        }
        return compilationUnit.findAll(AnnotationExpr.class).stream()
                .map(annotation -> annotation.getName().getIdentifier())
                .anyMatch(annotationSimpleName::equals);
    }

    private boolean usesWebFluxServerApi(CompilationUnit compilationUnit) {
        if (compilationUnit == null) {
            return false;
        }
        boolean webFluxImport =
                compilationUnit.getImports().stream()
                        .map(importDeclaration -> importDeclaration.getNameAsString())
                        .anyMatch(
                                name ->
                                        name.startsWith(
                                                        "org.springframework.web.reactive.function.server")
                                                || name.equals(
                                                        "org.springframework.web.reactive.config.WebFluxConfigurer")
                                                || name.equals(
                                                        "org.springframework.web.reactive.config.EnableWebFlux"));
        return webFluxImport || hasAnnotation(compilationUnit, "EnableWebFlux");
    }

    private WebStack determineWebStack(
            List<String> dependencyCoordinates,
            BuildInfo buildInfo,
            String configuredWebApplicationType,
            RuntimeEvidence evidence,
            List<DetectedClass> detectedComponents) {
        if (configuredWebApplicationType != null) {
            return switch (configuredWebApplicationType.toLowerCase(Locale.ROOT)) {
                case "servlet" -> WebStack.SERVLET_MVC;
                case "reactive" -> WebStack.REACTIVE_WEBFLUX;
                case "none" -> WebStack.NON_WEB;
                default -> WebStack.UNKNOWN;
            };
        }

        boolean servletDependency =
                dependencyCoordinates.stream().anyMatch(this::isServletDependency);
        boolean reactiveDependency =
                dependencyCoordinates.stream().anyMatch(this::isReactiveDependency);

        if (servletDependency && reactiveDependency) {
            // This is a mixed classpath, not a mixed running server. Spring Boot chooses the
            // Servlet application type when both framework stacks are present unless the user
            // explicitly selected REACTIVE above.
            return WebStack.SERVLET_MVC;
        }
        if (servletDependency) {
            return WebStack.SERVLET_MVC;
        }
        if (reactiveDependency) {
            return WebStack.REACTIVE_WEBFLUX;
        }
        if (evidence.webFluxRoutingDetected()) {
            return WebStack.REACTIVE_WEBFLUX;
        }
        if (buildInfo.springBootDetected()) {
            return WebStack.NON_WEB;
        }
        if (detectedComponents.stream()
                .anyMatch(component -> component.componentType().name().contains("CONTROLLER"))) {
            return WebStack.SERVLET_MVC;
        }
        return WebStack.UNKNOWN;
    }

    private String determineWebStackReason(
            List<String> dependencyCoordinates,
            BuildInfo buildInfo,
            String configuredWebApplicationType,
            RuntimeEvidence evidence,
            WebStack webStack) {
        if (configuredWebApplicationType != null) {
            return "Configured via spring.main.web-application-type="
                    + configuredWebApplicationType;
        }

        boolean servletDependency =
                dependencyCoordinates.stream().anyMatch(this::isServletDependency);
        boolean reactiveDependency =
                dependencyCoordinates.stream().anyMatch(this::isReactiveDependency);

        if (servletDependency && reactiveDependency) {
            return "Both Spring MVC/Servlet and WebFlux dependencies were detected. Spring Boot"
                    + " selects the Servlet/MVC application type by default; the WebFlux"
                    + " dependency may be present only for WebClient.";
        }
        if (servletDependency && evidence.controllerDetected()) {
            return "Spring MVC annotations and servlet web dependency declarations were detected.";
        }
        if (servletDependency) {
            return "Servlet web dependencies were detected in the build.";
        }
        if (reactiveDependency) {
            return "Reactive WebFlux dependencies were detected in the build.";
        }
        if (webStack == WebStack.SERVLET_MVC && evidence.controllerDetected()) {
            return "Detected from Spring MVC annotations in source files.";
        }
        if (evidence.webFluxRoutingDetected()) {
            return "Spring WebFlux server configuration or routing APIs were detected in source"
                    + " files.";
        }
        if (webStack == WebStack.NON_WEB) {
            return "No web starter or explicit web application type was detected.";
        }
        return "No strong runtime stack signal was detected.";
    }

    private VirtualThreadAnalysis analyzeVirtualThreads(
            String javaVersion,
            ConfigurationAnalysis configurationAnalysis,
            RuntimeEvidence evidence) {
        return analyzeVirtualThreads(
                javaVersion,
                configuredPropertyValue(configurationAnalysis, "spring.threads.virtual.enabled"),
                configuredPropertyValue(configurationAnalysis, "spring.main.keep-alive"),
                evidence);
    }

    private VirtualThreadAnalysis analyzeVirtualThreads(
            String javaVersion,
            String virtualThreadsProperty,
            String keepAliveProperty,
            RuntimeEvidence evidence) {
        boolean enabledByProperty = "true".equalsIgnoreCase(virtualThreadsProperty);
        boolean keepAliveConfigured = "true".equalsIgnoreCase(keepAliveProperty);
        boolean javaVersionCompatible = parseJavaVersion(javaVersion) >= 21;
        boolean scheduledWorkDetected =
                evidence.scheduledDetected() || evidence.enableSchedulingDetected();

        List<String> evidenceLines = new ArrayList<>(evidence.evidence());
        if (enabledByProperty) {
            evidenceLines.add("spring.threads.virtual.enabled=true");
        }
        if (keepAliveConfigured) {
            evidenceLines.add("spring.main.keep-alive=true");
        }

        String summary;
        if (enabledByProperty && javaVersionCompatible) {
            summary =
                    scheduledWorkDetected && !keepAliveConfigured
                            ? "Enabled, but scheduled work may need spring.main.keep-alive=true."
                            : "Enabled";
        } else if (enabledByProperty) {
            summary = "Configured, but the detected Java version may not support virtual threads.";
        } else if (evidence.directVirtualThreadUsage()) {
            summary = "Direct API usage";
        } else if (!javaVersionCompatible) {
            summary = "Java not compatible";
        } else {
            summary = "Disabled";
        }

        return new VirtualThreadAnalysis(
                enabledByProperty,
                javaVersionCompatible,
                evidence.directVirtualThreadUsage(),
                scheduledWorkDetected,
                keepAliveConfigured,
                summary,
                List.copyOf(evidenceLines));
    }

    private void addModuleRuntimeFindings(
            ModuleRuntimeResult moduleResult, List<Finding> findings) {
        List<Finding> moduleFindings = new ArrayList<>();
        addVirtualThreadFindings(moduleResult.virtualThreads(), moduleFindings);
        addWebStackFindings(
                moduleResult.buildInfo().dependencies(),
                moduleResult.configuredWebApplicationType(),
                moduleResult.analysis().webStack(),
                moduleResult.evidence(),
                moduleFindings);
        addJavaVersionFindings(
                moduleResult.analysis().springBootVersion(),
                moduleResult.analysis().javaVersion(),
                moduleResult.virtualThreads().enabledByProperty(),
                moduleFindings);
        moduleFindings.stream()
                .map(finding -> scopeRuntimeFinding(finding, moduleResult))
                .forEach(findings::add);
    }

    private Finding scopeRuntimeFinding(Finding finding, ModuleRuntimeResult moduleResult) {
        String modulePath = moduleResult.analysis().modulePath();
        String moduleEvidence =
                moduleResult.evidence().evidence().isEmpty()
                        ? ""
                        : " Module source evidence: "
                                + String.join("; ", moduleResult.evidence().evidence())
                                + ".";
        String evidence =
                "Module "
                        + modulePath
                        + ": "
                        + (finding.evidence() == null
                                ? "runtime metadata matched."
                                : finding.evidence())
                        + moduleEvidence;
        String sourcePath = moduleResult.sourcePath();
        return new Finding(
                finding.severity(),
                finding.message(),
                sourcePath == null ? "Runtime stack: " + modulePath : sourcePath,
                finding.ruleId(),
                finding.title(),
                finding.category(),
                finding.runtimeDetection(),
                finding.confidence(),
                finding.whyBadPractice(),
                finding.possibleImpact(),
                finding.recommendation(),
                evidence,
                finding.limitations(),
                sourcePath,
                finding.line(),
                finding.target(),
                finding.primaryLocation(),
                finding.highlightRanges(),
                finding.occurrences(),
                finding.relatedSignals());
    }

    private void addVirtualThreadFindings(VirtualThreadAnalysis analysis, List<Finding> findings) {
        // Java version incompatibility is handled by addJavaVersionFindings so it gets a proper
        // rule ID and richer finding body.
        if (analysis.enabledByProperty()
                && analysis.scheduledWorkDetected()
                && !analysis.keepAliveConfigured()) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_VIRTUAL_THREADS_NO_KEEP_ALIVE,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "Virtual threads are enabled and scheduled work was detected,"
                                            + " but spring.main.keep-alive=true was not found.")
                            .whyBadPractice(
                                    "Virtual threads are daemon threads. In a non-web application"
                                        + " whose only remaining work runs on them, nothing keeps"
                                        + " the JVM alive once the main thread finishes, so the"
                                        + " process can exit right after startup.")
                            .possibleImpact(
                                    "Scheduled jobs never run because the application terminates"
                                        + " immediately after the context is ready — and it exits"
                                        + " with a success code, so orchestrators may not alert.")
                            .recommendation(
                                    "Set spring.main.keep-alive=true so the application keeps"
                                            + " running for scheduled work, or keep a non-daemon"
                                            + " thread alive explicitly.")
                            .evidence(
                                    "spring.threads.virtual.enabled=true and scheduled work were"
                                            + " detected without spring.main.keep-alive.")
                            .limitations(
                                    "A web application's server thread already keeps the JVM"
                                            + " alive, in which case this finding is informational"
                                            + " only.")
                            .target("spring.main.keep-alive")
                            .location("Runtime configuration")
                            .build());
        }
    }

    private void addJavaVersionFindings(
            String springBootVersion,
            String javaVersion,
            boolean virtualThreadsEnabled,
            List<Finding> findings) {
        int javaMajor = parseJavaVersion(javaVersion);
        int bootMajor = parseMajorVersion(springBootVersion);

        if (bootMajor == 3 && javaMajor > 0 && javaMajor < 17) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_BOOT3_REQUIRES_JAVA17,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "Spring Boot "
                                            + springBootVersion
                                            + " requires Java 17 or later, but Java "
                                            + javaVersion
                                            + " was detected.")
                            .whyBadPractice(
                                    "Spring Boot 3.x requires Java 17 as a baseline. Running on"
                                            + " an older JVM will cause a hard startup failure.")
                            .possibleImpact(
                                    "The application will not start. Spring Boot 3 uses APIs and"
                                        + " bytecode features only available from Java 17 onwards.")
                            .recommendation(
                                    "Upgrade to Java 17 or later. Spring Boot 3.2+ supports Java"
                                            + " 21, which also unlocks virtual threads via"
                                            + " spring.threads.virtual.enabled.")
                            .evidence(
                                    "Spring Boot "
                                            + springBootVersion
                                            + "; detected Java "
                                            + javaVersion)
                            .target("java.version")
                            .build());
        }

        if (virtualThreadsEnabled && javaMajor > 0 && javaMajor < 21) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_VIRTUAL_THREADS_JAVA_TOO_OLD,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "spring.threads.virtual.enabled=true requires Java 21 or"
                                            + " later, but Java "
                                            + javaVersion
                                            + " was detected.")
                            .whyBadPractice(
                                    "Virtual threads (Project Loom) are a Java 21 feature. Enabling"
                                            + " them on an older JVM causes a startup failure or"
                                            + " silently falls back to platform threads.")
                            .possibleImpact(
                                    "The application may fail to start, or virtual threads may be"
                                        + " silently disabled, negating any throughput benefit.")
                            .recommendation(
                                    "Upgrade to Java 21 or later, or remove"
                                            + " spring.threads.virtual.enabled=true until the JVM"
                                            + " is updated.")
                            .evidence(
                                    "spring.threads.virtual.enabled=true; detected Java "
                                            + javaVersion)
                            .target("spring.threads.virtual.enabled")
                            .build());
        }
    }

    private int parseMajorVersion(String version) {
        if (version == null || version.isBlank()) return -1;
        try {
            return Integer.parseInt(version.replaceAll("[^0-9].*$", ""));
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }

    private void addWebStackFindings(
            List<String> dependencyCoordinates,
            String configuredWebApplicationType,
            WebStack webStack,
            RuntimeEvidence evidence,
            List<Finding> findings) {
        boolean servletDependency =
                dependencyCoordinates.stream().anyMatch(this::isServletDependency);
        boolean reactiveDependency =
                dependencyCoordinates.stream().anyMatch(this::isReactiveDependency);
        if (servletDependency && reactiveDependency) {
            boolean webFluxServerCodeInactive =
                    webStack == WebStack.SERVLET_MVC && evidence.webFluxRoutingDetected();
            String configuredSuffix =
                    configuredWebApplicationType == null
                            ? " Spring Boot therefore selects Servlet/MVC by default."
                            : " spring.main.web-application-type="
                                    + configuredWebApplicationType
                                    + " selects "
                                    + webStack
                                    + ".";
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_MIXED_MVC_AND_WEBFLUX,
                                    FindingConfidence.HIGH)
                            .severity(
                                    webFluxServerCodeInactive
                                            ? com.robbanhoglund.springbootanalyzer.analyzer.model
                                                    .FindingSeverity.WARNING
                                            : com.robbanhoglund.springbootanalyzer.analyzer.model
                                                    .FindingSeverity.INFO)
                            .shortMessage(
                                    "Both Spring MVC/Servlet and WebFlux dependencies were"
                                            + " detected."
                                            + configuredSuffix)
                            .whyBadPractice(
                                    webFluxServerCodeInactive
                                            ? "The application resolves to Servlet/MVC while"
                                                    + " WebFlux server routing APIs are present."
                                                    + " Those routes are not served by the MVC"
                                                    + " runtime."
                                            : "Having both dependencies is valid when an MVC"
                                                    + " application uses WebClient. The classpath"
                                                    + " alone does not mean both server stacks run"
                                                    + " at the same time.")
                            .possibleImpact(
                                    webFluxServerCodeInactive
                                            ? "Reactive routes can be silently unserved because"
                                                    + " the active server stack is MVC."
                                            : "Usually none when WebFlux is client-only. Unneeded"
                                                    + " framework dependencies still make runtime"
                                                    + " intent harder to review.")
                            .recommendation(
                                    "Keep both only when the secondary dependency is intentional."
                                            + " If WebFlux is used only for WebClient in an MVC"
                                            + " service, no server-stack migration is required."
                                            + " Otherwise remove the unused starter or set"
                                            + " spring.main.web-application-type explicitly.")
                            .evidence(
                                    "Both Servlet/MVC and WebFlux dependencies were resolved for"
                                            + " this project.")
                            .limitations(
                                    "Using WebFlux solely for WebClient is a common and valid"
                                            + " pattern; review before removing dependencies.")
                            .target("web stack")
                            .location("Runtime stack")
                            .build());
        }
        if (webStack == WebStack.SERVLET_MVC
                && evidence.webFluxRoutingDetected()
                && !(servletDependency && reactiveDependency)) {
            String reactiveEvidence =
                    evidence.evidence().stream()
                            .filter(item -> item.startsWith("WebFlux routing API in "))
                            .limit(4)
                            .reduce((left, right) -> left + ", " + right)
                            .orElse("Reactive types or routing APIs were detected in source code.");
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_REACTIVE_API_IN_SERVLET_APP,
                                    FindingConfidence.HIGH)
                            .severity(
                                    com.robbanhoglund.springbootanalyzer.analyzer.model
                                            .FindingSeverity.WARNING)
                            .shortMessage(
                                    "WebFlux server routing APIs were detected, but the active"
                                            + " application type is Servlet/MVC.")
                            .whyBadPractice(
                                    "WebClient and reactive return types are valid in an MVC"
                                            + " application, but WebFlux server routes require a"
                                            + " reactive application type and are not registered by"
                                            + " the MVC runtime.")
                            .possibleImpact(
                                    "Routes written for the WebFlux server API may never become"
                                            + " reachable in the deployed application.")
                            .recommendation(
                                    "If these are server routes, select the reactive application"
                                        + " type and remove MVC, or port the routes to MVC. Keep"
                                        + " client-only WebClient/Mono usage as-is.")
                            .evidence(reactiveEvidence)
                            .limitations(
                                    "Static analysis cannot see profile-specific dependency"
                                            + " substitutions or custom parent application"
                                            + " contexts.")
                            .target("WebFlux server routes")
                            .build());
        }
        if (webStack == WebStack.NON_WEB
                && dependencyCoordinates.stream().anyMatch(this::isServletDependency)) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_WEB_DEPENDENCIES_IN_NON_WEB_APP,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "Web dependencies were detected, but configuration indicates a"
                                            + " non-web application type.")
                            .whyBadPractice(
                                    "spring.main.web-application-type=none prevents the embedded"
                                        + " server from starting even though the servlet stack is"
                                        + " packaged, so the web dependencies add startup cost and"
                                        + " attack surface without serving anything.")
                            .possibleImpact(
                                    "A larger artifact and classpath than needed; developers may"
                                            + " also expect endpoints to be reachable when they are"
                                            + " not.")
                            .recommendation(
                                    "Remove the web starter if the application is intentionally"
                                        + " non-web, or drop the web-application-type override if"
                                        + " the server should start.")
                            .evidence(
                                    "Servlet/web dependencies were resolved while the application"
                                            + " type resolves to non-web.")
                            .limitations(
                                    "The web dependency may be required transitively for a client"
                                            + " (e.g. RestTemplate) rather than for serving.")
                            .target("web dependencies")
                            .location("Runtime stack")
                            .build());
        }
    }

    private String configuredPropertyValue(
            ConfigurationAnalysis configurationAnalysis, String name) {
        if (configurationAnalysis == null || configurationAnalysis.properties() == null) {
            return null;
        }
        return configurationAnalysis.properties().stream()
                .filter(property -> name.equals(property.name()))
                .map(ApplicationProperty::value)
                .filter(value -> value != null && !value.isBlank())
                .findFirst()
                .orElse(null);
    }

    private String configuredPropertyValue(
            ConfigurationAnalysis configurationAnalysis,
            String name,
            String modulePath,
            BuildInfo buildInfo) {
        if (configurationAnalysis == null || configurationAnalysis.properties() == null) {
            return null;
        }
        return configurationAnalysis.properties().stream()
                .filter(property -> name.equals(property.name()))
                .filter(
                        property ->
                                modulePath.equals(
                                        BuildModuleResolver.modulePathFor(
                                                property.sourceFile(), buildInfo)))
                .map(ApplicationProperty::value)
                .filter(value -> value != null && !value.isBlank())
                .findFirst()
                .orElse(null);
    }

    private int parseJavaVersion(String javaVersionHint) {
        if (javaVersionHint == null || javaVersionHint.isBlank()) {
            return -1;
        }
        try {
            return Integer.parseInt(javaVersionHint.replaceAll("[^0-9].*$", ""));
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }

    private boolean isServletDependency(String dependency) {
        String normalized = dependency.toLowerCase(Locale.ROOT);
        return (normalized.contains("spring-boot-starter-web")
                        && !normalized.contains("spring-boot-starter-webflux"))
                || normalized.contains("spring-webmvc");
    }

    private boolean isReactiveDependency(String dependency) {
        String normalized = dependency.toLowerCase(Locale.ROOT);
        return normalized.contains("spring-boot-starter-webflux")
                || normalized.contains("spring-webflux");
    }

    /**
     * Extracts the resolved Spring Boot version from the Gradle model when the model ran
     * successfully. All {@code org.springframework.boot} dependencies resolve to the same
     * BOM-managed version, so any one of them gives the authoritative version.
     *
     * <p>Returns {@code null} if the model is absent, was not successful, or has no Spring Boot
     * dependencies with a resolvable version.
     */
    private String gradleResolvedSpringBootVersion(GradleModelAnalysis gradleModelAnalysis) {
        if (gradleModelAnalysis == null || gradleModelAnalysis.resolvedDependencies() == null) {
            return null;
        }
        String statusName =
                gradleModelAnalysis.status() == null ? "" : gradleModelAnalysis.status().name();
        if (!statusName.startsWith("SUCCESS") && !statusName.equals("PARTIAL")) {
            return null;
        }
        return gradleModelAnalysis.resolvedDependencies().stream()
                .filter(dep -> "org.springframework.boot".equals(dep.group()))
                .map(GradleResolvedDependencyModel::version)
                .filter(v -> v != null && !v.isBlank())
                .findFirst()
                .orElse(null);
    }

    /**
     * Extracts the configured Java toolchain language version from the Gradle model.
     * The toolchain version is the most explicit signal for the project's target Java version —
     * more reliable than {@code sourceCompatibility} or build-file regex extraction.
     *
     * <p>Returns {@code null} if no toolchain is configured or the model is absent.
     */
    private String gradleToolchainJavaVersion(GradleModelAnalysis gradleModelAnalysis) {
        if (gradleModelAnalysis == null || gradleModelAnalysis.javaToolchains() == null) {
            return null;
        }
        String statusName =
                gradleModelAnalysis.status() == null ? "" : gradleModelAnalysis.status().name();
        if (!statusName.startsWith("SUCCESS") && !statusName.equals("PARTIAL")) {
            return null;
        }
        return gradleModelAnalysis.javaToolchains().stream()
                .map(GradleJavaToolchainModel::languageVersion)
                .filter(v -> v != null && !v.isBlank())
                .findFirst()
                .orElse(null);
    }

    private List<String> runtimeDependencies(
            BuildInfo buildInfo, GradleModelAnalysis gradleModelAnalysis) {
        if (gradleModelAnalysis != null
                && gradleModelAnalysis.resolvedDependencies() != null
                && !gradleModelAnalysis.resolvedDependencies().isEmpty()) {
            return gradleModelAnalysis.resolvedDependencies().stream()
                    .map(this::coordinate)
                    .distinct()
                    .toList();
        }
        return buildInfo.dependencies();
    }

    private String coordinate(GradleResolvedDependencyModel dependency) {
        return (dependency.group() == null ? "" : dependency.group())
                + ":"
                + (dependency.artifact() == null ? "" : dependency.artifact());
    }

    public record Result(RuntimeStackAnalysis runtimeStackAnalysis, List<Finding> findings) {}

    private record RuntimeEvidence(
            boolean scheduledDetected,
            boolean enableSchedulingDetected,
            boolean directVirtualThreadUsage,
            boolean reactiveSignalDetected,
            boolean webFluxRoutingDetected,
            boolean controllerDetected,
            List<String> evidence) {}

    private record ModuleRuntimeResult(
            ModuleRuntimeStackAnalysis analysis,
            BuildInfo buildInfo,
            String configuredWebApplicationType,
            RuntimeEvidence evidence,
            VirtualThreadAnalysis virtualThreads,
            String sourcePath) {}
}

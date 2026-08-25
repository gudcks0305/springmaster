package com.robbanhoglund.springbootanalyzer.analyzer;

import com.robbanhoglund.springbootanalyzer.analyzer.JavaSourceAnalyzer.SourceAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.configuration.ConfigurationAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleModelAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.http.HttpSurfaceAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.messaging.MessagingAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.model.AnalysisResult;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildInfo;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildModuleResolver;
import com.robbanhoglund.springbootanalyzer.analyzer.model.DetectedClass;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.model.SpringComponentType;
import com.robbanhoglund.springbootanalyzer.analyzer.runtime.RuntimeStackAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.scheduling.SchedulingAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import com.robbanhoglund.springbootanalyzer.config.AnalyzerProperties;
import com.robbanhoglund.springbootanalyzer.git.GitRepositoryReference;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Orchestrator for the full Spring Boot static analysis pipeline.
 *
 * <p>Each {@link #analyze} call runs the following stages in order:
 * <ol>
 *   <li><b>Build</b> — {@link BuildFileAnalyzer} extracts Spring Boot version, Java version,
 *       and the dependency set from build scripts.</li>
 *   <li><b>Source</b> — {@link JavaSourceAnalyzer} discovers all Spring-stereotype-annotated
 *       classes and emits any structural findings (default package, etc.).</li>
 *   <li><b>Configuration</b> — {@link ConfigurationAnalyzer} parses properties/YAML files and
 *       builds a {@link com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.ConfigurationAnalysis}.</li>
 *   <li><b>Gradle model</b> — {@link GradleModelAnalyzer} optionally invokes Gradle tooling to
 *       resolve the dependency graph and declared plugins.</li>
 *   <li><b>Runtime stack</b> — {@link RuntimeStackAnalyzer} classifies the detected runtime
 *       stacks (web, persistence, messaging, etc.).</li>
 *   <li><b>HTTP surface</b> — {@link HttpSurfaceAnalyzer} maps exposed endpoints.</li>
 *   <li><b>Scheduling</b> — {@link SchedulingAnalyzer} identifies scheduled tasks.</li>
 *   <li><b>Messaging</b> — {@link MessagingAnalyzer} identifies messaging listeners.</li>
 *   <li><b>Finding generation</b> — nine finding analyzers each contribute rule-based findings:
 *     <ul>
 *       <li>{@link StaticPracticeFindingAnalyzer} — source-code practice rules (field injection,
 *           transaction/async misuse, exception handling, CORS/CSRF, etc.)</li>
 *       <li>{@link ConfigurationFindingAnalyzer} — configuration and Gradle model rules
 *           (secrets, profile drift, actuator exposure, DDL safety, etc.)</li>
 *       <li>{@link ObservabilityFindingAnalyzer} — observability gaps ({@code @Timed} vs
 *           {@code @Observed}, unobserved scheduled tasks and messaging listeners)</li>
 *       <li>{@link TestingPracticeFindingAnalyzer} — test-layer rules (@SpringBootTest overuse,
 *           missing @Transactional rollback, @MockBean excess, wall-clock time in tests)</li>
 *       <li>{@link CachingPracticeFindingAnalyzer} — caching correctness rules (@Cacheable on
 *           void/private methods, self-invocation, missing TTL provider, etc.)</li>
 *       <li>{@link ObservabilityGapFindingAnalyzer} — gaps in observability annotations
 *           (@Async/@EventListener methods without @Observed, missing exception metrics)</li>
 *       <li>{@link TransactionPracticeFindingAnalyzer} — transaction boundary rules
 *           (@Transactional self-invocation, exception swallowed, HTTP calls inside tx)</li>
 *       <li>{@link SecurityPracticeFindingAnalyzer} — security source-code rules (CSRF disabled,
 *           @PreAuthorize on private methods, weak password hashing)</li>
 *       <li>{@link ScalabilityPracticeFindingAnalyzer} — scalability and bean-lifecycle rules
 *           (hardcoded paths, prototype-in-singleton, RestTemplate without timeout, etc.)</li>
 *     </ul>
 *   </li>
 *   <li><b>Component scan validation</b> — warns when Spring components exist outside the
 *       package tree rooted at the {@code @SpringBootApplication} class.</li>
 * </ol>
 *
 * <p>All collected findings are stored in the returned {@link AnalysisResult} as an immutable
 * list. No deduplication or normalisation is performed here; that is the responsibility of
 * {@link com.robbanhoglund.springbootanalyzer.application.FindingNormalizer}.
 */
@Component
public class SpringBootProjectAnalyzer implements StaticAnalyzer {

    private final BuildFileAnalyzer buildFileAnalyzer;
    private final JavaSourceAnalyzer javaSourceAnalyzer;
    private final ConfigurationAnalyzer configurationAnalyzer;
    private final GradleModelAnalyzer gradleModelAnalyzer;
    private final RuntimeStackAnalyzer runtimeStackAnalyzer;
    private final HttpSurfaceAnalyzer httpSurfaceAnalyzer;
    private final SchedulingAnalyzer schedulingAnalyzer;
    private final MessagingAnalyzer messagingAnalyzer;
    private final StaticPracticeFindingAnalyzer staticPracticeFindingAnalyzer;
    private final ConfigurationFindingAnalyzer configurationFindingAnalyzer;
    private final ObservabilityFindingAnalyzer observabilityFindingAnalyzer;
    private final TestingPracticeFindingAnalyzer testingPracticeFindingAnalyzer;
    private final CachingPracticeFindingAnalyzer cachingPracticeFindingAnalyzer;
    private final ObservabilityGapFindingAnalyzer observabilityGapFindingAnalyzer;
    private final TransactionPracticeFindingAnalyzer transactionPracticeFindingAnalyzer;
    private final SecurityPracticeFindingAnalyzer securityPracticeFindingAnalyzer;
    private final ScalabilityPracticeFindingAnalyzer scalabilityPracticeFindingAnalyzer;
    private final MigrationPracticeFindingAnalyzer migrationPracticeFindingAnalyzer;
    private final SchedulingPracticeFindingAnalyzer schedulingPracticeFindingAnalyzer;
    private final AnalyzerProperties analyzerProperties;

    public SpringBootProjectAnalyzer(
            BuildFileAnalyzer buildFileAnalyzer,
            JavaSourceAnalyzer javaSourceAnalyzer,
            ConfigurationAnalyzer configurationAnalyzer,
            GradleModelAnalyzer gradleModelAnalyzer,
            RuntimeStackAnalyzer runtimeStackAnalyzer,
            HttpSurfaceAnalyzer httpSurfaceAnalyzer,
            SchedulingAnalyzer schedulingAnalyzer,
            MessagingAnalyzer messagingAnalyzer,
            StaticPracticeFindingAnalyzer staticPracticeFindingAnalyzer,
            ConfigurationFindingAnalyzer configurationFindingAnalyzer,
            ObservabilityFindingAnalyzer observabilityFindingAnalyzer,
            TestingPracticeFindingAnalyzer testingPracticeFindingAnalyzer,
            CachingPracticeFindingAnalyzer cachingPracticeFindingAnalyzer,
            ObservabilityGapFindingAnalyzer observabilityGapFindingAnalyzer,
            TransactionPracticeFindingAnalyzer transactionPracticeFindingAnalyzer,
            SecurityPracticeFindingAnalyzer securityPracticeFindingAnalyzer,
            ScalabilityPracticeFindingAnalyzer scalabilityPracticeFindingAnalyzer,
            MigrationPracticeFindingAnalyzer migrationPracticeFindingAnalyzer,
            SchedulingPracticeFindingAnalyzer schedulingPracticeFindingAnalyzer,
            AnalyzerProperties analyzerProperties) {
        this.buildFileAnalyzer = buildFileAnalyzer;
        this.javaSourceAnalyzer = javaSourceAnalyzer;
        this.configurationAnalyzer = configurationAnalyzer;
        this.gradleModelAnalyzer = gradleModelAnalyzer;
        this.runtimeStackAnalyzer = runtimeStackAnalyzer;
        this.httpSurfaceAnalyzer = httpSurfaceAnalyzer;
        this.schedulingAnalyzer = schedulingAnalyzer;
        this.messagingAnalyzer = messagingAnalyzer;
        this.staticPracticeFindingAnalyzer = staticPracticeFindingAnalyzer;
        this.configurationFindingAnalyzer = configurationFindingAnalyzer;
        this.observabilityFindingAnalyzer = observabilityFindingAnalyzer;
        this.testingPracticeFindingAnalyzer = testingPracticeFindingAnalyzer;
        this.cachingPracticeFindingAnalyzer = cachingPracticeFindingAnalyzer;
        this.observabilityGapFindingAnalyzer = observabilityGapFindingAnalyzer;
        this.transactionPracticeFindingAnalyzer = transactionPracticeFindingAnalyzer;
        this.securityPracticeFindingAnalyzer = securityPracticeFindingAnalyzer;
        this.scalabilityPracticeFindingAnalyzer = scalabilityPracticeFindingAnalyzer;
        this.migrationPracticeFindingAnalyzer = migrationPracticeFindingAnalyzer;
        this.schedulingPracticeFindingAnalyzer = schedulingPracticeFindingAnalyzer;
        this.analyzerProperties = analyzerProperties;
    }

    /**
     * Runs the full analysis pipeline against a locally cloned repository and assembles the
     * combined {@link AnalysisResult}.
     *
     * <p>The {@code workspaceId} is passed to sub-analyzers that need a stable identifier for
     * caching or logging purposes (e.g. the Gradle tooling integration).
     *
     * @param repositoryReference the remote repository reference (URL + branch/commit) used to
     *                            generate GitHub permalinks in findings
     * @param repositoryRoot      root directory of the locally checked-out repository
     * @param workspaceId         opaque workspace identifier, unique per analysis job
     * @return the fully assembled {@link AnalysisResult}; never null
     */
    @Override
    public AnalysisResult analyze(
            GitRepositoryReference repositoryReference, Path repositoryRoot, String workspaceId) {
        BuildInfo buildInfo = buildFileAnalyzer.analyze(repositoryRoot);
        // Parse the Java source tree once and share it across the finding analyzers below, instead
        // of each analyzer walking and re-parsing src/main/java independently.
        JavaSources javaSources = JavaSources.from(repositoryRoot);
        SourceAnalysis sourceAnalysis = javaSourceAnalyzer.analyze(javaSources);
        ConfigurationAnalyzer.Result configurationResult =
                configurationAnalyzer.analyze(repositoryRoot, buildInfo, javaSources);
        GradleModelAnalyzer.Result gradleResult =
                gradleModelAnalyzer.analyze(
                        repositoryReference, repositoryRoot, buildInfo, analyzerProperties);

        List<DetectedClass> detectedClasses = sourceAnalysis.detectedClasses();
        List<Finding> findings = new ArrayList<>(sourceAnalysis.findings());
        findings.addAll(configurationResult.findings());
        findings.addAll(gradleResult.findings());

        List<String> mainApplicationClasses =
                detectedClasses.stream()
                        .filter(
                                detectedClass ->
                                        detectedClass.componentType()
                                                == SpringComponentType.MAIN_APPLICATION)
                        .map(detectedClass -> detectedClass.fullyQualifiedClassName())
                        .toList();

        addApplicationStructureFindings(
                detectedClasses, mainApplicationClasses, buildInfo, findings);
        RuntimeStackAnalyzer.Result runtimeResult =
                runtimeStackAnalyzer.analyze(
                        javaSources,
                        buildInfo,
                        gradleResult.gradleModelAnalysis(),
                        configurationResult.configurationAnalysis(),
                        detectedClasses,
                        mainApplicationClasses);
        findings.addAll(runtimeResult.findings());

        HttpSurfaceAnalyzer.Result httpResult =
                httpSurfaceAnalyzer.analyze(
                        javaSources,
                        configurationResult.configurationAnalysis(),
                        buildInfo,
                        runtimeResult.runtimeStackAnalysis());
        findings.addAll(httpResult.findings());
        findings.addAll(
                staticPracticeFindingAnalyzer.analyze(
                        javaSources,
                        buildInfo,
                        configurationResult.configurationAnalysis(),
                        gradleResult.gradleModelAnalysis(),
                        runtimeResult.runtimeStackAnalysis(),
                        httpResult.httpSurfaceAnalysis(),
                        detectedClasses));
        findings.addAll(
                configurationFindingAnalyzer.analyze(
                        repositoryRoot,
                        buildInfo,
                        configurationResult.configurationAnalysis(),
                        gradleResult.gradleModelAnalysis()));
        findings.addAll(
                observabilityFindingAnalyzer.analyze(
                        javaSources, runtimeResult.runtimeStackAnalysis(), buildInfo));
        findings.addAll(testingPracticeFindingAnalyzer.analyze(repositoryRoot, buildInfo));
        findings.addAll(cachingPracticeFindingAnalyzer.analyze(javaSources));
        findings.addAll(observabilityGapFindingAnalyzer.analyze(javaSources, buildInfo));
        findings.addAll(transactionPracticeFindingAnalyzer.analyze(javaSources));
        findings.addAll(securityPracticeFindingAnalyzer.analyze(javaSources));
        findings.addAll(
                scalabilityPracticeFindingAnalyzer.analyze(
                        javaSources, runtimeResult.runtimeStackAnalysis()));
        findings.addAll(schedulingPracticeFindingAnalyzer.analyze(javaSources));
        findings.addAll(
                migrationPracticeFindingAnalyzer.analyze(
                        javaSources, runtimeResult.runtimeStackAnalysis()));

        return new AnalysisResult(
                repositoryReference.repositoryUrl(),
                repositoryReference.branch(),
                workspaceId,
                workspaceId,
                null,
                buildInfo,
                mainApplicationClasses,
                detectedClasses,
                List.copyOf(findings),
                configurationResult.configurationAnalysis(),
                runtimeResult.runtimeStackAnalysis(),
                httpResult.httpSurfaceAnalysis(),
                gradleResult.gradleModelAnalysis(),
                schedulingAnalyzer.analyze(javaSources),
                messagingAnalyzer.analyze(javaSources));
    }

    private void addApplicationStructureFindings(
            List<DetectedClass> detectedClasses,
            List<String> mainApplicationClasses,
            BuildInfo buildInfo,
            List<Finding> findings) {
        if (mainApplicationClasses.isEmpty()) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_NO_MAIN_APPLICATION_CLASS,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "No @SpringBootApplication class was found. The project may not"
                                        + " be a Spring Boot application or the main class may be"
                                        + " outside a standard src/main/java source tree.")
                            .whyBadPractice(
                                    "The @SpringBootApplication class defines the component scan"
                                        + " root that most of this analysis depends on. Without it,"
                                        + " package-scoped rules cannot determine which classes"
                                        + " Spring would actually register.")
                            .possibleImpact(
                                    "Findings that depend on the scan root are skipped, so the"
                                            + " report is less complete than it appears.")
                            .recommendation(
                                    "If this is a Spring Boot application, confirm the entry point"
                                        + " lives under a standard src/main/java tree in this"
                                        + " repository. For a library-only repository this finding"
                                        + " is expected and can be suppressed.")
                            .evidence(
                                    "No class annotated @SpringBootApplication was found in any"
                                            + " nested src/main/java tree.")
                            .limitations(
                                    "Custom source sets and generated sources outside standard"
                                            + " src/main/java trees are not part of this analysis.")
                            .target("application entry point")
                            .location("Application structure")
                            .build());
            return;
        }

        Map<String, List<DetectedClass>> mainApplicationsByModule = new LinkedHashMap<>();
        for (DetectedClass detectedClass : detectedClasses) {
            if (detectedClass.componentType() != SpringComponentType.MAIN_APPLICATION) {
                continue;
            }
            mainApplicationsByModule
                    .computeIfAbsent(
                            BuildModuleResolver.modulePathFor(detectedClass.filePath(), buildInfo),
                            ignored -> new ArrayList<>())
                    .add(detectedClass);
        }

        for (Map.Entry<String, List<DetectedClass>> entry : mainApplicationsByModule.entrySet()) {
            List<String> moduleMainApplications =
                    entry.getValue().stream().map(DetectedClass::fullyQualifiedClassName).toList();
            if (moduleMainApplications.size() <= 1) {
                continue;
            }
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_MULTIPLE_MAIN_APPLICATION_CLASSES,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "Multiple @SpringBootApplication classes were found. Review the"
                                            + " intended application entry point and component scan"
                                            + " boundaries.")
                            .whyBadPractice(
                                    "Each @SpringBootApplication defines its own component scan"
                                        + " root and auto-configuration set. Tests using"
                                        + " @SpringBootTest without an explicit classes attribute"
                                        + " pick one by search order, which may not be the one that"
                                        + " runs in production.")
                            .possibleImpact(
                                    "Tests can bootstrap a different context than production, so"
                                        + " configuration problems are masked until deployment.")
                            .recommendation(
                                    "Keep a single @SpringBootApplication per deployable"
                                            + " application. Use plain @Configuration classes for"
                                            + " test-only or auxiliary contexts.")
                            .evidence(
                                    moduleMainApplications.size()
                                            + " @SpringBootApplication classes were detected: "
                                            + String.join(", ", moduleMainApplications)
                                            + ".")
                            .limitations(
                                    "This check is scoped to build module "
                                            + entry.getKey()
                                            + "; separate deployable modules may each define one"
                                            + " application entry point.")
                            .target("application entry points")
                            .location("Application structure: " + entry.getKey())
                            .build());
        }

        for (DetectedClass detectedClass : detectedClasses) {
            if (detectedClass.componentType() == SpringComponentType.MAIN_APPLICATION) {
                continue;
            }
            if (detectedClass.packageName() == null || detectedClass.packageName().isBlank()) {
                continue;
            }
            String modulePath =
                    BuildModuleResolver.modulePathFor(detectedClass.filePath(), buildInfo);
            List<DetectedClass> scopedMainApplications =
                    mainApplicationsByModule.getOrDefault(modulePath, List.of());
            if (scopedMainApplications.isEmpty()) {
                scopedMainApplications =
                        mainApplicationsByModule.values().stream().flatMap(List::stream).toList();
            }
            Set<String> mainPackages = new LinkedHashSet<>();
            for (DetectedClass mainApplication : scopedMainApplications) {
                String mainApplicationClass = mainApplication.fullyQualifiedClassName();
                int separatorIndex = mainApplicationClass.lastIndexOf('.');
                if (separatorIndex > 0) {
                    mainPackages.add(mainApplicationClass.substring(0, separatorIndex));
                }
            }
            boolean underMainPackage =
                    mainPackages.stream()
                            .anyMatch(
                                    mainPackage ->
                                            detectedClass.packageName().equals(mainPackage)
                                                    || detectedClass
                                                            .packageName()
                                                            .startsWith(mainPackage + "."));
            if (!underMainPackage) {
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_COMPONENT_OUTSIDE_MAIN_PACKAGE,
                                        FindingConfidence.MEDIUM)
                                .shortMessage(
                                        "Component "
                                                + detectedClass.fullyQualifiedClassName()
                                                + " lives outside the main application package —"
                                                + " it may never be scanned.")
                                .whyBadPractice(
                                        "Default component scanning starts at the"
                                            + " @SpringBootApplication class's package and covers"
                                            + " only its sub-packages. A stereotype class outside"
                                            + " that tree is not registered as a bean unless an"
                                            + " explicit @ComponentScan or auto-configuration"
                                            + " import includes it.")
                                .possibleImpact(
                                        "The bean silently does not exist: injection points fail at"
                                            + " startup, or a @ConditionalOnMissingBean default"
                                            + " takes over and the intended implementation never"
                                            + " runs.")
                                .recommendation(
                                        "Move the class under the application package, or add it"
                                            + " explicitly via @ComponentScan/@Import (for a"
                                            + " library, register it through an auto-configuration"
                                            + " entry).")
                                .evidence(
                                        detectedClass.fullyQualifiedClassName()
                                                + " is in package "
                                                + detectedClass.packageName()
                                                + " in module "
                                                + modulePath
                                                + ", outside the main application package(s): "
                                                + String.join(", ", mainPackages)
                                                + ".")
                                .limitations(
                                        "An explicit @ComponentScan, @Import, or"
                                                + " auto-configuration registration elsewhere may"
                                                + " already include this package.")
                                .location(detectedClass.filePath())
                                .target(detectedClass.fullyQualifiedClassName())
                                .build());
            }
        }
    }
}

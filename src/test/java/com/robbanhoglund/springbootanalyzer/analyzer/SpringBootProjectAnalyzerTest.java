package com.robbanhoglund.springbootanalyzer.analyzer;

import static org.assertj.core.api.Assertions.assertThat;

import com.robbanhoglund.springbootanalyzer.analyzer.configuration.ConfigurationAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.configuration.ConfigurationFileScanner;
import com.robbanhoglund.springbootanalyzer.analyzer.configuration.ConfigurationPropertiesClassAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.configuration.PropertiesFileParser;
import com.robbanhoglund.springbootanalyzer.analyzer.configuration.PropertyNameNormalizer;
import com.robbanhoglund.springbootanalyzer.analyzer.configuration.PropertyReferenceAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.configuration.SensitivePropertyValueRedactor;
import com.robbanhoglund.springbootanalyzer.analyzer.configuration.SpringConfigurationMetadataCatalog;
import com.robbanhoglund.springbootanalyzer.analyzer.configuration.YamlConfigurationParser;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleCommandBuilder;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleExecutableLocator;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleExecutionService;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleFailureClassifier;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleJavaCompatibilityService;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleModelAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleModelReportParser;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradlePluginResolutionFailureParser;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleSafetyPolicy;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleSettingsPluginScanner;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.GradleToolingApiExecutionService;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.plugin.GradleCorePluginDetector;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.plugin.GradlePluginDeclarationScanner;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.plugin.GradlePluginResolutionBridge;
import com.robbanhoglund.springbootanalyzer.analyzer.gradle.plugin.GradleVersionCatalogPluginScanner;
import com.robbanhoglund.springbootanalyzer.analyzer.http.HttpSurfaceAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingSeverity;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleExecutionMode;
import com.robbanhoglund.springbootanalyzer.analyzer.runtime.RuntimeStackAnalyzer;
import com.robbanhoglund.springbootanalyzer.config.AnalyzerProperties;
import com.robbanhoglund.springbootanalyzer.git.GitRepositoryReference;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SpringBootProjectAnalyzerTest {

    private final PropertyNameNormalizer propertyNameNormalizer = new PropertyNameNormalizer();
    private final ConfigurationAnalyzer configurationAnalyzer =
            new ConfigurationAnalyzer(
                    new ConfigurationFileScanner(),
                    new PropertiesFileParser(),
                    new YamlConfigurationParser(),
                    new SpringConfigurationMetadataCatalog(),
                    new ConfigurationPropertiesClassAnalyzer(propertyNameNormalizer),
                    new PropertyReferenceAnalyzer(propertyNameNormalizer),
                    new SensitivePropertyValueRedactor(),
                    propertyNameNormalizer);
    private final GradleJavaCompatibilityService gradleJavaCompatibilityService =
            new GradleJavaCompatibilityService();
    private final GradleFailureClassifier gradleFailureClassifier =
            new GradleFailureClassifier(new GradlePluginResolutionFailureParser());
    private final SpringBootProjectAnalyzer analyzer =
            new SpringBootProjectAnalyzer(
                    new BuildFileAnalyzer(),
                    new JavaSourceAnalyzer(),
                    configurationAnalyzer,
                    new GradleModelAnalyzer(
                            new GradleSafetyPolicy(gradleJavaCompatibilityService),
                            gradleJavaCompatibilityService,
                            new GradleToolingApiExecutionService(
                                    gradleJavaCompatibilityService, gradleFailureClassifier),
                            new GradleExecutionService(
                                    new GradleCommandBuilder(),
                                    new GradleExecutableLocator(),
                                    gradleJavaCompatibilityService,
                                    gradleFailureClassifier),
                            new GradleModelReportParser(),
                            new GradleSettingsPluginScanner(),
                            new GradlePluginDeclarationScanner(
                                    new GradleVersionCatalogPluginScanner()),
                            new GradlePluginResolutionBridge(new GradleCorePluginDetector())),
                    new RuntimeStackAnalyzer(),
                    new HttpSurfaceAnalyzer(),
                    new com.robbanhoglund.springbootanalyzer.analyzer.scheduling
                            .SchedulingAnalyzer(),
                    new com.robbanhoglund.springbootanalyzer.analyzer.messaging.MessagingAnalyzer(),
                    new StaticPracticeFindingAnalyzer(),
                    new ConfigurationFindingAnalyzer(),
                    new ObservabilityFindingAnalyzer(),
                    new TestingPracticeFindingAnalyzer(),
                    new CachingPracticeFindingAnalyzer(),
                    new ObservabilityGapFindingAnalyzer(),
                    new TransactionPracticeFindingAnalyzer(),
                    new SecurityPracticeFindingAnalyzer(),
                    new ScalabilityPracticeFindingAnalyzer(),
                    new MigrationPracticeFindingAnalyzer(),
                    new SchedulingPracticeFindingAnalyzer(),
                    new AnalyzerProperties(
                            Path.of("."),
                            true,
                            false,
                            new AnalyzerProperties.ScheduledWorkspaceCleanupProperties(
                                    true, Duration.ofDays(7), 4),
                            new AnalyzerProperties.GradleProperties(
                                    false,
                                    null,
                                    GradleExecutionMode.TOOLING_API,
                                    "9.5.0",
                                    Path.of(
                                            System.getProperty("java.io.tmpdir"),
                                            "spring-boot-analyzer-gradle-distributions"),
                                    java.util.List.of(),
                                    null,
                                    null,
                                    true,
                                    java.util.List.of("https://plugins.gradle.org/m2/"),
                                    true,
                                    false,
                                    true,
                                    false,
                                    true,
                                    false,
                                    false,
                                    new AnalyzerProperties.SettingsPluginWorkaroundProperties(
                                            false, false, java.util.List.of(), 1),
                                    new AnalyzerProperties.PluginResolutionBridgeProperties(
                                            true,
                                            true,
                                            true,
                                            "Spring Boot Analyzer plugin cache",
                                            java.util.List.of(
                                                    "https://plugins.gradle.org/m2/",
                                                    "https://repo.maven.apache.org/maven2/"),
                                            Duration.ofSeconds(30),
                                            50,
                                            500,
                                            false,
                                            2),
                                    false,
                                    false,
                                    true,
                                    null,
                                    null,
                                    0,
                                    0)));

    @TempDir Path tempDir;

    @Test
    void reportsComponentsOutsideMainApplicationPackage() throws IOException {
        Files.writeString(
                tempDir.resolve("build.gradle"),
                """
                plugins {
                    id 'org.springframework.boot' version '3.5.13'
                }

                dependencies {
                    implementation 'org.springframework.boot:spring-boot-starter-web'
                }
                """);

        Path mainPackage =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                mainPackage.resolve("DemoApplication.java"),
                """
                package com.example.demo;

                import org.springframework.boot.autoconfigure.SpringBootApplication;

                @SpringBootApplication
                public class DemoApplication {
                }
                """);
        Files.writeString(
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo/service"))
                        .resolve("GreetingService.java"),
                """
                package com.example.demo.service;

                import org.springframework.stereotype.Service;

                @Service
                public class GreetingService {
                }
                """);
        Files.writeString(
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/external"))
                        .resolve("ExternalComponent.java"),
                """
                package com.example.external;

                import org.springframework.stereotype.Component;

                @Component
                public class ExternalComponent {
                }
                """);

        var result =
                analyzer.analyze(
                        new GitRepositoryReference("https://github.com/example/demo.git", "main"),
                        tempDir,
                        "workspace-123");

        assertThat(result.mainApplicationClasses())
                .containsExactly("com.example.demo.DemoApplication");
        assertThat(result.detectedComponents()).hasSize(3);
        assertThat(result.findings())
                .extracting(finding -> finding.severity())
                .contains(FindingSeverity.WARNING);
        assertThat(result.findings())
                .extracting(finding -> finding.message())
                .anyMatch(message -> message.contains("outside the main application package"));
        assertThat(result.configurationAnalysis()).isNotNull();
        assertThat(result.runtimeStackAnalysis()).isNotNull();
        assertThat(result.httpSurfaceAnalysis()).isNotNull();
    }

    @Test
    void warnsWhenNoSpringBootApplicationClassIsFound() throws IOException {
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("GreetingService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;

                @Service
                public class GreetingService {
                }
                """);

        var result =
                analyzer.analyze(
                        new GitRepositoryReference("https://github.com/example/demo.git", null),
                        tempDir,
                        "workspace-456");

        assertThat(result.mainApplicationClasses()).isEmpty();
        assertThat(result.findings())
                .extracting(finding -> finding.message())
                .anyMatch(message -> message.contains("No @SpringBootApplication class was found"));
    }

    @Test
    void analyzesMavenSiblingModulesAsOneRepositorySnapshot() throws IOException {
        Files.writeString(
                tempDir.resolve("pom.xml"),
                """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <parent>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-parent</artifactId>
                        <version>3.5.13</version>
                    </parent>
                    <groupId>com.example</groupId>
                    <artifactId>multi-parent</artifactId>
                    <version>1.0.0</version>
                    <packaging>pom</packaging>
                    <modules>
                        <module>app</module>
                        <module>worker</module>
                    </modules>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>spring-boot-starter-web</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);
        writeModulePom("app");
        writeModulePom("worker");

        Path appSources =
                Files.createDirectories(
                        tempDir.resolve("app/src/main/java/com/example/application"));
        Files.writeString(
                appSources.resolve("MultiApplication.java"),
                """
                package com.example.application;

                import org.springframework.boot.autoconfigure.SpringBootApplication;
                import org.springframework.scheduling.annotation.EnableAsync;

                @SpringBootApplication
                @EnableAsync
                public class MultiApplication {}
                """);

        Path workerSources =
                Files.createDirectories(tempDir.resolve("worker/src/main/java/com/example/worker"));
        Files.writeString(
                workerSources.resolve("AsyncWorker.java"),
                """
                package com.example.worker;

                import org.springframework.beans.factory.annotation.Value;
                import org.springframework.scheduling.annotation.Async;
                import org.springframework.stereotype.Service;

                @Service
                class AsyncWorker {
                    @Value("${worker.timeout:30s}")
                    private String timeout;

                    @Async
                    void run() {}
                }
                """);
        Files.writeString(
                workerSources.resolve("WorkerController.java"),
                """
                package com.example.worker;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class WorkerController {
                    @GetMapping("/worker/status")
                    String status() { return "ok"; }
                }
                """);

        var result =
                analyzer.analyze(
                        new GitRepositoryReference("https://github.com/example/multi.git", "main"),
                        tempDir,
                        "workspace-multi");

        assertThat(result.mainApplicationClasses())
                .containsExactly("com.example.application.MultiApplication");
        assertThat(result.detectedComponents())
                .extracting(component -> component.filePath())
                .contains(
                        "app/src/main/java/com/example/application/MultiApplication.java",
                        "worker/src/main/java/com/example/worker/AsyncWorker.java",
                        "worker/src/main/java/com/example/worker/WorkerController.java");
        assertThat(result.findings())
                .extracting(finding -> finding.ruleId())
                .contains(FindingRules.SPRING_ASYNC_EXECUTOR_NOT_CONFIGURED.ruleId());
        assertThat(result.schedulingAnalysis().enableAsyncPresent()).isTrue();
        assertThat(result.schedulingAnalysis().asyncMethods())
                .singleElement()
                .satisfies(
                        endpoint ->
                                assertThat(endpoint.sourceFile())
                                        .isEqualTo(
                                                "worker/src/main/java/com/example/worker/AsyncWorker.java"));
        assertThat(result.httpSurfaceAnalysis().inboundEndpoints())
                .singleElement()
                .satisfies(
                        endpoint -> {
                            assertThat(endpoint.path()).isEqualTo("/worker/status");
                            assertThat(endpoint.sourceFile())
                                    .isEqualTo(
                                            "worker/src/main/java/com/example/worker/WorkerController.java");
                        });
        assertThat(result.configurationAnalysis().properties())
                .extracting(property -> property.name())
                .contains("worker.timeout");
    }

    @Test
    void scopesApplicationStructureRulesAcrossIndependentDeployableModules() throws IOException {
        Files.writeString(
                tempDir.resolve("pom.xml"),
                """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <groupId>com.example</groupId>
                    <artifactId>services</artifactId>
                    <version>1.0.0</version>
                    <packaging>pom</packaging>
                    <properties><java.version>11</java.version></properties>
                    <modules>
                        <module>orders</module>
                        <module>payments</module>
                        <module>reactive</module>
                    </modules>
                </project>
                """);
        writeDeployableModulePom("orders", "spring-boot-starter-web", "3.5.13", "25");
        writeDeployableModulePom("payments", "spring-boot-starter-batch", "3.3.9", "17");
        writeDeployableModulePom("reactive", "spring-boot-starter-webflux", "3.4.8", "21");
        writeApplicationModule("orders", "OrdersApplication", "OrdersService");
        writeApplicationModule("payments", "PaymentsApplication", "PaymentsService");
        writeApplicationModule("reactive", "ReactiveApplication", "ReactiveService");
        writeController("orders", "OrdersController", "/orders");
        writeController("payments", "PaymentsController", "/payments");
        writeController("reactive", "ReactiveController", "/reactive");
        writeModuleProperty("orders", "spring.main.web-application-type=servlet\n");
        writeModuleProperty("payments", "spring.main.web-application-type=none\n");
        writeModuleProperty("reactive", "spring.main.web-application-type=reactive\n");
        Path rootResources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(
                rootResources.resolve("application.properties"),
                "spring.threads.virtual.enabled=true\n");

        var result =
                analyzer.analyze(
                        new GitRepositoryReference(
                                "https://github.com/example/services.git", "main"),
                        tempDir,
                        "workspace-services");

        assertThat(result.mainApplicationClasses())
                .containsExactly(
                        "com.example.orders.OrdersApplication",
                        "com.example.payments.PaymentsApplication",
                        "com.example.reactive.ReactiveApplication");
        assertThat(result.findings())
                .extracting(finding -> finding.ruleId())
                .doesNotContain(
                        FindingRules.SPRING_MULTIPLE_MAIN_APPLICATION_CLASSES.ruleId(),
                        FindingRules.SPRING_COMPONENT_OUTSIDE_MAIN_PACKAGE.ruleId(),
                        FindingRules.SPRING_MIXED_MVC_AND_WEBFLUX.ruleId(),
                        FindingRules.SPRING_BOOT3_REQUIRES_JAVA17.ruleId(),
                        FindingRules.SPRING_VIRTUAL_THREADS_JAVA_TOO_OLD.ruleId());
        assertThat(result.runtimeStackAnalysis().modules())
                .filteredOn(module -> module.modulePath().equals("orders"))
                .singleElement()
                .satisfies(
                        module -> {
                            assertThat(module.webStack())
                                    .isEqualTo(
                                            com.robbanhoglund.springbootanalyzer.analyzer.model
                                                    .runtime.WebStack.SERVLET_MVC);
                            assertThat(module.springBootVersion()).isEqualTo("3.5.13");
                            assertThat(module.javaVersion()).isEqualTo("25");
                        });
        assertThat(result.runtimeStackAnalysis().modules())
                .filteredOn(module -> module.modulePath().equals("reactive"))
                .singleElement()
                .satisfies(
                        module -> {
                            assertThat(module.webStack())
                                    .isEqualTo(
                                            com.robbanhoglund.springbootanalyzer.analyzer.model
                                                    .runtime.WebStack.REACTIVE_WEBFLUX);
                            assertThat(module.springBootVersion()).isEqualTo("3.4.8");
                            assertThat(module.javaVersion()).isEqualTo("21");
                        });
        assertThat(result.runtimeStackAnalysis().modules())
                .filteredOn(module -> module.modulePath().equals("payments"))
                .singleElement()
                .satisfies(
                        module -> {
                            assertThat(module.webStack())
                                    .isEqualTo(
                                            com.robbanhoglund.springbootanalyzer.analyzer.model
                                                    .runtime.WebStack.NON_WEB);
                            assertThat(module.springBootVersion()).isEqualTo("3.3.9");
                            assertThat(module.javaVersion()).isEqualTo("17");
                        });
        assertThat(result.findings())
                .filteredOn(
                        finding ->
                                FindingRules.SPRING_INBOUND_ENDPOINTS_IN_NON_WEB_APP
                                        .ruleId()
                                        .equals(finding.ruleId()))
                .singleElement()
                .satisfies(
                        finding ->
                                assertThat(finding.location()).contains("payments/src/main/java"));
        assertThat(result.configurationAnalysis().properties())
                .filteredOn(property -> property.name().equals("spring.main.web-application-type"))
                .extracting(property -> property.sourceFile())
                .containsExactly(
                        "orders/src/main/resources/application.properties",
                        "payments/src/main/resources/application.properties",
                        "reactive/src/main/resources/application.properties");
        assertThat(result.buildInfo().modules())
                .filteredOn(module -> module.path().equals("orders"))
                .singleElement()
                .satisfies(
                        module ->
                                assertThat(module.dependencies())
                                        .contains(
                                                "org.springframework.boot:spring-boot-starter-web"));
        assertThat(result.buildInfo().modules())
                .filteredOn(module -> module.path().equals("payments"))
                .singleElement()
                .satisfies(
                        module ->
                                assertThat(module.dependencies())
                                        .contains(
                                                "org.springframework.boot:spring-boot-starter-batch")
                                        .doesNotContain(
                                                "org.springframework.boot:spring-boot-starter-web"));
    }

    @Test
    void scopesIndependentInitialAndCompleteBuildRootsWithoutRootDescriptor() throws IOException {
        writeDeployableModulePom("initial", "spring-boot-starter-web");
        writeDeployableModulePom("complete", "spring-boot-starter-web");
        writeApplicationModule("initial", "InitialApplication", "InitialService");
        writeApplicationModule("complete", "CompleteApplication", "CompleteService");
        Files.writeString(
                tempDir.resolve(
                        "complete/src/main/java/com/example/complete/CompleteController.java"),
                """
                package com.example.complete;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class CompleteController {
                    @GetMapping("/complete")
                    String complete() { return "complete"; }
                }
                """);

        var result =
                analyzer.analyze(
                        new GitRepositoryReference("https://github.com/example/guide.git", "main"),
                        tempDir,
                        "workspace-guide");

        assertThat(result.mainApplicationClasses()).hasSize(2);
        assertThat(result.findings())
                .extracting(finding -> finding.ruleId())
                .doesNotContain(
                        FindingRules.SPRING_MULTIPLE_MAIN_APPLICATION_CLASSES.ruleId(),
                        FindingRules.SPRING_COMPONENT_OUTSIDE_MAIN_PACKAGE.ruleId(),
                        FindingRules.SPRING_INBOUND_ENDPOINTS_IN_NON_WEB_APP.ruleId());
        assertThat(result.buildInfo().modules())
                .extracting(module -> module.path())
                .containsExactly(".", "complete", "initial");
    }

    @Test
    void reportsMixedMvcAndWebFluxOnlyForModuleThatDeclaresBoth() throws IOException {
        Files.writeString(
                tempDir.resolve("pom.xml"),
                """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <groupId>com.example</groupId>
                    <artifactId>mixed-services</artifactId>
                    <version>1.0.0</version>
                    <packaging>pom</packaging>
                    <modules><module>mixed</module><module>batch</module></modules>
                </project>
                """);
        writeDeployableModulePomWithStarters(
                "mixed",
                java.util.List.of("spring-boot-starter-web", "spring-boot-starter-webflux"));
        writeDeployableModulePom("batch", "spring-boot-starter-batch");
        writeApplicationModule("mixed", "MixedApplication", "MixedService");
        writeApplicationModule("batch", "BatchApplication", "BatchService");

        var result =
                analyzer.analyze(
                        new GitRepositoryReference(
                                "https://github.com/example/mixed-services.git", "main"),
                        tempDir,
                        "workspace-mixed");

        assertThat(result.findings())
                .filteredOn(
                        finding ->
                                FindingRules.SPRING_MIXED_MVC_AND_WEBFLUX
                                        .ruleId()
                                        .equals(finding.ruleId()))
                .singleElement()
                .satisfies(
                        finding -> {
                            assertThat(finding.sourceFile()).contains("mixed/src/main/java");
                            assertThat(finding.evidence()).contains("Module mixed:");
                            assertThat(finding.evidence()).doesNotContain("Module batch:");
                        });
    }

    @Test
    void dependencyOverlayProvidesSemanticContractsButNotBehavioralEnablement() throws IOException {
        Files.writeString(
                tempDir.resolve("pom.xml"),
                """
                <project>
                    <parent>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-parent</artifactId>
                        <version>3.5.13</version>
                    </parent>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>spring-boot-starter-batch</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);
        Path primarySources =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/target"));
        Files.writeString(
                primarySources.resolve("TargetApplication.java"),
                """
                package com.example.target;

                import org.springframework.boot.autoconfigure.SpringBootApplication;

                @SpringBootApplication
                public class TargetApplication {}
                """);
        Files.writeString(
                primarySources.resolve("TargetJob.java"),
                """
                package com.example.target;

                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;

                @Component
                class TargetJob {
                    @Scheduled(fixedDelay = 1000)
                    void run() {}
                }
                """);
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(resources.resolve("application.properties"), "service.message=hello\n");

        Path dependencySources =
                Files.createDirectories(
                        tempDir.resolve(
                                "_springmaster_deps/shared/src/main/java/com/example/shared"));
        Files.writeString(
                dependencySources.resolve("ServiceProperties.java"),
                """
                package com.example.shared;

                import org.springframework.boot.context.properties.ConfigurationProperties;

                @ConfigurationProperties("service")
                public record ServiceProperties(String message) {}
                """);
        Files.writeString(
                dependencySources.resolve("DependencyConfiguration.java"),
                """
                package com.example.shared;

                import org.springframework.boot.autoconfigure.SpringBootApplication;
                import org.springframework.scheduling.annotation.EnableScheduling;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @SpringBootApplication
                @EnableScheduling
                @RestController
                class DependencyConfiguration {
                    @GetMapping("/dependency")
                    String dependency() { return "dependency"; }
                }
                """);

        var result =
                analyzer.analyze(
                        new GitRepositoryReference("https://github.com/example/target.git", "main"),
                        tempDir,
                        "workspace-overlay");

        assertThat(result.mainApplicationClasses())
                .containsExactly("com.example.target.TargetApplication");
        assertThat(result.schedulingAnalysis().enableSchedulingPresent()).isFalse();
        assertThat(result.httpSurfaceAnalysis().inboundEndpoints()).isEmpty();
        assertThat(result.findings())
                .extracting(finding -> finding.ruleId())
                .contains(FindingRules.SPRING_SCHEDULED_WITHOUT_ENABLE_SCHEDULING.ruleId());
        assertThat(result.configurationAnalysis().properties())
                .filteredOn(property -> property.name().equals("service.message"))
                .singleElement()
                .satisfies(
                        property ->
                                assertThat(property.kind())
                                        .isEqualTo(
                                                com.robbanhoglund.springbootanalyzer.analyzer.model
                                                        .configuration.PropertyKind
                                                        .CUSTOM_CONFIGURATION_PROPERTIES));
        assertThat(result.findings())
                .filteredOn(finding -> "CONFIG_UNKNOWN_PROPERTY".equals(finding.ruleId()))
                .extracting(finding -> finding.evidence())
                .noneMatch(evidence -> evidence != null && evidence.contains("service.message"));
    }

    private void writeDeployableModulePom(String moduleName, String starter) throws IOException {
        writeDeployableModulePom(moduleName, starter, "3.5.13", "25");
    }

    private void writeDeployableModulePom(
            String moduleName, String starter, String bootVersion, String javaVersion)
            throws IOException {
        Path moduleRoot = Files.createDirectories(tempDir.resolve(moduleName));
        Files.writeString(
                moduleRoot.resolve("pom.xml"),
                """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <parent>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-parent</artifactId>
                        <version>%s</version>
                    </parent>
                    <artifactId>%s</artifactId>
                    <properties><java.version>%s</java.version></properties>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>%s</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """
                        .formatted(bootVersion, moduleName, javaVersion, starter));
    }

    private void writeDeployableModulePomWithStarters(
            String moduleName, java.util.List<String> starters) throws IOException {
        String dependencies =
                starters.stream()
                        .map(
                                starter ->
                                        """
                                        <dependency>
                                            <groupId>org.springframework.boot</groupId>
                                            <artifactId>%s</artifactId>
                                        </dependency>
                                        """
                                                .formatted(starter))
                        .collect(java.util.stream.Collectors.joining());
        Path moduleRoot = Files.createDirectories(tempDir.resolve(moduleName));
        Files.writeString(
                moduleRoot.resolve("pom.xml"),
                """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <parent>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-parent</artifactId>
                        <version>3.5.13</version>
                    </parent>
                    <artifactId>%s</artifactId>
                    <properties><java.version>25</java.version></properties>
                    <dependencies>%s</dependencies>
                </project>
                """
                        .formatted(moduleName, dependencies));
    }

    private void writeApplicationModule(
            String moduleName, String applicationClass, String serviceClass) throws IOException {
        Path sourceRoot =
                Files.createDirectories(
                        tempDir.resolve(moduleName + "/src/main/java/com/example/" + moduleName));
        Files.writeString(
                sourceRoot.resolve(applicationClass + ".java"),
                """
                package com.example.%s;

                import org.springframework.boot.autoconfigure.SpringBootApplication;

                @SpringBootApplication
                public class %s {}
                """
                        .formatted(moduleName, applicationClass));
        Files.writeString(
                sourceRoot.resolve(serviceClass + ".java"),
                """
                package com.example.%s;

                import org.springframework.stereotype.Service;

                @Service
                class %s {}
                """
                        .formatted(moduleName, serviceClass));
    }

    private void writeController(String moduleName, String controllerClass, String path)
            throws IOException {
        Path sourceRoot = tempDir.resolve(moduleName + "/src/main/java/com/example/" + moduleName);
        Files.writeString(
                sourceRoot.resolve(controllerClass + ".java"),
                """
                package com.example.%s;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class %s {
                    @GetMapping("%s")
                    String value() { return "ok"; }
                }
                """
                        .formatted(moduleName, controllerClass, path));
    }

    private void writeModuleProperty(String moduleName, String content) throws IOException {
        Path resources =
                Files.createDirectories(tempDir.resolve(moduleName + "/src/main/resources"));
        Files.writeString(resources.resolve("application.properties"), content);
    }

    private void writeModulePom(String moduleName) throws IOException {
        Path moduleRoot = Files.createDirectories(tempDir.resolve(moduleName));
        Files.writeString(
                moduleRoot.resolve("pom.xml"),
                """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <parent>
                        <groupId>com.example</groupId>
                        <artifactId>multi-parent</artifactId>
                        <version>1.0.0</version>
                        <relativePath>../pom.xml</relativePath>
                    </parent>
                    <artifactId>%s</artifactId>
                </project>
                """
                        .formatted(moduleName));
    }
}

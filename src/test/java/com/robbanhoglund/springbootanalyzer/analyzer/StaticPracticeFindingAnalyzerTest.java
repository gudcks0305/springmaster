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
import com.robbanhoglund.springbootanalyzer.analyzer.http.HttpSurfaceAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildInfo;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildTool;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingCategory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRuntimeDetection;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingSeverity;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleAnalysisStatus;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleModelAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.RuntimeStackAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.WebStack;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StaticPracticeFindingAnalyzerTest {

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
    private final JavaSourceAnalyzer javaSourceAnalyzer = new JavaSourceAnalyzer();
    private final HttpSurfaceAnalyzer httpSurfaceAnalyzer = new HttpSurfaceAnalyzer();
    private final StaticPracticeFindingAnalyzer analyzer = new StaticPracticeFindingAnalyzer();
    private final ConfigurationFindingAnalyzer configurationFindingAnalyzer =
            new ConfigurationFindingAnalyzer();
    private final ObservabilityFindingAnalyzer observabilityFindingAnalyzer =
            new ObservabilityFindingAnalyzer();

    @TempDir Path tempDir;

    @Test
    void emitsRichStaticFindingsForPrioritizedPracticeRisks() throws IOException {
        writeFixtureProject(tempDir);

        BuildInfo buildInfo =
                new BuildInfo(
                        BuildTool.GRADLE,
                        true,
                        "25",
                        List.of(
                                "org.springframework.boot:spring-boot-starter-web",
                                "org.springframework.boot:spring-boot-starter-data-jpa",
                                "org.flywaydb:flyway-core:11.20.3"),
                        "3.5.13",
                        "build.gradle plugin",
                        "HIGH");

        var configurationResult = configurationAnalyzer.analyze(tempDir, buildInfo);
        var sourceAnalysis = javaSourceAnalyzer.analyze(tempDir);
        HttpSurfaceAnalyzer.Result httpResult =
                httpSurfaceAnalyzer.analyze(
                        tempDir,
                        configurationResult.configurationAnalysis(),
                        buildInfo,
                        WebStack.SERVLET_MVC);

        var gradleAnalysis =
                GradleModelAnalysis.empty(
                        GradleAnalysisStatus.NOT_REQUESTED, "TOOLING_API", List.of());
        var runtimeAnalysis =
                new RuntimeStackAnalysis(
                        "3.5.13",
                        "build.gradle",
                        "25",
                        WebStack.SERVLET_MVC,
                        "Static servlet signals",
                        null,
                        "com.example.demo.DemoApplication");
        List<Finding> findings =
                java.util.stream.Stream.of(
                                analyzer.analyze(
                                        tempDir,
                                        buildInfo,
                                        configurationResult.configurationAnalysis(),
                                        gradleAnalysis,
                                        runtimeAnalysis,
                                        httpResult.httpSurfaceAnalysis(),
                                        sourceAnalysis.detectedClasses()),
                                configurationFindingAnalyzer.analyze(
                                        tempDir,
                                        buildInfo,
                                        configurationResult.configurationAnalysis(),
                                        gradleAnalysis),
                                observabilityFindingAnalyzer.analyze(tempDir, runtimeAnalysis))
                        .flatMap(java.util.Collection::stream)
                        .toList();

        assertRichFinding(
                findings,
                FindingRules.SPRING_SECRET_MULTI_PROFILE.ruleId(),
                FindingCategory.SECURITY,
                FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);
        assertRichFinding(
                findings,
                FindingRules.SPRING_PROFILE_DRIFT.ruleId(),
                FindingCategory.PROFILE_DRIFT,
                FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);
        assertRichFinding(
                findings,
                FindingRules.SPRING_CONDITIONAL_VALUE_MISMATCH.ruleId(),
                FindingCategory.CONDITIONAL_BEAN,
                FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);
        assertRichFinding(
                findings,
                FindingRules.SPRING_FLYWAY_DDL_AUTO_MIX.ruleId(),
                FindingCategory.PERSISTENCE,
                FindingRuntimeDetection.NOT_NORMALLY_DETECTED);
        assertRichFinding(
                findings,
                FindingRules.SPRING_STARTUP_SIDE_EFFECT.ruleId(),
                FindingCategory.STARTUP,
                FindingRuntimeDetection.NOT_NORMALLY_DETECTED);
        assertRichFinding(
                findings,
                FindingRules.SPRING_SCHEDULED_SIDE_EFFECT.ruleId(),
                FindingCategory.SCHEDULING,
                FindingRuntimeDetection.NOT_NORMALLY_DETECTED);
        assertRichFinding(
                findings,
                FindingRules.SPRING_HTTP_CLIENT_NO_TIMEOUT.ruleId(),
                FindingCategory.HTTP,
                FindingRuntimeDetection.NOT_NORMALLY_DETECTED);
        assertRichFinding(
                findings,
                FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId(),
                FindingCategory.TRANSACTION,
                FindingRuntimeDetection.NOT_NORMALLY_DETECTED);
        assertRichFinding(
                findings,
                FindingRules.SPRING_TRANSACTIONAL_ON_PRIVATE_METHOD.ruleId(),
                FindingCategory.TRANSACTION,
                FindingRuntimeDetection.NOT_NORMALLY_DETECTED);
        assertRichFinding(
                findings,
                FindingRules.SPRING_REQUEST_BODY_NO_VALID.ruleId(),
                FindingCategory.VALIDATION,
                FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

        assertThat(findings)
                .extracting(Finding::target)
                .contains("trading.provider", "schema management");
        assertThat(findings)
                .allMatch(
                        finding ->
                                finding.message() == null
                                        || !finding.message().contains("super-secret"));
    }

    @Test
    void configurationAnalyzerProducesRedactedEducationalFindingsForSensitiveAndRiskyConfig()
            throws IOException {
        writeFixtureProject(tempDir);

        BuildInfo buildInfo =
                new BuildInfo(
                        BuildTool.GRADLE,
                        true,
                        "25",
                        List.of("org.springframework.boot:spring-boot-starter-data-jpa"),
                        "3.5.13",
                        "build.gradle plugin",
                        "HIGH");

        var result = configurationAnalyzer.analyze(tempDir, buildInfo);

        Finding secretFinding =
                result.findings().stream()
                        .filter(
                                finding ->
                                        FindingRules.SPRING_SECRET_LITERAL
                                                .ruleId()
                                                .equals(finding.ruleId()))
                        .findFirst()
                        .orElseThrow();
        assertThat(secretFinding.category()).isEqualTo(FindingCategory.SECURITY);
        assertThat(secretFinding.runtimeDetection())
                .isEqualTo(FindingRuntimeDetection.NOT_NORMALLY_DETECTED);
        assertThat(secretFinding.confidence()).isEqualTo(FindingConfidence.HIGH);
        assertThat(secretFinding.whyBadPractice()).isNotBlank();
        assertThat(secretFinding.possibleImpact()).isNotBlank();
        assertThat(secretFinding.recommendation()).isNotBlank();
        assertThat(secretFinding.evidence())
                .contains("trading.api-secret")
                .doesNotContain("super-secret");

        // ddl-auto/actuator-wildcard are reported by their dedicated rules; the generic
        // risky-prod-config rule still covers health.show-details=always.
        Finding riskyFinding =
                result.findings().stream()
                        .filter(
                                finding ->
                                        FindingRules.SPRING_RISKY_PROD_CONFIG
                                                .ruleId()
                                                .equals(finding.ruleId()))
                        .findFirst()
                        .orElse(null);
        if (riskyFinding != null) {
            assertThat(riskyFinding.category()).isEqualTo(FindingCategory.CONFIGURATION);
            assertThat(riskyFinding.whyBadPractice()).isNotBlank();
            assertThat(riskyFinding.recommendation()).isNotBlank();
        }
    }

    @Test
    void doesNotTreatHttpClientBuildersAsConstructorSideEffects() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ClientHolder.java"),
"""
package com.example.demo;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

@Component
class ClientHolder {

    private final RestClient restClient;
    private final WebClient webClient;

    ClientHolder() {
        this.restClient = RestClient.builder().baseUrl("https://api.example.com").build();
        this.webClient = WebClient.builder().baseUrl("https://api.example.com").build();
    }
}
""");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_STARTUP_SIDE_EFFECT
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && (finding.target() != null
                                                && finding.target().contains("ClientHolder")));
    }

    @Test
    void flagsRealConstructorSideEffectsAndFiltersValidationNoise() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("StartupBean.java"),
"""
package com.example.demo;

import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import jakarta.validation.constraints.NotBlank;

@Component
class StartupBean {
    StartupBean() throws Exception {
        RestClient.create().get().uri("https://api.example.com").retrieve().body(String.class);
        Files.writeString(Path.of("marker.txt"), "hello");
    }
}

@RestController
class ApiController {
    @PostMapping("/typed")
    void typed(@RequestBody CreateRequest request) {
    }

    @PostMapping("/raw")
    void raw(@RequestBody java.util.Map<String, Object> payload) {
    }
}

record CreateRequest(@NotBlank String symbol, int quantity) {
}
""");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_STARTUP_SIDE_EFFECT
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.evidence() != null
                                        && finding.evidence().contains("outbound HTTP execution"));
        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_REQUEST_BODY_NO_VALID
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() != null
                                        && finding.severity().name().equals("INFO")
                                        && finding.evidence() != null
                                        && finding.evidence().contains("CreateRequest"));
        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_REQUEST_BODY_NO_VALID
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.evidence() != null
                                        && finding.evidence().contains("payload"));
    }

    @Test
    void avoidsMissingTransactionBoundaryForSingleRepositoryWrite() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("RepositoryAndService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Repository;
                import org.springframework.stereotype.Service;

                @Repository
                class OrderRepository {
                    void upsert() {
                        update();
                    }

                    void update() {
                    }
                }

                @Service
                class OrderService {
                    private final OrderRepository orderRepository = new OrderRepository();

                    void store() {
                        orderRepository.upsert();
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-data-jpa")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_TRANSACTION_MISSING_BOUNDARY
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void ignoresTransactionTemplateAndFlagsMultiWriteWithoutBoundary() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("TransactionalExamples.java"),
                """
                package com.example.demo;

                import org.springframework.jdbc.core.JdbcTemplate;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.support.TransactionTemplate;

                @Service
                class TransactionalExamples {
                    private final JdbcTemplate jdbcTemplate = null;
                    private final TransactionTemplate transactionTemplate = null;

                    void withTemplate() {
                        transactionTemplate.execute(status -> {
                            jdbcTemplate.update("update a set v=1");
                            jdbcTemplate.update("update b set v=2");
                            return null;
                        });
                    }

                    void withoutBoundary() {
                        jdbcTemplate.update("update a set v=1");
                        jdbcTemplate.update("update b set v=2");
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-jdbc")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_TRANSACTION_MISSING_BOUNDARY
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.target() != null
                                        && finding.target().contains("withTemplate"));
        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_TRANSACTION_MISSING_BOUNDARY
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() != null
                                        && finding.severity().name().equals("INFO")
                                        && finding.target() != null
                                        && finding.target().contains("withoutBoundary"));
    }

    @Test
    void downgradesNonPersistenceSideEffectOrchestrationToMaintainability() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("AnalyzerWorkflowService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;

                @Service
                class AnalyzerWorkflowService {
                    void runWorkflow() {
                        reportStore.save();
                        notificationClient.send();
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_SIDE_EFFECT_ORCHESTRATION_NO_BOUNDARY
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.category() == FindingCategory.MAINTAINABILITY
                                        && finding.message() != null
                                        && finding.message()
                                                .contains("Potential side-effect orchestration"));
        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_TRANSACTION_MISSING_BOUNDARY
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.target() != null
                                        && finding.target().contains("runWorkflow"));
    }

    @Test
    void doesNotFlagTransactionalMultiWriteMethod() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("TransactionalService.java"),
                """
                package com.example.demo;

                import org.springframework.jdbc.core.JdbcTemplate;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class TransactionalService {
                    private final JdbcTemplate jdbcTemplate = null;

                    @Transactional
                    void updateBoth() {
                        jdbcTemplate.update("update a set v=1");
                        jdbcTemplate.update("update b set v=2");
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-jdbc")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_TRANSACTION_MISSING_BOUNDARY
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void doesNotFlagSelfInvocationForCallOnCollaboratorBean() throws IOException {
        // A call qualified by an injected collaborator (orders.save()) targets a different bean,
        // even though this class also declares a @Transactional method named save(). It must not
        // be reported as self-invocation.
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    private final OrderRepository orders = null;

                    public void handle() {
                        orders.save();
                    }

                    @Transactional
                    public void save() {}
                }

                interface OrderRepository {
                    void save();
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void flagsEligibleMethodLevelTransactionalSelfInvocation() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    public void handle() {
                        save();
                    }

                    @Transactional(propagation = Propagation.REQUIRES_NEW)
                    public void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId());
    }

    @Test
    void doesNotFlagPlainRequiredSelfInvocationFromUnannotatedCaller() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    public void handle() {
                        save();
                    }

                    @Transactional
                    public void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId());
    }

    @Test
    void doesNotFlagClassLevelTransactionalPrivateHelperCall() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("KeyService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                @Transactional
                class KeyService {
                    public String load() {
                        return buildKey();
                    }

                    private String buildKey() {
                        return "key";
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId());
    }

    @Test
    void reportsPrivateTransactionalMethodWithoutDuplicateSelfInvocation() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    public void handle() {
                        save();
                    }

                    @Transactional
                    private void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TRANSACTIONAL_ON_PRIVATE_METHOD.ruleId())
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId());
    }

    @Test
    void doesNotFlagTransactionalOverloadWithDifferentArity() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    public void handle() {
                        save();
                    }

                    @Transactional
                    public void save(String id) {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId());
    }

    @Test
    void doesNotFlagDefaultTransactionalCalleeWhenCallerAlreadyTransactional() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    @Transactional
                    public void handle() {
                        save();
                    }

                    @Transactional
                    public void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId());
    }

    @Test
    void flagsRequiresNewSelfInvocationFromTransactionalCaller() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    @Transactional
                    public void handle() {
                        saveAudit();
                    }

                    @Transactional(propagation = Propagation.REQUIRES_NEW)
                    public void saveAudit() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId());
    }

    @Test
    void flagsDefaultTransactionalCalleeFromNotSupportedCaller() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    @Transactional(propagation = Propagation.NOT_SUPPORTED)
                    public void handle() {
                        save();
                    }

                    @Transactional
                    public void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId());
    }

    @Test
    void flagsClassLevelTransactionalTargetFromNotSupportedOverride() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                @Transactional
                class OrderService {
                    @Transactional(propagation = Propagation.NOT_SUPPORTED)
                    public void handle() {
                        save();
                    }

                    public void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId());
    }

    @Test
    void doesNotFlagNormalClassLevelPublicHelperCall() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                @Transactional
                class OrderService {
                    public void handle() {
                        save();
                    }

                    public void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_SELF_INVOCATION.ruleId());
    }

    @Test
    void respectsValidRequestBodyAnnotations() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ValidatedController.java"),
                """
                package com.example.demo;

                import jakarta.validation.Valid;
                import jakarta.validation.constraints.NotBlank;
                import org.springframework.web.bind.annotation.PostMapping;
                import org.springframework.web.bind.annotation.RequestBody;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class ValidatedController {
                    @PostMapping("/typed")
                    void typed(@Valid @RequestBody CreateRequest request) {
                    }

                    @PostMapping("/raw")
                    void raw(@RequestBody String payload) {
                    }
                }

                record CreateRequest(@NotBlank String symbol) {
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_REQUEST_BODY_NO_VALID
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void doesNotTreatRegexCompilationAsConstructorSideEffect() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("RegexHolder.java"),
                """
                package com.example.demo;

                import java.util.regex.Pattern;
                import org.springframework.stereotype.Component;

                @Component
                class RegexHolder {
                    private final Pattern pattern;

                    RegexHolder() {
                        this.pattern = Pattern.compile("^[A-Z]+$");
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_STARTUP_SIDE_EFFECT
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.target() != null
                                        && finding.target().contains("RegexHolder"));
    }

    @Test
    void flagsEmptyCatchBlocksAndCommentOnlyCatchBlocks() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("EmptyCatchExample.java"),
                """
                package com.example.demo;

                import java.io.IOException;

                class EmptyCatchExample {
                    void run() {
                        try {
                            work();
                        } catch (Exception e) {
                        }
                    }

                    void commentOnly() {
                        try {
                            work();
                        } catch (IOException e) {
                            // TODO
                        }
                    }

                    void work() {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        List<Finding> emptyCatchFindings =
                findings.stream()
                        .filter(
                                finding ->
                                        FindingRules.JAVA_EMPTY_CATCH_BLOCK
                                                .ruleId()
                                                .equals(finding.ruleId()))
                        .toList();

        assertThat(emptyCatchFindings).hasSize(2);
        assertThat(emptyCatchFindings)
                .anySatisfy(
                        finding -> {
                            assertThat(finding.severity()).isEqualTo(FindingSeverity.WARNING);
                            assertThat(finding.confidence()).isEqualTo(FindingConfidence.HIGH);
                            assertThat(finding.primaryLocation()).isNotNull();
                            assertThat(finding.highlightRanges()).isNotEmpty();
                            assertThat(finding.primaryLocation().startLine())
                                    .isLessThanOrEqualTo(finding.primaryLocation().endLine());
                        })
                .anySatisfy(
                        finding -> {
                            assertThat(finding.severity()).isEqualTo(FindingSeverity.WARNING);
                            assertThat(finding.confidence()).isEqualTo(FindingConfidence.MEDIUM);
                            assertThat(finding.evidence()).contains("Catch block for IOException");
                        });
    }

    @Test
    void skipsIntentionalIgnoredCleanupCatch() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("CleanupExample.java"),
                """
                package com.example.demo;

                import java.io.IOException;

                class CleanupExample {
                    void closeQuietly() {
                        try {
                            work();
                        } catch (IOException ignored) {
                            // Best effort cleanup; close failure is ignored intentionally.
                        }
                    }

                    void work() {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.JAVA_EMPTY_CATCH_BLOCK
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void flagsSwallowedFallbackInterruptedAndPrintStackTracePatterns() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import java.util.Optional;
                import org.springframework.stereotype.Service;

                @Service
                class OrderService {
                    Optional<String> load() {
                        try {
                            return Optional.of("ok");
                        } catch (Exception e) {
                            return Optional.empty();
                        }
                    }

                    void waitForSignal() {
                        try {
                            Thread.sleep(5);
                        } catch (InterruptedException e) {
                            logWarn(e);
                        }
                    }

                    void printFailure() {
                        try {
                            fail();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }

                    void fail() {
                    }

                    void logWarn(Exception e) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_SWALLOWED_EXCEPTION_FALLBACK
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && "com.example.demo.OrderService#load"
                                                .equals(finding.target())
                                        && finding.primaryLocation() != null
                                        && finding.primaryLocation().endLine()
                                                >= finding.primaryLocation().startLine()
                                        && !finding.highlightRanges().isEmpty());
        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_INTERRUPTED_EXCEPTION_SWALLOWED
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.recommendation() != null
                                        && finding.recommendation()
                                                .contains("Thread.currentThread().interrupt()"));
        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_PRINT_STACK_TRACE
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && "com.example.demo.OrderService#printFailure"
                                                .equals(finding.target()));
    }

    @Test
    void doesNotFlagProperInterruptedExceptionHandling() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("InterruptAwareJob.java"),
                """
                package com.example.demo;

                class InterruptAwareJob {
                    void run() {
                        try {
                            Thread.sleep(5);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_INTERRUPTED_EXCEPTION_SWALLOWED
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void flagsRawExceptionMessageReturnedFromController() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ApiController.java"),
                """
                package com.example.demo;

                import org.springframework.http.ResponseEntity;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class ApiController {
                    @GetMapping("/x")
                    ResponseEntity<String> get() {
                        try {
                            return ResponseEntity.ok("ok");
                        } catch (Exception e) {
                            return ResponseEntity.status(500).body(e.getMessage());
                        }
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_RAW_EXCEPTION_MESSAGE_HTTP
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.category() == FindingCategory.SECURITY
                                        && finding.evidence() != null
                                        && finding.evidence().contains("body(e.getMessage())")
                                        && "com.example.demo.ApiController#get"
                                                .equals(finding.target()));
    }

    @Test
    void flagsBroadSpringExceptionHandler() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("GlobalErrors.java"),
                """
                package com.example.demo;

                import org.springframework.http.ResponseEntity;
                import org.springframework.web.bind.annotation.ExceptionHandler;
                import org.springframework.web.bind.annotation.RestControllerAdvice;

                @RestControllerAdvice
                class GlobalErrors {
                    @ExceptionHandler(Exception.class)
                    ResponseEntity<String> handle(Exception ex) {
                        return ResponseEntity.status(500).body("nope");
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_BROAD_EXCEPTION_HANDLER
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && finding.category() == FindingCategory.EXCEPTION_HANDLING
                                        && finding.runtimeDetection()
                                                == FindingRuntimeDetection.NOT_NORMALLY_DETECTED);
    }

    @Test
    void warnsWhenBroadSpringExceptionHandlerMapsToBadRequest() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("GlobalErrors.java"),
                """
                package com.example.demo;

                import org.springframework.http.ResponseEntity;
                import org.springframework.web.bind.annotation.ExceptionHandler;
                import org.springframework.web.bind.annotation.RestControllerAdvice;

                @RestControllerAdvice
                class GlobalErrors {
                    @ExceptionHandler(Exception.class)
                    ResponseEntity<String> handle(Exception ex) {
                        return ResponseEntity.badRequest().body("invalid");
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_BROAD_EXCEPTION_HANDLER
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.evidence() != null
                                        && finding.evidence().contains("HTTP 400-style response"));
    }

    @Test
    void downgradesParserFallbackToInfo() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ParserHelper.java"),
                """
                package com.example.demo;

                class ParserHelper {
                    Integer parseAmount(String value) {
                        try {
                            return Integer.valueOf(value);
                        } catch (NumberFormatException ignored) {
                            return null;
                        }
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_SWALLOWED_EXCEPTION_FALLBACK
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && finding.whyBadPractice() != null
                                        && finding.whyBadPractice().contains("best-effort parsing")
                                        && "com.example.demo.ParserHelper#parseAmount"
                                                .equals(finding.target()));
    }

    @Test
    void warnsOnBroadCatchFallbackOutsideParserHelpers() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Worker.java"),
                """
                package com.example.demo;

                class Worker {
                    String loadValue() {
                        try {
                            return work();
                        } catch (Exception ignored) {
                            return "";
                        }
                    }

                    String work() {
                        return "ok";
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_SWALLOWED_EXCEPTION_FALLBACK
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.evidence() != null
                                        && finding.evidence().contains("return \"\"")
                                        && "com.example.demo.Worker#loadValue"
                                                .equals(finding.target()));
    }

    @Test
    void emitsRepeatedFallbackParsingPatternWhenParserFallbacksRepeat() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ParserA.java"),
                """
                package com.example.demo;

                class ParserA {
                    Integer parseAmount(String value) {
                        try {
                            return Integer.valueOf(value);
                        } catch (NumberFormatException ignored) {
                            return null;
                        }
                    }
                }
                """);
        Files.writeString(
                sourceRoot.resolve("ParserB.java"),
                """
                package com.example.demo;

                class ParserB {
                    Integer parseCount(String value) {
                        try {
                            return Integer.valueOf(value);
                        } catch (NumberFormatException ignored) {
                            return null;
                        }
                    }
                }
                """);
        Files.writeString(
                sourceRoot.resolve("ParserC.java"),
                """
                package com.example.demo;

                class ParserC {
                    Integer parseLimit(String value) {
                        try {
                            return Integer.valueOf(value);
                        } catch (NumberFormatException ignored) {
                            return null;
                        }
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_REPEATED_FALLBACK_PARSING_PATTERN
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.category() == FindingCategory.MAINTAINABILITY
                                        && finding.severity() == FindingSeverity.INFO
                                        && finding.message() != null
                                        && finding.message()
                                                .contains(
                                                        "Similar parse/fallback exception handling"
                                                                + " appears in multiple classes"));
    }

    private void writeFixtureProject(Path root) throws IOException {
        Files.createDirectories(root.resolve("src/main/resources"));
        Files.writeString(
                root.resolve("src/main/resources/application.properties"),
                """
                trading.provider=stub
                trading.api-secret=super-secret
                spring.flyway.enabled=true
                client.base-url=https://api.example.com
                spring.datasource.url=jdbc:postgresql://localhost:5432/demo
                """);
        Files.writeString(
                root.resolve("src/main/resources/application-prod.properties"),
                """
                trading.provider=real
                trading.api-secret=prod-secret
                spring.jpa.hibernate.ddl-auto=update
                """);

        Path sourceRoot = Files.createDirectories(root.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("DemoApplication.java"),
                """
                package com.example.demo;

                import org.springframework.boot.autoconfigure.SpringBootApplication;
                import org.springframework.scheduling.annotation.EnableScheduling;

                @SpringBootApplication
                @EnableScheduling
                class DemoApplication {
                }
                """);
        Files.writeString(
                sourceRoot.resolve("ProviderConfig.java"),
"""
package com.example.demo;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class ProviderConfig {

    @Bean
    @ConditionalOnProperty(prefix = "trading", name = "provider", havingValue = "stub", matchIfMissing = true)
    Object stubProvider() {
        return new Object();
    }

    @Bean
    @ConditionalOnProperty(prefix = "trading", name = "provider", havingValue = "alpaca")
    Object alpacaProvider() {
        return new Object();
    }
}
""");
        Files.writeString(
                sourceRoot.resolve("StartupSyncRunner.java"),
"""
package com.example.demo;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
class StartupSyncRunner implements CommandLineRunner {

    private final RestTemplate restTemplate = new RestTemplate();
    private final OrderRepository orderRepository = new OrderRepository();

    @Override
    public void run(String... args) {
        restTemplate.getForObject("https://api.example.com/bootstrap", String.class);
        orderRepository.save(new Object());
    }
}
""");
        Files.writeString(
                sourceRoot.resolve("PriceRefreshJob.java"),
"""
package com.example.demo;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
class PriceRefreshJob {

    private final RestTemplate restTemplate = new RestTemplate();

    @Scheduled(fixedRate = 5000)
    void refreshPrices() {
        restTemplate.postForObject("https://api.example.com/prices/refresh", null, String.class);
    }
}
""");
        Files.writeString(
                sourceRoot.resolve("TradingService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class TradingService {

                    private final OrderRepository orderRepository = new OrderRepository();
                    private final JdbcGateway jdbcGateway = new JdbcGateway();

                    void processOrders() {
                        this.persistOrder();
                        this.persistBatch();
                    }

                    void applyWrites() {
                        orderRepository.save(new Object());
                        jdbcGateway.update("update orders set status='DONE'");
                    }

                    @Transactional
                    private void persistOrder() {
                        orderRepository.save(new Object());
                    }

                    @Transactional(propagation = Propagation.REQUIRES_NEW)
                    public void persistBatch() {
                        orderRepository.save(new Object());
                    }
                }
                """);
        Files.writeString(
                sourceRoot.resolve("TradingController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.PostMapping;
                import org.springframework.web.bind.annotation.RequestBody;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class TradingController {

                    @PostMapping("/orders")
                    void create(@RequestBody CreateOrderRequest request) {
                    }
                }
                """);
        Files.writeString(
                sourceRoot.resolve("ExternalApiClient.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Component;
                import org.springframework.web.reactive.function.client.WebClient;

                @Component
                class ExternalApiClient {

                    private final WebClient client = WebClient.builder()
                            .baseUrl("https://api.example.com")
                            .build();

                    void send() {
                        client.post().uri("/orders");
                    }
                }
                """);
        Files.writeString(
                sourceRoot.resolve("SupportTypes.java"),
                """
                package com.example.demo;

                class OrderRepository {
                    void save(Object value) {
                    }
                }

                class JdbcGateway {
                    void update(String sql) {
                    }
                }

                record CreateOrderRequest(String symbol, int quantity) {
                }
                """);
    }

    /**
     * Combines findings from both StaticPracticeFindingAnalyzer and HttpSurfaceAnalyzer.
     * Use when the rule under test is emitted by the HTTP surface analyzer (e.g. SPRING_HTTP_PLAIN_URL).
     */
    private List<Finding> analyzeAllFindings(Path repositoryRoot, BuildInfo buildInfo) {
        var configurationResult = configurationAnalyzer.analyze(repositoryRoot, buildInfo);
        var sourceAnalysis = javaSourceAnalyzer.analyze(repositoryRoot);
        HttpSurfaceAnalyzer.Result httpResult =
                httpSurfaceAnalyzer.analyze(
                        repositoryRoot,
                        configurationResult.configurationAnalysis(),
                        buildInfo,
                        WebStack.SERVLET_MVC);
        var gradleAnalysis =
                GradleModelAnalysis.empty(
                        GradleAnalysisStatus.NOT_REQUESTED, "TOOLING_API", List.of());
        var runtimeAnalysis =
                new RuntimeStackAnalysis(
                        "3.5.13",
                        "build.gradle",
                        "25",
                        WebStack.SERVLET_MVC,
                        "Static servlet signals",
                        null,
                        "com.example.demo.DemoApplication");
        List<Finding> staticFindings =
                analyzer.analyze(
                        repositoryRoot,
                        buildInfo,
                        configurationResult.configurationAnalysis(),
                        gradleAnalysis,
                        runtimeAnalysis,
                        httpResult.httpSurfaceAnalysis(),
                        sourceAnalysis.detectedClasses());
        List<Finding> configFindings =
                configurationFindingAnalyzer.analyze(
                        repositoryRoot,
                        buildInfo,
                        configurationResult.configurationAnalysis(),
                        gradleAnalysis);
        List<Finding> observabilityFindings =
                observabilityFindingAnalyzer.analyze(
                        com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources.from(
                                repositoryRoot),
                        runtimeAnalysis,
                        buildInfo);
        return java.util.stream.Stream.of(
                        staticFindings,
                        httpResult.findings(),
                        configFindings,
                        observabilityFindings)
                .flatMap(java.util.Collection::stream)
                .toList();
    }

    private List<Finding> analyzeStaticPractice(Path repositoryRoot, BuildInfo buildInfo) {
        var configurationResult = configurationAnalyzer.analyze(repositoryRoot, buildInfo);
        var sourceAnalysis = javaSourceAnalyzer.analyze(repositoryRoot);
        HttpSurfaceAnalyzer.Result httpResult =
                httpSurfaceAnalyzer.analyze(
                        repositoryRoot,
                        configurationResult.configurationAnalysis(),
                        buildInfo,
                        WebStack.SERVLET_MVC);
        var gradleAnalysis =
                GradleModelAnalysis.empty(
                        GradleAnalysisStatus.NOT_REQUESTED, "TOOLING_API", List.of());
        var runtimeAnalysis =
                new RuntimeStackAnalysis(
                        "3.5.13",
                        "build.gradle",
                        "25",
                        WebStack.SERVLET_MVC,
                        "Static servlet signals",
                        null,
                        "com.example.demo.DemoApplication");
        List<Finding> staticFindings =
                analyzer.analyze(
                        repositoryRoot,
                        buildInfo,
                        configurationResult.configurationAnalysis(),
                        gradleAnalysis,
                        runtimeAnalysis,
                        httpResult.httpSurfaceAnalysis(),
                        sourceAnalysis.detectedClasses());
        List<Finding> configFindings =
                configurationFindingAnalyzer.analyze(
                        repositoryRoot,
                        buildInfo,
                        configurationResult.configurationAnalysis(),
                        gradleAnalysis);
        List<Finding> observabilityFindings =
                observabilityFindingAnalyzer.analyze(
                        com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources.from(
                                repositoryRoot),
                        runtimeAnalysis,
                        buildInfo);
        return java.util.stream.Stream.of(staticFindings, configFindings, observabilityFindings)
                .flatMap(java.util.Collection::stream)
                .toList();
    }

    private BuildInfo emptyBuildInfo(List<String> dependencies) {
        return new BuildInfo(
                BuildTool.GRADLE,
                true,
                "25",
                dependencies,
                "3.5.13",
                "build.gradle plugin",
                "HIGH");
    }

    private void assertRichFinding(
            List<Finding> findings,
            String ruleId,
            FindingCategory category,
            FindingRuntimeDetection runtimeDetection) {
        Finding finding =
                findings.stream()
                        .filter(candidate -> ruleId.equals(candidate.ruleId()))
                        .findFirst()
                        .orElseThrow();
        assertThat(finding.category()).isEqualTo(category);
        assertThat(finding.runtimeDetection()).isEqualTo(runtimeDetection);
        assertThat(finding.confidence())
                .isIn(FindingConfidence.HIGH, FindingConfidence.MEDIUM, FindingConfidence.LOW);
        assertThat(finding.whyBadPractice()).isNotBlank();
        assertThat(finding.possibleImpact()).isNotBlank();
        assertThat(finding.recommendation()).isNotBlank();
        assertThat(finding.evidence()).isNotBlank();
        assertThat(finding.limitations()).isNotBlank();
    }

    // -------------------------------------------------------------------------
    // Async proxy bypass / swallowed exception
    // -------------------------------------------------------------------------

    @Test
    void flagsAsyncOnPrivateMethod() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("NotificationService.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Async;
                import org.springframework.stereotype.Component;

                @Component
                class NotificationService {
                    @Async
                    private void sendEmail(String to) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_ASYNC_PROXY_BYPASS
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.confidence() == FindingConfidence.HIGH
                                        && "NotificationService#sendEmail".equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagAsyncOnPublicMethod() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("NotificationService.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Async;
                import org.springframework.stereotype.Component;

                @Component
                class NotificationService {
                    @Async
                    public void sendEmail(String to) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_ASYNC_PROXY_BYPASS
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void flagsAsyncVoidMethodWithNoExceptionHandling() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("EmailSender.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Async;
                import org.springframework.stereotype.Component;

                @Component
                class EmailSender {
                    @Async
                    public void send(String payload) {
                        doSend(payload);
                    }

                    void doSend(String payload) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_ASYNC_VOID_SWALLOWED_EXCEPTION
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && "EmailSender#send".equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagAsyncVoidWithTryCatch() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("EmailSender.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Async;
                import org.springframework.stereotype.Component;

                @Component
                class EmailSender {
                    @Async
                    public void send(String payload) {
                        try {
                            doSend(payload);
                        } catch (Exception e) {
                            log(e);
                        }
                    }

                    void doSend(String payload) {
                    }

                    void log(Exception e) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_ASYNC_VOID_SWALLOWED_EXCEPTION
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // Messaging listener without error handling
    // -------------------------------------------------------------------------

    @Test
    void flagsKafkaListenerWithNoExceptionHandling() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderConsumer.java"),
                """
                package com.example.demo;

                import org.springframework.kafka.annotation.KafkaListener;
                import org.springframework.stereotype.Component;

                @Component
                class OrderConsumer {
                    @KafkaListener(topics = "orders")
                    public void consume(String message) {
                        process(message);
                    }

                    void process(String message) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_MESSAGING_LISTENER_NO_ERROR_HANDLER
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && "OrderConsumer#consume".equals(finding.target()));
    }

    @Test
    void flagsRabbitListenerWithNoExceptionHandling() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderConsumer.java"),
                """
                package com.example.demo;

                import org.springframework.amqp.rabbit.annotation.RabbitListener;
                import org.springframework.stereotype.Component;

                @Component
                class OrderConsumer {
                    @RabbitListener(queues = "orders")
                    public void consume(String message) {
                        process(message);
                    }

                    void process(String message) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_MESSAGING_LISTENER_NO_ERROR_HANDLER
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && "OrderConsumer#consume".equals(finding.target()));
    }

    @Test
    void doesNotFlagKafkaListenerWithTryCatch() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderConsumer.java"),
                """
                package com.example.demo;

                import org.springframework.kafka.annotation.KafkaListener;
                import org.springframework.stereotype.Component;

                @Component
                class OrderConsumer {
                    @KafkaListener(topics = "orders")
                    public void consume(String message) {
                        try {
                            process(message);
                        } catch (Exception e) {
                            logError(e);
                        }
                    }

                    void process(String message) {
                    }

                    void logError(Exception e) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_MESSAGING_LISTENER_NO_ERROR_HANDLER
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // Missing Spring Security starter
    // -------------------------------------------------------------------------

    @Test
    void flagsMissingSecurityStarterForWebApp() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_SECURITY_STARTER_MISSING
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && finding.category() == FindingCategory.SECURITY);
    }

    @Test
    void doesNotFlagSecurityStarterWhenPresent() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of(
                                        "org.springframework.boot:spring-boot-starter-web",
                                        "org.springframework.boot:spring-boot-starter-security")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_SECURITY_STARTER_MISSING
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void doesNotFlagSecurityStarterForNonWebApp() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-data-jpa")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_SECURITY_STARTER_MISSING
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // JPA relationship risks
    // -------------------------------------------------------------------------

    @Test
    void flagsOneToManyMissingMappedBy() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Order.java"),
                """
                package com.example.demo;

                import jakarta.persistence.Entity;
                import jakarta.persistence.OneToMany;
                import java.util.List;

                @Entity
                class Order {
                    @OneToMany
                    private List<Item> items;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_JPA_ONETOMANY_MISSING_MAPPED_BY
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && "Order.items".equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagOneToManyWithMappedBy() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Order.java"),
                """
                package com.example.demo;

                import jakarta.persistence.Entity;
                import jakarta.persistence.OneToMany;
                import java.util.List;

                @Entity
                class Order {
                    @OneToMany(mappedBy = "order")
                    private List<Item> items;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_JPA_ONETOMANY_MISSING_MAPPED_BY
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void doesNotFlagOneToManyWithExplicitJoinColumn() throws IOException {
        // A unidirectional @OneToMany with @JoinColumn maps a plain FK column in the child table
        // and creates no join table — the standard intentional mapping must not be flagged.
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Order.java"),
                """
                package com.example.demo;

                import jakarta.persistence.Entity;
                import jakarta.persistence.JoinColumn;
                import jakarta.persistence.OneToMany;
                import java.util.List;

                @Entity
                class Order {
                    @OneToMany
                    @JoinColumn(name = "order_id")
                    private List<Item> items;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_JPA_ONETOMANY_MISSING_MAPPED_BY
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void doesNotFlagManyToManyWithoutMappedBy() throws IOException {
        // The owning side of a @ManyToMany MUST lack mappedBy — flagging it would hit every
        // correctly mapped association, so the rule is scoped to @OneToMany only.
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Student.java"),
                """
                package com.example.demo;

                import jakarta.persistence.Entity;
                import jakarta.persistence.ManyToMany;
                import java.util.List;

                @Entity
                class Student {
                    @ManyToMany
                    private List<Course> courses;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_JPA_ONETOMANY_MISSING_MAPPED_BY
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void flagsOneToOneMappedByWithLazyFetch() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("User.java"),
                """
                package com.example.demo;

                import jakarta.persistence.Entity;
                import jakarta.persistence.FetchType;
                import jakarta.persistence.OneToOne;

                @Entity
                class User {
                    @OneToOne(mappedBy = "user", fetch = FetchType.LAZY)
                    private Profile profile;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_JPA_ONETOONE_MAPPEDBY_LAZY_IGNORED
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && "User.profile".equals(finding.target()));
    }

    @Test
    void doesNotFlagOwningSideOneToOneWithLazyFetch() throws IOException {
        // The owning side (no mappedBy) of a @OneToOne is lazy-capable — must not be flagged.
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Profile.java"),
                """
                package com.example.demo;

                import jakarta.persistence.Entity;
                import jakarta.persistence.FetchType;
                import jakarta.persistence.JoinColumn;
                import jakarta.persistence.OneToOne;

                @Entity
                class Profile {
                    @OneToOne(fetch = FetchType.LAZY)
                    @JoinColumn(name = "user_id")
                    private User user;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_JPA_ONETOONE_MAPPEDBY_LAZY_IGNORED.ruleId());
    }

    @Test
    void flagsManyToOneWithoutFetchType() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Item.java"),
                """
                package com.example.demo;

                import jakarta.persistence.Entity;
                import jakarta.persistence.ManyToOne;

                @Entity
                class Item {
                    @ManyToOne
                    private Order order;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_JPA_MANYTOONE_EAGER_DEFAULT
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && "Item.order".equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagManyToOneWithLazyFetch() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Item.java"),
                """
                package com.example.demo;

                import jakarta.persistence.Entity;
                import jakarta.persistence.FetchType;
                import jakarta.persistence.ManyToOne;

                @Entity
                class Item {
                    @ManyToOne(fetch = FetchType.LAZY)
                    private Order order;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_JPA_MANYTOONE_EAGER_DEFAULT
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // @Bean in lite mode (non-@Configuration class)
    // -------------------------------------------------------------------------

    @Test
    void flagsBeanMethodInNonConfigurationClass() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("AppSetup.java"),
                """
                package com.example.demo;

                import org.springframework.context.annotation.Bean;
                import org.springframework.stereotype.Component;

                @Component
                class AppSetup {
                    @Bean
                    Object myService() {
                        return new Object();
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_BEAN_ON_NON_CONFIGURATION
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && "AppSetup#myService".equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagBeanMethodInConfigurationClass() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("AppConfig.java"),
                """
                package com.example.demo;

                import org.springframework.context.annotation.Bean;
                import org.springframework.context.annotation.Configuration;

                @Configuration
                class AppConfig {
                    @Bean
                    Object myService() {
                        return new Object();
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_BEAN_ON_NON_CONFIGURATION
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // @Modifying without @Transactional
    // -------------------------------------------------------------------------

    @Test
    void flagsModifyingQueryWithoutTransactional() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepository.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;
                import org.springframework.data.jpa.repository.Query;
                import org.springframework.stereotype.Repository;

                @Repository
                interface OrderRepository {
                }

                @Repository
                class OrderRepositoryImpl {
                    @Modifying
                    @Query("update Order o set o.status = :status")
                    void updateStatus(String status) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_MODIFYING_NO_TRANSACTION
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && "OrderRepositoryImpl#updateStatus"
                                                .equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagModifyingQueryCalledByTransactionalManager() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepository.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;
                import org.springframework.data.jpa.repository.Query;

                interface OrderRepository {
                    @Modifying
                    @Query("update Order o set o.status = :status")
                    void updateStatus(String status);
                }
                """);
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderRepository orderRepository = null;

                    @Transactional
                    void complete() {
                        orderRepository.updateStatus("DONE");
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_MODIFYING_NO_TRANSACTION.ruleId());
    }

    @Test
    void doesNotFlagModifyingQueryCalledInsideTransactionTemplate() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepository.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;
                import org.springframework.data.jpa.repository.Query;

                interface OrderRepository {
                    @Modifying
                    @Query("delete from Order o where o.expired = true")
                    int deleteExpired();
                }
                """);
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.support.TransactionTemplate;

                @Service
                class OrderManager {
                    private final TransactionTemplate transactions = null;
                    private final OrderRepository orderRepository = null;

                    void cleanup() {
                        transactions.execute(status -> orderRepository.deleteExpired());
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_MODIFYING_NO_TRANSACTION.ruleId());
    }

    @Test
    void doesNotFlagModifyingQueryReachedThroughPrivateHelperClosure() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepository.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;

                interface OrderRepository {
                    @Modifying
                    int deleteExpired();
                }
                """);
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderRepository repository = null;

                    @Transactional
                    void cleanup() {
                        deleteExpired();
                    }

                    private void deleteExpired() {
                        repository.deleteExpired();
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_MODIFYING_NO_TRANSACTION.ruleId());
    }

    @Test
    void doesNotFlagModifyingQueryReachedThroughTransactionTemplateHelperClosure()
            throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepository.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;

                interface OrderRepository {
                    @Modifying
                    int deleteExpired();
                }
                """);
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.support.TransactionTemplate;

                @Service
                class OrderManager {
                    private final TransactionTemplate transactions = null;
                    private final OrderRepository repository = null;

                    void cleanup() {
                        transactions.execute(status -> deleteExpired());
                    }

                    private int deleteExpired() {
                        return repository.deleteExpired();
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_MODIFYING_NO_TRANSACTION.ruleId());
    }

    @Test
    void flagsModifyingQueryWhenOnlyCallerUsesSupportsPropagation() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepository.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;

                interface OrderRepository {
                    @Modifying
                    int deleteExpired();
                }
                """);
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderRepository repository = null;

                    @Transactional(propagation = Propagation.SUPPORTS)
                    void cleanup() {
                        repository.deleteExpired();
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_MODIFYING_NO_TRANSACTION.ruleId());
    }

    @Test
    void flagsModifyingQueryWhenOnlyTransactionalCallerIsPrivateAndNotProxyEligible()
            throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepository.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;

                interface OrderRepository {
                    @Modifying
                    int deleteExpired();
                }
                """);
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderRepository repository = null;

                    @Transactional
                    private void cleanup() {
                        repository.deleteExpired();
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_MODIFYING_NO_TRANSACTION.ruleId());
    }

    @Test
    void keepsSameSimpleNameRepositoryCallersSeparatedByQualifiedOwner() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path firstPackage =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/first"));
        Path secondPackage =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/second"));
        Files.writeString(
                firstPackage.resolve("OrderRepository.java"),
                """
                package com.example.first;

                import org.springframework.data.jpa.repository.Modifying;

                public interface OrderRepository {
                    @Modifying
                    int updateStatus(String status);
                }
                """);
        Files.writeString(
                secondPackage.resolve("OrderRepository.java"),
                """
                package com.example.second;

                import org.springframework.data.jpa.repository.Modifying;

                public interface OrderRepository {
                    @Modifying
                    int updateStatus(String status);
                }
                """);
        Files.writeString(
                firstPackage.resolve("OrderManager.java"),
                """
                package com.example.first;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderRepository repository = null;

                    @Transactional
                    void update() {
                        repository.updateStatus("DONE");
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .filteredOn(
                        finding ->
                                FindingRules.SPRING_MODIFYING_NO_TRANSACTION
                                        .ruleId()
                                        .equals(finding.ruleId()))
                .singleElement()
                .satisfies(
                        finding ->
                                assertThat(finding.sourceFile())
                                        .contains("com/example/second/OrderRepository.java"));
    }

    @Test
    void suppressesModifyingFindingForSameArityOverloadsWithoutArgumentTypeResolution()
            throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepository.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;

                interface OrderRepository {
                    @Modifying
                    int updateStatus(String status);

                    @Modifying
                    int updateStatus(long statusCode);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_MODIFYING_NO_TRANSACTION.ruleId());
    }

    @Test
    void doesNotUseTransactionBoundaryFromDifferentExecutedCallbackParameter() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepository.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;

                interface OrderRepository {
                    @Modifying
                    int deleteExpired();
                }
                """);
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import java.util.function.Supplier;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final MultiCallbackExecutor transactions = null;
                    private final OrderRepository repository = null;

                    void cleanup() {
                        transactions.execute(() -> repository.deleteExpired(), () -> {});
                    }
                }

                class MultiCallbackExecutor {
                    @Transactional
                    <T> T execute(Supplier<T> work, Runnable cleanup) {
                        cleanup.run();
                        return null;
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_MODIFYING_NO_TRANSACTION.ruleId());
    }

    @Test
    void doesNotFlagModifyingQueryWithMethodLevelTransactional() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepositoryImpl.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;
                import org.springframework.data.jpa.repository.Query;
                import org.springframework.stereotype.Repository;
                import org.springframework.transaction.annotation.Transactional;

                @Repository
                class OrderRepositoryImpl {
                    @Modifying
                    @Transactional
                    @Query("update Order o set o.status = :status")
                    void updateStatus(String status) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_MODIFYING_NO_TRANSACTION
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void doesNotFlagModifyingQueryWithClassLevelTransactional() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderRepositoryImpl.java"),
                """
                package com.example.demo;

                import org.springframework.data.jpa.repository.Modifying;
                import org.springframework.data.jpa.repository.Query;
                import org.springframework.stereotype.Repository;
                import org.springframework.transaction.annotation.Transactional;

                @Repository
                @Transactional
                class OrderRepositoryImpl {
                    @Modifying
                    @Query("update Order o set o.status = :status")
                    void updateStatus(String status) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_MODIFYING_NO_TRANSACTION
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // Destructive DDL-auto in production profile
    // -------------------------------------------------------------------------

    @Test
    void flagsDestructiveDdlAutoInProdProfile() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.url=jdbc:h2:mem:test");
        Files.writeString(
                resources.resolve("application-prod.properties"),
                "spring.jpa.hibernate.ddl-auto=create\n");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-data-jpa")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_DDL_AUTO_DESTRUCTIVE_PROD
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.ERROR
                                        && finding.primaryLocation() != null);
    }

    @Test
    void flagsCreateDropDdlAutoInProdProfile() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.url=jdbc:h2:mem:test");
        Files.writeString(
                resources.resolve("application-prod.properties"),
                "spring.jpa.hibernate.ddl-auto=create-drop\n");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-data-jpa")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_DDL_AUTO_DESTRUCTIVE_PROD
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.ERROR);
    }

    @Test
    void doesNotFlagUpdateDdlAutoInProdProfile() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.url=jdbc:h2:mem:test");
        Files.writeString(
                resources.resolve("application-prod.properties"),
                "spring.jpa.hibernate.ddl-auto=validate\n");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-data-jpa")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_DDL_AUTO_DESTRUCTIVE_PROD
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // spring.jpa.show-sql=true in production profile
    // -------------------------------------------------------------------------

    @Test
    void flagsShowSqlTrueInProdProfile() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.url=jdbc:h2:mem:test");
        Files.writeString(
                resources.resolve("application-prod.properties"), "spring.jpa.show-sql=true\n");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-data-jpa")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_JPA_SHOW_SQL_PROD
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.evidence() != null
                                        && finding.evidence().contains("spring.jpa.show-sql")
                                        && finding.primaryLocation() != null);
    }

    // -------------------------------------------------------------------------
    // spring.h2.console.enabled=true in production profile
    // -------------------------------------------------------------------------

    @Test
    void flagsH2ConsoleEnabledInProdProfile() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.url=jdbc:h2:mem:test");
        Files.writeString(
                resources.resolve("application-prod.properties"),
                "spring.h2.console.enabled=true\n");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-data-jpa")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_H2_CONSOLE_ENABLED_PROD
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.ERROR
                                        && finding.evidence() != null
                                        && finding.evidence().contains("spring.h2.console.enabled")
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagH2ConsoleInDevProfile() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.url=jdbc:h2:mem:test");
        Files.writeString(
                resources.resolve("application-dev.properties"),
                "spring.h2.console.enabled=true\n");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-data-jpa")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_H2_CONSOLE_ENABLED_PROD
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // spring.jpa.open-in-view
    // -------------------------------------------------------------------------

    @Test
    void flagsOpenInViewExplicitlyEnabled() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.url=jdbc:h2:mem:test\nspring.jpa.open-in-view=true\n");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of(
                                        "org.springframework.boot:spring-boot-starter-data-jpa",
                                        "org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_JPA_OPEN_IN_VIEW
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING);
    }

    @Test
    void flagsOpenInViewImplicitlyWhenDatasourceConfiguredWithoutExplicitSetting()
            throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.url=jdbc:postgresql://localhost:5432/demo\n");

        // Open-session-in-view only registers in servlet web applications.
        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of(
                                        "org.springframework.boot:spring-boot-starter-data-jpa",
                                        "org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_JPA_OPEN_IN_VIEW
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO);
    }

    @Test
    void doesNotFlagOpenInViewWhenExplicitlyDisabled() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.url=jdbc:postgresql://localhost:5432/demo\n"
                        + "spring.jpa.open-in-view=false\n");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-data-jpa")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_JPA_OPEN_IN_VIEW
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // @Transactional + @Scheduled on same method
    // -------------------------------------------------------------------------

    @Test
    void flagsTransactionalOnScheduledMethod() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("DailyReportJob.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;
                import org.springframework.transaction.annotation.Transactional;

                @Component
                class DailyReportJob {
                    @Scheduled(cron = "0 0 3 * * *", zone = "UTC")
                    @Transactional
                    public void generate() {
                        writeReport();
                    }

                    void writeReport() {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_TRANSACTIONAL_ON_SCHEDULED
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && "DailyReportJob#generate".equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagScheduledAloneOrTransactionalAlone() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Jobs.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;
                import org.springframework.transaction.annotation.Transactional;

                @Component
                class Jobs {
                    @Scheduled(fixedDelay = 300000)
                    public void pollJob() {
                    }

                    @Transactional
                    public void doWork() {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_TRANSACTIONAL_ON_SCHEDULED
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // CSRF disabled
    // -------------------------------------------------------------------------

    @Test
    void flagsCsrfDisabledViaChainCall() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("SecurityConfig.java"),
                """
                package com.example.demo;

                import org.springframework.context.annotation.Bean;
                import org.springframework.context.annotation.Configuration;
                import org.springframework.security.config.annotation.web.builders.HttpSecurity;
                import org.springframework.security.web.SecurityFilterChain;

                @Configuration
                class SecurityConfig {
                    @Bean
                    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                        return http
                                .csrf(csrf -> csrf.disable())
                                .build();
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-security")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_CSRF_DISABLED.ruleId().equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.category() == FindingCategory.SECURITY
                                        && finding.primaryLocation() != null);
    }

    @Test
    void flagsCsrfDisabledViaAbstractHttpConfigurer() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("SecurityConfig.java"),
"""
package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }
}
""");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-security")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_CSRF_DISABLED.ruleId().equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING);
    }

    // -------------------------------------------------------------------------
    // CORS wildcard
    // -------------------------------------------------------------------------

    @Test
    void flagsCorsAllowAllOrigins() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("CorsConfig.java"),
                """
                package com.example.demo;

                import org.springframework.context.annotation.Bean;
                import org.springframework.context.annotation.Configuration;
                import org.springframework.web.servlet.config.annotation.CorsRegistry;
                import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

                @Configuration
                class CorsConfig {
                    @Bean
                    WebMvcConfigurer corsConfigurer() {
                        return new WebMvcConfigurer() {
                            @Override
                            public void addCorsMappings(CorsRegistry registry) {
                                registry.addMapping("/**")
                                        .allowedOrigins("*");
                            }
                        };
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_CORS_ALLOW_ALL.ruleId().equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.category() == FindingCategory.SECURITY
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagCorsWithSpecificOrigin() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("CorsConfig.java"),
                """
                package com.example.demo;

                import org.springframework.context.annotation.Bean;
                import org.springframework.context.annotation.Configuration;
                import org.springframework.web.servlet.config.annotation.CorsRegistry;
                import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

                @Configuration
                class CorsConfig {
                    @Bean
                    WebMvcConfigurer corsConfigurer() {
                        return new WebMvcConfigurer() {
                            @Override
                            public void addCorsMappings(CorsRegistry registry) {
                                registry.addMapping("/**")
                                        .allowedOrigins("https://app.example.com");
                            }
                        };
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_CORS_ALLOW_ALL
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // Sensitive URL parameters and path variables
    // -------------------------------------------------------------------------

    @Test
    void flagsPasswordAsRequestParam() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("AuthController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RequestParam;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class AuthController {
                    @GetMapping("/login")
                    String login(@RequestParam("password") String password) {
                        return "ok";
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_REQUEST_PARAM_SENSITIVE_NAME
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && "AuthController#login".equals(finding.target()));
    }

    @Test
    void flagsTokenAsPathVariable() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("TokenController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.PathVariable;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class TokenController {
                    @GetMapping("/verify/{token}")
                    String verify(@PathVariable("token") String token) {
                        return "ok";
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_REQUEST_PARAM_SENSITIVE_NAME
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && "TokenController#verify".equals(finding.target()));
    }

    @Test
    void doesNotFlagNonSensitiveRequestParam() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("SearchController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RequestParam;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class SearchController {
                    @GetMapping("/search")
                    String search(@RequestParam("query") String query) {
                        return "ok";
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_REQUEST_PARAM_SENSITIVE_NAME
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // @Value without default
    // -------------------------------------------------------------------------

    @Test
    void flagsValueAnnotationWithoutDefault() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ApiClient.java"),
                """
                package com.example.demo;

                import org.springframework.beans.factory.annotation.Value;
                import org.springframework.stereotype.Component;

                @Component
                class ApiClient {
                    @Value("${api.base-url}")
                    private String baseUrl;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_VALUE_NO_DEFAULT
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && "ApiClient.baseUrl".equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagValueAnnotationWithDefault() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ApiClient.java"),
                """
                package com.example.demo;

                import org.springframework.beans.factory.annotation.Value;
                import org.springframework.stereotype.Component;

                @Component
                class ApiClient {
                    @Value("${api.base-url:https://localhost}")
                    private String baseUrl;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_VALUE_NO_DEFAULT
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // Field injection
    // -------------------------------------------------------------------------

    @Test
    void flagsAutowiredFieldInjection() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.beans.factory.annotation.Autowired;
                import org.springframework.stereotype.Service;

                @Service
                class OrderService {
                    @Autowired
                    private OrderRepository orderRepository;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_FIELD_INJECTION
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && "OrderService.orderRepository".equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagConstructorInjection() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;

                @Service
                class OrderService {
                    private final OrderRepository orderRepository;

                    OrderService(OrderRepository orderRepository) {
                        this.orderRepository = orderRepository;
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_FIELD_INJECTION
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // @RequestMapping without HTTP method constraint
    // -------------------------------------------------------------------------

    @Test
    void flagsRequestMappingWithoutHttpMethod() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("LegacyController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.RequestMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class LegacyController {
                    @RequestMapping("/orders")
                    String listOrders() {
                        return "[]";
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_REQUEST_MAPPING_NO_METHOD
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && "LegacyController#listOrders".equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagRequestMappingWithMethodAttribute() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("LegacyController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.RequestMapping;
                import org.springframework.web.bind.annotation.RequestMethod;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class LegacyController {
                    @RequestMapping(value = "/orders", method = RequestMethod.GET)
                    String listOrders() {
                        return "[]";
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_REQUEST_MAPPING_NO_METHOD
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void doesNotFlagGetMappingAnnotation() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class OrderController {
                    @GetMapping("/orders")
                    String listOrders() {
                        return "[]";
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_REQUEST_MAPPING_NO_METHOD
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // @ConfigurationProperties without @Validated
    // -------------------------------------------------------------------------

    @Test
    void flagsConfigurationPropertiesWithoutValidated() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("AppProperties.java"),
                """
                package com.example.demo;

                import jakarta.validation.constraints.NotBlank;
                import org.springframework.boot.context.properties.ConfigurationProperties;

                @ConfigurationProperties(prefix = "app")
                class AppProperties {
                    @NotBlank
                    private String apiUrl;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_CONFIGURATION_PROPERTIES_NOT_VALIDATED
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && "AppProperties".equals(finding.target())
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagConfigurationPropertiesWithValidated() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("AppProperties.java"),
                """
                package com.example.demo;

                import jakarta.validation.constraints.NotBlank;
                import org.springframework.boot.context.properties.ConfigurationProperties;
                import org.springframework.validation.annotation.Validated;

                @ConfigurationProperties(prefix = "app")
                @Validated
                class AppProperties {
                    @NotBlank
                    private String apiUrl;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_CONFIGURATION_PROPERTIES_NOT_VALIDATED
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // Scheduling: cron zone and short interval
    // -------------------------------------------------------------------------

    @Test
    void flagsCronExpressionWithoutTimeZone() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ReportJob.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;

                @Component
                class ReportJob {
                    @Scheduled(cron = "0 30 3 * * *")
                    public void generate() {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_SCHEDULED_CRON_NO_ZONE
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && "ReportJob#generate".equals(finding.target()));
    }

    @Test
    void doesNotFlagCronExpressionWithExplicitTimeZone() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ReportJob.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;

                @Component
                class ReportJob {
                    @Scheduled(cron = "0 30 3 * * *", zone = "Europe/Stockholm")
                    public void generate() {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_SCHEDULED_CRON_NO_ZONE
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void flagsScheduledShortFixedRateInterval() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("HeartbeatJob.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;

                @Component
                class HeartbeatJob {
                    @Scheduled(fixedRate = 5000)
                    public void ping() {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_SCHEDULED_SHORT_INTERVAL
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && "HeartbeatJob#ping".equals(finding.target()));
    }

    @Test
    void doesNotFlagScheduledLongInterval() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("HeartbeatJob.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;

                @Component
                class HeartbeatJob {
                    @Scheduled(fixedRate = 300000)
                    public void ping() {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_SCHEDULED_SHORT_INTERVAL
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // Fatal error / Throwable catch
    // -------------------------------------------------------------------------

    @Test
    void flagsBroadFatalErrorCatch() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Processor.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Component;

                @Component
                class Processor {
                    public void run() {
                        try {
                            doWork();
                        } catch (Error e) {
                            logError(e);
                        }
                    }

                    void doWork() {
                    }

                    void logError(Throwable t) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_BROAD_FATAL_ERROR_CATCH
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.category()
                                                == FindingCategory.EXCEPTION_HANDLING);
    }

    @Test
    void flagsBroadThrowableCatch() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Processor.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Component;

                @Component
                class Processor {
                    public void run() {
                        try {
                            doWork();
                        } catch (Throwable t) {
                            logError(t);
                        }
                    }

                    void doWork() {
                    }

                    void logError(Throwable t) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_BROAD_FATAL_ERROR_CATCH
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.category()
                                                == FindingCategory.EXCEPTION_HANDLING);
    }

    // -------------------------------------------------------------------------
    // HTTP plain URL
    // -------------------------------------------------------------------------

    @Test
    void flagsPlainHttpUrlInOutboundClient() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("PaymentClient.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Component;
                import org.springframework.web.client.RestTemplate;

                @Component
                class PaymentClient {
                    private final RestTemplate rest = new RestTemplate();

                    void charge() {
                        rest.postForObject("http://payment.internal/charge", null, String.class);
                    }
                }
                """);

        // SPRING_HTTP_PLAIN_URL is emitted by HttpSurfaceAnalyzer (not
        // StaticPracticeFindingAnalyzer),
        // so we need to include its findings in the result set.
        List<Finding> findings =
                analyzeAllFindings(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_HTTP_PLAIN_URL.ruleId().equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.category() == FindingCategory.HTTP);
    }

    // -------------------------------------------------------------------------
    // Flyway missing migration files
    // -------------------------------------------------------------------------

    @Test
    void flagsFlywaydEnabledButNoMigrationFiles() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.flyway.enabled=true\nspring.datasource.url=jdbc:h2:mem:test\n");

        List<Finding> findings =
                analyzeStaticPractice(tempDir, emptyBuildInfo(List.of("org.flywaydb:flyway-core")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_FLYWAY_MISSING_MIGRATIONS
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING);
    }

    @Test
    void doesNotFlagFlywaydWhenMigrationFilesExist() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path migrations = Files.createDirectories(resources.resolve("db/migration"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.flyway.enabled=true\nspring.datasource.url=jdbc:h2:mem:test\n");
        // V1.0 satisfies the pattern V[0-9][^_]+__ (needs at least one non-underscore char after
        // the first digit)
        Files.writeString(
                migrations.resolve("V1.0__init.sql"),
                "CREATE TABLE orders (id BIGINT PRIMARY KEY);\n");

        List<Finding> findings =
                analyzeStaticPractice(tempDir, emptyBuildInfo(List.of("org.flywaydb:flyway-core")));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_FLYWAY_MISSING_MIGRATIONS
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // HTTP client resilience (no retry / circuit-breaker for write calls)
    // -------------------------------------------------------------------------

    @Test
    void flagsHttpClientWriteCallWithNoResilienceHandling() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("NotificationClient.java"),
"""
package com.example.demo;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
class NotificationClient {
    private final RestTemplate rest = new RestTemplate();

    void notify(String payload) {
        rest.postForObject("https://notify.example.com/events", payload, String.class);
    }
}
""");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_HTTP_CLIENT_NO_RESILIENCE
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO
                                        && finding.category() == FindingCategory.HTTP);
    }

    // -------------------------------------------------------------------------
    // Primary location / occurrences after the "View code" fix
    // -------------------------------------------------------------------------

    @Test
    void sensitiveProfileDuplicationFindingHasPrimaryLocationAndOccurrences() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"), "app.api-key=default-secret\n");
        Files.writeString(
                resources.resolve("application-prod.properties"), "app.api-key=prod-secret\n");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        Finding dupe =
                findings.stream()
                        .filter(
                                f ->
                                        FindingRules.SPRING_SECRET_MULTI_PROFILE
                                                .ruleId()
                                                .equals(f.ruleId()))
                        .findFirst()
                        .orElseThrow(
                                () ->
                                        new AssertionError(
                                                "SPRING_SECRET_MULTI_PROFILE finding not"
                                                        + " produced"));

        assertThat(dupe.primaryLocation())
                .as("primaryLocation must be set so the UI can show 'View code'")
                .isNotNull();
        assertThat(dupe.primaryLocation().filePath()).isNotBlank();
        assertThat(dupe.occurrences())
                .as("occurrences should list one entry per config file")
                .hasSizeGreaterThanOrEqualTo(2);
        assertThat(dupe.occurrences())
                .allSatisfy(
                        occ -> {
                            assertThat(occ.location()).isNotNull();
                            assertThat(occ.location().filePath()).isNotBlank();
                        });
    }

    @Test
    void crossProfileDriftFindingHasPrimaryLocationAndOccurrences() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        // "trading.provider" contains "provider" — passes isDriftRelevantProperty()
        Files.writeString(resources.resolve("application.properties"), "trading.provider=stub\n");
        Files.writeString(
                resources.resolve("application-prod.properties"), "trading.provider=real\n");

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        Finding drift =
                findings.stream()
                        .filter(f -> FindingRules.SPRING_PROFILE_DRIFT.ruleId().equals(f.ruleId()))
                        .findFirst()
                        .orElseThrow(
                                () ->
                                        new AssertionError(
                                                "SPRING_PROFILE_DRIFT finding not produced"));

        assertThat(drift.primaryLocation())
                .as("primaryLocation must be set so the UI can show 'View code'")
                .isNotNull();
        assertThat(drift.primaryLocation().filePath()).isNotBlank();
        assertThat(drift.occurrences())
                .as("occurrences should list one entry per profile")
                .hasSizeGreaterThanOrEqualTo(2);
    }

    @Test
    void repeatedFallbackPatternFindingHasPrimaryLocationFromFirstFallback() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ParserA.java"),
"""
package com.example.demo;

class ParserA {
    Integer parseAmount(String v) {
        try { return Integer.valueOf(v); } catch (NumberFormatException e) { return null; }
    }
}
""");
        Files.writeString(
                sourceRoot.resolve("ParserB.java"),
"""
package com.example.demo;

class ParserB {
    Integer parseCount(String v) {
        try { return Integer.valueOf(v); } catch (NumberFormatException e) { return null; }
    }
}
""");
        Files.writeString(
                sourceRoot.resolve("ParserC.java"),
"""
package com.example.demo;

class ParserC {
    Integer parseLimit(String v) {
        try { return Integer.valueOf(v); } catch (NumberFormatException e) { return null; }
    }
}
""");

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        Finding pattern =
                findings.stream()
                        .filter(
                                f ->
                                        FindingRules.SPRING_REPEATED_FALLBACK_PARSING_PATTERN
                                                .ruleId()
                                                .equals(f.ruleId()))
                        .findFirst()
                        .orElseThrow(
                                () ->
                                        new AssertionError(
                                                "SPRING_REPEATED_FALLBACK_PARSING_PATTERN finding"
                                                        + " not produced"));

        assertThat(pattern.primaryLocation())
                .as("primaryLocation must be set from the first underlying fallback finding")
                .isNotNull();
        assertThat(pattern.primaryLocation().filePath()).isNotBlank();
        assertThat(pattern.occurrences()).isNotEmpty();
    }

    // -------------------------------------------------------------------------
    // Broad exception in Spring boundary (@PostConstruct / startup)
    // -------------------------------------------------------------------------

    @Test
    void flagsBroadExceptionCatchInScheduledBoundary() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("SyncJob.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;

                @Component
                class SyncJob {
                    @Scheduled(fixedDelay = 60000)
                    public void sync() {
                        try {
                            doWork();
                        } catch (Exception e) {
                            updateStatus("failed");
                        }
                    }

                    void doWork() {
                    }

                    void updateStatus(String s) {
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_BROAD_EXCEPTION_SPRING_BOUNDARY
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.INFO);
    }

    // -------------------------------------------------------------------------
    // Findings carry rich metadata (evidence, recommendation, limitations)
    // -------------------------------------------------------------------------

    @Test
    void allNewRuleFindingsCarryRichMetadata() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("AllRules.java"),
                """
                package com.example.demo;

                import org.springframework.beans.factory.annotation.Autowired;
                import org.springframework.beans.factory.annotation.Value;
                import org.springframework.context.annotation.Bean;
                import org.springframework.kafka.annotation.KafkaListener;
                import org.springframework.scheduling.annotation.Async;
                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;
                import org.springframework.transaction.annotation.Transactional;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RequestMapping;
                import org.springframework.web.bind.annotation.RestController;

                @Component
                class AllRulesComponent {
                    @Autowired
                    private Object dependency;

                    @Value("${some.prop}")
                    private String prop;

                    @Async
                    private void asyncPrivate() {
                    }

                    @Async
                    public void asyncVoid() {
                        doWork();
                    }

                    @KafkaListener(topics = "t")
                    public void onMessage(String msg) {
                        doWork();
                    }

                    @Scheduled(cron = "0 * * * * *")
                    @Transactional
                    public void scheduledTx() {
                        doWork();
                    }

                    @Bean
                    Object someBean() {
                        return new Object();
                    }

                    void doWork() {
                    }
                }

                @RestController
                class AllRulesController {
                    @RequestMapping("/legacy")
                    String legacy() {
                        return "";
                    }
                }
                """);

        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-web")));

        List<String> expectedRules =
                List.of(
                        FindingRules.SPRING_ASYNC_PROXY_BYPASS.ruleId(),
                        FindingRules.SPRING_ASYNC_VOID_SWALLOWED_EXCEPTION.ruleId(),
                        FindingRules.SPRING_MESSAGING_LISTENER_NO_ERROR_HANDLER.ruleId(),
                        FindingRules.SPRING_TRANSACTIONAL_ON_SCHEDULED.ruleId(),
                        FindingRules.SPRING_BEAN_ON_NON_CONFIGURATION.ruleId(),
                        FindingRules.SPRING_FIELD_INJECTION.ruleId(),
                        FindingRules.SPRING_VALUE_NO_DEFAULT.ruleId(),
                        FindingRules.SPRING_REQUEST_MAPPING_NO_METHOD.ruleId());

        for (String ruleId : expectedRules) {
            Finding found =
                    findings.stream()
                            .filter(f -> ruleId.equals(f.ruleId()))
                            .findFirst()
                            .orElseThrow(
                                    () ->
                                            new AssertionError(
                                                    "Expected finding not produced: " + ruleId));
            assertThat(found.whyBadPractice())
                    .as(ruleId + ": whyBadPractice must not be blank")
                    .isNotBlank();
            assertThat(found.recommendation())
                    .as(ruleId + ": recommendation must not be blank")
                    .isNotBlank();
            assertThat(found.evidence()).as(ruleId + ": evidence must not be blank").isNotBlank();
        }
    }

    // -------------------------------------------------------------------------
    // SPRING_ACTUATOR_ENDPOINT_EXPOSED_PROD
    // -------------------------------------------------------------------------

    @Test
    void flagsActuatorWildcardExposure() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "management.endpoints.web.exposure.include=*\n");

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_ACTUATOR_ENDPOINT_EXPOSED_PROD
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.primaryLocation() != null);
    }

    @Test
    void flagsActuatorDangerousEndpointExposure() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "management.endpoints.web.exposure.include=health,info,env\n");

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_ACTUATOR_ENDPOINT_EXPOSED_PROD
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    @Test
    void doesNotFlagSafeActuatorExposure() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "management.endpoints.web.exposure.include=health,info\n");

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_ACTUATOR_ENDPOINT_EXPOSED_PROD
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // SPRING_CONNECTION_POOL_MISCONFIGURED
    // -------------------------------------------------------------------------

    @Test
    void flagsHikariPoolSizeTooSmall() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.hikari.maximum-pool-size=1\n");

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_CONNECTION_POOL_MISCONFIGURED
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagReasonableHikariPoolSize() throws IOException {
        Path resources = Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                resources.resolve("application.properties"),
                "spring.datasource.hikari.maximum-pool-size=10\n");

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_CONNECTION_POOL_MISCONFIGURED
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // SPRING_SQL_INJECTION_QUERY_CONCATENATION
    // -------------------------------------------------------------------------

    @Test
    void flagsNativeQueryWithStringConcatenation() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("UserRepository.java"),
"""
package com.example.demo;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;

@Repository
class UserRepository {
    private EntityManager entityManager;

    Object findByRole(String role) {
        return entityManager.createNativeQuery("SELECT * FROM users WHERE role = '" + role + "'");
    }
}
""");

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_SQL_INJECTION_QUERY_CONCATENATION
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.ERROR
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagNativeQueryWithLiteralOnly() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("UserRepository.java"),
                """
                package com.example.demo;

                import jakarta.persistence.EntityManager;
                import org.springframework.stereotype.Repository;

                @Repository
                class UserRepository {
                    private EntityManager entityManager;

                    Object findAll() {
                        return entityManager.createNativeQuery("SELECT * FROM users");
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_SQL_INJECTION_QUERY_CONCATENATION
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // SPRING_LOGGING_PII_EXPOSURE
    // -------------------------------------------------------------------------

    @Test
    void flagsLoggingPasswordVariable() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("AuthService.java"),
                """
                package com.example.demo;

                import org.slf4j.Logger;
                import org.slf4j.LoggerFactory;
                import org.springframework.stereotype.Service;

                @Service
                class AuthService {
                    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

                    void login(String username, String password) {
                        log.info("Login attempt for user: {}, password: {}", username, password);
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_LOGGING_PII_EXPOSURE
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING);
    }

    @Test
    void doesNotFlagLoggingNonSensitiveValues() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.slf4j.Logger;
                import org.slf4j.LoggerFactory;
                import org.springframework.stereotype.Service;

                @Service
                class OrderService {
                    private static final Logger log = LoggerFactory.getLogger(OrderService.class);

                    void processOrder(String orderId, String status) {
                        log.info("Processing order: {}, status: {}", orderId, status);
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_LOGGING_PII_EXPOSURE
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // SPRING_JPA_LAZY_LOADING_OUTSIDE_TRANSACTION
    // -------------------------------------------------------------------------

    @Test
    void flagsGetReferenceByIdWithoutTransaction() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;

                @Service
                class OrderService {
                    private OrderRepository orderRepository;

                    Order getOrder(Long id) {
                        return orderRepository.getReferenceById(id);
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_JPA_LAZY_LOADING_OUTSIDE_TRANSACTION
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagGetReferenceByIdWithTransactional() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    private OrderRepository orderRepository;

                    @Transactional(readOnly = true)
                    Order getOrder(Long id) {
                        return orderRepository.getReferenceById(id);
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_JPA_LAZY_LOADING_OUTSIDE_TRANSACTION
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // SPRING_ASYNC_EXECUTOR_NOT_CONFIGURED
    // -------------------------------------------------------------------------

    @Test
    void flagsAsyncWithoutCustomExecutor() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("NotificationService.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Async;
                import org.springframework.scheduling.annotation.EnableAsync;
                import org.springframework.stereotype.Service;

                @Service
                @EnableAsync
                class NotificationService {
                    @Async
                    void sendEmail(String to) {
                        // send email
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_ASYNC_EXECUTOR_NOT_CONFIGURED
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING);
    }

    @Test
    void doesNotFlagAsyncWhenExecutorBeanPresent() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("NotificationService.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Async;
                import org.springframework.stereotype.Service;

                @Service
                class NotificationService {
                    @Async
                    void sendEmail(String to) {
                        // send email
                    }
                }
                """);
        Files.writeString(
                sourceRoot.resolve("AsyncConfig.java"),
                """
                package com.example.demo;

                import org.springframework.context.annotation.Bean;
                import org.springframework.context.annotation.Configuration;
                import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

                @Configuration
                class AsyncConfig {
                    @Bean
                    ThreadPoolTaskExecutor taskExecutor() {
                        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
                        executor.setCorePoolSize(5);
                        return executor;
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_ASYNC_EXECUTOR_NOT_CONFIGURED
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // SPRING_SCHEDULED_EXECUTOR_SERVICE_NOT_CONFIGURED
    // -------------------------------------------------------------------------

    @Test
    void flagsMultipleScheduledMethodsWithoutTaskScheduler() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("CleanupJob.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.EnableScheduling;
                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;

                @Component
                @EnableScheduling
                class CleanupJob {
                    @Scheduled(fixedDelay = 60000)
                    void cleanExpiredSessions() {}

                    @Scheduled(cron = "0 0 * * * *")
                    void archiveOldRecords() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_SCHEDULED_EXECUTOR_SERVICE_NOT_CONFIGURED
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING);
    }

    @Test
    void doesNotFlagScheduledWhenTaskSchedulerPresent() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("CleanupJob.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;

                @Component
                class CleanupJob {
                    @Scheduled(fixedDelay = 60000)
                    void cleanExpiredSessions() {}

                    @Scheduled(cron = "0 0 * * * *")
                    void archiveOldRecords() {}
                }
                """);
        Files.writeString(
                sourceRoot.resolve("SchedulingConfig.java"),
                """
                package com.example.demo;

                import org.springframework.context.annotation.Bean;
                import org.springframework.context.annotation.Configuration;
                import org.springframework.scheduling.TaskScheduler;
                import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

                @Configuration
                class SchedulingConfig {
                    @Bean
                    TaskScheduler taskScheduler() {
                        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
                        scheduler.setPoolSize(4);
                        return scheduler;
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_SCHEDULED_EXECUTOR_SERVICE_NOT_CONFIGURED
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // SPRING_FEIGN_NO_FALLBACK_OR_TIMEOUT
    // -------------------------------------------------------------------------

    @Test
    void flagsFeignClientWithoutFallback() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("InventoryClient.java"),
                """
                package com.example.demo;

                import org.springframework.cloud.openfeign.FeignClient;
                import org.springframework.web.bind.annotation.GetMapping;

                @FeignClient(name = "inventory", url = "http://inventory-service")
                interface InventoryClient {
                    @GetMapping("/items")
                    java.util.List<String> getItems();
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_FEIGN_NO_FALLBACK_OR_TIMEOUT
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagFeignClientWithFallback() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("InventoryClient.java"),
"""
package com.example.demo;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "inventory", url = "http://inventory-service", fallback = InventoryClientFallback.class)
interface InventoryClient {
    @GetMapping("/items")
    java.util.List<String> getItems();
}
""");

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_FEIGN_NO_FALLBACK_OR_TIMEOUT
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // SPRING_RESTTEMPLATE_NO_HTTP_STATUS_HANDLER
    // -------------------------------------------------------------------------

    @Test
    void flagsRestTemplateBeanWithoutErrorHandler() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("WebConfig.java"),
                """
                package com.example.demo;

                import org.springframework.context.annotation.Bean;
                import org.springframework.context.annotation.Configuration;
                import org.springframework.web.client.RestTemplate;

                @Configuration
                class WebConfig {
                    @Bean
                    RestTemplate restTemplate() {
                        return new RestTemplate();
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_RESTTEMPLATE_NO_HTTP_STATUS_HANDLER
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagRestTemplateWithErrorHandler() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("WebConfig.java"),
                """
                package com.example.demo;

                import org.springframework.context.annotation.Bean;
                import org.springframework.context.annotation.Configuration;
                import org.springframework.web.client.RestTemplate;

                @Configuration
                class WebConfig {
                    @Bean
                    RestTemplate restTemplate() {
                        RestTemplate restTemplate = new RestTemplate();
                        restTemplate.setErrorHandler(new MyErrorHandler());
                        return restTemplate;
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_RESTTEMPLATE_NO_HTTP_STATUS_HANDLER
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // SPRING_TRANSACTION_ISOLATION_READ_UNCOMMITTED
    // -------------------------------------------------------------------------

    @Test
    void flagsReadUncommittedIsolation() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ReportService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Isolation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class ReportService {
                    @Transactional(isolation = Isolation.READ_UNCOMMITTED)
                    java.util.List<String> generateReport() {
                        return java.util.List.of();
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_TRANSACTION_ISOLATION_READ_UNCOMMITTED
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && finding.severity() == FindingSeverity.WARNING
                                        && finding.primaryLocation() != null);
    }

    @Test
    void doesNotFlagReadCommittedIsolation() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ReportService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Isolation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class ReportService {
                    @Transactional(isolation = Isolation.READ_COMMITTED)
                    java.util.List<String> generateReport() {
                        return java.util.List.of();
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .noneMatch(
                        finding ->
                                FindingRules.SPRING_TRANSACTION_ISOLATION_READ_UNCOMMITTED
                                        .ruleId()
                                        .equals(finding.ruleId()));
    }

    // -------------------------------------------------------------------------
    // Observability gaps
    // -------------------------------------------------------------------------

    @Test
    void flagsTimedOnBoot3PlusPreferObserved() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import io.micrometer.core.annotation.Timed;
                import org.springframework.stereotype.Service;

                @Service
                public class OrderService {
                    @Timed("orders.place")
                    public void placeOrder(String symbol) {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TIMED_PREFER_OBSERVED.ruleId());
    }

    @Test
    void doesNotFlagTimedOnBoot2() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import io.micrometer.core.annotation.Timed;
                import org.springframework.stereotype.Service;

                @Service
                public class OrderService {
                    @Timed("orders.place")
                    public void placeOrder(String symbol) {}
                }
                """);

        var configurationResult = configurationAnalyzer.analyze(tempDir, emptyBuildInfo(List.of()));
        var sourceAnalysis = javaSourceAnalyzer.analyze(tempDir);
        HttpSurfaceAnalyzer.Result httpResult =
                httpSurfaceAnalyzer.analyze(
                        tempDir,
                        configurationResult.configurationAnalysis(),
                        emptyBuildInfo(List.of()),
                        WebStack.SERVLET_MVC);
        List<Finding> findings =
                analyzer.analyze(
                        tempDir,
                        emptyBuildInfo(List.of()),
                        configurationResult.configurationAnalysis(),
                        GradleModelAnalysis.empty(
                                GradleAnalysisStatus.NOT_REQUESTED, "TOOLING_API", List.of()),
                        new RuntimeStackAnalysis(
                                "2.7.18",
                                "build.gradle",
                                "17",
                                WebStack.SERVLET_MVC,
                                "boot 2",
                                null,
                                null),
                        httpResult.httpSurfaceAnalysis(),
                        sourceAnalysis.detectedClasses());

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TIMED_PREFER_OBSERVED.ruleId());
    }

    @Test
    void flagsScheduledMethodWithNoObservability() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ReportJob.java"),
                """
                package com.example.demo;

                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;

                @Component
                public class ReportJob {
                    @Scheduled(cron = "0 0 1 * * *")
                    public void generateReport() {}
                }
                """);

        // The "missing observability annotation" rules require an observability stack.
        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-actuator")));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_SCHEDULED_NO_OBSERVABILITY.ruleId());
    }

    @Test
    void doesNotFlagScheduledMethodWithObserved() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ReportJob.java"),
                """
                package com.example.demo;

                import io.micrometer.observation.annotation.Observed;
                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.stereotype.Component;

                @Component
                public class ReportJob {
                    @Observed(name = "report.generate")
                    @Scheduled(cron = "0 0 1 * * *")
                    public void generateReport() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_SCHEDULED_NO_OBSERVABILITY.ruleId());
    }

    @Test
    void flagsKafkaListenerWithNoObservability() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderConsumer.java"),
                """
                package com.example.demo;

                import org.springframework.kafka.annotation.KafkaListener;
                import org.springframework.stereotype.Component;

                @Component
                public class OrderConsumer {
                    @KafkaListener(topics = "orders")
                    public void onOrder(String message) {}
                }
                """);

        // The "missing observability annotation" rules require an observability stack.
        List<Finding> findings =
                analyzeStaticPractice(
                        tempDir,
                        emptyBuildInfo(
                                List.of("org.springframework.boot:spring-boot-starter-actuator")));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_LISTENER_NO_OBSERVABILITY.ruleId());
    }

    @Test
    void doesNotFlagKafkaListenerWithTimed() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderConsumer.java"),
                """
                package com.example.demo;

                import io.micrometer.core.annotation.Timed;
                import org.springframework.kafka.annotation.KafkaListener;
                import org.springframework.stereotype.Component;

                @Component
                public class OrderConsumer {
                    @KafkaListener(topics = "orders")
                    @Timed("orders.consume")
                    public void onOrder(String message) {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_LISTENER_NO_OBSERVABILITY.ruleId());
    }

    // -------------------------------------------------------------------------
    // Validation gaps — @ModelAttribute without @Valid
    // -------------------------------------------------------------------------

    @Test
    void flagsModelAttributeWithoutValid() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderController.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Controller;
                import org.springframework.web.bind.annotation.ModelAttribute;
                import org.springframework.web.bind.annotation.PostMapping;

                @Controller
                public class OrderController {
                    @PostMapping("/orders")
                    public String placeOrder(@ModelAttribute CreateOrderRequest request) {
                        return "redirect:/orders";
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_MODEL_ATTRIBUTE_NO_VALID.ruleId());
    }

    @Test
    void doesNotFlagModelAttributeWithValid() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderController.java"),
                """
                package com.example.demo;

                import jakarta.validation.Valid;
                import org.springframework.stereotype.Controller;
                import org.springframework.web.bind.annotation.ModelAttribute;
                import org.springframework.web.bind.annotation.PostMapping;

                @Controller
                public class OrderController {
                    @PostMapping("/orders")
                    public String placeOrder(@Valid @ModelAttribute CreateOrderRequest request) {
                        return "redirect:/orders";
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_MODEL_ATTRIBUTE_NO_VALID.ruleId());
    }

    // ── SPRING_CROSS_ORIGIN_WILDCARD ──────────────────────────────────────────

    @Test
    void flagsCrossOriginWildcardOnControllerMethod() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ApiController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.CrossOrigin;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class ApiController {
                    @CrossOrigin(origins = "*")
                    @GetMapping("/data")
                    public String data() {
                        return "data";
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_CROSS_ORIGIN_WILDCARD.ruleId());
    }

    @Test
    void flagsBareCrossOriginAsAllowingAllOrigins() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ApiController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.CrossOrigin;
                import org.springframework.web.bind.annotation.RestController;

                @CrossOrigin
                @RestController
                public class ApiController {}
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_CROSS_ORIGIN_WILDCARD.ruleId());
    }

    @Test
    void doesNotFlagCrossOriginWithExplicitOrigin() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ApiController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.CrossOrigin;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class ApiController {
                    @CrossOrigin(origins = "https://app.example.com")
                    @GetMapping("/data")
                    public String data() {
                        return "data";
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_CROSS_ORIGIN_WILDCARD.ruleId());
    }

    // ── SPRING_DUPLICATE_EXCEPTION_HANDLER ────────────────────────────────────

    @Test
    void flagsDuplicateExceptionHandlerForSameType() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("GlobalExceptionHandler.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.ControllerAdvice;
                import org.springframework.web.bind.annotation.ExceptionHandler;

                @ControllerAdvice
                public class GlobalExceptionHandler {
                    @ExceptionHandler(IllegalArgumentException.class)
                    public String handleOne(IllegalArgumentException ex) {
                        return "one";
                    }

                    @ExceptionHandler(IllegalArgumentException.class)
                    public String handleTwo(IllegalArgumentException ex) {
                        return "two";
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        Finding f =
                findings.stream()
                        .filter(
                                finding ->
                                        FindingRules.SPRING_DUPLICATE_EXCEPTION_HANDLER
                                                .ruleId()
                                                .equals(finding.ruleId()))
                        .findFirst()
                        .orElse(null);
        assertThat(f).isNotNull();
        assertThat(f.message()).contains("IllegalArgumentException");
        assertThat(f.message()).contains("handleOne");
        assertThat(f.message()).contains("handleTwo");
    }

    @Test
    void doesNotFlagDistinctExceptionHandlers() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("GlobalExceptionHandler.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.ControllerAdvice;
                import org.springframework.web.bind.annotation.ExceptionHandler;

                @ControllerAdvice
                public class GlobalExceptionHandler {
                    @ExceptionHandler(IllegalArgumentException.class)
                    public String handleIllegalArg(IllegalArgumentException ex) {
                        return "one";
                    }

                    @ExceptionHandler(IllegalStateException.class)
                    public String handleIllegalState(IllegalStateException ex) {
                        return "two";
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_DUPLICATE_EXCEPTION_HANDLER.ruleId());
    }

    // ── SPRING_JPA_COLLECTION_EAGER_FETCH ─────────────────────────────────────

    @Test
    void flagsOneToManyEagerFetch() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Order.java"),
                """
                package com.example.demo;

                import jakarta.persistence.Entity;
                import jakarta.persistence.FetchType;
                import jakarta.persistence.OneToMany;
                import java.util.List;

                @Entity
                public class Order {
                    @OneToMany(mappedBy = "order", fetch = FetchType.EAGER)
                    private List<OrderLine> lines;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_JPA_COLLECTION_EAGER_FETCH.ruleId());
    }

    @Test
    void doesNotFlagOneToManyDefaultLazyFetch() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Order.java"),
                """
                package com.example.demo;

                import jakarta.persistence.Entity;
                import jakarta.persistence.OneToMany;
                import java.util.List;

                @Entity
                public class Order {
                    @OneToMany(mappedBy = "order")
                    private List<OrderLine> lines;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_JPA_COLLECTION_EAGER_FETCH.ruleId());
    }

    // ── SPRING_CORS_CREDENTIALS_WILDCARD ──────────────────────────────────────

    @Test
    void flagsCorsCredentialsWithWildcardOrigin() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("CorsConfig.java"),
                """
                package com.example.demo;

                import java.util.List;
                import org.springframework.web.cors.CorsConfiguration;

                public class CorsConfig {
                    public CorsConfiguration cors() {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOriginPatterns(List.of("*"));
                        config.setAllowCredentials(true);
                        return config;
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_CORS_CREDENTIALS_WILDCARD.ruleId());
    }

    @Test
    void doesNotFlagCorsCredentialsWithExplicitOrigins() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("CorsConfig.java"),
                """
                package com.example.demo;

                import java.util.List;
                import org.springframework.web.cors.CorsConfiguration;

                public class CorsConfig {
                    public CorsConfiguration cors() {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(List.of("https://app.example.com"));
                        config.setAllowCredentials(true);
                        return config;
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_CORS_CREDENTIALS_WILDCARD.ruleId());
    }

    // ── SPRING_TRANSACTIONAL_NON_PUBLIC_METHOD ────────────────────────────────

    @Test
    void flagsTransactionalOnProtectedMethodOnBoot2() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                public class OrderService {
                    @Transactional
                    protected void save() {}
                }
                """);

        BuildInfo boot2BuildInfo =
                new BuildInfo(
                        BuildTool.GRADLE,
                        true,
                        "11",
                        List.of(),
                        "2.7.18",
                        "build.gradle plugin",
                        "HIGH");
        List<Finding> findings = analyzeStaticPractice(tempDir, boot2BuildInfo);

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TRANSACTIONAL_NON_PUBLIC_METHOD.ruleId());
    }

    @Test
    void doesNotFlagTransactionalOnProtectedMethodOnBoot3() throws IOException {
        // Spring Framework 6.0 (Boot 3) advises protected/package-private @Transactional methods
        // on class-based proxies by default, so the rule must stay silent on Boot 3 projects.
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                public class OrderService {
                    @Transactional
                    protected void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_NON_PUBLIC_METHOD.ruleId());
    }

    @Test
    void doesNotFlagTransactionalOnPublicMethod() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                public class OrderService {
                    @Transactional
                    public void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_NON_PUBLIC_METHOD.ruleId());
    }

    // ── SPRING_TRANSACTIONAL_READONLY_WITH_WRITES ─────────────────────────────

    @Test
    void flagsWriteInsideReadOnlyTransaction() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                public class OrderService {
                    private final OrderRepository repository = null;

                    @Transactional(readOnly = true)
                    public void update(Order order) {
                        repository.save(order);
                    }
                }

                interface OrderRepository {
                    Order save(Order order);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        Finding finding =
                findings.stream()
                        .filter(
                                candidate ->
                                        FindingRules.SPRING_TRANSACTIONAL_READONLY_WITH_WRITES
                                                .ruleId()
                                                .equals(candidate.ruleId()))
                        .findFirst()
                        .orElseThrow();

        assertThat(finding.severity()).isEqualTo(FindingSeverity.WARNING);
    }

    @Test
    void doesNotFlagReadOnlyWritesRoutedThroughTenantTransactionExecutor() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("TenantService.java"),
                """
                package com.example.demo;

                import java.util.function.Supplier;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class TenantService {
                    private final TenantTransactionExecutor transactions = null;
                    private final OrderRepository repository = null;
                    private final DraftStore drafts = null;

                    @Transactional(readOnly = true)
                    void refresh(Order order) {
                        drafts.save(order);
                        transactions.execute(() -> repository.save(order));
                    }
                }

                class TenantTransactionExecutor {
                    @Transactional(propagation = Propagation.REQUIRES_NEW)
                    <T> T execute(Supplier<T> work) {
                        return work.get();
                    }
                }

                interface OrderRepository {
                    Order save(Order order);
                }

                interface DraftStore {
                    Order save(Order order);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_READONLY_WITH_WRITES.ruleId());
    }

    @Test
    void flagsReadOnlyWriteInsideDefaultTransactionTemplateCallback() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;
                import org.springframework.transaction.support.TransactionTemplate;

                @Service
                class OrderService {
                    private final TransactionTemplate transactions = null;
                    private final OrderRepository repository = null;

                    @Transactional(readOnly = true)
                    void update(Order order) {
                        transactions.execute(status -> repository.save(order));
                    }
                }

                interface OrderRepository {
                    Order save(Order order);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TRANSACTIONAL_READONLY_WITH_WRITES.ruleId());
    }

    @Test
    void flagsReadOnlyWriteInsideVisibleImmediateCustomExecutorWithoutRequiresNew()
            throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import java.util.function.Supplier;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    private final TenantTransactionExecutor transactions = null;
                    private final OrderRepository repository = null;

                    @Transactional(readOnly = true)
                    void update(Order order) {
                        transactions.execute(() -> repository.save(order));
                    }
                }

                class TenantTransactionExecutor {
                    <T> T execute(Supplier<T> work) {
                        return work.get();
                    }
                }

                interface OrderRepository {
                    Order save(Order order);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TRANSACTIONAL_READONLY_WITH_WRITES.ruleId());
    }

    @Test
    void doesNotTreatDeferredApplicationLambdaAsImmediatePersistenceWrite() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import java.util.function.Supplier;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    private final DeferredWorkQueue queue = null;
                    private final OrderRepository repository = null;

                    @Transactional(readOnly = true)
                    void schedule(Order order) {
                        queue.submit(() -> repository.save(order));
                    }
                }

                interface DeferredWorkQueue {
                    void submit(Supplier<Order> work);
                }

                interface OrderRepository {
                    Order save(Order order);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_READONLY_WITH_WRITES.ruleId());
    }

    @Test
    void doesNotFlagReadOnlyWritesWithoutProxyEligibleActiveTransaction() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    private final OrderRepository repository = null;

                    @Transactional(readOnly = true, propagation = Propagation.NOT_SUPPORTED)
                    void suspended(Order order) {
                        repository.save(order);
                    }

                    @Transactional(readOnly = true)
                    private void privateWrite(Order order) {
                        repository.save(order);
                    }
                }

                interface OrderRepository {
                    Order save(Order order);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_READONLY_WITH_WRITES.ruleId());
    }

    @Test
    void doesNotTreatUnexecutedCallbackParameterAsIndependentTransaction() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import java.util.function.Supplier;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    private final MultiCallbackExecutor transactions = null;
                    private final OrderRepository repository = null;

                    @Transactional(readOnly = true)
                    void update(Order order) {
                        transactions.execute(() -> repository.save(order), () -> {});
                    }
                }

                class MultiCallbackExecutor {
                    @Transactional(propagation = Propagation.REQUIRES_NEW)
                    <T> T execute(Supplier<T> work, Runnable cleanup) {
                        cleanup.run();
                        return null;
                    }
                }

                interface OrderRepository {
                    Order save(Order order);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_READONLY_WITH_WRITES.ruleId());
    }

    @Test
    void doesNotFlagReadOnlyTransactionWithoutWrites() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                public class OrderService {
                    private final OrderRepository repository = null;

                    @Transactional(readOnly = true)
                    public Order get(long id) {
                        return repository.findById(id);
                    }
                }

                interface OrderRepository {
                    Order findById(long id);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_READONLY_WITH_WRITES.ruleId());
    }

    // ── SPRING_JPA_MANYTOMANY_CASCADE_REMOVE ──────────────────────────────────

    @Test
    void flagsManyToManyCascadeRemove() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Post.java"),
                """
                package com.example.demo;

                import jakarta.persistence.CascadeType;
                import jakarta.persistence.Entity;
                import jakarta.persistence.ManyToMany;
                import java.util.Set;

                @Entity
                public class Post {
                    @ManyToMany(cascade = CascadeType.REMOVE)
                    private Set<Tag> tags;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_JPA_MANYTOMANY_CASCADE_REMOVE.ruleId());
    }

    @Test
    void doesNotFlagManyToManyCascadePersist() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Post.java"),
                """
                package com.example.demo;

                import jakarta.persistence.CascadeType;
                import jakarta.persistence.Entity;
                import jakarta.persistence.ManyToMany;
                import java.util.Set;

                @Entity
                public class Post {
                    @ManyToMany(cascade = CascadeType.PERSIST)
                    private Set<Tag> tags;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_JPA_MANYTOMANY_CASCADE_REMOVE.ruleId());
    }

    // ── SPRING_PROXY_ANNOTATION_ON_FINAL_METHOD ───────────────────────────────

    @Test
    void flagsTransactionalOnFinalMethod() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                public class OrderService {
                    @Transactional
                    public final void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_PROXY_ANNOTATION_ON_FINAL_METHOD.ruleId());
    }

    @Test
    void doesNotFlagTransactionalOnNonFinalMethod() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                public class OrderService {
                    @Transactional
                    public void save() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_PROXY_ANNOTATION_ON_FINAL_METHOD.ruleId());
    }

    // ── SPRING_BIGDECIMAL_DOUBLE_CONSTRUCTOR ──────────────────────────────────

    @Test
    void flagsBigDecimalDoubleConstructor() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Money.java"),
                """
                package com.example.demo;

                import java.math.BigDecimal;

                public class Money {
                    public BigDecimal rate() {
                        return new BigDecimal(0.1);
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_BIGDECIMAL_DOUBLE_CONSTRUCTOR.ruleId());
    }

    @Test
    void doesNotFlagBigDecimalStringConstructor() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("Money.java"),
                """
                package com.example.demo;

                import java.math.BigDecimal;

                public class Money {
                    public BigDecimal rate() {
                        return new BigDecimal("0.1");
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_BIGDECIMAL_DOUBLE_CONSTRUCTOR.ruleId());
    }

    // ── SPRING_TX_EVENT_LISTENER_WRITE_LOST ───────────────────────────────────

    @Test
    void flagsAfterCommitEventListenerWrite() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderEventHandler.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Component;
                import org.springframework.transaction.event.TransactionalEventListener;

                @Component
                public class OrderEventHandler {
                    private final AuditRepository repository = null;

                    @TransactionalEventListener
                    public void onOrderPlaced(OrderPlacedEvent event) {
                        repository.save(event);
                    }
                }

                interface AuditRepository {
                    Object save(Object event);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TX_EVENT_LISTENER_WRITE_LOST.ruleId());
    }

    @Test
    void doesNotFlagAfterCommitEventListenerWithRequiresNew() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderEventHandler.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Component;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;
                import org.springframework.transaction.event.TransactionalEventListener;

                @Component
                public class OrderEventHandler {
                    private final AuditRepository repository = null;

                    @TransactionalEventListener
                    @Transactional(propagation = Propagation.REQUIRES_NEW)
                    public void onOrderPlaced(OrderPlacedEvent event) {
                        repository.save(event);
                    }
                }

                interface AuditRepository {
                    Object save(Object event);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TX_EVENT_LISTENER_WRITE_LOST.ruleId());
    }

    @Test
    void doesNotFlagBeforeCommitEventListenerWrite() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderEventHandler.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Component;
                import org.springframework.transaction.event.TransactionPhase;
                import org.springframework.transaction.event.TransactionalEventListener;

                @Component
                public class OrderEventHandler {
                    private final AuditRepository repository = null;

                    @TransactionalEventListener(phase = TransactionPhase.BEFORE_COMMIT)
                    public void onOrderPlaced(OrderPlacedEvent event) {
                        repository.save(event);
                    }
                }

                interface AuditRepository {
                    Object save(Object event);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TX_EVENT_LISTENER_WRITE_LOST.ruleId());
    }

    // ── SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED ────────────────────────────────

    @Test
    void flagsCaughtTransactionalCollaboratorFailureFollowedByStatusWrite() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderWorker worker = null;
                    private final OrderRepository repository = null;

                    @Transactional
                    void complete() {
                        try {
                            worker.process();
                        } catch (RuntimeException failure) {
                            repository.save("FAILED");
                        }
                    }
                }

                @Service
                class OrderWorker {
                    @Transactional
                    void process() {}
                }

                interface OrderRepository {
                    void save(String status);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        Finding finding =
                findings.stream()
                        .filter(
                                candidate ->
                                        FindingRules.SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED
                                                .ruleId()
                                                .equals(candidate.ruleId()))
                        .findFirst()
                        .orElseThrow();
        assertThat(finding.confidence()).isEqualTo(FindingConfidence.MEDIUM);
    }

    @Test
    void doesNotFlagWhenAnotherPotentiallyThrowingCallFollowsTransactionalCollaborator()
            throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderWorker worker = null;
                    private final Metrics metrics = null;
                    private final OrderRepository repository = null;

                    @Transactional
                    void complete() {
                        try {
                            worker.process();
                            metrics.record();
                        } catch (RuntimeException failure) {
                            repository.save("FAILED");
                        }
                    }
                }

                @Service
                class OrderWorker {
                    @Transactional
                    void process() {}
                }

                interface Metrics {
                    void record();
                }

                interface OrderRepository {
                    void save(String status);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED.ruleId());
    }

    @Test
    void doesNotFlagSwallowedRuleWithoutProxyEligibleActiveOuterTransaction() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderWorker worker = null;
                    private final OrderRepository repository = null;

                    @Transactional(propagation = Propagation.NOT_SUPPORTED)
                    void suspended() {
                        try {
                            worker.process();
                        } catch (RuntimeException failure) {
                            repository.save("FAILED");
                        }
                    }

                    @Transactional
                    private void privateComplete() {
                        try {
                            worker.process();
                        } catch (RuntimeException failure) {
                            repository.save("FAILED");
                        }
                    }
                }

                @Service
                class OrderWorker {
                    @Transactional
                    void process() {}
                }

                interface OrderRepository {
                    void save(String status);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED.ruleId());
    }

    @Test
    void doesNotFlagSwallowedRuleForUnsafeTryExpressionsOrAdditionalStatements()
            throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderWorker worker = null;
                    private final OrderRepository repository = null;
                    private Order order;
                    private int status;

                    @Transactional
                    void unsafeArgument() {
                        try {
                            worker.process(order.id);
                        } catch (RuntimeException failure) {
                            repository.save("FAILED");
                        }
                    }

                    @Transactional
                    void arithmeticAfterCall(int divisor) {
                        try {
                            worker.process(1);
                            status = 10 / divisor;
                        } catch (RuntimeException failure) {
                            repository.save("FAILED");
                        }
                    }

                    @Transactional
                    void fieldAccessAfterCall() {
                        try {
                            worker.process(1);
                            status = order.id;
                        } catch (RuntimeException failure) {
                            repository.save("FAILED");
                        }
                    }
                }

                @Service
                class OrderWorker {
                    @Transactional
                    void process(int id) {}
                }

                interface OrderRepository {
                    void save(String status);
                }

                class Order {
                    int id;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED.ruleId());
    }

    @Test
    void flagsFailureStatusWrittenThroughDefaultTransactionTemplate() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;
                import org.springframework.transaction.support.TransactionTemplate;

                @Service
                class OrderManager {
                    private final OrderWorker worker = null;
                    private final TransactionTemplate transactions = null;
                    private final OrderRepository repository = null;

                    @Transactional
                    void complete() {
                        try {
                            worker.process();
                        } catch (RuntimeException failure) {
                            transactions.execute(status -> repository.save("FAILED"));
                        }
                    }
                }

                @Service
                class OrderWorker {
                    @Transactional
                    void process() {}
                }

                interface OrderRepository {
                    String save(String status);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED.ruleId());
    }

    @Test
    void doesNotFlagBroadCatchWithoutTransactionalCollaboratorFailure() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final PayloadParser parser = null;
                    private final OrderRepository repository = null;

                    @Transactional
                    void complete(String payload) {
                        try {
                            parser.parse(payload);
                        } catch (RuntimeException failure) {
                            repository.save("INVALID");
                        }
                    }
                }

                interface PayloadParser {
                    void parse(String payload);
                }

                interface OrderRepository {
                    void save(String status);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED.ruleId());
    }

    @Test
    void doesNotFlagFailureStatusWrittenInSeparateProgrammaticTransaction() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import java.util.function.Supplier;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderWorker worker = null;
                    private final TenantTransactionExecutor transactions = null;
                    private final OrderRepository repository = null;

                    @Transactional
                    void complete() {
                        try {
                            worker.process();
                        } catch (RuntimeException failure) {
                            transactions.execute(() -> repository.save("FAILED"));
                        }
                    }
                }

                @Service
                class OrderWorker {
                    @Transactional
                    void process() {}
                }

                class TenantTransactionExecutor {
                    @Transactional(propagation = Propagation.REQUIRES_NEW)
                    <T> T execute(Supplier<T> work) {
                        return work.get();
                    }
                }

                interface OrderRepository {
                    String save(String status);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED.ruleId());
    }

    @Test
    void doesNotFlagCaughtFailureWhenCatchMarksRollbackOnly() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;
                import org.springframework.transaction.interceptor.TransactionAspectSupport;

                @Service
                class OrderManager {
                    private final OrderWorker worker = null;
                    private final OrderRepository repository = null;

                    @Transactional
                    void complete() {
                        try {
                            worker.process();
                        } catch (RuntimeException failure) {
                            repository.save("FAILED");
                            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
                        }
                    }
                }

                @Service
                class OrderWorker {
                    @Transactional
                    void process() {}
                }

                interface OrderRepository {
                    void save(String status);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED.ruleId());
    }

    @Test
    void doesNotFlagRequiresNewCollaboratorFailureAsSharedTransactionDoomed() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderManager.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderManager {
                    private final OrderWorker worker = null;
                    private final OrderRepository repository = null;

                    @Transactional
                    void complete() {
                        try {
                            worker.process();
                        } catch (RuntimeException failure) {
                            repository.save("FAILED");
                        }
                    }
                }

                @Service
                class OrderWorker {
                    @Transactional(propagation = Propagation.REQUIRES_NEW)
                    void process() {}
                }

                interface OrderRepository {
                    void save(String status);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED.ruleId());
    }

    // ── SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK ─────────────────────

    @Test
    void flagsTransactionalDeclaringCheckedExceptionWithoutRollbackFor() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import java.io.IOException;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                public class OrderService {
                    private final OrderRepository repository = null;

                    @Transactional
                    public void importOrders() throws IOException {
                        repository.save(new Object());
                        throw new IOException("boom");
                    }
                }

                interface OrderRepository {
                    Object save(Object value);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK.ruleId());
    }

    @Test
    void doesNotFlagCheckedExceptionThrownBeforePersistenceWrite() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import java.io.IOException;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    private final OrderRepository repository = null;

                    @Transactional
                    void importOrders(boolean invalid) throws IOException {
                        if (invalid) {
                            throw new IOException("invalid input");
                        }
                        repository.save(new Object());
                    }
                }

                interface OrderRepository {
                    Object save(Object value);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(
                        FindingRules.SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK.ruleId());
    }

    @Test
    void doesNotFlagCheckedThrowAfterBranchContainedWrite() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import java.io.IOException;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    private final OrderRepository repository = null;

                    @Transactional
                    void importOrders(boolean persist) throws IOException {
                        if (persist) {
                            repository.save(new Object());
                        }
                        throw new IOException("boom");
                    }
                }

                interface OrderRepository {
                    Object save(Object value);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(
                        FindingRules.SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK.ruleId());
    }

    @Test
    void doesNotFlagCheckedThrowAcrossConditionalReturnPath() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import java.io.IOException;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    private final OrderRepository repository = null;

                    @Transactional
                    void importOrders(boolean stop) throws IOException {
                        repository.save(new Object());
                        if (stop) {
                            return;
                        }
                        throw new IOException("boom");
                    }
                }

                interface OrderRepository {
                    Object save(Object value);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(
                        FindingRules.SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK.ruleId());
    }

    @Test
    void doesNotFlagCheckedRollbackWithoutProxyEligibleActiveTransaction() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import java.io.IOException;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Propagation;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class OrderService {
                    private final OrderRepository repository = null;

                    @Transactional(propagation = Propagation.NOT_SUPPORTED)
                    void suspended() throws IOException {
                        repository.save(new Object());
                        throw new IOException("boom");
                    }

                    @Transactional
                    private void privateImport() throws IOException {
                        repository.save(new Object());
                        throw new IOException("boom");
                    }
                }

                interface OrderRepository {
                    Object save(Object value);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(
                        FindingRules.SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK.ruleId());
    }

    @Test
    void doesNotTreatAuthenticationExceptionAsChecked() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("LoginService.java"),
                """
                package com.example.demo;

                import org.springframework.security.core.AuthenticationException;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                class LoginService {
                    private final LoginRepository repository = null;

                    @Transactional
                    void login() throws AuthenticationException {
                        repository.save(new Object());
                        throw new AuthenticationException("denied") {};
                    }
                }

                interface LoginRepository {
                    Object save(Object value);
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(
                        FindingRules.SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK.ruleId());
    }

    @Test
    void doesNotFlagTransactionalCheckedExceptionWithRollbackFor() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import java.io.IOException;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                public class OrderService {
                    @Transactional(rollbackFor = Exception.class)
                    public void importOrders() throws IOException {
                        throw new IOException("boom");
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(
                        FindingRules.SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK.ruleId());
    }

    @Test
    void doesNotFlagTransactionalWithoutCheckedException() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("OrderService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;

                @Service
                public class OrderService {
                    @Transactional
                    public void process() {}
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(
                        FindingRules.SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK.ruleId());
    }

    // ── SPRING_PATH_VARIABLE_TEMPLATE_MISMATCH ────────────────────────────────

    @Test
    void flagsPathVariableNameMissingFromTemplate() throws IOException {
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("UserController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.PathVariable;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class UserController {
                    @GetMapping("/users/{id}")
                    public String user(@PathVariable("userId") String userId) {
                        return userId;
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .anyMatch(
                        finding ->
                                FindingRules.SPRING_PATH_VARIABLE_TEMPLATE_MISMATCH
                                                .ruleId()
                                                .equals(finding.ruleId())
                                        && "UserController#user".equals(finding.target()));
    }

    @Test
    void doesNotFlagPathVariableMatchingClassLevelTemplate() throws IOException {
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("UserController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.PathVariable;
                import org.springframework.web.bind.annotation.RequestMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                @RequestMapping("/tenants/{tenantId}")
                public class UserController {
                    @GetMapping("/users/{id}")
                    public String user(
                            @PathVariable("tenantId") String tenantId,
                            @PathVariable("id") String id) {
                        return tenantId + id;
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_PATH_VARIABLE_TEMPLATE_MISMATCH.ruleId());
    }

    @Test
    void doesNotFlagPathVariableWhenMappingPathIsNonLiteral() throws IOException {
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("UserController.java"),
                """
                package com.example.demo;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.PathVariable;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class UserController {
                    static final String PATH = "/users/{userId}";

                    @GetMapping(PATH)
                    public String user(@PathVariable("userId") String userId) {
                        return userId;
                    }
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_PATH_VARIABLE_TEMPLATE_MISMATCH.ruleId());
    }

    // ── SPRING_INJECTION_ON_STATIC_FIELD ──────────────────────────────────────

    @Test
    void flagsInjectionAnnotationOnStaticField() throws IOException {
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("StaticHolder.java"),
                """
                package com.example.demo;

                import org.springframework.beans.factory.annotation.Autowired;
                import org.springframework.stereotype.Service;

                @Service
                public class StaticHolder {
                    @Autowired private static Helper helper;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .contains(FindingRules.SPRING_INJECTION_ON_STATIC_FIELD.ruleId());
    }

    @Test
    void doesNotFlagInjectionOnInstanceField() throws IOException {
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("InstanceHolder.java"),
                """
                package com.example.demo;

                import org.springframework.beans.factory.annotation.Autowired;
                import org.springframework.stereotype.Service;

                @Service
                public class InstanceHolder {
                    @Autowired private Helper helper;
                }
                """);

        List<Finding> findings = analyzeStaticPractice(tempDir, emptyBuildInfo(List.of()));

        assertThat(findings)
                .extracting(Finding::ruleId)
                .doesNotContain(FindingRules.SPRING_INJECTION_ON_STATIC_FIELD.ruleId());
    }
}

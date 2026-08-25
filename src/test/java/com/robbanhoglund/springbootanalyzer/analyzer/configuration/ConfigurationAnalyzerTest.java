package com.robbanhoglund.springbootanalyzer.analyzer.configuration;

import static org.assertj.core.api.Assertions.assertThat;

import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildInfo;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildTool;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingSeverity;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.PropertyKind;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.PropertyReference;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigurationAnalyzerTest {

    private final PropertyNameNormalizer propertyNameNormalizer = new PropertyNameNormalizer();
    private final ConfigurationAnalyzer analyzer =
            new ConfigurationAnalyzer(
                    new ConfigurationFileScanner(),
                    new PropertiesFileParser(),
                    new YamlConfigurationParser(),
                    new SpringConfigurationMetadataCatalog(),
                    new ConfigurationPropertiesClassAnalyzer(propertyNameNormalizer),
                    new PropertyReferenceAnalyzer(propertyNameNormalizer),
                    new SensitivePropertyValueRedactor(),
                    propertyNameNormalizer);

    @TempDir Path tempDir;

    @Test
    void readsAllDocumentsInMultiDocumentYamlAndBindsActivationProfile() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(
                tempDir.resolve("src/main/resources/application.yml"),
                """
                server:
                  port: 8080
                ---
                spring:
                  config:
                    activate:
                      on-profile: prod
                prod:
                  only:
                    flag: true
                """);

        var analysis =
                analyzer.analyze(
                                tempDir,
                                new BuildInfo(
                                        BuildTool.GRADLE,
                                        true,
                                        "25",
                                        java.util.List.of(),
                                        "3.5.13",
                                        "build.gradle plugin",
                                        "HIGH"))
                        .configurationAnalysis();

        // The property in the second document must not be silently dropped.
        var prodOnly =
                analysis.properties().stream()
                        .filter(property -> property.name().equals("prod.only.flag"))
                        .findFirst()
                        .orElseThrow();
        // It must be attributed to the in-file activation profile, not the filename profile.
        assertThat(prodOnly.profile()).isEqualTo("prod");

        var serverPort =
                analysis.properties().stream()
                        .filter(property -> property.name().equals("server.port"))
                        .findFirst()
                        .orElseThrow();
        assertThat(serverPort.profile()).isEqualTo("default");

        assertThat(analysis.summary().profiles()).contains("default", "prod");
    }

    @Test
    void analyzesConfigurationFilesMetadataCustomPropertiesAndReferences() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources/META-INF"));
        Files.writeString(
                tempDir.resolve("src/main/resources/application.properties"),
                """
                server.port=8080
                trading.enabled=true
                trading.api-key=secret-value
                legacy.flag=true
                mystery.value=surprise
                spring.mail.properties.mail.smtp.auth=true
                """);
        Files.writeString(
                tempDir.resolve("src/main/resources/application-prod.properties"),
                """
                spring.jpa.hibernate.ddl-auto=update
                management.endpoints.web.exposure.include=*
                management.endpoint.health.show-details=always
                springdoc.api-docs.enabled=true
                trading.api-key=${TRADING_API_KEY}
                """);
        Files.writeString(
                tempDir.resolve("src/main/resources/application-dev.yml"),
                """
                management:
                  endpoints:
                    web:
                      exposure:
                        include:
                          - health
                          - info
                trading:
                  risk-per-trade: 2
                """);
        Files.writeString(
                tempDir.resolve(
                        "src/main/resources/META-INF/additional-spring-configuration-metadata.json"),
                """
                {
                  "properties": [
                    {
                      "name": "legacy.flag",
                      "type": "java.lang.Boolean",
                      "description": "Legacy toggle.",
                      "deprecated": true,
                      "deprecation": {
                        "reason": "Replaced by newer behavior."
                      }
                    }
                  ]
                }
                """);

        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("TradingProperties.java"),
                """
                package com.example.demo;

                import jakarta.validation.constraints.NotNull;
                import org.springframework.boot.context.properties.ConfigurationProperties;

                @ConfigurationProperties(prefix = "trading")
                public record TradingProperties(
                        @NotNull Boolean enabled,
                        Integer riskPerTrade,
                        Notifications notifications
                ) {
                    public static class Notifications {
                        Events events;
                    }

                    public static class Events {
                        boolean orderFills;
                        boolean stopLoss;
                    }
                }
                """);
        Files.writeString(
                sourceRoot.resolve("TradingService.java"),
"""
package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "trading", name = "enabled", havingValue = "true", matchIfMissing = true)
public class TradingService {

    @Value("${trading.enabled:false}")
    private boolean enabled;

    @Scheduled(fixedDelayString = "${trading.jobs.strategy.fixed-delay:PT5M}")
    void runJob() {
    }

    public boolean isEnabled(Environment environment) {
        return environment.getProperty("trading.enabled", "false").equals("true")
                && environment.containsProperty("trading.missing")
                && environment.getRequiredProperty("trading.api-key") != null;
    }
}
""");

        var result =
                analyzer.analyze(
                        tempDir,
                        new BuildInfo(
                                BuildTool.GRADLE,
                                true,
                                "25",
                                java.util.List.of(
                                        "org.springframework.boot:spring-boot-starter-mail",
                                        "org.springframework.boot:spring-boot-starter-data-jpa",
                                        "org.springdoc:springdoc-openapi-starter-webmvc-ui:2.3.0"),
                                "3.5.13",
                                "build.gradle plugin",
                                "HIGH"));
        var analysis = result.configurationAnalysis();

        assertThat(analysis.files())
                .extracting(file -> file.path())
                .contains(
                        "src/main/resources/application.properties",
                        "src/main/resources/application-dev.yml");
        assertThat(analysis.files()).extracting(file -> file.profile()).contains("default", "dev");

        assertThat(analysis.properties())
                .extracting(property -> property.name())
                .contains(
                        "server.port",
                        "management.endpoints.web.exposure.include[0]",
                        "trading.enabled",
                        "trading.risk-per-trade",
                        "trading.notifications.events.order-fills",
                        "trading.notifications.events.stop-loss");

        var serverPort =
                analysis.properties().stream()
                        .filter(property -> property.name().equals("server.port"))
                        .findFirst()
                        .orElseThrow();
        assertThat(serverPort.documentation().known()).isTrue();
        assertThat(serverPort.kind()).isEqualTo(PropertyKind.SPRING_BOOT);

        var customProperty =
                analysis.properties().stream()
                        .filter(property -> property.name().equals("trading.enabled"))
                        .findFirst()
                        .orElseThrow();
        assertThat(customProperty.kind()).isEqualTo(PropertyKind.CUSTOM_CONFIGURATION_PROPERTIES);
        assertThat(customProperty.references())
                .extracting(reference -> reference.referenceType())
                .contains("@Value", "Environment#getProperty", "@ConditionalOnProperty");
        assertThat(customProperty.references())
                .anyMatch(
                        reference ->
                                "true".equals(reference.expectedValue())
                                        && Boolean.TRUE.equals(reference.matchIfMissing()));

        var sensitiveProperties =
                analysis.properties().stream()
                        .filter(property -> property.name().equals("trading.api-key"))
                        .toList();
        assertThat(sensitiveProperties).allMatch(property -> property.valueRedacted());
        assertThat(sensitiveProperties)
                .extracting(property -> property.value())
                .contains("[redacted]", "${TRADING_API_KEY}");

        var mailMapProperty =
                analysis.properties().stream()
                        .filter(
                                property ->
                                        property.name()
                                                .equals("spring.mail.properties.mail.smtp.auth"))
                        .findFirst()
                        .orElseThrow();
        assertThat(mailMapProperty.kind()).isEqualTo(PropertyKind.SPRING_BOOT_MAP_PROPERTY);
        assertThat(mailMapProperty.documentation().sourceType()).contains("MailProperties");

        var springdocProperty =
                analysis.properties().stream()
                        .filter(property -> property.name().equals("springdoc.api-docs.enabled"))
                        .findFirst()
                        .orElseThrow();
        assertThat(springdocProperty.kind()).isEqualTo(PropertyKind.THIRD_PARTY);

        assertThat(analysis.codeReferences())
                .extracting(reference -> reference.propertyName())
                .contains(
                        "trading.enabled",
                        "trading.missing",
                        "trading.api-key",
                        "trading.jobs.strategy.fixed-delay");
        assertThat(analysis.codeReferences())
                .anyMatch(reference -> "@Scheduled".equals(reference.referenceType()));

        assertThat(analysis.summary().configuredPropertyCount()).isGreaterThanOrEqualTo(5);
        assertThat(analysis.summary().profiles()).contains("default", "dev", "prod");

        assertThat(result.findings())
                .extracting(finding -> finding.severity())
                .contains(FindingSeverity.WARNING, FindingSeverity.INFO);
        assertThat(result.findings())
                .extracting(finding -> finding.message())
                .anyMatch(message -> message.contains("could not be matched"))
                .anyMatch(message -> message.contains("trading.missing"))
                .anyMatch(message -> message.contains("Deprecated configuration property"))
                .anyMatch(message -> message.contains("literal value"))
                .anyMatch(message -> message.contains("Profile-specific configuration files"))
                // ddl-auto and exposure.include=* are reported by the dedicated
                // SPRING_DDL_AUTO_DESTRUCTIVE_PROD / SPRING_ACTUATOR_ENDPOINT_EXPOSED_PROD rules
                // in ConfigurationFindingAnalyzer, not as generic risky-prod-config findings.
                .anyMatch(message -> message.contains("health.show-details=always"));
    }

    @Test
    void distinguishesCredentialTokensFromTokenLimitsAndFlagsLiteralFallbacks() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(
                tempDir.resolve("src/main/resources/application.properties"),
                """
                summary.ai.max-output-tokens=900
                openai.max-output-tokens=1200
                token-limit=1000
                openai.api-key=sk-live-secret
                openai.safe-api-key=${OPENAI_API_KEY}
                openai.fallback-api-key=${OPENAI_API_KEY:sk-fallback-secret}
                spring.datasource.password=${DB_PASSWORD:secret}
                deployment.path=/srv/application
                security.password-policy=strict
                service.password=${SERVICE_PASSWORD:CHANGE_ME_OR_SET_ENV}
                github.pat=ghp-literal-token
                """);

        var result = analyzer.analyze(tempDir, emptyBuildInfo());
        var analysis = result.configurationAnalysis();

        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "summary.ai.max-output-tokens".equals(property.name())
                                        && !property.valueRedacted());
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "openai.max-output-tokens".equals(property.name())
                                        && !property.valueRedacted());
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "token-limit".equals(property.name()) && !property.valueRedacted());
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "openai.api-key".equals(property.name())
                                        && property.valueRedacted());
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "openai.safe-api-key".equals(property.name())
                                        && property.placeholderValue()
                                        && "${OPENAI_API_KEY}".equals(property.value()));

        assertThat(result.findings())
                .filteredOn(finding -> "SPRING_SECRET_LITERAL".equals(finding.ruleId()))
                .extracting(finding -> finding.target())
                .contains("openai.api-key", "openai.fallback-api-key")
                .doesNotContain(
                        "summary.ai.max-output-tokens",
                        "openai.max-output-tokens",
                        "openai.safe-api-key",
                        "token-limit",
                        "deployment.path",
                        "security.password-policy",
                        "service.password")
                .contains("github.pat");
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "deployment.path".equals(property.name())
                                        && !property.valueRedacted());
        assertThat(result.findings())
                .filteredOn(
                        finding ->
                                "SPRING_SECRET_WEAK_PLACEHOLDER_DEFAULT".equals(finding.ruleId()))
                .extracting(finding -> finding.target())
                .contains("spring.datasource.password");
    }

    @Test
    void recognizesWildcardSpringBootPropertiesAndIgnoresJvmSystemPropertyReferences()
            throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(
                tempDir.resolve("src/main/resources/application.properties"),
                """
                logging.level.xfeeder=INFO
                logging.level.org.springframework.web.client=WARN
                management.endpoint.health.show-details=always
                management.endpoints.web.exposure.include=health,info
                spring.mail.properties.mail.smtp.auth=true
                spring.datasource.hikari.maximum-pool-size=10
                custom.unknown.property=value
                """);
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ConfigReferences.java"),
                """
                package com.example.demo;

                import org.springframework.beans.factory.annotation.Value;
                import org.springframework.core.env.Environment;
                import org.springframework.stereotype.Component;

                @Component
                class ConfigReferences {

                    @Value("${my.application.setting}")
                    String appSetting;

                    String read(Environment environment) {
                        return System.getProperty("java.version")
                                + System.getProperty("java.vm.name")
                                + System.getProperty("java.runtime.version")
                                + environment.getProperty("my.application.setting");
                    }
                }
                """);

        var result = analyzer.analyze(tempDir, emptyBuildInfo());
        var analysis = result.configurationAnalysis();

        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "logging.level.xfeeder".equals(property.name())
                                        && property.kind()
                                                == PropertyKind.SPRING_BOOT_MAP_PROPERTY);
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "logging.level.org.springframework.web.client"
                                                .equals(property.name())
                                        && property.kind()
                                                == PropertyKind.SPRING_BOOT_MAP_PROPERTY);
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "management.endpoint.health.show-details".equals(property.name())
                                        && property.kind() == PropertyKind.SPRING_BOOT);
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "management.endpoints.web.exposure.include".equals(property.name())
                                        && property.kind() == PropertyKind.SPRING_BOOT);
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "spring.mail.properties.mail.smtp.auth".equals(property.name())
                                        && property.kind()
                                                == PropertyKind.SPRING_BOOT_MAP_PROPERTY);
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "spring.datasource.hikari.maximum-pool-size".equals(property.name())
                                        && property.kind() == PropertyKind.SPRING_BOOT);
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "custom.unknown.property".equals(property.name())
                                        && property.kind() == PropertyKind.UNKNOWN);
        assertThat(analysis.properties())
                .noneMatch(
                        property ->
                                "java.version".equals(property.name())
                                        || "java.vm.name".equals(property.name())
                                        || "java.runtime.version".equals(property.name()));

        assertThat(result.findings())
                .extracting(finding -> finding.message())
                .noneMatch(message -> message != null && message.contains("java.version"))
                .noneMatch(message -> message != null && message.contains("java.vm.name"))
                .noneMatch(message -> message != null && message.contains("java.runtime.version"))
                .anyMatch(message -> message != null && message.contains("my.application.setting"));
        assertThat(result.findings())
                .filteredOn(finding -> "CONFIG_CODE_REFERENCE_MISSING".equals(finding.ruleId()))
                .singleElement()
                .satisfies(
                        finding -> {
                            assertThat(finding.primaryLocation()).isNotNull();
                            assertThat(finding.primaryLocation().filePath())
                                    .isEqualTo(
                                            "src/main/java/com/example/demo/ConfigReferences.java");
                            assertThat(finding.primaryLocation().startLine()).isGreaterThan(0);
                            assertThat(finding.occurrences()).hasSize(2);
                        });
    }

    @Test
    void ignoresGradleAndWrapperPropertyLookupsWhenCheckingMissingSpringConfiguration()
            throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(
                tempDir.resolve("src/main/resources/application.properties"),
                """
                app.mode=demo
                """);
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("BuildSupport.java"),
                """
                package com.example.demo;

                import java.util.Properties;
                import org.springframework.core.env.Environment;
                import org.springframework.stereotype.Component;

                @Component
                class BuildSupport {

                    String read(Environment environment, Properties properties) {
                        return properties.getProperty("distributionUrl")
                                + properties.getProperty("org.gradle.jvmargs")
                                + properties.getProperty("java_version")
                                + environment.getProperty("spring.application.name");
                    }
                }
                """);

        var result = analyzer.analyze(tempDir, emptyBuildInfo());

        assertThat(result.configurationAnalysis().codeReferences())
                .extracting(PropertyReference::propertyName)
                .contains("spring.application.name")
                .doesNotContain("distributionurl", "org.gradle.jvmargs", "java_version");

        assertThat(result.findings())
                .filteredOn(finding -> "CONFIG_CODE_REFERENCE_MISSING".equals(finding.ruleId()))
                .extracting(Finding::target)
                .contains("spring.application.name")
                .doesNotContain("distributionurl", "org.gradle.jvmargs", "java_version");
    }

    @Test
    void attachesProfileSpecificFilesAsOccurrencesWithoutFakeLineNumbers() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(
                tempDir.resolve("src/main/resources/application.properties"), "app.mode=default");
        Files.writeString(
                tempDir.resolve("src/main/resources/application-prod.properties"), "app.mode=prod");
        Files.writeString(
                tempDir.resolve("src/main/resources/application-dev.yml"),
                """
                app:
                  mode: dev
                """);

        var result = analyzer.analyze(tempDir, emptyBuildInfo());

        assertThat(result.findings())
                .filteredOn(finding -> "SPRING_PROFILE_SPECIFIC_CONFIG".equals(finding.ruleId()))
                .singleElement()
                .satisfies(
                        finding -> {
                            assertThat(finding.primaryLocation()).isNotNull();
                            assertThat(finding.primaryLocation().filePath())
                                    .isEqualTo("src/main/resources/application-dev.yml");
                            assertThat(finding.primaryLocation().startLine()).isZero();
                            assertThat(finding.occurrences())
                                    .extracting(occurrence -> occurrence.location().filePath())
                                    .contains(
                                            "src/main/resources/application-dev.yml",
                                            "src/main/resources/application-prod.properties");
                            assertThat(finding.occurrences())
                                    .allSatisfy(
                                            occurrence ->
                                                    assertThat(occurrence.location().startLine())
                                                            .isZero());
                        });
    }

    @Test
    void flagsWeakSecretPlaceholderDefaultsWithoutFlaggingSafePlaceholders() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(
                tempDir.resolve("src/main/resources/application.properties"),
                """
                admin.security.password=${ADMIN_PASSWORD:admin}
                spring.datasource.password=${DB_PASSWORD:password}
                external.api.key=${API_KEY:}
                external.other.password=${ADMIN_PASSWORD}
                """);

        var result = analyzer.analyze(tempDir, emptyBuildInfo());

        assertThat(result.findings())
                .filteredOn(
                        finding ->
                                "SPRING_SECRET_WEAK_PLACEHOLDER_DEFAULT".equals(finding.ruleId()))
                .extracting(finding -> finding.target())
                .contains("admin.security.password", "spring.datasource.password")
                .doesNotContain("external.api.key", "external.other.password");
    }

    @Test
    void classifiesNestedAndMapStyleCustomPropertiesUnderConfigurationPrefixes()
            throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(
                tempDir.resolve("src/main/resources/application.properties"),
                """
                reports.cleanup.initial-delay-ms=15000
                ticker.overrides[saab]=SAAB-B.ST
                logging.level.xfeeder=INFO
                unknown.custom.typo=true
                """);

        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ReportCleanupProperties.java"),
                """
                package com.example.demo;

                import org.springframework.boot.context.properties.ConfigurationProperties;

                @ConfigurationProperties(prefix = "reports.cleanup")
                public record ReportCleanupProperties(Long retentionDays) {
                }
                """);
        Files.writeString(
                sourceRoot.resolve("TickerProperties.java"),
                """
                package com.example.demo;

                import java.util.Map;
                import org.springframework.boot.context.properties.ConfigurationProperties;

                @ConfigurationProperties(prefix = "ticker")
                public record TickerProperties(Map<String, String> overrides) {
                }
                """);

        var result = analyzer.analyze(tempDir, emptyBuildInfo());
        var analysis = result.configurationAnalysis();

        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "reports.cleanup.initial-delay-ms".equals(property.name())
                                        && property.kind()
                                                == PropertyKind.CUSTOM_CONFIGURATION_PROPERTIES);
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "ticker.overrides[saab]".equals(property.name())
                                        && property.kind()
                                                == PropertyKind.CUSTOM_CONFIGURATION_PROPERTIES);
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "logging.level.xfeeder".equals(property.name())
                                        && property.kind()
                                                == PropertyKind.SPRING_BOOT_MAP_PROPERTY);
        assertThat(analysis.properties())
                .anyMatch(
                        property ->
                                "unknown.custom.typo".equals(property.name())
                                        && property.kind() == PropertyKind.UNKNOWN);

        assertThat(result.findings())
                .filteredOn(finding -> "CONFIG_UNKNOWN_PROPERTY".equals(finding.ruleId()))
                .extracting(finding -> finding.evidence())
                .allMatch(
                        evidence ->
                                evidence != null
                                        && !evidence.contains("reports.cleanup.initial-delay-ms")
                                        && !evidence.contains("ticker.overrides[saab]"));
    }

    @Test
    void resolvesPrimaryConfigurationFromDependencyOverlayConfigurationPropertiesContract()
            throws IOException {
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

        var result = analyzer.analyze(tempDir, emptyBuildInfo());

        assertThat(result.configurationAnalysis().properties())
                .filteredOn(property -> property.name().equals("service.message"))
                .singleElement()
                .satisfies(
                        property -> {
                            assertThat(property.kind())
                                    .isEqualTo(PropertyKind.CUSTOM_CONFIGURATION_PROPERTIES);
                            assertThat(property.documentation()).isNotNull();
                        });
        assertThat(result.findings())
                .filteredOn(finding -> "CONFIG_UNKNOWN_PROPERTY".equals(finding.ruleId()))
                .extracting(Finding::evidence)
                .noneMatch(evidence -> evidence != null && evidence.contains("service.message"));
    }

    private BuildInfo emptyBuildInfo() {
        return new BuildInfo(
                BuildTool.GRADLE,
                true,
                "25",
                java.util.List.of(),
                "3.5.13",
                "build.gradle plugin",
                "HIGH");
    }
}

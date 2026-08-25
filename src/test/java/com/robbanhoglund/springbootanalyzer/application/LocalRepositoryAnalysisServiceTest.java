package com.robbanhoglund.springbootanalyzer.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.robbanhoglund.springbootanalyzer.analyzer.StaticAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.model.AnalysisResult;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildInfo;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildTool;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingCategory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRuntimeDetection;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingSeverity;
import com.robbanhoglund.springbootanalyzer.analyzer.model.SourceLocation;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.ConfigurationAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleAnalysisStatus;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleModelAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.HttpSurfaceAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.messaging.MessagingAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.scheduling.SchedulingAnalysis;
import com.robbanhoglund.springbootanalyzer.api.dto.AnalysisMode;
import com.robbanhoglund.springbootanalyzer.api.dto.AnalyzeRepositoryResponse;
import com.robbanhoglund.springbootanalyzer.git.GitRepositoryReference;
import com.robbanhoglund.springbootanalyzer.suppression.SuppressionService;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

class LocalRepositoryAnalysisServiceTest {

    @TempDir Path tempDir;

    @Test
    void analyzesProvidedDirectoryWithoutCloneAndMapsExistingResponseModel() {
        StaticAnalyzer staticAnalyzer = mock(StaticAnalyzer.class);
        LocalRepositoryAnalysisService service = service(staticAnalyzer);
        AnalysisResult analysisResult = analysisResult();
        given(staticAnalyzer.analyze(org.mockito.ArgumentMatchers.any(), eq(tempDir), eq("repo-1")))
                .willReturn(analysisResult);

        AnalyzeRepositoryResponse response =
                service.analyze(
                        tempDir,
                        "repo-1",
                        "https://github.com/example/demo.git",
                        "main",
                        AnalysisMode.EXTENDED);

        ArgumentCaptor<GitRepositoryReference> referenceCaptor =
                ArgumentCaptor.forClass(GitRepositoryReference.class);
        verify(staticAnalyzer).analyze(referenceCaptor.capture(), eq(tempDir), eq("repo-1"));
        assertThat(referenceCaptor.getValue().analysisMode()).isEqualTo(AnalysisMode.EXTENDED);
        assertThat(response.analysisId()).isEqualTo("analysis-1");
        assertThat(response.buildTool()).isEqualTo(BuildTool.GRADLE);
        assertThat(response.findings()).isEmpty();
    }

    @Test
    void normalizesOverlappingFindingsLikeRepositoryAnalysis() {
        StaticAnalyzer staticAnalyzer = mock(StaticAnalyzer.class);
        given(staticAnalyzer.analyze(any(), eq(tempDir), eq("repo-1")))
                .willReturn(
                        analysisResult(
                                List.of(
                                        finding(
                                                "SPRING_SWALLOWED_EXCEPTION_FALLBACK",
                                                FindingSeverity.WARNING,
                                                10),
                                        finding(
                                                "SPRING_BROAD_FATAL_ERROR_CATCH",
                                                FindingSeverity.WARNING,
                                                10))));

        AnalyzeRepositoryResponse response =
                service(staticAnalyzer)
                        .analyze(tempDir, "repo-1", null, null, AnalysisMode.STATIC_ONLY);

        assertThat(response.findings())
                .singleElement()
                .satisfies(
                        finding -> {
                            assertThat(finding.ruleId())
                                    .isEqualTo("SPRING_SWALLOWED_EXCEPTION_FALLBACK");
                            assertThat(finding.relatedSignals())
                                    .singleElement()
                                    .extracting(signal -> signal.ruleId())
                                    .isEqualTo("SPRING_BROAD_FATAL_ERROR_CATCH");
                        });
    }

    @Test
    void appliesRepositorySuppressionFile() throws IOException {
        StaticAnalyzer staticAnalyzer = mock(StaticAnalyzer.class);
        given(staticAnalyzer.analyze(any(), eq(tempDir), eq("repo-1")))
                .willReturn(
                        analysisResult(
                                List.of(
                                        finding(
                                                "SPRING_FIELD_INJECTION",
                                                FindingSeverity.WARNING,
                                                10),
                                        finding(
                                                "SPRING_JPA_OPEN_IN_VIEW",
                                                FindingSeverity.WARNING,
                                                20))));
        java.nio.file.Files.writeString(
                tempDir.resolve(".analyzer-suppress.yml"),
                """
                suppress:
                  - ruleId: SPRING_FIELD_INJECTION
                """);

        AnalyzeRepositoryResponse response =
                service(staticAnalyzer)
                        .analyze(tempDir, "repo-1", null, null, AnalysisMode.STATIC_ONLY);

        assertThat(response.findings())
                .extracting(Finding::ruleId)
                .containsExactly("SPRING_JPA_OPEN_IN_VIEW");
    }

    @Test
    void appliesDisabledRulesAndFullyDisabledSeverityFallback() {
        StaticAnalyzer staticAnalyzer = mock(StaticAnalyzer.class);
        UserRuleConfigService userRuleConfigService = mock(UserRuleConfigService.class);
        given(userRuleConfigService.getDisabledRuleIds())
                .willReturn(Set.of("SPRING_FIELD_INJECTION"));
        given(userRuleConfigService.fullyDisabledSeverities(Set.of("SPRING_FIELD_INJECTION")))
                .willReturn(Set.of("ERROR"));
        given(staticAnalyzer.analyze(any(), eq(tempDir), eq("repo-1")))
                .willReturn(
                        analysisResult(
                                List.of(
                                        finding(
                                                "SPRING_FIELD_INJECTION",
                                                FindingSeverity.WARNING,
                                                10),
                                        finding("UNREGISTERED", FindingSeverity.ERROR, 20),
                                        finding(
                                                "SPRING_JPA_OPEN_IN_VIEW",
                                                FindingSeverity.WARNING,
                                                30))));

        AnalyzeRepositoryResponse response =
                service(staticAnalyzer, userRuleConfigService)
                        .analyze(tempDir, "repo-1", null, null, AnalysisMode.STATIC_ONLY);

        assertThat(response.findings())
                .extracting(Finding::ruleId)
                .containsExactly("SPRING_JPA_OPEN_IN_VIEW");
    }

    private static LocalRepositoryAnalysisService service(StaticAnalyzer staticAnalyzer) {
        UserRuleConfigService userRuleConfigService = mock(UserRuleConfigService.class);
        given(userRuleConfigService.getDisabledRuleIds()).willReturn(Set.of());
        given(userRuleConfigService.fullyDisabledSeverities(Set.of())).willReturn(Set.of());
        return service(staticAnalyzer, userRuleConfigService);
    }

    private static LocalRepositoryAnalysisService service(
            StaticAnalyzer staticAnalyzer, UserRuleConfigService userRuleConfigService) {
        return new LocalRepositoryAnalysisService(
                staticAnalyzer,
                new FindingPostProcessor(
                        new FindingNormalizer(), new SuppressionService(), userRuleConfigService));
    }

    private static AnalysisResult analysisResult() {
        return analysisResult(List.of());
    }

    private static AnalysisResult analysisResult(List<Finding> findings) {
        BuildInfo buildInfo =
                new BuildInfo(BuildTool.GRADLE, true, "25", List.of(), "3.5.13", "test", "HIGH");
        return new AnalysisResult(
                "https://github.com/example/demo.git",
                "main",
                "repo-1",
                "analysis-1",
                null,
                buildInfo,
                List.of(),
                List.of(),
                findings,
                ConfigurationAnalysis.empty(),
                null,
                HttpSurfaceAnalysis.empty(),
                GradleModelAnalysis.empty(
                        GradleAnalysisStatus.NOT_REQUESTED, "TOOLING_API", List.of()),
                SchedulingAnalysis.empty(),
                MessagingAnalysis.empty());
    }

    private static Finding finding(String ruleId, FindingSeverity severity, int line) {
        return FindingFactory.builder(
                        ruleId,
                        ruleId + " title",
                        severity,
                        FindingCategory.EXCEPTION_HANDLING,
                        FindingRuntimeDetection.NOT_NORMALLY_DETECTED,
                        FindingConfidence.HIGH)
                .sourceLocation(
                        new SourceLocation(
                                "src/main/java/example/Service.java",
                                line,
                                line,
                                null,
                                null,
                                "Service#run",
                                "java",
                                null))
                .target("Service#run")
                .build();
    }
}

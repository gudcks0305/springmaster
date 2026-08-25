package com.robbanhoglund.springbootanalyzer.application;

import com.robbanhoglund.springbootanalyzer.analyzer.StaticAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.model.AnalysisResult;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.api.dto.AnalysisMode;
import com.robbanhoglund.springbootanalyzer.api.dto.AnalyzeRepositoryResponse;
import com.robbanhoglund.springbootanalyzer.git.GitRepositoryReference;
import java.nio.file.Path;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * Runs the static analyzer against a caller-provided local repository directory.
 *
 * <p>This deliberately does not use {@link RepositoryAnalysisService}: that service owns clone
 * workspace creation and cleanup, while worker requests already point at an immutable local
 * snapshot.
 */
@Service
public class LocalRepositoryAnalysisService {

    private final StaticAnalyzer staticAnalyzer;
    private final FindingPostProcessor findingPostProcessor;

    public LocalRepositoryAnalysisService(
            StaticAnalyzer staticAnalyzer, FindingPostProcessor findingPostProcessor) {
        this.staticAnalyzer = staticAnalyzer;
        this.findingPostProcessor = findingPostProcessor;
    }

    /**
     * Analyze {@code repositoryPath} in place. No clone, workspace, or source-snippet session is
     * created.
     */
    public AnalyzeRepositoryResponse analyze(
            Path repositoryPath,
            String repositoryId,
            String repositoryUrl,
            String branch,
            AnalysisMode analysisMode) {
        GitRepositoryReference repositoryReference =
                new GitRepositoryReference(repositoryUrl, branch, null, analysisMode);
        AnalysisResult result =
                staticAnalyzer.analyze(repositoryReference, repositoryPath, repositoryId);
        List<Finding> findings = findingPostProcessor.process(result.findings(), repositoryPath);
        return toResponse(result, findings);
    }

    private static AnalyzeRepositoryResponse toResponse(
            AnalysisResult result, List<Finding> findings) {
        return new AnalyzeRepositoryResponse(
                result.repositoryUrl(),
                result.branch(),
                result.workspaceId(),
                result.analysisId(),
                result.commitSha(),
                result.buildInfo().buildTool(),
                result.buildInfo().javaVersionHint(),
                result.buildInfo().springBootDetected(),
                result.mainApplicationClasses(),
                result.detectedComponents(),
                result.buildInfo().dependencies(),
                findings,
                result.configurationAnalysis(),
                result.runtimeStackAnalysis(),
                result.httpSurfaceAnalysis(),
                result.gradleModelAnalysis(),
                result.schedulingAnalysis(),
                result.messagingAnalysis());
    }
}

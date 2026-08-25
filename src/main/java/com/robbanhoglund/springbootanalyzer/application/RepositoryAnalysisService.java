package com.robbanhoglund.springbootanalyzer.application;

import com.robbanhoglund.springbootanalyzer.analyzer.StaticAnalyzer;
import com.robbanhoglund.springbootanalyzer.analyzer.model.AnalysisResult;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingOccurrence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.RelatedFindingSignal;
import com.robbanhoglund.springbootanalyzer.analyzer.model.SourceLocation;
import com.robbanhoglund.springbootanalyzer.config.AnalyzerProperties;
import com.robbanhoglund.springbootanalyzer.git.GitCloneService;
import com.robbanhoglund.springbootanalyzer.git.GitHubLinkBuilder;
import com.robbanhoglund.springbootanalyzer.git.GitRepositoryReference;
import com.robbanhoglund.springbootanalyzer.workspace.WorkspaceService;
import com.robbanhoglund.springbootanalyzer.workspace.WorkspaceService.Workspace;
import java.nio.file.Path;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Service;

@Service
public class RepositoryAnalysisService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RepositoryAnalysisService.class);

    private final WorkspaceService workspaceService;
    private final GitCloneService gitCloneService;
    private final StaticAnalyzer staticAnalyzer;
    private final AnalyzerProperties analyzerProperties;
    private final GitHubLinkBuilder gitHubLinkBuilder;
    private final AnalysisSessionRegistry analysisSessionRegistry;
    private final FindingPostProcessor findingPostProcessor;

    /**
     * Whether to retain the workspace after analysis so the UI can fetch source snippets. Only
     * meaningful in web mode: there the scheduled cleanup task eventually reclaims retained
     * workspaces. In CLI mode there is no scheduler and no snippet UI, so retaining would leak the
     * cloned repository into the temp directory on every run.
     */
    private final boolean retainWorkspaceForSnippetBrowsing;

    public RepositoryAnalysisService(
            WorkspaceService workspaceService,
            GitCloneService gitCloneService,
            StaticAnalyzer staticAnalyzer,
            AnalyzerProperties analyzerProperties,
            GitHubLinkBuilder gitHubLinkBuilder,
            AnalysisSessionRegistry analysisSessionRegistry,
            FindingPostProcessor findingPostProcessor,
            Environment environment) {
        this.workspaceService = workspaceService;
        this.gitCloneService = gitCloneService;
        this.staticAnalyzer = staticAnalyzer;
        this.analyzerProperties = analyzerProperties;
        this.gitHubLinkBuilder = gitHubLinkBuilder;
        this.analysisSessionRegistry = analysisSessionRegistry;
        this.findingPostProcessor = findingPostProcessor;
        this.retainWorkspaceForSnippetBrowsing = !environment.acceptsProfiles(Profiles.of("cli"));
    }

    public AnalysisResult analyze(GitRepositoryReference repositoryReference) {
        Workspace workspace = workspaceService.createWorkspace();
        AnalysisResult result = null;
        LOGGER.info(
                "Starting repository analysis: workspaceId={}, repository={}, branch={},"
                        + " analysisMode={}",
                workspace.id(),
                repositoryReference.logLabel(),
                repositoryReference.branch(),
                repositoryReference.analysisMode());
        try {
            Path clonedRepository =
                    gitCloneService.cloneRepository(
                            repositoryReference, workspace.path().resolve("repository"));
            String commitSha = gitCloneService.resolveHeadCommit(clonedRepository).orElse(null);
            LOGGER.info(
                    "Repository cloned successfully: workspaceId={}, repository={}",
                    workspace.id(),
                    repositoryReference.logLabel());
            result = staticAnalyzer.analyze(repositoryReference, clonedRepository, workspace.id());
            result = enrichAnalysisResult(result, workspace.id(), commitSha, clonedRepository);
            analysisSessionRegistry.register(
                    new AnalysisSessionRegistry.AnalysisSession(
                            result.analysisId(),
                            clonedRepository,
                            result.repositoryUrl(),
                            result.branch(),
                            result.commitSha()));
            LOGGER.info(
                    "Repository analysis completed: workspaceId={}, findings={}, components={},"
                            + " gradleStatus={}",
                    workspace.id(),
                    result.findings().size(),
                    result.detectedComponents().size(),
                    result.gradleModelAnalysis() == null
                            ? "none"
                            : result.gradleModelAnalysis().status());
            return result;
        } finally {
            cleanupWorkspace(workspace, result);
        }
    }

    private void cleanupWorkspace(Workspace workspace, AnalysisResult result) {
        if (!analyzerProperties.cleanupAfterAnalysis()) {
            LOGGER.info(
                    "Workspace cleanup skipped by configuration: workspaceId={}", workspace.id());
            return;
        }
        if (retainWorkspaceForSnippetBrowsing && result != null && result.analysisId() != null) {
            LOGGER.info(
                    "Workspace retained for source snippet browsing: workspaceId={}",
                    workspace.id());
            return;
        }
        if (analyzerProperties.workspaceKeepOnGradleFailure()
                && result != null
                && result.gradleModelAnalysis() != null
                && result.gradleModelAnalysis().status() != null
                && !"SUCCESS".equals(result.gradleModelAnalysis().status().name())
                && !"NOT_REQUESTED".equals(result.gradleModelAnalysis().status().name())) {
            LOGGER.info(
                    "Workspace retained because Gradle model analysis failed: workspaceId={}",
                    workspace.id());
            return;
        }
        try {
            workspaceService.deleteWorkspace(workspace);
            LOGGER.info("Workspace deleted: workspaceId={}", workspace.id());
        } catch (RuntimeException exception) {
            LOGGER.warn("Failed to delete workspace {}", workspace.id(), exception);
        }
    }

    private AnalysisResult enrichAnalysisResult(
            AnalysisResult result, String analysisId, String commitSha, Path repositoryRoot) {
        List<Finding> findings =
                findingPostProcessor.process(result.findings(), repositoryRoot).stream()
                        .map(finding -> enrichFinding(finding, result.repositoryUrl(), commitSha))
                        .toList();
        return new AnalysisResult(
                result.repositoryUrl(),
                result.branch(),
                result.workspaceId(),
                analysisId,
                commitSha,
                result.buildInfo(),
                result.mainApplicationClasses(),
                result.detectedComponents(),
                findings,
                result.configurationAnalysis(),
                result.runtimeStackAnalysis(),
                result.httpSurfaceAnalysis(),
                result.gradleModelAnalysis(),
                result.schedulingAnalysis(),
                result.messagingAnalysis());
    }

    private Finding enrichFinding(Finding finding, String repositoryUrl, String commitSha) {
        SourceLocation location =
                enrichLocation(finding.primaryLocation(), repositoryUrl, commitSha);
        List<FindingOccurrence> occurrences =
                finding.occurrences().stream()
                        .map(
                                occurrence ->
                                        occurrence.withGithubUrl(
                                                buildGithubUrl(
                                                        repositoryUrl,
                                                        commitSha,
                                                        occurrence.location())))
                        .toList();
        List<RelatedFindingSignal> relatedSignals =
                finding.relatedSignals().stream()
                        .map(
                                signal ->
                                        signal.withGithubUrl(
                                                buildGithubUrl(
                                                        repositoryUrl,
                                                        commitSha,
                                                        signal.sourceLocation())))
                        .toList();
        return finding.withSourceDetails(location, finding.highlightRanges(), occurrences)
                .withRelatedSignals(relatedSignals);
    }

    private SourceLocation enrichLocation(
            SourceLocation location, String repositoryUrl, String commitSha) {
        if (location == null) {
            return null;
        }
        return location.withGithubUrl(buildGithubUrl(repositoryUrl, commitSha, location));
    }

    private String buildGithubUrl(String repositoryUrl, String commitSha, SourceLocation location) {
        if (location == null) {
            return null;
        }
        return gitHubLinkBuilder.buildBlobUrl(
                repositoryUrl,
                commitSha,
                location.filePath(),
                location.startLine(),
                location.endLine());
    }
}

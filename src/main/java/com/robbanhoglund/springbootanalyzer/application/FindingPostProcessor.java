package com.robbanhoglund.springbootanalyzer.application;

import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.suppression.SuppressionService;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Applies finding transformations which must be identical for remote-clone and local-path
 * analysis.
 *
 * <p>This deliberately owns no workspace, Git, session, or source-snippet state. Callers can
 * apply transport-specific enrichment, such as GitHub permalinks, after this processing step.
 */
@Component
public class FindingPostProcessor {

    private final FindingNormalizer findingNormalizer;
    private final SuppressionService suppressionService;
    private final UserRuleConfigService userRuleConfigService;

    public FindingPostProcessor(
            FindingNormalizer findingNormalizer,
            SuppressionService suppressionService,
            UserRuleConfigService userRuleConfigService) {
        this.findingNormalizer = findingNormalizer;
        this.suppressionService = suppressionService;
        this.userRuleConfigService = userRuleConfigService;
    }

    /**
     * Normalizes overlapping findings, applies repository-local suppressions, then applies the
     * user's disabled rule and severity configuration.
     *
     * @param findings raw analyzer findings
     * @param repositoryRoot analyzed repository root, used only to read its suppression file
     * @return findings visible to the caller
     */
    public List<Finding> process(List<Finding> findings, Path repositoryRoot) {
        List<Finding> normalizedFindings = findingNormalizer.normalize(findings);
        List<Finding> suppressedFindings =
                suppressionService.apply(normalizedFindings, repositoryRoot);
        Set<String> disabledRuleIds = userRuleConfigService.getDisabledRuleIds();
        Set<String> disabledSeverities =
                userRuleConfigService.fullyDisabledSeverities(disabledRuleIds);
        return suppressedFindings.stream()
                .filter(finding -> isNotDisabled(finding, disabledRuleIds, disabledSeverities))
                .toList();
    }

    private static boolean isNotDisabled(
            Finding finding, Set<String> disabledRuleIds, Set<String> disabledSeverities) {
        if (finding.ruleId() != null && disabledRuleIds.contains(finding.ruleId())) {
            return false;
        }
        return finding.severity() == null
                || !disabledSeverities.contains(finding.severity().name());
    }
}

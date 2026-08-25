package com.robbanhoglund.springbootanalyzer.analyzer;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ThisExpr;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Detects scheduling and async anti-patterns in {@code src/main/java} source files.
 *
 * <p>Rules covered:
 *
 * <ul>
 *   <li>{@link FindingRules#SPRING_SCHEDULED_WITHOUT_ENABLE_SCHEDULING} — {@code @Scheduled} is used
 *       but no {@code @EnableScheduling} is present anywhere, so the jobs never run.
 *   <li>{@link FindingRules#SPRING_ASYNC_WITHOUT_ENABLE_ASYNC} — {@code @Async} is used but no
 *       {@code @EnableAsync} is present anywhere, so the methods run synchronously.
 *   <li>{@link FindingRules#SPRING_SCHEDULED_METHOD_INVALID_SIGNATURE} — a {@code @Scheduled} method
 *       declares parameters; Spring requires no-arg methods and fails at startup.
 *   <li>{@link FindingRules#SPRING_ASYNC_SELF_INVOCATION} — an {@code @Async} method is called via
 *       self-invocation, bypassing the proxy so it runs synchronously.
 *   <li>{@link FindingRules#SPRING_RETRYABLE_WITHOUT_ENABLE_RETRY} — {@code @Retryable}/
 *       {@code @Recover} are used but no {@code @EnableRetry} is present anywhere, so no retries
 *       ever happen (same proxy-enablement mechanism as the scheduling/async rules above).
 *   <li>{@link FindingRules#SPRING_SCHEDULED_CRON_INVALID_EXPRESSION} — a {@code @Scheduled} cron
 *       literal does not have the six fields Spring requires (or uses an unknown macro), so task
 *       registration fails at startup.
 * </ul>
 *
 * <p>{@code @Async} on a private method is detected separately by {@link
 * StaticPracticeFindingAnalyzer} as {@link FindingRules#SPRING_ASYNC_PROXY_BYPASS}.
 */
@Component
public class SchedulingPracticeFindingAnalyzer {

    /**
     * Analyzes all Java source files under {@code src/main/java} within the given repository root.
     *
     * @param repositoryRoot root directory of the locally checked-out repository
     * @return list of findings; never null
     */
    public List<Finding> analyze(Path repositoryRoot) {
        return analyze(JavaSources.from(repositoryRoot));
    }

    /**
     * Analyzes the {@code src/main/java} sources parsed once and shared across the pipeline.
     *
     * @param sources the source tree parsed once for this analysis
     * @return list of findings; never null
     */
    public List<Finding> analyze(JavaSources sources) {
        List<Finding> findings = new ArrayList<>();

        // Cross-file enablement signals for the "@Scheduled/@Async/@Retryable used but not
        // enabled" rules: whether any class enables the feature, and the first place the feature
        // is actually used.
        boolean enableScheduling = false;
        boolean enableAsync = false;
        boolean enableRetry = false;
        String scheduledUsagePath = null;
        Integer scheduledUsageLine = null;
        String scheduledUsageTarget = null;
        String asyncUsagePath = null;
        Integer asyncUsageLine = null;
        String asyncUsageTarget = null;
        String retryUsagePath = null;
        Integer retryUsageLine = null;
        String retryUsageTarget = null;

        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            CompilationUnit cu = file.compilationUnit();
            if (cu == null) {
                continue;
            }
            // Guard the spring-retry rule on the import to avoid clashing with same-named
            // annotations from other libraries (resilience4j uses @Retry, so overlap is rare).
            boolean springRetryImported = file.content().contains("org.springframework.retry");
            for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                if (hasAnnotation(cls.getAnnotations(), "EnableScheduling")) {
                    enableScheduling = true;
                }
                if (hasAnnotation(cls.getAnnotations(), "EnableAsync")) {
                    enableAsync = true;
                }
                if (hasAnnotation(cls.getAnnotations(), "EnableRetry")) {
                    enableRetry = true;
                }
                if (retryUsageTarget == null
                        && springRetryImported
                        && hasAnnotation(cls.getAnnotations(), "Retryable")) {
                    retryUsageTarget = cls.getNameAsString();
                    retryUsageLine = cls.getBegin().map(p -> p.line).orElse(null);
                    retryUsagePath = file.relativePath();
                }

                // @Async method names in this class drive self-invocation detection. Private
                // @Async methods are excluded (covered by SPRING_ASYNC_PROXY_BYPASS).
                Set<String> asyncMethodNames =
                        cls.getMethods().stream()
                                .filter(
                                        m ->
                                                !m.isPrivate()
                                                        && hasAnnotation(
                                                                m.getAnnotations(), "Async"))
                                .map(MethodDeclaration::getNameAsString)
                                .collect(Collectors.toSet());

                for (MethodDeclaration method : cls.getMethods()) {
                    if (hasAnnotation(method.getAnnotations(), "Scheduled")) {
                        if (scheduledUsageTarget == null) {
                            scheduledUsageTarget =
                                    cls.getNameAsString() + "#" + method.getNameAsString();
                            scheduledUsageLine = method.getBegin().map(p -> p.line).orElse(null);
                            scheduledUsagePath = file.relativePath();
                        }
                        detectScheduledInvalidSignature(cls, method, file.relativePath(), findings);
                        detectScheduledInvalidCronExpression(
                                cls, method, file.relativePath(), findings);
                        detectScheduledTriggerMissingOrConflicting(
                                cls, method, file.relativePath(), findings);
                    }
                    if (asyncUsageTarget == null
                            && !method.isPrivate()
                            && hasAnnotation(method.getAnnotations(), "Async")) {
                        asyncUsageTarget = cls.getNameAsString() + "#" + method.getNameAsString();
                        asyncUsageLine = method.getBegin().map(p -> p.line).orElse(null);
                        asyncUsagePath = file.relativePath();
                    }
                    if (retryUsageTarget == null
                            && springRetryImported
                            && (hasAnnotation(method.getAnnotations(), "Retryable")
                                    || hasAnnotation(method.getAnnotations(), "Recover"))) {
                        retryUsageTarget = cls.getNameAsString() + "#" + method.getNameAsString();
                        retryUsageLine = method.getBegin().map(p -> p.line).orElse(null);
                        retryUsagePath = file.relativePath();
                    }
                    detectAsyncSelfInvocation(
                            cls, method, asyncMethodNames, file.relativePath(), findings);
                }
            }
        }

        if (scheduledUsageTarget != null && !enableScheduling) {
            addScheduledWithoutEnableSchedulingFinding(
                    scheduledUsagePath, scheduledUsageLine, scheduledUsageTarget, findings);
        }
        if (asyncUsageTarget != null && !enableAsync) {
            addAsyncWithoutEnableAsyncFinding(
                    asyncUsagePath, asyncUsageLine, asyncUsageTarget, findings);
        }
        if (retryUsageTarget != null && !enableRetry) {
            addRetryableWithoutEnableRetryFinding(
                    retryUsagePath, retryUsageLine, retryUsageTarget, findings);
        }
        return findings;
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_RETRYABLE_WITHOUT_ENABLE_RETRY
    // ---------------------------------------------------------------------------

    private void addRetryableWithoutEnableRetryFinding(
            String relativePath, Integer line, String target, List<Finding> findings) {
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_RETRYABLE_WITHOUT_ENABLE_RETRY,
                                FindingConfidence.MEDIUM)
                        .shortMessage(
                                "@Retryable is used (first seen on "
                                        + target
                                        + ") but no @EnableRetry was found — no retries happen.")
                        .whyBadPractice(
                                "Spring Boot does not auto-configure spring-retry. @Retryable and"
                                    + " @Recover only take effect when a configuration class is"
                                    + " annotated with @EnableRetry, which registers the retry AOP"
                                    + " advisor. Without it the annotations are parsed but no"
                                    + " interceptor is applied: the method executes exactly once"
                                    + " and @Recover callbacks never run.")
                        .possibleImpact(
                                "The resilience the code visibly declares does not exist. The happy"
                                        + " path works, so the missing retries surface only when a"
                                        + " transient production failure is not retried and the"
                                        + " recovery path never executes.")
                        .recommendation(
                                "Add @EnableRetry to a @Configuration class (or the main"
                                        + " application class) and verify retry behaviour with a"
                                        + " test that forces a transient failure.")
                        .evidence(
                                "@Retryable/@Recover is used (first seen on "
                                        + target
                                        + " in "
                                        + relativePath
                                        + ") but no @EnableRetry annotation was found in"
                                        + " src/main/java.")
                        .limitations(
                                "Static analysis only sees src/main/java. If @EnableRetry is"
                                        + " applied through an imported library configuration or a"
                                        + " meta-annotation, this finding is a false positive.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SCHEDULED_CRON_INVALID_EXPRESSION
    // ---------------------------------------------------------------------------

    private static final Set<String> VALID_CRON_MACROS =
            Set.of("@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly");

    private void detectScheduledInvalidCronExpression(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        AnnotationExpr annotation = method.getAnnotationByName("Scheduled").orElse(null);
        if (annotation == null || !annotation.isNormalAnnotationExpr()) {
            return;
        }
        String cron = null;
        for (com.github.javaparser.ast.expr.MemberValuePair pair :
                annotation.asNormalAnnotationExpr().getPairs()) {
            if ("cron".equals(pair.getNameAsString()) && pair.getValue().isStringLiteralExpr()) {
                cron = pair.getValue().asStringLiteralExpr().asString();
            }
        }
        if (cron == null) {
            return;
        }
        String trimmed = cron.trim();
        // Skip values static analysis cannot judge: property/SpEL placeholders and Spring's
        // documented "-" disabled sentinel.
        if (trimmed.isEmpty()
                || "-".equals(trimmed)
                || trimmed.contains("${")
                || trimmed.contains("#{")) {
            return;
        }
        String problem = null;
        if (trimmed.startsWith("@")) {
            if (!VALID_CRON_MACROS.contains(trimmed.toLowerCase(java.util.Locale.ROOT))) {
                problem = "unknown macro '" + trimmed + "'";
            }
        } else {
            int fieldCount = trimmed.split("\\s+").length;
            if (fieldCount != 6) {
                String hint =
                        fieldCount == 5
                                ? " — this looks like a 5-field Unix crontab; Spring adds a"
                                        + " leading seconds field"
                                : fieldCount == 7
                                        ? " — this looks like a 7-field Quartz expression; Spring"
                                                + " has no trailing year field"
                                        : "";
                problem = fieldCount + " fields instead of the required 6" + hint;
            }
        }
        if (problem == null) {
            return;
        }
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_SCHEDULED_CRON_INVALID_EXPRESSION,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@Scheduled cron expression \""
                                        + trimmed
                                        + "\" on "
                                        + target
                                        + " is invalid: "
                                        + problem
                                        + ".")
                        .whyBadPractice(
                                "Spring's CronExpression requires exactly six space-separated"
                                    + " fields (second, minute, hour, day-of-month, month,"
                                    + " day-of-week) or a supported macro such as @hourly or"
                                    + " @daily. Expressions copied from a Unix crontab (5 fields)"
                                    + " or Quartz (7 fields) do not parse.")
                        .possibleImpact(
                                "ScheduledAnnotationBeanPostProcessor throws IllegalStateException"
                                        + " while registering the task, so the whole application"
                                        + " context fails to start — not just the one job.")
                        .recommendation(
                                "Rewrite the expression with six fields (prepend a seconds field"
                                        + " to a Unix crontab, drop the year field from a Quartz"
                                        + " expression), or use a supported macro. Validate with"
                                        + " org.springframework.scheduling.support.CronExpression"
                                        + ".parse(...) in a unit test.")
                        .evidence(
                                "@Scheduled(cron = \""
                                        + trimmed
                                        + "\") found on "
                                        + target
                                        + " in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SCHEDULED_WITHOUT_ENABLE_SCHEDULING
    // ---------------------------------------------------------------------------

    private void addScheduledWithoutEnableSchedulingFinding(
            String relativePath, Integer line, String target, List<Finding> findings) {
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_SCHEDULED_WITHOUT_ENABLE_SCHEDULING,
                                FindingConfidence.MEDIUM)
                        .shortMessage(
                                "@Scheduled is used (first seen on "
                                        + target
                                        + ") but no @EnableScheduling was found — the jobs never"
                                        + " run.")
                        .whyBadPractice(
                                "Spring Boot does not enable scheduling automatically. @Scheduled"
                                    + " methods are only registered with a TaskScheduler when a"
                                    + " configuration class is annotated with @EnableScheduling."
                                    + " Without it the annotations are parsed but no trigger is"
                                    + " ever registered.")
                        .possibleImpact(
                                "Background jobs (cleanups, polling, refresh tasks, health pings)"
                                    + " silently never execute. The application starts cleanly, so"
                                    + " the omission is easy to miss until the missing work causes"
                                    + " a downstream incident.")
                        .recommendation(
                                "Add @EnableScheduling to a @Configuration class (or the main"
                                        + " @SpringBootApplication class) and confirm the scheduled"
                                        + " methods run as expected.")
                        .evidence(
                                "@Scheduled is used (first seen on "
                                        + target
                                        + " in "
                                        + relativePath
                                        + ") but no @EnableScheduling annotation was found in"
                                        + " src/main/java.")
                        .limitations(
                                "Static analysis only sees src/main/java. If @EnableScheduling is"
                                    + " applied through an imported library configuration, a"
                                    + " meta-annotation, or XML, this finding is a false positive.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_ASYNC_WITHOUT_ENABLE_ASYNC
    // ---------------------------------------------------------------------------

    private void addAsyncWithoutEnableAsyncFinding(
            String relativePath, Integer line, String target, List<Finding> findings) {
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_ASYNC_WITHOUT_ENABLE_ASYNC,
                                FindingConfidence.MEDIUM)
                        .shortMessage(
                                "@Async is used (first seen on "
                                        + target
                                        + ") but no @EnableAsync was found — the methods run"
                                        + " synchronously.")
                        .whyBadPractice(
                                "Spring Boot does not enable async processing automatically. @Async"
                                    + " only takes effect when a configuration class is annotated"
                                    + " with @EnableAsync. Without it the proxy that dispatches the"
                                    + " call to an executor is never created, so the method runs"
                                    + " inline on the caller's thread.")
                        .possibleImpact(
                                "Work the developer expected to run in the background blocks the"
                                    + " calling thread (often an HTTP request thread), increasing"
                                    + " latency and reducing throughput. Fire-and-forget semantics"
                                    + " are silently lost.")
                        .recommendation(
                                "Add @EnableAsync to a @Configuration class and configure a"
                                    + " ThreadPoolTaskExecutor so async methods are dispatched off"
                                    + " the caller's thread.")
                        .evidence(
                                "@Async is used (first seen on "
                                        + target
                                        + " in "
                                        + relativePath
                                        + ") but no @EnableAsync annotation was found in"
                                        + " src/main/java.")
                        .limitations(
                                "Static analysis only sees src/main/java. If @EnableAsync is"
                                    + " applied through an imported library configuration, a"
                                    + " meta-annotation, or XML, this finding is a false positive.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SCHEDULED_METHOD_INVALID_SIGNATURE
    // ---------------------------------------------------------------------------

    private void detectScheduledInvalidSignature(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        if (method.getParameters().isEmpty()) {
            return;
        }
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_SCHEDULED_METHOD_INVALID_SIGNATURE,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@Scheduled method "
                                        + target
                                        + " declares parameters — Spring requires no-arg scheduled"
                                        + " methods and fails at startup.")
                        .whyBadPractice(
                                "Spring's ScheduledAnnotationBeanPostProcessor can only invoke a"
                                    + " scheduled method with no arguments, because it has no"
                                    + " source of values to pass. When it registers a @Scheduled"
                                    + " method that declares parameters it throws"
                                    + " IllegalStateException (\"Only no-arg methods may be"
                                    + " annotated with @Scheduled\").")
                        .possibleImpact(
                                "The application context fails to start: the bean post-processor"
                                        + " throws while wiring the scheduled task, so the whole"
                                        + " application is down rather than just the one job.")
                        .recommendation(
                                "Remove the parameters from the @Scheduled method. If the method"
                                    + " needs collaborators or configuration, inject them as bean"
                                    + " fields/constructor arguments and reference them from the"
                                    + " no-arg body.")
                        .evidence(
                                "@Scheduled method "
                                        + method.getNameAsString()
                                        + " declares "
                                        + method.getParameters().size()
                                        + " parameter(s) in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SCHEDULED_TRIGGER_MISSING_OR_CONFLICTING
    // ---------------------------------------------------------------------------

    private static final Set<String> SCHEDULED_TRIGGER_ATTRIBUTES =
            Set.of("cron", "fixedDelay", "fixedDelayString", "fixedRate", "fixedRateString");

    /**
     * Flags {@code @Scheduled} annotations that declare no trigger attribute, or more than one.
     * Spring requires exactly one of {@code cron}/{@code fixedDelay}/{@code fixedRate} (or their
     * {@code String} variants) and throws {@code IllegalStateException} while registering the
     * task, failing application startup. {@code initialDelay} is a modifier, not a trigger.
     */
    private void detectScheduledTriggerMissingOrConflicting(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        AnnotationExpr annotation = method.getAnnotationByName("Scheduled").orElse(null);
        if (annotation == null) {
            return;
        }
        List<String> triggers = new ArrayList<>();
        if (annotation.isNormalAnnotationExpr()) {
            for (com.github.javaparser.ast.expr.MemberValuePair pair :
                    annotation.asNormalAnnotationExpr().getPairs()) {
                if (SCHEDULED_TRIGGER_ATTRIBUTES.contains(pair.getNameAsString())) {
                    triggers.add(pair.getNameAsString());
                }
            }
        } else if (annotation.isSingleMemberAnnotationExpr()) {
            // @Scheduled has no value() attribute, so a single-member form cannot compile;
            // nothing to judge.
            return;
        }
        if (triggers.size() == 1) {
            return;
        }
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        String problem =
                triggers.isEmpty()
                        ? "declares no trigger attribute"
                        : "declares "
                                + triggers.size()
                                + " trigger attributes ("
                                + String.join(", ", triggers)
                                + ")";
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_SCHEDULED_TRIGGER_MISSING_OR_CONFLICTING,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@Scheduled on "
                                        + target
                                        + " "
                                        + problem
                                        + " — exactly one is required.")
                        .whyBadPractice(
                                "Spring's ScheduledAnnotationBeanPostProcessor requires exactly one"
                                    + " of cron, fixedDelay(String) or fixedRate(String) to build a"
                                    + " trigger. With none it has no schedule to register; with"
                                    + " several the intent is ambiguous. Either way it throws"
                                    + " IllegalStateException while wiring the bean.")
                        .possibleImpact(
                                "The application context fails to start — the whole application is"
                                        + " down, not just the one job.")
                        .recommendation(
                                triggers.isEmpty()
                                        ? "Add exactly one trigger attribute, e.g."
                                                + " @Scheduled(fixedDelay = 60000) or"
                                                + " @Scheduled(cron = \"0 0 * * * *\")."
                                        : "Keep only the intended trigger attribute and remove the"
                                                + " others (initialDelay may be combined with a"
                                                + " fixedDelay/fixedRate trigger).")
                        .evidence(
                                "@Scheduled on "
                                        + target
                                        + " in "
                                        + relativePath
                                        + " "
                                        + problem
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_ASYNC_SELF_INVOCATION
    // ---------------------------------------------------------------------------

    private void detectAsyncSelfInvocation(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            Set<String> asyncMethodNames,
            String relativePath,
            List<Finding> findings) {
        if (asyncMethodNames.isEmpty()) {
            return;
        }
        method.findAll(MethodCallExpr.class)
                .forEach(
                        call -> {
                            if (!asyncMethodNames.contains(call.getNameAsString())) {
                                return;
                            }
                            // Only flag calls without an external receiver: no scope (implicit
                            // this) or an explicit this scope. A call qualified by any other
                            // receiver goes through that bean's proxy and is fine.
                            var scope = call.getScope().orElse(null);
                            boolean isSelfCall = scope == null || scope instanceof ThisExpr;
                            if (!isSelfCall) {
                                return;
                            }
                            // Don't emit on the async method's own recursive self-call.
                            if (method.getNameAsString().equals(call.getNameAsString())) {
                                return;
                            }
                            Integer line = call.getBegin().map(p -> p.line).orElse(null);
                            String callerTarget =
                                    cls.getNameAsString() + "#" + method.getNameAsString();
                            findings.add(
                                    FindingFactory.builder(
                                                    FindingRules.SPRING_ASYNC_SELF_INVOCATION,
                                                    FindingConfidence.MEDIUM)
                                            .shortMessage(
                                                    "@Async method '"
                                                            + call.getNameAsString()
                                                            + "' called via self-invocation in "
                                                            + callerTarget
                                                            + " — it will run synchronously.")
                                            .whyBadPractice(
                                                    "Spring dispatches @Async calls through a proxy"
                                                        + " wrapper around the bean. When a method"
                                                        + " in the same class calls an @Async"
                                                        + " method directly, the call bypasses the"
                                                        + " proxy, so no executor is involved and"
                                                        + " the method runs on the caller's"
                                                        + " thread.")
                                            .possibleImpact(
                                                    "Work assumed to run in the background blocks"
                                                        + " the caller. Any expected concurrency or"
                                                        + " fire-and-forget behaviour is silently"
                                                        + " lost.")
                                            .recommendation(
                                                    "Move the @Async method to a separate"
                                                        + " Spring-managed bean and call it through"
                                                        + " the injected reference, or self-inject"
                                                        + " the bean and invoke the method through"
                                                        + " the injected proxy.")
                                            .evidence(
                                                    "Method "
                                                            + method.getNameAsString()
                                                            + " calls @Async method "
                                                            + call.getNameAsString()
                                                            + " directly in "
                                                            + relativePath
                                                            + ".")
                                            .source(relativePath, line)
                                            .target(callerTarget)
                                            .build());
                        });
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private static boolean hasAnnotation(List<AnnotationExpr> annotations, String name) {
        return annotations.stream().anyMatch(a -> name.equals(simpleName(a.getNameAsString())));
    }

    private static String simpleName(String name) {
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : name;
    }
}

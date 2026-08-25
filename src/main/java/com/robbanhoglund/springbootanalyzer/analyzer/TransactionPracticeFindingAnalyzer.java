package com.robbanhoglund.springbootanalyzer.analyzer;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Detects transaction-related anti-patterns in {@code src/main/java} source files.
 *
 * <p>Rules covered:
 *
 * <ul>
 *   <li>{@link FindingRules#SPRING_ASYNC_TRANSACTIONAL} — a method annotated with both
 *       {@code @Async} and {@code @Transactional}; the transaction context is not propagated to
 *       the async thread.
 * </ul>
 *
 * <p>{@code @Transactional} on private methods and self-invocation are detected by {@link
 * StaticPracticeFindingAnalyzer} as {@link FindingRules#SPRING_TRANSACTIONAL_ON_PRIVATE_METHOD}
 * and {@link FindingRules#SPRING_TRANSACTIONAL_SELF_INVOCATION} respectively.
 */
@Component
public class TransactionPracticeFindingAnalyzer {

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
        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            if (file.compilationUnit() == null) {
                continue;
            }
            analyzeSourceFile(file.compilationUnit(), file.relativePath(), findings);
        }
        return findings;
    }

    // ---------------------------------------------------------------------------
    // Per-file analysis
    // ---------------------------------------------------------------------------

    private void analyzeSourceFile(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            for (MethodDeclaration method : cls.getMethods()) {
                detectAsyncTransactional(cls, method, relativePath, findings);
                detectTransactionalOnPostConstruct(cls, method, relativePath, findings);
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_ASYNC_TRANSACTIONAL
    // ---------------------------------------------------------------------------

    /**
     * Flags methods that are annotated with both {@code @Async} and {@code @Transactional}.
     * Spring's transaction context is bound to the calling thread via a {@code ThreadLocal} and is
     * not propagated to the new thread started by {@code @Async}. The {@code @Transactional}
     * annotation on the async method starts an entirely new, unrelated transaction on the worker
     * thread — completely separate from any outer transaction the caller may hold.
     */
    private void detectAsyncTransactional(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        if (!hasAnnotation(method, "Async")) {
            return;
        }
        if (!hasTransactionalAnnotation(method)) {
            return;
        }
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_ASYNC_TRANSACTIONAL, FindingConfidence.HIGH)
                        .shortMessage(
                                "Method "
                                        + target
                                        + " is annotated with both @Async and @Transactional —"
                                        + " the transaction context is not propagated to the new"
                                        + " thread.")
                        .whyBadPractice(
                                "@Async dispatches the method to a thread pool. Spring's"
                                    + " transaction context is bound to the calling thread via a"
                                    + " ThreadLocal and is not propagated to the new thread. The"
                                    + " @Transactional annotation on the async method starts a new,"
                                    + " unrelated transaction on the worker thread — completely"
                                    + " separate from any outer transaction the caller may have.")
                        .possibleImpact(
                                "Database operations inside the async method run in a new,"
                                    + " independent transaction that the caller cannot roll back"
                                    + " and whose failure the caller never observes. Work the"
                                    + " caller assumed to be atomic with its own transaction is"
                                    + " not.")
                        .recommendation(
                                "If an independent transaction on the async thread is intended,"
                                    + " keep the combination but make the decoupling explicit"
                                    + " (naming, documentation, failure handling). If the work must"
                                    + " share the caller's transaction, run it synchronously before"
                                    + " dispatching the async part. If delegating to a"
                                    + " @Transactional helper, place the helper in a separate bean"
                                    + " so the proxy is not bypassed by self-invocation.")
                        .evidence(
                                "Method "
                                        + target
                                        + " has both @Async and @Transactional annotations in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_TRANSACTIONAL_ON_POSTCONSTRUCT
    // ---------------------------------------------------------------------------

    /**
     * Flags methods annotated with both {@code @PostConstruct} and {@code @Transactional}. Spring
     * invokes {@code @PostConstruct} callbacks while the bean is still being initialized, before the
     * transactional proxy that would start a transaction is in place. The {@code @Transactional}
     * annotation therefore has no effect during initialization — the callback runs without a
     * transaction.
     */
    private void detectTransactionalOnPostConstruct(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        if (!hasAnnotation(method, "PostConstruct")) {
            return;
        }
        if (!hasTransactionalAnnotation(method)) {
            return;
        }
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_TRANSACTIONAL_ON_POSTCONSTRUCT,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "Method "
                                        + target
                                        + " is annotated with both @PostConstruct and"
                                        + " @Transactional — no transaction is started during"
                                        + " initialization.")
                        .whyBadPractice(
                                "Spring runs @PostConstruct callbacks as part of bean"
                                    + " initialization, before the AOP proxy that applies"
                                    + " @Transactional wraps the bean. The annotation is processed"
                                    + " for normal (post-initialization) calls but is not in effect"
                                    + " while the @PostConstruct method itself runs, so the work"
                                    + " executes with no active transaction.")
                        .possibleImpact(
                                "Persistence operations in the callback run without transactional"
                                    + " guarantees: no rollback on failure, and reads/writes may"
                                    + " use auto-commit or fail with 'no active transaction'"
                                    + " depending on the setup. The developer's assumption of"
                                    + " atomicity is silently false.")
                        .recommendation(
                                "Move the transactional work out of @PostConstruct. Delegate to a"
                                    + " separate @Transactional bean method invoked through the"
                                    + " proxy, or run initialization on an"
                                    + " ApplicationReadyEvent/ContextRefreshedEvent listener where"
                                    + " the proxy is fully in place.")
                        .evidence(
                                "Method "
                                        + target
                                        + " has both @PostConstruct and @Transactional annotations"
                                        + " in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private static boolean hasTransactionalAnnotation(MethodDeclaration method) {
        return method.getAnnotations().stream()
                .anyMatch(
                        a -> {
                            String name = a.getNameAsString();
                            return "Transactional".equals(name) || name.endsWith(".Transactional");
                        });
    }

    private static boolean hasAnnotation(MethodDeclaration method, String name) {
        return method.getAnnotations().stream()
                .anyMatch(a -> name.equals(simpleName(a.getNameAsString())));
    }

    private static String simpleName(String name) {
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : name;
    }
}

package com.robbanhoglund.springbootanalyzer.analyzer;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRule;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.RuntimeStackAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Detects source-code patterns that block or complicate an upgrade to Spring Boot 3 (Jakarta EE 9
 * namespace, Spring Security 6).
 *
 * <p>Rules covered:
 *
 * <ul>
 *   <li>{@link FindingRules#SPRING_SECURITY_WEBSECURITYCONFIGURERADAPTER} — a class still extends
 *       {@code WebSecurityConfigurerAdapter}, removed in Spring Security 6.
 *   <li>{@link FindingRules#SPRING_SECURITY_ANTMATCHERS_REMOVED} — {@code antMatchers(...)},
 *       {@code mvcMatchers(...)}, or {@code regexMatchers(...)}, all removed in Spring Security 6.
 *   <li>{@link FindingRules#SPRING_SECURITY_ENABLE_GLOBAL_METHOD_SECURITY} —
 *       {@code @EnableGlobalMethodSecurity}, removed in Spring Security 6 in favour of
 *       {@code @EnableMethodSecurity}.
 *   <li>{@link FindingRules#SPRING_JAKARTA_NAMESPACE_ON_BOOT3} — a legacy {@code javax.*} EE import
 *       in a project whose detected Spring Boot version is 3.x or later.
 * </ul>
 *
 * <p>The first three rules fire regardless of the detected Spring Boot version: on a Spring Boot 2
 * project they flag work that must be done before upgrading; on a Spring Boot 3 project the code
 * would not compile. The Jakarta-namespace rule fires only when the project is already on Spring
 * Boot 3, where {@code javax.*} EE types no longer resolve.
 */
@Component
public class MigrationPracticeFindingAnalyzer {

    private static final Set<String> REMOVED_MATCHER_METHODS =
            Set.of("antMatchers", "mvcMatchers", "regexMatchers");

    /**
     * Legacy Java EE package prefixes that moved to the {@code jakarta.*} namespace in Jakarta EE
     * 9 (adopted by Spring Boot 3). Deliberately excludes {@code javax.annotation.*} (some members,
     * e.g. {@code javax.annotation.processing}, remain in the JDK) and JSR-305 types to avoid false
     * positives.
     */
    private static final Set<String> LEGACY_EE_IMPORT_PREFIXES =
            Set.of(
                    "javax.persistence.",
                    "javax.servlet.",
                    "javax.validation.",
                    "javax.transaction.",
                    "javax.jms.",
                    "javax.ws.rs.",
                    "javax.websocket.",
                    "javax.mail.");

    /**
     * Walks every {@code .java} file under {@code <repositoryRoot>/src/main/java} and returns all
     * migration findings.
     *
     * @param repositoryRoot       root directory of the project being analysed
     * @param runtimeStackAnalysis the detected runtime stacks; used to gate the Jakarta-namespace
     *                             rule on Spring Boot 3+
     * @return all detected migration findings; never null, may be empty
     */
    public List<Finding> analyze(Path repositoryRoot, RuntimeStackAnalysis runtimeStackAnalysis) {
        return analyze(JavaSources.from(repositoryRoot), runtimeStackAnalysis);
    }

    /**
     * Analyzes the {@code src/main/java} sources parsed once and shared across the pipeline.
     *
     * @param sources the source tree parsed once for this analysis
     * @param runtimeStackAnalysis the detected runtime stacks; used to gate the Jakarta-namespace
     *     rule on Spring Boot 3+
     * @return all detected migration findings; never null, may be empty
     */
    public List<Finding> analyze(JavaSources sources, RuntimeStackAnalysis runtimeStackAnalysis) {
        List<Finding> findings = new ArrayList<>();
        boolean springBoot3Plus = isSpringBoot3Plus(runtimeStackAnalysis);
        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            if (file.compilationUnit() == null) {
                continue;
            }
            analyzeSourceFile(
                    file.compilationUnit(), file.relativePath(), springBoot3Plus, findings);
        }
        return findings;
    }

    private void analyzeSourceFile(
            CompilationUnit cu,
            String relativePath,
            boolean springBoot3Plus,
            List<Finding> findings) {
        detectWebSecurityConfigurerAdapter(cu, relativePath, findings);
        detectRemovedMatchers(cu, relativePath, findings);
        detectEnableGlobalMethodSecurity(cu, relativePath, findings);
        if (springBoot3Plus) {
            detectLegacyJavaxImport(cu, relativePath, findings);
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SECURITY_WEBSECURITYCONFIGURERADAPTER
    // ---------------------------------------------------------------------------

    private void detectWebSecurityConfigurerAdapter(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            boolean extendsAdapter =
                    cls.getExtendedTypes().stream()
                            .anyMatch(
                                    t ->
                                            simpleName(t.getNameAsString())
                                                    .equals("WebSecurityConfigurerAdapter"));
            if (!extendsAdapter) {
                continue;
            }
            Integer line = cls.getBegin().map(p -> p.line).orElse(null);
            add(
                    findings,
                    FindingRules.SPRING_SECURITY_WEBSECURITYCONFIGURERADAPTER,
                    FindingConfidence.HIGH,
                    relativePath,
                    line,
                    cls.getNameAsString()
                            + " extends WebSecurityConfigurerAdapter in "
                            + relativePath
                            + " — removed in Spring Security 6.",
                    "WebSecurityConfigurerAdapter was deprecated in Spring Security 5.7 and removed"
                        + " in Spring Security 6 (the version bundled with Spring Boot 3). The"
                        + " framework moved to a component-based model where security is configured"
                        + " by exposing SecurityFilterChain and WebSecurityCustomizer beans instead"
                        + " of overriding adapter methods.",
                    "The class will not compile against Spring Boot 3, blocking the upgrade. Until"
                            + " migrated, the security configuration is tied to a removed base"
                            + " class.",
                    "Delete the adapter base class and expose a SecurityFilterChain @Bean that"
                            + " configures HttpSecurity, plus a WebSecurityCustomizer @Bean for"
                            + " web.ignoring() rules. See the Spring Security migration guide.",
                    "High confidence — WebSecurityConfigurerAdapter no longer exists in Spring"
                            + " Security 6.",
                    "class "
                            + cls.getNameAsString()
                            + " extends WebSecurityConfigurerAdapter found in "
                            + relativePath
                            + ".",
                    cls.getNameAsString());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SECURITY_ANTMATCHERS_REMOVED
    // ---------------------------------------------------------------------------

    private void detectRemovedMatchers(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            String name = call.getNameAsString();
            if (!REMOVED_MATCHER_METHODS.contains(name)) {
                continue;
            }
            Integer line = call.getBegin().map(p -> p.line).orElse(null);
            add(
                    findings,
                    FindingRules.SPRING_SECURITY_ANTMATCHERS_REMOVED,
                    FindingConfidence.MEDIUM,
                    relativePath,
                    line,
                    name
                            + "(...) in "
                            + relativePath
                            + " was removed in Spring Security 6 — use requestMatchers(...).",
                    "Spring Security 6 (Spring Boot 3) removed antMatchers(), mvcMatchers(), and"
                        + " regexMatchers() from the authorization DSL. They were unified into"
                        + " requestMatchers(), which selects the matcher strategy automatically.",
                    "The configuration will not compile against Spring Boot 3, blocking the"
                            + " upgrade.",
                    "Replace "
                            + name
                            + "(...) with requestMatchers(...). For an explicit strategy use the"
                            + " AntPathRequestMatcher / RegexRequestMatcher overloads of"
                            + " requestMatchers.",
                    "Medium confidence — a method named "
                            + name
                            + " could in principle belong to a non-Spring-Security DSL; review the"
                            + " surrounding configuration.",
                    name + "(...) call found in " + relativePath + ".",
                    null);
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SECURITY_ENABLE_GLOBAL_METHOD_SECURITY
    // ---------------------------------------------------------------------------

    private void detectEnableGlobalMethodSecurity(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            boolean annotated =
                    cls.getAnnotations().stream()
                            .anyMatch(
                                    a ->
                                            simpleName(a.getNameAsString())
                                                    .equals("EnableGlobalMethodSecurity"));
            if (!annotated) {
                continue;
            }
            Integer line = cls.getBegin().map(p -> p.line).orElse(null);
            add(
                    findings,
                    FindingRules.SPRING_SECURITY_ENABLE_GLOBAL_METHOD_SECURITY,
                    FindingConfidence.HIGH,
                    relativePath,
                    line,
                    "@EnableGlobalMethodSecurity on "
                            + cls.getNameAsString()
                            + " in "
                            + relativePath
                            + " was removed in Spring Security 6.",
                    "@EnableMethodSecurity (introduced in Spring Security 5.6) replaces"
                            + " @EnableGlobalMethodSecurity, which was deprecated in 5.8 and"
                            + " removed in Spring Security 6 (Spring Boot 3). The replacement"
                            + " enables @PreAuthorize/@PostAuthorize by default and no longer"
                            + " requires prePostEnabled = true.",
                    "Code using the annotation does not compile against Spring Security 6, so the"
                            + " Spring Boot 3 upgrade is blocked until it is migrated.",
                    "Replace @EnableGlobalMethodSecurity(prePostEnabled = true) with"
                        + " @EnableMethodSecurity (prePost is enabled by default). Review"
                        + " securedEnabled / jsr250Enabled flags and carry them over explicitly.",
                    "High confidence — the annotation is read directly from the class.",
                    "@EnableGlobalMethodSecurity found on "
                            + cls.getNameAsString()
                            + " in "
                            + relativePath
                            + ".",
                    cls.getNameAsString());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_JAKARTA_NAMESPACE_ON_BOOT3
    // ---------------------------------------------------------------------------

    private void detectLegacyJavaxImport(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ImportDeclaration importDecl : cu.getImports()) {
            String imported = importDecl.getNameAsString();
            String matchTarget = importDecl.isAsterisk() ? imported + "." : imported;
            String prefix =
                    LEGACY_EE_IMPORT_PREFIXES.stream()
                            .filter(matchTarget::startsWith)
                            .findFirst()
                            .orElse(null);
            if (prefix == null) {
                continue;
            }
            Integer line = importDecl.getBegin().map(p -> p.line).orElse(null);
            String jakartaEquivalent = "jakarta." + imported.substring("javax.".length());
            add(
                    findings,
                    FindingRules.SPRING_JAKARTA_NAMESPACE_ON_BOOT3,
                    FindingConfidence.HIGH,
                    relativePath,
                    line,
                    "import "
                            + imported
                            + " in "
                            + relativePath
                            + " uses the legacy javax.* namespace on a Spring Boot 3 project.",
                    "Spring Boot 3 is built on Jakarta EE 9, which renamed every javax.* EE package"
                            + " to jakarta.*. The javax.* types ("
                            + prefix
                            + "*) are no longer on the classpath, so the import does not resolve.",
                    "The file will not compile against Spring Boot 3, and any annotations or types"
                            + " from this package are silently inactive.",
                    "Replace the import with its jakarta.* equivalent (e.g. "
                            + jakartaEquivalent
                            + "). Most projects can run the Eclipse Transformer or the OpenRewrite"
                            + " 'jakarta' recipes to migrate all imports at once.",
                    "High confidence — the detected Spring Boot version is 3.x or later, where"
                            + " these javax.* EE packages do not exist.",
                    "import " + imported + " found in " + relativePath + ".",
                    null);
            return; // One finding per file is enough to flag the migration need.
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private static boolean isSpringBoot3Plus(RuntimeStackAnalysis runtimeStackAnalysis) {
        if (runtimeStackAnalysis == null || runtimeStackAnalysis.springBootVersion() == null) {
            return false;
        }
        try {
            String[] parts = runtimeStackAnalysis.springBootVersion().split("\\.");
            return parts.length > 0 && Integer.parseInt(parts[0]) >= 3;
        } catch (NumberFormatException ignored) {
            return false;
        }
    }

    private void add(
            List<Finding> findings,
            FindingRule rule,
            FindingConfidence confidence,
            String relativePath,
            Integer line,
            String shortMessage,
            String whyBadPractice,
            String possibleImpact,
            String recommendation,
            String limitations,
            String evidence,
            String target) {
        FindingFactory.Builder builder =
                FindingFactory.builder(rule, confidence)
                        .shortMessage(shortMessage)
                        .whyBadPractice(whyBadPractice)
                        .possibleImpact(possibleImpact)
                        .recommendation(recommendation)
                        .limitations(limitations)
                        .evidence(evidence)
                        .source(relativePath, line);
        if (target != null) {
            builder.target(target);
        }
        findings.add(builder.build());
    }

    private static String simpleName(String name) {
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : name;
    }
}

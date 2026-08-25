package com.robbanhoglund.springbootanalyzer.analyzer;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayCreationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.IntegerLiteralExpr;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRule;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Detects security-related anti-patterns in {@code src/main/java} source files.
 *
 * <p>Rules covered:
 *
 * <ul>
 *   <li>{@link FindingRules#SPRING_PREAUTHORIZE_ON_PRIVATE_METHOD} — {@code @PreAuthorize},
 *       {@code @PostAuthorize}, {@code @Secured}, or {@code @RolesAllowed} on a private method
 *       that Spring Security's AOP proxy cannot intercept.
 *   <li>{@link FindingRules#SPRING_WEAK_PASSWORD_HASH} — {@code MessageDigest.getInstance()} called
 *       with {@code "MD5"}, {@code "SHA-1"}, or {@code "SHA-256"} — algorithms that are too fast
 *       for safe password hashing.
 *   <li>{@link FindingRules#SPRING_INSECURE_TRUST_MANAGER} — {@code X509TrustManager} with an
 *       empty {@code checkServerTrusted}/{@code checkClientTrusted} body, a {@code
 *       HostnameVerifier} whose {@code verify} returns {@code true} unconditionally, or a library
 *       trust-all/no-op shortcut ({@code NoopHostnameVerifier}, {@code TrustAllStrategy},
 *       {@code TrustSelfSignedStrategy}).
 *   <li>{@link FindingRules#SPRING_XXE_VULNERABLE_PARSER} — XML parser factory created without
 *       any {@code setFeature}/{@code setProperty} call disabling external entities.
 *   <li>{@link FindingRules#SPRING_INSECURE_DESERIALIZATION} — Jackson default-typing,
 *       {@code new ObjectInputStream(...)}, or SnakeYAML's {@code new Yaml()} default
 *       constructor.
 *   <li>{@link FindingRules#SPRING_SECURITY_HEADERS_DISABLED} — Spring Security HTTP response
 *       headers explicitly disabled (full {@code .headers().disable()}, or any of
 *       {@code frameOptions/contentTypeOptions/httpStrictTransportSecurity/contentSecurityPolicy}).
 *       {@code xssProtection} is deliberately excluded — the header is deprecated and Spring
 *       Security 5.8+/6 already sends {@code 0} per OWASP guidance.
 *   <li>{@link FindingRules#SPRING_COOKIE_MISSING_HTTPONLY} — a servlet {@code Cookie} added to
 *       the response with no {@code setHttpOnly(true)} call in the file.
 *   <li>{@link FindingRules#SPRING_ZIP_SLIP} — an archive entry name used to build a file path
 *       inside extraction code without containment validation.
 *   <li>{@link FindingRules#SPRING_PERMIT_ALL_ANY_REQUEST} — {@code anyRequest().permitAll()}
 *       or {@code requestMatchers("/**").permitAll()} in a {@code SecurityFilterChain}.
 *   <li>{@link FindingRules#SPRING_H2_CONSOLE_PERMITALL} — H2 console path
 *       ({@code /h2-console**}) granted {@code permitAll()} in a security configuration.
 *   <li>{@link FindingRules#SPRING_COMMAND_INJECTION} — {@code Runtime.exec}/{@code ProcessBuilder}
 *       argument built with string concatenation.
 *   <li>{@link FindingRules#SPRING_SPEL_INJECTION} — {@code parseExpression(...)} on a
 *       concatenated SpEL string.
 *   <li>{@link FindingRules#SPRING_PATH_TRAVERSAL} — file path built with concatenation.
 *   <li>{@link FindingRules#SPRING_SSRF_USER_URL} — outbound URL built with concatenation.
 *   <li>{@link FindingRules#SPRING_OPEN_REDIRECT} — redirect target built with concatenation.
 *   <li>{@link FindingRules#SPRING_INSECURE_RANDOM_FOR_SECURITY} — {@code java.util.Random}/
 *       {@code Math.random()} used in a security-sensitive context.
 *   <li>{@link FindingRules#SPRING_WEAK_CIPHER_ALGORITHM} — weak cipher algorithm/mode passed to
 *       {@code Cipher.getInstance(...)}.
 *   <li>{@link FindingRules#SPRING_HARDCODED_ENCRYPTION_KEY} — {@code SecretKeySpec}/
 *       {@code IvParameterSpec} built from a hardcoded value.
 *   <li>{@link FindingRules#SPRING_NOOP_PASSWORD_ENCODER} — {@code NoOpPasswordEncoder} or the
 *       deprecated {@code StandardPasswordEncoder} is used to store/compare passwords.
 *   <li>{@link FindingRules#SPRING_METHOD_SECURITY_NOT_ENABLED} — method-security annotations are
 *       used anywhere in the project but no {@code @EnableMethodSecurity} enables them.
 *   <li>{@link FindingRules#SPRING_SECURITY_IGNORING_BROAD_PATH} — {@code WebSecurity#ignoring()}
 *       matches a broad path, bypassing the Spring Security filter chain.
 *   <li>{@link FindingRules#SPRING_JWT_SIGNATURE_NOT_VERIFIED} — a JWT is parsed without verifying
 *       its signature (jjwt {@code parseClaimsJwt}/{@code parsePlaintextJwt}, or {@code
 *       SignatureAlgorithm.NONE}).
 * </ul>
 */
@Component
public class SecurityPracticeFindingAnalyzer {

    private static final Set<String> SECURITY_ANNOTATIONS =
            Set.of("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed");
    private static final Set<String> METHOD_SECURITY_ENABLERS =
            Set.of(
                    "EnableMethodSecurity",
                    "EnableGlobalMethodSecurity",
                    "EnableReactiveMethodSecurity");
    private static final Set<String> UNSIGNED_JWT_PARSE_METHODS =
            Set.of(
                    "parseClaimsJwt",
                    "parsePlaintextJwt",
                    "parseUnsecuredClaims",
                    "parseUnsecuredContent");
    private static final Set<String> INSECURE_TLS_TYPES =
            Set.of("NoopHostnameVerifier", "TrustAllStrategy", "TrustSelfSignedStrategy");

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
        // Cross-file signals for SPRING_METHOD_SECURITY_NOT_ENABLED: whether any class enables
        // method security, and the first place a method-security annotation is actually used.
        boolean methodSecurityEnabled = false;
        String usageRelativePath = null;
        Integer usageLine = null;
        String usageTarget = null;
        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            CompilationUnit cu = file.compilationUnit();
            if (cu == null) {
                continue;
            }
            analyzeSourceFile(cu, file.relativePath(), findings);

            for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                if (!methodSecurityEnabled && annotatedWithAny(cls, METHOD_SECURITY_ENABLERS)) {
                    methodSecurityEnabled = true;
                }
                if (usageTarget == null && annotatedWithAny(cls, SECURITY_ANNOTATIONS)) {
                    usageTarget = cls.getNameAsString();
                    usageLine = cls.getBegin().map(position -> position.line).orElse(null);
                    usageRelativePath = file.relativePath();
                }
                if (usageTarget == null) {
                    for (MethodDeclaration method : cls.getMethods()) {
                        if (annotatedWithAny(method, SECURITY_ANNOTATIONS)) {
                            usageTarget = cls.getNameAsString() + "#" + method.getNameAsString();
                            usageLine =
                                    method.getBegin().map(position -> position.line).orElse(null);
                            usageRelativePath = file.relativePath();
                            break;
                        }
                    }
                }
            }
        }
        if (usageTarget != null && !methodSecurityEnabled) {
            addMethodSecurityNotEnabledFinding(usageRelativePath, usageLine, usageTarget, findings);
        }
        return findings;
    }

    private boolean annotatedWithAny(MethodDeclaration method, Set<String> annotationNames) {
        return annotatedWithAny(method.getAnnotations(), annotationNames);
    }

    private boolean annotatedWithAny(ClassOrInterfaceDeclaration cls, Set<String> annotationNames) {
        return annotatedWithAny(cls.getAnnotations(), annotationNames);
    }

    private boolean annotatedWithAny(
            List<AnnotationExpr> annotations, Set<String> annotationNames) {
        return annotations.stream()
                .anyMatch(
                        annotation ->
                                annotationNames.contains(simpleName(annotation.getNameAsString())));
    }

    private void addMethodSecurityNotEnabledFinding(
            String relativePath, Integer line, String target, List<Finding> findings) {
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_METHOD_SECURITY_NOT_ENABLED,
                                FindingConfidence.MEDIUM)
                        .shortMessage(
                                "Method-security annotation on "
                                        + target
                                        + " is used, but no @EnableMethodSecurity was found —"
                                        + " the check is silently ignored.")
                        .whyBadPractice(
                                "Spring does not enable method security automatically."
                                    + " @PreAuthorize, @PostAuthorize, @Secured and @RolesAllowed"
                                    + " only take effect when a configuration class is annotated"
                                    + " with @EnableMethodSecurity (or the legacy"
                                    + " @EnableGlobalMethodSecurity). Without it the annotations"
                                    + " are parsed but never enforced.")
                        .possibleImpact(
                                "Endpoints and service methods that look protected are reachable by"
                                    + " any authenticated (or unauthenticated) caller — a silent"
                                    + " authorization bypass.")
                        .recommendation(
                                "Add @EnableMethodSecurity to a @Configuration class (prePost is"
                                    + " enabled by default), and verify the annotations actually"
                                    + " enforce the intended authorities.")
                        .evidence(
                                "Method-security annotations are used (first seen on "
                                        + target
                                        + " in "
                                        + relativePath
                                        + ") but no"
                                        + " @EnableMethodSecurity/@EnableGlobalMethodSecurity was"
                                        + " found in src/main/java.")
                        .limitations(
                                "Static analysis only sees src/main/java; method security enabled"
                                        + " via an imported library auto-configuration or a parent"
                                        + " context is not visible and would be a false positive.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Per-file analysis
    // ---------------------------------------------------------------------------

    private void analyzeSourceFile(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        detectWeakPasswordHash(cu, relativePath, findings);
        detectXxeVulnerableParser(cu, relativePath, findings);
        detectInsecureDeserialization(cu, relativePath, findings);
        detectSecurityHeadersDisabled(cu, relativePath, findings);
        detectPermitAllAnyRequest(cu, relativePath, findings);
        detectH2ConsolePermitAll(cu, relativePath, findings);
        detectCommandInjection(cu, relativePath, findings);
        detectSpelInjection(cu, relativePath, findings);
        detectPathTraversal(cu, relativePath, findings);
        detectSsrfUserUrl(cu, relativePath, findings);
        detectOpenRedirect(cu, relativePath, findings);
        detectInsecureRandomForSecurity(cu, relativePath, findings);
        detectWeakCipherAlgorithm(cu, relativePath, findings);
        detectHardcodedEncryptionKey(cu, relativePath, findings);
        detectLoggingAuthHeader(cu, relativePath, findings);
        detectBcryptLowStrength(cu, relativePath, findings);
        detectNoOpPasswordEncoder(cu, relativePath, findings);
        detectSecurityIgnoringBroadPath(cu, relativePath, findings);
        detectJwtSignatureNotVerified(cu, relativePath, findings);
        detectInsecureTlsBypass(cu, relativePath, findings);
        detectCookieMissingHttpOnly(cu, relativePath, findings);
        detectZipSlip(cu, relativePath, findings);

        for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            for (MethodDeclaration method : cls.getMethods()) {
                detectPreAuthorizeOnPrivateMethod(cls, method, relativePath, findings);
            }
            detectInsecureTrustManager(cls, relativePath, findings);
            detectInsecureHostnameVerifier(cls, relativePath, findings);
        }
        detectInsecureHostnameVerifierLambda(cu, relativePath, findings);
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_NOOP_PASSWORD_ENCODER
    // ---------------------------------------------------------------------------

    private void detectNoOpPasswordEncoder(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        Integer line = null;
        String detail = null;
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (call.getScope()
                    .map(scope -> simpleName(scope.toString()))
                    .filter("NoOpPasswordEncoder"::equals)
                    .isPresent()) {
                line = call.getBegin().map(position -> position.line).orElse(null);
                detail = "NoOpPasswordEncoder";
                break;
            }
        }
        if (detail == null) {
            for (ObjectCreationExpr expr : cu.findAll(ObjectCreationExpr.class)) {
                String type = simpleName(expr.getType().asString());
                if (type.equals("NoOpPasswordEncoder") || type.equals("StandardPasswordEncoder")) {
                    line = expr.getBegin().map(position -> position.line).orElse(null);
                    detail = type;
                    break;
                }
            }
        }
        if (detail == null) {
            return;
        }
        boolean plaintext = detail.equals("NoOpPasswordEncoder");
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_NOOP_PASSWORD_ENCODER, FindingConfidence.HIGH)
                        .shortMessage(
                                detail
                                        + " is used in "
                                        + relativePath
                                        + (plaintext
                                                ? " — passwords are stored and compared in clear"
                                                        + " text."
                                                : " — passwords are hashed with a known-weak"
                                                        + " algorithm."))
                        .whyBadPractice(
                                plaintext
                                        ? "NoOpPasswordEncoder performs no hashing at all: the raw"
                                              + " password is stored and compared verbatim. Anyone"
                                              + " with read access to the credential store"
                                              + " immediately obtains every password."
                                        : "StandardPasswordEncoder uses a fixed, fast SHA-256-based"
                                                + " scheme that is deprecated and unsuitable for"
                                                + " password storage; it is trivial to brute-force"
                                                + " with modern hardware.")
                        .possibleImpact(
                                "A database leak or log exposure reveals usable credentials"
                                    + " directly, enabling account takeover and credential-stuffing"
                                    + " against other systems.")
                        .recommendation(
                                "Use an adaptive password encoder such as"
                                    + " PasswordEncoderFactories.createDelegatingPasswordEncoder(),"
                                    + " or a BCryptPasswordEncoder/Argon2PasswordEncoder with a"
                                    + " sufficient work factor.")
                        .evidence(detail + " reference found in " + relativePath + ".")
                        .limitations(
                                "Static analysis flags the encoder reference; it cannot confirm it"
                                    + " is wired as the application's PasswordEncoder bean, though"
                                    + " that is the usual reason to declare one.")
                        .source(relativePath, line)
                        .target(detail)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SECURITY_IGNORING_BROAD_PATH
    // ---------------------------------------------------------------------------

    private void detectSecurityIgnoringBroadPath(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!call.getNameAsString().equals("ignoring")) {
                continue;
            }
            MethodCallExpr root = call;
            while (root.getParentNode().orElse(null) instanceof MethodCallExpr parent) {
                root = parent;
            }
            String chain = root.toString();
            if (!chain.contains("\"/**\"") && !chain.contains("anyRequest(")) {
                continue;
            }
            Integer line = call.getName().getBegin().map(position -> position.line).orElse(null);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_SECURITY_IGNORING_BROAD_PATH,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "WebSecurity.ignoring() matches a broad path in "
                                            + relativePath
                                            + " — those URLs bypass Spring Security entirely.")
                            .whyBadPractice(
                                    "Paths matched by web.ignoring() are excluded from the Spring"
                                        + " Security filter chain altogether. Unlike permitAll(),"
                                        + " which still runs the filters, ignored requests get no"
                                        + " authentication, no authorization, and no security"
                                        + " response headers. Using /** (or anyRequest) ignores the"
                                        + " entire application.")
                            .possibleImpact(
                                    "Every endpoint becomes reachable without authentication and"
                                            + " without CSRF, CORS, or security-header protection —"
                                            + " effectively disabling Spring Security.")
                            .recommendation(
                                    "Restrict ignoring() to genuinely public static resources (e.g."
                                        + " /css/**, /js/**), and authorize application endpoints"
                                        + " inside the SecurityFilterChain with"
                                        + " authorizeHttpRequests instead.")
                            .evidence(
                                    "web.ignoring() over a broad matcher found in "
                                            + relativePath
                                            + ".")
                            .limitations(
                                    "Static analysis matches the ignoring() chain textually; a"
                                            + " constant or variable holding \"/**\" would not be"
                                            + " detected.")
                            .source(relativePath, line)
                            .target("WebSecurity.ignoring")
                            .build());
            return; // one finding per file is sufficient
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_JWT_SIGNATURE_NOT_VERIFIED
    // ---------------------------------------------------------------------------

    private void detectJwtSignatureNotVerified(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        Integer line = null;
        String detail = null;
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (UNSIGNED_JWT_PARSE_METHODS.contains(call.getNameAsString())) {
                line = call.getName().getBegin().map(position -> position.line).orElse(null);
                detail =
                        call.getNameAsString()
                                + "(...) parses a JWT without verifying its signature";
                break;
            }
        }
        if (detail == null) {
            for (FieldAccessExpr field : cu.findAll(FieldAccessExpr.class)) {
                if (field.getNameAsString().equals("NONE")
                        && simpleName(field.getScope().toString()).equals("SignatureAlgorithm")) {
                    line = field.getBegin().map(position -> position.line).orElse(null);
                    detail = "SignatureAlgorithm.NONE produces or accepts an unsigned JWT";
                    break;
                }
            }
        }
        if (detail == null) {
            return;
        }
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_JWT_SIGNATURE_NOT_VERIFIED,
                                FindingConfidence.HIGH)
                        .shortMessage(detail + " in " + relativePath + ".")
                        .whyBadPractice(
                                "Reading a JWT without verifying its signature — jjwt"
                                    + " parseClaimsJwt/parsePlaintextJwt/parseUnsecuredClaims, or"
                                    + " the 'none' algorithm — trusts the token's claims with no"
                                    + " proof of integrity. An attacker can mint a token with any"
                                    + " claims, including elevated roles or another user's"
                                    + " identity.")
                        .possibleImpact(
                                "Full authentication/authorization bypass: forged tokens are"
                                        + " accepted as if issued by the server.")
                        .recommendation(
                                "Verify the signature with the expected key (parseSignedClaims /"
                                    + " parseClaimsJws), reject the 'none' algorithm, and pin the"
                                    + " accepted signature algorithm(s).")
                        .evidence(detail + " found in " + relativePath + ".")
                        .limitations(
                                "Static analysis flags unsigned-parse APIs and the 'none'"
                                    + " algorithm; it cannot confirm the parsed token is used for"
                                    + " authentication.")
                        .source(relativePath, line)
                        .target("JWT verification")
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_INSECURE_TRUST_MANAGER (library trust-all / no-op verifier shortcuts)
    // ---------------------------------------------------------------------------

    private void detectInsecureTlsBypass(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        Integer line = null;
        String detail = null;
        for (ObjectCreationExpr expr : cu.findAll(ObjectCreationExpr.class)) {
            String type = simpleName(expr.getType().asString());
            if (INSECURE_TLS_TYPES.contains(type)) {
                line = expr.getBegin().map(position -> position.line).orElse(null);
                detail = type;
                break;
            }
        }
        if (detail == null) {
            for (FieldAccessExpr field : cu.findAll(FieldAccessExpr.class)) {
                String type = simpleName(field.getScope().toString());
                if (INSECURE_TLS_TYPES.contains(type)) {
                    line = field.getBegin().map(position -> position.line).orElse(null);
                    detail = type;
                    break;
                }
            }
        }
        if (detail == null) {
            return;
        }
        boolean hostname = detail.equals("NoopHostnameVerifier");
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_INSECURE_TRUST_MANAGER, FindingConfidence.HIGH)
                        .shortMessage(
                                (hostname
                                                ? "NoopHostnameVerifier disables hostname"
                                                        + " verification"
                                                : detail
                                                        + " trusts all (or any self-signed)"
                                                        + " certificates")
                                        + " in "
                                        + relativePath
                                        + ".")
                        .whyBadPractice(
                                hostname
                                        ? "NoopHostnameVerifier accepts a certificate regardless of"
                                              + " which host it was issued for, disabling hostname"
                                              + " verification on the TLS connection."
                                        : "TrustAllStrategy/TrustSelfSignedStrategy make the client"
                                                + " accept certificates that do not chain to a"
                                                + " trusted CA, so the server's identity is never"
                                                + " verified.")
                        .possibleImpact(
                                "A man-in-the-middle attacker can present any certificate and"
                                    + " transparently intercept or modify traffic the application"
                                    + " believes is secure.")
                        .recommendation(
                                "Remove the trust-all/no-op shortcut and rely on the default"
                                    + " verification. If an internal CA or specific host must be"
                                    + " trusted, load that CA into a truststore or pin the exact"
                                    + " host rather than trusting everything.")
                        .evidence(detail + " reference found in " + relativePath + ".")
                        .limitations(
                                "High confidence — these APIs exist only to bypass certificate or"
                                        + " hostname verification.")
                        .source(relativePath, line)
                        .target(detail)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_PREAUTHORIZE_ON_PRIVATE_METHOD
    // ---------------------------------------------------------------------------

    private void detectPreAuthorizeOnPrivateMethod(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        if (!method.isPrivate()) {
            return;
        }
        String securityAnn =
                method.getAnnotations().stream()
                        .map(a -> simpleName(a.getNameAsString()))
                        .filter(SECURITY_ANNOTATIONS::contains)
                        .findFirst()
                        .orElse(null);
        if (securityAnn == null) {
            return;
        }
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_PREAUTHORIZE_ON_PRIVATE_METHOD,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@"
                                        + securityAnn
                                        + " on private method "
                                        + target
                                        + " — Spring Security's proxy cannot intercept private"
                                        + " methods.")
                        .whyBadPractice(
                                "Spring Security applies authorization through a proxy (JDK dynamic"
                                        + " proxy or CGLIB). Proxies can only intercept calls made"
                                        + " through the proxy reference and cannot override private"
                                        + " methods. The security annotation is silently ignored.")
                        .possibleImpact(
                                "The authorization check is never executed for calls to this"
                                    + " method; any caller — even unauthenticated or unauthorized"
                                    + " callers — can invoke the method without restriction.")
                        .recommendation(
                                "Change the method visibility to package-private, protected, or"
                                    + " public. If the method must remain private, extract the"
                                    + " secured logic to a public wrapper method, or use AspectJ"
                                    + " compile-time weaving instead of proxy-based AOP.")
                        .limitations(
                                "If the project uses AspectJ weaving instead of Spring proxies,"
                                        + " private methods can be intercepted.")
                        .evidence(
                                "@"
                                        + securityAnn
                                        + " found on private method "
                                        + method.getNameAsString()
                                        + " in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_WEAK_PASSWORD_HASH
    // ---------------------------------------------------------------------------

    private static final Set<String> WEAK_HASH_ALGORITHMS = Set.of("MD5", "SHA-1", "SHA-256");

    /**
     * Keywords indicating that the enclosing method/class handles passwords or credentials. The
     * weak-hash rule only fires in such a context: MD5/SHA-1/SHA-256 are perfectly appropriate for
     * checksums, ETags, and content addressing — they are only wrong for password storage.
     */
    private static final Set<String> PASSWORD_CONTEXT_KEYWORDS =
            Set.of("password", "passwd", "pwd", "credential", "login", "secret");

    private static boolean inPasswordContext(com.github.javaparser.ast.Node node) {
        StringBuilder context = new StringBuilder();
        node.findAncestor(MethodDeclaration.class)
                .ifPresent(m -> context.append(m.getNameAsString()).append(' '));
        node.findAncestor(ClassOrInterfaceDeclaration.class)
                .ifPresent(c -> context.append(c.getNameAsString()));
        String haystack = context.toString().toLowerCase(java.util.Locale.ROOT);
        return PASSWORD_CONTEXT_KEYWORDS.stream().anyMatch(haystack::contains);
    }

    private void detectWeakPasswordHash(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"getInstance".equals(call.getNameAsString())) {
                continue;
            }
            boolean scopeIsMessageDigest =
                    call.getScope()
                            .map(s -> simpleName(s.toString()).equals("MessageDigest"))
                            .orElse(false);
            if (!scopeIsMessageDigest) {
                continue;
            }
            if (!inPasswordContext(call)) {
                continue;
            }
            call.getArguments().stream()
                    .filter(arg -> arg instanceof com.github.javaparser.ast.expr.StringLiteralExpr)
                    .map(arg -> ((com.github.javaparser.ast.expr.StringLiteralExpr) arg).asString())
                    .filter(WEAK_HASH_ALGORITHMS::contains)
                    .findFirst()
                    .ifPresent(
                            algo -> {
                                Integer line = call.getBegin().map(p -> p.line).orElse(null);
                                findings.add(
                                        FindingFactory.builder(
                                                        FindingRules.SPRING_WEAK_PASSWORD_HASH,
                                                        FindingConfidence.MEDIUM)
                                                .shortMessage(
                                                        "MessageDigest.getInstance(\""
                                                                + algo
                                                                + "\") used in "
                                                                + relativePath
                                                                + " — too fast for password"
                                                                + " hashing.")
                                                .whyBadPractice(
                                                        algo
                                                                + " is a general-purpose"
                                                                + " cryptographic hash function"
                                                                + " optimised for speed. Speed is"
                                                                + " exactly what you do not want"
                                                                + " for password hashing: a modern"
                                                                + " GPU can compute billions of MD5"
                                                                + " or SHA-256 hashes per second,"
                                                                + " making brute-force and"
                                                                + " rainbow-table attacks trivial"
                                                                + " against any leaked hash"
                                                                + " database.")
                                                .possibleImpact(
                                                        "In a credential breach, all stored"
                                                            + " passwords can be recovered within"
                                                            + " hours or days using commodity"
                                                            + " hardware. Credential stuffing"
                                                            + " attacks then compromise user"
                                                            + " accounts on other services.")
                                                .recommendation(
                                                        "Use BCryptPasswordEncoder,"
                                                            + " Argon2PasswordEncoder, or"
                                                            + " SCryptPasswordEncoder from Spring"
                                                            + " Security. These are slow by design"
                                                            + " (tunable work factor) and include a"
                                                            + " per-password salt automatically."
                                                            + " Never implement password hashing"
                                                            + " manually.")
                                                .limitations(
                                                        "Medium confidence — flagged because the"
                                                            + " enclosing method/class name"
                                                            + " suggests password or credential"
                                                            + " handling. Non-password uses"
                                                            + " (checksums, ETags, content"
                                                            + " addressing) are not flagged. Review"
                                                            + " the context to confirm the hash"
                                                            + " result is used for credential"
                                                            + " storage.")
                                                .evidence(
                                                        "MessageDigest.getInstance(\""
                                                                + algo
                                                                + "\") found in "
                                                                + relativePath
                                                                + ".")
                                                .source(relativePath, line)
                                                .build());
                            });
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_INSECURE_TRUST_MANAGER (TrustManager half)
    // ---------------------------------------------------------------------------

    private void detectInsecureTrustManager(
            ClassOrInterfaceDeclaration cls, String relativePath, List<Finding> findings) {
        boolean implementsX509TrustManager =
                cls.getImplementedTypes().stream()
                        .anyMatch(t -> simpleName(t.getNameAsString()).equals("X509TrustManager"));
        if (!implementsX509TrustManager) {
            return;
        }
        for (MethodDeclaration method : cls.getMethods()) {
            String name = method.getNameAsString();
            if (!"checkServerTrusted".equals(name) && !"checkClientTrusted".equals(name)) {
                continue;
            }
            if (method.getBody().isEmpty()) {
                continue;
            }
            if (!method.getBody().get().getStatements().isEmpty()) {
                continue;
            }
            Integer line = method.getBegin().map(p -> p.line).orElse(null);
            String target = cls.getNameAsString() + "#" + name;
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_INSECURE_TRUST_MANAGER,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "X509TrustManager."
                                            + name
                                            + " has an empty body in "
                                            + relativePath
                                            + " — TLS certificate validation is disabled.")
                            .whyBadPractice(
                                    "An X509TrustManager whose check method does nothing and never"
                                        + " throws CertificateException accepts every server"
                                        + " certificate, including self-signed certificates from a"
                                        + " man-in-the-middle proxy.")
                            .possibleImpact(
                                    "All HTTPS traffic from this application can be silently"
                                            + " intercepted, allowing credential theft and data"
                                            + " tampering.")
                            .recommendation(
                                    "Remove the custom TrustManager and rely on the default JVM"
                                        + " trust store. If a self-signed certificate is required"
                                        + " for testing, install it in the JVM trust store via"
                                        + " keytool instead of bypassing validation.")
                            .limitations(
                                    "High confidence — an empty implementation has no legitimate"
                                            + " production purpose.")
                            .evidence(
                                    "X509TrustManager."
                                            + name
                                            + " with empty body found in "
                                            + relativePath
                                            + ".")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_INSECURE_TRUST_MANAGER (HostnameVerifier half)
    // ---------------------------------------------------------------------------

    private void detectInsecureHostnameVerifier(
            ClassOrInterfaceDeclaration cls, String relativePath, List<Finding> findings) {
        boolean implementsHostnameVerifier =
                cls.getImplementedTypes().stream()
                        .anyMatch(t -> simpleName(t.getNameAsString()).equals("HostnameVerifier"));
        if (!implementsHostnameVerifier) {
            return;
        }
        for (MethodDeclaration method : cls.getMethods()) {
            if (!"verify".equals(method.getNameAsString())) {
                continue;
            }
            if (method.getBody().isEmpty()) {
                continue;
            }
            boolean returnsTrueUnconditionally =
                    method.getBody().get().getStatements().size() == 1
                            && method.getBody().get().getStatement(0) instanceof ReturnStmt ret
                            && ret.getExpression()
                                    .filter(e -> e instanceof BooleanLiteralExpr)
                                    .map(e -> ((BooleanLiteralExpr) e).getValue())
                                    .orElse(false);
            if (!returnsTrueUnconditionally) {
                continue;
            }
            Integer line = method.getBegin().map(p -> p.line).orElse(null);
            reportInsecureHostnameVerifier(
                    relativePath,
                    line,
                    cls.getNameAsString() + "#verify",
                    "HostnameVerifier.verify always returns true",
                    findings);
        }
    }

    private void detectInsecureHostnameVerifierLambda(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"setHostnameVerifier".equals(call.getNameAsString())) {
                continue;
            }
            for (Expression arg : call.getArguments()) {
                if (!(arg instanceof LambdaExpr lambda)) {
                    continue;
                }
                Expression body = null;
                if (lambda.getBody().isExpressionStmt()) {
                    body = lambda.getBody().asExpressionStmt().getExpression();
                } else if (lambda.getExpressionBody().isPresent()) {
                    body = lambda.getExpressionBody().get();
                } else if (lambda.getBody().isBlockStmt()
                        && lambda.getBody().asBlockStmt().getStatements().size() == 1
                        && lambda.getBody().asBlockStmt().getStatement(0) instanceof ReturnStmt r) {
                    body = r.getExpression().orElse(null);
                }
                boolean unconditionalTrue =
                        body instanceof BooleanLiteralExpr lit && lit.getValue();
                if (!unconditionalTrue) {
                    continue;
                }
                Integer line = call.getBegin().map(p -> p.line).orElse(null);
                reportInsecureHostnameVerifier(
                        relativePath,
                        line,
                        null,
                        "setHostnameVerifier((h, s) -> true) accepts any hostname",
                        findings);
            }
        }
    }

    private void reportInsecureHostnameVerifier(
            String relativePath,
            Integer line,
            String target,
            String shortMessageDetail,
            List<Finding> findings) {
        var builder =
                FindingFactory.builder(
                                FindingRules.SPRING_INSECURE_TRUST_MANAGER, FindingConfidence.HIGH)
                        .shortMessage(shortMessageDetail + " in " + relativePath + ".")
                        .whyBadPractice(
                                "A HostnameVerifier that returns true for every host disables"
                                    + " hostname verification: the TLS connection completes even"
                                    + " when the certificate was issued to a different domain.")
                        .possibleImpact(
                                "A man-in-the-middle attacker presenting any valid-but-unrelated"
                                        + " certificate can intercept traffic that the application"
                                        + " believes is going to the intended host.")
                        .recommendation(
                                "Remove the custom HostnameVerifier and rely on the default."
                                        + " If a specific alternate hostname must be accepted (e.g."
                                        + " an internal CA), constrain the verifier to that exact"
                                        + " hostname rather than returning true unconditionally.")
                        .limitations("High confidence — verifier returns true unconditionally.")
                        .evidence(shortMessageDetail + " found in " + relativePath + ".")
                        .source(relativePath, line);
        if (target != null) {
            builder.target(target);
        }
        findings.add(builder.build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_XXE_VULNERABLE_PARSER
    // ---------------------------------------------------------------------------

    private static final Set<String> XXE_FACTORY_TYPES =
            Set.of(
                    "DocumentBuilderFactory",
                    "SAXParserFactory",
                    "XMLInputFactory",
                    "TransformerFactory");

    private void detectXxeVulnerableParser(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        // Skip files that look like XML security hardening helpers (e.g. test fixtures).
        boolean fileSetsFeature =
                cu.findAll(MethodCallExpr.class).stream()
                        .anyMatch(
                                m ->
                                        "setFeature".equals(m.getNameAsString())
                                                || "setProperty".equals(m.getNameAsString())
                                                || "setXIncludeAware".equals(m.getNameAsString())
                                                || "setExpandEntityReferences"
                                                        .equals(m.getNameAsString()));
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            String n = call.getNameAsString();
            if (!"newInstance".equals(n) && !"newFactory".equals(n)) {
                continue;
            }
            String scopeType = call.getScope().map(s -> simpleName(s.toString())).orElse("");
            if (!XXE_FACTORY_TYPES.contains(scopeType)) {
                continue;
            }
            if (fileSetsFeature) {
                continue; // Best-effort heuristic — assume hardening is in place.
            }
            Integer line = call.getBegin().map(p -> p.line).orElse(null);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_XXE_VULNERABLE_PARSER,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    scopeType
                                            + "."
                                            + n
                                            + "() in "
                                            + relativePath
                                            + " — no setFeature/setProperty call disables external"
                                            + " entities anywhere in this file.")
                            .whyBadPractice(
                                    "Java's default XML parsers expand external entities and honour"
                                        + " DOCTYPE declarations. A malicious XML document can read"
                                        + " arbitrary local files (file:///etc/passwd), trigger"
                                        + " internal-network SSRF, or cause denial of service via"
                                        + " billion-laughs expansion.")
                            .possibleImpact(
                                    "Any endpoint or job that parses externally supplied XML can be"
                                        + " coerced into reading local files, making outbound HTTP"
                                        + " requests, or exhausting CPU/memory.")
                            .recommendation(
                                    "Disable external entities and DOCTYPE before using the parser:"
                                        + " factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,"
                                        + " true);"
                                        + " factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\","
                                        + " true); factory.setXIncludeAware(false);"
                                        + " factory.setExpandEntityReferences(false). Or use"
                                        + " OWASP's safe XML parsing utility.")
                            .limitations(
                                    "Medium confidence — heuristic checks the same file only. If"
                                            + " hardening is performed in a helper class the parser"
                                            + " may still be safe.")
                            .evidence(
                                    scopeType
                                            + "."
                                            + n
                                            + "() found in "
                                            + relativePath
                                            + " with no setFeature/setProperty hardening in the"
                                            + " same file.")
                            .source(relativePath, line)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_INSECURE_DESERIALIZATION
    // ---------------------------------------------------------------------------

    private void detectInsecureDeserialization(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        // Jackson polymorphic typing: enableDefaultTyping / activateDefaultTyping
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            String name = call.getNameAsString();
            if (!"enableDefaultTyping".equals(name) && !"activateDefaultTyping".equals(name)) {
                continue;
            }
            Integer line = call.getBegin().map(p -> p.line).orElse(null);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_INSECURE_DESERIALIZATION,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "Jackson polymorphic deserialization enabled via "
                                            + name
                                            + "() in "
                                            + relativePath
                                            + ".")
                            .whyBadPractice(
                                    "Jackson default typing instructs the deserializer to honour a"
                                        + " @class type hint in the JSON payload and instantiate"
                                        + " the named class. Many classes on a typical classpath"
                                        + " are known gadget chains that achieve remote code"
                                        + " execution when constructed with attacker-chosen state.")
                            .possibleImpact(
                                    "An attacker who can submit JSON to any deserializing endpoint"
                                            + " can execute arbitrary code on the server.")
                            .recommendation(
                                    "Do not enable default typing. If polymorphism is required, use"
                                        + " @JsonTypeInfo with an explicit, restrictive subtype"
                                        + " allowlist via @JsonSubTypes, or use a"
                                        + " BasicPolymorphicTypeValidator that only allows known"
                                        + " base types.")
                            .limitations(
                                    "High confidence — both APIs are widely flagged in CVE"
                                            + " advisories.")
                            .evidence(name + "() call found in " + relativePath + ".")
                            .source(relativePath, line)
                            .build());
        }

        // Java serialization: new ObjectInputStream(...) anywhere is risky for untrusted input.
        // SnakeYAML: new Yaml() (no-arg) uses an unsafe Constructor.
        for (ObjectCreationExpr creation : cu.findAll(ObjectCreationExpr.class)) {
            String typeName = simpleName(creation.getType().getNameAsString());
            if ("ObjectInputStream".equals(typeName)) {
                Integer line = creation.getBegin().map(p -> p.line).orElse(null);
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_INSECURE_DESERIALIZATION,
                                        FindingConfidence.MEDIUM)
                                .shortMessage(
                                        "new ObjectInputStream(...) in "
                                                + relativePath
                                                + " — Java serialization of untrusted input is a"
                                                + " known RCE vector.")
                                .whyBadPractice(
                                        "ObjectInputStream.readObject reconstructs arbitrary class"
                                            + " graphs and invokes readObject / readResolve on each"
                                            + " element. Many libraries on a normal classpath are"
                                            + " published gadget chains that achieve remote code"
                                            + " execution.")
                                .possibleImpact(
                                        "If the input stream is ever attacker-controlled (queue"
                                            + " message, cache value, uploaded file), the server"
                                            + " can be remotely compromised.")
                                .recommendation(
                                        "Replace Java serialization with a structured format such"
                                            + " as JSON or Protocol Buffers. If unavoidable,"
                                            + " install a strict ObjectInputFilter allowlist via"
                                            + " ObjectInputFilter.Config.")
                                .limitations(
                                        "Medium confidence — flagged based on type alone. Some uses"
                                                + " (deserializing trusted local files) are safe in"
                                                + " practice.")
                                .evidence(
                                        "new ObjectInputStream(...) found in " + relativePath + ".")
                                .source(relativePath, line)
                                .build());
            } else if ("Yaml".equals(typeName) && creation.getArguments().isEmpty()) {
                Integer line = creation.getBegin().map(p -> p.line).orElse(null);
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_INSECURE_DESERIALIZATION,
                                        FindingConfidence.MEDIUM)
                                .shortMessage(
                                        "new Yaml() with no-arg constructor in "
                                                + relativePath
                                                + " — SnakeYAML's default Constructor can"
                                                + " instantiate arbitrary classes.")
                                .whyBadPractice(
                                        "SnakeYAML's default Constructor honours the !!javaClass"
                                            + " tag in the document and reflectively instantiates"
                                            + " the named class. Several gadget chains on a typical"
                                            + " Spring Boot classpath escalate this to remote code"
                                            + " execution.")
                                .possibleImpact(
                                        "An attacker controlling the YAML input can execute"
                                                + " arbitrary code on the server.")
                                .recommendation(
                                        "Use new Yaml(new SafeConstructor(new LoaderOptions())) or"
                                            + " a Constructor configured with a restrictive type"
                                            + " allowlist. SnakeYAML 2.x defaults to"
                                            + " SafeConstructor for the no-arg path — verify the"
                                            + " version.")
                                .limitations(
                                        "Medium confidence — SnakeYAML 2.x changed the default to"
                                                + " be safe; the rule cannot determine the bundled"
                                                + " version statically.")
                                .evidence("new Yaml() call found in " + relativePath + ".")
                                .source(relativePath, line)
                                .build());
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SECURITY_HEADERS_DISABLED
    // ---------------------------------------------------------------------------

    // Note: "xssProtection" is deliberately absent. The X-XSS-Protection header is dead —
    // browsers removed the XSS auditor, OWASP recommends sending "0", and Spring Security
    // 5.8+/6 already defaults the header value to "0" — so disabling that writer removes no
    // active protection and must not be reported as a security regression.
    private static final Set<String> HEADER_CONFIG_NAMES =
            Set.of(
                    "headers",
                    "frameOptions",
                    "contentTypeOptions",
                    "httpStrictTransportSecurity",
                    "contentSecurityPolicy");

    private void detectSecurityHeadersDisabled(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"disable".equals(call.getNameAsString())) {
                continue;
            }
            String scopeName =
                    call.getScope()
                            .filter(s -> s instanceof MethodCallExpr)
                            .map(s -> ((MethodCallExpr) s).getNameAsString())
                            .orElse("");
            if (!HEADER_CONFIG_NAMES.contains(scopeName)) {
                continue;
            }
            if ("headers".equals(scopeName) && !isInsideSpringSecurityConfig(call)) {
                // The bare name "headers" can collide with non-security DSLs; restrict to
                // contexts that look like a Spring Security SecurityFilterChain configuration.
                continue;
            }
            Integer line = call.getBegin().map(p -> p.line).orElse(null);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_SECURITY_HEADERS_DISABLED,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "."
                                            + scopeName
                                            + "().disable() turns off a Spring Security HTTP header"
                                            + " in "
                                            + relativePath
                                            + ".")
                            .whyBadPractice(
                                    "Spring Security enables a small set of HTTP response headers"
                                            + " (X-Frame-Options, X-Content-Type-Options,"
                                            + " Strict-Transport-Security, and an optional"
                                            + " Content-Security-Policy) by default. They are"
                                            + " browser-enforced defenses against clickjacking,"
                                            + " content sniffing, and TLS downgrade.")
                            .possibleImpact(
                                    "The application becomes vulnerable to clickjacking via"
                                        + " iframe-embedding, content-type confusion attacks, and"
                                        + " (for the HSTS variant) protocol-downgrade attacks.")
                            .recommendation(
                                    "Keep the default headers enabled. If a single header conflicts"
                                        + " with a specific use case (e.g. SAMEORIGIN frame"
                                        + " embedding from a known partner), configure that header"
                                        + " instead of disabling it entirely.")
                            .limitations(
                                    "Medium confidence — some applications legitimately disable a"
                                        + " single header (frameOptions for OAuth pop-ups,"
                                        + " httpStrictTransportSecurity behind a TLS-terminating"
                                        + " proxy). Review the surrounding context.")
                            .evidence(
                                    "." + scopeName + "().disable() found in " + relativePath + ".")
                            .source(relativePath, line)
                            .build());
        }
    }

    private static boolean isInsideSpringSecurityConfig(MethodCallExpr call) {
        // Walk up parents and look for a chain that includes a known security DSL anchor.
        var node = call.getParentNode();
        while (node.isPresent()) {
            var n = node.get();
            String repr = n.toString();
            if (repr.contains("HttpSecurity")
                    || repr.contains("SecurityFilterChain")
                    || repr.contains("authorizeHttpRequests")
                    || repr.contains("authorizeRequests")) {
                return true;
            }
            node = n.getParentNode();
        }
        return false;
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_PERMIT_ALL_ANY_REQUEST
    // ---------------------------------------------------------------------------

    private void detectPermitAllAnyRequest(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"permitAll".equals(call.getNameAsString())) {
                continue;
            }
            var scope = call.getScope();
            if (scope.isEmpty() || !(scope.get() instanceof MethodCallExpr scopeCall)) {
                continue;
            }
            String scopeName = scopeCall.getNameAsString();
            boolean matchesAnyRequest = "anyRequest".equals(scopeName);
            boolean matchesWildcardMatcher =
                    ("requestMatchers".equals(scopeName) || "antMatchers".equals(scopeName))
                            && scopeCall.getArguments().stream()
                                    .filter(a -> a instanceof StringLiteralExpr)
                                    .map(a -> ((StringLiteralExpr) a).asString())
                                    .anyMatch(s -> "/**".equals(s) || "/*".equals(s));
            if (!matchesAnyRequest && !matchesWildcardMatcher) {
                continue;
            }
            Integer line = call.getBegin().map(p -> p.line).orElse(null);
            String shape =
                    matchesAnyRequest
                            ? "anyRequest().permitAll()"
                            : scopeName + "(\"/**\").permitAll()";
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_PERMIT_ALL_ANY_REQUEST,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    shape
                                            + " grants unauthenticated access to every endpoint in "
                                            + relativePath
                                            + ".")
                            .whyBadPractice(
                                    "permitAll() on the catch-all matcher removes authentication"
                                        + " from the entire application. Because the rule sits at"
                                        + " the end of the chain, any more specific matchers above"
                                        + " it still apply — but anything that does not match a"
                                        + " preceding rule is now public.")
                            .possibleImpact(
                                    "Every endpoint that is not explicitly secured by an earlier"
                                            + " matcher is reachable without authentication,"
                                            + " including any controller a developer later adds.")
                            .recommendation(
                                    "Replace the catch-all permitAll() with"
                                        + " .anyRequest().authenticated() (or .denyAll() if the app"
                                        + " is purely public-content), and grant permitAll only to"
                                        + " specific whitelisted paths.")
                            .limitations(
                                    "High confidence for the exact patterns checked. Some apps"
                                        + " intentionally publish read-only public APIs; review the"
                                        + " controllers behind the chain.")
                            .evidence(shape + " found in " + relativePath + ".")
                            .source(relativePath, line)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_H2_CONSOLE_PERMITALL
    // ---------------------------------------------------------------------------

    private void detectH2ConsolePermitAll(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"permitAll".equals(call.getNameAsString())) {
                continue;
            }
            var scope = call.getScope();
            if (scope.isEmpty() || !(scope.get() instanceof MethodCallExpr scopeCall)) {
                continue;
            }
            String scopeName = scopeCall.getNameAsString();
            if (!"requestMatchers".equals(scopeName) && !"antMatchers".equals(scopeName)) {
                continue;
            }
            boolean targetsH2Console =
                    scopeCall.getArguments().stream()
                            .filter(a -> a instanceof StringLiteralExpr)
                            .map(a -> ((StringLiteralExpr) a).asString())
                            .anyMatch(s -> s.contains("/h2-console") || s.contains("/h2"));
            if (!targetsH2Console) {
                continue;
            }
            Integer line = call.getBegin().map(p -> p.line).orElse(null);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_H2_CONSOLE_PERMITALL,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "Security configuration permits unauthenticated access to the"
                                            + " H2 console path in "
                                            + relativePath
                                            + ".")
                            .whyBadPractice(
                                    "The H2 web console accepts arbitrary SQL through a JDBC"
                                        + " connection and can run Java stored procedures, making"
                                        + " it a remote-code-execution surface. permitAll() on the"
                                        + " /h2-console path removes the only access control in"
                                        + " front of it.")
                            .possibleImpact(
                                    "Any client that can reach the application port can read and"
                                            + " write every row in the database and, on most"
                                            + " configurations, execute arbitrary Java code on the"
                                            + " host.")
                            .recommendation(
                                    "Remove the permitAll() on /h2-console — require"
                                        + " authentication, restrict it to a developer-only role,"
                                        + " or remove the H2 dependency entirely from production"
                                        + " builds.")
                            .limitations(
                                    "High confidence — there is essentially no production reason"
                                            + " to expose the H2 console unauthenticated.")
                            .evidence(
                                    scopeName
                                            + "(\".../h2-console...\").permitAll() found in "
                                            + relativePath
                                            + ".")
                            .source(relativePath, line)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_COMMAND_INJECTION
    // ---------------------------------------------------------------------------

    private void detectCommandInjection(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"exec".equals(call.getNameAsString())) {
                continue;
            }
            boolean scopeRefersRuntime =
                    call.getScope()
                            .map(Object::toString)
                            .map(t -> t.contains("getRuntime") || t.contains("Runtime"))
                            .orElse(false);
            if (!scopeRefersRuntime) {
                continue;
            }
            if (call.getArguments().stream()
                    .anyMatch(SecurityPracticeFindingAnalyzer::isDynamicConcat)) {
                addCommandInjection(relativePath, lineOf(call), "Runtime.exec(...)", findings);
            }
        }
        for (ObjectCreationExpr creation : cu.findAll(ObjectCreationExpr.class)) {
            if (!"ProcessBuilder".equals(simpleName(creation.getType().getNameAsString()))) {
                continue;
            }
            if (creation.getArguments().stream()
                    .anyMatch(SecurityPracticeFindingAnalyzer::isDynamicConcat)) {
                addCommandInjection(
                        relativePath, lineOf(creation), "new ProcessBuilder(...)", findings);
            }
        }
    }

    private void addCommandInjection(
            String relativePath, Integer line, String shape, List<Finding> findings) {
        add(
                findings,
                FindingRules.SPRING_COMMAND_INJECTION,
                FindingConfidence.MEDIUM,
                relativePath,
                line,
                shape + " builds the command with string concatenation in " + relativePath + ".",
                "Concatenating non-literal data into an OS command lets an attacker who influences"
                    + " that data inject additional commands or arguments. When the command runs"
                    + " through a shell, metacharacters (;, |, &&, $()) execute arbitrary"
                    + " programs.",
                "If the concatenated value is reachable from user input, an attacker can execute"
                        + " arbitrary commands on the host with the application's privileges.",
                "Avoid the shell: pass the program and each argument as separate elements to"
                        + " ProcessBuilder (no shell interpolation), validate against a strict"
                        + " allowlist, and never concatenate user input into the command string.",
                "Medium confidence — flags concatenation into exec/ProcessBuilder; whether the"
                        + " value is attacker-controlled requires manual review.",
                shape + " with concatenated argument found in " + relativePath + ".");
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SPEL_INJECTION
    // ---------------------------------------------------------------------------

    private void detectSpelInjection(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"parseExpression".equals(call.getNameAsString())) {
                continue;
            }
            if (call.getArguments().stream()
                    .anyMatch(SecurityPracticeFindingAnalyzer::isDynamicConcat)) {
                add(
                        findings,
                        FindingRules.SPRING_SPEL_INJECTION,
                        FindingConfidence.MEDIUM,
                        relativePath,
                        lineOf(call),
                        "parseExpression(...) is called on a concatenated SpEL string in "
                                + relativePath
                                + ".",
                        "Spring Expression Language can call arbitrary methods, constructors, and"
                                + " static utilities (e.g. T(java.lang.Runtime)). Parsing and"
                                + " evaluating an expression assembled from non-literal data turns"
                                + " that data into executable code.",
                        "If the concatenated value is attacker-influenced, the attacker achieves"
                                + " remote code execution.",
                        "Never build SpEL from untrusted input. Use a fixed expression with a"
                                + " controlled EvaluationContext, or use SimpleEvaluationContext to"
                                + " restrict the expression to data binding only.",
                        "Medium confidence — flags concatenation into parseExpression; confirm"
                                + " whether the value is attacker-controlled.",
                        "parseExpression(...) with concatenated argument found in "
                                + relativePath
                                + ".");
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_PATH_TRAVERSAL
    // ---------------------------------------------------------------------------

    private static final Set<String> PATH_CONSTRUCTOR_TYPES =
            Set.of(
                    "File",
                    "FileInputStream",
                    "FileOutputStream",
                    "FileReader",
                    "FileWriter",
                    "RandomAccessFile");

    private void detectPathTraversal(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ObjectCreationExpr creation : cu.findAll(ObjectCreationExpr.class)) {
            if (!PATH_CONSTRUCTOR_TYPES.contains(
                    simpleName(creation.getType().getNameAsString()))) {
                continue;
            }
            if (creation.getArguments().stream()
                    .anyMatch(SecurityPracticeFindingAnalyzer::isDynamicConcat)) {
                addPathTraversal(
                        relativePath,
                        lineOf(creation),
                        "new " + simpleName(creation.getType().getNameAsString()) + "(...)",
                        findings);
            }
        }
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            String name = call.getNameAsString();
            String scope = call.getScope().map(s -> simpleName(s.toString())).orElse("");
            boolean isPathsGet = "get".equals(name) && "Paths".equals(scope);
            boolean isPathOf = "of".equals(name) && "Path".equals(scope);
            if (!isPathsGet && !isPathOf) {
                continue;
            }
            if (call.getArguments().stream()
                    .anyMatch(SecurityPracticeFindingAnalyzer::isDynamicConcat)) {
                addPathTraversal(
                        relativePath, lineOf(call), scope + "." + name + "(...)", findings);
            }
        }
    }

    private void addPathTraversal(
            String relativePath, Integer line, String shape, List<Finding> findings) {
        add(
                findings,
                FindingRules.SPRING_PATH_TRAVERSAL,
                FindingConfidence.MEDIUM,
                relativePath,
                line,
                shape + " builds a file path with string concatenation in " + relativePath + ".",
                "A file path assembled by concatenation can contain traversal sequences (../../)"
                    + " supplied by the caller, escaping the intended base directory and reaching"
                    + " arbitrary files on disk.",
                "If the concatenated value is attacker-influenced, an attacker can read sensitive"
                        + " files (configuration, keys) or overwrite files outside the intended"
                        + " directory.",
                "Resolve the path against a fixed base directory, call"
                    + " toRealPath()/getCanonicalPath(), and verify the result still starts with"
                    + " the base directory before using it. Reject inputs containing path"
                    + " separators or '..'.",
                "Medium confidence — flags concatenation into a file path; confirm whether the"
                        + " value is attacker-controlled.",
                shape + " with concatenated argument found in " + relativePath + ".");
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_SSRF_USER_URL
    // ---------------------------------------------------------------------------

    private static final Set<String> REST_TEMPLATE_URL_METHODS =
            Set.of("getForObject", "getForEntity", "postForObject", "postForEntity");

    private void detectSsrfUserUrl(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ObjectCreationExpr creation : cu.findAll(ObjectCreationExpr.class)) {
            if (!"URL".equals(simpleName(creation.getType().getNameAsString()))) {
                continue;
            }
            if (creation.getArguments().stream()
                    .anyMatch(SecurityPracticeFindingAnalyzer::isDynamicConcat)) {
                addSsrf(relativePath, lineOf(creation), "new URL(...)", findings);
            }
        }
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            String name = call.getNameAsString();
            String scope = call.getScope().map(s -> simpleName(s.toString())).orElse("");
            boolean isUriCreate = "create".equals(name) && "URI".equals(scope);
            boolean isRestTemplate = REST_TEMPLATE_URL_METHODS.contains(name);
            boolean isWebClientUri = "uri".equals(name);
            if (!isUriCreate && !isRestTemplate && !isWebClientUri) {
                continue;
            }
            boolean firstArgConcat =
                    !call.getArguments().isEmpty() && isDynamicConcat(call.getArgument(0));
            if (firstArgConcat) {
                addSsrf(relativePath, lineOf(call), name + "(...)", findings);
            }
        }
    }

    private void addSsrf(String relativePath, Integer line, String shape, List<Finding> findings) {
        add(
                findings,
                FindingRules.SPRING_SSRF_USER_URL,
                FindingConfidence.MEDIUM,
                relativePath,
                line,
                shape
                        + " builds an outbound request URL with string concatenation in "
                        + relativePath
                        + ".",
                "When the host/path of an outbound request is concatenated from non-literal data,"
                    + " an attacker who influences it can point the request at internal hosts the"
                    + " server can reach but the attacker cannot — cloud metadata endpoints,"
                    + " internal admin APIs, or localhost services.",
                "If the concatenated value is attacker-influenced, the attacker can read internal"
                        + " resources or pivot into the internal network (SSRF).",
                "Validate the target against a strict allowlist of permitted hosts/schemes before"
                    + " making the call; do not let user input control the host or scheme. Block"
                    + " requests to private/loopback/link-local address ranges.",
                "Medium confidence — flags concatenation into an outbound URL; confirm whether the"
                        + " value is attacker-controlled.",
                shape + " with concatenated argument found in " + relativePath + ".");
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_OPEN_REDIRECT
    // ---------------------------------------------------------------------------

    private void detectOpenRedirect(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ReturnStmt ret : cu.findAll(ReturnStmt.class)) {
            Expression expr = ret.getExpression().orElse(null);
            if (expr == null || !isDynamicConcat(expr)) {
                continue;
            }
            boolean redirectPrefix =
                    expr.findAll(StringLiteralExpr.class).stream()
                            .anyMatch(s -> s.asString().startsWith("redirect:"));
            if (redirectPrefix) {
                addOpenRedirect(relativePath, lineOf(ret), "\"redirect:\" + value", findings);
            }
        }
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"sendRedirect".equals(call.getNameAsString())) {
                continue;
            }
            if (call.getArguments().stream()
                    .anyMatch(SecurityPracticeFindingAnalyzer::isDynamicConcat)) {
                addOpenRedirect(relativePath, lineOf(call), "sendRedirect(...)", findings);
            }
        }
    }

    private void addOpenRedirect(
            String relativePath, Integer line, String shape, List<Finding> findings) {
        add(
                findings,
                FindingRules.SPRING_OPEN_REDIRECT,
                FindingConfidence.MEDIUM,
                relativePath,
                line,
                shape + " builds a redirect target with concatenation in " + relativePath + ".",
                "A redirect destination assembled from non-literal data lets an attacker craft a"
                    + " link to the trusted application that bounces the victim to an"
                    + " attacker-controlled site, which is convincing for phishing and can steal"
                    + " OAuth tokens passed in the URL.",
                "If the concatenated value is attacker-influenced, the application becomes an"
                        + " open redirector usable in phishing and token-theft attacks.",
                "Redirect only to a fixed allowlist of paths, or map an opaque key to a known"
                    + " destination server-side. If an absolute URL is unavoidable, validate the"
                    + " host against an allowlist.",
                "Medium confidence — flags concatenation into a redirect target; confirm whether"
                        + " the value is attacker-controlled.",
                shape + " with concatenated argument found in " + relativePath + ".");
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_COOKIE_MISSING_HTTPONLY
    // ---------------------------------------------------------------------------

    private void detectCookieMissingHttpOnly(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        // Import gate: only servlet cookies are relevant; a domain class named Cookie is not.
        boolean servletCookieImported =
                cu.getImports().stream()
                        .map(imp -> imp.getNameAsString())
                        .anyMatch(
                                name ->
                                        name.equals("jakarta.servlet.http.Cookie")
                                                || name.equals("javax.servlet.http.Cookie")
                                                // Wildcard imports: JavaParser reports the name
                                                // without the trailing ".*".
                                                || name.equals("jakarta.servlet.http")
                                                || name.equals("javax.servlet.http"));
        if (!servletCookieImported) {
            return;
        }
        // Only flag cookies that are actually sent to the client.
        boolean addCookieCalled =
                cu.findAll(MethodCallExpr.class).stream()
                        .anyMatch(call -> "addCookie".equals(call.getNameAsString()));
        if (!addCookieCalled) {
            return;
        }
        // File-level flag search absorbs helper-method patterns (cookie built in one method,
        // hardened in another).
        boolean httpOnlySet =
                cu.findAll(MethodCallExpr.class).stream()
                        .anyMatch(
                                call ->
                                        "setHttpOnly".equals(call.getNameAsString())
                                                && call.getArguments().size() == 1
                                                && "true".equals(call.getArgument(0).toString()));
        if (httpOnlySet) {
            return;
        }
        ObjectCreationExpr creation =
                cu.findAll(ObjectCreationExpr.class).stream()
                        .filter(c -> "Cookie".equals(simpleName(c.getType().getNameAsString())))
                        .findFirst()
                        .orElse(null);
        if (creation == null) {
            return;
        }
        add(
                findings,
                FindingRules.SPRING_COOKIE_MISSING_HTTPONLY,
                FindingConfidence.MEDIUM,
                relativePath,
                lineOf(creation),
                "A servlet Cookie is added to the response in "
                        + relativePath
                        + " without setHttpOnly(true).",
                "jakarta.servlet.http.Cookie defaults to httpOnly=false and secure=false. Without"
                        + " setHttpOnly(true) the cookie is readable from JavaScript, so any XSS"
                        + " vulnerability can exfiltrate it; without setSecure(true) it is also"
                        + " sent over plain HTTP.",
                "If the cookie carries a session id, token, or other credential, an XSS flaw"
                        + " escalates to full session hijacking. Cookies sent over HTTP can be"
                        + " intercepted in transit.",
                "Call setHttpOnly(true) and setSecure(true) on the cookie before addCookie(...)"
                        + " (or build it via ResponseCookie.from(...).httpOnly(true).secure(true))."
                        + " Only omit HttpOnly for cookies that client-side script genuinely must"
                        + " read.",
                "Medium confidence — legitimately JavaScript-readable cookies (locale, theme,"
                        + " consent) exist; review what the cookie carries. The flag may also be"
                        + " set in another class not visible to this per-file check.",
                "new Cookie(...) and response.addCookie(...) found in "
                        + relativePath
                        + " with no setHttpOnly(true) call anywhere in the file.");
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_ZIP_SLIP
    // ---------------------------------------------------------------------------

    /** Chained form: {@code dir.resolve(name).normalize().startsWith(dir)}. */
    private static final java.util.regex.Pattern CHAINED_NORMALIZED_CONTAINMENT =
            java.util.regex.Pattern.compile("normalize\\(\\)\\s*\\.\\s*startsWith\\(");

    /**
     * Assignment form: {@code Path out = ....normalize();} — captures the variable name. The
     * gap excludes {@code =} as well as {@code ;} so an earlier assignment in an enclosing
     * statement (e.g. {@code while ((entry = zip.getNextEntry()) != null)}) cannot be matched
     * greedily and yield the wrong variable.
     */
    private static final java.util.regex.Pattern NORMALIZED_ASSIGNMENT =
            java.util.regex.Pattern.compile("(\\w+)\\s*=\\s*[^;=]*\\bnormalize\\(\\)\\s*;");

    /**
     * Returns {@code true} when the method body contains a genuine normalize()-then-startsWith
     * containment check: either chained on one expression, or a variable assigned from
     * {@code normalize()} that is later the receiver of {@code startsWith(...)}. Independent
     * occurrences of the two markers (e.g. a cosmetic {@code normalize()} plus an unrelated entry
     * prefix filter) do not count as validation.
     */
    private static boolean hasNormalizedContainmentCheck(String body) {
        if (CHAINED_NORMALIZED_CONTAINMENT.matcher(body).find()) {
            return true;
        }
        var matcher = NORMALIZED_ASSIGNMENT.matcher(body);
        while (matcher.find()) {
            String variable = matcher.group(1);
            java.util.regex.Pattern exactReceiver =
                    java.util.regex.Pattern.compile(
                            "(?<![\\w.])"
                                    + java.util.regex.Pattern.quote(variable)
                                    + "\\s*\\.\\s*startsWith\\(");
            if (exactReceiver.matcher(body).find()) {
                return true;
            }
        }
        return false;
    }

    /** Identifier fragments suggesting the {@code getName()} receiver is an archive entry. */
    private static final java.util.regex.Pattern ARCHIVE_ENTRY_GET_NAME =
            java.util.regex.Pattern.compile("(?i)\\b\\w*entry\\w*\\s*\\.\\s*getName\\(\\)");

    private static boolean isArchiveEntryName(String argumentText) {
        return ARCHIVE_ENTRY_GET_NAME.matcher(argumentText).find();
    }

    private void detectZipSlip(CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
            if (method.getBody().isEmpty()) {
                continue;
            }
            String body = method.getBody().get().toString();
            // Scope gate: only extraction code that iterates archive entries.
            boolean archiveScope =
                    body.contains("ZipEntry")
                            || body.contains("getNextEntry")
                            || body.contains("ZipFile")
                            || body.contains("ArchiveEntry")
                            || body.contains("JarEntry")
                            || body.contains("JarFile")
                            || body.contains("getNextJarEntry");
            if (!archiveScope) {
                continue;
            }
            // Suppress when the method shows containment-validation markers. normalize()+
            // startsWith must appear on the same statement to count — an unrelated
            // entry-name prefix filter elsewhere in the body must not mask a real defect.
            if (body.contains("getCanonicalPath")
                    || body.contains("toRealPath")
                    || body.contains("contains(\"..\")")
                    || hasNormalizedContainmentCheck(body)) {
                continue;
            }
            // The argument must be an ARCHIVE ENTRY's getName(); java.io.File#getName() returns
            // only the last path segment and cannot carry traversal sequences.
            com.github.javaparser.ast.Node riskySite = null;
            for (ObjectCreationExpr creation :
                    method.getBody().get().findAll(ObjectCreationExpr.class)) {
                if ("File".equals(simpleName(creation.getType().getNameAsString()))
                        && creation.getArguments().size() >= 2
                        && creation.getArguments().stream()
                                .anyMatch(arg -> isArchiveEntryName(arg.toString()))) {
                    riskySite = creation;
                    break;
                }
            }
            if (riskySite == null) {
                for (MethodCallExpr call : method.getBody().get().findAll(MethodCallExpr.class)) {
                    if ("resolve".equals(call.getNameAsString())
                            && call.getArguments().stream()
                                    .anyMatch(arg -> isArchiveEntryName(arg.toString()))) {
                        riskySite = call;
                        break;
                    }
                }
            }
            if (riskySite == null) {
                continue;
            }
            Integer line = riskySite.getBegin().map(p -> p.line).orElse(null);
            add(
                    findings,
                    FindingRules.SPRING_ZIP_SLIP,
                    FindingConfidence.MEDIUM,
                    relativePath,
                    line,
                    "Archive entry name flows into a file path without validation in "
                            + relativePath
                            + " (Zip Slip).",
                    "ZipEntry.getName() is attacker-controlled when the archive comes from"
                            + " outside. Entry names may contain ../ sequences, so resolving them"
                            + " against the extraction directory (new File(dir, name) /"
                            + " dir.resolve(name)) writes files outside the intended target"
                            + " directory.",
                    "A malicious archive can overwrite arbitrary files writable by the process"
                            + " (cron jobs, JARs, SSH keys) during extraction — the well-known Zip"
                            + " Slip vulnerability (CWE-22). Extraction of benign archives works"
                            + " fine, so the flaw stays invisible in testing.",
                    "Resolve the entry name against the target directory, normalize the result,"
                            + " and verify it still starts with the target directory's canonical"
                            + " path before writing (e.g. Path dest ="
                            + " destDir.resolve(name).normalize(); if"
                            + " (!dest.startsWith(destDir)) throw ...).",
                    "Medium confidence — flagged only inside methods that reference archive types"
                            + " and show no containment-validation markers"
                            + " (getCanonicalPath/toRealPath/normalize+startsWith).",
                    "Archive-entry getName() used in a File/resolve path expression in "
                            + relativePath
                            + " without visible path-containment validation.");
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_INSECURE_RANDOM_FOR_SECURITY
    // ---------------------------------------------------------------------------

    private static final Set<String> SECURITY_VALUE_KEYWORDS =
            Set.of(
                    "token",
                    "password",
                    "passwd",
                    "secret",
                    "salt",
                    "nonce",
                    "otp",
                    "sessionid",
                    "apikey",
                    "credential",
                    "csrf");

    private void detectInsecureRandomForSecurity(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ObjectCreationExpr creation : cu.findAll(ObjectCreationExpr.class)) {
            if (!"Random".equals(simpleName(creation.getType().getNameAsString()))) {
                continue;
            }
            if (inSecuritySensitiveContext(creation)) {
                addInsecureRandom(relativePath, lineOf(creation), "new Random()", findings);
            }
        }
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            boolean isMathRandom =
                    "random".equals(call.getNameAsString())
                            && call.getScope()
                                    .map(s -> simpleName(s.toString()))
                                    .map("Math"::equals)
                                    .orElse(false);
            if (isMathRandom && inSecuritySensitiveContext(call)) {
                addInsecureRandom(relativePath, lineOf(call), "Math.random()", findings);
            }
        }
    }

    private static boolean inSecuritySensitiveContext(com.github.javaparser.ast.Node node) {
        StringBuilder context = new StringBuilder();
        node.findAncestor(MethodDeclaration.class)
                .ifPresent(m -> context.append(m.getNameAsString()).append(' '));
        node.findAncestor(ClassOrInterfaceDeclaration.class)
                .ifPresent(c -> context.append(c.getNameAsString()));
        String haystack = context.toString().toLowerCase(java.util.Locale.ROOT);
        return SECURITY_VALUE_KEYWORDS.stream().anyMatch(haystack::contains);
    }

    private void addInsecureRandom(
            String relativePath, Integer line, String shape, List<Finding> findings) {
        add(
                findings,
                FindingRules.SPRING_INSECURE_RANDOM_FOR_SECURITY,
                FindingConfidence.MEDIUM,
                relativePath,
                line,
                shape
                        + " is used in a security-sensitive context in "
                        + relativePath
                        + " — use SecureRandom.",
                "java.util.Random (and Math.random()) is a linear congruential generator. Its"
                        + " 48-bit seed and predictable sequence let an attacker who observes a few"
                        + " outputs reconstruct the internal state and predict all future values.",
                "Predictable tokens, password-reset codes, session identifiers, or salts can be"
                        + " guessed by an attacker, enabling account takeover.",
                "Generate security-sensitive values with java.security.SecureRandom (or"
                    + " RandomStringUtils backed by SecureRandom). Never use java.util.Random or"
                    + " Math.random() for anything an attacker should not be able to predict.",
                "Medium confidence — flagged because the enclosing method/class name suggests a"
                        + " security value; review the actual use of the random output.",
                shape + " found in a security-named context in " + relativePath + ".");
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_WEAK_CIPHER_ALGORITHM
    // ---------------------------------------------------------------------------

    private static final Set<String> WEAK_CIPHER_PREFIXES =
            Set.of("DES", "DESEDE", "RC2", "RC4", "ARCFOUR", "BLOWFISH");

    private static final Set<String> KEY_FACTORY_SCOPES =
            Set.of("KeyGenerator", "SecretKeyFactory", "KeyPairGenerator");

    private void detectWeakCipherAlgorithm(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"getInstance".equals(call.getNameAsString())) {
                continue;
            }
            String scope = call.getScope().map(s -> simpleName(s.toString())).orElse("");
            boolean isCipher = "Cipher".equals(scope);
            boolean isKeyFactory = KEY_FACTORY_SCOPES.contains(scope);
            if (!isCipher && !isKeyFactory) {
                continue;
            }
            String algo =
                    call.getArguments().stream()
                            .filter(a -> a instanceof StringLiteralExpr)
                            .map(a -> ((StringLiteralExpr) a).asString())
                            .findFirst()
                            .orElse(null);
            if (algo == null) {
                continue;
            }
            String upper = algo.toUpperCase(java.util.Locale.ROOT);
            String base = upper.contains("/") ? upper.substring(0, upper.indexOf('/')) : upper;
            boolean weakLegacy = WEAK_CIPHER_PREFIXES.contains(base);
            boolean ecbMode = isCipher && upper.contains("/ECB/");
            boolean bareEcbDefault = isCipher && ("AES".equals(upper) || "DES".equals(upper));
            if (!weakLegacy && !ecbMode && !bareEcbDefault) {
                continue;
            }
            String reason =
                    weakLegacy
                            ? base + " is cryptographically broken"
                            : ecbMode
                                    ? "ECB mode leaks plaintext structure"
                                    : "the bare \""
                                            + algo
                                            + "\" transformation defaults to ECB mode";
            add(
                    findings,
                    FindingRules.SPRING_WEAK_CIPHER_ALGORITHM,
                    FindingConfidence.HIGH,
                    relativePath,
                    lineOf(call),
                    scope
                            + ".getInstance(\""
                            + algo
                            + "\") in "
                            + relativePath
                            + " — "
                            + reason
                            + ".",
                    "Legacy ciphers (DES, 3DES, RC2, RC4, Blowfish) have small key sizes or known"
                            + " attacks. ECB mode encrypts identical plaintext blocks to identical"
                            + " ciphertext blocks, revealing patterns; the bare \"AES\"/\"DES\""
                            + " transformation silently selects ECB.",
                    "Encrypted data can be decrypted or have its structure inferred, defeating the"
                            + " confidentiality the encryption was meant to provide.",
                    "Use AES in an authenticated mode — \"AES/GCM/NoPadding\" — with a random IV"
                            + " per message and a key from a KDF or a managed key store. Avoid DES,"
                            + " 3DES, RC4, and ECB entirely.",
                    "High confidence — the algorithm/mode is read directly from the string"
                            + " literal.",
                    scope + ".getInstance(\"" + algo + "\") found in " + relativePath + ".");
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_HARDCODED_ENCRYPTION_KEY
    // ---------------------------------------------------------------------------

    private static final Set<String> KEY_SPEC_TYPES = Set.of("SecretKeySpec", "IvParameterSpec");

    private void detectHardcodedEncryptionKey(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ObjectCreationExpr creation : cu.findAll(ObjectCreationExpr.class)) {
            String type = simpleName(creation.getType().getNameAsString());
            if (!KEY_SPEC_TYPES.contains(type) || creation.getArguments().isEmpty()) {
                continue;
            }
            Expression firstArg = creation.getArgument(0);
            boolean literalGetBytes =
                    firstArg instanceof MethodCallExpr mce
                            && "getBytes".equals(mce.getNameAsString())
                            && mce.getScope()
                                    .filter(s -> s instanceof StringLiteralExpr)
                                    .isPresent();
            boolean inlineByteArray =
                    firstArg instanceof ArrayCreationExpr ace && ace.getInitializer().isPresent()
                            || firstArg instanceof ArrayInitializerExpr;
            if (!literalGetBytes && !inlineByteArray) {
                continue;
            }
            add(
                    findings,
                    FindingRules.SPRING_HARDCODED_ENCRYPTION_KEY,
                    literalGetBytes ? FindingConfidence.HIGH : FindingConfidence.MEDIUM,
                    relativePath,
                    lineOf(creation),
                    "new "
                            + type
                            + "(...) is built from a hardcoded value in "
                            + relativePath
                            + ".",
                    "A cryptographic key or IV embedded in source code is visible to anyone with"
                        + " the JAR or the repository, is identical across every deployment, and"
                        + " cannot be rotated without rebuilding and redeploying the application.",
                    "An attacker who obtains the artifact can decrypt all data protected with the"
                            + " key, and a leaked key cannot be revoked quickly.",
                    "Load keys from a secret manager or the environment at runtime (e.g. Vault,"
                            + " AWS KMS, a JCEKS/PKCS12 keystore). Generate a fresh random IV per"
                            + " message rather than hardcoding one.",
                    literalGetBytes
                            ? "High confidence — key/IV material is a string literal."
                            : "Medium confidence — key/IV material is an inline byte-array"
                                    + " literal.",
                    "new " + type + "(...) with hardcoded material found in " + relativePath + ".");
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_LOGGING_AUTH_HEADER
    // ---------------------------------------------------------------------------

    private static final Set<String> LOGGING_METHODS =
            Set.of("trace", "debug", "info", "warn", "error");

    private static final Set<String> AUTH_NAME_HINTS =
            Set.of("authorizationheader", "authheader", "bearertoken", "jwttoken", "accesstoken");

    private void detectLoggingAuthHeader(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!LOGGING_METHODS.contains(call.getNameAsString()) || call.getScope().isEmpty()) {
                continue;
            }
            if (!referencesAuthorization(call)) {
                continue;
            }
            add(
                    findings,
                    FindingRules.SPRING_LOGGING_AUTH_HEADER,
                    FindingConfidence.MEDIUM,
                    relativePath,
                    lineOf(call),
                    "A logging call may write the Authorization header or a bearer token to logs in"
                            + " "
                            + relativePath
                            + ".",
                    "The Authorization header carries credentials — Basic auth secrets or"
                            + " bearer/JWT tokens. Logging frameworks persist messages to files and"
                            + " forward them to centralized aggregation and SIEM systems that are"
                            + " usually less tightly access-controlled than the credential store.",
                    "Anyone with read access to the logs can replay the captured token or"
                        + " credential and impersonate the user until it expires or is revoked.",
                    "Never log the Authorization header or token. If you must record that a request"
                        + " was authenticated, log a non-reversible identifier (user id, token id)"
                        + " or a redacted placeholder. Add a masking converter to the logging"
                        + " configuration as defense in depth.",
                    "Medium confidence — flagged because the logging call references an"
                            + " Authorization header or a token-named value; confirm the value is"
                            + " actually emitted.",
                    "Logging call referencing an Authorization header/token found in "
                            + relativePath
                            + ".");
            return; // One finding per file is sufficient.
        }
    }

    private static boolean referencesAuthorization(MethodCallExpr call) {
        boolean headerLookup =
                call.findAll(MethodCallExpr.class).stream()
                        .anyMatch(
                                m ->
                                        ("getHeader".equals(m.getNameAsString())
                                                        || "getHeaders".equals(m.getNameAsString())
                                                        || "getFirst".equals(m.getNameAsString()))
                                                && m.getArguments().stream()
                                                        .filter(a -> a instanceof StringLiteralExpr)
                                                        .map(
                                                                a ->
                                                                        ((StringLiteralExpr) a)
                                                                                .asString())
                                                        .anyMatch(
                                                                s ->
                                                                        s.equalsIgnoreCase(
                                                                                "authorization")));
        boolean stringLiteralHint =
                call.findAll(StringLiteralExpr.class).stream()
                        .map(s -> s.asString().toLowerCase(java.util.Locale.ROOT))
                        .anyMatch(s -> s.contains("authorization") || s.startsWith("bearer "));
        boolean nameHint =
                call.findAll(NameExpr.class).stream()
                        .map(n -> n.getNameAsString().toLowerCase(java.util.Locale.ROOT))
                        .anyMatch(AUTH_NAME_HINTS::contains);
        return headerLookup || stringLiteralHint || nameHint;
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_BCRYPT_LOW_STRENGTH
    // ---------------------------------------------------------------------------

    private void detectBcryptLowStrength(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ObjectCreationExpr creation : cu.findAll(ObjectCreationExpr.class)) {
            if (!"BCryptPasswordEncoder".equals(simpleName(creation.getType().getNameAsString()))) {
                continue;
            }
            Integer strength =
                    creation.getArguments().stream()
                            .filter(a -> a instanceof IntegerLiteralExpr)
                            .map(a -> safeInt(((IntegerLiteralExpr) a).getValue()))
                            .filter(v -> v != null)
                            .findFirst()
                            .orElse(null);
            if (strength == null || strength >= 10) {
                continue;
            }
            add(
                    findings,
                    FindingRules.SPRING_BCRYPT_LOW_STRENGTH,
                    FindingConfidence.HIGH,
                    relativePath,
                    lineOf(creation),
                    "new BCryptPasswordEncoder("
                            + strength
                            + ") in "
                            + relativePath
                            + " uses a work factor below the default of 10.",
                    "BCrypt's strength parameter is the base-2 logarithm of the number of hashing"
                        + " rounds, so each step doubles the work an attacker must do. The Spring"
                        + " Security default is 10. A value of "
                            + strength
                            + " makes hashing — and therefore offline brute-forcing of a leaked"
                            + " hash — dramatically cheaper.",
                    "If the password hashes are leaked, a low work factor lets an attacker crack"
                            + " them far faster than intended.",
                    "Remove the explicit strength to use the default of 10, or pass a value of"
                        + " 10–12 (tuned so a single hash takes roughly 100–250 ms on production"
                        + " hardware). Re-encode existing passwords on next login when raising the"
                        + " factor.",
                    "High confidence — the strength is read directly from the integer literal.",
                    "new BCryptPasswordEncoder(" + strength + ") found in " + relativePath + ".");
        }
    }

    private static Integer safeInt(String value) {
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /**
     * Returns true when {@code e} is a string concatenation ({@code a + b}) that mixes at least
     * one fixed string literal with at least one non-literal operand (a variable, field access,
     * or method call). This is the canonical "building a command/path/URL string from input"
     * shape; pure-literal and pure-numeric expressions are intentionally excluded.
     */
    private static boolean isDynamicConcat(Expression e) {
        if (!(e instanceof BinaryExpr be) || be.getOperator() != BinaryExpr.Operator.PLUS) {
            return false;
        }
        boolean hasStringLiteral = !e.findAll(StringLiteralExpr.class).isEmpty();
        boolean hasDynamicLeaf =
                !e.findAll(NameExpr.class).isEmpty()
                        || !e.findAll(FieldAccessExpr.class).isEmpty()
                        || !e.findAll(MethodCallExpr.class).isEmpty();
        return hasStringLiteral && hasDynamicLeaf;
    }

    private static Integer lineOf(com.github.javaparser.ast.Node node) {
        return node.getBegin().map(p -> p.line).orElse(null);
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
            String evidence) {
        findings.add(
                FindingFactory.builder(rule, confidence)
                        .shortMessage(shortMessage)
                        .whyBadPractice(whyBadPractice)
                        .possibleImpact(possibleImpact)
                        .recommendation(recommendation)
                        .limitations(limitations)
                        .evidence(evidence)
                        .source(relativePath, line)
                        .build());
    }

    private static String simpleName(String name) {
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : name;
    }
}

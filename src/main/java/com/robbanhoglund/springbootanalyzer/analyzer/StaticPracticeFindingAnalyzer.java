package com.robbanhoglund.springbootanalyzer.analyzer;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.ClassExpr;
import com.github.javaparser.ast.expr.DoubleLiteralExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.LiteralStringValueExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NullLiteralExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.ThisExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.BreakStmt;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.ContinueStmt;
import com.github.javaparser.ast.stmt.EmptyStmt;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.ast.stmt.TryStmt;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.type.UnionType;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildInfo;
import com.robbanhoglund.springbootanalyzer.analyzer.model.DetectedClass;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingOccurrence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingSeverity;
import com.robbanhoglund.springbootanalyzer.analyzer.model.HighlightRange;
import com.robbanhoglund.springbootanalyzer.analyzer.model.SourceLocation;
import com.robbanhoglund.springbootanalyzer.analyzer.model.SpringComponentType;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.ConfigurationAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.gradle.GradleModelAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.HttpSurfaceAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.OutboundEndpoint;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.RuntimeStackAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

@Component
public class StaticPracticeFindingAnalyzer {

    private static final Set<String> SENSITIVE_MARKERS =
            Set.of(
                    "password",
                    "passwd",
                    "secret",
                    "client-secret",
                    "api-key",
                    "apikey",
                    "access-key",
                    "private-key",
                    "credential",
                    "credentials",
                    "authorization",
                    "api-token",
                    "access-token",
                    "refresh-token",
                    "bearer-token",
                    "auth-token",
                    "oauth-token",
                    "github-token",
                    "signing-key",
                    "pat",
                    "jwt-secret");
    private static final Set<String> HTTP_WRITE_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");
    private static final Set<String> WRITE_CALL_MARKERS =
            Set.of(
                    "save",
                    "saveAll",
                    "delete",
                    "deleteAll",
                    "update",
                    "insert",
                    "batchUpdate",
                    "execute",
                    "persist",
                    "merge",
                    "flush");
    private static final Set<String> PROXY_ANNOTATIONS =
            Set.of(
                    "Transactional",
                    "Cacheable",
                    "CacheEvict",
                    "CachePut",
                    "Caching",
                    "Async",
                    "PreAuthorize",
                    "PostAuthorize",
                    "Secured",
                    "RolesAllowed",
                    "Observed");
    private static final Set<String> KNOWN_RUNTIME_EXCEPTIONS =
            Set.of(
                    "RuntimeException",
                    "IllegalArgumentException",
                    "IllegalStateException",
                    "NullPointerException",
                    "UnsupportedOperationException",
                    "IndexOutOfBoundsException",
                    "ArrayIndexOutOfBoundsException",
                    "ClassCastException",
                    "ArithmeticException",
                    "NumberFormatException",
                    "ConcurrentModificationException",
                    "NoSuchElementException",
                    "DataAccessException",
                    "AuthenticationException",
                    "AccessDeniedException");
    private static final Set<String> KNOWN_CHECKED_EXCEPTIONS =
            Set.of(
                    "Exception",
                    "IOException",
                    "SQLException",
                    "ParseException",
                    "ReflectiveOperationException",
                    "ClassNotFoundException",
                    "InterruptedException",
                    "ExecutionException",
                    "TimeoutException",
                    "ServletException",
                    "GeneralSecurityException",
                    "NamingException");
    private static final Set<String> PERSISTENCE_INFRASTRUCTURE_TYPES =
            Set.of(
                    "EntityManager",
                    "Session",
                    "JdbcTemplate",
                    "NamedParameterJdbcTemplate",
                    "JdbcClient",
                    "SimpleJdbcInsert");
    private static final Set<String> IGNORE_VARIABLE_NAMES =
            Set.of("ignored", "ignore", "expected", "intentionallyignored");
    private static final Set<String> BENIGN_IGNORE_COMMENT_MARKERS =
            Set.of(
                    "best effort cleanup",
                    "ignore close failure",
                    "already closed",
                    "not relevant in test",
                    "safe to ignore",
                    "cleanup only",
                    "best effort",
                    "close failure");
    private static final Set<String> MESSAGING_LISTENER_ANNOTATIONS =
            Set.of("KafkaListener", "RabbitListener", "JmsListener", "SqsListener");
    private static final Set<String> SENSITIVE_PARAM_NAMES =
            Set.of(
                    "password",
                    "passwd",
                    "secret",
                    "token",
                    "apikey",
                    "api_key",
                    "api-key",
                    "credential",
                    "credentials",
                    "authorization",
                    "private_key",
                    "private-key",
                    "access_token",
                    "access-token",
                    "refresh_token",
                    "refresh-token",
                    "client_secret",
                    "client-secret",
                    "jwt",
                    "jwt_secret",
                    "jwt-secret");

    private static boolean hasTopLevelPlaceholderWithoutDefault(String expr) {
        int i = 0;
        while (i < expr.length()) {
            if (i + 1 < expr.length() && expr.charAt(i) == '$' && expr.charAt(i + 1) == '{') {
                int depth = 1;
                int j = i + 2;
                boolean hasDefault = false;
                while (j < expr.length() && depth > 0) {
                    if (j + 1 < expr.length()
                            && expr.charAt(j) == '$'
                            && expr.charAt(j + 1) == '{') {
                        depth++;
                        j += 2;
                        continue;
                    }
                    char c = expr.charAt(j);
                    if (c == '}') {
                        depth--;
                    } else if (c == ':' && depth == 1) {
                        hasDefault = true;
                    }
                    j++;
                }
                if (depth == 0 && !hasDefault) return true;
                i = j;
            } else {
                i++;
            }
        }
        return false;
    }

    public List<Finding> analyze(
            Path repositoryRoot,
            BuildInfo buildInfo,
            ConfigurationAnalysis configurationAnalysis,
            GradleModelAnalysis gradleModelAnalysis,
            RuntimeStackAnalysis runtimeStackAnalysis,
            HttpSurfaceAnalysis httpSurfaceAnalysis,
            List<DetectedClass> detectedClasses) {
        return analyze(
                JavaSources.from(repositoryRoot),
                buildInfo,
                configurationAnalysis,
                gradleModelAnalysis,
                runtimeStackAnalysis,
                httpSurfaceAnalysis,
                detectedClasses);
    }

    public List<Finding> analyze(
            JavaSources javaSources,
            BuildInfo buildInfo,
            ConfigurationAnalysis configurationAnalysis,
            GradleModelAnalysis gradleModelAnalysis,
            RuntimeStackAnalysis runtimeStackAnalysis,
            HttpSurfaceAnalysis httpSurfaceAnalysis,
            List<DetectedClass> detectedClasses) {
        List<Finding> findings = new ArrayList<>();
        // Spring Framework 6.0 (Spring Boot 3) applies transaction advice to protected and
        // package-visible methods on class-based proxies by default, so the non-public
        // @Transactional rule is only accurate for Boot 1.x/2.x (Framework 5) projects.
        String bootVersion = buildInfo == null ? null : buildInfo.springBootVersion();
        boolean legacyTransactionalVisibility =
                bootVersion != null
                        && (bootVersion.startsWith("1.") || bootVersion.startsWith("2."));
        detectSourcePractices(
                javaSources,
                httpSurfaceAnalysis,
                detectedClasses,
                legacyTransactionalVisibility,
                findings);
        detectRepeatedFallbackParsingPattern(findings);
        return dedupe(findings);
    }

    private void detectSourcePractices(
            JavaSources javaSources,
            HttpSurfaceAnalysis httpSurfaceAnalysis,
            List<DetectedClass> detectedClasses,
            boolean legacyTransactionalVisibility,
            List<Finding> findings) {
        TransactionEvidenceIndex transactionEvidence =
                transactionEvidence(javaSources, legacyTransactionalVisibility);
        Map<String, List<OutboundEndpoint>> outboundByFile =
                (httpSurfaceAnalysis == null
                                ? List.<OutboundEndpoint>of()
                                : httpSurfaceAnalysis.outboundEndpoints())
                        .stream()
                                .collect(
                                        Collectors.groupingBy(
                                                endpoint ->
                                                        endpoint.sourceFile() == null
                                                                ? ""
                                                                : endpoint.sourceFile(),
                                                LinkedHashMap::new,
                                                Collectors.toList()));
        Set<String> controllerClasses =
                detectedClasses.stream()
                        .filter(
                                item ->
                                        item.componentType() == SpringComponentType.REST_CONTROLLER
                                                || item.componentType()
                                                        == SpringComponentType.CONTROLLER)
                        .map(DetectedClass::fullyQualifiedClassName)
                        .collect(Collectors.toSet());

        for (JavaSources.JavaFile sourceFile : javaSources.primaryFiles()) {
            if (sourceFile.compilationUnit() == null) {
                continue;
            }
            parseSourcePractices(
                    sourceFile,
                    outboundByFile,
                    controllerClasses,
                    legacyTransactionalVisibility,
                    transactionEvidence,
                    findings);
        }
        detectAsyncWithoutExecutor(javaSources, findings);
        detectScheduledWithoutExecutor(javaSources, findings);
    }

    private void parseSourcePractices(
            JavaSources.JavaFile sourceFile,
            Map<String, List<OutboundEndpoint>> outboundByFile,
            Set<String> controllerClasses,
            boolean legacyTransactionalVisibility,
            TransactionEvidenceIndex transactionEvidence,
            List<Finding> findings) {
        CompilationUnit compilationUnit = sourceFile.compilationUnit();
        String relativePath = sourceFile.relativePath();
        String fileContent = sourceFile.content();
        for (ClassOrInterfaceDeclaration declaration :
                compilationUnit.findAll(ClassOrInterfaceDeclaration.class)) {
            analyzeClassSourceSignals(
                    declaration,
                    relativePath,
                    fileContent,
                    outboundByFile.getOrDefault(relativePath, List.of()),
                    controllerClasses,
                    legacyTransactionalVisibility,
                    transactionEvidence,
                    findings);
        }
    }

    private TransactionEvidenceIndex transactionEvidence(
            JavaSources javaSources, boolean legacyTransactionalVisibility) {
        List<ClassOrInterfaceDeclaration> declarations = new ArrayList<>();
        for (JavaSources.JavaFile sourceFile : javaSources.primaryFiles()) {
            if (sourceFile.compilationUnit() != null) {
                declarations.addAll(
                        sourceFile.compilationUnit().findAll(ClassOrInterfaceDeclaration.class));
            }
        }
        Map<String, Set<String>> ownersBySimpleName = new LinkedHashMap<>();
        Map<MethodKey, Integer> methodCounts = new LinkedHashMap<>();
        Set<MethodKey> participatingTransactionalMethods = new LinkedHashSet<>();
        Map<MethodKey, Set<Integer>> executedCallbackParameterIndexes = new LinkedHashMap<>();
        Set<MethodKey> activeCallbackBoundaryMethods = new LinkedHashSet<>();
        Set<MethodKey> independentCallbackBoundaryMethods = new LinkedHashSet<>();
        Set<MethodKey> activeMethods = new LinkedHashSet<>();
        for (ClassOrInterfaceDeclaration declaration : declarations) {
            String owner = qualifiedTypeName(declaration);
            ownersBySimpleName
                    .computeIfAbsent(
                            declaration.getNameAsString(), ignored -> new LinkedHashSet<>())
                    .add(owner);
            for (MethodDeclaration method : declaration.getMethods()) {
                MethodKey key = methodKey(declaration, method);
                methodCounts.merge(key, 1, Integer::sum);
                Set<Integer> callbackIndexes = executedCallbackParameterIndexes(method);
                boolean executesCallback = !callbackIndexes.isEmpty();
                if (executesCallback) {
                    executedCallbackParameterIndexes.put(key, callbackIndexes);
                }
                AnnotationExpr annotation = effectiveTransactionalAnnotation(declaration, method);
                if (annotation == null
                        || !isEligibleTransactionalProxyMethod(
                                declaration, method, legacyTransactionalVisibility)
                        || !transactionalAnnotationOpensActiveBoundary(annotation)) {
                    continue;
                }
                activeMethods.add(key);
                if (canMarkSharedTransactionRollbackOnly(annotation)) {
                    participatingTransactionalMethods.add(key);
                }
                if (executesCallback) {
                    activeCallbackBoundaryMethods.add(key);
                    if ("REQUIRES_NEW".equals(transactionalPropagation(annotation))) {
                        independentCallbackBoundaryMethods.add(key);
                    }
                }
            }
        }
        Set<MethodKey> ambiguousMethods =
                methodCounts.entrySet().stream()
                        .filter(entry -> entry.getValue() > 1)
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<MethodKey> transactionalCalls = new LinkedHashSet<>();
        TransactionEvidenceIndex index =
                new TransactionEvidenceIndex(
                        participatingTransactionalMethods,
                        executedCallbackParameterIndexes,
                        activeCallbackBoundaryMethods,
                        independentCallbackBoundaryMethods,
                        transactionalCalls,
                        ownersBySimpleName,
                        ambiguousMethods);

        boolean changed;
        do {
            changed = false;
            for (ClassOrInterfaceDeclaration declaration : declarations) {
                for (MethodDeclaration method : declaration.getMethods()) {
                    boolean methodActive = activeMethods.contains(methodKey(declaration, method));
                    for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {
                        if (!belongsToMethod(call, method)) {
                            continue;
                        }
                        boolean insideLambda = isInsideLambda(call, method);
                        boolean insideActiveCallback =
                                isInsideActiveProgrammaticTransaction(
                                        call, method, declaration, index);
                        if ((insideLambda && !insideActiveCallback)
                                || (!methodActive && !insideActiveCallback)) {
                            continue;
                        }
                        MethodDeclaration helper =
                                resolveUniqueSameClassCall(declaration, method, call);
                        if (helper != null) {
                            changed |= activeMethods.add(methodKey(declaration, helper));
                            continue;
                        }
                        MethodKey target = resolveSourceMethodKey(call, method, declaration, index);
                        if (target != null && !index.isAmbiguous(target)) {
                            transactionalCalls.add(target);
                        }
                    }
                }
            }
        } while (changed);
        return index;
    }

    private boolean transactionalAnnotationOpensActiveBoundary(AnnotationExpr annotation) {
        return Set.of("REQUIRED", "REQUIRES_NEW", "NESTED", "MANDATORY")
                .contains(transactionalPropagation(annotation));
    }

    private boolean canMarkSharedTransactionRollbackOnly(AnnotationExpr annotation) {
        String propagation = transactionalPropagation(annotation);
        if (!Set.of("REQUIRED", "MANDATORY").contains(propagation)) {
            return false;
        }
        if (!annotation.isNormalAnnotationExpr()) {
            return true;
        }
        return annotation.asNormalAnnotationExpr().getPairs().stream()
                .noneMatch(
                        pair ->
                                Set.of("noRollbackFor", "noRollbackForClassName")
                                        .contains(pair.getNameAsString()));
    }

    private MethodKey methodKey(ClassOrInterfaceDeclaration declaration, MethodDeclaration method) {
        return new MethodKey(
                qualifiedTypeName(declaration),
                method.getNameAsString(),
                method.getParameters().size());
    }

    private String qualifiedTypeName(ClassOrInterfaceDeclaration declaration) {
        String packageName =
                declaration
                        .findCompilationUnit()
                        .flatMap(CompilationUnit::getPackageDeclaration)
                        .map(value -> value.getNameAsString())
                        .orElse("");
        return packageName.isBlank()
                ? declaration.getNameAsString()
                : packageName + "." + declaration.getNameAsString();
    }

    private Set<Integer> executedCallbackParameterIndexes(MethodDeclaration method) {
        if (method.getBody().isEmpty()) {
            return Set.of();
        }
        Set<String> executedParameters =
                method.getBody().get().findAll(MethodCallExpr.class).stream()
                        .filter(
                                call ->
                                        Set.of("get", "run", "call", "apply", "accept")
                                                .contains(call.getNameAsString()))
                        .filter(
                                call ->
                                        call.getScope()
                                                .filter(NameExpr.class::isInstance)
                                                .map(NameExpr.class::cast)
                                                .map(NameExpr::getNameAsString)
                                                .isPresent())
                        .filter(call -> isDirectCallbackInvocation(method, call))
                        .map(call -> call.getScope().orElseThrow().asNameExpr().getNameAsString())
                        .collect(Collectors.toSet());
        Set<Integer> indexes = new LinkedHashSet<>();
        for (int index = 0; index < method.getParameters().size(); index++) {
            if (executedParameters.contains(method.getParameter(index).getNameAsString())) {
                indexes.add(index);
            }
        }
        return Set.copyOf(indexes);
    }

    private boolean isDirectCallbackInvocation(
            MethodDeclaration method, MethodCallExpr callbackCall) {
        if (method.getBody().isEmpty()) {
            return false;
        }
        Node parent = callbackCall.getParentNode().orElse(null);
        if (parent instanceof ExpressionStmt statement) {
            return statement.getExpression() == callbackCall
                    && statement.getParentNode().orElse(null) == method.getBody().get();
        }
        if (parent instanceof ReturnStmt returnStmt) {
            return returnStmt.getExpression().orElse(null) == callbackCall
                    && returnStmt.getParentNode().orElse(null) == method.getBody().get();
        }
        return false;
    }

    private boolean belongsToMethod(Node node, MethodDeclaration method) {
        return node.findAncestor(MethodDeclaration.class).filter(method::equals).isPresent();
    }

    private String resolveReceiverType(
            MethodCallExpr call,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration) {
        Expression scope = call.getScope().orElse(null);
        if (scope == null) {
            return null;
        }
        if (scope instanceof ThisExpr) {
            return declaration.getNameAsString();
        }
        if (scope instanceof ObjectCreationExpr creation) {
            return normalizedTypeName(creation.getTypeAsString());
        }
        String variableName = null;
        if (scope instanceof NameExpr name) {
            variableName = name.getNameAsString();
        } else if (scope instanceof FieldAccessExpr access
                && access.getScope() instanceof ThisExpr) {
            variableName = access.getNameAsString();
        }
        if (variableName == null) {
            return null;
        }
        for (Parameter parameter : method.getParameters()) {
            if (parameter.getNameAsString().equals(variableName)) {
                return normalizedTypeName(parameter.getTypeAsString());
            }
        }
        for (VariableDeclarator variable : method.findAll(VariableDeclarator.class)) {
            if (!variable.getNameAsString().equals(variableName)
                    || variable.findAncestor(MethodDeclaration.class)
                            .filter(method::equals)
                            .isEmpty()) {
                continue;
            }
            if (variable.getType().isVarType()
                    && variable.getInitializer().orElse(null)
                            instanceof ObjectCreationExpr creation) {
                return normalizedTypeName(creation.getTypeAsString());
            }
            return normalizedTypeName(variable.getTypeAsString());
        }
        for (FieldDeclaration field : declaration.getFields()) {
            for (VariableDeclarator variable : field.getVariables()) {
                if (variable.getNameAsString().equals(variableName)) {
                    return normalizedTypeName(variable.getTypeAsString());
                }
            }
        }
        return null;
    }

    private String normalizedTypeName(String rawType) {
        if (rawType == null || rawType.isBlank()) {
            return null;
        }
        String withoutGenerics = rawType.replaceAll("<.*>", "").replace("[]", "").trim();
        return simpleName(withoutGenerics);
    }

    private MethodDeclaration resolveUniqueSameClassCall(
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration caller,
            MethodCallExpr call) {
        Expression scope = call.getScope().orElse(null);
        if (scope != null && !(scope instanceof ThisExpr)) {
            return null;
        }
        List<MethodDeclaration> candidates =
                declaration.getMethodsByName(call.getNameAsString()).stream()
                        .filter(candidate -> candidate != caller)
                        .filter(candidate -> invocationArityMatches(candidate, call))
                        .toList();
        return candidates.size() == 1 ? candidates.getFirst() : null;
    }

    private boolean isInsideLambda(Node node, MethodDeclaration method) {
        return node.findAncestor(LambdaExpr.class)
                .filter(lambda -> belongsToMethod(lambda, method))
                .isPresent();
    }

    private boolean isInsideActiveProgrammaticTransaction(
            Node node,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex index) {
        return enclosingProgrammaticBoundary(
                node, method, declaration, index, ProgrammaticBoundaryKind.ACTIVE);
    }

    private boolean isInsideImmediateProgrammaticCallback(
            Node node,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex index) {
        return enclosingProgrammaticBoundary(
                node, method, declaration, index, ProgrammaticBoundaryKind.IMMEDIATE);
    }

    private boolean isInsideIndependentProgrammaticTransaction(
            Node node,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex index) {
        return enclosingProgrammaticBoundary(
                node, method, declaration, index, ProgrammaticBoundaryKind.INDEPENDENT);
    }

    private boolean enclosingProgrammaticBoundary(
            Node node,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex index,
            ProgrammaticBoundaryKind boundaryKind) {
        Node current = node;
        while (current != method && current.getParentNode().isPresent()) {
            if (current instanceof LambdaExpr lambda) {
                MethodCallExpr boundary = lambda.findAncestor(MethodCallExpr.class).orElse(null);
                int callbackArgumentIndex =
                        boundary == null ? -1 : boundary.getArguments().indexOf(lambda);
                return boundary != null
                        && callbackArgumentIndex >= 0
                        && belongsToMethod(boundary, method)
                        && isProgrammaticTransactionBoundary(
                                boundary,
                                callbackArgumentIndex,
                                method,
                                declaration,
                                index,
                                boundaryKind);
            }
            current = current.getParentNode().get();
        }
        return false;
    }

    private boolean isProgrammaticTransactionBoundary(
            MethodCallExpr call,
            int callbackArgumentIndex,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex index,
            ProgrammaticBoundaryKind boundaryKind) {
        if (!Set.of("execute", "executeWithoutResult", "executeInTransaction")
                .contains(call.getNameAsString())) {
            return false;
        }
        String receiverType = resolveReceiverType(call, method, declaration);
        if (Set.of("TransactionTemplate", "TransactionOperations").contains(receiverType)) {
            return boundaryKind != ProgrammaticBoundaryKind.INDEPENDENT;
        }
        MethodKey target = resolveSourceMethodKey(call, method, declaration, index);
        if (target == null) {
            return false;
        }
        return switch (boundaryKind) {
            case IMMEDIATE -> index.executesCallbackArgument(target, callbackArgumentIndex);
            case ACTIVE ->
                    index.executesCallbackArgument(target, callbackArgumentIndex)
                            && index.isActiveCallbackBoundary(target);
            case INDEPENDENT ->
                    index.executesCallbackArgument(target, callbackArgumentIndex)
                            && index.isIndependentCallbackBoundary(target);
        };
    }

    private MethodKey resolveSourceMethodKey(
            MethodCallExpr call,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex index) {
        String receiverType = resolveReceiverType(call, method, declaration);
        String owner = resolveSourceOwner(receiverType, declaration, index);
        if (owner == null) {
            return null;
        }
        MethodKey key = new MethodKey(owner, call.getNameAsString(), call.getArguments().size());
        return index.isAmbiguous(key) ? null : key;
    }

    private String resolveSourceOwner(
            String receiverType,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex index) {
        if (receiverType == null) {
            return null;
        }
        String simple = simpleName(receiverType);
        Set<String> candidates = index.ownersBySimpleName().getOrDefault(simple, Set.of());
        if (candidates.isEmpty()) {
            return null;
        }
        String imported =
                declaration.findCompilationUnit().stream()
                        .flatMap(unit -> unit.getImports().stream())
                        .filter(importDeclaration -> !importDeclaration.isAsterisk())
                        .map(importDeclaration -> importDeclaration.getNameAsString())
                        .filter(name -> simpleName(name).equals(simple))
                        .findFirst()
                        .orElse(null);
        if (imported != null && candidates.contains(imported)) {
            return imported;
        }
        String samePackage =
                declaration
                        .findCompilationUnit()
                        .flatMap(CompilationUnit::getPackageDeclaration)
                        .map(value -> value.getNameAsString() + "." + simple)
                        .orElse(simple);
        if (candidates.contains(samePackage)) {
            return samePackage;
        }
        return candidates.size() == 1 ? candidates.iterator().next() : null;
    }

    private void analyzeClassSourceSignals(
            ClassOrInterfaceDeclaration declaration,
            String relativePath,
            String fileContent,
            List<OutboundEndpoint> outboundEndpoints,
            Set<String> controllerClasses,
            boolean legacyTransactionalVisibility,
            TransactionEvidenceIndex transactionEvidence,
            List<Finding> findings) {
        if (isGeneratedSource(relativePath, declaration)) {
            return;
        }
        String packageName =
                declaration
                        .findCompilationUnit()
                        .flatMap(CompilationUnit::getPackageDeclaration)
                        .map(value -> value.getNameAsString())
                        .orElse("");
        String className =
                packageName.isBlank()
                        ? declaration.getNameAsString()
                        : packageName + "." + declaration.getNameAsString();
        boolean controllerLike =
                controllerClasses.contains(className)
                        || hasAnyAnnotation(
                                declaration.getAnnotations(),
                                Set.of(
                                        "RestController",
                                        "Controller",
                                        "ControllerAdvice",
                                        "RestControllerAdvice"));
        boolean serviceLike =
                hasAnyAnnotation(declaration.getAnnotations(), Set.of("Service", "Component"));
        boolean repositoryLike =
                hasAnyAnnotation(declaration.getAnnotations(), Set.of("Repository"));
        boolean entityLike = hasAnnotation(declaration.getAnnotations(), "Entity");
        boolean configurationLike = hasAnnotation(declaration.getAnnotations(), "Configuration");
        boolean configPropertiesLike =
                hasAnnotation(declaration.getAnnotations(), "ConfigurationProperties");
        boolean classTransactional = hasAnnotation(declaration.getAnnotations(), "Transactional");
        boolean startupInterface =
                implementsAny(
                        declaration,
                        Set.of(
                                "CommandLineRunner",
                                "ApplicationRunner",
                                "InitializingBean",
                                "SmartLifecycle"));
        if (!outboundEndpoints.isEmpty()) {
            detectHttpClientGaps(relativePath, fileContent, outboundEndpoints, findings);
        }

        if (controllerLike && classTransactional) {
            detectTransactionalOnController(relativePath, declaration, null, findings);
        }

        for (FieldDeclaration field : declaration.getFields()) {
            if (hasAnnotation(field.getAnnotations(), "Autowired") && !field.isStatic()) {
                detectFieldInjection(relativePath, declaration, field, findings);
            }
            if (hasAnnotation(field.getAnnotations(), "Value")) {
                detectValueWithoutDefault(relativePath, declaration, field, findings);
            }
            if ((controllerLike || serviceLike || repositoryLike)
                    && !configurationLike
                    && isApplicationContextField(field)) {
                detectApplicationContextInjected(relativePath, declaration, field, findings);
            }
            if ((controllerLike || serviceLike || repositoryLike || configurationLike)
                    && field.isStatic()
                    && !field.isFinal()) {
                detectStaticMutableField(relativePath, declaration, field, findings);
            }
            if ((controllerLike || serviceLike || repositoryLike || configurationLike)
                    && field.isStatic()
                    && hasAnyAnnotation(field.getAnnotations(), INJECTION_ANNOTATIONS)) {
                detectInjectionOnStaticField(relativePath, declaration, field, findings);
            }
        }

        for (ConstructorDeclaration constructor : declaration.getConstructors()) {
            MethodSignals signals =
                    methodSignals(constructor.getBody().toString(), constructor.getNameAsString());
            detectExceptionHandlingInConstructor(
                    relativePath,
                    className,
                    declaration,
                    constructor,
                    controllerLike,
                    serviceLike,
                    repositoryLike,
                    findings);
            if (signals.hasMeaningfulSideEffects()) {
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_STARTUP_SIDE_EFFECT,
                                        FindingConfidence.MEDIUM)
                                .shortMessage(
                                        "Constructor in "
                                                + declaration.getNameAsString()
                                                + " appears to perform side effects.")
                                .whyBadPractice(
                                        "Constructors run during bean creation, so heavy or"
                                            + " side-effecting work there makes object construction"
                                            + " harder to reason about and harder to isolate in"
                                            + " tests.")
                                .possibleImpact(
                                        "Bean creation may trigger network calls, writes, or thread"
                                            + " creation before the application is fully ready to"
                                            + " handle failures safely.")
                                .recommendation(
                                        "Keep constructors lightweight and move side effects behind"
                                                + " explicit lifecycle hooks, background jobs, or"
                                                + " service methods with clear error handling.")
                                .evidence(
                                        "Constructor in "
                                                + relativePath
                                                + " performs "
                                                + signals.describe()
                                                + ".")
                                .limitations(
                                        "Static analysis infers side effects from method calls and"
                                                + " cannot prove runtime execution frequency.")
                                .source(
                                        relativePath,
                                        constructor
                                                .getBegin()
                                                .map(position -> position.line)
                                                .orElse(null))
                                .target(className)
                                .build());
            }
        }

        for (MethodDeclaration method : declaration.getMethods()) {
            MethodSignals signals =
                    methodSignals(
                            method.getBody().map(Object::toString).orElse(""),
                            method.getNameAsString());
            boolean startupHook = isStartupHook(declaration, method, startupInterface);
            boolean scheduled = hasAnnotation(method.getAnnotations(), "Scheduled");
            detectExceptionHandlingInMethod(
                    relativePath,
                    className,
                    declaration,
                    method,
                    controllerLike,
                    startupHook,
                    scheduled,
                    serviceLike,
                    repositoryLike,
                    findings);

            if (startupHook && signals.hasMeaningfulSideEffects()) {
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_STARTUP_SIDE_EFFECT,
                                        signals.directSignalConfidence())
                                .shortMessage(
                                        "Startup hook "
                                                + declaration.getNameAsString()
                                                + "#"
                                                + method.getNameAsString()
                                                + " appears to perform side effects.")
                                .whyBadPractice(
                                        "Startup hooks run as the application initializes. Heavy or"
                                            + " side-effecting work there makes readiness depend on"
                                            + " external systems and hidden background actions.")
                                .possibleImpact(
                                        "Deployments can become slow or brittle, repeated restarts"
                                            + " can replay work, and rollouts may fail for reasons"
                                            + " unrelated to normal request handling.")
                                .recommendation(
                                        "Move heavy work behind explicit admin actions, background"
                                                + " jobs with idempotency, or controlled"
                                                + " migration/backfill workflows.")
                                .evidence(
                                        "Detected startup hook "
                                                + startupHookDescription(method, declaration)
                                                + " with "
                                                + signals.describe()
                                                + " in "
                                                + relativePath
                                                + ".")
                                .limitations(
                                        "Static analysis cannot prove that every call is always"
                                                + " executed, but the method is wired into startup"
                                                + " lifecycle code.")
                                .source(
                                        relativePath,
                                        method.getBegin()
                                                .map(position -> position.line)
                                                .orElse(null))
                                .target(className + "#" + method.getNameAsString())
                                .build());
            }

            if (scheduled) {
                detectSchedulingRisks(relativePath, declaration, method, signals, findings);
            }

            if (serviceLike) {
                detectTransactionRisks(
                        relativePath,
                        declaration,
                        method,
                        repositoryLike,
                        legacyTransactionalVisibility,
                        signals,
                        transactionEvidence,
                        findings);
            }

            if (controllerLike) {
                detectPathVariableTemplateMismatch(relativePath, declaration, method, findings);
            }

            if (controllerLike) {
                detectValidationGap(relativePath, declaration, method, signals, findings);
            }

            if (hasAnnotation(method.getAnnotations(), "Async")) {
                detectAsyncMethodRisks(relativePath, declaration, method, findings);
            }

            if (hasAnyAnnotation(
                            method.getAnnotations(),
                            Set.of("EventListener", "TransactionalEventListener"))
                    && !hasAnnotation(method.getAnnotations(), "Async")) {
                detectEventListenerBlocking(relativePath, declaration, method, findings);
            }

            if (hasAnyAnnotation(method.getAnnotations(), MESSAGING_LISTENER_ANNOTATIONS)) {
                detectMessagingListenerRisks(relativePath, declaration, method, findings);
            }

            if (hasAnnotation(method.getAnnotations(), "Modifying")
                    && !hasAnnotation(method.getAnnotations(), "Transactional")
                    && !classTransactional
                    && !transactionEvidence.isAmbiguous(
                            new MethodKey(
                                    qualifiedTypeName(declaration),
                                    method.getNameAsString(),
                                    method.getParameters().size()))
                    && !transactionEvidence.hasTransactionalCaller(
                            qualifiedTypeName(declaration),
                            method.getNameAsString(),
                            method.getParameters().size())) {
                detectModifyingNoTransaction(relativePath, declaration, method, findings);
            }

            if (scheduled && hasAnnotation(method.getAnnotations(), "Transactional")) {
                detectTransactionalOnScheduled(relativePath, declaration, method, findings);
            }

            if (hasAnnotation(method.getAnnotations(), "Transactional") || classTransactional) {
                detectTransactionIsolationReadUncommitted(
                        relativePath, declaration, method, findings);
                if (callerTransactionGuaranteesActiveTransaction(
                        declaration,
                        method,
                        effectiveTransactionalAnnotation(declaration, method),
                        legacyTransactionalVisibility)) {
                    detectTransactionalExceptionSwallowed(
                            relativePath, declaration, method, transactionEvidence, findings);
                }
                detectTransactionalHttpCall(relativePath, declaration, method, findings);
            }

            // Only flag method-level @Transactional when the class itself is not already flagged;
            // a class-level finding already covers all methods.
            if (controllerLike
                    && !classTransactional
                    && hasAnnotation(method.getAnnotations(), "Transactional")) {
                detectTransactionalOnController(relativePath, declaration, method, findings);
            }

            if (controllerLike) {
                detectRequestMappingNoMethod(relativePath, declaration, method, findings);
                detectSensitiveRequestParams(relativePath, declaration, method, findings);
            }
        }

        if (entityLike) {
            detectJpaRelationshipRisks(relativePath, declaration, findings);
        }

        if (!configurationLike) {
            detectBeanInNonConfigurationClass(relativePath, declaration, findings);
        }

        if (configPropertiesLike && !hasAnnotation(declaration.getAnnotations(), "Validated")) {
            detectConfigPropertiesNotValidated(relativePath, declaration, findings);
        }

        detectCsrfDisabled(relativePath, declaration, findings);
        detectCorsAllowAll(relativePath, declaration, findings);
        detectCorsCredentialsWildcard(relativePath, declaration, findings);
        detectCrossOriginAnnotation(relativePath, declaration, findings);
        detectDuplicateExceptionHandlers(relativePath, declaration, findings);
        detectFeignClientRisks(relativePath, declaration, findings);
        detectRestTemplateNoStatusHandler(relativePath, declaration, findings);
        detectSqlInjectionInQueries(relativePath, declaration, findings);
        detectLoggingPiiExposure(relativePath, declaration, findings);
        detectSystemOutPrintln(relativePath, declaration, findings);
        if (controllerLike || serviceLike || repositoryLike) {
            detectUnmanagedThread(relativePath, declaration, findings);
        }
        if (controllerLike) {
            detectEntityExposedInApi(relativePath, declaration, findings);
            detectRepositoryInController(relativePath, declaration, findings);
        }
        detectJpaLazyLoadingOutsideTransaction(relativePath, declaration, findings);
        detectProxyAnnotationOnFinalMethod(relativePath, declaration, findings);
        detectBigDecimalDoubleConstructor(relativePath, declaration, findings);
        detectTransactionalEventListenerWriteLost(relativePath, declaration, findings);
    }

    private void detectExceptionHandlingInConstructor(
            String relativePath,
            String className,
            ClassOrInterfaceDeclaration declaration,
            ConstructorDeclaration constructor,
            boolean controllerLike,
            boolean serviceLike,
            boolean repositoryLike,
            List<Finding> findings) {
        ExceptionHandlingContext context =
                new ExceptionHandlingContext(
                        relativePath,
                        className,
                        className + "#" + constructor.getNameAsString(),
                        controllerLike,
                        false,
                        false,
                        serviceLike,
                        repositoryLike,
                        false,
                        true,
                        false);
        detectPrintStackTrace(
                relativePath, context, constructor.findAll(MethodCallExpr.class), findings);
        for (CatchClause catchClause : constructor.findAll(CatchClause.class)) {
            analyzeCatchClause(context, catchClause, findings);
        }
    }

    private void detectExceptionHandlingInMethod(
            String relativePath,
            String className,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            boolean controllerLike,
            boolean startupHook,
            boolean scheduled,
            boolean serviceLike,
            boolean repositoryLike,
            List<Finding> findings) {
        boolean exceptionHandler = hasAnnotation(method.getAnnotations(), "ExceptionHandler");
        ExceptionHandlingContext context =
                new ExceptionHandlingContext(
                        relativePath,
                        className,
                        className + "#" + method.getNameAsString(),
                        controllerLike,
                        startupHook,
                        scheduled,
                        serviceLike,
                        repositoryLike,
                        exceptionHandler,
                        false,
                        isTopLevelUncaughtHandler(declaration, method));
        detectPrintStackTrace(
                relativePath, context, method.findAll(MethodCallExpr.class), findings);
        for (CatchClause catchClause : method.findAll(CatchClause.class)) {
            analyzeCatchClause(context, catchClause, findings);
        }
        if (exceptionHandler) {
            detectBroadSpringExceptionHandler(context, method, findings);
        }
    }

    private void analyzeCatchClause(
            ExceptionHandlingContext context, CatchClause catchClause, List<Finding> findings) {
        CatchAnalysis analysis =
                analyzeCatchBody(
                        catchClause.getBody(), catchClause.getParameter().getNameAsString());
        Set<String> caughtTypes = caughtTypeNames(catchClause);
        Integer line = catchClause.getBegin().map(position -> position.line).orElse(null);
        String primaryType =
                caughtTypes.isEmpty()
                        ? catchClause.getParameter().getTypeAsString()
                        : caughtTypes.iterator().next();
        String evidencePrefix =
                "Catch block for "
                        + primaryType
                        + " in "
                        + context.target()
                        + " ("
                        + context.relativePath()
                        + ":"
                        + defaultString(line == null ? null : String.valueOf(line))
                        + ").";
        boolean specificRuleTriggered = false;
        SourceLocation catchLocation = catchLocation(context, catchClause);
        boolean broadCatch = caughtTypes.stream().anyMatch(this::isBroadCatchType);
        boolean likelyParserFallback = isLikelyParserFallback(context, caughtTypes, analysis);

        if (analysis.emptyLike()) {
            if (!analysis.intentionalIgnoreSafe()) {
                boolean testSource = context.relativePath().startsWith("src/test/");
                boolean commentOnly = analysis.commentOnly();
                FindingSeverity severity =
                        (testSource || likelyParserFallback)
                                ? FindingSeverity.INFO
                                : FindingSeverity.WARNING;
                FindingConfidence confidence =
                        (commentOnly || likelyParserFallback)
                                ? FindingConfidence.MEDIUM
                                : (broadCatch && !testSource
                                        ? FindingConfidence.HIGH
                                        : FindingConfidence.MEDIUM);
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.JAVA_EMPTY_CATCH_BLOCK.ruleId(),
                                        FindingRules.JAVA_EMPTY_CATCH_BLOCK.title(),
                                        severity,
                                        FindingRules.JAVA_EMPTY_CATCH_BLOCK.category(),
                                        FindingRules.JAVA_EMPTY_CATCH_BLOCK.runtimeDetection(),
                                        confidence)
                                .shortMessage("Exception is caught but the catch block is empty.")
                                .whyBadPractice(
                                        "An empty catch block silently discards failure"
                                            + " information. The application may continue in an"
                                            + " invalid state while the original cause is lost.")
                                .possibleImpact(
                                        "Operators and developers may see missing data, partial"
                                            + " processing, inconsistent state, or later failures"
                                            + " without any useful log entry pointing to the"
                                            + " original exception.")
                                .recommendation(
                                        "Handle the exception intentionally, log it with useful"
                                            + " context, rethrow/wrap it, or document and isolate"
                                            + " the intentionally ignored case.")
                                .evidence(
                                        evidencePrefix
                                                + " Catch variable: "
                                                + catchClause.getParameter().getNameAsString()
                                                + ".")
                                .limitations(
                                        "Static analysis cannot prove whether the exception is"
                                            + " truly harmless, but an empty catch block hides the"
                                            + " failure path from normal runtime diagnostics.")
                                .sourceLocation(catchLocation)
                                .highlightRange(
                                        new HighlightRange(
                                                catchLocation.startLine(),
                                                catchLocation.endLine(),
                                                null,
                                                null,
                                                "issue"))
                                .target(context.target())
                                .build());
                specificRuleTriggered = true;
            }
        }

        if (caughtTypes.stream().anyMatch(this::isInterruptedType)
                && !analysis.restoresInterrupt()
                && !analysis.rethrows()) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_INTERRUPTED_EXCEPTION_SWALLOWED,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "InterruptedException is caught without restoring the interrupt"
                                            + " status or propagating the interruption.")
                            .whyBadPractice(
                                    "InterruptedException is part of Java's cooperative"
                                        + " cancellation mechanism. Swallowing it can prevent"
                                        + " shutdown, cancellation, and thread-pool management from"
                                        + " working correctly.")
                            .possibleImpact(
                                    "Background jobs, scheduled tasks, or request processing may"
                                            + " ignore shutdown signals and continue running longer"
                                            + " than expected.")
                            .recommendation(
                                    "Call Thread.currentThread().interrupt() and either return"
                                            + " safely or rethrow/wrap the exception.")
                            .evidence(
                                    evidencePrefix
                                            + " No Thread.currentThread().interrupt() or rethrow"
                                            + " was found.")
                            .limitations(
                                    "Static analysis cannot prove the surrounding threading model,"
                                            + " but swallowing interruption is usually unsafe in"
                                            + " application code.")
                            .sourceLocation(catchLocation)
                            .highlightRange(
                                    new HighlightRange(
                                            catchLocation.startLine(),
                                            catchLocation.endLine(),
                                            null,
                                            null,
                                            "issue"))
                            .target(context.target())
                            .build());
            specificRuleTriggered = true;
        }

        if (caughtTypes.stream().anyMatch(this::isFatalCatchType)) {
            FindingSeverity severity =
                    context.topLevelUncaughtHandler()
                                    || (analysis.hasStrongLogging() && analysis.rethrows())
                            ? FindingSeverity.INFO
                            : FindingRules.SPRING_BROAD_FATAL_ERROR_CATCH.defaultSeverity();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_BROAD_FATAL_ERROR_CATCH.ruleId(),
                                    FindingRules.SPRING_BROAD_FATAL_ERROR_CATCH.title(),
                                    severity,
                                    FindingRules.SPRING_BROAD_FATAL_ERROR_CATCH.category(),
                                    FindingRules.SPRING_BROAD_FATAL_ERROR_CATCH.runtimeDetection(),
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "Code catches "
                                            + primaryType
                                            + ", which may include JVM-level failures that"
                                            + " application code should normally not handle.")
                            .whyBadPractice(
                                    "Catching Throwable or Error can intercept serious JVM or"
                                            + " infrastructure failures that are not safely"
                                            + " recoverable.")
                            .possibleImpact(
                                    "The application may continue after a fatal condition, hide the"
                                        + " real failure, or interfere with container and platform"
                                        + " failure handling.")
                            .recommendation(
                                    "Catch the narrowest expected exception type. Only catch"
                                        + " Throwable at process boundaries where the error is"
                                        + " logged and rethrown or the process is allowed to fail"
                                        + " safely.")
                            .evidence(
                                    evidencePrefix
                                            + " Catch type(s): "
                                            + String.join(", ", caughtTypes)
                                            + ".")
                            .limitations(
                                    "Static analysis cannot know whether this is an intentional"
                                            + " top-level boundary, so review the surrounding code"
                                            + " before changing it.")
                            .sourceLocation(catchLocation)
                            .highlightRange(
                                    new HighlightRange(
                                            catchLocation.startLine(),
                                            catchLocation.endLine(),
                                            null,
                                            null,
                                            "issue"))
                            .target(context.target())
                            .build());
            specificRuleTriggered = true;
        }

        if (context.controllerLike() || context.exceptionHandler()) {
            Optional<Node> rawExposureNode =
                    findRawExceptionMessageExposureNode(
                            catchClause.getBody(), catchClause.getParameter().getNameAsString());
            if (rawExposureNode.isPresent()) {
                SourceLocation rawExposureLocation =
                        nodeLocation(
                                context.relativePath(),
                                context.target(),
                                rawExposureNode.get(),
                                catchLocation);
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_RAW_EXCEPTION_MESSAGE_HTTP,
                                        FindingConfidence.MEDIUM)
                                .shortMessage(
                                        "HTTP response appears to include a raw exception message.")
                                .whyBadPractice(
                                        "Exception messages can contain internal class names, SQL"
                                            + " details, file paths, URLs, configuration names, or"
                                            + " sensitive operational details.")
                                .possibleImpact(
                                        "Clients may see internal implementation details that help"
                                                + " attackers or confuse normal users.")
                                .recommendation(
                                        "Return a sanitized client-facing error message and log the"
                                            + " technical exception server-side with correlation"
                                            + " information.")
                                .evidence(
                                        evidencePrefix
                                                + " Response construction uses "
                                                + summarizeNode(rawExposureNode.get())
                                                + ".")
                                .limitations(
                                        "Static analysis cannot prove whether the exception message"
                                                + " is sanitized before this point.")
                                .sourceLocation(rawExposureLocation)
                                .highlightRange(highlightRangeFor(rawExposureLocation))
                                .target(context.target())
                                .build());
                specificRuleTriggered = true;
            }
        }

        if (analysis.usesFallbackWithoutVisibleHandling()
                && !analysis.hasStrongLogging()
                && !analysis.rethrows()) {
            boolean warningContext = broadCatch || context.productionLikeBoundary();
            FindingSeverity severity =
                    likelyParserFallback && !warningContext
                            ? FindingSeverity.INFO
                            : (warningContext
                                    ? FindingSeverity.WARNING
                                    : FindingRules.SPRING_SWALLOWED_EXCEPTION_FALLBACK
                                            .defaultSeverity());
            String whyBadPractice =
                    likelyParserFallback && !warningContext
                            ? "This may be intentional for best-effort parsing, but without logging"
                                    + " or an explicit comment it is hard to distinguish expected"
                                    + " parse failures from unexpected data loss."
                            : "Returning a fallback without recording the exception makes real"
                                    + " failures look like valid empty or default results.";
            String possibleImpact =
                    likelyParserFallback && !warningContext
                            ? "Unexpected input formats can be silently ignored, which may make"
                                    + " later data quality issues harder to diagnose."
                            : "Data may silently disappear, processing may be skipped, or callers"
                                    + " may make decisions based on incomplete information.";
            String recommendation =
                    likelyParserFallback && !warningContext
                            ? "Keep the fallback if it is intentional, but consider adding a short"
                                    + " comment, metric, debug log, or typed parse result when the"
                                    + " failure is operationally relevant."
                            : "Log the exception with useful context, return a typed error result,"
                                    + " rethrow a domain exception, or make the fallback behavior"
                                    + " explicit and observable.";
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_SWALLOWED_EXCEPTION_FALLBACK.ruleId(),
                                    FindingRules.SPRING_SWALLOWED_EXCEPTION_FALLBACK.title(),
                                    severity,
                                    FindingRules.SPRING_SWALLOWED_EXCEPTION_FALLBACK.category(),
                                    FindingRules.SPRING_SWALLOWED_EXCEPTION_FALLBACK
                                            .runtimeDetection(),
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "Exception is caught and replaced with a fallback result"
                                            + " without visible logging or propagation.")
                            .whyBadPractice(whyBadPractice)
                            .possibleImpact(possibleImpact)
                            .recommendation(recommendation)
                            .evidence(
                                    evidencePrefix
                                            + " Detected fallback-only handling: "
                                            + analysis.fallbackDescription()
                                            + ".")
                            .limitations(
                                    "Static analysis cannot prove whether the fallback is"
                                            + " intentional or safe for this business path.")
                            .sourceLocation(catchLocation)
                            .highlightRange(
                                    new HighlightRange(
                                            catchLocation.startLine(),
                                            catchLocation.endLine(),
                                            null,
                                            null,
                                            "issue"))
                            .target(context.target())
                            .build());
            specificRuleTriggered = true;
        }

        if (!specificRuleTriggered
                && caughtTypes.stream()
                        .anyMatch(
                                type -> type.equals("Exception") || type.equals("RuntimeException"))
                && context.springBoundary()
                && !analysis.hasStrongLogging()
                && !analysis.rethrows()
                && !analysis.intentionalIgnoreSafe()) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_BROAD_EXCEPTION_SPRING_BOUNDARY,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "Spring boundary catches a broad exception type without a"
                                            + " clearly actionable handling strategy.")
                            .whyBadPractice(
                                    "Broad catch blocks at Spring boundaries can hide different"
                                            + " failure modes behind the same behavior.")
                            .possibleImpact(
                                    "Startup failures, scheduled job failures, or request failures"
                                        + " may be harder to diagnose and may produce inconsistent"
                                        + " operational behavior.")
                            .recommendation(
                                    "Catch the expected exception types separately, add"
                                        + " context-rich logging, or convert failures to a clear"
                                        + " domain or application exception.")
                            .evidence(
                                    evidencePrefix
                                            + " Catch type "
                                            + primaryType
                                            + " uses weak handling in a Spring boundary.")
                            .limitations(
                                    "Static analysis cannot prove whether all possible exceptions"
                                            + " are equivalent in this context.")
                            .sourceLocation(catchLocation)
                            .highlightRange(
                                    new HighlightRange(
                                            catchLocation.startLine(),
                                            catchLocation.endLine(),
                                            null,
                                            null,
                                            "issue"))
                            .target(context.target())
                            .build());
        }
    }

    private SourceLocation catchLocation(
            ExceptionHandlingContext context, CatchClause catchClause) {
        int startLine = catchClause.getBegin().map(position -> position.line).orElse(1);
        int endLine = catchClause.getEnd().map(position -> position.line).orElse(startLine);
        Integer startColumn = catchClause.getBegin().map(position -> position.column).orElse(null);
        Integer endColumn = catchClause.getEnd().map(position -> position.column).orElse(null);
        return new SourceLocation(
                context.relativePath(),
                startLine,
                endLine,
                startColumn,
                endColumn,
                context.target(),
                "java",
                null);
    }

    private void detectBroadSpringExceptionHandler(
            ExceptionHandlingContext context, MethodDeclaration method, List<Finding> findings) {
        if (!handlesBroadException(method)) {
            return;
        }
        Optional<Node> rawExposureNode = findRawExceptionMessageExposureNode(method);
        if (rawExposureNode.isPresent()) {
            SourceLocation location =
                    nodeLocation(
                            context.relativePath(),
                            context.target(),
                            rawExposureNode.get(),
                            methodLocation(context, method));
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_RAW_EXCEPTION_MESSAGE_HTTP,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "HTTP response appears to include a raw exception message.")
                            .whyBadPractice(
                                    "Exception messages can contain internal class names, SQL"
                                            + " details, file paths, URLs, configuration names, or"
                                            + " sensitive operational details.")
                            .possibleImpact(
                                    "Clients may see internal implementation details that help"
                                            + " attackers or confuse normal users.")
                            .recommendation(
                                    "Return a sanitized client-facing error message and log the"
                                            + " technical exception server-side with correlation"
                                            + " information.")
                            .evidence(
                                    "@ExceptionHandler method "
                                            + context.target()
                                            + " returns "
                                            + summarizeNode(rawExposureNode.get())
                                            + " to HTTP clients.")
                            .limitations(
                                    "Static analysis cannot prove whether the exception message is"
                                            + " sanitized before this point.")
                            .sourceLocation(location)
                            .highlightRange(highlightRangeFor(location))
                            .target(context.target())
                            .build());
            return;
        }
        String responseBehavior = broadExceptionHandlerResponseBehavior(method);
        FindingSeverity severity =
                responseBehavior == null
                        ? FindingRules.SPRING_BROAD_EXCEPTION_HANDLER.defaultSeverity()
                        : FindingSeverity.WARNING;
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_BROAD_EXCEPTION_HANDLER.ruleId(),
                                FindingRules.SPRING_BROAD_EXCEPTION_HANDLER.title(),
                                severity,
                                FindingRules.SPRING_BROAD_EXCEPTION_HANDLER.category(),
                                FindingRules.SPRING_BROAD_EXCEPTION_HANDLER.runtimeDetection(),
                                FindingConfidence.MEDIUM)
                        .shortMessage("Spring exception handler catches a broad exception type.")
                        .whyBadPractice(
                                "A catch-all exception handler can make unrelated failures look the"
                                        + " same and can accidentally hide programming errors.")
                        .possibleImpact(
                                "Operational failures, validation failures, and unexpected bugs may"
                                        + " be mapped to the same HTTP response or log level.")
                        .recommendation(
                                "Use narrower exception handlers for expected application errors"
                                        + " and keep a final catch-all handler for sanitized 500"
                                        + " responses.")
                        .evidence(
                                "@ExceptionHandler on "
                                        + context.target()
                                        + " catches Exception, RuntimeException, or Throwable."
                                        + (responseBehavior == null
                                                ? ""
                                                : " Response behavior appears to map failures to "
                                                        + responseBehavior
                                                        + "."))
                        .limitations(
                                "Static analysis cannot prove whether this is the intended global"
                                        + " fallback handler.")
                        .source(
                                context.relativePath(),
                                method.getBegin().map(position -> position.line).orElse(null))
                        .target(context.target())
                        .build());
    }

    private void detectPrintStackTrace(
            String relativePath,
            ExceptionHandlingContext context,
            List<MethodCallExpr> methodCalls,
            List<Finding> findings) {
        for (MethodCallExpr call : methodCalls) {
            if (!"printStackTrace".equals(call.getNameAsString())) {
                continue;
            }
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_PRINT_STACK_TRACE.ruleId(),
                                    FindingRules.SPRING_PRINT_STACK_TRACE.title(),
                                    context.productionLikeBoundary()
                                            ? FindingSeverity.WARNING
                                            : FindingRules.SPRING_PRINT_STACK_TRACE
                                                    .defaultSeverity(),
                                    FindingRules.SPRING_PRINT_STACK_TRACE.category(),
                                    FindingRules.SPRING_PRINT_STACK_TRACE.runtimeDetection(),
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "Exception is printed directly instead of using the application"
                                            + " logger.")
                            .whyBadPractice(
                                    "Direct stack-trace printing bypasses structured application"
                                        + " logging, log levels, correlation IDs, and deployment"
                                        + " logging conventions.")
                            .possibleImpact(
                                    "Failures may be hard to search, correlate, redact, or route in"
                                            + " production log systems.")
                            .recommendation(
                                    "Use the application logger with useful context, for example"
                                        + " log.warn(..., exception) or log.error(..., exception).")
                            .evidence(
                                    "Detected printStackTrace() in "
                                            + relativePath
                                            + " within "
                                            + context.target()
                                            + ".")
                            .limitations(
                                    "Static analysis cannot know the deployment logging setup, but"
                                            + " Spring Boot applications should normally use the"
                                            + " configured logging framework.")
                            .source(
                                    relativePath,
                                    call.getBegin().map(position -> position.line).orElse(null))
                            .target(context.target())
                            .build());
        }
    }

    private static final java.util.regex.Pattern NO_ARG_REST_TEMPLATE_PATTERN =
            java.util.regex.Pattern.compile("new\\s+RestTemplate\\s*\\(\\s*\\)");

    private void detectHttpClientGaps(
            String relativePath,
            String fileContent,
            List<OutboundEndpoint> outboundEndpoints,
            List<Finding> findings) {
        String normalized = fileContent.toLowerCase(Locale.ROOT);
        boolean timeoutConfigured =
                normalized.contains("setconnecttimeout")
                        || normalized.contains("setreadtimeout")
                        || normalized.contains("responsetimeout")
                        || normalized.contains("readtimeout")
                        || normalized.contains("connecttimeout")
                        || normalized.contains("calltimeout")
                        || normalized.contains("clienthttprequestfactory");
        boolean resilienceConfigured =
                normalized.contains("retry")
                        || normalized.contains("circuitbreaker")
                        || normalized.contains("resilience4j")
                        || normalized.contains("retrytemplate")
                        || normalized.contains("retrywhen")
                        || normalized.contains("@retryable")
                        || normalized.contains("backoff");
        // A no-arg `new RestTemplate()` in the same file is already reported, with a more
        // specific message, as SPRING_REST_TEMPLATE_NO_TIMEOUT — don't report the same missing
        // timeout twice.
        boolean noArgRestTemplateInFile = NO_ARG_REST_TEMPLATE_PATTERN.matcher(fileContent).find();
        OutboundEndpoint representative = outboundEndpoints.get(0);
        if (!timeoutConfigured && !noArgRestTemplateInFile) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_HTTP_CLIENT_NO_TIMEOUT,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "No visible timeout configuration was found for outbound HTTP"
                                            + " client usage in "
                                            + relativePath)
                            .whyBadPractice(
                                    "Outbound HTTP calls are production dependencies. Without"
                                            + " explicit timeouts, a slow remote service can hold"
                                            + " threads far longer than intended.")
                            .possibleImpact(
                                    "Slow external APIs can delay startup hooks, stall scheduled"
                                        + " jobs, or exhaust worker threads under production load.")
                            .recommendation(
                                    "Configure connect, read, and response timeouts in the client"
                                            + " bean or builder used for this integration.")
                            .evidence(
                                    "Outbound HTTP client usage was detected in "
                                            + relativePath
                                            + " for host "
                                            + defaultString(
                                                    representative.host(),
                                                    representative.baseUrl(),
                                                    representative.urlOrTemplate())
                                            + ", but no obvious timeout configuration was found in"
                                            + " the same source file.")
                            .limitations(
                                    "Static analysis may miss timeouts configured in imported"
                                            + " shared beans, external configuration classes, or"
                                            + " auto-configured infrastructure.")
                            .source(relativePath, representative.line())
                            .target(
                                    representative.host() != null
                                            ? representative.host()
                                            : representative.clientType())
                            .build());
        }
        boolean hasWriteLikeOutbound =
                outboundEndpoints.stream()
                        .anyMatch(
                                endpoint ->
                                        HTTP_WRITE_METHODS.contains(
                                                defaultString(endpoint.method())
                                                        .toUpperCase(Locale.ROOT)));
        if (!resilienceConfigured && hasWriteLikeOutbound) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_HTTP_CLIENT_NO_RESILIENCE,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "No visible retry or circuit-breaker handling was found around"
                                            + " outbound HTTP calls in "
                                            + relativePath)
                            .whyBadPractice(
                                    "External integrations fail in partial ways. Without visible"
                                        + " retry or backoff handling, write-like HTTP calls are"
                                        + " more likely to fail noisily or be retried unsafely"
                                        + " elsewhere.")
                            .possibleImpact(
                                    "Operators may see flaky integrations, duplicate manual"
                                            + " retries, or unstable job behavior when the external"
                                            + " service is slow or intermittently unavailable.")
                            .recommendation(
                                    "Review whether retries, backoff, idempotency, and circuit"
                                        + " breakers are appropriate for this integration and make"
                                        + " the choice explicit in code or client configuration.")
                            .evidence(
                                    "Outbound HTTP calls including write-like methods were detected"
                                            + " in "
                                            + relativePath
                                            + ", but no obvious retry or circuit-breaker"
                                            + " configuration was found in the same source file.")
                            .limitations(
                                    "Static analysis may miss resilience policies applied by shared"
                                            + " client beans, infrastructure proxies, or external"
                                            + " libraries.")
                            .source(relativePath, representative.line())
                            .target(representative.clientType())
                            .build());
        }
    }

    private void detectAsyncMethodRisks(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        Integer line = method.getBegin().map(position -> position.line).orElse(null);
        String target = declaration.getNameAsString() + "#" + method.getNameAsString();
        if (method.isPrivate()) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_ASYNC_PROXY_BYPASS, FindingConfidence.HIGH)
                            .shortMessage(
                                    "@Async on private method "
                                            + target
                                            + " will not be intercepted by the proxy.")
                            .whyBadPractice(
                                    "Spring @Async relies on proxy interception. Private methods"
                                        + " are not visible to the proxy, so the async behaviour is"
                                        + " silently dropped.")
                            .possibleImpact(
                                    "The method executes synchronously on the calling thread"
                                        + " instead of asynchronously, potentially blocking callers"
                                        + " and causing unexpected behaviour.")
                            .recommendation(
                                    "Make the method public or package-protected. If it must stay"
                                        + " private, submit work explicitly via an ExecutorService"
                                        + " instead.")
                            .evidence(
                                    "@Async was found on private method "
                                            + method.getNameAsString()
                                            + " in "
                                            + relativePath
                                            + ".")
                            .limitations(
                                    "Static analysis cannot determine whether AspectJ compile-time"
                                        + " weaving is used instead of proxy-based interception.")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
        boolean returnsVoid = method.getType().asString().equals("void");
        boolean hasExceptionHandling = !method.findAll(CatchClause.class).isEmpty();
        if (returnsVoid && !hasExceptionHandling) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_ASYNC_VOID_SWALLOWED_EXCEPTION,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "@Async void method " + target + " has no exception handling.")
                            .whyBadPractice(
                                    "Exceptions thrown by @Async void methods are routed to"
                                        + " AsyncUncaughtExceptionHandler, which by default only"
                                        + " logs them. Callers have no way to observe failures.")
                            .possibleImpact(
                                    "Failures in async operations are silently lost unless a custom"
                                        + " AsyncUncaughtExceptionHandler is configured, making the"
                                        + " system appear healthy when it is not.")
                            .recommendation(
                                    "Add try/catch handling within the method, return"
                                        + " CompletableFuture so callers can react to failures, or"
                                        + " register a custom AsyncUncaughtExceptionHandler.")
                            .evidence(
                                    "@Async void method "
                                            + method.getNameAsString()
                                            + " found without exception handling in "
                                            + relativePath
                                            + ".")
                            .limitations(
                                    "Static analysis cannot verify whether a global"
                                        + " AsyncUncaughtExceptionHandler is configured elsewhere"
                                        + " in the application.")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    private void detectMessagingListenerRisks(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        String presentAnnotation =
                MESSAGING_LISTENER_ANNOTATIONS.stream()
                        .filter(name -> hasAnnotation(method.getAnnotations(), name))
                        .findFirst()
                        .orElse(null);
        if (presentAnnotation == null) {
            return;
        }
        boolean hasExceptionHandling = !method.findAll(CatchClause.class).isEmpty();
        if (!hasExceptionHandling) {
            Integer line = method.getBegin().map(position -> position.line).orElse(null);
            String target = declaration.getNameAsString() + "#" + method.getNameAsString();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_MESSAGING_LISTENER_NO_ERROR_HANDLER,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "@"
                                            + presentAnnotation
                                            + " method "
                                            + target
                                            + " has no visible exception handling.")
                            .whyBadPractice(
                                    "Unhandled exceptions in messaging listeners cause message"
                                        + " redelivery or dead-letter routing depending on broker"
                                        + " configuration. Without explicit handling, errors can"
                                        + " cause repeated processing or silent message loss.")
                            .possibleImpact(
                                    "Poison messages can block consumption or flood the dead-letter"
                                            + " queue. Retry storms may amplify load on downstream"
                                            + " services.")
                            .recommendation(
                                    "Add try/catch to handle expected failures explicitly,"
                                            + " configure a dead-letter topic or queue for"
                                            + " unrecoverable messages, and log errors with enough"
                                            + " context for investigation.")
                            .evidence(
                                    "@"
                                            + presentAnnotation
                                            + " method "
                                            + method.getNameAsString()
                                            + " found without exception handling in "
                                            + relativePath
                                            + ".")
                            .limitations(
                                    "Static analysis cannot verify whether a container-level error"
                                            + " handler or retry policy is configured for this"
                                            + " listener.")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_PATH_VARIABLE_TEMPLATE_MISMATCH
    // ---------------------------------------------------------------------------

    private static final Set<String> REQUEST_MAPPING_ANNOTATIONS =
            Set.of(
                    "RequestMapping",
                    "GetMapping",
                    "PostMapping",
                    "PutMapping",
                    "DeleteMapping",
                    "PatchMapping");

    private static final java.util.regex.Pattern TEMPLATE_VARIABLE_PATTERN =
            java.util.regex.Pattern.compile("\\{([^}/]+)\\}");

    /**
     * Flags handler parameters whose explicit {@code @PathVariable("name")} matches no
     * {@code {name}} variable in the merged class+method mapping template. Spring throws
     * {@code MissingPathVariableException} (HTTP 500) on every invocation of such a handler.
     * Skipped entirely when any mapping path is a non-literal expression or contains a property
     * placeholder, and for {@code @PathVariable} parameters without an explicit name (their
     * binding depends on compiled parameter names, which static analysis cannot judge).
     */
    private void detectPathVariableTemplateMismatch(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        AnnotationExpr mapping =
                method.getAnnotations().stream()
                        .filter(
                                a ->
                                        REQUEST_MAPPING_ANNOTATIONS.contains(
                                                simpleName(a.getNameAsString())))
                        .findFirst()
                        .orElse(null);
        if (mapping == null) {
            return;
        }
        List<String> methodPaths = mappingPathLiterals(mapping);
        if (methodPaths == null) {
            return;
        }
        // Spring merges @RequestMapping from superclasses and implemented interfaces. Those
        // templates are not visible here, so a controller with a supertype could declare the
        // variable elsewhere — stay conservative and skip.
        if (!declaration.getExtendedTypes().isEmpty()
                || !declaration.getImplementedTypes().isEmpty()) {
            return;
        }
        List<String> allPaths = new ArrayList<>(methodPaths);
        for (AnnotationExpr classAnnotation : declaration.getAnnotations()) {
            if (!REQUEST_MAPPING_ANNOTATIONS.contains(
                    simpleName(classAnnotation.getNameAsString()))) {
                continue;
            }
            List<String> classPaths = mappingPathLiterals(classAnnotation);
            if (classPaths == null) {
                return;
            }
            allPaths.addAll(classPaths);
        }
        Set<String> templateVariables = new HashSet<>();
        for (String path : allPaths) {
            if (path.contains("${")) {
                return;
            }
            var matcher = TEMPLATE_VARIABLE_PATTERN.matcher(path);
            while (matcher.find()) {
                String variable = matcher.group(1);
                int colon = variable.indexOf(':');
                if (colon >= 0) {
                    variable = variable.substring(0, colon);
                }
                if (variable.startsWith("*")) {
                    variable = variable.substring(1);
                }
                templateVariables.add(variable.trim());
            }
        }
        for (Parameter parameter : method.getParameters()) {
            AnnotationExpr pathVariable =
                    parameter.getAnnotationByName("PathVariable").orElse(null);
            if (pathVariable == null) {
                continue;
            }
            String explicitName = null;
            if (pathVariable.isSingleMemberAnnotationExpr()
                    && pathVariable
                            .asSingleMemberAnnotationExpr()
                            .getMemberValue()
                            .isStringLiteralExpr()) {
                explicitName =
                        pathVariable
                                .asSingleMemberAnnotationExpr()
                                .getMemberValue()
                                .asStringLiteralExpr()
                                .asString();
            } else if (pathVariable.isNormalAnnotationExpr()) {
                for (var pair : pathVariable.asNormalAnnotationExpr().getPairs()) {
                    String pairName = pair.getNameAsString();
                    if (("value".equals(pairName) || "name".equals(pairName))
                            && pair.getValue().isStringLiteralExpr()) {
                        explicitName = pair.getValue().asStringLiteralExpr().asString();
                    }
                }
            }
            if (explicitName == null || templateVariables.contains(explicitName)) {
                continue;
            }
            Integer line = parameter.getBegin().map(p -> p.line).orElse(null);
            String target = declaration.getNameAsString() + "#" + method.getNameAsString();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_PATH_VARIABLE_TEMPLATE_MISMATCH,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "@PathVariable(\""
                                            + explicitName
                                            + "\") on "
                                            + target
                                            + " matches no {variable} in the mapping template.")
                            .whyBadPractice(
                                    "Spring resolves @PathVariable values from the URI template"
                                            + " variables of the merged class+method mapping. A"
                                            + " variable name that appears in no template cannot be"
                                            + " resolved, so the handler throws"
                                            + " MissingPathVariableException on every request —"
                                            + " typically after a rename touched only one side.")
                            .possibleImpact(
                                    "The endpoint deploys cleanly but returns HTTP 500 on every"
                                            + " single invocation.")
                            .recommendation(
                                    "Align the names: add {"
                                            + explicitName
                                            + "} to the mapping path or correct the @PathVariable"
                                            + " value to one of the declared template variables ("
                                            + (templateVariables.isEmpty()
                                                    ? "none declared"
                                                    : String.join(", ", templateVariables))
                                            + ").")
                            .evidence(
                                    "@PathVariable(\""
                                            + explicitName
                                            + "\") found on "
                                            + target
                                            + " in "
                                            + relativePath
                                            + "; mapping paths: "
                                            + (allPaths.isEmpty()
                                                    ? "(none)"
                                                    : String.join(", ", allPaths))
                                            + ".")
                            .limitations(
                                    "Only literal mapping paths are checked; handlers whose paths"
                                        + " come from constants, expressions, or placeholders are"
                                        + " skipped. @PathVariable parameters without an explicit"
                                        + " name are not checked.")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    /**
     * Returns the literal path strings of a mapping annotation: empty list for a marker
     * annotation, the collected string literals for single-member/normal forms, or {@code null}
     * when any path value is a non-literal expression (constant reference, concatenation, …).
     */
    private List<String> mappingPathLiterals(AnnotationExpr annotation) {
        if (annotation.isMarkerAnnotationExpr()) {
            return List.of();
        }
        if (annotation.isSingleMemberAnnotationExpr()) {
            return literalStrings(annotation.asSingleMemberAnnotationExpr().getMemberValue());
        }
        if (annotation.isNormalAnnotationExpr()) {
            List<String> paths = new ArrayList<>();
            for (var pair : annotation.asNormalAnnotationExpr().getPairs()) {
                String pairName = pair.getNameAsString();
                if (!"value".equals(pairName) && !"path".equals(pairName)) {
                    continue;
                }
                List<String> literals = literalStrings(pair.getValue());
                if (literals == null) {
                    return null;
                }
                paths.addAll(literals);
            }
            return paths;
        }
        return List.of();
    }

    private List<String> literalStrings(com.github.javaparser.ast.expr.Expression expression) {
        if (expression.isStringLiteralExpr()) {
            return List.of(expression.asStringLiteralExpr().asString());
        }
        if (expression.isArrayInitializerExpr()) {
            List<String> values = new ArrayList<>();
            for (var value : expression.asArrayInitializerExpr().getValues()) {
                if (!value.isStringLiteralExpr()) {
                    return null;
                }
                values.add(value.asStringLiteralExpr().asString());
            }
            return values;
        }
        return null;
    }

    /**
     * Flags {@code @OneToOne} associations declaring both {@code mappedBy} and
     * {@code fetch = FetchType.LAZY}. Hibernate cannot honour LAZY on the inverse (non-owning)
     * side of a one-to-one without bytecode enhancement: the foreign key lives in the owning
     * table, so Hibernate must query it anyway to decide between {@code null} and a proxy — the
     * association silently loads eagerly.
     */
    private void detectOneToOneMappedByLazy(
            String relativePath,
            AnnotationExpr annotation,
            String annotationName,
            String target,
            Integer line,
            List<Finding> findings) {
        if (!"OneToOne".equals(annotationName) || !annotation.isNormalAnnotationExpr()) {
            return;
        }
        var pairs = annotation.asNormalAnnotationExpr().getPairs();
        boolean hasMappedBy = pairs.stream().anyMatch(p -> p.getNameAsString().equals("mappedBy"));
        boolean lazyFetch =
                pairs.stream()
                        .anyMatch(
                                p ->
                                        p.getNameAsString().equals("fetch")
                                                && p.getValue().toString().endsWith("LAZY"));
        if (!hasMappedBy || !lazyFetch) {
            return;
        }
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_JPA_ONETOONE_MAPPEDBY_LAZY_IGNORED,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@OneToOne(mappedBy, fetch = LAZY) on "
                                        + target
                                        + " — LAZY is silently ignored on the inverse side.")
                        .whyBadPractice(
                                "The inverse (mappedBy) side of a @OneToOne cannot be lazy without"
                                    + " bytecode enhancement. The foreign key lives in the owning"
                                    + " table, so Hibernate must query it anyway to decide whether"
                                    + " to populate null or a proxy — and therefore loads the"
                                    + " association eagerly despite the explicit LAZY hint.")
                        .possibleImpact(
                                "Every load of this entity issues an extra query the developer"
                                    + " believes is deferred — a hidden N+1 source that is hard to"
                                    + " spot because the mapping looks correctly lazy.")
                        .recommendation(
                                "Model the association from the owning side (@OneToOne with"
                                    + " @JoinColumn is lazy-capable), map it as a @ManyToOne, use"
                                    + " @MapsId to share the primary key, or enable Hibernate"
                                    + " bytecode enhancement if inverse-side laziness is truly"
                                    + " required.")
                        .evidence(
                                "@OneToOne with both mappedBy and fetch = FetchType.LAZY found on "
                                        + target
                                        + " in "
                                        + relativePath
                                        + ".")
                        .limitations(
                                "Projects using the Hibernate bytecode-enhancement plugin can make"
                                        + " the inverse side genuinely lazy; that build-level setup"
                                        + " is not visible to this check.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private void detectJpaRelationshipRisks(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        String className = declaration.getNameAsString();
        for (FieldDeclaration field : declaration.getFields()) {
            for (AnnotationExpr annotation : field.getAnnotations()) {
                String annotationName = simpleName(annotation.getNameAsString());
                if (!Set.of("OneToMany", "ManyToOne", "OneToOne", "ManyToMany")
                        .contains(annotationName)) {
                    continue;
                }
                String fieldName =
                        field.getVariables().isEmpty()
                                ? "?"
                                : field.getVariables().get(0).getNameAsString();
                Integer line = field.getBegin().map(position -> position.line).orElse(null);
                String target = className + "." + fieldName;
                if (annotationName.equals("OneToMany") || annotationName.equals("ManyToMany")) {
                    boolean hasMappedBy =
                            annotation.isNormalAnnotationExpr()
                                    && annotation.asNormalAnnotationExpr().getPairs().stream()
                                            .anyMatch(
                                                    pair ->
                                                            pair.getNameAsString()
                                                                    .equals("mappedBy"));
                    // Only @OneToMany is checked: a @ManyToMany owning side MUST lack mappedBy,
                    // so flagging it would hit every correctly mapped association. Fields with an
                    // explicit @JoinColumn/@JoinTable are deliberate unidirectional mappings —
                    // @OneToMany + @JoinColumn maps a plain FK column and creates no join table.
                    boolean hasExplicitJoinMapping =
                            hasAnnotation(field.getAnnotations(), "JoinColumn")
                                    || hasAnnotation(field.getAnnotations(), "JoinTable");
                    if (annotationName.equals("OneToMany")
                            && !hasMappedBy
                            && !hasExplicitJoinMapping) {
                        findings.add(
                                FindingFactory.builder(
                                                FindingRules.SPRING_JPA_ONETOMANY_MISSING_MAPPED_BY,
                                                FindingConfidence.MEDIUM)
                                        .shortMessage(
                                                "@OneToMany on "
                                                        + target
                                                        + " has neither mappedBy nor @JoinColumn.")
                                        .whyBadPractice(
                                                "A bare @OneToMany without mappedBy (and without an"
                                                    + " explicit @JoinColumn) makes this the owning"
                                                    + " side, and Hibernate maps it through an"
                                                    + " additional join table even though a foreign"
                                                    + " key column in the child table would"
                                                    + " suffice.")
                                        .possibleImpact(
                                                "The schema contains an unexpected join table,"
                                                    + " resulting in extra writes on every save and"
                                                    + " a data model that is harder to query and"
                                                    + " maintain.")
                                        .recommendation(
                                                "For a bidirectional association, add mappedBy"
                                                    + " referencing the owning @ManyToOne field."
                                                    + " For an intentional unidirectional"
                                                    + " association, add an explicit @JoinColumn to"
                                                    + " map a foreign key column instead of a join"
                                                    + " table.")
                                        .evidence(
                                                "@OneToMany on field "
                                                        + fieldName
                                                        + " in "
                                                        + relativePath
                                                        + " has neither a mappedBy attribute nor a"
                                                        + " @JoinColumn/@JoinTable annotation.")
                                        .limitations(
                                                "Static analysis cannot determine whether a"
                                                    + " unidirectional relationship and join table"
                                                    + " are intentional design choices.")
                                        .source(relativePath, line)
                                        .target(target)
                                        .build());
                    }
                    detectCollectionEagerFetch(
                            relativePath, annotation, annotationName, target, line, findings);
                    detectManyToManyCascadeRemove(
                            relativePath, annotation, annotationName, target, line, findings);
                } else {
                    detectOneToOneMappedByLazy(
                            relativePath, annotation, annotationName, target, line, findings);
                    boolean hasFetchType =
                            annotation.isNormalAnnotationExpr()
                                    && annotation.asNormalAnnotationExpr().getPairs().stream()
                                            .anyMatch(
                                                    pair -> pair.getNameAsString().equals("fetch"));
                    // On the inverse (mappedBy) side of a @OneToOne, "add fetch = LAZY" would be
                    // anti-advice: Hibernate ignores LAZY there (see
                    // SPRING_JPA_ONETOONE_MAPPEDBY_LAZY_IGNORED), so don't recommend it.
                    boolean inverseOneToOne =
                            "OneToOne".equals(annotationName)
                                    && annotation.isNormalAnnotationExpr()
                                    && annotation.asNormalAnnotationExpr().getPairs().stream()
                                            .anyMatch(
                                                    pair ->
                                                            pair.getNameAsString()
                                                                    .equals("mappedBy"));
                    if (!hasFetchType && !inverseOneToOne) {
                        findings.add(
                                FindingFactory.builder(
                                                FindingRules.SPRING_JPA_MANYTOONE_EAGER_DEFAULT,
                                                FindingConfidence.HIGH)
                                        .shortMessage(
                                                "@"
                                                        + annotationName
                                                        + " on "
                                                        + target
                                                        + " uses eager loading by default.")
                                        .whyBadPractice(
                                                "@ManyToOne and @OneToOne load the related entity"
                                                    + " eagerly by default, meaning every query for"
                                                    + " the owning entity also fetches the related"
                                                    + " entity even when it is not needed.")
                                        .possibleImpact(
                                                "Unnecessary queries on every load can cause"
                                                        + " performance problems, especially when"
                                                        + " fetching collections of entities.")
                                        .recommendation(
                                                "Add fetch = FetchType.LAZY explicitly and use JOIN"
                                                    + " FETCH in queries or entity graphs when the"
                                                    + " related entity is needed.")
                                        .evidence(
                                                "@"
                                                        + annotationName
                                                        + " on field "
                                                        + fieldName
                                                        + " in "
                                                        + relativePath
                                                        + " has no fetch attribute.")
                                        .limitations(
                                                "Static analysis cannot determine actual query"
                                                        + " patterns or whether eager loading is"
                                                        + " intentionally desired for this"
                                                        + " relationship.")
                                        .source(relativePath, line)
                                        .target(target)
                                        .build());
                    }
                }
            }
        }
    }

    private void detectBeanInNonConfigurationClass(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        for (MethodDeclaration method : declaration.getMethods()) {
            if (!hasAnnotation(method.getAnnotations(), "Bean")) {
                continue;
            }
            Integer line = method.getBegin().map(position -> position.line).orElse(null);
            String target = declaration.getNameAsString() + "#" + method.getNameAsString();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_BEAN_ON_NON_CONFIGURATION,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "@Bean method "
                                            + target
                                            + " is in a class without @Configuration (lite mode).")
                            .whyBadPractice(
                                    "In lite mode, Spring does not apply CGLIB proxying to the"
                                        + " class. Direct calls to @Bean methods from within the"
                                        + " same class create new instances rather than returning"
                                        + " the managed singleton from the container.")
                            .possibleImpact(
                                    "Dependencies between beans defined in the same class can"
                                        + " receive different instances than the Spring container"
                                        + " manages, causing subtle wiring bugs that are hard to"
                                        + " diagnose.")
                            .recommendation(
                                    "Annotate the class with @Configuration to enable full CGLIB"
                                            + " proxy mode, or move the @Bean method to a dedicated"
                                            + " @Configuration class.")
                            .evidence(
                                    "@Bean method "
                                            + method.getNameAsString()
                                            + " found in class "
                                            + declaration.getNameAsString()
                                            + " without @Configuration in "
                                            + relativePath
                                            + ".")
                            .limitations(
                                    "Lite mode may be intentional for simple factory methods that"
                                        + " are never called directly from within the same class.")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    private static final Set<String> INJECTION_ANNOTATIONS =
            Set.of("Autowired", "Inject", "Resource", "Value");

    private void detectInjectionOnStaticField(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            FieldDeclaration field,
            List<Finding> findings) {
        String fieldName =
                field.getVariables().isEmpty()
                        ? "?"
                        : field.getVariables().get(0).getNameAsString();
        String annotationName =
                field.getAnnotations().stream()
                        .map(annotation -> simpleName(annotation.getNameAsString()))
                        .filter(INJECTION_ANNOTATIONS::contains)
                        .findFirst()
                        .orElse("Autowired");
        String target = declaration.getNameAsString() + "." + fieldName;
        Integer line = field.getBegin().map(position -> position.line).orElse(null);
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_INJECTION_ON_STATIC_FIELD,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@"
                                        + annotationName
                                        + " on static field "
                                        + target
                                        + " — Spring cannot inject into static fields.")
                        .whyBadPractice(
                                "Spring's dependency injection populates instance fields on the"
                                    + " bean it creates. A static field belongs to the class, not"
                                    + " the instance, so the container never assigns it. The"
                                    + " annotation is silently ignored and the field keeps its"
                                    + " default value (null for reference types).")
                        .possibleImpact(
                                "The first use of the field throws NullPointerException at runtime."
                                        + " Because the application starts cleanly, the failure"
                                        + " surfaces only when the code path that reads the field"
                                        + " executes.")
                        .recommendation(
                                "Remove the static modifier and inject the dependency normally"
                                    + " (constructor injection preferred). If the value genuinely"
                                    + " must be static, set it from a non-static setter or"
                                    + " @PostConstruct method that copies an injected instance"
                                    + " field into the static field.")
                        .evidence(
                                "@"
                                        + annotationName
                                        + " found on static field "
                                        + fieldName
                                        + " in "
                                        + relativePath
                                        + ".")
                        .limitations(
                                "Some projects deliberately copy an injected instance value into a"
                                    + " static field via a setter; that pattern is not flagged"
                                    + " because the annotation is on the setter, not the field.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private void detectFieldInjection(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            FieldDeclaration field,
            List<Finding> findings) {
        String fieldName =
                field.getVariables().isEmpty()
                        ? "?"
                        : field.getVariables().get(0).getNameAsString();
        String target = declaration.getNameAsString() + "." + fieldName;
        Integer line = field.getBegin().map(position -> position.line).orElse(null);
        findings.add(
                FindingFactory.builder(FindingRules.SPRING_FIELD_INJECTION, FindingConfidence.HIGH)
                        .shortMessage("Field injection via @Autowired in " + target + ".")
                        .whyBadPractice(
                                "Field injection hides dependencies from the class API, makes the"
                                        + " class harder to instantiate in tests without a Spring"
                                        + " context, and can enable circular dependency wiring that"
                                        + " would fail with constructor injection.")
                        .possibleImpact(
                                "Tests require a full Spring context or reflection tricks to inject"
                                    + " mocks. Circular dependencies may be silently resolved in an"
                                    + " order that is hard to reason about.")
                        .recommendation(
                                "Use constructor injection instead. Declare dependencies as final"
                                    + " fields and inject them via a constructor. This makes"
                                    + " dependencies explicit, enables immutability, and fails fast"
                                    + " on circular dependencies.")
                        .evidence(
                                "@Autowired found on field "
                                        + fieldName
                                        + " in "
                                        + relativePath
                                        + ".")
                        .limitations(
                                "Field injection is sometimes intentional in test code or legacy"
                                        + " classes. Some Spring-specific injection points such as"
                                        + " @Value on fields require field access.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private void detectValueWithoutDefault(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            FieldDeclaration field,
            List<Finding> findings) {
        field.getAnnotationByName("Value")
                .ifPresent(
                        annotation -> {
                            String expr =
                                    annotation.isSingleMemberAnnotationExpr()
                                            ? annotation
                                                    .asSingleMemberAnnotationExpr()
                                                    .getMemberValue()
                                                    .toString()
                                            : annotation.isNormalAnnotationExpr()
                                                    ? annotation
                                                            .asNormalAnnotationExpr()
                                                            .getPairs()
                                                            .stream()
                                                            .filter(
                                                                    p ->
                                                                            "value"
                                                                                    .equals(
                                                                                            p
                                                                                                    .getNameAsString()))
                                                            .map(p -> p.getValue().toString())
                                                            .findFirst()
                                                            .orElse("")
                                                    : "";
                            if (expr.contains("${") && hasTopLevelPlaceholderWithoutDefault(expr)) {
                                String fieldName =
                                        field.getVariables().isEmpty()
                                                ? "?"
                                                : field.getVariables().get(0).getNameAsString();
                                String target = declaration.getNameAsString() + "." + fieldName;
                                Integer line =
                                        field.getBegin()
                                                .map(position -> position.line)
                                                .orElse(null);
                                findings.add(
                                        FindingFactory.builder(
                                                        FindingRules.SPRING_VALUE_NO_DEFAULT,
                                                        FindingConfidence.MEDIUM)
                                                .shortMessage(
                                                        "@Value(\""
                                                                + expr.replace("\"", "")
                                                                + "\") on "
                                                                + target
                                                                + " has no default value.")
                                                .whyBadPractice(
                                                        "@Value expressions without a default cause"
                                                            + " an immediate startup failure with a"
                                                            + " BeanCreationException if the"
                                                            + " property is not present in the"
                                                            + " environment, regardless of whether"
                                                            + " the bean is actually used.")
                                                .possibleImpact(
                                                        "A missing property in any environment"
                                                            + " causes a hard startup failure. This"
                                                            + " is unforgiving in environments"
                                                            + " where not all properties are always"
                                                            + " provided.")
                                                .recommendation(
                                                        "Add a default with the colon syntax:"
                                                            + " @Value(\"${property.name:defaultValue}\")."
                                                            + " Use an empty string or null default"
                                                            + " only if the absent case is handled"
                                                            + " explicitly in the code.")
                                                .evidence(
                                                        "@Value without default found on "
                                                                + fieldName
                                                                + " in "
                                                                + relativePath
                                                                + ".")
                                                .limitations(
                                                        "Static analysis cannot determine whether"
                                                            + " the property is guaranteed to be"
                                                            + " present in all target"
                                                            + " environments.")
                                                .source(relativePath, line)
                                                .target(target)
                                                .build());
                            }
                        });
    }

    private void detectModifyingNoTransaction(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        Integer line = method.getBegin().map(position -> position.line).orElse(null);
        String target = declaration.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_MODIFYING_NO_TRANSACTION,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@Modifying query " + target + " has no @Transactional boundary.")
                        .whyBadPractice(
                                "Spring Data JPA requires a transaction for @Modifying queries."
                                        + " Without one, the repository throws"
                                        + " TransactionRequiredException at runtime on every"
                                        + " invocation.")
                        .possibleImpact(
                                "Every call to this method fails with a runtime exception. The"
                                    + " absence of a transaction is not detectable at compile time"
                                    + " or startup.")
                        .recommendation(
                                "Add @Transactional to the repository method or to the service"
                                        + " method that calls it.")
                        .evidence(
                                "@Modifying found without @Transactional on "
                                        + method.getNameAsString()
                                        + " in "
                                        + relativePath
                                        + ".")
                        .limitations(
                                "Visible source callers with eligible @Transactional boundaries or"
                                    + " TransactionTemplate callbacks are suppressed. Reflection,"
                                    + " unresolved overloads, and callers outside the analyzed"
                                    + " source may still be missed.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private void detectTransactionalOnScheduled(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        Integer line = method.getBegin().map(position -> position.line).orElse(null);
        String target = declaration.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_TRANSACTIONAL_ON_SCHEDULED,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@Transactional and @Scheduled are both present on " + target + ".")
                        .whyBadPractice(
                                "@Scheduled methods run in a dedicated scheduler thread that has no"
                                    + " existing transaction. @Transactional on the same method may"
                                    + " create a transaction, but it cannot be propagated or rolled"
                                    + " back by an outer caller because there is none.")
                        .possibleImpact(
                                "Transaction behaviour becomes implicit and hard to reason about."
                                    + " Failures in the scheduled method may not roll back as"
                                    + " expected, and long transactions in the scheduler thread can"
                                    + " hold database connections for the full scheduled interval.")
                        .recommendation(
                                "Extract the transactional work into a separate service method"
                                        + " annotated with @Transactional, and call it from the"
                                        + " @Scheduled method. This makes the transaction boundary"
                                        + " explicit and keeps the scheduler method a thin"
                                        + " orchestration layer.")
                        .evidence(
                                "Both @Transactional and @Scheduled found on method "
                                        + method.getNameAsString()
                                        + " in "
                                        + relativePath
                                        + ".")
                        .limitations(
                                "Static analysis cannot determine whether the transaction actually"
                                        + " causes problems in the specific scheduler thread pool"
                                        + " configuration used at runtime.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private void detectRequestMappingNoMethod(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        method.getAnnotationByName("RequestMapping")
                .ifPresent(
                        annotation -> {
                            boolean hasMethodAttr =
                                    annotation.isNormalAnnotationExpr()
                                            && annotation
                                                    .asNormalAnnotationExpr()
                                                    .getPairs()
                                                    .stream()
                                                    .anyMatch(
                                                            pair ->
                                                                    "method"
                                                                            .equals(
                                                                                    pair
                                                                                            .getNameAsString()));
                            if (!hasMethodAttr) {
                                Integer line =
                                        method.getBegin()
                                                .map(position -> position.line)
                                                .orElse(null);
                                String target =
                                        declaration.getNameAsString()
                                                + "#"
                                                + method.getNameAsString();
                                findings.add(
                                        FindingFactory.builder(
                                                        FindingRules
                                                                .SPRING_REQUEST_MAPPING_NO_METHOD,
                                                        FindingConfidence.HIGH)
                                                .shortMessage(
                                                        "@RequestMapping on "
                                                                + target
                                                                + " has no HTTP method constraint.")
                                                .whyBadPractice(
                                                        "@RequestMapping without a method attribute"
                                                            + " matches all HTTP verbs (GET, POST,"
                                                            + " PUT, DELETE, PATCH, etc.). This is"
                                                            + " broader than almost any endpoint"
                                                            + " actually needs.")
                                                .possibleImpact(
                                                        "Mutation endpoints can be called with GET"
                                                            + " (and thus by browsers navigating a"
                                                            + " URL). Read endpoints can receive"
                                                            + " POSTs with bodies. This makes the"
                                                            + " API surface wider than intended.")
                                                .recommendation(
                                                        "Replace @RequestMapping with a specific"
                                                            + " annotation such as @GetMapping,"
                                                            + " @PostMapping, @PutMapping,"
                                                            + " @PatchMapping, or @DeleteMapping,"
                                                            + " or add method = RequestMethod.GET"
                                                            + " to the existing annotation.")
                                                .evidence(
                                                        "@RequestMapping with no method attribute"
                                                                + " found on "
                                                                + method.getNameAsString()
                                                                + " in "
                                                                + relativePath
                                                                + ".")
                                                .limitations(
                                                        "Static analysis cannot determine whether"
                                                            + " the broad method mapping is"
                                                            + " intentional, for example for CORS"
                                                            + " preflight or protocol negotiation.")
                                                .source(relativePath, line)
                                                .target(target)
                                                .build());
                            }
                        });
    }

    private void detectSensitiveRequestParams(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        for (Parameter parameter : method.getParameters()) {
            String sensitiveAnnotation = null;
            String paramValue = null;
            for (AnnotationExpr annotation : parameter.getAnnotations()) {
                String annotationName = simpleName(annotation.getNameAsString());
                if (!annotationName.equals("RequestParam")
                        && !annotationName.equals("PathVariable")) {
                    continue;
                }
                String nameValue =
                        annotation.isSingleMemberAnnotationExpr()
                                ? annotation
                                        .asSingleMemberAnnotationExpr()
                                        .getMemberValue()
                                        .toString()
                                        .replace("\"", "")
                                : annotation.isNormalAnnotationExpr()
                                        ? annotation.asNormalAnnotationExpr().getPairs().stream()
                                                .filter(
                                                        p ->
                                                                "value".equals(p.getNameAsString())
                                                                        || "name"
                                                                                .equals(
                                                                                        p
                                                                                                .getNameAsString()))
                                                .map(p -> p.getValue().toString().replace("\"", ""))
                                                .findFirst()
                                                .orElse(parameter.getNameAsString())
                                        : parameter.getNameAsString();
                if (SENSITIVE_PARAM_NAMES.contains(nameValue.toLowerCase(Locale.ROOT))) {
                    sensitiveAnnotation = annotationName;
                    paramValue = nameValue;
                    break;
                }
            }
            if (sensitiveAnnotation != null) {
                Integer line = method.getBegin().map(position -> position.line).orElse(null);
                String target = declaration.getNameAsString() + "#" + method.getNameAsString();
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_REQUEST_PARAM_SENSITIVE_NAME,
                                        FindingConfidence.HIGH)
                                .shortMessage(
                                        "Sensitive value '"
                                                + paramValue
                                                + "' passed as @"
                                                + sensitiveAnnotation
                                                + " in "
                                                + target
                                                + ".")
                                .whyBadPractice(
                                        "Passwords, tokens, and secrets passed as URL parameters or"
                                            + " path variables appear in server access logs,"
                                            + " browser history, proxy logs, and referrer headers"
                                            + " in plaintext.")
                                .possibleImpact(
                                        "Credentials are exposed in any log aggregation system that"
                                                + " captures request URLs, making them visible to"
                                                + " operators and making log-based security audits"
                                                + " harder.")
                                .recommendation(
                                        "Pass sensitive values in the request body (POST/PUT) or in"
                                                + " an Authorization or custom header, never in the"
                                                + " URL.")
                                .evidence(
                                        "@"
                                                + sensitiveAnnotation
                                                + "(\""
                                                + paramValue
                                                + "\") found in "
                                                + method.getNameAsString()
                                                + " in "
                                                + relativePath
                                                + ".")
                                .limitations(
                                        "Static analysis cannot determine whether the URL is only"
                                            + " ever called over HTTPS, but even encrypted URLs are"
                                            + " logged in plaintext on the server side.")
                                .source(relativePath, line)
                                .target(target)
                                .build());
            }
        }
    }

    private void detectConfigPropertiesNotValidated(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        String className = declaration.getNameAsString();
        Integer line = declaration.getBegin().map(position -> position.line).orElse(null);
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_CONFIGURATION_PROPERTIES_NOT_VALIDATED,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@ConfigurationProperties class "
                                        + className
                                        + " has no @Validated annotation.")
                        .whyBadPractice(
                                "Without @Validated, constraint annotations such as @NotNull, @Min,"
                                    + " @Max, and @Pattern on the properties class fields are"
                                    + " silently ignored. Invalid configuration is not caught at"
                                    + " startup.")
                        .possibleImpact(
                                "A misconfigured value (null, out of range, wrong format) reaches"
                                    + " the application logic instead of failing fast at startup,"
                                    + " potentially causing hard-to-diagnose runtime errors.")
                        .recommendation(
                                "Add @Validated to the @ConfigurationProperties class and annotate"
                                        + " fields with appropriate Bean Validation constraints.")
                        .evidence(
                                "@ConfigurationProperties without @Validated found on class "
                                        + className
                                        + " in "
                                        + relativePath
                                        + ".")
                        .limitations(
                                "Static analysis cannot determine whether validation is performed"
                                        + " elsewhere, or whether the configuration is always"
                                        + " guaranteed to be valid by deployment tooling.")
                        .source(relativePath, line)
                        .target(className)
                        .build());
    }

    private void detectCsrfDisabled(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        for (MethodDeclaration method : declaration.getMethods()) {
            List<MethodCallExpr> allCalls = method.findAll(MethodCallExpr.class);
            for (MethodCallExpr call : allCalls) {
                boolean isDisableCall =
                        "disable".equals(call.getNameAsString())
                                && call.getScope()
                                        .map(Object::toString)
                                        .orElse("")
                                        .contains("csrf");
                boolean isCsrfLambdaDisable =
                        "csrf".equals(call.getNameAsString())
                                && call.getArguments().stream()
                                        .anyMatch(arg -> arg.toString().contains("disable"));
                if (isDisableCall || isCsrfLambdaDisable) {
                    Integer line =
                            call.getName().getBegin().map(position -> position.line).orElse(null);
                    findings.add(
                            FindingFactory.builder(
                                            FindingRules.SPRING_CSRF_DISABLED,
                                            FindingConfidence.HIGH)
                                    .shortMessage(
                                            "CSRF protection is disabled in "
                                                    + declaration.getNameAsString()
                                                    + "#"
                                                    + method.getNameAsString()
                                                    + ".")
                                    .whyBadPractice(
                                            "CSRF protection prevents forged cross-origin requests"
                                                + " from tricking authenticated users into"
                                                + " performing unintended actions. Disabling it"
                                                + " removes this protection for all browser-based"
                                                + " clients.")
                                    .possibleImpact(
                                            "State-changing endpoints can be invoked by malicious"
                                                    + " sites using an authenticated user's session"
                                                    + " without their knowledge.")
                                    .recommendation(
                                            "Keep CSRF enabled. If the application is a stateless"
                                                + " REST API using token-based authentication"
                                                + " (JWT/Bearer) and has no browser session, CSRF"
                                                + " protection is unnecessary — but document that"
                                                + " decision explicitly.")
                                    .evidence(
                                            "csrf().disable() or equivalent pattern found in "
                                                    + relativePath
                                                    + ".")
                                    .limitations(
                                            "Static analysis cannot determine whether the"
                                                + " application uses stateless token authentication"
                                                + " that makes CSRF irrelevant.")
                                    .source(relativePath, line)
                                    .target(
                                            declaration.getNameAsString()
                                                    + "#"
                                                    + method.getNameAsString())
                                    .build());
                    return;
                }
            }
        }
    }

    private void detectCorsAllowAll(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        for (MethodDeclaration method : declaration.getMethods()) {
            // A wildcard origin combined with allowCredentials(true) is the strictly worse
            // variant reported by SPRING_CORS_CREDENTIALS_WILDCARD; reporting both would emit
            // two findings for the same CORS configuration.
            if (methodAllowsCorsCredentials(method)) {
                continue;
            }
            for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {
                boolean isAllowedOrigins =
                        call.getNameAsString().equals("allowedOrigins")
                                || call.getNameAsString().equals("setAllowedOrigins")
                                || call.getNameAsString().equals("allowedOriginPatterns");
                if (!isAllowedOrigins) {
                    continue;
                }
                boolean hasWildcard =
                        call.getArguments().stream()
                                .anyMatch(arg -> arg.toString().contains("\"*\""));
                if (hasWildcard) {
                    Integer line =
                            call.getName().getBegin().map(position -> position.line).orElse(null);
                    findings.add(
                            FindingFactory.builder(
                                            FindingRules.SPRING_CORS_ALLOW_ALL,
                                            FindingConfidence.HIGH)
                                    .shortMessage(
                                            "CORS wildcard allowedOrigins(\"*\") found in "
                                                    + declaration.getNameAsString()
                                                    + "#"
                                                    + method.getNameAsString()
                                                    + ".")
                                    .whyBadPractice(
                                            "Allowing all origins removes the same-origin"
                                                + " protection that browsers enforce by default."
                                                + " Any website can make cross-origin requests to"
                                                + " the API on behalf of a user.")
                                    .possibleImpact(
                                            "Browser-based attacks can read API responses from any"
                                                + " origin. Combined with cookie-based"
                                                + " authentication, this can expose user data to"
                                                + " third-party sites.")
                                    .recommendation(
                                            "Restrict allowedOrigins to an explicit allowlist of"
                                                    + " trusted domains. If the API is public and"
                                                    + " stateless, a wildcard may be acceptable but"
                                                    + " should be an explicit decision.")
                                    .evidence(
                                            "allowedOrigins(\"*\") or equivalent found in "
                                                    + relativePath
                                                    + ".")
                                    .limitations(
                                            "Static analysis cannot determine whether the API uses"
                                                    + " stateless authentication that makes the"
                                                    + " wildcard safe, or whether this is an"
                                                    + " internal-only endpoint.")
                                    .source(relativePath, line)
                                    .target(
                                            declaration.getNameAsString()
                                                    + "#"
                                                    + method.getNameAsString())
                                    .build());
                    return;
                }
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_CORS_CREDENTIALS_WILDCARD
    // ---------------------------------------------------------------------------

    private static boolean methodAllowsCorsCredentials(MethodDeclaration method) {
        return method.findAll(MethodCallExpr.class).stream()
                .anyMatch(
                        call ->
                                (call.getNameAsString().equals("allowCredentials")
                                                || call.getNameAsString()
                                                        .equals("setAllowCredentials"))
                                        && call.getArguments().stream()
                                                .anyMatch(arg -> arg.toString().contains("true")));
    }

    private void detectCorsCredentialsWildcard(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        for (MethodDeclaration method : declaration.getMethods()) {
            boolean wildcardOrigin = false;
            boolean allowCredentials = false;
            Integer line = null;
            for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {
                String name = call.getNameAsString();
                if ((name.equals("allowedOrigins")
                                || name.equals("setAllowedOrigins")
                                || name.equals("allowedOriginPatterns")
                                || name.equals("setAllowedOriginPatterns"))
                        && call.getArguments().stream()
                                .anyMatch(arg -> arg.toString().contains("\"*\""))) {
                    wildcardOrigin = true;
                    if (line == null) {
                        line =
                                call.getName()
                                        .getBegin()
                                        .map(position -> position.line)
                                        .orElse(null);
                    }
                }
                if ((name.equals("allowCredentials") || name.equals("setAllowCredentials"))
                        && call.getArguments().stream()
                                .anyMatch(
                                        arg ->
                                                arg instanceof BooleanLiteralExpr bool
                                                        && bool.getValue())) {
                    allowCredentials = true;
                }
            }
            if (!wildcardOrigin || !allowCredentials) {
                continue;
            }
            String target = declaration.getNameAsString() + "#" + method.getNameAsString();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_CORS_CREDENTIALS_WILDCARD,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "CORS allows credentials with a wildcard origin in "
                                            + target
                                            + ".")
                            .whyBadPractice(
                                    "Combining a wildcard origin (allowedOriginPatterns(\"*\") or"
                                        + " allowedOrigins(\"*\")) with allowCredentials(true)"
                                        + " makes Spring reflect the caller's Origin back and send"
                                        + " cookies / Authorization headers to it. Any site can"
                                        + " then make authenticated cross-origin requests and read"
                                        + " the responses.")
                            .possibleImpact(
                                    "Cross-origin credential theft and data exfiltration: a"
                                        + " malicious page can call the API as the logged-in user"
                                        + " and read protected responses.")
                            .recommendation(
                                    "Never combine a wildcard origin with allowCredentials(true)."
                                            + " Enumerate the exact trusted origins, or drop"
                                            + " allowCredentials if the API is genuinely public.")
                            .evidence(
                                    "A wildcard CORS origin and allowCredentials(true) were found"
                                            + " together in "
                                            + target
                                            + ".")
                            .limitations(
                                    "Static analysis correlates the calls within a single method;"
                                        + " configuration split across helper methods may not be"
                                        + " detected.")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_CROSS_ORIGIN_WILDCARD
    // ---------------------------------------------------------------------------

    private void detectCrossOriginAnnotation(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        String className = declaration.getNameAsString();
        checkCrossOriginAnnotation(
                relativePath,
                declaration.getAnnotations(),
                className,
                declaration.getBegin().map(position -> position.line).orElse(null),
                findings);
        for (MethodDeclaration method : declaration.getMethods()) {
            checkCrossOriginAnnotation(
                    relativePath,
                    method.getAnnotations(),
                    className + "#" + method.getNameAsString(),
                    method.getBegin().map(position -> position.line).orElse(null),
                    findings);
        }
    }

    private void checkCrossOriginAnnotation(
            String relativePath,
            NodeList<AnnotationExpr> annotations,
            String target,
            Integer line,
            List<Finding> findings) {
        for (AnnotationExpr annotation : annotations) {
            if (!simpleName(annotation.getNameAsString()).equals("CrossOrigin")
                    || !crossOriginAllowsAllOrigins(annotation)) {
                continue;
            }
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_CROSS_ORIGIN_WILDCARD,
                                    FindingConfidence.MEDIUM)
                            .shortMessage("@CrossOrigin on " + target + " allows all origins.")
                            .whyBadPractice(
                                    "A bare @CrossOrigin, or one with origins set to \"*\", permits"
                                        + " cross-origin requests from any site. Declaring CORS per"
                                        + " controller also scatters the policy across the"
                                        + " codebase, making it easy to ship a wildcard to"
                                        + " production.")
                            .possibleImpact(
                                    "Any website can call the annotated endpoint on behalf of a"
                                        + " user; combined with cookie-based authentication this"
                                        + " can expose user data to third-party origins.")
                            .recommendation(
                                    "Restrict origins to an explicit allowlist, and prefer a"
                                        + " central CorsConfigurationSource / WebMvcConfigurer over"
                                        + " per-controller @CrossOrigin so the policy is reviewed"
                                        + " in one place.")
                            .evidence("@CrossOrigin on " + target + " in " + relativePath + ".")
                            .limitations(
                                    "Static analysis cannot tell whether the endpoint is public and"
                                            + " stateless, which can make a wildcard acceptable.")
                            .source(relativePath, line)
                            .target(target)
                            .build());
            return; // one finding per annotated element is sufficient
        }
    }

    private boolean crossOriginAllowsAllOrigins(AnnotationExpr annotation) {
        if (annotation.isMarkerAnnotationExpr()) {
            return true; // a bare @CrossOrigin defaults to allowing every origin
        }
        if (annotation.isSingleMemberAnnotationExpr()) {
            return annotation
                    .asSingleMemberAnnotationExpr()
                    .getMemberValue()
                    .toString()
                    .contains("\"*\"");
        }
        if (annotation.isNormalAnnotationExpr()) {
            Optional<MemberValuePair> originsPair =
                    annotation.asNormalAnnotationExpr().getPairs().stream()
                            .filter(
                                    pair ->
                                            pair.getNameAsString().equals("origins")
                                                    || pair.getNameAsString()
                                                            .equals("originPatterns"))
                            .findFirst();
            if (originsPair.isEmpty()) {
                return true; // no origins attribute → defaults to all origins
            }
            return originsPair.get().getValue().toString().contains("\"*\"");
        }
        return false;
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_DUPLICATE_EXCEPTION_HANDLER
    // ---------------------------------------------------------------------------

    private void detectDuplicateExceptionHandlers(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        Map<String, List<String>> handlersByException = new LinkedHashMap<>();
        for (MethodDeclaration method : declaration.getMethods()) {
            if (!hasAnnotation(method.getAnnotations(), "ExceptionHandler")) {
                continue;
            }
            for (String exceptionType : exceptionTypesHandledBy(method)) {
                handlersByException
                        .computeIfAbsent(exceptionType, key -> new ArrayList<>())
                        .add(method.getNameAsString());
            }
        }
        String className = declaration.getNameAsString();
        Integer line = declaration.getBegin().map(position -> position.line).orElse(null);
        for (Map.Entry<String, List<String>> entry : handlersByException.entrySet()) {
            List<String> methods = entry.getValue();
            if (methods.size() < 2) {
                continue;
            }
            String exceptionType = entry.getKey();
            String methodList = String.join(", ", methods);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_DUPLICATE_EXCEPTION_HANDLER,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "Multiple @ExceptionHandler methods in "
                                            + className
                                            + " handle "
                                            + exceptionType
                                            + ": "
                                            + methodList
                                            + ".")
                            .whyBadPractice(
                                    "Spring permits only one @ExceptionHandler per exception type"
                                            + " within a @Controller/@ControllerAdvice bean. Two"
                                            + " methods mapping the same exception class make the"
                                            + " mapping ambiguous.")
                            .possibleImpact(
                                    "Spring throws IllegalStateException (\"Ambiguous"
                                        + " @ExceptionHandler method mapped\") while building the"
                                        + " handler mappings, preventing the application from"
                                        + " starting.")
                            .recommendation(
                                    "Keep a single @ExceptionHandler per exception type — merge the"
                                        + " duplicate handlers, or narrow one to a more specific"
                                        + " exception subclass.")
                            .evidence(
                                    "@ExceptionHandler for "
                                            + exceptionType
                                            + " appears on methods "
                                            + methodList
                                            + " in "
                                            + className
                                            + ".")
                            .limitations(
                                    "Exception types are matched by simple name. Handlers split"
                                        + " across separate @ControllerAdvice beans are resolved by"
                                        + " @Order at runtime and are not flagged.")
                            .source(relativePath, line)
                            .target(className)
                            .build());
        }
    }

    private Set<String> exceptionTypesHandledBy(MethodDeclaration method) {
        Set<String> types = new LinkedHashSet<>();
        method.getAnnotationByName("ExceptionHandler")
                .ifPresent(
                        annotation ->
                                annotation
                                        .findAll(ClassExpr.class)
                                        .forEach(
                                                classExpr ->
                                                        types.add(
                                                                simpleName(
                                                                        classExpr
                                                                                .getType()
                                                                                .asString()))));
        if (types.isEmpty()) {
            // No explicit value — Spring infers the handled types from the method's parameters.
            for (Parameter parameter : method.getParameters()) {
                String parameterType = simpleName(parameter.getType().asString());
                if (parameterType.endsWith("Exception")
                        || parameterType.endsWith("Error")
                        || parameterType.equals("Throwable")) {
                    types.add(parameterType);
                }
            }
        }
        return types;
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_JPA_COLLECTION_EAGER_FETCH
    // ---------------------------------------------------------------------------

    private void detectManyToManyCascadeRemove(
            String relativePath,
            AnnotationExpr annotation,
            String annotationName,
            String target,
            Integer line,
            List<Finding> findings) {
        if (!annotationName.equals("ManyToMany") || !annotation.isNormalAnnotationExpr()) {
            return;
        }
        boolean cascadeRemove =
                annotation.asNormalAnnotationExpr().getPairs().stream()
                        .anyMatch(
                                pair ->
                                        pair.getNameAsString().equals("cascade")
                                                && (pair.getValue().toString().contains("REMOVE")
                                                        || pair.getValue()
                                                                .toString()
                                                                .contains("ALL")));
        if (!cascadeRemove) {
            return;
        }
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_JPA_MANYTOMANY_CASCADE_REMOVE,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@ManyToMany on " + target + " cascades remove to shared entities.")
                        .whyBadPractice(
                                "CascadeType.REMOVE/ALL on a @ManyToMany cascades deletes across"
                                    + " the join table to the entities on the other side, which are"
                                    + " typically shared with other parents.")
                        .possibleImpact(
                                "Deleting one entity also deletes shared rows that other entities"
                                        + " still reference — irreversible data loss.")
                        .recommendation(
                                "Remove CascadeType.REMOVE/ALL from the @ManyToMany; cascade only"
                                        + " PERSIST/MERGE if needed and remove join-table links"
                                        + " explicitly.")
                        .evidence(
                                "@ManyToMany on "
                                        + target
                                        + " in "
                                        + relativePath
                                        + " declares cascade = REMOVE/ALL.")
                        .limitations(
                                "The cascade member is matched textually; cascade on an owned,"
                                        + " non-shared association would be a false positive.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private void detectProxyAnnotationOnFinalMethod(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        if (declaration.isInterface()) {
            return;
        }
        for (MethodDeclaration method : declaration.getMethods()) {
            if (!method.isFinal() || method.isStatic() || method.isPrivate()) {
                continue;
            }
            String proxyAnnotation =
                    method.getAnnotations().stream()
                            .map(annotation -> simpleName(annotation.getNameAsString()))
                            .filter(PROXY_ANNOTATIONS::contains)
                            .findFirst()
                            .orElse(null);
            if (proxyAnnotation == null) {
                continue;
            }
            Integer line = method.getBegin().map(position -> position.line).orElse(null);
            String target = declaration.getNameAsString() + "#" + method.getNameAsString();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_PROXY_ANNOTATION_ON_FINAL_METHOD,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "@"
                                            + proxyAnnotation
                                            + " on final method "
                                            + target
                                            + " is silently skipped by the CGLIB proxy.")
                            .whyBadPractice(
                                    "Spring's CGLIB proxy subclasses the bean and overrides advised"
                                        + " methods. A final method cannot be overridden, so the @"
                                            + proxyAnnotation
                                            + " advice (transaction, cache, async, security,"
                                            + " observation) is never applied.")
                            .possibleImpact(
                                    "The method runs with none of the behavior the annotation"
                                        + " implies — no transaction, no caching, no authorization"
                                        + " — with no error at startup.")
                            .recommendation(
                                    "Remove final from the method (and the class, if final), or"
                                            + " move the annotation to a non-final method invoked"
                                            + " through the proxy.")
                            .evidence(
                                    "@"
                                            + proxyAnnotation
                                            + " on final method "
                                            + target
                                            + " in "
                                            + relativePath
                                            + ".")
                            .limitations(
                                    "Interface-based JDK-proxy beans tolerate final methods on the"
                                        + " implementation; this is most relevant for class-proxied"
                                        + " @Component/@Service beans.")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    private void detectBigDecimalDoubleConstructor(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        for (ObjectCreationExpr expr : declaration.findAll(ObjectCreationExpr.class)) {
            if (!simpleName(expr.getType().asString()).equals("BigDecimal")
                    || expr.getArguments().size() != 1) {
                continue;
            }
            Expression argument = expr.getArguments().get(0);
            if (!(argument instanceof DoubleLiteralExpr)) {
                continue;
            }
            Integer line = expr.getBegin().map(position -> position.line).orElse(null);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_BIGDECIMAL_DOUBLE_CONSTRUCTOR,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "new BigDecimal("
                                            + argument
                                            + ") uses the double constructor in "
                                            + relativePath
                                            + ".")
                            .whyBadPractice(
                                    "new BigDecimal(double) stores the exact binary value of the"
                                        + " double, which cannot represent most decimal fractions —"
                                        + " new BigDecimal(0.1) becomes"
                                        + " 0.1000000000000000055511151231257827021181583404541015625.")
                            .possibleImpact(
                                    "Monetary and other precise calculations are silently off by"
                                            + " tiny amounts that accumulate into reconciliation"
                                            + " failures and off-by-a-cent bugs.")
                            .recommendation(
                                    "Use BigDecimal.valueOf(double), or the String constructor:"
                                            + " new BigDecimal(\"0.1\").")
                            .evidence(
                                    "new BigDecimal("
                                            + argument
                                            + ") found in "
                                            + relativePath
                                            + ".")
                            .limitations(
                                    "Only the floating-point literal form is flagged; a"
                                        + " double-typed variable argument is not detected to avoid"
                                        + " false positives.")
                            .source(relativePath, line)
                            .target("BigDecimal")
                            .build());
            return; // one finding per class is sufficient
        }
    }

    private void detectCollectionEagerFetch(
            String relativePath,
            AnnotationExpr annotation,
            String annotationName,
            String target,
            Integer line,
            List<Finding> findings) {
        boolean explicitEager =
                annotation.isNormalAnnotationExpr()
                        && annotation.asNormalAnnotationExpr().getPairs().stream()
                                .anyMatch(
                                        pair ->
                                                pair.getNameAsString().equals("fetch")
                                                        && pair.getValue()
                                                                .toString()
                                                                .contains("EAGER"));
        if (!explicitEager) {
            return;
        }
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_JPA_COLLECTION_EAGER_FETCH,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@"
                                        + annotationName
                                        + " on "
                                        + target
                                        + " uses fetch = FetchType.EAGER.")
                        .whyBadPractice(
                                "Collections default to lazy loading; setting EAGER forces the"
                                    + " whole collection to load on every query for the owning"
                                    + " entity, even when it is not used. With more than one eager"
                                    + " collection Hibernate also produces Cartesian-product"
                                    + " joins.")
                        .possibleImpact(
                                "N+1 queries and large result sets degrade database and heap"
                                        + " performance, often only under production-scale data.")
                        .recommendation(
                                "Use fetch = FetchType.LAZY (the default) and load the collection"
                                    + " on demand with JOIN FETCH or an entity graph where it is"
                                    + " actually needed.")
                        .evidence(
                                "@"
                                        + annotationName
                                        + " on "
                                        + target
                                        + " in "
                                        + relativePath
                                        + " sets fetch = FetchType.EAGER.")
                        .limitations(
                                "Static analysis cannot confirm the collection is large or"
                                        + " frequently loaded; small, always-needed collections may"
                                        + " justify eager fetching.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private void detectSchedulingRisks(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            MethodSignals signals,
            List<Finding> findings) {
        method.getAnnotationByName("Scheduled")
                .ifPresent(
                        annotation -> {
                            Integer line =
                                    method.getBegin().map(position -> position.line).orElse(null);
                            annotation.ifNormalAnnotationExpr(
                                    expr -> {
                                        String cron = valueFor(expr.getPairs(), "cron");
                                        String zone = valueFor(expr.getPairs(), "zone");
                                        String fixedRate = valueFor(expr.getPairs(), "fixedRate");
                                        String fixedRateString =
                                                valueFor(expr.getPairs(), "fixedRateString");
                                        String fixedDelay = valueFor(expr.getPairs(), "fixedDelay");
                                        String fixedDelayString =
                                                valueFor(expr.getPairs(), "fixedDelayString");
                                        Duration interval =
                                                parseInterval(
                                                        defaultString(
                                                                fixedRateString,
                                                                fixedRate,
                                                                fixedDelayString,
                                                                fixedDelay));
                                        if (interval != null
                                                && interval.compareTo(Duration.ofMinutes(1)) < 0) {
                                            findings.add(
                                                    FindingFactory.builder(
                                                                    FindingRules
                                                                            .SPRING_SCHEDULED_SHORT_INTERVAL,
                                                                    FindingConfidence.HIGH)
                                                            .shortMessage(
                                                                    "Scheduled method "
                                                                            + declaration
                                                                                    .getNameAsString()
                                                                            + "#"
                                                                            + method
                                                                                    .getNameAsString()
                                                                            + " runs on a short"
                                                                            + " interval.")
                                                            .whyBadPractice(
                                                                    "Very short schedules increase"
                                                                        + " the chance of overlap,"
                                                                        + " backlog, and accidental"
                                                                        + " load amplification in"
                                                                        + " multi-instance"
                                                                        + " deployments.")
                                                            .possibleImpact(
                                                                    "Background jobs can re-enter"
                                                                        + " before previous work"
                                                                        + " finishes, compete for"
                                                                        + " resources, or put"
                                                                        + " avoidable pressure on"
                                                                        + " external APIs and"
                                                                        + " databases.")
                                                            .recommendation(
                                                                    "Use a longer interval, prefer"
                                                                        + " fixedDelay when"
                                                                        + " non-overlap is desired,"
                                                                        + " and add explicit"
                                                                        + " coordination if the job"
                                                                        + " may run on multiple"
                                                                        + " instances.")
                                                            .evidence(
                                                                    "Detected @Scheduled interval "
                                                                            + interval
                                                                            + " in "
                                                                            + relativePath
                                                                            + ".")
                                                            .limitations(
                                                                    "Static analysis cannot measure"
                                                                        + " real execution time or"
                                                                        + " whether another"
                                                                        + " scheduler layer"
                                                                        + " prevents overlap.")
                                                            .source(relativePath, line)
                                                            .target(
                                                                    declaration.getNameAsString()
                                                                            + "#"
                                                                            + method
                                                                                    .getNameAsString())
                                                            .build());
                                        }
                                        if (cron != null
                                                && !cron.isBlank()
                                                && (zone == null || zone.isBlank())) {
                                            findings.add(
                                                    FindingFactory.builder(
                                                                    FindingRules
                                                                            .SPRING_SCHEDULED_CRON_NO_ZONE,
                                                                    FindingConfidence.MEDIUM)
                                                            .shortMessage(
                                                                    "Scheduled cron expression has"
                                                                            + " no explicit zone: "
                                                                            + declaration
                                                                                    .getNameAsString()
                                                                            + "#"
                                                                            + method
                                                                                    .getNameAsString())
                                                            .whyBadPractice(
                                                                    "Cron schedules without an"
                                                                        + " explicit zone inherit"
                                                                        + " the JVM or container"
                                                                        + " default time zone,"
                                                                        + " which can vary across"
                                                                        + " environments.")
                                                            .possibleImpact(
                                                                    "Jobs may run at different"
                                                                        + " wall-clock times after"
                                                                        + " deployment, daylight"
                                                                        + " saving changes, or"
                                                                        + " infrastructure moves.")
                                                            .recommendation(
                                                                    "Set the zone attribute"
                                                                        + " explicitly for"
                                                                        + " cron-based jobs whose"
                                                                        + " timing matters across"
                                                                        + " environments.")
                                                            .evidence(
                                                                    "@Scheduled cron was found in "
                                                                            + relativePath
                                                                            + " without a zone"
                                                                            + " attribute.")
                                                            .limitations(
                                                                    "Static analysis cannot"
                                                                        + " determine whether the"
                                                                        + " deployment environment"
                                                                        + " already pins a"
                                                                        + " consistent default time"
                                                                        + " zone.")
                                                            .source(relativePath, line)
                                                            .target(
                                                                    declaration.getNameAsString()
                                                                            + "#"
                                                                            + method
                                                                                    .getNameAsString())
                                                            .build());
                                        }
                                    });
                            if (signals.hasHttpCalls() || signals.hasDatabaseWrites()) {
                                findings.add(
                                        FindingFactory.builder(
                                                        FindingRules.SPRING_SCHEDULED_SIDE_EFFECT,
                                                        signals.directSignalConfidence())
                                                .shortMessage(
                                                        "Scheduled method "
                                                                + declaration.getNameAsString()
                                                                + "#"
                                                                + method.getNameAsString()
                                                                + " appears to perform side"
                                                                + " effects.")
                                                .whyBadPractice(
                                                        "Scheduled methods are background side"
                                                            + " effects. In multi-instance"
                                                            + " deployments they can run once per"
                                                            + " instance unless coordination is"
                                                            + " made explicit.")
                                                .possibleImpact(
                                                        "Duplicate writes, overlapping API calls,"
                                                            + " or hidden background pressure can"
                                                            + " appear only in production when"
                                                            + " multiple instances run the same"
                                                            + " job.")
                                                .recommendation(
                                                        "Add explicit enable flags, timeouts, error"
                                                            + " handling, and distributed"
                                                            + " coordination when scheduled work"
                                                            + " changes state or calls external"
                                                            + " systems.")
                                                .evidence(
                                                        "Detected @Scheduled method with "
                                                                + signals.describe()
                                                                + " in "
                                                                + relativePath
                                                                + ".")
                                                .limitations(
                                                        "Static analysis infers behavior from"
                                                            + " method calls and cannot prove"
                                                            + " runtime deployment topology or"
                                                            + " distributed lock usage elsewhere.")
                                                .source(relativePath, line)
                                                .target(
                                                        declaration.getNameAsString()
                                                                + "#"
                                                                + method.getNameAsString())
                                                .build());
                            }
                        });
    }

    private boolean isReadOnlyTransactional(
            MethodDeclaration method, ClassOrInterfaceDeclaration declaration) {
        if (readOnlyTrue(method.getAnnotationByName("Transactional").orElse(null))) {
            return true;
        }
        // Inherit a class-level readOnly only when the method has no own @Transactional override.
        return !hasAnnotation(method.getAnnotations(), "Transactional")
                && readOnlyTrue(declaration.getAnnotationByName("Transactional").orElse(null));
    }

    private boolean readOnlyTrue(AnnotationExpr annotation) {
        if (annotation == null || !annotation.isNormalAnnotationExpr()) {
            return false;
        }
        return annotation.asNormalAnnotationExpr().getPairs().stream()
                .anyMatch(
                        pair ->
                                pair.getNameAsString().equals("readOnly")
                                        && pair.getValue() instanceof BooleanLiteralExpr bool
                                        && bool.getValue());
    }

    private boolean methodHasPersistenceWriteInCurrentTransaction(
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex transactionEvidence) {
        return persistenceWriteCalls(method, declaration).stream()
                .anyMatch(
                        call ->
                                persistenceWriteRunsInCurrentTransaction(
                                        call, method, declaration, transactionEvidence));
    }

    private List<MethodCallExpr> persistenceWriteCalls(
            MethodDeclaration method, ClassOrInterfaceDeclaration declaration) {
        return method.findAll(MethodCallExpr.class).stream()
                .filter(call -> belongsToMethod(call, method))
                .filter(call -> isDirectPersistenceWrite(call, method, declaration))
                .toList();
    }

    private boolean persistenceWriteRunsInCurrentTransaction(
            MethodCallExpr call,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex transactionEvidence) {
        if (!isInsideLambda(call, method)) {
            return true;
        }
        return isInsideImmediateProgrammaticCallback(call, method, declaration, transactionEvidence)
                && !isInsideIndependentProgrammaticTransaction(
                        call, method, declaration, transactionEvidence);
    }

    private boolean isDirectPersistenceWrite(
            MethodCallExpr call,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration) {
        if (!WRITE_CALL_MARKERS.contains(call.getNameAsString())) {
            return false;
        }
        String receiverType = resolveReceiverType(call, method, declaration);
        if (receiverType == null) {
            return false;
        }
        if (receiverType.endsWith("Repository") || receiverType.endsWith("Dao")) {
            return true;
        }
        if (!PERSISTENCE_INFRASTRUCTURE_TYPES.contains(receiverType)) {
            return false;
        }
        if (receiverType.equals("EntityManager") || receiverType.equals("Session")) {
            return Set.of("persist", "merge", "remove", "delete", "flush")
                    .contains(call.getNameAsString());
        }
        return Set.of("update", "batchUpdate", "execute", "insert", "delete")
                .contains(call.getNameAsString());
    }

    private String firstCheckedThrownExceptionAfterWrite(
            MethodDeclaration method, ClassOrInterfaceDeclaration declaration) {
        List<MethodCallExpr> writes =
                persistenceWriteCalls(method, declaration).stream()
                        .filter(call -> isDirectTopLevelWriteCall(method, call))
                        .toList();
        if (writes.isEmpty()) {
            return null;
        }
        for (var thrown : method.getThrownExceptions()) {
            String name = simpleName(thrown.asString());
            if (isProvablyCheckedExceptionName(method, name)
                    && hasTopLevelWriteBeforeEscapingThrow(method, writes, name)) {
                return name;
            }
        }
        return null;
    }

    private boolean isProvablyCheckedExceptionName(MethodDeclaration method, String name) {
        if (KNOWN_RUNTIME_EXCEPTIONS.contains(name) || name.endsWith("RuntimeException")) {
            return false;
        }
        if (KNOWN_CHECKED_EXCEPTIONS.contains(name)) {
            return true;
        }
        return method.findCompilationUnit().stream()
                .flatMap(unit -> unit.findAll(ClassOrInterfaceDeclaration.class).stream())
                .filter(type -> type.getNameAsString().equals(name))
                .anyMatch(
                        type ->
                                type.getExtendedTypes().stream()
                                        .map(parent -> simpleName(parent.getNameAsString()))
                                        .anyMatch(
                                                parent ->
                                                        parent.equals("Exception")
                                                                || KNOWN_CHECKED_EXCEPTIONS
                                                                        .contains(parent)));
    }

    private boolean hasTopLevelWriteBeforeEscapingThrow(
            MethodDeclaration method, List<MethodCallExpr> writes, String checkedType) {
        if (method.getBody().isEmpty()) {
            return false;
        }
        for (ThrowStmt throwStmt : method.getBody().get().findAll(ThrowStmt.class)) {
            if (!belongsToMethod(throwStmt, method)
                    || explicitThrownType(throwStmt) == null
                    || !checkedType.equals(explicitThrownType(throwStmt))
                    || isCaughtBeforeMethodExit(throwStmt, checkedType, method)) {
                continue;
            }
            int throwIndex = directTopLevelStatementIndex(method, throwStmt);
            if (throwIndex < 0) {
                continue;
            }
            for (MethodCallExpr write : writes) {
                int writeIndex = directTopLevelStatementIndex(method, write);
                if (writeIndex >= 0
                        && writeIndex < throwIndex
                        && hasOnlyStraightLineStatementsBetween(method, writeIndex, throwIndex)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isDirectTopLevelWriteCall(MethodDeclaration method, MethodCallExpr writeCall) {
        if (!(writeCall.getParentNode().orElse(null) instanceof ExpressionStmt statement)
                || method.getBody().isEmpty()) {
            return false;
        }
        return statement.getExpression() == writeCall
                && statement.getParentNode().orElse(null) == method.getBody().get();
    }

    private boolean hasOnlyStraightLineStatementsBetween(
            MethodDeclaration method, int writeIndex, int throwIndex) {
        List<Statement> statements = method.getBody().orElseThrow().getStatements();
        for (int index = writeIndex + 1; index < throwIndex; index++) {
            Statement statement = statements.get(index);
            if (!(statement instanceof ExpressionStmt) && !(statement instanceof EmptyStmt)) {
                return false;
            }
        }
        return true;
    }

    private boolean isCaughtBeforeMethodExit(
            ThrowStmt throwStmt, String thrownType, MethodDeclaration method) {
        Node current = throwStmt;
        while (current != method && current.getParentNode().isPresent()) {
            current = current.getParentNode().get();
            if (!(current instanceof TryStmt tryStmt)
                    || !tryStmt.getTryBlock().findAll(ThrowStmt.class).contains(throwStmt)) {
                continue;
            }
            boolean caught =
                    tryStmt.getCatchClauses().stream()
                            .flatMap(catchClause -> caughtTypeNames(catchClause).stream())
                            .anyMatch(
                                    caughtType ->
                                            caughtType.equals(thrownType)
                                                    || caughtType.equals("Exception")
                                                    || caughtType.equals("Throwable"));
            if (caught) {
                return true;
            }
        }
        return false;
    }

    private String explicitThrownType(ThrowStmt throwStmt) {
        if (throwStmt.getExpression() instanceof ObjectCreationExpr creation) {
            return simpleName(creation.getTypeAsString());
        }
        return null;
    }

    private int directTopLevelStatementIndex(MethodDeclaration method, Node node) {
        if (method.getBody().isEmpty()) {
            return -1;
        }
        BlockStmt body = method.getBody().get();
        Statement statement;
        if (node instanceof ThrowStmt throwStmt) {
            statement = throwStmt;
        } else if (node instanceof MethodCallExpr call
                && call.getParentNode().orElse(null) instanceof ExpressionStmt expressionStmt
                && expressionStmt.getExpression() == call) {
            statement = expressionStmt;
        } else {
            return -1;
        }
        if (statement.getParentNode().orElse(null) != body) {
            return -1;
        }
        return body.getStatements().indexOf(statement);
    }

    private boolean transactionalRollbackForPresent(
            MethodDeclaration method, ClassOrInterfaceDeclaration declaration) {
        AnnotationExpr annotation =
                method.getAnnotationByName("Transactional")
                        .or(() -> declaration.getAnnotationByName("Transactional"))
                        .orElse(null);
        if (annotation == null || !annotation.isNormalAnnotationExpr()) {
            return false;
        }
        return annotation.asNormalAnnotationExpr().getPairs().stream()
                .anyMatch(
                        pair ->
                                pair.getNameAsString().equals("rollbackFor")
                                        || pair.getNameAsString().equals("rollbackForClassName"));
    }

    private void detectTransactionalEventListenerWriteLost(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        for (MethodDeclaration method : declaration.getMethods()) {
            AnnotationExpr listener =
                    method.getAnnotationByName("TransactionalEventListener").orElse(null);
            if (listener == null
                    || !isAfterCommitPhase(listener)
                    || persistenceWriteCalls(method, declaration).stream()
                            .noneMatch(call -> !isInsideLambda(call, method))
                    || runsInRequiresNewTransaction(method, declaration)) {
                continue;
            }
            Integer line = method.getBegin().map(position -> position.line).orElse(null);
            String target = declaration.getNameAsString() + "#" + method.getNameAsString();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_TX_EVENT_LISTENER_WRITE_LOST,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "After-commit @TransactionalEventListener "
                                            + target
                                            + " writes to the database with no active transaction.")
                            .whyBadPractice(
                                    "A @TransactionalEventListener runs after the original"
                                        + " transaction has committed (the default AFTER_COMMIT"
                                        + " phase), so there is no active transaction. Persistence"
                                        + " writes are not flushed unless the listener opens its"
                                        + " own transaction.")
                            .possibleImpact(
                                    "The listener appears to run but its writes are silently lost —"
                                            + " a classic outbox/audit data-loss bug.")
                            .recommendation(
                                    "Annotate the listener with @Transactional(propagation ="
                                        + " Propagation.REQUIRES_NEW) so its writes run in a new"
                                        + " transaction.")
                            .evidence(
                                    "After-commit @TransactionalEventListener "
                                            + target
                                            + " performs a persistence write without REQUIRES_NEW"
                                            + " in "
                                            + relativePath
                                            + ".")
                            .limitations(
                                    "Write calls are matched by name; a REQUIRES_NEW transaction"
                                            + " opened in a called collaborator is not detected.")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    private boolean isAfterCommitPhase(AnnotationExpr listener) {
        if (!listener.isNormalAnnotationExpr()) {
            return true; // no phase member → default AFTER_COMMIT
        }
        var phasePair =
                listener.asNormalAnnotationExpr().getPairs().stream()
                        .filter(pair -> pair.getNameAsString().equals("phase"))
                        .findFirst()
                        .orElse(null);
        if (phasePair == null) {
            return true; // default AFTER_COMMIT
        }
        String phase = phasePair.getValue().toString();
        return phase.contains("AFTER_COMMIT")
                || phase.contains("AFTER_COMPLETION")
                || phase.contains("AFTER_ROLLBACK");
    }

    private boolean runsInRequiresNewTransaction(
            MethodDeclaration method, ClassOrInterfaceDeclaration declaration) {
        AnnotationExpr annotation =
                method.getAnnotationByName("Transactional")
                        .or(() -> declaration.getAnnotationByName("Transactional"))
                        .orElse(null);
        return annotation != null && annotation.toString().contains("REQUIRES_NEW");
    }

    private void detectTransactionRisks(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            boolean repositoryLike,
            boolean legacyTransactionalVisibility,
            MethodSignals signals,
            TransactionEvidenceIndex transactionEvidence,
            List<Finding> findings) {
        boolean transactional =
                hasAnnotation(method.getAnnotations(), "Transactional")
                        || hasAnnotation(declaration.getAnnotations(), "Transactional");
        AnnotationExpr callerTransaction = effectiveTransactionalAnnotation(declaration, method);
        boolean guaranteedActiveTransaction =
                callerTransactionGuaranteesActiveTransaction(
                        declaration, method, callerTransaction, legacyTransactionalVisibility);
        Integer line = method.getBegin().map(position -> position.line).orElse(null);
        if (hasAnnotation(method.getAnnotations(), "Transactional") && method.isPrivate()) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_TRANSACTIONAL_ON_PRIVATE_METHOD,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "@Transactional was found on a private method: "
                                            + declaration.getNameAsString()
                                            + "#"
                                            + method.getNameAsString())
                            .whyBadPractice(
                                    "Spring transaction boundaries are normally applied through"
                                        + " proxies around eligible methods. Private methods are a"
                                        + " common place where that expectation becomes"
                                        + " ineffective.")
                            .possibleImpact(
                                    "Writes may happen without the transaction semantics the code"
                                            + " appears to request, leading to partial updates or"
                                            + " inconsistent rollback behavior.")
                            .recommendation(
                                    "Move the transaction boundary to a public service method or"
                                        + " use TransactionTemplate when an explicit local boundary"
                                        + " is required.")
                            .evidence(
                                    "@Transactional was found on private method "
                                            + method.getNameAsString()
                                            + " in "
                                            + relativePath
                                            + ".")
                            .limitations(
                                    "Static analysis cannot prove the exact proxying strategy or"
                                        + " whether AspectJ weaving is used instead of proxy-based"
                                        + " interception.")
                            .source(relativePath, line)
                            .target(declaration.getNameAsString() + "#" + method.getNameAsString())
                            .build());
        }
        // Only meaningful on Spring Boot 1.x/2.x (Framework 5): as of Spring Framework 6.0,
        // protected and package-visible @Transactional methods ARE advised on class-based
        // (CGLIB) proxies by default, so this finding would be a false positive on Boot 3+.
        if (legacyTransactionalVisibility
                && hasAnnotation(method.getAnnotations(), "Transactional")
                && !method.isPublic()
                && !method.isPrivate()
                && !declaration.isInterface()) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_TRANSACTIONAL_NON_PUBLIC_METHOD,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "@Transactional was found on a non-public method: "
                                            + declaration.getNameAsString()
                                            + "#"
                                            + method.getNameAsString())
                            .whyBadPractice(
                                    "On Spring Framework 5 (Spring Boot 1.x/2.x, the version this"
                                            + " project resolves to), the transaction proxy applies"
                                            + " advice only to public methods. On a protected or"
                                            + " package-private method the annotation is silently"
                                            + " ignored and no transaction is started. (Spring"
                                            + " Framework 6.0+ supports non-public methods on"
                                            + " class-based proxies.)")
                            .possibleImpact(
                                    "Multi-statement writes run without a transaction, so a failure"
                                            + " leaves partially-applied changes with no rollback.")
                            .recommendation(
                                    "Make the method public, or move the @Transactional boundary to"
                                            + " a public method invoked through the proxy."
                                            + " Upgrading to Spring Boot 3 (Framework 6) also lifts"
                                            + " this restriction for class-based proxies.")
                            .limitations(
                                    "Reported only when the resolved Spring Boot version is 1.x or"
                                            + " 2.x. Static analysis cannot prove the proxying"
                                            + " strategy; AspectJ weaving (mode=ASPECTJ) would"
                                            + " advise non-public methods even on Framework 5.")
                            .source(relativePath, line)
                            .target(declaration.getNameAsString() + "#" + method.getNameAsString())
                            .build());
        }
        if (guaranteedActiveTransaction
                && isReadOnlyTransactional(method, declaration)
                && methodHasPersistenceWriteInCurrentTransaction(
                        method, declaration, transactionEvidence)) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_TRANSACTIONAL_READONLY_WITH_WRITES,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "Writes inside a readOnly=true transaction in "
                                            + declaration.getNameAsString()
                                            + "#"
                                            + method.getNameAsString()
                                            + " are silently dropped.")
                            .whyBadPractice(
                                    "@Transactional(readOnly = true) sets the Hibernate flush mode"
                                        + " to MANUAL, so dirty-checked entity changes are never"
                                        + " flushed. Explicit writes either vanish silently or fail"
                                        + " late on a read-only JDBC connection.")
                            .possibleImpact(
                                    "Updates appear to succeed but are never persisted — a silent"
                                            + " data-loss bug that is hard to trace.")
                            .recommendation(
                                    "Remove readOnly = true from methods that write, or split the"
                                            + " read and write work into separate transactions.")
                            .limitations(
                                    "Only calls on locally resolvable repository, EntityManager, or"
                                        + " JDBC template receivers are considered. Writes hidden"
                                        + " behind application-specific abstractions may be"
                                        + " missed.")
                            .source(relativePath, line)
                            .target(declaration.getNameAsString() + "#" + method.getNameAsString())
                            .build());
        }
        if (guaranteedActiveTransaction) {
            String checkedException = firstCheckedThrownExceptionAfterWrite(method, declaration);
            if (checkedException != null && !transactionalRollbackForPresent(method, declaration)) {
                findings.add(
                        FindingFactory.builder(
                                        FindingRules
                                                .SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK,
                                        FindingConfidence.MEDIUM)
                                .shortMessage(
                                        declaration.getNameAsString()
                                                + "#"
                                                + method.getNameAsString()
                                                + " declares checked exception "
                                                + checkedException
                                                + " but @Transactional has no rollbackFor.")
                                .whyBadPractice(
                                        "Spring's default rollback policy only rolls back on"
                                            + " RuntimeException and Error. A checked exception"
                                            + " propagating out of a @Transactional method commits"
                                            + " the partially-applied transaction instead of"
                                            + " rolling it back.")
                                .possibleImpact(
                                        "On a checked failure the database is left in a"
                                                + " partially-updated, inconsistent state with no"
                                                + " rollback.")
                                .recommendation(
                                        "Add rollbackFor (e.g. @Transactional(rollbackFor ="
                                            + " Exception.class)), or wrap the checked exception in"
                                            + " a RuntimeException.")
                                .limitations(
                                        "Only known checked types or locally declared subclasses of"
                                            + " Exception are considered, and a direct persistence"
                                            + " write must precede an explicit escaping throw."
                                            + " Indirect throws may be missed.")
                                .source(relativePath, line)
                                .target(
                                        declaration.getNameAsString()
                                                + "#"
                                                + method.getNameAsString())
                                .build());
            }
        }
        boolean callerHasActiveTransaction = guaranteedActiveTransaction;
        method.findAll(MethodCallExpr.class)
                .forEach(
                        call -> {
                            // Do not attribute calls declared inside a local/anonymous type back to
                            // the enclosing service method.
                            if (call.findAncestor(MethodDeclaration.class)
                                    .filter(method::equals)
                                    .isEmpty()) {
                                return;
                            }
                            var scope = call.getScope().orElse(null);
                            if (scope != null && !(scope instanceof ThisExpr)) {
                                return;
                            }
                            TransactionalSelfInvocationTarget target =
                                    resolveTransactionalSelfInvocationTarget(
                                            declaration,
                                            method,
                                            call,
                                            legacyTransactionalVisibility);
                            if (target == null
                                    || !transactionalProxyChangesContext(
                                            callerTransaction,
                                            callerHasActiveTransaction,
                                            target.annotation())) {
                                return;
                            }
                            findings.add(
                                    FindingFactory.builder(
                                                    FindingRules
                                                            .SPRING_TRANSACTIONAL_SELF_INVOCATION,
                                                    FindingConfidence.MEDIUM)
                                            .shortMessage(
                                                    "Transactional method appears to be called"
                                                            + " from the same class: "
                                                            + declaration.getNameAsString()
                                                            + "#"
                                                            + target.method().getNameAsString())
                                            .whyBadPractice(
                                                    "Self-invocation bypasses the usual Spring"
                                                        + " proxy boundary, so the callee may not"
                                                        + " receive the transaction semantics its"
                                                        + " annotation suggests.")
                                            .possibleImpact(
                                                    "Code may appear transactional in reviews"
                                                            + " while still executing without the"
                                                            + " expected rollback or propagation"
                                                            + " behavior at runtime.")
                                            .recommendation(
                                                    "Call the transactional method through another"
                                                        + " Spring bean or move the transaction"
                                                        + " boundary to the public entry point that"
                                                        + " is invoked externally.")
                                            .evidence(
                                                    "Method "
                                                            + method.getNameAsString()
                                                            + " calls "
                                                            + call
                                                            + " inside "
                                                            + relativePath
                                                            + ".")
                                            .limitations(
                                                    "The target is matched conservatively by local"
                                                        + " method name and arity without full type"
                                                        + " resolution. AspectJ weaving can also"
                                                        + " advise same-class calls.")
                                            .source(
                                                    relativePath,
                                                    call.getBegin()
                                                            .map(position -> position.line)
                                                            .orElse(line))
                                            .target(
                                                    declaration.getNameAsString()
                                                            + "#"
                                                            + target.method().getNameAsString())
                                            .build());
                        });
        if (method.isPrivate()) {
            return;
        }
        if (method.toString().toLowerCase(Locale.ROOT).contains("transactiontemplate")) {
            return;
        }
        boolean multiWrite = signals.writeCallCount() >= 2;
        boolean mixedSideEffects =
                signals.hasPotentialWriteOperations()
                        && (signals.hasHttpCalls() || signals.hasMessagingCalls());
        if (transactional || (!multiWrite && !mixedSideEffects)) {
            return;
        }
        if (signals.hasDatabaseWrites() || repositoryLike) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_TRANSACTION_MISSING_BOUNDARY.ruleId(),
                                    FindingRules.SPRING_TRANSACTION_MISSING_BOUNDARY.title(),
                                    com.robbanhoglund.springbootanalyzer.analyzer.model
                                            .FindingSeverity.INFO,
                                    FindingRules.SPRING_TRANSACTION_MISSING_BOUNDARY.category(),
                                    FindingRules.SPRING_TRANSACTION_MISSING_BOUNDARY
                                            .runtimeDetection(),
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "Write-heavy method has no visible transaction boundary: "
                                            + declaration.getNameAsString()
                                            + "#"
                                            + method.getNameAsString())
                            .whyBadPractice(
                                    "Multiple write operations in one service method often rely on"
                                        + " a transaction boundary to keep state changes consistent"
                                        + " when one step fails.")
                            .possibleImpact(
                                    "Partial writes, inconsistent state, or retry behavior that"
                                            + " replays only part of the method can appear under"
                                            + " failure conditions.")
                            .recommendation(
                                    "Review whether the method should be wrapped in a public"
                                            + " @Transactional boundary or use an explicit"
                                            + " TransactionTemplate.")
                            .evidence(
                                    "Detected "
                                            + signals.describe()
                                            + " in "
                                            + relativePath
                                            + " without a visible @Transactional annotation on the"
                                            + " method or class.")
                            .limitations(
                                    "Static analysis cannot prove whether an outer caller already"
                                            + " supplies the transaction boundary or whether all"
                                            + " detected write-like calls are truly mutating"
                                            + " operations.")
                            .source(relativePath, line)
                            .target(declaration.getNameAsString() + "#" + method.getNameAsString())
                            .build());
            return;
        }
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_SIDE_EFFECT_ORCHESTRATION_NO_BOUNDARY,
                                FindingConfidence.MEDIUM)
                        .shortMessage(
                                "Potential side-effect orchestration without explicit consistency"
                                        + " boundary: "
                                        + declaration.getNameAsString()
                                        + "#"
                                        + method.getNameAsString())
                        .whyBadPractice(
                                "Methods that coordinate several write-like or external side"
                                        + " effects can be hard to reason about when one step fails"
                                        + " partway through the workflow.")
                        .possibleImpact(
                                "Retries or partial failures can leave downstream systems out of"
                                        + " sync even when no single database transaction applies.")
                        .recommendation(
                                "Review whether the workflow should use an explicit consistency"
                                        + " strategy, idempotency guard, compensating action, or a"
                                        + " clearer orchestration boundary.")
                        .evidence(
                                "Detected "
                                        + signals.describe()
                                        + " in "
                                        + relativePath
                                        + " without a visible consistency boundary, but the code"
                                        + " did not show clear persistence infrastructure signals.")
                        .limitations(
                                "Static analysis cannot prove whether the detected write-like calls"
                                    + " mutate shared state or whether another consistency boundary"
                                    + " exists outside this method.")
                        .source(relativePath, line)
                        .target(declaration.getNameAsString() + "#" + method.getNameAsString())
                        .build());
    }

    private void detectValidationGap(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            MethodSignals signals,
            List<Finding> findings) {
        if (!isWriteLikeEndpoint(method)
                && !signals.hasDatabaseWrites()
                && !signals.hasHttpCalls()
                && !signals.hasMessagingCalls()) {
            return;
        }
        for (Parameter parameter : method.getParameters()) {
            if (!hasAnnotation(parameter.getAnnotations(), "RequestBody")) {
                continue;
            }
            if (hasAnnotation(parameter.getAnnotations(), "Valid")
                    || hasAnnotation(parameter.getAnnotations(), "Validated")) {
                continue;
            }
            if (!isValidationCandidateType(parameter)) {
                continue;
            }
            ValidationSignals validationSignals = validationSignals(parameter, declaration);
            if (!validationSignals.shouldFlag()) {
                continue;
            }
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_REQUEST_BODY_NO_VALID.ruleId(),
                                    FindingRules.SPRING_REQUEST_BODY_NO_VALID.title(),
                                    com.robbanhoglund.springbootanalyzer.analyzer.model
                                            .FindingSeverity.INFO,
                                    FindingRules.SPRING_REQUEST_BODY_NO_VALID.category(),
                                    FindingRules.SPRING_REQUEST_BODY_NO_VALID.runtimeDetection(),
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "@RequestBody parameter is missing @Valid: "
                                            + declaration.getNameAsString()
                                            + "#"
                                            + method.getNameAsString())
                            .whyBadPractice(
                                    "Spring can bind request payloads successfully even when"
                                        + " business-critical fields are missing, out of range, or"
                                        + " structurally inconsistent.")
                            .possibleImpact(
                                    "Invalid input can travel deeper into service logic before"
                                        + " being rejected, which makes failure handling and client"
                                        + " error reporting less predictable.")
                            .recommendation(
                                    "Add @Valid or @Validated at the request boundary and place"
                                            + " validation annotations on the DTO fields that must"
                                            + " satisfy business constraints.")
                            .evidence(
                                    "Parameter "
                                            + parameter.getNameAsString()
                                            + " of type "
                                            + parameter.getTypeAsString()
                                            + " in "
                                            + relativePath
                                            + " is annotated with @RequestBody without a local"
                                            + " @Valid or @Validated annotation. DTO validation"
                                            + " annotations detected: "
                                            + (validationSignals.hasValidationAnnotations()
                                                    ? "yes"
                                                    : "no")
                                            + ".")
                            .limitations(
                                    "Static analysis cannot prove whether validation occurs in a"
                                        + " custom argument resolver, service layer, or downstream"
                                        + " pipeline.")
                            .source(
                                    relativePath,
                                    parameter
                                            .getBegin()
                                            .map(position -> position.line)
                                            .orElse(
                                                    method.getBegin()
                                                            .map(position -> position.line)
                                                            .orElse(null)))
                            .target(declaration.getNameAsString() + "#" + method.getNameAsString())
                            .build());
        }
        for (Parameter parameter : method.getParameters()) {
            if (!hasAnnotation(parameter.getAnnotations(), "ModelAttribute")) {
                continue;
            }
            if (hasAnnotation(parameter.getAnnotations(), "Valid")
                    || hasAnnotation(parameter.getAnnotations(), "Validated")) {
                continue;
            }
            if (!isValidationCandidateType(parameter)) {
                continue;
            }
            ValidationSignals validationSignals = validationSignals(parameter, declaration);
            if (!validationSignals.shouldFlag()) {
                continue;
            }
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_MODEL_ATTRIBUTE_NO_VALID,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "@ModelAttribute parameter is missing @Valid: "
                                            + declaration.getNameAsString()
                                            + "#"
                                            + method.getNameAsString())
                            .whyBadPractice(
                                    "Spring binds form or query parameters to the model attribute"
                                            + " without validating constraints unless @Valid or"
                                            + " @Validated is present.")
                            .possibleImpact(
                                    "Invalid form input reaches service logic unchecked, making it"
                                            + " harder to return precise client error messages.")
                            .recommendation(
                                    "Add @Valid or @Validated to the @ModelAttribute parameter and"
                                            + " annotate the DTO fields with Bean Validation"
                                            + " constraints.")
                            .evidence(
                                    "Parameter "
                                            + parameter.getNameAsString()
                                            + " of type "
                                            + parameter.getTypeAsString()
                                            + " in "
                                            + relativePath
                                            + " is annotated with @ModelAttribute without @Valid or"
                                            + " @Validated. DTO validation annotations detected: "
                                            + (validationSignals.hasValidationAnnotations()
                                                    ? "yes"
                                                    : "no")
                                            + ".")
                            .limitations(
                                    "Static analysis cannot prove whether validation occurs in a"
                                            + " custom argument resolver or service layer.")
                            .source(
                                    relativePath,
                                    parameter
                                            .getBegin()
                                            .map(position -> position.line)
                                            .orElse(
                                                    method.getBegin()
                                                            .map(position -> position.line)
                                                            .orElse(null)))
                            .target(declaration.getNameAsString() + "#" + method.getNameAsString())
                            .build());
        }
    }

    private TransactionalSelfInvocationTarget resolveTransactionalSelfInvocationTarget(
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration caller,
            MethodCallExpr call,
            boolean legacyTransactionalVisibility) {
        List<MethodDeclaration> candidates =
                declaration.getMethodsByName(call.getNameAsString()).stream()
                        .filter(candidate -> invocationArityMatches(candidate, call))
                        .toList();
        // Without symbol solving, same-arity overloads cannot be resolved reliably. Prefer a
        // missed finding over assigning the annotation from the wrong overload.
        if (candidates.size() != 1) {
            return null;
        }
        MethodDeclaration candidate = candidates.getFirst();
        if (candidate == caller
                || !isEligibleTransactionalProxyMethod(
                        declaration, candidate, legacyTransactionalVisibility)) {
            return null;
        }
        AnnotationExpr annotation = effectiveTransactionalAnnotation(declaration, candidate);
        return annotation == null
                ? null
                : new TransactionalSelfInvocationTarget(candidate, annotation);
    }

    private boolean invocationArityMatches(MethodDeclaration method, MethodCallExpr call) {
        int parameterCount = method.getParameters().size();
        int argumentCount = call.getArguments().size();
        if (parameterCount > 0 && method.getParameter(parameterCount - 1).isVarArgs()) {
            return argumentCount >= parameterCount - 1;
        }
        return argumentCount == parameterCount;
    }

    private boolean isEligibleTransactionalProxyMethod(
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            boolean legacyTransactionalVisibility) {
        if (method.isPrivate() || method.isStatic() || method.isFinal()) {
            return false;
        }
        return !legacyTransactionalVisibility || declaration.isInterface() || method.isPublic();
    }

    private AnnotationExpr effectiveTransactionalAnnotation(
            ClassOrInterfaceDeclaration declaration, MethodDeclaration method) {
        AnnotationExpr methodAnnotation = transactionalAnnotation(method.getAnnotations());
        return methodAnnotation != null
                ? methodAnnotation
                : transactionalAnnotation(declaration.getAnnotations());
    }

    private AnnotationExpr transactionalAnnotation(NodeList<AnnotationExpr> annotations) {
        return annotations.stream()
                .filter(
                        candidate ->
                                "Transactional".equals(simpleName(candidate.getNameAsString())))
                .findFirst()
                .orElse(null);
    }

    private boolean callerTransactionGuaranteesActiveTransaction(
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            AnnotationExpr annotation,
            boolean legacyTransactionalVisibility) {
        if (annotation == null) {
            return false;
        }
        if (!isEligibleTransactionalProxyMethod(
                declaration, method, legacyTransactionalVisibility)) {
            return false;
        }
        String propagation = transactionalPropagation(annotation);
        return Set.of("REQUIRED", "REQUIRES_NEW", "NESTED", "MANDATORY").contains(propagation);
    }

    private boolean transactionalProxyChangesContext(
            AnnotationExpr callerAnnotation,
            boolean callerHasActiveTransaction,
            AnnotationExpr targetAnnotation) {
        String targetPropagation = transactionalPropagation(targetAnnotation);
        if (targetPropagation == null) {
            return false;
        }
        if (!callerHasActiveTransaction) {
            // An unannotated entry point may itself be called inside an outer transaction. A plain
            // REQUIRED callee would simply join it, so reporting that common shape creates far more
            // noise than signal. Keep only semantics that materially require proxy interception.
            if (callerAnnotation == null) {
                return Set.of("REQUIRES_NEW", "NESTED", "NOT_SUPPORTED", "NEVER")
                                .contains(targetPropagation)
                        || hasDistinctTransactionalInterceptorSemantics(targetAnnotation);
            }
            return Set.of("REQUIRED", "REQUIRES_NEW", "NESTED", "MANDATORY")
                            .contains(targetPropagation)
                    || hasDistinctTransactionalInterceptorSemantics(targetAnnotation);
        }
        if (Set.of("REQUIRES_NEW", "NESTED", "NOT_SUPPORTED", "NEVER")
                .contains(targetPropagation)) {
            return true;
        }
        if (transactionalAnnotationsEquivalent(callerAnnotation, targetAnnotation)) {
            return false;
        }
        return hasDistinctTransactionalInterceptorSemantics(targetAnnotation);
    }

    private String transactionalPropagation(AnnotationExpr annotation) {
        if (annotation == null || !annotation.isNormalAnnotationExpr()) {
            return annotation == null ? null : "REQUIRED";
        }
        return annotation.asNormalAnnotationExpr().getPairs().stream()
                .filter(pair -> "propagation".equals(pair.getNameAsString()))
                .map(pair -> simpleName(pair.getValue().toString()))
                .findFirst()
                .orElse("REQUIRED");
    }

    private boolean transactionalAnnotationsEquivalent(
            AnnotationExpr callerAnnotation, AnnotationExpr targetAnnotation) {
        return callerAnnotation != null
                && callerAnnotation.toString().equals(targetAnnotation.toString());
    }

    private boolean hasDistinctTransactionalInterceptorSemantics(AnnotationExpr annotation) {
        if (annotation.isMarkerAnnotationExpr()) {
            return false;
        }
        // @Transactional("orders") selects a transaction manager and therefore needs its own
        // interceptor even when the caller already has a transaction.
        if (annotation.isSingleMemberAnnotationExpr()) {
            Expression value = annotation.asSingleMemberAnnotationExpr().getMemberValue();
            return !(value instanceof LiteralStringValueExpr literal
                    && literal.getValue().isBlank());
        }
        return annotation.asNormalAnnotationExpr().getPairs().stream()
                .anyMatch(
                        pair -> {
                            String member = pair.getNameAsString();
                            if (Set.of("value", "transactionManager").contains(member)) {
                                return !(pair.getValue() instanceof LiteralStringValueExpr literal
                                        && literal.getValue().isBlank());
                            }
                            if (Set.of(
                                            "rollbackFor",
                                            "rollbackForClassName",
                                            "noRollbackFor",
                                            "noRollbackForClassName")
                                    .contains(member)) {
                                return !pair.getValue().isArrayInitializerExpr()
                                        || !pair.getValue()
                                                .asArrayInitializerExpr()
                                                .getValues()
                                                .isEmpty();
                            }
                            if (!"propagation".equals(member)) {
                                return false;
                            }
                            String propagation = simpleName(pair.getValue().toString());
                            return Set.of("REQUIRES_NEW", "NESTED", "NOT_SUPPORTED", "NEVER")
                                    .contains(propagation);
                        });
    }

    private CatchAnalysis analyzeCatchBody(BlockStmt body, String variableName) {
        List<Statement> statements = body.getStatements();
        boolean emptyLike =
                statements.isEmpty() || statements.stream().allMatch(EmptyStmt.class::isInstance);
        String comments = allCommentText(body);
        boolean commentOnly = emptyLike && !comments.isBlank();
        boolean hasStrongLogging = hasVisibleLogging(body, Set.of("warn", "error"));
        boolean hasWeakLogging = hasVisibleLogging(body, Set.of("debug", "trace", "info"));
        boolean rethrows = !body.findAll(ThrowStmt.class).isEmpty();
        boolean restoresInterrupt =
                body.findAll(MethodCallExpr.class).stream().anyMatch(this::isInterruptRestoreCall);
        boolean fallbackReturn =
                body.findAll(ReturnStmt.class).stream().anyMatch(this::isFallbackReturn);
        boolean fallbackLoopControl =
                !body.findAll(BreakStmt.class).isEmpty()
                        || !body.findAll(ContinueStmt.class).isEmpty();
        boolean fallbackAssignment = hasFallbackAssignmentOnly(statements);
        boolean intentionalIgnoreSafe =
                emptyLike
                        && IGNORE_VARIABLE_NAMES.contains(
                                defaultString(variableName).toLowerCase(Locale.ROOT))
                        && hasBenignIgnoreComment(comments);
        String fallbackDescription = describeFallback(statements);
        return new CatchAnalysis(
                emptyLike,
                hasStrongLogging,
                hasWeakLogging,
                rethrows,
                restoresInterrupt,
                fallbackReturn || fallbackLoopControl || fallbackAssignment,
                intentionalIgnoreSafe,
                commentOnly,
                fallbackDescription);
    }

    private boolean hasFallbackAssignmentOnly(List<Statement> statements) {
        if (statements.isEmpty()) {
            return false;
        }
        return statements.stream()
                .allMatch(
                        statement -> {
                            if (statement instanceof ExpressionStmt expressionStmt) {
                                Expression expression = expressionStmt.getExpression();
                                if (expression instanceof AssignExpr assignExpr) {
                                    return isFallbackExpression(assignExpr.getValue());
                                }
                            }
                            return false;
                        });
    }

    private String describeFallback(List<Statement> statements) {
        for (Statement statement : statements) {
            if (statement instanceof ReturnStmt returnStmt) {
                return "return " + returnStmt.getExpression().map(Expression::toString).orElse("");
            }
            if (statement instanceof BreakStmt) {
                return "break";
            }
            if (statement instanceof ContinueStmt) {
                return "continue";
            }
            if (statement instanceof ExpressionStmt expressionStmt
                    && expressionStmt.getExpression() instanceof AssignExpr assignExpr) {
                return "assignment to fallback value " + assignExpr.getTarget();
            }
        }
        return "fallback control flow";
    }

    private boolean isFallbackReturn(ReturnStmt returnStmt) {
        return returnStmt.getExpression().map(this::isFallbackExpression).orElse(false);
    }

    private boolean isFallbackExpression(Expression expression) {
        if (expression instanceof NullLiteralExpr || expression instanceof BooleanLiteralExpr) {
            return true;
        }
        if (expression instanceof LiteralStringValueExpr literalStringValueExpr) {
            return literalStringValueExpr.getValue().isBlank();
        }
        String rendered = expression.toString();
        return rendered.equals("Optional.empty()")
                || rendered.equals("List.of()")
                || rendered.equals("Map.of()")
                || rendered.equals("Set.of()")
                || rendered.startsWith("Collections.empty")
                || rendered.equals("false")
                || rendered.equals("true");
    }

    private boolean hasVisibleLogging(BlockStmt body, Set<String> levels) {
        return body.findAll(MethodCallExpr.class).stream()
                .anyMatch(
                        call ->
                                levels.contains(call.getNameAsString())
                                        && call.getScope()
                                                .map(
                                                        scope -> {
                                                            String rendered = scope.toString();
                                                            return rendered.equals("log")
                                                                    || rendered.equals("logger")
                                                                    || rendered.equals("LOGGER")
                                                                    || rendered.equals("LOG");
                                                        })
                                                .orElse(false));
    }

    private boolean isInterruptRestoreCall(MethodCallExpr call) {
        return "interrupt".equals(call.getNameAsString())
                && call.getScope()
                        .map(Expression::toString)
                        .orElse("")
                        .equals("Thread.currentThread()");
    }

    private Optional<Node> findRawExceptionMessageExposureNode(
            BlockStmt body, String exceptionVariableName) {
        String needle = exceptionVariableName + ".getMessage()";
        Optional<Node> returnNode =
                body.findAll(ReturnStmt.class).stream()
                        .filter(
                                statement ->
                                        statement
                                                .getExpression()
                                                .map(Expression::toString)
                                                .filter(text -> text.contains(needle))
                                                .isPresent())
                        .map(statement -> (Node) statement)
                        .findFirst();
        if (returnNode.isPresent()) {
            return returnNode;
        }
        return body.findAll(MethodCallExpr.class).stream()
                .filter(
                        call -> {
                            if (!Set.of("body", "put", "setDetail")
                                    .contains(call.getNameAsString())) {
                                return false;
                            }
                            return call.getArguments().stream()
                                    .map(Expression::toString)
                                    .anyMatch(text -> text.contains(needle));
                        })
                .map(call -> (Node) call)
                .findFirst();
    }

    private Optional<Node> findRawExceptionMessageExposureNode(MethodDeclaration method) {
        Set<String> exceptionParameters =
                method.getParameters().stream()
                        .filter(
                                parameter ->
                                        parameter.getTypeAsString().endsWith("Exception")
                                                || parameter.getTypeAsString().endsWith("Throwable")
                                                || parameter
                                                        .getTypeAsString()
                                                        .endsWith("RuntimeException"))
                        .map(Parameter::getNameAsString)
                        .collect(Collectors.toSet());
        if (exceptionParameters.isEmpty()) {
            return Optional.empty();
        }
        for (String name : exceptionParameters) {
            Optional<Node> exposure =
                    method.getBody()
                            .flatMap(body -> findRawExceptionMessageExposureNode(body, name));
            if (exposure.isPresent()) {
                return exposure;
            }
        }
        return Optional.empty();
    }

    private boolean handlesBroadException(MethodDeclaration method) {
        return method.getAnnotationByName("ExceptionHandler")
                .map(AnnotationExpr::toString)
                .map(
                        annotation ->
                                annotation.contains("Exception.class")
                                        || annotation.contains("RuntimeException.class")
                                        || annotation.contains("Throwable.class"))
                .orElse(false);
    }

    private String broadExceptionHandlerResponseBehavior(MethodDeclaration method) {
        String normalized = method.toString().toLowerCase(Locale.ROOT);
        if (normalized.contains("badrequest(")
                || normalized.contains("status(400)")
                || normalized.contains("httpstatus.bad_request")) {
            return "HTTP 400-style response";
        }
        if (normalized.contains("ok(")
                || normalized.contains("status(200)")
                || normalized.contains("httpstatus.ok")) {
            return "HTTP 200-style response";
        }
        return null;
    }

    private SourceLocation methodLocation(
            ExceptionHandlingContext context, MethodDeclaration method) {
        Integer startLine = method.getBegin().map(position -> position.line).orElse(null);
        Integer endLine = method.getEnd().map(position -> position.line).orElse(startLine);
        if (startLine == null) {
            return null;
        }
        return new SourceLocation(
                context.relativePath(),
                startLine,
                endLine == null ? startLine : endLine,
                method.getBegin().map(position -> position.column).orElse(null),
                method.getEnd().map(position -> position.column).orElse(null),
                context.target(),
                "java",
                null);
    }

    private SourceLocation nodeLocation(
            String relativePath, String target, Node node, SourceLocation fallback) {
        Integer startLine = node.getBegin().map(position -> position.line).orElse(null);
        if (startLine == null) {
            return fallback;
        }
        int endLine = node.getEnd().map(position -> position.line).orElse(startLine);
        Integer startColumn = node.getBegin().map(position -> position.column).orElse(null);
        Integer endColumn = node.getEnd().map(position -> position.column).orElse(null);
        return new SourceLocation(
                relativePath, startLine, endLine, startColumn, endColumn, target, "java", null);
    }

    private HighlightRange highlightRangeFor(SourceLocation location) {
        return new HighlightRange(
                location.startLine(),
                location.endLine(),
                location.startColumn(),
                location.endColumn(),
                "issue");
    }

    private String summarizeNode(Node node) {
        String compact = node.toString().replaceAll("\\s+", " ").trim();
        return compact.length() > 160 ? compact.substring(0, 157) + "..." : compact;
    }

    private boolean isInterruptedType(String typeName) {
        return "InterruptedException".equals(simpleName(typeName));
    }

    private boolean isBroadCatchType(String typeName) {
        String simple = simpleName(typeName);
        return simple.equals("Exception")
                || simple.equals("RuntimeException")
                || simple.equals("Throwable");
    }

    private boolean isFatalCatchType(String typeName) {
        String simple = simpleName(typeName);
        return simple.equals("Throwable")
                || simple.equals("Error")
                || simple.equals("VirtualMachineError")
                || simple.equals("OutOfMemoryError")
                || simple.equals("StackOverflowError");
    }

    private Set<String> caughtTypeNames(CatchClause catchClause) {
        if (catchClause.getParameter().getType() instanceof UnionType unionType) {
            return unionType.getElements().stream()
                    .map(type -> simpleName(type.asString()))
                    .collect(Collectors.toCollection(LinkedHashSet::new));
        }
        return Set.of(simpleName(catchClause.getParameter().getTypeAsString()));
    }

    private boolean isTopLevelUncaughtHandler(
            ClassOrInterfaceDeclaration declaration, MethodDeclaration method) {
        return implementsAny(declaration, Set.of("UncaughtExceptionHandler"))
                && "uncaughtException".equals(method.getNameAsString());
    }

    private boolean isGeneratedSource(
            String relativePath, ClassOrInterfaceDeclaration declaration) {
        String normalizedPath = relativePath.toLowerCase(Locale.ROOT);
        return normalizedPath.contains("/generated/")
                || hasAnnotation(declaration.getAnnotations(), "Generated");
    }

    private String allCommentText(BlockStmt body) {
        return body.getAllContainedComments().stream()
                .map(comment -> comment.getContent().toLowerCase(Locale.ROOT))
                .collect(Collectors.joining(" "));
    }

    private boolean hasBenignIgnoreComment(String comments) {
        if (comments == null || comments.isBlank()) {
            return false;
        }
        return BENIGN_IGNORE_COMMENT_MARKERS.stream().anyMatch(comments::contains);
    }

    private boolean isLikelyParserFallback(
            ExceptionHandlingContext context, Set<String> caughtTypes, CatchAnalysis analysis) {
        if (context.productionLikeBoundary()) {
            return false;
        }
        if (!analysis.usesFallbackWithoutVisibleHandling() && !analysis.emptyLike()) {
            return false;
        }
        String normalizedTarget = defaultString(context.target()).toLowerCase(Locale.ROOT);
        boolean parserLikeName =
                normalizedTarget.contains("#parse")
                        || normalizedTarget.contains("#tryparse")
                        || normalizedTarget.contains("#extract")
                        || normalizedTarget.contains("#decode")
                        || normalizedTarget.contains("#convert")
                        || normalizedTarget.contains("#normalize");
        if (!parserLikeName) {
            return false;
        }
        return caughtTypes.stream()
                .map(this::simpleName)
                .anyMatch(
                        type ->
                                type.equals("NumberFormatException")
                                        || type.equals("DateTimeParseException")
                                        || type.equals("ParseException")
                                        || type.equals("IllegalArgumentException"));
    }

    private void detectRepeatedFallbackParsingPattern(List<Finding> findings) {
        List<Finding> parserFallbacks =
                findings.stream()
                        .filter(Objects::nonNull)
                        .filter(
                                finding ->
                                        FindingRules.SPRING_SWALLOWED_EXCEPTION_FALLBACK
                                                        .ruleId()
                                                        .equals(finding.ruleId())
                                                || FindingRules.JAVA_EMPTY_CATCH_BLOCK
                                                        .ruleId()
                                                        .equals(finding.ruleId()))
                        .filter(this::isParserLikeFallbackFinding)
                        .toList();
        if (parserFallbacks.size() < 3) {
            return;
        }
        Set<String> classes =
                parserFallbacks.stream()
                        .map(Finding::target)
                        .filter(Objects::nonNull)
                        .map(
                                target ->
                                        target.contains("#")
                                                ? target.substring(0, target.indexOf('#'))
                                                : target)
                        .collect(Collectors.toCollection(LinkedHashSet::new));
        if (classes.size() < 2) {
            return;
        }
        String evidence =
                parserFallbacks.stream()
                        .map(finding -> defaultString(finding.target(), finding.sourceFile()))
                        .filter(value -> !value.isBlank())
                        .limit(6)
                        .collect(Collectors.joining(", "));
        if (parserFallbacks.size() > 6) {
            evidence = evidence + ", ...";
        }
        SourceLocation firstFallbackLocation =
                parserFallbacks.stream()
                        .map(Finding::primaryLocation)
                        .filter(Objects::nonNull)
                        .findFirst()
                        .orElse(null);
        FindingFactory.Builder patternBuilder =
                FindingFactory.builder(
                                FindingRules.SPRING_REPEATED_FALLBACK_PARSING_PATTERN,
                                FindingConfidence.MEDIUM)
                        .shortMessage(
                                "Similar parse/fallback exception handling appears in multiple"
                                        + " classes.")
                        .whyBadPractice(
                                "Repeated parser helpers that silently fall back on exceptions"
                                        + " spread data-loss behavior across the codebase and make"
                                        + " failure handling harder to reason about consistently.")
                        .possibleImpact(
                                "Unexpected input can be dropped in slightly different ways across"
                                    + " parsing paths, which makes data quality issues harder to"
                                    + " diagnose and operational behavior harder to compare.")
                        .recommendation(
                                "Consider centralizing parsing rules and making fallback behavior"
                                    + " explicit with typed parse results, comments, metrics, or"
                                    + " targeted debug logging where the behavior matters"
                                    + " operationally.")
                        .evidence(
                                "Parser-like fallback handling was detected in multiple locations: "
                                        + evidence
                                        + ".")
                        .limitations(
                                "Static analysis cannot prove whether every fallback is wrong, but"
                                        + " repeated silent parsing fallbacks are worth reviewing"
                                        + " together.")
                        .target("Multiple parsing helpers");
        if (firstFallbackLocation != null) {
            patternBuilder.sourceLocation(firstFallbackLocation);
        } else {
            patternBuilder.location("Exception handling");
        }
        for (Finding fallback : parserFallbacks) {
            if (fallback.primaryLocation() != null) {
                String occMsg = defaultString(fallback.target(), fallback.sourceFile());
                patternBuilder.addOccurrence(
                        new FindingOccurrence(occMsg, fallback.primaryLocation(), null));
            }
        }
        findings.add(patternBuilder.build());
    }

    private boolean isParserLikeFallbackFinding(Finding finding) {
        String target = defaultString(finding.target()).toLowerCase(Locale.ROOT);
        String why = defaultString(finding.whyBadPractice()).toLowerCase(Locale.ROOT);
        return target.contains("#parse")
                || target.contains("#tryparse")
                || target.contains("#extract")
                || target.contains("#decode")
                || target.contains("#convert")
                || target.contains("#normalize")
                || why.contains("best-effort parsing");
    }

    private MethodSignals methodSignals(String body, String methodName) {
        String normalized = body.toLowerCase(Locale.ROOT);
        boolean httpCalls =
                normalized.contains(".retrieve(")
                        || normalized.contains(".exchange(")
                        || normalized.contains(".exchangetomono(")
                        || normalized.contains(".exchangetoflux(")
                        || normalized.contains("getforobject(")
                        || normalized.contains("getforentity(")
                        || normalized.contains("postforobject(")
                        || normalized.contains("postforentity(")
                        || normalized.contains(".execute(")
                        || normalized.contains(".block()")
                        || normalized.contains(".toentity(")
                        || normalized.contains(".bodytomono(")
                        || normalized.contains(".bodytoflux(");
        int writeCalls = 0;
        for (String marker : WRITE_CALL_MARKERS) {
            writeCalls += countOccurrences(normalized, "." + marker.toLowerCase(Locale.ROOT) + "(");
        }
        boolean persistenceSignals =
                normalized.contains("repository.")
                        || normalized.contains("jdbctemplate.")
                        || normalized.contains("namedparameterjdbctemplate.")
                        || normalized.contains("entitymanager.")
                        || normalized.contains("crudrepository")
                        || normalized.contains("springdata")
                        || normalized.contains("hibernate");
        boolean fileOps =
                normalized.contains("files.writestring")
                        || normalized.contains("files.write(")
                        || normalized.contains("deleteifexists")
                        || normalized.contains("files.delete(")
                        || normalized.contains("fileoutputstream(");
        boolean threadCreation =
                (normalized.contains("new thread(") && normalized.contains(".start("))
                        || normalized.contains("executor.submit(")
                        || normalized.contains("executor.execute(")
                        || normalized.contains("taskscheduler.schedule(")
                        || normalized.contains("scheduler.schedule(");
        boolean messagingCalls =
                normalized.contains(".publish(")
                        || normalized.contains(".send(")
                        || normalized.contains(".convertandsend(")
                        || normalized.contains("kafkatemplate.send(")
                        || normalized.contains("rabbittemplate.convertandsend(");
        boolean repositoryLoop =
                normalized.contains("for (")
                        || normalized.contains("foreach")
                        || normalized.contains("while (");
        boolean tryCatch = normalized.contains("try {");
        return new MethodSignals(
                httpCalls,
                writeCalls,
                persistenceSignals,
                fileOps,
                threadCreation,
                messagingCalls,
                repositoryLoop,
                tryCatch,
                methodName);
    }

    private boolean isWriteLikeEndpoint(MethodDeclaration method) {
        return method.getAnnotations().stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .anyMatch(
                        name ->
                                Set.of("PostMapping", "PutMapping", "PatchMapping", "DeleteMapping")
                                        .contains(name));
    }

    private boolean isValidationCandidateType(Parameter parameter) {
        String type = parameter.getTypeAsString();
        String simpleType = simpleName(type);
        return !parameter.getType().isPrimitiveType()
                && !simpleType.equals("String")
                && !simpleType.equals("Map")
                && !simpleType.equals("JsonNode")
                && !simpleType.equals("MultipartFile")
                && !type.equals("byte[]")
                && !simpleType.equals("Object");
    }

    private ValidationSignals validationSignals(
            Parameter parameter, ClassOrInterfaceDeclaration declaration) {
        String typeName = simpleName(parameter.getTypeAsString());
        if (typeName.isBlank()) {
            return new ValidationSignals(false, false);
        }
        CompilationUnit compilationUnit = declaration.findCompilationUnit().orElse(null);
        if (compilationUnit == null) {
            return new ValidationSignals(
                    false,
                    typeName.endsWith("Request")
                            || typeName.endsWith("Dto")
                            || typeName.endsWith("Command"));
        }
        for (RecordDeclaration recordDeclaration :
                compilationUnit.findAll(RecordDeclaration.class)) {
            if (!recordDeclaration.getNameAsString().equals(typeName)) {
                continue;
            }
            boolean hasValidationAnnotations =
                    recordDeclaration.getAnnotations().stream()
                                    .anyMatch(this::looksLikeValidationAnnotation)
                            || recordDeclaration.getParameters().stream()
                                    .flatMap(
                                            recordParameter ->
                                                    recordParameter.getAnnotations().stream())
                                    .anyMatch(this::looksLikeValidationAnnotation);
            boolean looksCritical =
                    recordDeclaration.getParameters().stream()
                            .map(parameterNode -> parameterNode.getNameAsString())
                            .anyMatch(this::looksBusinessCriticalField);
            return new ValidationSignals(hasValidationAnnotations, looksCritical);
        }
        for (ClassOrInterfaceDeclaration candidate :
                compilationUnit.findAll(ClassOrInterfaceDeclaration.class)) {
            if (!candidate.getNameAsString().equals(typeName)) {
                continue;
            }
            boolean hasValidationAnnotations =
                    candidate.getAnnotations().stream()
                                    .anyMatch(this::looksLikeValidationAnnotation)
                            || candidate.findAll(FieldDeclaration.class).stream()
                                    .flatMap(field -> field.getAnnotations().stream())
                                    .anyMatch(this::looksLikeValidationAnnotation);
            boolean looksCritical =
                    candidate.findAll(VariableDeclarator.class).stream()
                            .map(VariableDeclarator::getNameAsString)
                            .anyMatch(this::looksBusinessCriticalField);
            return new ValidationSignals(hasValidationAnnotations, looksCritical);
        }
        return new ValidationSignals(
                false,
                typeName.endsWith("Request")
                        || typeName.endsWith("Dto")
                        || typeName.endsWith("Command"));
    }

    private boolean looksLikeValidationAnnotation(AnnotationExpr annotation) {
        String name = simpleName(annotation.getNameAsString());
        return name.startsWith("Not")
                || name.equals("Valid")
                || name.equals("Validated")
                || name.equals("Size")
                || name.equals("Min")
                || name.equals("Max")
                || name.equals("DecimalMin")
                || name.equals("DecimalMax")
                || name.equals("Email")
                || name.equals("Pattern");
    }

    private boolean looksBusinessCriticalField(String fieldName) {
        String normalized = fieldName.toLowerCase(Locale.ROOT);
        return normalized.contains("amount")
                || normalized.contains("quantity")
                || normalized.contains("limit")
                || normalized.contains("days")
                || normalized.contains("percent")
                || normalized.contains("email")
                || normalized.contains("symbol")
                || normalized.contains("interval")
                || normalized.contains("price")
                || normalized.contains("id");
    }

    private boolean isStartupHook(
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            boolean startupInterface) {
        if (hasAnnotation(method.getAnnotations(), "PostConstruct")) {
            return true;
        }
        if (hasAnnotation(method.getAnnotations(), "EventListener")
                && method.getAnnotationByName("EventListener")
                        .map(AnnotationExpr::toString)
                        .map(text -> text.contains("ApplicationReadyEvent"))
                        .orElse(false)) {
            return true;
        }
        if (startupInterface && "run".equals(method.getNameAsString())) {
            return true;
        }
        return implementsAny(declaration, Set.of("InitializingBean"))
                        && "afterPropertiesSet".equals(method.getNameAsString())
                || implementsAny(declaration, Set.of("SmartLifecycle"))
                        && "start".equals(method.getNameAsString());
    }

    private String startupHookDescription(
            MethodDeclaration method, ClassOrInterfaceDeclaration declaration) {
        if (hasAnnotation(method.getAnnotations(), "PostConstruct")) {
            return "@PostConstruct";
        }
        if (hasAnnotation(method.getAnnotations(), "EventListener")) {
            return "@EventListener(ApplicationReadyEvent.class)";
        }
        if (implementsAny(declaration, Set.of("CommandLineRunner"))) {
            return "CommandLineRunner#run";
        }
        if (implementsAny(declaration, Set.of("ApplicationRunner"))) {
            return "ApplicationRunner#run";
        }
        if (implementsAny(declaration, Set.of("InitializingBean"))) {
            return "InitializingBean#afterPropertiesSet";
        }
        if (implementsAny(declaration, Set.of("SmartLifecycle"))) {
            return "SmartLifecycle#start";
        }
        return method.getNameAsString();
    }

    private boolean implementsAny(ClassOrInterfaceDeclaration declaration, Set<String> typeNames) {
        return declaration.getImplementedTypes().stream()
                .map(ClassOrInterfaceType::getNameAsString)
                .map(this::simpleName)
                .anyMatch(typeNames::contains);
    }

    private boolean hasAnyAnnotation(NodeList<AnnotationExpr> annotations, Set<String> names) {
        return annotations.stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .anyMatch(names::contains);
    }

    private boolean hasAnnotation(NodeList<AnnotationExpr> annotations, String name) {
        return annotations.stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .anyMatch(name::equals);
    }

    private Duration parseInterval(String value) {
        if (value == null || value.isBlank() || value.startsWith("${")) {
            return null;
        }
        String trimmed = value.trim();
        try {
            if (trimmed.startsWith("PT")) {
                return Duration.parse(trimmed);
            }
            if (trimmed.chars().allMatch(Character::isDigit)) {
                return Duration.ofMillis(Long.parseLong(trimmed));
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private String valueFor(Collection<MemberValuePair> pairs, String name) {
        return pairs.stream()
                .filter(pair -> name.equals(pair.getNameAsString()))
                .map(
                        pair ->
                                pair.getValue().isStringLiteralExpr()
                                        ? pair.getValue().asStringLiteralExpr().asString()
                                        : pair.getValue().toString().replace("\"", ""))
                .findFirst()
                .orElse(null);
    }

    private int countOccurrences(String value, String needle) {
        int count = 0;
        int index = 0;
        while ((index = value.indexOf(needle, index)) >= 0) {
            count++;
            index += needle.length();
        }
        return count;
    }

    private String simpleName(String value) {
        int separator = value.lastIndexOf('.');
        return separator < 0 ? value : value.substring(separator + 1);
    }

    private String defaultString(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate;
            }
        }
        return "";
    }

    private void detectFeignClientRisks(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        declaration
                .getAnnotationByName("FeignClient")
                .ifPresent(
                        annotation -> {
                            boolean hasFallback =
                                    annotation.isNormalAnnotationExpr()
                                            && annotation
                                                    .asNormalAnnotationExpr()
                                                    .getPairs()
                                                    .stream()
                                                    .anyMatch(
                                                            pair ->
                                                                    "fallback"
                                                                                    .equals(
                                                                                            pair
                                                                                                    .getNameAsString())
                                                                            || "fallbackFactory"
                                                                                    .equals(
                                                                                            pair
                                                                                                    .getNameAsString()));
                            if (!hasFallback) {
                                Integer line = declaration.getBegin().map(p -> p.line).orElse(null);
                                String name = declaration.getNameAsString();
                                findings.add(
                                        FindingFactory.builder(
                                                        FindingRules
                                                                .SPRING_FEIGN_NO_FALLBACK_OR_TIMEOUT,
                                                        FindingConfidence.MEDIUM)
                                                .shortMessage(
                                                        "@FeignClient "
                                                                + name
                                                                + " has no fallback or"
                                                                + " fallbackFactory.")
                                                .whyBadPractice(
                                                        "Without a fallback, any failure in the"
                                                            + " remote service propagates directly"
                                                            + " to the caller as an exception."
                                                            + " Feign's defaults are 10 s connect /"
                                                            + " 60 s read timeout — long enough for"
                                                            + " blocked threads to pile up under"
                                                            + " load when a downstream service"
                                                            + " degrades.")
                                                .possibleImpact(
                                                        "Thread pool exhaustion under sustained"
                                                            + " failure or latency in the remote"
                                                            + " service. Cascading failures across"
                                                            + " the call stack.")
                                                .recommendation(
                                                        "Add a fallback class via"
                                                            + " @FeignClient(fallback ="
                                                            + " MyFallback.class), or configure a"
                                                            + " circuit-breaker via Resilience4j."
                                                            + " Configure workload-appropriate"
                                                            + " timeouts via"
                                                            + " feign.client.config.<name>.connectTimeout"
                                                            + " and readTimeout instead of relying"
                                                            + " on the 10 s/60 s defaults.")
                                                .evidence(
                                                        "@FeignClient on "
                                                                + name
                                                                + " in "
                                                                + relativePath
                                                                + " has no fallback or"
                                                                + " fallbackFactory attribute.")
                                                .limitations(
                                                        "Static analysis cannot determine whether a"
                                                            + " global Resilience4j circuit-breaker"
                                                            + " or timeout is configured"
                                                            + " externally.")
                                                .source(relativePath, line)
                                                .target(name)
                                                .build());
                            }
                        });
    }

    private void detectRestTemplateNoStatusHandler(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        for (MethodDeclaration method : declaration.getMethods()) {
            if (!hasAnnotation(method.getAnnotations(), "Bean")) {
                continue;
            }
            if (!"RestTemplate".equals(simpleName(method.getTypeAsString()))) {
                continue;
            }
            boolean hasErrorHandler =
                    method.findAll(MethodCallExpr.class).stream()
                            .anyMatch(call -> "setErrorHandler".equals(call.getNameAsString()));
            if (!hasErrorHandler) {
                Integer line = method.getBegin().map(p -> p.line).orElse(null);
                String target = declaration.getNameAsString() + "#" + method.getNameAsString();
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_RESTTEMPLATE_NO_HTTP_STATUS_HANDLER,
                                        FindingConfidence.MEDIUM)
                                .shortMessage(
                                        "RestTemplate @Bean "
                                                + target
                                                + " has no custom error handler.")
                                .whyBadPractice(
                                        "By default, RestTemplate throws HttpClientErrorException"
                                            + " or HttpServerErrorException on 4xx/5xx responses."
                                            + " Without a custom ResponseErrorHandler, callers must"
                                            + " catch these specific Spring exceptions or let them"
                                            + " bubble up unexpectedly.")
                                .possibleImpact(
                                        "Non-2xx responses cause uncaught exceptions. Error details"
                                            + " from downstream services are lost or inconsistently"
                                            + " handled across different call sites.")
                                .recommendation(
                                        "Set a custom ResponseErrorHandler via"
                                            + " restTemplate.setErrorHandler(...) that converts"
                                            + " error responses to application-specific exceptions"
                                            + " with meaningful messages.")
                                .evidence(
                                        "@Bean RestTemplate method "
                                                + method.getNameAsString()
                                                + " in "
                                                + relativePath
                                                + " has no setErrorHandler call.")
                                .limitations(
                                        "Static analysis cannot determine whether error handling is"
                                            + " configured on the RestTemplate instance after the"
                                            + " @Bean method returns.")
                                .source(relativePath, line)
                                .target(target)
                                .build());
            }
        }
    }

    private void detectSqlInjectionInQueries(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        for (MethodDeclaration method : declaration.getMethods()) {
            for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {
                String callName = call.getNameAsString();
                if (!"createNativeQuery".equals(callName) && !"createQuery".equals(callName)) {
                    continue;
                }
                boolean hasConcat =
                        call.getArguments().stream()
                                .anyMatch(this::containsNonLiteralStringConcatenation);
                if (hasConcat) {
                    Integer line = call.getBegin().map(p -> p.line).orElse(null);
                    String target = declaration.getNameAsString() + "#" + method.getNameAsString();
                    findings.add(
                            FindingFactory.builder(
                                            FindingRules.SPRING_SQL_INJECTION_QUERY_CONCATENATION,
                                            FindingConfidence.HIGH)
                                    .shortMessage(
                                            "SQL query in "
                                                    + target
                                                    + " is built with string concatenation.")
                                    .whyBadPractice(
                                            "Building SQL queries by concatenating strings allows"
                                                    + " user-controlled input to alter the query"
                                                    + " structure, enabling SQL injection attacks.")
                                    .possibleImpact(
                                            "An attacker can read, modify, or delete arbitrary"
                                                + " data, bypass authentication, or execute stored"
                                                + " procedures depending on database permissions.")
                                    .recommendation(
                                            "Use named parameters or positional parameters. Replace"
                                                + " string concatenation with setParameter() calls"
                                                + " on the Query object.")
                                    .evidence(
                                            "createNativeQuery or createQuery with string"
                                                    + " concatenation detected in "
                                                    + target
                                                    + " in "
                                                    + relativePath
                                                    + ".")
                                    .limitations(
                                            "Static analysis cannot prove whether the concatenated"
                                                + " values are sanitized or come only from trusted"
                                                + " sources.")
                                    .source(relativePath, line)
                                    .target(target)
                                    .build());
                }
            }
        }
    }

    private boolean containsNonLiteralStringConcatenation(Expression expr) {
        if (!(expr instanceof BinaryExpr binaryExpr)) {
            return false;
        }
        if (binaryExpr.getOperator() != BinaryExpr.Operator.PLUS) {
            return false;
        }
        Expression left = binaryExpr.getLeft();
        Expression right = binaryExpr.getRight();
        boolean leftIsNonLiteral =
                left instanceof NameExpr
                        || left instanceof MethodCallExpr
                        || left instanceof FieldAccessExpr;
        boolean rightIsNonLiteral =
                right instanceof NameExpr
                        || right instanceof MethodCallExpr
                        || right instanceof FieldAccessExpr;
        return leftIsNonLiteral
                || rightIsNonLiteral
                || containsNonLiteralStringConcatenation(left)
                || containsNonLiteralStringConcatenation(right);
    }

    private void detectLoggingPiiExposure(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        Set<String> logMethodNames = Set.of("error", "warn", "info", "debug", "trace");
        for (MethodDeclaration method : declaration.getMethods()) {
            for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {
                if (!logMethodNames.contains(call.getNameAsString())) {
                    continue;
                }
                boolean isLogCall =
                        call.getScope()
                                .map(
                                        scope -> {
                                            String s = scope.toString().toLowerCase(Locale.ROOT);
                                            return s.equals("log")
                                                    || s.equals("logger")
                                                    || s.endsWith(".log")
                                                    || s.endsWith(".logger");
                                        })
                                .orElse(false);
                if (!isLogCall) {
                    continue;
                }
                for (Expression arg : call.getArguments()) {
                    String argStr = arg.toString().toLowerCase(Locale.ROOT);
                    boolean hasSensitiveRef = SENSITIVE_MARKERS.stream().anyMatch(argStr::contains);
                    if (hasSensitiveRef) {
                        Integer line = call.getBegin().map(p -> p.line).orElse(null);
                        String target =
                                declaration.getNameAsString() + "#" + method.getNameAsString();
                        findings.add(
                                FindingFactory.builder(
                                                FindingRules.SPRING_LOGGING_PII_EXPOSURE,
                                                FindingConfidence.MEDIUM)
                                        .shortMessage(
                                                "Potentially sensitive value logged in "
                                                        + target
                                                        + ".")
                                        .whyBadPractice(
                                                "Logging sensitive values such as passwords,"
                                                    + " tokens, or API keys makes them visible in"
                                                    + " log aggregation systems, operator consoles,"
                                                    + " and security audit trails.")
                                        .possibleImpact(
                                                "Credentials exposed in logs can be extracted by"
                                                        + " anyone with log read access — including"
                                                        + " operators, monitoring systems, or an"
                                                        + " attacker who compromises log storage.")
                                        .recommendation(
                                                "Redact or mask sensitive values before logging."
                                                    + " Use structured logging with explicit field"
                                                    + " whitelists and never include raw credential"
                                                    + " values.")
                                        .evidence(
                                                "Log statement in "
                                                        + target
                                                        + " contains a reference matching a"
                                                        + " sensitive-sounding name in "
                                                        + relativePath
                                                        + ".")
                                        .limitations(
                                                "Static analysis detects sensitive-looking names in"
                                                    + " log arguments but cannot prove the value is"
                                                    + " actually sensitive at runtime.")
                                        .source(relativePath, line)
                                        .target(target)
                                        .build());
                        break;
                    }
                }
            }
        }
    }

    private static final Set<String> PRINT_STREAM_TARGETS = Set.of("out", "err");
    private static final Set<String> PRINT_METHOD_NAMES =
            Set.of("print", "println", "printf", "format");

    private void detectSystemOutPrintln(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        for (MethodDeclaration method : declaration.getMethods()) {
            for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {
                if (!PRINT_METHOD_NAMES.contains(call.getNameAsString())) {
                    continue;
                }
                boolean isSystemStream =
                        call.getScope()
                                .filter(
                                        scope ->
                                                scope
                                                                instanceof
                                                                com.github.javaparser.ast.expr
                                                                                .FieldAccessExpr
                                                                        fa
                                                        && PRINT_STREAM_TARGETS.contains(
                                                                fa.getNameAsString())
                                                        && fa.getScope()
                                                                .toString()
                                                                .equals("System"))
                                .isPresent();
                if (!isSystemStream) {
                    continue;
                }
                Integer line = call.getBegin().map(p -> p.line).orElse(null);
                String target = declaration.getNameAsString() + "#" + method.getNameAsString();
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_SYSTEM_OUT_PRINTLN,
                                        FindingConfidence.HIGH)
                                .shortMessage(
                                        "System.out/err used for output instead of the application"
                                                + " logger.")
                                .whyBadPractice(
                                        "System.out and System.err bypass the configured logging"
                                            + " framework. Output goes to the raw JVM stdout/stderr"
                                            + " stream, which misses log levels, correlation IDs,"
                                            + " structured fields, and shipping to log"
                                            + " aggregators.")
                                .possibleImpact(
                                        "Operational information is lost or mixed with container"
                                            + " stdout noise. Log-based monitoring, alerting, and"
                                            + " audit trails will miss these lines.")
                                .recommendation(
                                        "Replace with a SLF4J logger: private static final Logger"
                                            + " log = LoggerFactory.getLogger(Foo.class); and use"
                                            + " log.info/warn/error/debug.")
                                .evidence(
                                        "System.out.println (or similar) detected in "
                                                + target
                                                + " at "
                                                + relativePath
                                                + ".")
                                .limitations(
                                        "Test classes are not analysed. System.out usage in"
                                                + " intentional diagnostic utilities may be a"
                                                + " false positive.")
                                .source(relativePath, line)
                                .target(target)
                                .build());
            }
        }
    }

    private static final Set<String> APPLICATION_CONTEXT_TYPES =
            Set.of(
                    "ApplicationContext",
                    "ConfigurableApplicationContext",
                    "WebApplicationContext",
                    "ConfigurableWebApplicationContext");

    private static boolean isApplicationContextField(FieldDeclaration field) {
        return field.getVariables().stream()
                .anyMatch(
                        v -> APPLICATION_CONTEXT_TYPES.contains(rawTypeName(v.getTypeAsString())));
    }

    private void detectApplicationContextInjected(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            FieldDeclaration field,
            List<Finding> findings) {
        String fieldName =
                field.getVariables().isEmpty()
                        ? "?"
                        : field.getVariables().get(0).getNameAsString();
        String typeName =
                field.getVariables().isEmpty()
                        ? "ApplicationContext"
                        : rawTypeName(field.getVariables().get(0).getTypeAsString());
        String target = declaration.getNameAsString() + "." + fieldName;
        Integer line = field.getBegin().map(p -> p.line).orElse(null);
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_APPLICATION_CONTEXT_INJECTED,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                typeName
                                        + " injected as a field in "
                                        + declaration.getNameAsString()
                                        + " — service-locator anti-pattern.")
                        .whyBadPractice(
                                "Injecting the ApplicationContext to look up beans at runtime"
                                    + " bypasses Spring's compile-time dependency graph. The class"
                                    + " can secretly depend on any bean in the context, making"
                                    + " dependencies invisible, tests harder to write, and"
                                    + " refactoring risky.")
                        .possibleImpact(
                                "Hidden coupling to arbitrary beans makes the class difficult to"
                                    + " test in isolation and obscures the real dependency surface."
                                    + " Bean lookup failures surface at runtime rather than at"
                                    + " startup.")
                        .recommendation(
                                "Declare each dependency explicitly via constructor injection. If"
                                        + " the dependency is truly optional or dynamic, consider"
                                        + " injecting a Provider<T> or ObjectProvider<T> instead.")
                        .evidence(
                                typeName
                                        + " field '"
                                        + fieldName
                                        + "' found in "
                                        + relativePath
                                        + ".")
                        .limitations(
                                "Some legitimate use cases require ApplicationContext access,"
                                        + " such as custom lifecycle hooks or framework extension"
                                        + " points in @Configuration classes (not flagged).")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private void detectEventListenerBlocking(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = declaration.getNameAsString() + "#" + method.getNameAsString();
        String annName =
                hasAnnotation(method.getAnnotations(), "TransactionalEventListener")
                        ? "TransactionalEventListener"
                        : "EventListener";
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_EVENT_LISTENER_BLOCKING, FindingConfidence.LOW)
                        .shortMessage(
                                "@"
                                        + annName
                                        + " method "
                                        + target
                                        + " runs synchronously on the publisher thread.")
                        .whyBadPractice(
                                "By default, Spring dispatches application events synchronously."
                                    + " The listener runs on the same thread as the code that"
                                    + " called ApplicationEventPublisher.publishEvent(). If the"
                                    + " listener performs slow work (email sending, remote calls,"
                                    + " heavy computation), it blocks the original thread for the"
                                    + " full duration.")
                        .possibleImpact(
                                "HTTP request threads can be blocked until the listener finishes,"
                                        + " increasing latency and reducing server throughput under"
                                        + " concurrent load.")
                        .recommendation(
                                "Add @Async to the listener method if the work is non-trivial"
                                        + " and does not need to run in the same thread. Ensure"
                                        + " @EnableAsync is present on a @Configuration class and"
                                        + " a custom ThreadPoolTaskExecutor is configured.")
                        .evidence(
                                "@"
                                        + annName
                                        + " without @Async found on "
                                        + target
                                        + " in "
                                        + relativePath
                                        + ".")
                        .limitations(
                                "Fast listeners that perform only lightweight, in-memory work"
                                        + " are fine without @Async. This finding is advisory and"
                                        + " requires human judgement.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private static String rawTypeName(String type) {
        int lt = type.indexOf('<');
        return lt >= 0 ? type.substring(0, lt).trim() : type.trim();
    }

    private void detectUnmanagedThread(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        for (MethodDeclaration method : declaration.getMethods()) {
            if (method.getBody().isEmpty()) {
                continue;
            }
            for (ObjectCreationExpr creation :
                    method.getBody().get().findAll(ObjectCreationExpr.class)) {
                if (!"Thread".equals(creation.getTypeAsString())) {
                    continue;
                }
                // Check the parent chain for .start() — common pattern: new Thread(...).start()
                // or thread variable later called with .start(). Flag on construction.
                Integer line = creation.getBegin().map(p -> p.line).orElse(null);
                String target = declaration.getNameAsString() + "#" + method.getNameAsString();
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_UNMANAGED_THREAD,
                                        FindingConfidence.HIGH)
                                .shortMessage(
                                        "Raw Thread created inside a Spring component instead of"
                                                + " using a managed executor.")
                                .whyBadPractice(
                                        "Manually created threads run outside Spring's container."
                                            + " They have no access to the current transaction"
                                            + " context, security context, or MDC logging"
                                            + " correlation IDs, and exceptions thrown on them are"
                                            + " not handled by Spring's unified error handling.")
                                .possibleImpact(
                                        "Silent data loss if a thread throws and the exception is"
                                            + " never observed. Security context not propagated to"
                                            + " the spawned thread. Unbounded thread creation can"
                                            + " exhaust server memory under load.")
                                .recommendation(
                                        "Use @Async with a configured ThreadPoolTaskExecutor, or"
                                            + " inject a TaskExecutor / ExecutorService bean and"
                                            + " submit Callables or Runnables to it. This keeps"
                                            + " threads managed, bounded, and observable.")
                                .evidence(
                                        "new Thread(...) detected in "
                                                + target
                                                + " at "
                                                + relativePath
                                                + ".")
                                .limitations(
                                        "The check triggers on any Thread construction inside"
                                                + " Spring stereotype components. Intentional"
                                                + " low-level thread management (e.g. a custom"
                                                + " lifecycle bean) may be a false positive.")
                                .source(relativePath, line)
                                .target(target)
                                .build());
                // One finding per method
                break;
            }
        }
    }

    private static final Set<String> MUTABLE_COLLECTION_TYPES =
            Set.of(
                    "List",
                    "ArrayList",
                    "LinkedList",
                    "Map",
                    "HashMap",
                    "LinkedHashMap",
                    "TreeMap",
                    "Set",
                    "HashSet",
                    "LinkedHashSet",
                    "TreeSet",
                    "Deque",
                    "ArrayDeque",
                    "Queue",
                    "PriorityQueue",
                    "Vector",
                    "Stack");

    private void detectStaticMutableField(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            FieldDeclaration field,
            List<Finding> findings) {
        String typeName = shortTypeName(field.getElementType().asString());
        if (!MUTABLE_COLLECTION_TYPES.contains(typeName)) {
            return;
        }
        Integer line = field.getBegin().map(p -> p.line).orElse(null);
        String fieldName = field.getVariable(0).getNameAsString();
        String target = declaration.getNameAsString() + "#" + fieldName;
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_STATIC_MUTABLE_FIELD, FindingConfidence.HIGH)
                        .shortMessage(
                                "Static mutable "
                                        + typeName
                                        + " field "
                                        + fieldName
                                        + " in Spring bean "
                                        + declaration.getNameAsString()
                                        + " — shared across all threads and requests.")
                        .whyBadPractice(
                                "A static non-final mutable collection in a Spring-managed class is"
                                    + " shared by every thread in the JVM. Any concurrent write"
                                    + " (add, remove, put) without explicit synchronization is a"
                                    + " data race. Even with synchronization, the cache accumulates"
                                    + " entries indefinitely and becomes inconsistent across"
                                    + " horizontally-scaled instances because each pod maintains"
                                    + " its own copy with no coordination.")
                        .possibleImpact(
                                "ConcurrentModificationException or silent data corruption under"
                                    + " concurrent load. Stale data returned after updates in a"
                                    + " multi-instance deployment. OutOfMemoryError if the"
                                    + " collection grows without bound. Bugs that are invisible in"
                                    + " single-user testing but manifest under load.")
                        .recommendation(
                                "If you need a per-request store, use a method-local variable or"
                                    + " inject a request-scoped bean. If you need a shared cache,"
                                    + " use Spring's @Cacheable with a proper cache provider"
                                    + " (Caffeine, Redis) that has TTL and eviction policies. If"
                                    + " you need a thread-safe counter, use AtomicLong or"
                                    + " Micrometer's Counter. Remove the static modifier and inject"
                                    + " the dependency through Spring's DI mechanism.")
                        .limitations(
                                "Detects static non-final fields whose declared type is a common"
                                    + " mutable collection. Thread-safe variants"
                                    + " (ConcurrentHashMap, CopyOnWriteArrayList) are not flagged"
                                    + " but still represent shared unbounded state. Constants"
                                    + " (static final) are not flagged.")
                        .evidence(
                                "static "
                                        + typeName
                                        + " "
                                        + fieldName
                                        + " in "
                                        + declaration.getNameAsString()
                                        + " ("
                                        + relativePath
                                        + ").")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private void detectTransactionalOnController(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        boolean classLevel = method == null;
        Integer line =
                classLevel
                        ? declaration.getBegin().map(p -> p.line).orElse(null)
                        : method.getBegin().map(p -> p.line).orElse(null);
        String target =
                classLevel
                        ? declaration.getNameAsString()
                        : declaration.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_TRANSACTIONAL_ON_CONTROLLER,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@Transactional on "
                                        + (classLevel ? "controller class " : "controller method ")
                                        + target
                                        + " — database connection held open during HTTP"
                                        + " processing.")
                        .whyBadPractice(
                                "Placing @Transactional on a controller means the database"
                                    + " transaction is open for the entire duration of request"
                                    + " handling, including request body parsing, business logic,"
                                    + " and — critically — response serialisation by Jackson."
                                    + " Jackson serialisation can trigger lazy-loading of JPA"
                                    + " associations, creating unintended queries inside the HTTP"
                                    + " layer. This violates the layered architecture: transaction"
                                    + " boundaries belong in the service layer.")
                        .possibleImpact(
                                "Database connections held for longer than necessary, increasing"
                                    + " connection pool pressure under load. Lazy-loading queries"
                                    + " triggered by Jackson during serialisation produce N+1 query"
                                    + " patterns. Deadlock risk if multiple controller methods"
                                    + " acquire locks in different orders.")
                        .recommendation(
                                "Move the @Transactional annotation to the service-layer method"
                                    + " that actually performs the database work. The controller"
                                    + " should call the service and serialize only the returned"
                                    + " DTO, which must not contain JPA proxy references.")
                        .limitations(
                                "High confidence when @Transactional appears directly on a class or"
                                        + " method that is also annotated with @RestController or"
                                        + " @Controller. Meta-annotated aliases are not detected.")
                        .evidence(
                                "@Transactional found on "
                                        + (classLevel ? "controller class " : "controller method ")
                                        + target
                                        + " in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private void detectRepositoryInController(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        // Check fields
        for (FieldDeclaration field : declaration.getFields()) {
            String typeName = shortTypeName(field.getElementType().asString());
            if (!isRepositoryType(typeName)) {
                continue;
            }
            Integer line = field.getBegin().map(p -> p.line).orElse(null);
            String fieldName = field.getVariable(0).getNameAsString();
            String target = declaration.getNameAsString() + "#" + fieldName;
            findings.add(buildRepositoryInControllerFinding(relativePath, target, typeName, line));
        }
        // Check constructor parameters
        for (ConstructorDeclaration ctor : declaration.getConstructors()) {
            for (Parameter param : ctor.getParameters()) {
                String typeName = shortTypeName(param.getTypeAsString());
                if (!isRepositoryType(typeName)) {
                    continue;
                }
                Integer line = param.getBegin().map(p -> p.line).orElse(null);
                String target = declaration.getNameAsString() + "(" + typeName + ")";
                findings.add(
                        buildRepositoryInControllerFinding(relativePath, target, typeName, line));
            }
        }
    }

    private static String shortTypeName(String typeName) {
        int dot = typeName.lastIndexOf('.');
        return dot >= 0 ? typeName.substring(dot + 1) : typeName;
    }

    private static boolean isRepositoryType(String simpleTypeName) {
        return simpleTypeName.endsWith("Repository")
                || simpleTypeName.endsWith("Dao")
                || simpleTypeName.endsWith("DAO");
    }

    private static Finding buildRepositoryInControllerFinding(
            String relativePath, String target, String typeName, Integer line) {
        return FindingFactory.builder(
                        FindingRules.SPRING_REPOSITORY_IN_CONTROLLER, FindingConfidence.HIGH)
                .shortMessage(
                        typeName
                                + " injected directly into a controller — service layer is"
                                + " bypassed.")
                .whyBadPractice(
                        "Controllers should be responsible only for HTTP concerns:"
                                + " routing, request parsing, and response serialization. When a"
                                + " repository is injected directly into a controller, persistence"
                                + " logic leaks into the web layer. Business rules, transactions,"
                                + " caching, and authorization decisions have no natural home and"
                                + " tend to accumulate in the controller, making the code hard to"
                                + " test, reuse, or reason about.")
                .possibleImpact(
                        "Business logic duplicated across controllers. No single place to add"
                                + " cross-cutting concerns (transactions, audit logging, caching)."
                                + " Controller tests require a full persistence stack instead of a"
                                + " simple service mock.")
                .recommendation(
                        "Introduce a @Service class that owns the business logic and calls the"
                                + " repository. The controller should call the service. This keeps"
                                + " each layer focused: web layer handles HTTP, service layer owns"
                                + " the domain, repository layer handles persistence.")
                .limitations(
                        "Detects injection of types whose name ends in Repository, Dao, or DAO."
                                + " A legitimately named class that is not actually a repository"
                                + " would produce a false positive.")
                .evidence(
                        "Controller "
                                + target
                                + " in "
                                + relativePath
                                + " directly injects "
                                + typeName
                                + ".")
                .source(relativePath, line)
                .target(target)
                .build();
    }

    private static final Set<String> HTTP_MAPPING_ANNOTATIONS =
            Set.of(
                    "GetMapping",
                    "PostMapping",
                    "PutMapping",
                    "PatchMapping",
                    "DeleteMapping",
                    "RequestMapping");

    private void detectEntityExposedInApi(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        // Collect @Entity simple names within this compilation unit and from imports
        Set<String> entityNames = new java.util.HashSet<>();
        declaration
                .findCompilationUnit()
                .ifPresent(
                        cu ->
                                cu.findAll(ClassOrInterfaceDeclaration.class).stream()
                                        .filter(
                                                cls ->
                                                        hasAnnotation(
                                                                cls.getAnnotations(), "Entity"))
                                        .map(ClassOrInterfaceDeclaration::getNameAsString)
                                        .forEach(entityNames::add));

        for (MethodDeclaration method : declaration.getMethods()) {
            if (!hasAnyAnnotation(method.getAnnotations(), HTTP_MAPPING_ANNOTATIONS)) {
                continue;
            }
            com.github.javaparser.ast.type.Type returnType = method.getType();
            if (containsEntityType(returnType, entityNames)) {
                Integer line = method.getBegin().map(p -> p.line).orElse(null);
                String target = declaration.getNameAsString() + "#" + method.getNameAsString();
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_ENTITY_EXPOSED_IN_API,
                                        FindingConfidence.HIGH)
                                .shortMessage(
                                        "REST endpoint returns a JPA entity directly instead of a"
                                                + " DTO.")
                                .whyBadPractice(
                                        "Returning @Entity types from REST controllers couples the"
                                            + " HTTP API to the persistence model. Jackson may"
                                            + " serialize lazy-loading proxies and trigger N+1"
                                            + " queries, and internal fields (soft-delete flags,"
                                            + " audit columns, credentials) may be accidentally"
                                            + " exposed.")
                                .possibleImpact(
                                        "Over-fetched or sensitive data sent to clients."
                                            + " LazyInitializationException at serialization time."
                                            + " Inability to evolve the schema without breaking the"
                                            + " API contract.")
                                .recommendation(
                                        "Introduce a dedicated DTO or record that only includes the"
                                            + " fields needed by the client. Map the entity to the"
                                            + " DTO in the service layer using a mapper or manual"
                                            + " mapping.")
                                .evidence(
                                        "Method "
                                                + target
                                                + " in "
                                                + relativePath
                                                + " has an HTTP mapping annotation and a return"
                                                + " type that contains an @Entity class.")
                                .limitations(
                                        "Detection is based on simple-name matching against @Entity"
                                            + " classes in the same compilation unit. Cross-file"
                                            + " entity detection is not performed, so entities"
                                            + " defined in other packages may be missed.")
                                .source(relativePath, line)
                                .target(target)
                                .build());
            }
        }
    }

    /** Recursively checks if a return type (including generic arguments) contains an entity name. */
    private static boolean containsEntityType(
            com.github.javaparser.ast.type.Type type, Set<String> entityNames) {
        if (type instanceof com.github.javaparser.ast.type.ClassOrInterfaceType ct) {
            if (entityNames.contains(ct.getNameAsString())) {
                return true;
            }
            for (com.github.javaparser.ast.type.Type arg :
                    ct.getTypeArguments().orElse(new com.github.javaparser.ast.NodeList<>())) {
                if (containsEntityType(arg, entityNames)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static final Set<String> BROAD_EXCEPTION_TYPES =
            Set.of("Exception", "RuntimeException", "Throwable");

    private void detectTransactionalExceptionSwallowed(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            TransactionEvidenceIndex transactionEvidence,
            List<Finding> findings) {
        if (method.getBody().isEmpty()) {
            return;
        }
        for (TryStmt tryStmt : method.getBody().get().findAll(TryStmt.class)) {
            for (CatchClause catchClause : tryStmt.getCatchClauses()) {
                Set<String> caughtTypes = caughtTypeNames(catchClause);
                boolean catchesBroad =
                        caughtTypes.stream().anyMatch(BROAD_EXCEPTION_TYPES::contains);
                if (!catchesBroad) {
                    continue;
                }
                CatchAnalysis analysis =
                        analyzeCatchBody(
                                catchClause.getBody(),
                                catchClause.getParameter().getNameAsString());
                if (analysis.rethrows()
                        || marksCurrentTransactionRollbackOnly(catchClause.getBody())
                        || !tryInvokesTransactionalCollaborator(
                                tryStmt, method, declaration, transactionEvidence)
                        || !catchWritesInCurrentTransaction(
                                catchClause, method, declaration, transactionEvidence)) {
                    continue;
                }
                Integer line = catchClause.getBegin().map(p -> p.line).orElse(null);
                String target = declaration.getNameAsString() + "#" + method.getNameAsString();
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED,
                                        FindingConfidence.MEDIUM)
                                .shortMessage(
                                        "@Transactional method catches a transactional collaborator"
                                            + " failure and then writes in the same transaction.")
                                .whyBadPractice(
                                        "A participating transactional collaborator can mark the"
                                            + " shared transaction rollback-only before throwing."
                                            + " Catching that failure and recording status in the"
                                            + " same transaction does not make that status"
                                            + " durable.")
                                .possibleImpact(
                                        "The status write may be rolled back and the outer boundary"
                                            + " can still fail with UnexpectedRollbackException.")
                                .recommendation(
                                        "Let the failure propagate, or record the failure state in"
                                                + " a separate REQUIRES_NEW boundary. A default"
                                                + " TransactionTemplate still joins the existing"
                                                + " transaction.")
                                .evidence(
                                        "Method "
                                                + target
                                                + " in "
                                                + relativePath
                                                + " is @Transactional and catches "
                                                + String.join(" | ", caughtTypes)
                                                + " after a visible transactional collaborator"
                                                + " call, then performs a direct persistence"
                                                + " write.")
                                .limitations(
                                        "Receiver types and collaborator annotations are resolved"
                                            + " from source declarations only. Custom transaction"
                                            + " aspects or indirect status writers may be missed.")
                                .source(relativePath, line)
                                .target(target)
                                .build());
            }
        }
    }

    private boolean marksCurrentTransactionRollbackOnly(BlockStmt catchBody) {
        return catchBody.findAll(MethodCallExpr.class).stream()
                .anyMatch(call -> call.getNameAsString().equals("setRollbackOnly"));
    }

    private boolean tryInvokesTransactionalCollaborator(
            TryStmt tryStmt,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex transactionEvidence) {
        BlockStmt tryBody = tryStmt.getTryBlock();
        List<MethodCallExpr> candidates =
                tryBody.findAll(MethodCallExpr.class).stream()
                        .filter(call -> belongsToMethod(call, method))
                        .filter(call -> isDirectTopLevelCall(tryBody, call))
                        .filter(
                                call -> {
                                    MethodKey target =
                                            resolveSourceMethodKey(
                                                    call, method, declaration, transactionEvidence);
                                    return target != null
                                            && !target.ownerType()
                                                    .equals(qualifiedTypeName(declaration))
                                            && transactionEvidence
                                                    .isParticipatingTransactionalMethod(target);
                                })
                        .toList();
        if (candidates.size() != 1) {
            return false;
        }
        MethodCallExpr collaborator = candidates.getFirst();
        ExpressionStmt collaboratorStatement =
                (ExpressionStmt) collaborator.getParentNode().orElseThrow();
        if (tryBody.getStatements().size() != 1
                || tryBody.getStatement(0) != collaboratorStatement
                || collaboratorStatement.findAll(MethodCallExpr.class).size() != 1
                || !collaboratorStatement.findAll(ObjectCreationExpr.class).isEmpty()
                || collaborator.getArguments().stream()
                        .anyMatch(argument -> !isConservativeSafeCallArgument(argument))) {
            return false;
        }
        return true;
    }

    private boolean isConservativeSafeCallArgument(Expression argument) {
        return argument.isNameExpr() || argument.isLiteralExpr() || argument.isThisExpr();
    }

    private boolean isDirectTopLevelCall(BlockStmt block, MethodCallExpr call) {
        return call.getParentNode().orElse(null) instanceof ExpressionStmt statement
                && statement.getExpression() == call
                && statement.getParentNode().orElse(null) == block;
    }

    private boolean catchWritesInCurrentTransaction(
            CatchClause catchClause,
            MethodDeclaration method,
            ClassOrInterfaceDeclaration declaration,
            TransactionEvidenceIndex transactionEvidence) {
        return catchClause.getBody().findAll(MethodCallExpr.class).stream()
                .filter(call -> belongsToMethod(call, method))
                .anyMatch(
                        call ->
                                isDirectPersistenceWrite(call, method, declaration)
                                        && persistenceWriteRunsInCurrentTransaction(
                                                call, method, declaration, transactionEvidence)
                                        && isDirectCatchWrite(catchClause.getBody(), call, method));
    }

    private boolean isDirectCatchWrite(
            BlockStmt catchBody, MethodCallExpr writeCall, MethodDeclaration method) {
        if (!isInsideLambda(writeCall, method)) {
            return isDirectTopLevelCall(catchBody, writeCall);
        }
        Node current = writeCall;
        while (current != method && current.getParentNode().isPresent()) {
            if (current instanceof LambdaExpr lambda) {
                MethodCallExpr boundary = lambda.findAncestor(MethodCallExpr.class).orElse(null);
                return boundary != null && isDirectTopLevelCall(catchBody, boundary);
            }
            current = current.getParentNode().get();
        }
        return false;
    }

    private static final Set<String> HTTP_CLIENT_TYPE_NAMES =
            Set.of(
                    "RestTemplate",
                    "WebClient",
                    "RestClient",
                    "HttpClient",
                    "OkHttpClient",
                    "CloseableHttpClient");
    private static final Set<String> HTTP_CLIENT_METHOD_NAMES =
            Set.of(
                    "getForObject",
                    "getForEntity",
                    "postForObject",
                    "postForEntity",
                    "exchange",
                    "execute",
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "retrieve",
                    "exchangeToMono",
                    "exchangeToFlux",
                    "send");

    private void detectTransactionalHttpCall(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        if (method.getBody().isEmpty()) {
            return;
        }
        for (MethodCallExpr call : method.getBody().get().findAll(MethodCallExpr.class)) {
            if (!HTTP_CLIENT_METHOD_NAMES.contains(call.getNameAsString())) {
                continue;
            }
            boolean scopeIsHttpClient =
                    call.getScope()
                            .map(
                                    scope -> {
                                        String s = scope.toString();
                                        String simple =
                                                s.contains(".")
                                                        ? s.substring(s.lastIndexOf('.') + 1)
                                                        : s;
                                        return HTTP_CLIENT_TYPE_NAMES.stream()
                                                .anyMatch(
                                                        t ->
                                                                simple.toLowerCase(Locale.ROOT)
                                                                        .contains(
                                                                                t.toLowerCase(
                                                                                        Locale
                                                                                                .ROOT)));
                                    })
                            .orElse(false);
            if (!scopeIsHttpClient) {
                continue;
            }
            Integer line = call.getBegin().map(p -> p.line).orElse(null);
            String target = declaration.getNameAsString() + "#" + method.getNameAsString();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_TRANSACTIONAL_HTTP_CALL,
                                    FindingConfidence.MEDIUM)
                            .shortMessage("Outbound HTTP call made inside a @Transactional method.")
                            .whyBadPractice(
                                    "A database connection is held open for the full duration of"
                                        + " the @Transactional method. Outbound HTTP calls inside"
                                        + " the transaction add network round-trip latency (often"
                                        + " 50–5000 ms) to connection hold time, rapidly exhausting"
                                        + " the connection pool under concurrent load.")
                            .possibleImpact(
                                    "Connection pool exhaustion under moderate traffic, cascading"
                                            + " timeouts across the application, and database"
                                            + " starvation caused by slow or unavailable external"
                                            + " services.")
                            .recommendation(
                                    "Restructure so the HTTP call happens outside the transaction:"
                                        + " call the external service first, then open a"
                                        + " transaction to persist the result. If atomicity is"
                                        + " needed, use an outbox pattern or message broker instead"
                                        + " of a synchronous HTTP call.")
                            .evidence(
                                    "Method "
                                            + target
                                            + " in "
                                            + relativePath
                                            + " is @Transactional and calls "
                                            + call.getScope().map(Object::toString).orElse("?")
                                            + "."
                                            + call.getNameAsString()
                                            + "().")
                            .limitations(
                                    "Detection is based on variable name matching against known"
                                            + " HTTP client type names. If the client is accessed"
                                            + " through a helper or wrapper method the call may not"
                                            + " be detected.")
                            .source(relativePath, line)
                            .target(target)
                            .build());
            // One finding per method is enough
            return;
        }
    }

    private void detectJpaLazyLoadingOutsideTransaction(
            String relativePath, ClassOrInterfaceDeclaration declaration, List<Finding> findings) {
        if (!hasAnyAnnotation(declaration.getAnnotations(), Set.of("Service", "Component"))) {
            return;
        }
        boolean classTransactional = hasAnnotation(declaration.getAnnotations(), "Transactional");
        for (MethodDeclaration method : declaration.getMethods()) {
            if (classTransactional || hasAnnotation(method.getAnnotations(), "Transactional")) {
                continue;
            }
            if (method.isPrivate()) {
                continue;
            }
            boolean callsLazyProxy =
                    method.findAll(MethodCallExpr.class).stream()
                            .anyMatch(
                                    call ->
                                            "getReferenceById".equals(call.getNameAsString())
                                                    || "getOne".equals(call.getNameAsString()));
            if (callsLazyProxy) {
                Integer line = method.getBegin().map(p -> p.line).orElse(null);
                String target = declaration.getNameAsString() + "#" + method.getNameAsString();
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_JPA_LAZY_LOADING_OUTSIDE_TRANSACTION,
                                        FindingConfidence.HIGH)
                                .shortMessage(
                                        "Service method "
                                                + target
                                                + " calls getReferenceById/getOne without"
                                                + " @Transactional.")
                                .whyBadPractice(
                                        "getReferenceById() and getOne() return a Hibernate lazy"
                                                + " proxy that is not loaded until a property is"
                                                + " accessed. Accessing the proxy outside an active"
                                                + " Hibernate session throws"
                                                + " LazyInitializationException.")
                                .possibleImpact(
                                        "Any caller that accesses properties on the returned entity"
                                                + " — including JSON serializers — will receive"
                                                + " LazyInitializationException at runtime.")
                                .recommendation(
                                        "Annotate the service method with @Transactional, or"
                                            + " replace getReferenceById with findById() and handle"
                                            + " the Optional explicitly.")
                                .evidence(
                                        "getReferenceById or getOne called in non-transactional"
                                                + " method "
                                                + method.getNameAsString()
                                                + " in "
                                                + relativePath
                                                + ".")
                                .limitations(
                                        "Static analysis cannot determine whether open-in-view or"
                                                + " another session-extending mechanism provides an"
                                                + " active session at the point of access.")
                                .source(relativePath, line)
                                .target(target)
                                .build());
            }
        }
    }

    private void detectTransactionIsolationReadUncommitted(
            String relativePath,
            ClassOrInterfaceDeclaration declaration,
            MethodDeclaration method,
            List<Finding> findings) {
        method.getAnnotationByName("Transactional")
                .ifPresent(
                        annotation -> {
                            if (!annotation.isNormalAnnotationExpr()) {
                                return;
                            }
                            annotation.asNormalAnnotationExpr().getPairs().stream()
                                    .filter(pair -> "isolation".equals(pair.getNameAsString()))
                                    .filter(
                                            pair -> {
                                                String val = pair.getValue().toString();
                                                return val.contains("READ_UNCOMMITTED")
                                                        || "1".equals(val.trim());
                                            })
                                    .findFirst()
                                    .ifPresent(
                                            pair -> {
                                                Integer line =
                                                        method.getBegin()
                                                                .map(p -> p.line)
                                                                .orElse(null);
                                                String target =
                                                        declaration.getNameAsString()
                                                                + "#"
                                                                + method.getNameAsString();
                                                findings.add(
                                                        FindingFactory.builder(
                                                                        FindingRules
                                                                                .SPRING_TRANSACTION_ISOLATION_READ_UNCOMMITTED,
                                                                        FindingConfidence.HIGH)
                                                                .shortMessage(
                                                                        "@Transactional on "
                                                                                + target
                                                                                + " uses"
                                                                                + " READ_UNCOMMITTED"
                                                                                + " isolation.")
                                                                .whyBadPractice(
                                                                        "READ_UNCOMMITTED allows"
                                                                            + " dirty reads —"
                                                                            + " reading data that"
                                                                            + " has been modified"
                                                                            + " but not yet"
                                                                            + " committed by"
                                                                            + " another"
                                                                            + " transaction. This"
                                                                            + " is the weakest"
                                                                            + " isolation level and"
                                                                            + " almost never"
                                                                            + " correct for"
                                                                            + " application code.")
                                                                .possibleImpact(
                                                                        "Business logic can read"
                                                                            + " uncommitted,"
                                                                            + " temporary, or"
                                                                            + " rolled-back values,"
                                                                            + " leading to data"
                                                                            + " consistency"
                                                                            + " violations and"
                                                                            + " incorrect"
                                                                            + " calculations.")
                                                                .recommendation(
                                                                        "Use READ_COMMITTED (the"
                                                                            + " default in most"
                                                                            + " databases) or a"
                                                                            + " higher isolation"
                                                                            + " level. Use"
                                                                            + " SERIALIZABLE or"
                                                                            + " REPEATABLE_READ"
                                                                            + " only when the"
                                                                            + " specific"
                                                                            + " consistency"
                                                                            + " guarantee is"
                                                                            + " required and"
                                                                            + " understood.")
                                                                .evidence(
                                                                        "@Transactional(isolation ="
                                                                            + " Isolation.READ_UNCOMMITTED)"
                                                                            + " found on "
                                                                                + method
                                                                                        .getNameAsString()
                                                                                + " in "
                                                                                + relativePath
                                                                                + ".")
                                                                .limitations(
                                                                        "Static analysis cannot"
                                                                            + " determine whether"
                                                                            + " the database"
                                                                            + " actually supports"
                                                                            + " or enforces the"
                                                                            + " requested isolation"
                                                                            + " level.")
                                                                .source(relativePath, line)
                                                                .target(target)
                                                                .build());
                                            });
                        });
    }

    private void detectAsyncWithoutExecutor(JavaSources javaSources, List<Finding> findings) {
        boolean hasAsyncAnnotation = false;
        boolean hasExecutorBean = false;
        boolean hasEnableAsync = false;
        for (JavaSources.JavaFile file : javaSources.primaryFiles()) {
            String content = file.content();
            if (content.contains("@Async")) {
                hasAsyncAnnotation = true;
            }
            if (content.contains("@EnableAsync")) {
                hasEnableAsync = true;
            }
            if (content.contains("@Bean")
                    && (content.contains("ThreadPoolTaskExecutor")
                            || content.contains("AsyncTaskExecutor")
                            || content.contains("TaskExecutor"))) {
                hasExecutorBean = true;
            }
        }
        // Without @EnableAsync the methods run synchronously and no executor is ever used, so
        // the executor advice would be moot — SPRING_ASYNC_WITHOUT_ENABLE_ASYNC covers that case.
        if (hasAsyncAnnotation && hasEnableAsync && !hasExecutorBean) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_ASYNC_EXECUTOR_NOT_CONFIGURED,
                                    FindingConfidence.MEDIUM)
                            .shortMessage("@Async is used but no custom Executor bean was found.")
                            .whyBadPractice(
                                    "In a Spring Boot application, @Async without explicit"
                                        + " configuration uses the auto-configured"
                                        + " applicationTaskExecutor: a ThreadPoolTaskExecutor with"
                                        + " 8 core threads and an unbounded queue. Bursts of async"
                                        + " work queue up without limit behind those 8 threads."
                                        + " (Outside Boot, plain Spring falls back to"
                                        + " SimpleAsyncTaskExecutor, which spawns a new thread per"
                                        + " invocation.)")
                            .possibleImpact(
                                    "Unbounded queue growth consumes heap and silently delays tasks"
                                        + " under sustained async load; there is no backpressure"
                                        + " and no rejection signal until memory runs out.")
                            .recommendation(
                                    "Tune spring.task.execution.* (pool size, queue-capacity) or"
                                        + " configure a bounded ThreadPoolTaskExecutor @Bean with"
                                        + " explicit corePoolSize, maxPoolSize, and queueCapacity."
                                        + " Optionally implement AsyncConfigurer to set it as the"
                                        + " default executor.")
                            .evidence(
                                    "@Async annotation found in the codebase without a"
                                        + " ThreadPoolTaskExecutor or equivalent Executor @Bean.")
                            .limitations(
                                    "Static analysis may miss executor beans defined in imported"
                                            + " @Configuration classes or provided by"
                                            + " auto-configuration.")
                            .location("Async configuration")
                            .target("Async executor")
                            .build());
        }
    }

    private void detectScheduledWithoutExecutor(JavaSources javaSources, List<Finding> findings) {
        int scheduledCount = 0;
        boolean hasTaskScheduler = false;
        boolean hasEnableScheduling = false;
        for (JavaSources.JavaFile file : javaSources.primaryFiles()) {
            String content = file.content();
            scheduledCount += countOccurrences(content, "@Scheduled");
            if (content.contains("@EnableScheduling")) {
                hasEnableScheduling = true;
            }
            if (content.contains("@Bean")
                    && (content.contains("TaskScheduler")
                            || content.contains("SchedulingConfigurer"))) {
                hasTaskScheduler = true;
            }
        }
        // Without @EnableScheduling no trigger is registered at all, so warning about the
        // single-threaded scheduler would be moot — SPRING_SCHEDULED_WITHOUT_ENABLE_SCHEDULING
        // reports the real problem in that case.
        if (scheduledCount > 1 && hasEnableScheduling && !hasTaskScheduler) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_SCHEDULED_EXECUTOR_SERVICE_NOT_CONFIGURED,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    scheduledCount
                                            + " @Scheduled methods found without a dedicated"
                                            + " TaskScheduler.")
                            .whyBadPractice(
                                    "By default, Spring uses a single-threaded scheduler for all"
                                        + " @Scheduled methods. If one job runs long or blocks, all"
                                        + " other scheduled tasks are delayed.")
                            .possibleImpact(
                                    "Scheduled jobs miss their execution windows. A slow or"
                                        + " blocking job starves all other scheduled tasks in the"
                                        + " application.")
                            .recommendation(
                                    "Configure a TaskScheduler @Bean with a thread pool sized to"
                                        + " the number of concurrent scheduled jobs, or implement"
                                        + " SchedulingConfigurer to wire a custom scheduler.")
                            .evidence(
                                    scheduledCount
                                            + " @Scheduled methods found in the codebase without a"
                                            + " TaskScheduler or SchedulingConfigurer bean.")
                            .limitations(
                                    "Static analysis may miss TaskScheduler beans in imported"
                                            + " @Configuration classes or provided by"
                                            + " auto-configuration.")
                            .location("Scheduling configuration")
                            .target("Task scheduler")
                            .build());
        }
    }

    private List<Finding> dedupe(List<Finding> findings) {
        Map<String, Finding> deduped = new LinkedHashMap<>();
        for (Finding finding : findings) {
            String key =
                    String.join(
                            "|",
                            defaultString(finding.ruleId()),
                            defaultString(finding.sourceFile()),
                            String.valueOf(finding.line()),
                            defaultString(finding.target()),
                            defaultString(finding.message()));
            deduped.putIfAbsent(key, finding);
        }
        return List.copyOf(deduped.values());
    }

    private record TransactionalSelfInvocationTarget(
            MethodDeclaration method, AnnotationExpr annotation) {}

    private enum ProgrammaticBoundaryKind {
        IMMEDIATE,
        ACTIVE,
        INDEPENDENT
    }

    private record MethodKey(String ownerType, String methodName, int arity) {}

    private record TransactionEvidenceIndex(
            Set<MethodKey> participatingTransactionalMethods,
            Map<MethodKey, Set<Integer>> executedCallbackParameterIndexes,
            Set<MethodKey> activeCallbackBoundaryMethods,
            Set<MethodKey> independentCallbackBoundaryMethods,
            Set<MethodKey> transactionalCalls,
            Map<String, Set<String>> ownersBySimpleName,
            Set<MethodKey> ambiguousMethods) {
        boolean hasTransactionalCaller(String ownerType, String methodName, int arity) {
            return transactionalCalls.contains(new MethodKey(ownerType, methodName, arity));
        }

        boolean isParticipatingTransactionalMethod(MethodKey key) {
            return participatingTransactionalMethods.contains(key) && !isAmbiguous(key);
        }

        boolean executesCallbackArgument(MethodKey key, int argumentIndex) {
            return !isAmbiguous(key)
                    && executedCallbackParameterIndexes
                            .getOrDefault(key, Set.of())
                            .contains(argumentIndex);
        }

        boolean isActiveCallbackBoundary(MethodKey key) {
            return activeCallbackBoundaryMethods.contains(key) && !isAmbiguous(key);
        }

        boolean isIndependentCallbackBoundary(MethodKey key) {
            return independentCallbackBoundaryMethods.contains(key) && !isAmbiguous(key);
        }

        boolean isAmbiguous(MethodKey key) {
            return ambiguousMethods.contains(key);
        }
    }

    private record MethodSignals(
            boolean httpCalls,
            int writeCallCount,
            boolean persistenceSignals,
            boolean fileOperations,
            boolean threadCreation,
            boolean messagingCalls,
            boolean loopDetected,
            boolean localTryCatch,
            String methodName) {
        boolean hasMeaningfulSideEffects() {
            return httpCalls
                    || writeCallCount > 0
                    || fileOperations
                    || threadCreation
                    || messagingCalls;
        }

        boolean hasHttpCalls() {
            return httpCalls;
        }

        boolean hasDatabaseWrites() {
            return writeCallCount > 0 && persistenceSignals;
        }

        boolean hasPotentialWriteOperations() {
            return writeCallCount > 0;
        }

        boolean hasMessagingCalls() {
            return messagingCalls;
        }

        FindingConfidence directSignalConfidence() {
            return (httpCalls
                            || writeCallCount > 0
                            || fileOperations
                            || threadCreation
                            || messagingCalls)
                    ? FindingConfidence.HIGH
                    : FindingConfidence.MEDIUM;
        }

        String describe() {
            List<String> parts = new ArrayList<>();
            if (httpCalls) {
                parts.add("outbound HTTP execution");
            }
            if (writeCallCount > 0) {
                parts.add(
                        persistenceSignals
                                ? "write-like persistence calls"
                                : "write-like side effects");
            }
            if (fileOperations) {
                parts.add("file system operations");
            }
            if (threadCreation) {
                parts.add("manual thread or task execution");
            }
            if (messagingCalls) {
                parts.add("message publishing or send operations");
            }
            if (loopDetected) {
                parts.add("looping control flow");
            }
            if (parts.isEmpty()) {
                return "side-effecting work";
            }
            return String.join(", ", parts);
        }
    }

    private record ValidationSignals(
            boolean hasValidationAnnotations, boolean looksBusinessCritical) {
        boolean shouldFlag() {
            return hasValidationAnnotations || looksBusinessCritical;
        }
    }

    private record ExceptionHandlingContext(
            String relativePath,
            String className,
            String target,
            boolean controllerLike,
            boolean startupHook,
            boolean scheduled,
            boolean serviceLike,
            boolean repositoryLike,
            boolean exceptionHandler,
            boolean constructorBoundary,
            boolean topLevelUncaughtHandler) {
        boolean springBoundary() {
            return controllerLike
                    || startupHook
                    || scheduled
                    || exceptionHandler
                    || constructorBoundary;
        }

        boolean productionLikeBoundary() {
            return springBoundary() || serviceLike || repositoryLike;
        }
    }

    private record CatchAnalysis(
            boolean emptyLike,
            boolean hasStrongLogging,
            boolean hasWeakLogging,
            boolean rethrows,
            boolean restoresInterrupt,
            boolean usesFallbackWithoutVisibleHandling,
            boolean intentionalIgnoreSafe,
            boolean commentOnly,
            String fallbackDescription) {}
}

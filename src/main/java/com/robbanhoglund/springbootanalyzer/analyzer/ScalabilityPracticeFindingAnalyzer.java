package com.robbanhoglund.springbootanalyzer.analyzer;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.stmt.DoStmt;
import com.github.javaparser.ast.stmt.ForEachStmt;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.WhileStmt;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingSeverity;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.RuntimeStackAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.WebStack;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Detects cloud-native scalability and bean-lifecycle anti-patterns in {@code src/main/java}.
 *
 * <p>Rules covered:
 *
 * <ul>
 *   <li>{@link FindingRules#SPRING_PROTOTYPE_BEAN_IN_SINGLETON} — prototype-scoped bean injected
 *       directly into a singleton, losing per-use instantiation semantics.
 *   <li>{@link FindingRules#SPRING_FILTER_COMPONENT_REGISTRATION_LEAK} — {@code @Component} on a
 *       {@code Filter} implementation causes global servlet registration bypassing Security config.
 *   <li>{@link FindingRules#SPRING_HARDCODED_FILE_PATH} — absolute file system path literals
 *       passed to {@code new File(…)}, {@code Paths.get(…)}, or {@code Path.of(…)}.
 *   <li>{@link FindingRules#SPRING_LOMBOK_DATA_ON_ENTITY} — {@code @Data} combined with
 *       {@code @Entity}, risking eager proxy initialisation and infinite recursion.
 *   <li>{@link FindingRules#SPRING_REST_TEMPLATE_NO_TIMEOUT} — {@code new RestTemplate()} with
 *       no-arg constructor and no explicit timeout.
 *   <li>{@link FindingRules#SPRING_WEBFLUX_BLOCKING_CALL} — {@code .block()}, {@code .blockFirst()},
 *       or {@code .blockLast()} called while WebFlux is the active server stack.
 *   <li>{@link FindingRules#SPRING_MANAGED_THREAD_SLEEP} — {@code Thread.sleep()} in a
 *       Spring-managed execution path, with severity and guidance adapted to its context.
 *   <li>{@link FindingRules#SPRING_NON_THREAD_SAFE_FORMATTER_FIELD} — {@code SimpleDateFormat},
 *       {@code NumberFormat}, etc. held as a field in a Spring singleton.
 *   <li>{@link FindingRules#SPRING_UNBOUNDED_FINDALL} — no-arg {@code repository.findAll()} that
 *       can load an entire table into memory.
 *   <li>{@link FindingRules#SPRING_ENTITY_MISSING_ID} — {@code @Entity} class with no
 *       {@code @Id}/{@code @EmbeddedId}.
 * </ul>
 */
@Component
public class ScalabilityPracticeFindingAnalyzer {

    private static final Pattern ABSOLUTE_PATH_PATTERN =
            Pattern.compile(
                    "^(/var/|/tmp/|/home/|/etc/|/opt/|/data/|/mnt/|/srv/|/usr/)"
                            + "|^[A-Za-z]:\\\\");

    private static final Set<String> SINGLETON_ANNOTATIONS =
            Set.of(
                    "Service",
                    "Component",
                    "Controller",
                    "RestController",
                    "Repository",
                    "Configuration");
    private static final Set<String> RAW_EXECUTOR_TYPES =
            Set.of(
                    "ExecutorService",
                    "ScheduledExecutorService",
                    "ThreadPoolExecutor",
                    "ScheduledThreadPoolExecutor");
    private static final Set<String> SPRING_DATA_REPOSITORY_BASE_TYPES =
            Set.of(
                    "Repository",
                    "CrudRepository",
                    "ListCrudRepository",
                    "PagingAndSortingRepository",
                    "ListPagingAndSortingRepository",
                    "ReactiveCrudRepository",
                    "ReactiveSortingRepository",
                    "RxJava3CrudRepository",
                    "RxJava3SortingRepository",
                    "CoroutineCrudRepository",
                    "CoroutineSortingRepository",
                    "JpaRepository",
                    "JpaSpecificationExecutor",
                    "MongoRepository",
                    "ReactiveMongoRepository",
                    "ElasticsearchRepository",
                    "ReactiveElasticsearchRepository",
                    "CassandraRepository",
                    "ReactiveCassandraRepository",
                    "Neo4jRepository",
                    "ReactiveNeo4jRepository");
    private static final Pattern BOUNDED_REFERENCE_REPOSITORY_PATTERN =
            Pattern.compile(
                    "(?:Code|Codes|Config|Configuration|Reference|Lookup|Dictionary|Setting|Settings|Constant|Constants)(?=[A-Z]|$)");

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
        return analyze(sources, null);
    }

    /**
     * Analyzes sources with the resolved runtime stack so blocking-call rules can distinguish
     * WebFlux event-loop code from valid MVC client-side reactive usage.
     */
    public List<Finding> analyze(JavaSources sources, RuntimeStackAnalysis runtimeStackAnalysis) {
        List<Finding> findings = new ArrayList<>();
        // Pass 1: collect all simple type names of @Scope("prototype") beans and the names of
        // methods annotated @Transactional(propagation = REQUIRES_NEW).
        Set<String> prototypeTypes = collectPrototypeTypes(sources);
        Set<String> requiresNewMethods = collectRequiresNewMethods(sources);
        RepositoryTypeIndex repositoryTypes = collectRepositoryTypes(sources);

        // Pass 2: per-file analysis
        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            if (file.compilationUnit() == null) {
                continue;
            }
            analyzeSourceFile(
                    file.compilationUnit(),
                    file.relativePath(),
                    prototypeTypes,
                    requiresNewMethods,
                    repositoryTypes,
                    runtimeStackAnalysis,
                    findings);
        }
        // Pass 3: cross-file bean-name collision detection.
        detectBeanNameCollisions(sources, findings);
        return findings;
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_BEAN_NAME_COLLISION
    // ---------------------------------------------------------------------------

    private static final Set<String> STEREOTYPE_ANNOTATIONS =
            Set.of(
                    "Component",
                    "Service",
                    "Repository",
                    "Controller",
                    "RestController",
                    "Configuration");

    private void detectBeanNameCollisions(JavaSources sources, List<Finding> findings) {
        record BeanOccurrence(String fqcn, String path, Integer line) {}

        // Scope guard: only when a @SpringBootApplication defines the scan root and no custom
        // @ComponentScan redirects/narrows scanning — otherwise which classes are actually
        // scanned cannot be determined statically.
        Set<String> basePackages = new LinkedHashSet<>();
        boolean defaultPackageApplication = false;
        boolean customComponentScan = false;
        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            CompilationUnit cu = file.compilationUnit();
            if (cu == null) {
                continue;
            }
            for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                for (AnnotationExpr annotation : cls.getAnnotations()) {
                    String annotationName = simpleName(annotation.getNameAsString());
                    if ("SpringBootApplication".equals(annotationName)) {
                        String applicationPackage =
                                cu.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("");
                        if (applicationPackage.isBlank()) {
                            defaultPackageApplication = true;
                        } else {
                            basePackages.add(applicationPackage);
                        }
                        // scanBasePackages/scanBasePackageClasses redirect scanning away from
                        // the application class's package — same bail-out as @ComponentScan.
                        String annotationText = annotation.toString();
                        if (annotationText.contains("scanBasePackages")
                                || annotationText.contains("scanBasePackageClasses")) {
                            customComponentScan = true;
                        }
                    }
                    if ("ComponentScan".equals(annotationName)
                            && !annotation.isMarkerAnnotationExpr()) {
                        customComponentScan = true;
                    }
                }
            }
        }
        if (basePackages.isEmpty() || defaultPackageApplication || customComponentScan) {
            return;
        }

        // A broader application package already covers a nested application package. Keeping only
        // the broadest roots avoids duplicate findings while disjoint application contexts remain
        // independent and therefore cannot create cross-context bean-name collisions.
        List<String> effectiveBasePackages =
                basePackages.stream()
                        .filter(
                                candidate ->
                                        basePackages.stream()
                                                .noneMatch(
                                                        other ->
                                                                !other.equals(candidate)
                                                                        && isInScanRoot(
                                                                                candidate, other)))
                        .toList();

        for (String basePackage : effectiveBasePackages) {
            Map<String, List<BeanOccurrence>> bySimpleName = new LinkedHashMap<>();
            for (JavaSources.JavaFile file : sources.primaryFiles()) {
                CompilationUnit cu = file.compilationUnit();
                if (cu == null) {
                    continue;
                }
                String pkg = cu.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("");
                if (!isInScanRoot(pkg, basePackage)) {
                    continue;
                }
                for (ClassOrInterfaceDeclaration cls :
                        cu.findAll(ClassOrInterfaceDeclaration.class)) {
                    // Nested classes get bean names prefixed with the outer class ("outer.Inner"),
                    // so their simple names never collide with same-named nested classes elsewhere.
                    if (cls.isInterface() || cls.isAbstract() || !cls.isTopLevelType()) {
                        continue;
                    }
                    AnnotationExpr stereotype =
                            cls.getAnnotations().stream()
                                    .filter(
                                            a ->
                                                    STEREOTYPE_ANNOTATIONS.contains(
                                                            simpleName(a.getNameAsString())))
                                    .findFirst()
                                    .orElse(null);
                    if (stereotype == null || hasExplicitBeanName(stereotype)) {
                        continue;
                    }
                    bySimpleName
                            .computeIfAbsent(cls.getNameAsString(), key -> new ArrayList<>())
                            .add(
                                    new BeanOccurrence(
                                            pkg + "." + cls.getNameAsString(),
                                            file.relativePath(),
                                            cls.getBegin().map(p -> p.line).orElse(null)));
                }
            }

            for (Map.Entry<String, List<BeanOccurrence>> entry : bySimpleName.entrySet()) {
                List<BeanOccurrence> occurrences = entry.getValue();
                if (occurrences.stream().map(BeanOccurrence::fqcn).distinct().count() < 2) {
                    continue;
                }
                BeanOccurrence reported = occurrences.get(1);
                String allClasses =
                        occurrences.stream()
                                .map(BeanOccurrence::fqcn)
                                .collect(java.util.stream.Collectors.joining(", "));
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_BEAN_NAME_COLLISION,
                                        FindingConfidence.MEDIUM)
                                .shortMessage(
                                        "Component classes share the simple name '"
                                                + entry.getKey()
                                                + "' ("
                                                + allClasses
                                                + ") — bean registration fails at startup.")
                                .whyBadPractice(
                                        "Spring's default AnnotationBeanNameGenerator derives the"
                                            + " bean name from the decapitalised simple class name."
                                            + " Two component-scanned classes with the same simple"
                                            + " name in different packages therefore claim the same"
                                            + " bean name, and the context fails with"
                                            + " ConflictingBeanDefinitionException regardless of"
                                            + " bean-overriding settings.")
                                .possibleImpact(
                                        "The application crashes at startup in every environment —"
                                                + " a classic outcome of v1/v2 package splits or"
                                                + " module refactorings that duplicate a class"
                                                + " name.")
                                .recommendation(
                                        "Rename one of the classes, or give one an explicit bean"
                                                + " name (e.g. @Service(\"orderServiceV2\")).")
                                .evidence(
                                        "Classes "
                                                + allClasses
                                                + " are all component-scanned under base package '"
                                                + basePackage
                                                + "' without explicit bean names.")
                                .limitations(
                                        "Evaluates each default @SpringBootApplication package as"
                                            + " an independent scan root; default-package apps and"
                                            + " projects with custom @ComponentScan configuration"
                                            + " are skipped entirely. Excluded classes (e.g. via"
                                            + " scan filters or profiles) are not visible"
                                            + " statically.")
                                .source(reported.path(), reported.line())
                                .target(entry.getKey())
                                .build());
            }
        }
    }

    private static boolean isInScanRoot(String packageName, String scanRoot) {
        return packageName.equals(scanRoot) || packageName.startsWith(scanRoot + ".");
    }

    private static boolean hasExplicitBeanName(AnnotationExpr annotation) {
        if (annotation.isSingleMemberAnnotationExpr()) {
            return true;
        }
        return annotation.isNormalAnnotationExpr()
                && annotation.asNormalAnnotationExpr().getPairs().stream()
                        .anyMatch(pair -> pair.getNameAsString().equals("value"));
    }

    private Set<String> collectRequiresNewMethods(JavaSources sources) {
        Set<String> methods = new HashSet<>();
        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            CompilationUnit cu = file.compilationUnit();
            if (cu == null) {
                continue;
            }
            for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
                boolean requiresNew =
                        method.getAnnotations().stream()
                                .anyMatch(
                                        a ->
                                                simpleName(a.getNameAsString())
                                                                .equals("Transactional")
                                                        && a.toString().contains("REQUIRES_NEW"));
                if (requiresNew) {
                    methods.add(method.getNameAsString());
                }
            }
        }
        return methods;
    }

    // ---------------------------------------------------------------------------
    // Pass 1: collect prototype-scoped type names
    // ---------------------------------------------------------------------------

    private Set<String> collectPrototypeTypes(JavaSources sources) {
        Set<String> prototypeTypes = new HashSet<>();
        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            CompilationUnit cu = file.compilationUnit();
            if (cu == null) {
                continue;
            }
            for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                boolean isPrototype =
                        cls.getAnnotations().stream()
                                .anyMatch(
                                        a -> {
                                            if (!simpleName(a.getNameAsString()).equals("Scope")) {
                                                return false;
                                            }
                                            return a.toString().contains("prototype");
                                        });
                if (isPrototype) {
                    prototypeTypes.add(cls.getNameAsString());
                }
            }
        }
        return prototypeTypes;
    }

    // ---------------------------------------------------------------------------
    // Pass 2: per-file analysis
    // ---------------------------------------------------------------------------

    private void analyzeSourceFile(
            CompilationUnit cu,
            String relativePath,
            Set<String> prototypeTypes,
            Set<String> requiresNewMethods,
            RepositoryTypeIndex repositoryTypes,
            RuntimeStackAnalysis runtimeStackAnalysis,
            List<Finding> findings) {
        detectHardcodedFilePaths(cu, relativePath, findings);
        detectRestTemplateNoTimeout(cu, relativePath, findings);
        detectBlockingCalls(cu, relativePath, runtimeStackAnalysis, findings);
        detectUnboundedThreadPool(cu, relativePath, findings);
        detectUnboundedFindAll(cu, relativePath, repositoryTypes, findings);
        detectRestTemplateNewPerRequest(cu, relativePath, findings);
        detectJpaQueryNoPagination(cu, relativePath, findings);
        if (!requiresNewMethods.isEmpty()) {
            detectRequiresNewInLoop(cu, relativePath, requiresNewMethods, findings);
        }

        for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            detectLombokDataOnEntity(cls, relativePath, findings);
            detectFilterComponentRegistrationLeak(cls, relativePath, findings);
            detectNonThreadSafeFormatterField(cls, relativePath, findings);
            detectEntityMissingId(cls, relativePath, findings);
            detectEntityNoArgConstructor(cls, relativePath, findings);
            detectFinalEntity(cls, relativePath, findings);
            detectExecutorNoShutdown(cls, relativePath, findings);
            if (!prototypeTypes.isEmpty()) {
                detectPrototypeBeanInSingleton(cls, relativePath, prototypeTypes, findings);
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_HARDCODED_FILE_PATH
    // ---------------------------------------------------------------------------

    private void detectUnboundedThreadPool(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"newCachedThreadPool".equals(call.getNameAsString())) {
                continue;
            }
            boolean onExecutors =
                    call.getScope()
                            .map(scope -> simpleName(scope.toString()))
                            .filter("Executors"::equals)
                            .isPresent();
            if (!onExecutors) {
                continue;
            }
            Integer line = call.getName().getBegin().map(position -> position.line).orElse(null);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_EXECUTORS_UNBOUNDED_THREAD_POOL,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "Executors.newCachedThreadPool() creates an unbounded thread"
                                            + " pool in "
                                            + relativePath
                                            + ".")
                            .whyBadPractice(
                                    "newCachedThreadPool() has no upper bound on thread count and"
                                        + " hands tasks to a SynchronousQueue, so it spawns a new"
                                        + " thread for every task that cannot start immediately.")
                            .possibleImpact(
                                    "Under load or a downstream slowdown the pool spawns threads"
                                        + " without limit until the JVM dies with OutOfMemoryError:"
                                        + " unable to create new native thread.")
                            .recommendation(
                                    "Use a bounded pool — new ThreadPoolExecutor with a fixed max"
                                        + " size and a bounded queue, or inject a Spring"
                                        + " ThreadPoolTaskExecutor — and apply a rejection policy.")
                            .evidence(
                                    "Executors.newCachedThreadPool() found in "
                                            + relativePath
                                            + ".")
                            .limitations(
                                    "Bounded factory methods"
                                        + " (newFixedThreadPool/newScheduledThreadPool) are not"
                                        + " flagged even though their task queue is unbounded by"
                                        + " default.")
                            .source(relativePath, line)
                            .target("Executors.newCachedThreadPool")
                            .build());
            return; // one finding per file is sufficient
        }
    }

    private void detectExecutorNoShutdown(
            ClassOrInterfaceDeclaration declaration, String relativePath, List<Finding> findings) {
        boolean springComponent =
                declaration.getAnnotations().stream()
                        .anyMatch(
                                annotation ->
                                        SINGLETON_ANNOTATIONS.contains(
                                                simpleName(annotation.getNameAsString())));
        if (!springComponent) {
            return;
        }
        FieldDeclaration executorField = null;
        for (FieldDeclaration field : declaration.getFields()) {
            if (!RAW_EXECUTOR_TYPES.contains(simpleName(field.getElementType().asString()))) {
                continue;
            }
            boolean constructedInClass =
                    field.getVariables().stream()
                            .anyMatch(
                                    variable ->
                                            variable.getInitializer()
                                                    .map(this::isExecutorConstruction)
                                                    .orElse(false));
            if (constructedInClass) {
                executorField = field;
                break;
            }
        }
        if (executorField == null) {
            return;
        }
        boolean hasPreDestroy =
                declaration.getMethods().stream()
                        .anyMatch(
                                method ->
                                        method.getAnnotations().stream()
                                                .anyMatch(
                                                        annotation ->
                                                                simpleName(
                                                                                annotation
                                                                                        .getNameAsString())
                                                                        .equals("PreDestroy")));
        boolean hasShutdownCall =
                declaration.findAll(MethodCallExpr.class).stream()
                        .anyMatch(
                                call ->
                                        call.getScope().isPresent()
                                                && (call.getNameAsString().equals("shutdown")
                                                        || call.getNameAsString()
                                                                .equals("shutdownNow")
                                                        || call.getNameAsString().equals("close")));
        if (hasPreDestroy || hasShutdownCall) {
            return;
        }
        String fieldName =
                executorField.getVariables().isEmpty()
                        ? "?"
                        : executorField.getVariables().get(0).getNameAsString();
        String target = declaration.getNameAsString() + "." + fieldName;
        Integer line = executorField.getBegin().map(position -> position.line).orElse(null);
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_EXECUTOR_NO_SHUTDOWN, FindingConfidence.MEDIUM)
                        .shortMessage(
                                "ExecutorService field "
                                        + target
                                        + " is created in the bean but never shut down.")
                        .whyBadPractice(
                                "An ExecutorService built with Executors.* / new ThreadPoolExecutor"
                                    + " owns non-daemon threads. The bean is a singleton, but on"
                                    + " context refresh or redeploy it is discarded without the"
                                    + " pool being shut down, so its threads leak and block clean"
                                    + " JVM shutdown.")
                        .possibleImpact(
                                "Threads accumulate across hot reloads/redeploys and the JVM cannot"
                                        + " exit cleanly, eventually exhausting resources.")
                        .recommendation(
                                "Shut the executor down in an @PreDestroy method"
                                        + " (executor.shutdown()), or expose it as a @Bean with"
                                        + " destroyMethod = \"shutdown\" so Spring manages its"
                                        + " lifecycle.")
                        .evidence(
                                "Executor field "
                                        + target
                                        + " has no @PreDestroy or shutdown() call in "
                                        + relativePath
                                        + ".")
                        .limitations(
                                "Only executors constructed in the class are flagged; a shutdown in"
                                        + " a superclass or via an injected lifecycle helper is not"
                                        + " detected.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private boolean isExecutorConstruction(Expression initializer) {
        if (initializer instanceof MethodCallExpr call) {
            return call.getScope()
                    .map(scope -> simpleName(scope.toString()))
                    .filter("Executors"::equals)
                    .isPresent();
        }
        if (initializer instanceof ObjectCreationExpr creation) {
            String type = simpleName(creation.getType().asString());
            return type.equals("ThreadPoolExecutor") || type.equals("ScheduledThreadPoolExecutor");
        }
        return false;
    }

    private void detectHardcodedFilePaths(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ObjectCreationExpr expr : cu.findAll(ObjectCreationExpr.class)) {
            String typeName = expr.getTypeAsString();
            if (!"File".equals(typeName) && !"java.io.File".equals(typeName)) {
                continue;
            }
            expr.getArguments().stream()
                    .filter(arg -> arg instanceof StringLiteralExpr)
                    .map(arg -> ((StringLiteralExpr) arg).asString())
                    .filter(val -> ABSOLUTE_PATH_PATTERN.matcher(val).find())
                    .findFirst()
                    .ifPresent(
                            val -> {
                                Integer line = expr.getBegin().map(p -> p.line).orElse(null);
                                findings.add(
                                        FindingFactory.builder(
                                                        FindingRules.SPRING_HARDCODED_FILE_PATH,
                                                        FindingConfidence.HIGH)
                                                .shortMessage(
                                                        "Hardcoded absolute path \""
                                                                + val
                                                                + "\" passed to new File() in "
                                                                + relativePath
                                                                + ".")
                                                .whyBadPractice(
                                                        "Hardcoded absolute file system paths break"
                                                            + " in containerised or cloud-native"
                                                            + " deployments where the path may not"
                                                            + " exist. Data written to a"
                                                            + " container's local file system is"
                                                            + " also lost on restart or horizontal"
                                                            + " scaling.")
                                                .possibleImpact(
                                                        "Application fails on startup or at runtime"
                                                            + " in cloud environments. Files"
                                                            + " written to a container's local disk"
                                                            + " are lost on pod restart, causing"
                                                            + " silent data loss.")
                                                .recommendation(
                                                        "Abstract file storage behind an interface"
                                                            + " and use cloud-agnostic object"
                                                            + " storage (Amazon S3, Azure Blob,"
                                                            + " GCS) for uploaded files and"
                                                            + " persistent data. Read paths from"
                                                            + " configuration properties rather"
                                                            + " than hardcoding them.")
                                                .limitations(
                                                        "Only detects string literals passed"
                                                                + " directly to new File(). Paths"
                                                                + " assembled via concatenation or"
                                                                + " variables are not detected.")
                                                .evidence(
                                                        "new File(\""
                                                                + val
                                                                + "\") found in "
                                                                + relativePath
                                                                + ".")
                                                .source(relativePath, line)
                                                .build());
                            });
        }

        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            String callName = call.getNameAsString();
            // Paths.get(...) — legacy API
            boolean isPaths =
                    "get".equals(callName)
                            && call.getScope()
                                    .map(s -> s.toString().endsWith("Paths"))
                                    .orElse(false);
            // Path.of(...) — modern Java 11+ API, same semantics
            boolean isPathOf =
                    "of".equals(callName)
                            && call.getScope().map(s -> "Path".equals(s.toString())).orElse(false);
            if (!isPaths && !isPathOf) {
                continue;
            }
            String apiName = isPaths ? "Paths.get" : "Path.of";
            call.getArguments().stream()
                    .filter(arg -> arg instanceof StringLiteralExpr)
                    .map(arg -> ((StringLiteralExpr) arg).asString())
                    .filter(val -> ABSOLUTE_PATH_PATTERN.matcher(val).find())
                    .findFirst()
                    .ifPresent(
                            val -> {
                                Integer line = call.getBegin().map(p -> p.line).orElse(null);
                                findings.add(
                                        FindingFactory.builder(
                                                        FindingRules.SPRING_HARDCODED_FILE_PATH,
                                                        FindingConfidence.HIGH)
                                                .shortMessage(
                                                        "Hardcoded absolute path \""
                                                                + val
                                                                + "\" passed to "
                                                                + apiName
                                                                + "() in "
                                                                + relativePath
                                                                + ".")
                                                .whyBadPractice(
                                                        "Hardcoded absolute file system paths break"
                                                            + " in containerised or cloud-native"
                                                            + " deployments where the path may not"
                                                            + " exist. Data written to a"
                                                            + " container's local file system is"
                                                            + " also lost on restart or horizontal"
                                                            + " scaling.")
                                                .possibleImpact(
                                                        "Application fails on startup or at runtime"
                                                            + " in cloud environments. Files"
                                                            + " written to a container's local disk"
                                                            + " are lost on pod restart, causing"
                                                            + " silent data loss.")
                                                .recommendation(
                                                        "Abstract file storage behind an interface"
                                                            + " and use cloud-agnostic object"
                                                            + " storage (Amazon S3, Azure Blob,"
                                                            + " GCS) for uploaded files and"
                                                            + " persistent data. Read paths from"
                                                            + " configuration properties rather"
                                                            + " than hardcoding them.")
                                                .limitations(
                                                        "Only detects string literals passed"
                                                                + " directly to Paths.get() or"
                                                                + " Path.of(). Paths assembled via"
                                                                + " concatenation or variables are"
                                                                + " not detected.")
                                                .evidence(
                                                        apiName
                                                                + "(\""
                                                                + val
                                                                + "\") found in "
                                                                + relativePath
                                                                + ".")
                                                .source(relativePath, line)
                                                .build());
                            });
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_LOMBOK_DATA_ON_ENTITY
    // ---------------------------------------------------------------------------

    private void detectLombokDataOnEntity(
            ClassOrInterfaceDeclaration cls, String relativePath, List<Finding> findings) {
        boolean hasEntity =
                cls.getAnnotations().stream()
                        .anyMatch(a -> simpleName(a.getNameAsString()).equals("Entity"));
        boolean hasData =
                cls.getAnnotations().stream()
                        .anyMatch(a -> simpleName(a.getNameAsString()).equals("Data"));
        if (!hasEntity || !hasData) {
            return;
        }
        Integer line = cls.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_LOMBOK_DATA_ON_ENTITY, FindingConfidence.HIGH)
                        .shortMessage(
                                "@Data combined with @Entity on "
                                        + target
                                        + " — auto-generated equals/hashCode/toString risk.")
                        .whyBadPractice(
                                "Lombok @Data generates equals(), hashCode(), and toString() over"
                                    + " all fields. On JPA entities, these generated methods"
                                    + " traverse lazy-loaded associations, eagerly initialising the"
                                    + " entire object graph. Bidirectional relationships cause"
                                    + " infinite recursion and StackOverflowError when any of these"
                                    + " methods are called (e.g., during logging, hashing, or"
                                    + " serialisation).")
                        .possibleImpact(
                                "StackOverflowError in production when entities with bidirectional"
                                    + " associations are serialised to JSON, put in a Set/Map, or"
                                    + " logged. LazyInitializationException if lazy associations"
                                    + " are accessed outside a transaction via the generated"
                                    + " methods.")
                        .recommendation(
                                "Replace @Data with @Getter and @Setter. Implement equals() and"
                                    + " hashCode() manually based on the entity's primary key, or"
                                    + " use @EqualsAndHashCode(onlyExplicitlyIncluded = true) with"
                                    + " @EqualsAndHashCode.Include on the ID field. Exclude"
                                    + " bidirectional association fields from toString() using"
                                    + " @ToString.Exclude.")
                        .limitations(
                                "High confidence. Risk is always present when @Data is used on an"
                                        + " entity with any association fields.")
                        .evidence(
                                cls.getNameAsString()
                                        + " in "
                                        + relativePath
                                        + " has both @Entity and @Data.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_REST_TEMPLATE_NO_TIMEOUT
    // ---------------------------------------------------------------------------

    private void detectRestTemplateNoTimeout(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ObjectCreationExpr expr : cu.findAll(ObjectCreationExpr.class)) {
            String typeName = expr.getTypeAsString();
            if (!"RestTemplate".equals(typeName)) {
                continue;
            }
            if (!expr.getArguments().isEmpty()) {
                // Arguments suggest a custom factory/interceptor list is being passed
                continue;
            }
            Integer line = expr.getBegin().map(p -> p.line).orElse(null);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_REST_TEMPLATE_NO_TIMEOUT,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "new RestTemplate() with no-arg constructor in "
                                            + relativePath
                                            + " — no timeout is configured.")
                            .whyBadPractice(
                                    "The no-arg RestTemplate constructor uses"
                                        + " SimpleClientHttpRequestFactory with connect and read"
                                        + " timeouts of zero, which means the connection can block"
                                        + " indefinitely. If a downstream service hangs, the"
                                        + " calling thread is held until the OS or JVM forcibly"
                                        + " closes the socket, which can take minutes.")
                            .possibleImpact(
                                    "Thread pool exhaustion and application-wide outage when a"
                                        + " downstream service slows down or becomes unresponsive."
                                        + " Under load, all available threads can be consumed"
                                        + " waiting for a response that never arrives.")
                            .recommendation(
                                    "Configure a timeout-aware request factory:"
                                        + " HttpComponentsClientHttpRequestFactory or"
                                        + " SimpleClientHttpRequestFactory with explicit connect"
                                        + " and read timeouts. Alternatively, inject the"
                                        + " auto-configured RestTemplateBuilder and set"
                                        + " connectTimeout/readTimeout on it; on Spring Boot 3.4+"
                                        + " the global spring.http.client.connect-timeout and"
                                        + " spring.http.client.read-timeout properties apply to"
                                        + " auto-configured client request factories.")
                            .limitations(
                                    "Medium confidence — a timeout may be configured later by"
                                        + " calling setRequestFactory() on the returned instance."
                                        + " Only direct no-arg constructor calls are detected.")
                            .evidence("new RestTemplate() (no-arg) found in " + relativePath + ".")
                            .source(relativePath, line)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_PROTOTYPE_BEAN_IN_SINGLETON
    // ---------------------------------------------------------------------------

    private void detectPrototypeBeanInSingleton(
            ClassOrInterfaceDeclaration cls,
            String relativePath,
            Set<String> prototypeTypes,
            List<Finding> findings) {
        boolean isSingleton =
                cls.getAnnotations().stream()
                        .anyMatch(
                                a ->
                                        SINGLETON_ANNOTATIONS.contains(
                                                simpleName(a.getNameAsString())));
        if (!isSingleton) {
            return;
        }
        // Check directly-injected fields
        for (FieldDeclaration field : cls.getFields()) {
            String fieldType = field.getElementType().asString();
            String simpleFieldType = simpleName(fieldType);
            if (!prototypeTypes.contains(simpleFieldType)) {
                continue;
            }
            Integer line = field.getBegin().map(p -> p.line).orElse(null);
            String target = cls.getNameAsString() + "#" + field.getVariable(0).getNameAsString();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_PROTOTYPE_BEAN_IN_SINGLETON,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "Prototype bean "
                                            + simpleFieldType
                                            + " injected as a field into singleton "
                                            + cls.getNameAsString()
                                            + " — it will only be instantiated once.")
                            .whyBadPractice(
                                    "When a @Scope(\"prototype\") bean is injected directly into a"
                                        + " singleton bean, Spring creates one instance of the"
                                        + " prototype at context startup and reuses it for the"
                                        + " singleton's entire lifetime. The prototype effectively"
                                        + " becomes a singleton, which defeats the purpose of the"
                                        + " scope and typically causes shared mutable state and"
                                        + " thread-safety bugs.")
                            .possibleImpact(
                                    "Race conditions and shared-state bugs if the prototype bean"
                                        + " holds per-request or per-use state. The application"
                                        + " appears to work correctly in low-concurrency testing"
                                        + " but fails unpredictably under production load.")
                            .recommendation(
                                    "Inject an ObjectFactory<"
                                            + simpleFieldType
                                            + "> or Provider<"
                                            + simpleFieldType
                                            + "> instead of the bean directly, and call"
                                            + " objectFactory.getObject() each time a fresh"
                                            + " instance is needed. Alternatively, annotate the"
                                            + " injection method with @Lookup to delegate instance"
                                            + " creation to the Spring container on every call.")
                            .limitations(
                                    "High confidence. Detects direct field injection. Constructor"
                                            + " injection of prototype types is also flagged.")
                            .evidence(
                                    "Field "
                                            + field.getVariable(0).getNameAsString()
                                            + " of type "
                                            + simpleFieldType
                                            + " (prototype) in singleton "
                                            + cls.getNameAsString()
                                            + " in "
                                            + relativePath
                                            + ".")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }

        // Check constructor parameters (constructor injection)
        for (ConstructorDeclaration ctor : cls.getConstructors()) {
            for (var param : ctor.getParameters()) {
                String paramType = simpleName(param.getTypeAsString());
                if (!prototypeTypes.contains(paramType)) {
                    continue;
                }
                Integer line = ctor.getBegin().map(p -> p.line).orElse(null);
                String target = cls.getNameAsString() + "(" + paramType + ")";
                findings.add(
                        FindingFactory.builder(
                                        FindingRules.SPRING_PROTOTYPE_BEAN_IN_SINGLETON,
                                        FindingConfidence.HIGH)
                                .shortMessage(
                                        "Prototype bean "
                                                + paramType
                                                + " injected via constructor into singleton "
                                                + cls.getNameAsString()
                                                + " — it will only be instantiated once.")
                                .whyBadPractice(
                                        "When a @Scope(\"prototype\") bean is injected into a"
                                            + " singleton's constructor, Spring creates one"
                                            + " instance at context startup and keeps it for the"
                                            + " singleton's lifetime. The prototype loses its"
                                            + " per-use semantics.")
                                .possibleImpact(
                                        "Race conditions and shared-state bugs under concurrent"
                                            + " load if the prototype bean holds per-use state.")
                                .recommendation(
                                        "Inject an ObjectFactory<"
                                                + paramType
                                                + "> or Provider<"
                                                + paramType
                                                + "> and call getObject() each time a fresh"
                                                + " instance is required, or use @Lookup method"
                                                + " injection.")
                                .limitations(
                                        "Constructor injection may be intentional if the class is"
                                                + " itself prototype-scoped — verify the caller's"
                                                + " scope.")
                                .evidence(
                                        "Constructor parameter of type "
                                                + paramType
                                                + " (prototype) in singleton "
                                                + cls.getNameAsString()
                                                + " in "
                                                + relativePath
                                                + ".")
                                .source(relativePath, line)
                                .target(target)
                                .build());
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_FILTER_COMPONENT_REGISTRATION_LEAK
    // ---------------------------------------------------------------------------

    private void detectFilterComponentRegistrationLeak(
            ClassOrInterfaceDeclaration cls, String relativePath, List<Finding> findings) {
        // @Component, @Service, @Repository are all meta-annotated with @Component and cause the
        // same auto-registration of the Filter into the global servlet chain.
        boolean hasSpringStereotype =
                cls.getAnnotations().stream()
                        .map(a -> simpleName(a.getNameAsString()))
                        .anyMatch(
                                n ->
                                        n.equals("Component")
                                                || n.equals("Service")
                                                || n.equals("Repository"));
        if (!hasSpringStereotype) {
            return;
        }
        boolean implementsFilter =
                cls.getImplementedTypes().stream()
                        .anyMatch(t -> simpleName(t.getNameAsString()).equals("Filter"));
        if (!implementsFilter) {
            return;
        }
        Integer line = cls.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_FILTER_COMPONENT_REGISTRATION_LEAK,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                cls.getNameAsString()
                                        + " implements Filter and carries a Spring stereotype"
                                        + " annotation — Spring Boot will register it globally,"
                                        + " bypassing any SecurityFilterChain restrictions.")
                        .whyBadPractice(
                                "Spring Boot auto-registers every @Component that implements"
                                    + " javax.servlet.Filter or jakarta.servlet.Filter into the"
                                    + " main Servlet filter chain. This happens independently of"
                                    + " any Spring Security configuration. If the filter is also"
                                    + " added to a SecurityFilterChain via addFilterBefore() /"
                                    + " addFilterAfter(), it will execute twice per request. URL"
                                    + " pattern restrictions configured in SecurityFilterChain do"
                                    + " not apply to the auto-registered instance.")
                        .possibleImpact(
                                "Security filters execute for every request including"
                                    + " unauthenticated or public endpoints where they should not"
                                    + " apply. Filters added to a SecurityFilterChain may execute"
                                    + " twice, causing double logging, double token consumption, or"
                                    + " incorrect authentication state.")
                        .recommendation(
                                "Remove @Component from the filter class. Register it exclusively"
                                    + " through Spring Security's SecurityFilterChain using"
                                    + " http.addFilterBefore() or http.addFilterAfter(). If the"
                                    + " filter must be a Spring bean for dependency injection but"
                                    + " should not be auto-registered, declare a"
                                    + " FilterRegistrationBean<YourFilter> bean and call"
                                    + " setEnabled(false) on it.")
                        .limitations(
                                "High confidence. Detects @Component, @Service, and @Repository"
                                        + " on Filter implementations. @Controller and"
                                        + " @RestController are intentionally excluded — those are"
                                        + " unlikely on a Filter class.")
                        .evidence(
                                cls.getNameAsString()
                                        + " in "
                                        + relativePath
                                        + " implements Filter and carries @Component.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_WEBFLUX_BLOCKING_CALL
    // ---------------------------------------------------------------------------

    private static final Set<String> BLOCKING_METHOD_NAMES =
            Set.of("block", "blockFirst", "blockLast");

    private void detectBlockingCalls(
            CompilationUnit cu,
            String relativePath,
            RuntimeStackAnalysis runtimeStackAnalysis,
            List<Finding> findings) {
        WebStack webStack =
                runtimeStackAnalysis == null || runtimeStackAnalysis.webStack() == null
                        ? WebStack.UNKNOWN
                        : runtimeStackAnalysis.webStack();
        boolean reactorTypesImported = usesReactorTypes(cu);
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            String name = call.getNameAsString();
            boolean isThreadSleep =
                    "sleep".equals(name)
                            && call.getScope()
                                    .map(
                                            scope ->
                                                    "Thread".equals(scope.toString())
                                                            || "java.lang.Thread"
                                                                    .equals(scope.toString()))
                                    .orElse(false);
            // Detect .block(), .blockFirst(), .blockLast() with 0 or 1 argument.
            // .block(Duration) with a timeout is still blocking and still dangerous in WebFlux.
            boolean isReactiveBlock =
                    BLOCKING_METHOD_NAMES.contains(name) && call.getArguments().size() <= 1;

            if (!isReactiveBlock && !isThreadSleep) {
                continue;
            }

            ClassOrInterfaceDeclaration enclosingClass =
                    call.findAncestor(ClassOrInterfaceDeclaration.class).orElse(null);
            if (enclosingClass == null || !isSpringManagedClass(enclosingClass)) {
                continue;
            }

            MethodDeclaration enclosingMethod =
                    call.findAncestor(MethodDeclaration.class).orElse(null);
            if (isThreadSleep) {
                addThreadSleepFinding(
                        call,
                        enclosingClass,
                        enclosingMethod,
                        relativePath,
                        runtimeStackAnalysis,
                        webStack,
                        findings);
                continue;
            }

            // A method named block() is common in non-reactive APIs. Requiring Reactor types in
            // this file avoids warning on unrelated DSLs, and MVC is intentionally excluded:
            // blocking at a deliberate client boundary is valid there even when WebClient is on
            // the classpath.
            if (!reactorTypesImported
                    || (webStack != WebStack.REACTIVE_WEBFLUX && webStack != WebStack.UNKNOWN)) {
                continue;
            }

            Integer line = call.getBegin().map(p -> p.line).orElse(null);
            String callDescription = "." + name + "()";
            String target =
                    enclosingClass.getNameAsString()
                            + (enclosingMethod == null
                                    ? ""
                                    : "#" + enclosingMethod.getNameAsString());
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_WEBFLUX_BLOCKING_CALL,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    callDescription
                                            + " called inside a Spring-managed component in "
                                            + relativePath
                                            + " — blocks the calling thread.")
                            .whyBadPractice(
                                    "Calling .block() on a Mono or Flux blocks the calling thread"
                                            + " until the reactive pipeline completes. In a"
                                            + " WebFlux application this can block an event-loop"
                                            + " worker that is expected to remain non-blocking.")
                            .possibleImpact(
                                    "Event-loop thread starvation in WebFlux, cascading latency"
                                        + " under concurrent load, and thread pool exhaustion. In"
                                        + " the worst case the application becomes unresponsive"
                                        + " under traffic while appearing healthy at low"
                                        + " concurrency.")
                            .recommendation(
                                    "Remove .block() and compose or return the Mono/Flux. If an"
                                            + " unavoidable blocking API must be called, isolate"
                                            + " that API on Schedulers.boundedElastic() at the"
                                            + " blocking boundary.")
                            .limitations(
                                    "Requires Reactor types in the same source file and an active"
                                            + " or unresolved WebFlux stack. Static analysis cannot"
                                            + " prove which Scheduler executes this exact call.")
                            .evidence(callDescription + " found in " + relativePath + ".")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    private void addThreadSleepFinding(
            MethodCallExpr call,
            ClassOrInterfaceDeclaration enclosingClass,
            MethodDeclaration enclosingMethod,
            String relativePath,
            RuntimeStackAnalysis runtimeStackAnalysis,
            WebStack webStack,
            List<Finding> findings) {
        boolean controller = hasAnyAnnotation(enclosingClass, "Controller", "RestController");
        boolean httpHandler =
                controller
                        || hasAnyMethodAnnotation(
                                enclosingMethod,
                                "RequestMapping",
                                "GetMapping",
                                "PostMapping",
                                "PutMapping",
                                "PatchMapping",
                                "DeleteMapping");
        boolean scheduled = hasAnyMethodAnnotation(enclosingMethod, "Scheduled");
        boolean async = hasAnyMethodAnnotation(enclosingMethod, "Async");
        boolean listener =
                hasAnyMethodAnnotation(
                        enclosingMethod,
                        "KafkaListener",
                        "RabbitListener",
                        "JmsListener",
                        "EventListener");
        boolean beanCreation = hasAnyMethodAnnotation(enclosingMethod, "Bean");
        boolean reactiveHttpHandler =
                webStack == WebStack.REACTIVE_WEBFLUX
                        && (httpHandler
                                || (!scheduled
                                        && !async
                                        && !listener
                                        && !beanCreation
                                        && hasReactiveHandlerSignature(enclosingMethod)));
        boolean highImpactContext =
                reactiveHttpHandler
                        || httpHandler
                        || scheduled
                        || async
                        || listener
                        || beanCreation;
        boolean virtualThreadsEnabled =
                runtimeStackAnalysis != null
                        && runtimeStackAnalysis.virtualThreads() != null
                        && runtimeStackAnalysis.virtualThreads().enabledByProperty();

        String context =
                scheduled
                        ? "a scheduled method"
                        : async
                                ? "an @Async method"
                                : listener
                                        ? "a message or event listener"
                                        : beanCreation
                                                ? "bean creation"
                                                : reactiveHttpHandler
                                                        ? "a reactive HTTP handler"
                                                        : httpHandler
                                                                ? "an HTTP request handler"
                                                                : "a Spring-managed component";
        String recommendation =
                scheduled
                        ? "Model the cadence with @Scheduled(fixedDelayString = ...) or a"
                                + " TaskScheduler instead of sleeping inside the job."
                        : async || listener
                                ? "Schedule delayed work with TaskScheduler or a bounded"
                                        + " delayed executor so a worker is not occupied"
                                        + " while nothing is running."
                                : reactiveHttpHandler
                                        ? "Replace the delay with Mono.delay(...)"
                                                + " and compose it into the"
                                                + " reactive chain. Do not sleep on"
                                                + " an event-loop worker."
                                        : httpHandler
                                                ? "Remove the artificial wait from the"
                                                        + " request path. Model"
                                                        + " asynchronous completion or a"
                                                        + " real downstream timeout"
                                                        + " explicitly."
                                                : "If this is retry backoff, prefer Spring Retry"
                                                      + " @Backoff or TaskScheduler. If the sleep"
                                                      + " is deliberately bounded, document it and"
                                                      + " preserve interruption by restoring the"
                                                      + " interrupt flag.";
        String impact =
                virtualThreadsEnabled && !reactiveHttpHandler
                        ? "Virtual threads reduce the platform-thread cost, but the operation still"
                                + " waits for the full sleep duration and can delay requests, jobs,"
                                + " or message handling."
                        : highImpactContext
                                ? "The managed worker cannot make progress during the sleep. Under"
                                        + " concurrency this can increase latency, reduce scheduler"
                                        + " or listener throughput, and exhaust a bounded executor."
                                : "The call blocks its current worker and may reduce throughput if"
                                        + " this method is reached concurrently.";
        Integer line = call.getBegin().map(position -> position.line).orElse(null);
        String target =
                enclosingClass.getNameAsString()
                        + (enclosingMethod == null ? "" : "#" + enclosingMethod.getNameAsString());
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_MANAGED_THREAD_SLEEP,
                                highImpactContext
                                        ? FindingConfidence.HIGH
                                        : FindingConfidence.MEDIUM)
                        .severity(
                                highImpactContext ? FindingSeverity.WARNING : FindingSeverity.INFO)
                        .shortMessage("Thread.sleep() is called in " + context + ".")
                        .whyBadPractice(
                                "Thread.sleep() represents waiting by occupying the current"
                                    + " execution path. Whether that is dangerous depends on the"
                                    + " Spring-managed context, so this rule prioritizes request,"
                                    + " reactive, scheduled, async, and listener code.")
                        .possibleImpact(impact)
                        .recommendation(recommendation)
                        .evidence("Thread.sleep() found in " + target + " in " + relativePath + ".")
                        .limitations(
                                "Static analysis cannot prove the executing thread or whether the"
                                        + " method has already been offloaded to a dedicated"
                                        + " executor. Generic component methods are therefore INFO"
                                        + " rather than WARNING. Test sources are not scanned.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    private boolean usesReactorTypes(CompilationUnit compilationUnit) {
        return compilationUnit.getImports().stream()
                .map(importDeclaration -> importDeclaration.getNameAsString())
                .anyMatch(name -> name.startsWith("reactor.core.publisher"));
    }

    private boolean isSpringManagedClass(ClassOrInterfaceDeclaration declaration) {
        return declaration.getAnnotations().stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .anyMatch(SINGLETON_ANNOTATIONS::contains);
    }

    private boolean hasAnyAnnotation(
            ClassOrInterfaceDeclaration declaration, String... annotationNames) {
        return declaration.getAnnotations().stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .anyMatch(annotation -> matchesAny(annotation, annotationNames));
    }

    private boolean hasAnyMethodAnnotation(MethodDeclaration method, String... annotationNames) {
        if (method == null) {
            return false;
        }
        return method.getAnnotations().stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .anyMatch(annotation -> matchesAny(annotation, annotationNames));
    }

    private boolean hasReactiveHandlerSignature(MethodDeclaration method) {
        if (method == null) {
            return false;
        }
        String returnType = method.getTypeAsString();
        boolean reactiveReturnType =
                returnType.contains("Mono")
                        || returnType.contains("Flux")
                        || returnType.contains("ServerResponse");
        boolean serverRequestParameter =
                method.getParameters().stream()
                        .map(parameter -> parameter.getTypeAsString())
                        .anyMatch(type -> type.contains("ServerRequest"));
        return reactiveReturnType || serverRequestParameter;
    }

    private boolean matchesAny(String candidate, String... expectedValues) {
        for (String expected : expectedValues) {
            if (expected.equals(candidate)) {
                return true;
            }
        }
        return false;
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_NON_THREAD_SAFE_FORMATTER_FIELD
    // ---------------------------------------------------------------------------

    private static final Set<String> NON_THREAD_SAFE_FORMATTER_TYPES =
            Set.of("SimpleDateFormat", "DateFormat", "NumberFormat", "DecimalFormat");

    private void detectNonThreadSafeFormatterField(
            ClassOrInterfaceDeclaration cls, String relativePath, List<Finding> findings) {
        boolean isSingleton =
                cls.getAnnotations().stream()
                        .anyMatch(
                                a ->
                                        SINGLETON_ANNOTATIONS.contains(
                                                simpleName(a.getNameAsString())));
        if (!isSingleton) {
            return;
        }
        for (FieldDeclaration field : cls.getFields()) {
            String fieldType = simpleName(field.getElementType().asString());
            if (!NON_THREAD_SAFE_FORMATTER_TYPES.contains(fieldType)) {
                continue;
            }
            Integer line = field.getBegin().map(p -> p.line).orElse(null);
            String fieldName =
                    field.getVariables().isEmpty()
                            ? fieldType
                            : field.getVariable(0).getNameAsString();
            String target = cls.getNameAsString() + "#" + fieldName;
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_NON_THREAD_SAFE_FORMATTER_FIELD,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    fieldType
                                            + " field "
                                            + target
                                            + " in a Spring singleton is not thread-safe.")
                            .whyBadPractice(
                                    fieldType
                                            + " (and the other java.text formatters) is documented"
                                            + " as not thread-safe: it mutates internal Calendar"
                                            + " state during format()/parse(). A Spring"
                                            + " @Service/@Component is a singleton shared by every"
                                            + " request thread, so concurrent calls interleave and"
                                            + " corrupt that state.")
                            .possibleImpact(
                                    "Under concurrency the formatter silently returns wrong dates"
                                        + " or numbers, or throws NumberFormatException /"
                                        + " ArrayIndexOutOfBoundsException intermittently — bugs"
                                        + " that are very hard to reproduce.")
                            .recommendation(
                                    "Use java.time.format.DateTimeFormatter (immutable and"
                                        + " thread-safe) instead of SimpleDateFormat. If you must"
                                        + " use a java.text formatter, create a new instance per"
                                        + " call or store it in a ThreadLocal.")
                            .limitations(
                                    "High confidence — these types are well-documented as not"
                                            + " thread-safe and a singleton field is shared across"
                                            + " threads.")
                            .evidence(
                                    fieldType
                                            + " field declared in "
                                            + cls.getNameAsString()
                                            + " ("
                                            + relativePath
                                            + ").")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_UNBOUNDED_FINDALL
    // ---------------------------------------------------------------------------

    private record RepositoryDeclaration(
            String qualifiedName,
            CompilationUnit compilationUnit,
            ClassOrInterfaceDeclaration declaration) {}

    private record RepositoryTypeIndex(
            Set<String> repositoryTypes,
            Set<String> boundedRepositoryTypes,
            Map<String, Set<String>> repositoryTypesBySimpleName) {}

    private RepositoryTypeIndex collectRepositoryTypes(JavaSources sources) {
        Map<String, RepositoryDeclaration> declarations = new LinkedHashMap<>();
        Map<String, Set<String>> declarationsBySimpleName = new LinkedHashMap<>();
        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            CompilationUnit cu = file.compilationUnit();
            if (cu == null) {
                continue;
            }
            for (ClassOrInterfaceDeclaration declaration :
                    cu.findAll(ClassOrInterfaceDeclaration.class)) {
                if (!declaration.isTopLevelType()) {
                    continue;
                }
                String qualifiedName =
                        declaration
                                .getFullyQualifiedName()
                                .orElseGet(
                                        () ->
                                                cu.getPackageDeclaration()
                                                        .map(
                                                                pkg ->
                                                                        pkg.getNameAsString()
                                                                                + "."
                                                                                + declaration
                                                                                        .getNameAsString())
                                                        .orElse(declaration.getNameAsString()));
                declarations.put(
                        qualifiedName, new RepositoryDeclaration(qualifiedName, cu, declaration));
                declarationsBySimpleName
                        .computeIfAbsent(
                                declaration.getNameAsString(), ignored -> new LinkedHashSet<>())
                        .add(qualifiedName);
            }
        }

        Set<String> repositoryTypes = new LinkedHashSet<>();
        for (RepositoryDeclaration candidate : declarations.values()) {
            if (hasSpringDataRepositoryDefinition(candidate)
                    || candidate.declaration().getExtendedTypes().stream()
                            .anyMatch(
                                    type ->
                                            isDirectSpringDataRepositoryType(
                                                    candidate, type, declarations))) {
                repositoryTypes.add(candidate.qualifiedName());
            }
        }

        boolean changed;
        do {
            changed = false;
            for (RepositoryDeclaration candidate : declarations.values()) {
                if (repositoryTypes.contains(candidate.qualifiedName())) {
                    continue;
                }
                boolean extendsLocalRepository =
                        candidate.declaration().getExtendedTypes().stream()
                                .map(
                                        type ->
                                                resolveLocalType(
                                                        candidate.compilationUnit(),
                                                        type.asString(),
                                                        declarations,
                                                        declarationsBySimpleName))
                                .anyMatch(repositoryTypes::contains);
                if (extendsLocalRepository) {
                    changed |= repositoryTypes.add(candidate.qualifiedName());
                }
            }
        } while (changed);

        Set<String> boundedRepositoryTypes = new LinkedHashSet<>();
        for (String repositoryType : repositoryTypes) {
            RepositoryDeclaration declaration = declarations.get(repositoryType);
            if (declaration != null && looksLikeBoundedReferenceRepository(declaration)) {
                boundedRepositoryTypes.add(repositoryType);
            }
        }
        Map<String, Set<String>> repositoryTypesBySimpleName = new LinkedHashMap<>();
        for (String repositoryType : repositoryTypes) {
            repositoryTypesBySimpleName
                    .computeIfAbsent(simpleName(repositoryType), ignored -> new LinkedHashSet<>())
                    .add(repositoryType);
        }
        return new RepositoryTypeIndex(
                Set.copyOf(repositoryTypes),
                Set.copyOf(boundedRepositoryTypes),
                repositoryTypesBySimpleName);
    }

    private boolean hasSpringDataRepositoryDefinition(RepositoryDeclaration candidate) {
        return candidate.declaration().getAnnotations().stream()
                .anyMatch(
                        annotation -> {
                            String annotationName = annotation.getNameAsString();
                            if (!"RepositoryDefinition".equals(simpleName(annotationName))) {
                                return false;
                            }
                            if ("org.springframework.data.repository.RepositoryDefinition"
                                    .equals(annotationName)) {
                                return true;
                            }
                            return candidate.compilationUnit().getImports().stream()
                                    .filter(importDeclaration -> !importDeclaration.isStatic())
                                    .filter(importDeclaration -> !importDeclaration.isAsterisk())
                                    .map(importDeclaration -> importDeclaration.getNameAsString())
                                    .anyMatch(
                                            "org.springframework.data.repository.RepositoryDefinition"
                                                    ::equals);
                        });
    }

    private boolean isDirectSpringDataRepositoryType(
            RepositoryDeclaration candidate,
            ClassOrInterfaceType type,
            Map<String, RepositoryDeclaration> declarations) {
        String typeName = type.getNameWithScope();
        String typeSimpleName = simpleName(typeName);
        if (!SPRING_DATA_REPOSITORY_BASE_TYPES.contains(typeSimpleName)) {
            return false;
        }
        if (typeName.startsWith("org.springframework.data.")) {
            return true;
        }
        CompilationUnit cu = candidate.compilationUnit();
        boolean explicitlyImported =
                cu.getImports().stream()
                        .filter(importDeclaration -> !importDeclaration.isStatic())
                        .filter(importDeclaration -> !importDeclaration.isAsterisk())
                        .map(importDeclaration -> importDeclaration.getNameAsString())
                        .anyMatch(
                                imported ->
                                        imported.startsWith("org.springframework.data.")
                                                && simpleName(imported).equals(typeSimpleName));
        if (explicitlyImported) {
            return true;
        }
        String samePackageType =
                cu.getPackageDeclaration()
                        .map(pkg -> pkg.getNameAsString() + "." + typeSimpleName)
                        .orElse(typeSimpleName);
        if (declarations.containsKey(samePackageType)) {
            return false;
        }
        return cu.getImports().stream()
                .filter(importDeclaration -> !importDeclaration.isStatic())
                .filter(importDeclaration -> importDeclaration.isAsterisk())
                .map(importDeclaration -> importDeclaration.getNameAsString())
                .anyMatch(imported -> imported.startsWith("org.springframework.data."));
    }

    private boolean isImportedType(CompilationUnit cu, String typeName, String packagePrefix) {
        if (typeName.startsWith(packagePrefix + ".")) {
            return true;
        }
        String typeSimpleName = simpleName(typeName);
        return cu.getImports().stream()
                .filter(importDeclaration -> !importDeclaration.isStatic())
                .anyMatch(
                        importDeclaration -> {
                            String imported = importDeclaration.getNameAsString();
                            if (!imported.startsWith(packagePrefix + ".")) {
                                return false;
                            }
                            return importDeclaration.isAsterisk()
                                    || simpleName(imported).equals(typeSimpleName);
                        });
    }

    private String resolveLocalType(
            CompilationUnit cu,
            String rawType,
            Map<String, RepositoryDeclaration> declarations,
            Map<String, Set<String>> declarationsBySimpleName) {
        String type = rawType.replaceAll("<.*>", "").trim();
        if (declarations.containsKey(type)) {
            return type;
        }
        String typeSimpleName = simpleName(type);
        String importedType =
                cu.getImports().stream()
                        .filter(importDeclaration -> !importDeclaration.isStatic())
                        .filter(importDeclaration -> !importDeclaration.isAsterisk())
                        .map(importDeclaration -> importDeclaration.getNameAsString())
                        .filter(imported -> simpleName(imported).equals(typeSimpleName))
                        .findFirst()
                        .orElse(null);
        if (importedType != null && declarations.containsKey(importedType)) {
            return importedType;
        }
        String samePackageType =
                cu.getPackageDeclaration()
                        .map(pkg -> pkg.getNameAsString() + "." + typeSimpleName)
                        .orElse(typeSimpleName);
        if (declarations.containsKey(samePackageType)) {
            return samePackageType;
        }
        Set<String> candidates = declarationsBySimpleName.getOrDefault(typeSimpleName, Set.of());
        return candidates.size() == 1 ? candidates.iterator().next() : null;
    }

    private boolean looksLikeBoundedReferenceRepository(RepositoryDeclaration repository) {
        if (BOUNDED_REFERENCE_REPOSITORY_PATTERN
                .matcher(repository.declaration().getNameAsString())
                .find()) {
            return true;
        }
        return repository.declaration().getExtendedTypes().stream()
                .flatMap(type -> type.getTypeArguments().stream().flatMap(List::stream))
                .map(type -> simpleName(type.asString()))
                .anyMatch(type -> BOUNDED_REFERENCE_REPOSITORY_PATTERN.matcher(type).find());
    }

    private void detectUnboundedFindAll(
            CompilationUnit cu,
            String relativePath,
            RepositoryTypeIndex repositoryTypes,
            List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!"findAll".equals(call.getNameAsString()) || !call.getArguments().isEmpty()) {
                continue;
            }
            String receiver = receiverName(call.getScope().orElse(null));
            if (receiver == null) {
                continue;
            }
            String declaredType = declaredReceiverType(call, receiver);
            String repositoryType = resolveRepositoryType(cu, declaredType, repositoryTypes);
            if (repositoryType == null
                    || repositoryTypes.boundedRepositoryTypes().contains(repositoryType)
                    || !isHotRuntimeContext(call)) {
                continue;
            }
            Integer line = call.getBegin().map(p -> p.line).orElse(null);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_UNBOUNDED_FINDALL, FindingConfidence.MEDIUM)
                            .shortMessage(
                                    receiver
                                            + ".findAll() with no Pageable in "
                                            + relativePath
                                            + " loads the whole table into memory.")
                            .whyBadPractice(
                                    "A no-argument findAll() issues an unbounded datastore query."
                                        + " On a table or collection that grows over time this"
                                        + " materialises every record (and its associations) into"
                                        + " the heap at once.")
                            .possibleImpact(
                                    "As the table grows the call causes long GC pauses and"
                                        + " eventually OutOfMemoryError, taking down the instance —"
                                        + " a failure that only appears once production data is"
                                        + " large enough.")
                            .recommendation(
                                    "Use the paginated overload findAll(Pageable) and stream/page"
                                        + " through results, or add a query with an explicit WHERE"
                                        + " and LIMIT. Reserve unbounded findAll() for small,"
                                        + " bounded reference tables only.")
                            .limitations(
                                    "Medium confidence — the receiver's declared type resolves to a"
                                        + " locally declared Spring Data/@Repository type and the"
                                        + " call is in a mapped, scheduled, listener, runner, or"
                                        + " loop context. Static analysis still cannot establish"
                                        + " table cardinality or prove every call path. Repository"
                                        + " and domain names that clearly indicate bounded"
                                        + " code/config/reference data are conservatively skipped.")
                            .evidence(
                                    receiver
                                            + ".findAll() resolves to "
                                            + repositoryType
                                            + " in a runtime/hot context in "
                                            + relativePath
                                            + ".")
                            .source(relativePath, line)
                            .build());
        }
    }

    private String declaredReceiverType(MethodCallExpr call, String receiver) {
        MethodDeclaration method = call.findAncestor(MethodDeclaration.class).orElse(null);
        if (method != null) {
            String parameterType =
                    method.getParameters().stream()
                            .filter(parameter -> parameter.getNameAsString().equals(receiver))
                            .map(Parameter::getTypeAsString)
                            .findFirst()
                            .orElse(null);
            if (parameterType != null) {
                return parameterType;
            }
            int callLine = call.getBegin().map(position -> position.line).orElse(Integer.MAX_VALUE);
            String localType =
                    method.findAll(VariableDeclarator.class).stream()
                            .filter(variable -> variable.getNameAsString().equals(receiver))
                            .filter(
                                    variable ->
                                            variable.getBegin()
                                                    .map(position -> position.line <= callLine)
                                                    .orElse(true))
                            .map(variable -> variable.getType().asString())
                            .reduce((first, second) -> second)
                            .orElse(null);
            if (localType != null) {
                return localType;
            }
        }
        ClassOrInterfaceDeclaration enclosingClass =
                call.findAncestor(ClassOrInterfaceDeclaration.class).orElse(null);
        if (enclosingClass == null) {
            return null;
        }
        return enclosingClass.getFields().stream()
                .flatMap(field -> field.getVariables().stream())
                .filter(variable -> variable.getNameAsString().equals(receiver))
                .map(variable -> variable.getType().asString())
                .findFirst()
                .orElse(null);
    }

    private String resolveRepositoryType(
            CompilationUnit cu, String declaredType, RepositoryTypeIndex repositoryTypes) {
        if (declaredType == null) {
            return null;
        }
        String type = declaredType.replaceAll("<.*>", "").replace("[]", "").trim();
        if (repositoryTypes.repositoryTypes().contains(type)) {
            return type;
        }
        String typeSimpleName = simpleName(type);
        String importedType =
                cu.getImports().stream()
                        .filter(importDeclaration -> !importDeclaration.isStatic())
                        .filter(importDeclaration -> !importDeclaration.isAsterisk())
                        .map(importDeclaration -> importDeclaration.getNameAsString())
                        .filter(imported -> simpleName(imported).equals(typeSimpleName))
                        .findFirst()
                        .orElse(null);
        if (importedType != null && repositoryTypes.repositoryTypes().contains(importedType)) {
            return importedType;
        }
        String samePackageType =
                cu.getPackageDeclaration()
                        .map(pkg -> pkg.getNameAsString() + "." + typeSimpleName)
                        .orElse(typeSimpleName);
        if (repositoryTypes.repositoryTypes().contains(samePackageType)) {
            return samePackageType;
        }
        Set<String> candidates =
                repositoryTypes
                        .repositoryTypesBySimpleName()
                        .getOrDefault(typeSimpleName, Set.of());
        return candidates.size() == 1 ? candidates.iterator().next() : null;
    }

    private boolean isHotRuntimeContext(MethodCallExpr call) {
        MethodDeclaration method = call.findAncestor(MethodDeclaration.class).orElse(null);
        ClassOrInterfaceDeclaration enclosingClass =
                call.findAncestor(ClassOrInterfaceDeclaration.class).orElse(null);
        if (method == null || enclosingClass == null) {
            return false;
        }
        CompilationUnit cu = call.findCompilationUnit().orElse(null);
        if (cu == null) {
            return false;
        }
        boolean runtimeBean = isImportedSpringBean(cu, enclosingClass);
        if (!runtimeBean) {
            return false;
        }
        boolean mappedController =
                hasImportedAnnotation(
                                cu,
                                enclosingClass.getAnnotations(),
                                "org.springframework.web.bind.annotation",
                                "Controller",
                                "RestController")
                        && hasImportedAnnotation(
                                cu,
                                method.getAnnotations(),
                                "org.springframework.web.bind.annotation",
                                "RequestMapping",
                                "GetMapping",
                                "PostMapping",
                                "PutMapping",
                                "PatchMapping",
                                "DeleteMapping");
        boolean runtimeCallback = hasImportedRuntimeCallback(cu, method);
        boolean runner =
                "run".equals(method.getNameAsString())
                        && enclosingClass.getImplementedTypes().stream()
                                .anyMatch(
                                        type ->
                                                ("CommandLineRunner"
                                                                        .equals(
                                                                                simpleName(
                                                                                        type
                                                                                                .asString()))
                                                                || "ApplicationRunner"
                                                                        .equals(
                                                                                simpleName(
                                                                                        type
                                                                                                .asString())))
                                                        && isImportedType(
                                                                cu,
                                                                type.getNameWithScope(),
                                                                "org.springframework.boot"));
        if (mappedController || runtimeCallback || runner) {
            return true;
        }
        if (method.isPrivate()) {
            return false;
        }
        Node current = call;
        while (current != method) {
            if (current instanceof ForStmt
                    || current instanceof ForEachStmt
                    || current instanceof WhileStmt
                    || current instanceof DoStmt) {
                return true;
            }
            current = current.getParentNode().orElse(method);
        }
        return false;
    }

    private boolean isImportedSpringBean(
            CompilationUnit cu, ClassOrInterfaceDeclaration enclosingClass) {
        return hasImportedAnnotation(
                        cu,
                        enclosingClass.getAnnotations(),
                        "org.springframework.stereotype",
                        "Component",
                        "Service",
                        "Repository",
                        "Controller")
                || hasImportedAnnotation(
                        cu,
                        enclosingClass.getAnnotations(),
                        "org.springframework.web.bind.annotation",
                        "RestController")
                || hasImportedAnnotation(
                        cu,
                        enclosingClass.getAnnotations(),
                        "org.springframework.context.annotation",
                        "Configuration")
                || hasImportedAnnotation(
                        cu,
                        enclosingClass.getAnnotations(),
                        "org.springframework.boot.autoconfigure",
                        "SpringBootApplication");
    }

    private boolean hasImportedRuntimeCallback(CompilationUnit cu, MethodDeclaration method) {
        return hasImportedAnnotation(
                        cu,
                        method.getAnnotations(),
                        "org.springframework.scheduling.annotation",
                        "Scheduled")
                || hasImportedAnnotation(
                        cu,
                        method.getAnnotations(),
                        "org.springframework.context.event",
                        "EventListener")
                || hasImportedAnnotation(
                        cu,
                        method.getAnnotations(),
                        "org.springframework.transaction.event",
                        "TransactionalEventListener")
                || hasImportedAnnotation(
                        cu,
                        method.getAnnotations(),
                        "org.springframework.kafka.annotation",
                        "KafkaListener")
                || hasImportedAnnotation(
                        cu,
                        method.getAnnotations(),
                        "org.springframework.amqp.rabbit.annotation",
                        "RabbitListener")
                || hasImportedAnnotation(
                        cu,
                        method.getAnnotations(),
                        "org.springframework.jms.annotation",
                        "JmsListener");
    }

    private boolean hasImportedAnnotation(
            CompilationUnit cu,
            Iterable<AnnotationExpr> annotations,
            String packagePrefix,
            String... annotationNames) {
        for (AnnotationExpr annotation : annotations) {
            if (matchesAny(simpleName(annotation.getNameAsString()), annotationNames)
                    && isImportedType(cu, annotation.getNameAsString(), packagePrefix)) {
                return true;
            }
        }
        return false;
    }

    private static String receiverName(Expression scope) {
        if (scope instanceof NameExpr ne) {
            return ne.getNameAsString();
        }
        if (scope instanceof FieldAccessExpr fae && fae.getScope().isThisExpr()) {
            return fae.getNameAsString();
        }
        return null;
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_JPA_ENTITY_NO_NOARG_CONSTRUCTOR
    // ---------------------------------------------------------------------------

    /**
     * Lombok annotations that (conservatively) may generate a usable constructor. Suppressing on
     * any of them keeps false positives near zero at the cost of a few missed cases.
     */
    private static final Set<String> LOMBOK_CONSTRUCTOR_ANNOTATIONS =
            Set.of(
                    "NoArgsConstructor",
                    "Data",
                    "Value",
                    "RequiredArgsConstructor",
                    "AllArgsConstructor",
                    "Builder");

    private void detectEntityNoArgConstructor(
            ClassOrInterfaceDeclaration cls, String relativePath, List<Finding> findings) {
        boolean entityLike =
                cls.getAnnotations().stream()
                        .map(a -> simpleName(a.getNameAsString()))
                        .anyMatch(name -> "Entity".equals(name) || "Embeddable".equals(name));
        if (!entityLike) {
            return;
        }
        // Hibernate never instantiates abstract entity classes; concrete subclasses supply the
        // no-arg constructor and may call super(args).
        if (cls.isAbstract()) {
            return;
        }
        var constructors = cls.getConstructors();
        // No explicit constructor -> the compiler provides the implicit default one.
        if (constructors.isEmpty()) {
            return;
        }
        if (constructors.stream().anyMatch(c -> c.getParameters().isEmpty())) {
            return;
        }
        boolean lombokMayGenerate =
                cls.getAnnotations().stream()
                        .anyMatch(
                                a ->
                                        LOMBOK_CONSTRUCTOR_ANNOTATIONS.contains(
                                                simpleName(a.getNameAsString())));
        if (lombokMayGenerate) {
            return;
        }
        String annotationName =
                cls.getAnnotations().stream()
                        .map(a -> simpleName(a.getNameAsString()))
                        .filter(name -> "Entity".equals(name) || "Embeddable".equals(name))
                        .findFirst()
                        .orElse("Entity");
        Integer line = cls.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_JPA_ENTITY_NO_NOARG_CONSTRUCTOR,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "@"
                                        + annotationName
                                        + " "
                                        + target
                                        + " declares only parameterized constructors — Hibernate"
                                        + " cannot instantiate it.")
                        .whyBadPractice(
                                "JPA requires every entity to have a no-arg constructor (at least"
                                    + " protected). Declaring any constructor removes the implicit"
                                    + " default one, so Hibernate can no longer instantiate the"
                                    + " class when materialising query results.")
                        .possibleImpact(
                                "The application starts cleanly and writes may even work, but the"
                                        + " first SELECT that loads the entity throws"
                                        + " org.hibernate.InstantiationException ('No default"
                                        + " constructor for entity') — often on a code path first"
                                        + " exercised in production.")
                        .recommendation(
                                "Add a protected no-arg constructor (or Lombok's"
                                        + " @NoArgsConstructor(access = AccessLevel.PROTECTED))"
                                        + " alongside the parameterized ones.")
                        .evidence(
                                "@Entity "
                                        + target
                                        + " in "
                                        + relativePath
                                        + " declares "
                                        + constructors.size()
                                        + " constructor(s), none of which is no-arg.")
                        .limitations(
                                "Suppressed when any Lombok constructor-generating annotation is"
                                        + " present, even ones that do not actually produce a"
                                        + " no-arg constructor — conservative to avoid false"
                                        + " positives.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_JPA_FINAL_ENTITY
    // ---------------------------------------------------------------------------

    private void detectFinalEntity(
            ClassOrInterfaceDeclaration cls, String relativePath, List<Finding> findings) {
        boolean isEntity =
                cls.getAnnotations().stream()
                        .anyMatch(a -> "Entity".equals(simpleName(a.getNameAsString())));
        if (!isEntity || !cls.isFinal()) {
            return;
        }
        Integer line = cls.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString();
        findings.add(
                FindingFactory.builder(FindingRules.SPRING_JPA_FINAL_ENTITY, FindingConfidence.HIGH)
                        .shortMessage(
                                "final @Entity "
                                        + target
                                        + " cannot be proxied — lazy references to it load"
                                        + " eagerly.")
                        .whyBadPractice(
                                "Hibernate implements lazy loading by subclassing the entity to"
                                    + " create a proxy. A final class cannot be subclassed, so lazy"
                                    + " @ManyToOne/@OneToOne references to this entity and"
                                    + " getReferenceById(...) silently fall back to eager loading"
                                    + " (Hibernate logs HHH000305 at startup).")
                        .possibleImpact(
                                "Associations that look lazy in the mapping load eagerly, issuing"
                                        + " extra queries on every parent load — a hidden N+1"
                                        + " source.")
                        .recommendation(
                                "Remove the final modifier from the entity class. Hibernate needs"
                                        + " to subclass it for proxying; use other means (private"
                                        + " constructors, documentation) to discourage extension.")
                        .evidence(
                                "final class "
                                        + target
                                        + " annotated @Entity found in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_ENTITY_MISSING_ID
    // ---------------------------------------------------------------------------

    private static final Set<String> ID_ANNOTATIONS = Set.of("Id", "EmbeddedId");

    private void detectEntityMissingId(
            ClassOrInterfaceDeclaration cls, String relativePath, List<Finding> findings) {
        boolean hasEntity =
                cls.getAnnotations().stream()
                        .anyMatch(a -> "Entity".equals(simpleName(a.getNameAsString())));
        if (!hasEntity) {
            return;
        }
        // An @IdClass on the type, or a superclass (possibly @MappedSuperclass), may supply the id.
        boolean hasIdClass =
                cls.getAnnotations().stream()
                        .anyMatch(a -> "IdClass".equals(simpleName(a.getNameAsString())));
        if (hasIdClass || !cls.getExtendedTypes().isEmpty()) {
            return;
        }
        boolean hasIdOnField =
                cls.getFields().stream()
                        .flatMap(f -> f.getAnnotations().stream())
                        .anyMatch(a -> ID_ANNOTATIONS.contains(simpleName(a.getNameAsString())));
        boolean hasIdOnMethod =
                cls.getMethods().stream()
                        .flatMap(m -> m.getAnnotations().stream())
                        .anyMatch(a -> ID_ANNOTATIONS.contains(simpleName(a.getNameAsString())));
        if (hasIdOnField || hasIdOnMethod) {
            return;
        }
        Integer line = cls.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_ENTITY_MISSING_ID, FindingConfidence.MEDIUM)
                        .shortMessage(
                                "@Entity "
                                        + target
                                        + " in "
                                        + relativePath
                                        + " declares no @Id — Hibernate mapping fails at startup.")
                        .whyBadPractice(
                                "Every JPA entity needs a persistent identity. Without @Id,"
                                        + " @EmbeddedId, or @IdClass, Hibernate cannot build the"
                                        + " persister for the entity and throws"
                                        + " '"
                                        + target
                                        + " has no identifier' while building the"
                                        + " EntityManagerFactory.")
                        .possibleImpact(
                                "The application context fails to start: the bean factory cannot"
                                        + " initialise the JPA EntityManagerFactory, so the whole"
                                        + " service is down.")
                        .recommendation(
                                "Add an identifier: a field annotated @Id (optionally with"
                                    + " @GeneratedValue), an @EmbeddedId for a composite key, or"
                                    + " @IdClass on the type. If identity is inherited, extend a"
                                    + " @MappedSuperclass that declares the @Id.")
                        .limitations(
                                "Medium confidence — the analyzer only sees this class. An @Id"
                                    + " provided by an interface default or a superclass it cannot"
                                    + " resolve would be a false positive (classes that extend a"
                                    + " parent are already skipped).")
                        .evidence(
                                "@Entity "
                                        + target
                                        + " with no @Id/@EmbeddedId/@IdClass found in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_RESTTEMPLATE_NEW_PER_REQUEST
    // ---------------------------------------------------------------------------

    private void detectRestTemplateNewPerRequest(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        // new RestTemplate(factory) created inside a regular method body. The no-arg
        // constructor is already covered by SPRING_REST_TEMPLATE_NO_TIMEOUT, so only the
        // arg-bearing form (which may have a timeout but is still recreated per call) is flagged.
        for (ObjectCreationExpr creation : cu.findAll(ObjectCreationExpr.class)) {
            if (!"RestTemplate".equals(simpleName(creation.getType().getNameAsString()))) {
                continue;
            }
            if (creation.getArguments().isEmpty()) {
                continue;
            }
            if (!isPerRequestInstantiation(creation)) {
                continue;
            }
            reportPerRequestClient(
                    relativePath,
                    creation.getBegin().map(p -> p.line).orElse(null),
                    "new RestTemplate(...)",
                    findings);
        }
        // RestClient.create(...) inside a regular method body.
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            boolean isRestClientCreate =
                    "create".equals(call.getNameAsString())
                            && call.getScope()
                                    .map(s -> "RestClient".equals(simpleName(s.toString())))
                                    .orElse(false);
            if (!isRestClientCreate || !isPerRequestInstantiation(call)) {
                continue;
            }
            reportPerRequestClient(
                    relativePath,
                    call.getBegin().map(p -> p.line).orElse(null),
                    "RestClient.create(...)",
                    findings);
        }
    }

    /**
     * True when {@code node} sits inside a method body (not a field initializer) of a
     * Spring-managed component, and that method is not a {@code @Bean} factory method. This is the
     * "created fresh on every call" shape, as opposed to a reused singleton bean.
     */
    private boolean isPerRequestInstantiation(Node node) {
        MethodDeclaration method = node.findAncestor(MethodDeclaration.class).orElse(null);
        if (method == null) {
            return false;
        }
        boolean isBeanMethod =
                method.getAnnotations().stream()
                        .anyMatch(a -> "Bean".equals(simpleName(a.getNameAsString())));
        if (isBeanMethod) {
            return false;
        }
        ClassOrInterfaceDeclaration cls =
                node.findAncestor(ClassOrInterfaceDeclaration.class).orElse(null);
        return cls != null
                && cls.getAnnotations().stream()
                        .anyMatch(
                                a ->
                                        SINGLETON_ANNOTATIONS.contains(
                                                simpleName(a.getNameAsString())));
    }

    private void reportPerRequestClient(
            String relativePath, Integer line, String shape, List<Finding> findings) {
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_RESTTEMPLATE_NEW_PER_REQUEST,
                                FindingConfidence.MEDIUM)
                        .shortMessage(
                                shape
                                        + " is created inside a method in "
                                        + relativePath
                                        + " — a new HTTP client per call.")
                        .whyBadPractice(
                                "Instantiating an HTTP client inside a request-handling method"
                                    + " builds a fresh client — and its underlying connection pool"
                                    + " and TLS context — on every invocation. None of that is"
                                    + " reused across calls, and the auto-configured Micrometer"
                                    + " metrics and tracing instrumentation are bypassed.")
                        .possibleImpact(
                                "Per-call connection setup adds latency, leaks sockets under load,"
                                        + " and defeats connection keep-alive. Throughput collapses"
                                        + " when the endpoint is hot.")
                        .recommendation(
                                "Create the client once as a singleton bean (or inject the"
                                    + " auto-configured RestTemplateBuilder / RestClient.Builder)"
                                    + " and reuse it. Configure timeouts and connection pooling on"
                                    + " that single instance.")
                        .limitations(
                                "Medium confidence — flagged because the client is built inside a"
                                        + " non-@Bean method of a Spring component. A short-lived"
                                        + " client intentionally scoped to one operation may be"
                                        + " acceptable.")
                        .evidence(
                                shape + " inside a component method found in " + relativePath + ".")
                        .source(relativePath, line)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_JPA_QUERY_NO_PAGINATION
    // ---------------------------------------------------------------------------

    private static final Set<String> COLLECTION_RETURN_TYPES =
            Set.of("List", "Collection", "Set", "Iterable");

    private void detectJpaQueryNoPagination(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
            boolean hasQuery =
                    method.getAnnotations().stream()
                            .anyMatch(a -> "Query".equals(simpleName(a.getNameAsString())));
            if (!hasQuery) {
                continue;
            }
            if (!method.getType().isClassOrInterfaceType()) {
                continue;
            }
            String returnType = method.getType().asClassOrInterfaceType().getNameAsString();
            if (!COLLECTION_RETURN_TYPES.contains(returnType)) {
                continue;
            }
            boolean hasPageable =
                    method.getParameters().stream()
                            .map(Parameter::getType)
                            .anyMatch(t -> "Pageable".equals(simpleName(t.asString())));
            if (hasPageable) {
                continue;
            }
            Integer line = method.getBegin().map(p -> p.line).orElse(null);
            String target = method.getNameAsString();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_JPA_QUERY_NO_PAGINATION,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "@Query method "
                                            + target
                                            + " in "
                                            + relativePath
                                            + " returns "
                                            + returnType
                                            + " with no Pageable — the query has no LIMIT.")
                            .whyBadPractice(
                                    "A @Query that returns a collection and takes no Pageable runs"
                                        + " without a LIMIT clause. Every matching row is fetched"
                                        + " and materialised into the heap, regardless of how large"
                                        + " the result set grows over time.")
                            .possibleImpact(
                                    "As the underlying data grows, the query causes rising memory"
                                        + " use, long GC pauses, and eventually OutOfMemoryError —"
                                        + " problems that only surface once production data is"
                                        + " large.")
                            .recommendation(
                                    "Add a Pageable parameter and return Page<T> or Slice<T>, or"
                                        + " constrain the query with an explicit WHERE/LIMIT."
                                        + " Reserve unbounded collection queries for small bounded"
                                        + " reference data.")
                            .limitations(
                                    "Medium confidence — some queries are intentionally bounded by"
                                        + " their WHERE clause to a small result set, in which case"
                                        + " pagination is unnecessary.")
                            .evidence(
                                    "@Query method "
                                            + target
                                            + " returning "
                                            + returnType
                                            + " without a Pageable parameter found in "
                                            + relativePath
                                            + ".")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_REQUIRES_NEW_IN_LOOP
    // ---------------------------------------------------------------------------

    private void detectRequiresNewInLoop(
            CompilationUnit cu,
            String relativePath,
            Set<String> requiresNewMethods,
            List<Finding> findings) {
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!requiresNewMethods.contains(call.getNameAsString())) {
                continue;
            }
            boolean inLoop =
                    call.findAncestor(ForStmt.class).isPresent()
                            || call.findAncestor(ForEachStmt.class).isPresent()
                            || call.findAncestor(WhileStmt.class).isPresent()
                            || call.findAncestor(DoStmt.class).isPresent();
            if (!inLoop) {
                continue;
            }
            Integer line = call.getBegin().map(p -> p.line).orElse(null);
            String target = call.getNameAsString();
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_REQUIRES_NEW_IN_LOOP, FindingConfidence.LOW)
                            .shortMessage(
                                    target
                                            + "(...) is annotated @Transactional(REQUIRES_NEW) and"
                                            + " is called inside a loop in "
                                            + relativePath
                                            + ".")
                            .whyBadPractice(
                                    "Propagation.REQUIRES_NEW suspends the current transaction and"
                                        + " starts a fresh one for the call, which borrows a second"
                                        + " connection from the pool while the outer transaction"
                                        + " still holds its own. Doing this once per loop iteration"
                                        + " multiplies connection pressure by the iteration count.")
                            .possibleImpact(
                                    "Large loops can exhaust the connection pool and deadlock"
                                            + " (every thread holds one connection and waits for a"
                                            + " second), or simply run far slower than a single"
                                            + " transaction would.")
                            .recommendation(
                                    "Move the loop inside a single transaction, or batch the work"
                                        + " so a new transaction is not opened per element. Reserve"
                                        + " REQUIRES_NEW for the few cases that genuinely need an"
                                        + " independent commit, and call them outside hot loops.")
                            .limitations(
                                    "Low confidence — the match is by method name across the"
                                            + " scanned sources, so an unrelated method sharing the"
                                            + " name could be flagged. Confirm the callee is the"
                                            + " REQUIRES_NEW method.")
                            .evidence(
                                    "Call to REQUIRES_NEW method "
                                            + target
                                            + "(...) found inside a loop in "
                                            + relativePath
                                            + ".")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private static String simpleName(String name) {
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : name;
    }
}

package com.robbanhoglund.springbootanalyzer.analyzer;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ThisExpr;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.stereotype.Component;

/**
 * Detects caching anti-patterns in {@code src/main/java} source files.
 *
 * <p>Rules covered:
 *
 * <ul>
 *   <li>{@link FindingRules#SPRING_CACHEABLE_VOID_RETURN} — {@code @Cacheable} on a void method.
 *   <li>{@link FindingRules#SPRING_CACHEABLE_MUTABLE_RETURN_TYPE} — {@code @Cacheable} /
 *       {@code @CachePut} returns a mutable collection type that callers can corrupt.
 *   <li>{@link FindingRules#SPRING_CACHE_ON_PRIVATE_METHOD} — cache annotation on a private
 *       method that Spring's proxy cannot intercept.
 *   <li>{@link FindingRules#SPRING_CACHE_SELF_INVOCATION} — cache-annotated method called via
 *       self-invocation, bypassing the proxy.
 *   <li>{@link FindingRules#SPRING_CACHE_EVICT_WITHOUT_ALL_ENTRIES} — {@code @CacheEvict} on a
 *       no-arg method without {@code allEntries = true}.
 *   <li>{@link FindingRules#SPRING_CACHEABLE_SYNC_INCOMPATIBLE} — {@code @Cacheable(sync = true)}
 *       combined with {@code unless} or multiple cache names, both of which are unsupported and
 *       cause an {@code IllegalStateException} at runtime.
 * </ul>
 */
@Component
public class CachingPracticeFindingAnalyzer {

    private static final Set<String> CACHE_WRITE_ANNOTATIONS = Set.of("Cacheable", "CachePut");
    private static final Set<String> ALL_CACHE_ANNOTATIONS =
            Set.of("Cacheable", "CachePut", "CacheEvict", "Caching");

    /**
     * Mutable collection types whose instances can be corrupted if returned from a cached method.
     * Immutable variants (e.g. returned by {@code List.of()}) are not in this set because the
     * declared return type cannot be narrowed to {@code ImmutableList} etc. in a way the AST
     * exposes at the method signature level.
     */
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
                    "TreeSet",
                    "Collection",
                    "Deque",
                    "ArrayDeque",
                    "Queue",
                    "PriorityQueue");

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
        boolean cacheableFound = false;
        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            if (file.compilationUnit() != null) {
                analyzeSourceFile(file.compilationUnit(), file.relativePath(), findings);
            }
            if (!cacheableFound && file.content().contains("@Cacheable")) {
                cacheableFound = true;
            }
        }
        if (cacheableFound) {
            detectCacheableNoTtlProvider(sources, findings);
        }
        return findings;
    }

    // ---------------------------------------------------------------------------
    // Per-file analysis
    // ---------------------------------------------------------------------------

    private void analyzeSourceFile(
            CompilationUnit cu, String relativePath, List<Finding> findings) {
        for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            analyzeClass(cls, relativePath, findings);
        }
    }

    private void analyzeClass(
            ClassOrInterfaceDeclaration cls, String relativePath, List<Finding> findings) {
        // Collect all cache-annotated method names for self-invocation detection
        Set<String> cachedMethodNames =
                cls.getMethods().stream()
                        .filter(m -> hasCacheAnnotation(m, ALL_CACHE_ANNOTATIONS))
                        .map(MethodDeclaration::getNameAsString)
                        .collect(Collectors.toSet());

        for (MethodDeclaration method : cls.getMethods()) {
            detectCacheableVoidReturn(cls, method, relativePath, findings);
            detectCacheableMutableReturnType(cls, method, relativePath, findings);
            detectCacheOnPrivateMethod(cls, method, relativePath, findings);
            detectCacheEvictWithoutAllEntries(cls, method, relativePath, findings);
            detectCacheSelfInvocation(cls, method, cachedMethodNames, relativePath, findings);
            detectCacheableSyncIncompatible(cls, method, relativePath, findings);
            detectCachePutAndCacheableSameMethod(cls, method, relativePath, findings);
        }

        detectCacheableNoEviction(cls, relativePath, findings);
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_CACHEABLE_VOID_RETURN
    // ---------------------------------------------------------------------------

    private void detectCacheableVoidReturn(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        if (!hasCacheAnnotation(method, CACHE_WRITE_ANNOTATIONS)) {
            return;
        }
        if (!method.getType().isVoidType()) {
            return;
        }
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_CACHEABLE_VOID_RETURN, FindingConfidence.HIGH)
                        .shortMessage(
                                "@Cacheable on void method "
                                        + target
                                        + " — nothing to cache; annotation is ineffective.")
                        .whyBadPractice(
                                "@Cacheable works by intercepting the method call and storing its"
                                    + " return value. A void method returns nothing, so the"
                                    + " annotation either caches null (and returns null to callers"
                                    + " on subsequent hits, breaking the method contract) or throws"
                                    + " an exception at runtime depending on the CacheManager.")
                        .possibleImpact(
                                "Runtime NullPointerException or unexpected null returns on cached"
                                    + " calls; the method's side effects execute only once instead"
                                    + " of on every invocation.")
                        .recommendation(
                                "Remove @Cacheable from the void method. If the goal is to cache a"
                                    + " side-effect-free computation, change the method to return"
                                    + " the computed value and annotate that.")
                        .evidence(
                                "Method "
                                        + target
                                        + " has return type void and is annotated with @Cacheable"
                                        + " in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_CACHEABLE_MUTABLE_RETURN_TYPE
    // ---------------------------------------------------------------------------

    private void detectCacheableMutableReturnType(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        if (!hasCacheAnnotation(method, CACHE_WRITE_ANNOTATIONS)) {
            return;
        }
        String rawType = rawTypeName(method.getType().asString());
        if (!MUTABLE_COLLECTION_TYPES.contains(rawType)) {
            return;
        }
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_CACHEABLE_MUTABLE_RETURN_TYPE,
                                FindingConfidence.MEDIUM)
                        .shortMessage(
                                "@Cacheable method "
                                        + target
                                        + " returns a mutable "
                                        + rawType
                                        + " — callers can corrupt the cached instance.")
                        .whyBadPractice(
                                "Spring caches the exact object reference returned by the method."
                                    + " If a caller mutates the returned collection (add, remove,"
                                    + " clear), those changes are reflected in the cached value."
                                    + " Subsequent cache hits will return the mutated, corrupted"
                                    + " data.")
                        .possibleImpact(
                                "Silent data corruption in the cache; intermittent bugs that are"
                                        + " hard to reproduce because they depend on call order.")
                        .recommendation(
                                "Return an unmodifiable view: List.copyOf(...), Map.copyOf(...),"
                                    + " Collections.unmodifiableList(...), or an immutable record."
                                    + " Alternatively, use a deep-copy strategy if the elements"
                                    + " themselves are mutable.")
                        .evidence(
                                "Method "
                                        + target
                                        + " is annotated with @Cacheable and declares return type "
                                        + method.getType().asString()
                                        + " in "
                                        + relativePath
                                        + ".")
                        .limitations(
                                "The declared return type may be mutable but the implementation"
                                        + " may return an immutable instance (e.g. List.of()). The"
                                        + " risk is still real if a future change returns a mutable"
                                        + " list.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_CACHE_ON_PRIVATE_METHOD
    // ---------------------------------------------------------------------------

    private void detectCacheOnPrivateMethod(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        if (!method.isPrivate()) {
            return;
        }
        if (!hasCacheAnnotation(method, ALL_CACHE_ANNOTATIONS)) {
            return;
        }
        String cacheAnn = firstCacheAnnotationName(method, ALL_CACHE_ANNOTATIONS);
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_CACHE_ON_PRIVATE_METHOD, FindingConfidence.HIGH)
                        .shortMessage(
                                "@"
                                        + cacheAnn
                                        + " on private method "
                                        + target
                                        + " — Spring's proxy cannot intercept private methods.")
                        .whyBadPractice(
                                "Spring applies caching through a proxy (JDK dynamic proxy or"
                                    + " CGLIB) that wraps the bean. Proxies can only intercept"
                                    + " calls made through the proxy reference, and they cannot"
                                    + " override private methods. The cache annotation is silently"
                                    + " ignored.")
                        .possibleImpact(
                                "The method is called on every invocation without any caching,"
                                        + " potentially causing performance problems or unexpected"
                                        + " behaviour the developer assumed was being cached.")
                        .recommendation(
                                "Change the method visibility to package-private, protected, or"
                                        + " public. If the method must remain private, extract the"
                                        + " caching to a public wrapper method or use AspectJ"
                                        + " compile-time weaving instead of proxy-based AOP.")
                        .limitations(
                                "If the project uses AspectJ weaving instead of Spring proxies,"
                                        + " private methods can be intercepted.")
                        .evidence(
                                "@"
                                        + cacheAnn
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
    // Rule: SPRING_CACHE_SELF_INVOCATION
    // ---------------------------------------------------------------------------

    private void detectCacheSelfInvocation(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            Set<String> cachedMethodNames,
            String relativePath,
            List<Finding> findings) {
        if (cachedMethodNames.isEmpty()) {
            return;
        }
        // Don't flag a cache-annotated method calling itself (already covered by the name set)
        // but do flag non-annotated methods or other annotated methods calling cached methods
        method.findAll(MethodCallExpr.class)
                .forEach(
                        call -> {
                            if (!cachedMethodNames.contains(call.getNameAsString())) {
                                return;
                            }
                            // Only flag calls without an external receiver:
                            // - no scope (implicit this)
                            // - explicit this scope
                            var scope = call.getScope().orElse(null);
                            boolean isSelfCall = scope == null || scope instanceof ThisExpr;
                            if (!isSelfCall) {
                                return;
                            }
                            // Don't emit on the method's own recursive self-call
                            if (method.getNameAsString().equals(call.getNameAsString())) {
                                return;
                            }
                            Integer line = call.getBegin().map(p -> p.line).orElse(null);
                            String callerTarget =
                                    cls.getNameAsString() + "#" + method.getNameAsString();
                            findings.add(
                                    FindingFactory.builder(
                                                    FindingRules.SPRING_CACHE_SELF_INVOCATION,
                                                    FindingConfidence.MEDIUM)
                                            .shortMessage(
                                                    "Cache-annotated method '"
                                                            + call.getNameAsString()
                                                            + "' called via self-invocation in "
                                                            + callerTarget
                                                            + " — caching will be bypassed.")
                                            .whyBadPractice(
                                                    "Spring applies caching through a proxy wrapper"
                                                        + " around the bean. When a method in the"
                                                        + " same class calls another method"
                                                        + " directly, the call bypasses the proxy"
                                                        + " and the cache annotation is not"
                                                        + " intercepted.")
                                            .possibleImpact(
                                                    "The cached method always executes its full"
                                                        + " body on every internal call, defeating"
                                                        + " the purpose of the cache and causing"
                                                        + " performance issues.")
                                            .recommendation(
                                                    "Inject the bean into itself (self-injection"
                                                        + " via @Autowired or ApplicationContext)"
                                                        + " and call the method through the"
                                                        + " injected reference, or extract the"
                                                        + " cached method into a separate"
                                                        + " Spring-managed bean.")
                                            .evidence(
                                                    "Method "
                                                            + method.getNameAsString()
                                                            + " calls cache-annotated method "
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
    // Rule: SPRING_CACHE_EVICT_WITHOUT_ALL_ENTRIES
    // ---------------------------------------------------------------------------

    private void detectCacheEvictWithoutAllEntries(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        Optional<AnnotationExpr> evictAnn =
                method.getAnnotations().stream()
                        .filter(a -> "CacheEvict".equals(simpleName(a.getNameAsString())))
                        .findFirst();
        if (evictAnn.isEmpty()) {
            return;
        }
        // Only flag no-parameter methods (where allEntries=true is almost certainly the intent)
        if (!method.getParameters().isEmpty()) {
            return;
        }
        // Check if allEntries = true is explicitly set
        boolean allEntriesTrue = false;
        AnnotationExpr ann = evictAnn.get();
        if (ann.isNormalAnnotationExpr()) {
            for (MemberValuePair pair : ann.asNormalAnnotationExpr().getPairs()) {
                if ("allEntries".equals(pair.getNameAsString())) {
                    allEntriesTrue = "true".equals(pair.getValue().toString());
                    break;
                }
            }
        }
        if (allEntriesTrue) {
            return;
        }

        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_CACHE_EVICT_WITHOUT_ALL_ENTRIES,
                                FindingConfidence.MEDIUM)
                        .shortMessage(
                                "@CacheEvict on no-arg method "
                                        + target
                                        + " without allEntries=true — may not clear the cache as"
                                        + " intended.")
                        .whyBadPractice(
                                "Without parameters, Spring uses SimpleKey.EMPTY as the eviction"
                                        + " key. This only removes the single entry that was stored"
                                        + " with an empty-key @Cacheable call. If the intent is to"
                                        + " invalidate all entries (e.g. after an admin action or"
                                        + " scheduled refresh), the cache will not be cleared.")
                        .possibleImpact(
                                "Stale cache entries that were expected to be evicted remain in"
                                        + " the cache, causing users to see outdated data.")
                        .recommendation(
                                "Add allEntries = true to @CacheEvict if the intent is to clear all"
                                    + " entries. If you only want to evict a specific entry, add"
                                    + " the cache key as a method parameter.")
                        .evidence(
                                "@CacheEvict found on no-arg method "
                                        + method.getNameAsString()
                                        + " without allEntries=true in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_CACHEABLE_SYNC_INCOMPATIBLE
    // ---------------------------------------------------------------------------

    /**
     * Flags {@code @Cacheable(sync = true)} when combined with an {@code unless} expression or
     * more than one cache name. Spring's {@code CacheAspectSupport} validates these at the first
     * method invocation and throws {@code IllegalStateException}; neither combination is
     * supported.
     *
     * <p>Detection strategy:
     *
     * <ul>
     *   <li>Locate {@code @Cacheable} annotations that contain {@code sync = true}.
     *   <li>Check whether the same annotation also sets {@code unless} to a non-empty string.
     *   <li>Check whether {@code value} / {@code cacheNames} resolves to more than one string
     *       literal — array initialiser with ≥ 2 elements is the detectable form.
     * </ul>
     */
    private void detectCacheableSyncIncompatible(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        for (AnnotationExpr ann : method.getAnnotations()) {
            if (!"Cacheable".equals(simpleName(ann.getNameAsString()))) {
                continue;
            }
            if (!ann.isNormalAnnotationExpr()) {
                continue;
            }

            var pairs = ann.asNormalAnnotationExpr().getPairs();

            // Check sync = true
            boolean syncTrue =
                    pairs.stream()
                            .filter(p -> "sync".equals(p.getNameAsString()))
                            .anyMatch(p -> "true".equals(p.getValue().toString()));
            if (!syncTrue) {
                continue;
            }

            // Check for unless attribute (any non-empty value)
            Optional<MemberValuePair> unlessPair =
                    pairs.stream().filter(p -> "unless".equals(p.getNameAsString())).findFirst();

            boolean hasUnless =
                    unlessPair.isPresent()
                            && !unlessPair
                                    .get()
                                    .getValue()
                                    .toString()
                                    .replaceAll("\"", "")
                                    .isBlank();

            // Check for multiple cache names (value or cacheNames as array with ≥ 2 entries)
            boolean hasMultipleCaches =
                    pairs.stream()
                            .filter(
                                    p ->
                                            "value".equals(p.getNameAsString())
                                                    || "cacheNames".equals(p.getNameAsString()))
                            .anyMatch(
                                    p ->
                                            p.getValue().isArrayInitializerExpr()
                                                    && p.getValue()
                                                                    .asArrayInitializerExpr()
                                                                    .getValues()
                                                                    .size()
                                                            >= 2);

            if (!hasUnless && !hasMultipleCaches) {
                continue;
            }

            Integer line = method.getBegin().map(p -> p.line).orElse(null);
            String target = cls.getNameAsString() + "#" + method.getNameAsString();

            List<String> problems = new ArrayList<>();
            if (hasUnless) problems.add("'unless' attribute");
            if (hasMultipleCaches) problems.add("multiple cache names");

            String problemList = String.join(" and ", problems);
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_CACHEABLE_SYNC_INCOMPATIBLE,
                                    FindingConfidence.HIGH)
                            .shortMessage(
                                    "@Cacheable(sync = true) on "
                                            + target
                                            + " is combined with "
                                            + problemList
                                            + " — Spring will throw IllegalStateException at"
                                            + " runtime.")
                            .whyBadPractice(
                                    "Spring's CacheAspectSupport explicitly rejects @Cacheable(sync"
                                        + " = true) when paired with the 'unless' attribute or"
                                        + " multiple cache names. Synchronized caching uses a"
                                        + " single lock per cache entry; the 'unless' expression is"
                                        + " evaluated after the method returns (making it"
                                        + " incompatible with the lock semantics), and coordinating"
                                        + " a lock across multiple caches is not supported.")
                            .possibleImpact(
                                    "IllegalStateException thrown on the first invocation of the"
                                            + " method, causing a 500 error or application startup"
                                            + " failure.")
                            .recommendation(
                                    hasUnless
                                            ? "Remove the 'unless' attribute when using sync ="
                                                    + " true. If conditional caching is required,"
                                                    + " handle it inside the method body instead."
                                            : "Use a single cache name when sync = true. Distribute"
                                                    + " across multiple caches without sync if"
                                                    + " necessary.")
                            .evidence(
                                    "@Cacheable(sync = true) on "
                                            + method.getNameAsString()
                                            + " also specifies "
                                            + problemList
                                            + " in "
                                            + relativePath
                                            + ".")
                            .source(relativePath, line)
                            .target(target)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_CACHEPUT_AND_CACHEABLE_SAME_METHOD
    // ---------------------------------------------------------------------------

    private void detectCachePutAndCacheableSameMethod(
            ClassOrInterfaceDeclaration cls,
            MethodDeclaration method,
            String relativePath,
            List<Finding> findings) {
        boolean hasCacheable = hasCacheAnnotation(method, Set.of("Cacheable"));
        boolean hasCachePut = hasCacheAnnotation(method, Set.of("CachePut"));
        if (!hasCacheable || !hasCachePut) {
            return;
        }
        Integer line = method.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString() + "#" + method.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_CACHEPUT_AND_CACHEABLE_SAME_METHOD,
                                FindingConfidence.HIGH)
                        .shortMessage(
                                "Method "
                                        + target
                                        + " has both @CachePut and @Cacheable — the cache never"
                                        + " serves a hit, silently defeating @Cacheable.")
                        .whyBadPractice(
                                "@Cacheable reads from the cache and only executes the method on a"
                                    + " miss. @CachePut always executes the method and updates the"
                                    + " cache. When both are present, Spring's CacheAspectSupport"
                                    + " resolves the conflict by always invoking the method (the"
                                    + " @CachePut wins), so the @Cacheable never short-circuits."
                                    + " Spring's own documentation strongly discourages the"
                                    + " combination.")
                        .possibleImpact(
                                "The method body executes on every call while both annotations"
                                        + " appear active — the intended caching is silently"
                                        + " negated, masking the performance problem it was meant"
                                        + " to solve.")
                        .recommendation(
                                "Use only one of @Cacheable or @CachePut on a given method. If the"
                                        + " intent is to always update the cache and also return a"
                                        + " cached value, use @CachePut only. If the intent is to"
                                        + " populate the cache on miss, use @Cacheable only.")
                        .evidence(
                                "Method "
                                        + target
                                        + " has both @Cacheable and @CachePut annotations in "
                                        + relativePath
                                        + ".")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_CACHEABLE_NO_EVICTION
    // ---------------------------------------------------------------------------

    private static final Set<String> WRITE_METHOD_PREFIXES =
            Set.of(
                    "save", "update", "delete", "remove", "create", "add", "insert", "put", "set",
                    "persist", "modify", "patch", "merge", "clear", "reset", "evict");

    private void detectCacheableNoEviction(
            ClassOrInterfaceDeclaration cls, String relativePath, List<Finding> findings) {
        boolean hasCacheable =
                cls.getMethods().stream().anyMatch(m -> hasCacheAnnotation(m, Set.of("Cacheable")));
        if (!hasCacheable) {
            return;
        }
        boolean hasEviction =
                cls.getMethods().stream()
                        .anyMatch(
                                m ->
                                        hasCacheAnnotation(
                                                m, Set.of("CacheEvict", "CachePut", "Caching")));
        if (hasEviction) {
            return;
        }
        // Only flag if the class also contains methods with write-like names,
        // indicating it manages both reads and writes without eviction.
        boolean hasWriteMethods =
                cls.getMethods().stream()
                        .map(m -> m.getNameAsString().toLowerCase(java.util.Locale.ROOT))
                        .anyMatch(
                                name -> WRITE_METHOD_PREFIXES.stream().anyMatch(name::startsWith));
        if (!hasWriteMethods) {
            return;
        }
        Integer line = cls.getBegin().map(p -> p.line).orElse(null);
        String target = cls.getNameAsString();
        findings.add(
                FindingFactory.builder(
                                FindingRules.SPRING_CACHEABLE_NO_EVICTION, FindingConfidence.LOW)
                        .shortMessage(
                                cls.getNameAsString()
                                        + " has @Cacheable read methods but no @CacheEvict or"
                                        + " @CachePut — cache entries may become stale.")
                        .whyBadPractice(
                                "@Cacheable caches the result of a read method. If the same class"
                                    + " also contains write methods (save, update, delete, …) that"
                                    + " modify the underlying data, those changes will not"
                                    + " automatically invalidate the cached entries. Clients will"
                                    + " see stale data until the cache expires or the application"
                                    + " restarts.")
                        .possibleImpact(
                                "Stale data served to clients after updates. The window of"
                                        + " inconsistency grows larger the longer the TTL or the"
                                        + " absence of an eviction policy.")
                        .recommendation(
                                "Add @CacheEvict (or @CachePut) to all write methods that modify"
                                    + " the data returned by @Cacheable reads. Use"
                                    + " @CacheEvict(allEntries = true) for bulk operations where"
                                    + " individual key eviction is impractical.")
                        .evidence(
                                "Class "
                                        + cls.getNameAsString()
                                        + " in "
                                        + relativePath
                                        + " has @Cacheable but no cache eviction annotations.")
                        .limitations(
                                "Eviction may happen in a separate class (e.g. a service delegates"
                                    + " to this repository and handles eviction there). Review the"
                                    + " full call graph before acting on this finding.")
                        .source(relativePath, line)
                        .target(target)
                        .build());
    }

    // ---------------------------------------------------------------------------
    // Rule: SPRING_CACHEABLE_NO_TTL_PROVIDER
    // ---------------------------------------------------------------------------

    private static final Set<String> TTL_PROVIDER_INDICATORS =
            Set.of(
                    "spring.cache.type=caffeine",
                    "spring.cache.type=redis",
                    "spring.cache.type=jcache",
                    "spring.cache.type=hazelcast",
                    "spring.cache.caffeine",
                    "spring.cache.redis",
                    "spring.cache.jcache",
                    "spring.jcache",
                    "CaffeineCacheManager",
                    "RedisCacheManager",
                    "JCacheCacheManager",
                    "HazelcastCacheManager",
                    "caffeine",
                    "com.github.ben-manes.caffeine");

    private void detectCacheableNoTtlProvider(JavaSources sources, List<Finding> findings) {
        // Scan config files for TTL-capable provider indicators
        boolean providerConfigured = false;
        Path resourceRoot = sources.repositoryRoot().resolve("src/main/resources");
        if (Files.exists(resourceRoot)) {
            try (Stream<java.nio.file.Path> files = Files.walk(resourceRoot)) {
                for (java.nio.file.Path file :
                        files.filter(Files::isRegularFile)
                                .filter(
                                        p -> {
                                            String name = p.getFileName().toString();
                                            return name.endsWith(".properties")
                                                    || name.endsWith(".yml")
                                                    || name.endsWith(".yaml");
                                        })
                                .toList()) {
                    try {
                        String content =
                                java.nio.file.Files.readString(
                                        file, java.nio.charset.StandardCharsets.UTF_8);
                        for (String indicator : TTL_PROVIDER_INDICATORS) {
                            if (content.contains(indicator)) {
                                providerConfigured = true;
                                break;
                            }
                        }
                    } catch (IOException ignored) {
                        // skip unreadable files
                    }
                    if (providerConfigured) {
                        break;
                    }
                }
            } catch (IOException ignored) {
                // best-effort
            }
        }
        // Also scan Java source for CacheManager bean declarations
        if (!providerConfigured) {
            for (JavaSources.JavaFile file : sources.primaryFiles()) {
                for (String indicator : TTL_PROVIDER_INDICATORS) {
                    if (file.content().contains(indicator)) {
                        providerConfigured = true;
                        break;
                    }
                }
                if (providerConfigured) {
                    break;
                }
            }
        }
        if (!providerConfigured) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_CACHEABLE_NO_TTL_PROVIDER,
                                    FindingConfidence.LOW)
                            .shortMessage(
                                    "@Cacheable is used but no TTL-capable cache provider"
                                        + " (Caffeine, Redis, JCache) appears to be configured.")
                            .whyBadPractice(
                                    "Without a configured cache provider, Spring Boot falls back to"
                                        + " a simple ConcurrentHashMap-backed cache. This"
                                        + " implementation has no time-to-live (TTL) or"
                                        + " time-to-idle (TTI) policy, so cached entries never"
                                        + " expire automatically. Memory usage grows without bound"
                                        + " as the cache fills up, and stale data is served"
                                        + " indefinitely.")
                            .possibleImpact(
                                    "Unbounded heap growth leading to OutOfMemoryError under"
                                            + " sustained load. Stale data served to users with no"
                                            + " automatic refresh until the application restarts.")
                            .recommendation(
                                    "Add a TTL-capable cache provider. For local in-process"
                                        + " caching, add the Caffeine dependency and set"
                                        + " spring.cache.type=caffeine and"
                                        + " spring.cache.caffeine.spec=maximumSize=500,expireAfterWrite=10m."
                                        + " For distributed caching, use Redis with"
                                        + " spring.cache.type=redis and configure TTL via"
                                        + " spring.cache.redis.time-to-live.")
                            .evidence(
                                    "@Cacheable annotation found in project sources but no"
                                            + " Caffeine, Redis, or JCache provider configuration"
                                            + " detected in src/main/resources or src/main/java.")
                            .limitations(
                                    "Cache provider configuration might be in an external config"
                                            + " server, environment variables, or a non-standard"
                                            + " location not visible to static analysis.")
                            .source(null, null)
                            .target(null)
                            .build());
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private static boolean hasCacheAnnotation(MethodDeclaration method, Set<String> names) {
        return method.getAnnotations().stream()
                .anyMatch(a -> names.contains(simpleName(a.getNameAsString())));
    }

    private static String firstCacheAnnotationName(MethodDeclaration method, Set<String> names) {
        return method.getAnnotations().stream()
                .map(a -> simpleName(a.getNameAsString()))
                .filter(names::contains)
                .findFirst()
                .orElse("Cache");
    }

    /** Strips generic type parameters: {@code List<String>} → {@code List}. */
    private static String rawTypeName(String type) {
        int lt = type.indexOf('<');
        return lt >= 0 ? type.substring(0, lt).trim() : type.trim();
    }

    private static String simpleName(String name) {
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : name;
    }
}

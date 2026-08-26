package com.robbanhoglund.springbootanalyzer.analyzer.model;

/**
 * Catalogue of all static-analysis rule definitions used by this tool.
 *
 * <p>Each constant is a {@link FindingRule} that bundles a stable rule ID, a human-readable
 * title, a default severity, the finding category, and a hint about whether the issue would
 * normally surface during ordinary runtime operation. Analyzers create {@link Finding} instances
 * by passing one of these constants to {@link FindingFactory#builder(FindingRule, FindingConfidence)}.
 *
 * <p>Rule IDs are stable identifiers; do not rename them without a migration step because
 * clients may suppress specific rules by ID.
 */
public final class FindingRules {

    /** A sensitive property (password, secret, token, …) is set to a plain-text literal value
     *  rather than referencing an environment variable or secret-management placeholder. */
    public static final FindingRule SPRING_SECRET_LITERAL =
            rule(
                    "SPRING_SECRET_LITERAL",
                    "Sensitive property uses a literal value",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A sensitive property uses a {@code ${…:defaultValue}} placeholder where the default
     *  value itself looks like a real secret (non-blank, non-CHANGEME, …). */
    public static final FindingRule SPRING_SECRET_WEAK_PLACEHOLDER_DEFAULT =
            rule(
                    "SPRING_SECRET_WEAK_PLACEHOLDER_DEFAULT",
                    "Secret placeholder has a weak default value",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** The same sensitive property key appears in two or more profile-specific configuration
     *  files, making consistent secret rotation harder and increasing the risk of stale values. */
    public static final FindingRule SPRING_SECRET_MULTI_PROFILE =
            rule(
                    "SPRING_SECRET_MULTI_PROFILE",
                    "Sensitive property is configured in multiple profiles",
                    FindingSeverity.INFO,
                    FindingCategory.PROFILE_DRIFT,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** A configuration property in a production-oriented profile has a value that carries
     *  known operational risk (e.g. {@code debug=true}, {@code server.error.include-stacktrace=always},
     *  {@code springdoc.swagger-ui.enabled=true}). */
    public static final FindingRule SPRING_RISKY_PROD_CONFIG =
            rule(
                    "SPRING_RISKY_PROD_CONFIG",
                    "Risky production configuration detected",
                    FindingSeverity.WARNING,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** A structurally significant property (URL, endpoint, provider, security setting) has
     *  different values across two or more Spring profiles, which can cause surprising behaviour
     *  when a non-default profile is activated. */
    public static final FindingRule SPRING_PROFILE_DRIFT =
            rule(
                    "SPRING_PROFILE_DRIFT",
                    "Configuration differs across profiles",
                    FindingSeverity.INFO,
                    FindingCategory.PROFILE_DRIFT,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** A {@code @PostConstruct}, {@code ApplicationRunner}, or {@code CommandLineRunner} method
     *  performs outbound I/O, state mutation, or other side effects that run unconditionally
     *  on every startup, including test contexts. */
    public static final FindingRule SPRING_STARTUP_SIDE_EFFECT =
            rule(
                    "SPRING_STARTUP_SIDE_EFFECT",
                    "Startup hook performs side effects",
                    FindingSeverity.WARNING,
                    FindingCategory.STARTUP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Scheduled} method contains write operations or outbound calls that execute
     *  repeatedly and unconditionally. Combined with a missing transaction boundary this can
     *  cause data inconsistency or unintended external effects. */
    public static final FindingRule SPRING_SCHEDULED_SIDE_EFFECT =
            rule(
                    "SPRING_SCHEDULED_SIDE_EFFECT",
                    "Scheduled job performs side effects",
                    FindingSeverity.WARNING,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code fixedRate} or {@code fixedDelay} scheduler is configured with an interval
     *  shorter than one minute, which may overwhelm downstream systems or the thread pool. */
    public static final FindingRule SPRING_SCHEDULED_SHORT_INTERVAL =
            rule(
                    "SPRING_SCHEDULED_SHORT_INTERVAL",
                    "Scheduled job runs on a short interval",
                    FindingSeverity.INFO,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Scheduled(cron = …)} expression omits an explicit {@code zone} attribute,
     *  so the trigger fires according to the JVM default time zone, which may differ between
     *  environments and after DST transitions. */
    public static final FindingRule SPRING_SCHEDULED_CRON_NO_ZONE =
            rule(
                    "SPRING_SCHEDULED_CRON_NO_ZONE",
                    "Scheduled cron has no explicit time zone",
                    FindingSeverity.INFO,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code RestTemplate}, {@code WebClient}, or {@code RestClient} bean has no visible
     *  read/connect timeout configured. Without a timeout, a slow or unresponsive upstream
     *  can hold threads indefinitely and cause thread-pool exhaustion. */
    public static final FindingRule SPRING_HTTP_CLIENT_NO_TIMEOUT =
            rule(
                    "SPRING_HTTP_CLIENT_NO_TIMEOUT",
                    "HTTP client has no visible timeout configuration",
                    FindingSeverity.WARNING,
                    FindingCategory.HTTP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A hard-coded or configured service URL uses the {@code http://} scheme, exposing traffic
     *  to interception. Should use {@code https://} except for localhost/internal loopback. */
    public static final FindingRule SPRING_HTTP_PLAIN_URL =
            rule(
                    "SPRING_HTTP_PLAIN_URL",
                    "External service URL uses plain HTTP",
                    FindingSeverity.WARNING,
                    FindingCategory.HTTP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An HTTP client declaration has no visible retry policy, circuit breaker, or fallback.
     *  A single transient failure propagates directly to the caller as an exception. */
    public static final FindingRule SPRING_HTTP_CLIENT_NO_RESILIENCE =
            rule(
                    "SPRING_HTTP_CLIENT_NO_RESILIENCE",
                    "HTTP client has no visible retry or circuit-breaker handling",
                    FindingSeverity.INFO,
                    FindingCategory.HTTP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A property that controls a {@code @ConditionalOnProperty} selection has a configured
     *  value that does not match any of the {@code havingValue} strings declared in source,
     *  so the application may silently activate an unexpected or no bean. */
    public static final FindingRule SPRING_CONDITIONAL_VALUE_MISMATCH =
            rule(
                    "SPRING_CONDITIONAL_VALUE_MISMATCH",
                    "Configured provider value does not match any conditional bean",
                    FindingSeverity.WARNING,
                    FindingCategory.CONDITIONAL_BEAN,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** Two or more {@code @ConditionalOnProperty} beans for the same property key set
     *  {@code matchIfMissing = true}, making the active bean depend on classpath ordering
     *  when the controlling property is absent. */
    public static final FindingRule SPRING_CONDITIONAL_MATCH_IF_MISSING_OVERLAP =
            rule(
                    "SPRING_CONDITIONAL_MATCH_IF_MISSING_OVERLAP",
                    "Multiple conditional beans default to matchIfMissing",
                    FindingSeverity.WARNING,
                    FindingCategory.CONDITIONAL_BEAN,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** Flyway (migration-based schema management) is active at the same time as a
     *  Hibernate {@code ddl-auto} setting that mutates the schema ({@code update}, {@code create},
     *  {@code create-drop}, {@code drop}), creating two competing schema authorities. */
    public static final FindingRule SPRING_FLYWAY_DDL_AUTO_MIX =
            rule(
                    "SPRING_FLYWAY_DDL_AUTO_MIX",
                    "Flyway is combined with schema-mutating Hibernate DDL",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Flyway is present on the classpath or explicitly enabled in configuration, but no
     *  {@code V__*.sql} migration files were found under {@code src/main/resources/db/migration}. */
    public static final FindingRule SPRING_FLYWAY_MISSING_MIGRATIONS =
            rule(
                    "SPRING_FLYWAY_MISSING_MIGRATIONS",
                    "Flyway is enabled but migration files were not found",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A service method performs write-like operations ({@code save}, {@code delete},
     *  {@code update}, …) but has no {@code @Transactional} annotation and does not
     *  appear to delegate to a transactional method. */
    public static final FindingRule SPRING_TRANSACTION_MISSING_BOUNDARY =
            rule(
                    "SPRING_TRANSACTION_MISSING_BOUNDARY",
                    "Write-heavy service method has no visible transaction boundary",
                    FindingSeverity.INFO,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A method calls two or more different external services or performs mixed I/O without
     *  an explicit consistency or compensation boundary, making partial-failure scenarios
     *  harder to reason about. */
    public static final FindingRule SPRING_SIDE_EFFECT_ORCHESTRATION_NO_BOUNDARY =
            rule(
                    "SPRING_SIDE_EFFECT_ORCHESTRATION_NO_BOUNDARY",
                    "Potential side-effect orchestration without explicit consistency boundary",
                    FindingSeverity.INFO,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code catch} block is completely empty — no logging, no re-throw, no handling —
     *  silently discarding the exception and any context it carries. */
    public static final FindingRule JAVA_EMPTY_CATCH_BLOCK =
            rule(
                    "JAVA_EMPTY_CATCH_BLOCK",
                    "Empty catch block",
                    FindingSeverity.WARNING,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An exception is caught and replaced by a fallback return value or default assignment
     *  without being logged or rethrown. The original failure is invisible to operators. */
    public static final FindingRule SPRING_SWALLOWED_EXCEPTION_FALLBACK =
            rule(
                    "SPRING_SWALLOWED_EXCEPTION_FALLBACK",
                    "Exception is swallowed and replaced with fallback",
                    FindingSeverity.INFO,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** The same try-parse-then-fallback pattern appears in three or more places in the
     *  same file, suggesting the logic should be extracted into a shared utility. */
    public static final FindingRule SPRING_REPEATED_FALLBACK_PARSING_PATTERN =
            rule(
                    "SPRING_REPEATED_FALLBACK_PARSING_PATTERN",
                    "Repeated fallback parsing pattern",
                    FindingSeverity.INFO,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code InterruptedException} is caught and swallowed without restoring the thread's
     *  interrupted status. This breaks cooperative thread cancellation and can prevent the
     *  JVM from shutting down cleanly. */
    public static final FindingRule SPRING_INTERRUPTED_EXCEPTION_SWALLOWED =
            rule(
                    "SPRING_INTERRUPTED_EXCEPTION_SWALLOWED",
                    "InterruptedException is swallowed",
                    FindingSeverity.WARNING,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code catch} clause catches {@code Error} or {@code Throwable}, masking JVM-level
     *  fatal errors ({@code OutOfMemoryError}, {@code StackOverflowError}, …) that should
     *  normally terminate the process. */
    public static final FindingRule SPRING_BROAD_FATAL_ERROR_CATCH =
            rule(
                    "SPRING_BROAD_FATAL_ERROR_CATCH",
                    "Broad fatal error catch",
                    FindingSeverity.WARNING,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring boundary method (controller, listener, scheduled job) catches
     *  {@code Exception} or broader without re-throwing or converting to a
     *  structured error response. Framework error handling is bypassed. */
    public static final FindingRule SPRING_BROAD_EXCEPTION_SPRING_BOUNDARY =
            rule(
                    "SPRING_BROAD_EXCEPTION_SPRING_BOUNDARY",
                    "Broad exception catch in Spring boundary",
                    FindingSeverity.INFO,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code Throwable.printStackTrace()} is called instead of routing the exception
     *  through the application's logging framework, so stack traces bypass log level
     *  controls, structured formats, and aggregation pipelines. */
    public static final FindingRule SPRING_PRINT_STACK_TRACE =
            rule(
                    "SPRING_PRINT_STACK_TRACE",
                    "printStackTrace used instead of application logging",
                    FindingSeverity.INFO,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A controller method returns {@code exception.getMessage()} directly in the HTTP
     *  response body, leaking internal implementation details (class names, stack frames,
     *  dependency versions) to external callers. */
    public static final FindingRule SPRING_RAW_EXCEPTION_MESSAGE_HTTP =
            rule(
                    "SPRING_RAW_EXCEPTION_MESSAGE_HTTP",
                    "Raw exception message exposed through HTTP response",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Two or more {@code @ExceptionHandler} methods in the same {@code @Controller}/
     *  {@code @ControllerAdvice} class map the same exception type. Spring rejects this with an
     *  {@code IllegalStateException} ("Ambiguous @ExceptionHandler method mapped") at startup. */
    public static final FindingRule SPRING_DUPLICATE_EXCEPTION_HANDLER =
            rule(
                    "SPRING_DUPLICATE_EXCEPTION_HANDLER",
                    "Multiple @ExceptionHandler methods map the same exception type",
                    FindingSeverity.ERROR,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @ControllerAdvice} or {@code @ExceptionHandler} method catches
     *  {@code Exception} or broader and returns a generic response, suppressing
     *  more specific handlers that might be registered lower in the chain. */
    public static final FindingRule SPRING_BROAD_EXCEPTION_HANDLER =
            rule(
                    "SPRING_BROAD_EXCEPTION_HANDLER",
                    "Broad Spring exception handler",
                    FindingSeverity.INFO,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A controller method accepts a {@code @RequestBody} parameter without
     *  {@code @Valid}, so Bean Validation constraints on the request object are
     *  silently ignored and invalid input reaches the service layer. */
    public static final FindingRule SPRING_REQUEST_BODY_NO_VALID =
            rule(
                    "SPRING_REQUEST_BODY_NO_VALID",
                    "@RequestBody is missing @Valid",
                    FindingSeverity.INFO,
                    FindingCategory.VALIDATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A controller method accepts a {@code @ModelAttribute} parameter without
     *  {@code @Valid}. Same consequence as {@link #SPRING_REQUEST_BODY_NO_VALID}. */
    public static final FindingRule SPRING_MODEL_ATTRIBUTE_NO_VALID =
            rule(
                    "SPRING_MODEL_ATTRIBUTE_NO_VALID",
                    "@ModelAttribute is missing @Valid",
                    FindingSeverity.INFO,
                    FindingCategory.VALIDATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Async} is placed on a {@code private} method. Spring's proxy-based AOP
     *  cannot intercept non-overridable methods, so the method runs synchronously
     *  on the calling thread despite the annotation. */
    public static final FindingRule SPRING_ASYNC_PROXY_BYPASS =
            rule(
                    "SPRING_ASYNC_PROXY_BYPASS",
                    "@Async on private method will not be intercepted by proxy",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A proxy-driven annotation ({@code @Transactional}, {@code @Cacheable}/{@code @CacheEvict}/
     *  {@code @CachePut}, {@code @Async}, {@code @PreAuthorize}/{@code @Secured}, {@code @Observed})
     *  is placed on a {@code final} method of a Spring bean. Spring's CGLIB proxy cannot override a
     *  final method, so the advice is silently skipped. */
    public static final FindingRule SPRING_PROXY_ANNOTATION_ON_FINAL_METHOD =
            rule(
                    "SPRING_PROXY_ANNOTATION_ON_FINAL_METHOD",
                    "Proxy-driven annotation on a final method is silently skipped",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code new BigDecimal(double)} is constructed from a floating-point literal. The double's
     *  binary value is stored exactly (e.g. {@code new BigDecimal(0.1)} is
     *  0.1000000000000000055...), silently corrupting monetary/precise calculations. */
    public static final FindingRule SPRING_BIGDECIMAL_DOUBLE_CONSTRUCTOR =
            rule(
                    "SPRING_BIGDECIMAL_DOUBLE_CONSTRUCTOR",
                    "new BigDecimal(double) introduces floating-point precision errors",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code Executors.newCachedThreadPool()} is used. Its thread count is unbounded and tasks
     *  are handed to a {@code SynchronousQueue}, so a burst of work spawns threads until the JVM
     *  fails with {@code OutOfMemoryError: unable to create new native thread}. */
    public static final FindingRule SPRING_EXECUTORS_UNBOUNDED_THREAD_POOL =
            rule(
                    "SPRING_EXECUTORS_UNBOUNDED_THREAD_POOL",
                    "Executors.newCachedThreadPool() creates an unbounded thread pool",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring-managed component constructs an {@code ExecutorService}/{@code Executors.*} as a
     *  field but never shuts it down ({@code @PreDestroy} / {@code shutdown()}). The pool's
     *  non-daemon threads leak on every context refresh/redeploy and block clean JVM shutdown. */
    public static final FindingRule SPRING_EXECUTOR_NO_SHUTDOWN =
            rule(
                    "SPRING_EXECUTOR_NO_SHUTDOWN",
                    "ExecutorService created in a bean is never shut down",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An {@code @Async void} method has no try/catch and no custom
     *  {@code AsyncUncaughtExceptionHandler} configured. Exceptions thrown asynchronously never
     *  propagate to the caller; the default {@code SimpleAsyncUncaughtExceptionHandler} only
     *  logs them, so failures are easy to miss. */
    public static final FindingRule SPRING_ASYNC_VOID_SWALLOWED_EXCEPTION =
            rule(
                    "SPRING_ASYNC_VOID_SWALLOWED_EXCEPTION",
                    "@Async void method has no exception handling",
                    FindingSeverity.INFO,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @KafkaListener}, {@code @RabbitListener}, {@code @JmsListener}, or
     *  {@code @SqsListener} method has no visible try/catch or error-channel configuration.
     *  A poison message or processing failure may cause the consumer to stop silently. */
    public static final FindingRule SPRING_MESSAGING_LISTENER_NO_ERROR_HANDLER =
            rule(
                    "SPRING_MESSAGING_LISTENER_NO_ERROR_HANDLER",
                    "Messaging listener has no visible exception handling",
                    FindingSeverity.INFO,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** The project declares a web starter ({@code spring-boot-starter-web} or
     *  {@code spring-boot-starter-webflux}) but has no Spring Security dependency.
     *  All endpoints are publicly accessible by default. */
    public static final FindingRule SPRING_SECURITY_STARTER_MISSING =
            rule(
                    "SPRING_SECURITY_STARTER_MISSING",
                    "Web application has no Spring Security dependency",
                    FindingSeverity.INFO,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @ManyToOne} or {@code @OneToOne} relationship uses the JPA default fetch
     *  type ({@code EAGER}), which issues an extra SQL join on every parent load regardless
     *  of whether the association is needed. */
    public static final FindingRule SPRING_JPA_MANYTOONE_EAGER_DEFAULT =
            rule(
                    "SPRING_JPA_MANYTOONE_EAGER_DEFAULT",
                    "@ManyToOne or @OneToOne uses eager loading by default",
                    FindingSeverity.INFO,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @OneToMany} or {@code @ManyToMany} collection explicitly sets
     *  {@code fetch = FetchType.EAGER}. Collections default to lazy, so eager fetching is a
     *  deliberate choice that loads the whole collection on every parent query and is a common
     *  source of N+1 queries and Cartesian-product joins. */
    public static final FindingRule SPRING_JPA_COLLECTION_EAGER_FETCH =
            rule(
                    "SPRING_JPA_COLLECTION_EAGER_FETCH",
                    "@OneToMany or @ManyToMany collection uses eager fetching",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @ManyToMany} association declares {@code cascade = CascadeType.REMOVE} (or
     *  {@code ALL}). Deleting one side then cascades the delete across the join table to the
     *  shared entities on the other side — which usually still belong to other parents — causing
     *  irreversible data loss. */
    public static final FindingRule SPRING_JPA_MANYTOMANY_CASCADE_REMOVE =
            rule(
                    "SPRING_JPA_MANYTOMANY_CASCADE_REMOVE",
                    "@ManyToMany with CascadeType.REMOVE/ALL deletes shared entities",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @OneToMany} relationship has neither a {@code mappedBy} attribute nor an
     *  explicit {@code @JoinColumn}/{@code @JoinTable}, so Hibernate maps it through an
     *  additional join table even though a foreign-key column in the child table would suffice.
     *  ({@code @ManyToMany} is not checked: its owning side must lack {@code mappedBy}, and
     *  explicit {@code @JoinColumn} mappings are deliberate unidirectional designs.) */
    public static final FindingRule SPRING_JPA_ONETOMANY_MISSING_MAPPED_BY =
            rule(
                    "SPRING_JPA_ONETOMANY_MISSING_MAPPED_BY",
                    "@OneToMany has neither mappedBy nor @JoinColumn",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Bean} method is declared in a class annotated with {@code @Component} or
     *  {@code @Service} instead of {@code @Configuration}. Spring processes these in "lite"
     *  mode, meaning inter-bean method calls are not proxied and singletons are not enforced. */
    public static final FindingRule SPRING_BEAN_ON_NON_CONFIGURATION =
            rule(
                    "SPRING_BEAN_ON_NON_CONFIGURATION",
                    "@Bean method in class without @Configuration uses lite mode",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring Data {@code @Modifying} query method has no {@code @Transactional} on the method
     *  or its class. Executing the modifying query without ANY active transaction throws
     *  {@code jakarta.persistence.TransactionRequiredException} — but the boundary is commonly
     *  (and correctly) provided by a {@code @Transactional} service-layer caller, which static
     *  per-file analysis cannot see. Verify a transactional caller exists. */
    public static final FindingRule SPRING_MODIFYING_NO_TRANSACTION =
            rule(
                    "SPRING_MODIFYING_NO_TRANSACTION",
                    "@Modifying query has no visible transaction boundary",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code spring.jpa.hibernate.ddl-auto} is set to {@code create} or {@code create-drop}
     *  in a production-oriented profile ({@code prod}, {@code production}, {@code staging}).
     *  This drops and recreates all tables on every startup, destroying all existing data. */
    public static final FindingRule SPRING_DDL_AUTO_DESTRUCTIVE_PROD =
            rule(
                    "SPRING_DDL_AUTO_DESTRUCTIVE_PROD",
                    "Destructive Hibernate DDL-auto setting in production-oriented profile",
                    FindingSeverity.ERROR,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** {@code spring.jpa.show-sql=true} is set in a production-oriented profile.
     *  SQL logging bypasses the application logging framework, writes directly to stdout,
     *  and cannot be suppressed by log-level configuration. */
    public static final FindingRule SPRING_JPA_SHOW_SQL_PROD =
            rule(
                    "SPRING_JPA_SHOW_SQL_PROD",
                    "spring.jpa.show-sql=true in production-oriented profile",
                    FindingSeverity.WARNING,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** {@code spring.jpa.open-in-view} is either explicitly set to {@code true}, or not set at
     *  all in a project with a datasource (Spring Boot defaults it to {@code true}). Both keep
     *  the Hibernate session open through the entire HTTP request lifecycle, enabling lazy
     *  loading during serialization and masking N+1 query problems. */
    public static final FindingRule SPRING_JPA_OPEN_IN_VIEW =
            rule(
                    "SPRING_JPA_OPEN_IN_VIEW",
                    "Open-session-in-view is not explicitly disabled",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Transactional} and {@code @Scheduled} are placed on the same method.
     *  Scheduled methods run in a dedicated thread pool that does not participate in
     *  caller-supplied transaction contexts, so the transaction semantics are often
     *  unintentional or misunderstood. */
    public static final FindingRule SPRING_TRANSACTIONAL_ON_SCHEDULED =
            rule(
                    "SPRING_TRANSACTIONAL_ON_SCHEDULED",
                    "@Transactional and @Scheduled on the same method",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** CSRF protection is explicitly disabled in a Spring Security configuration.
     *  Disabling CSRF is only safe for stateless APIs that use token-based authentication
     *  and never rely on browser session cookies. */
    public static final FindingRule SPRING_CSRF_DISABLED =
            rule(
                    "SPRING_CSRF_DISABLED",
                    "CSRF protection is disabled",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A CORS configuration allows all origins ({@code allowedOrigins("*")} or
     *  {@code allowedOriginPatterns("*")}), potentially enabling cross-origin requests
     *  from untrusted domains including credential-carrying requests. */
    public static final FindingRule SPRING_CORS_ALLOW_ALL =
            rule(
                    "SPRING_CORS_ALLOW_ALL",
                    "CORS configuration allows all origins",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @CrossOrigin} annotation on a controller class or handler method allows all
     *  origins — either explicitly ({@code origins = "*"}) or by omission (a bare
     *  {@code @CrossOrigin} defaults to allowing every origin). Per-controller CORS rules are
     *  easy to forget and frequently ship a wildcard to production. */
    public static final FindingRule SPRING_CROSS_ORIGIN_WILDCARD =
            rule(
                    "SPRING_CROSS_ORIGIN_WILDCARD",
                    "@CrossOrigin allows all origins",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code spring-boot-starter-data-rest} is on the classpath. With the default detection
     *  strategy, Spring Data REST auto-exposes full CRUD HTTP endpoints for every public Spring
     *  Data repository, often exposing internal data that was never meant to be reachable. */
    public static final FindingRule SPRING_DATA_REST_REPOSITORIES_EXPOSED =
            rule(
                    "SPRING_DATA_REST_REPOSITORIES_EXPOSED",
                    "Spring Data REST auto-exposes repositories over HTTP",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code NoOpPasswordEncoder} (or the deprecated {@code StandardPasswordEncoder}) is used,
     *  so passwords are stored and compared in clear text (or with a known-weak hash). */
    public static final FindingRule SPRING_NOOP_PASSWORD_ENCODER =
            rule(
                    "SPRING_NOOP_PASSWORD_ENCODER",
                    "Password encoder stores passwords without secure hashing",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @PreAuthorize}/{@code @PostAuthorize}/{@code @Secured}/{@code @RolesAllowed} are used
     *  but no {@code @EnableMethodSecurity}/{@code @EnableGlobalMethodSecurity} is present, so the
     *  annotations are silently ignored and the authorization checks never run. */
    public static final FindingRule SPRING_METHOD_SECURITY_NOT_ENABLED =
            rule(
                    "SPRING_METHOD_SECURITY_NOT_ENABLED",
                    "Method-security annotations are used but method security is not enabled",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code WebSecurity#ignoring()} rule matches a broad path ({@code /**} or every request),
     *  so those URLs bypass the entire Spring Security filter chain — no authentication,
     *  authorization, or security headers are applied. */
    public static final FindingRule SPRING_SECURITY_IGNORING_BROAD_PATH =
            rule(
                    "SPRING_SECURITY_IGNORING_BROAD_PATH",
                    "web.ignoring() bypasses Spring Security for a broad path",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A JWT is parsed without verifying its signature — jjwt {@code parseClaimsJwt}/
     *  {@code parsePlaintextJwt}/{@code parseUnsecuredClaims}, or the {@code none} algorithm
     *  ({@code SignatureAlgorithm.NONE}) — so forged tokens are accepted as genuine. */
    public static final FindingRule SPRING_JWT_SIGNATURE_NOT_VERIFIED =
            rule(
                    "SPRING_JWT_SIGNATURE_NOT_VERIFIED",
                    "JWT is parsed without verifying its signature",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A CORS configuration combines a wildcard origin ({@code allowedOriginPatterns("*")} or
     *  {@code allowedOrigins("*")}) with {@code allowCredentials(true)}, reflecting any origin
     *  while sending credentials — a cross-origin data-exfiltration risk. */
    public static final FindingRule SPRING_CORS_CREDENTIALS_WILDCARD =
            rule(
                    "SPRING_CORS_CREDENTIALS_WILDCARD",
                    "CORS allows credentials with a wildcard origin",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A sensitive value (password, token, API key, …) is passed as a URL query parameter
     *  or path variable, where it may be logged by proxies, CDNs, or the application itself
     *  as part of the request URL. */
    public static final FindingRule SPRING_REQUEST_PARAM_SENSITIVE_NAME =
            rule(
                    "SPRING_REQUEST_PARAM_SENSITIVE_NAME",
                    "Sensitive value passed as URL parameter or path variable",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Value("${property}")} annotation has no default ({@code :}) and the
     *  application will throw {@code IllegalArgumentException} on startup if the property
     *  is absent from the environment. */
    public static final FindingRule SPRING_VALUE_NO_DEFAULT =
            rule(
                    "SPRING_VALUE_NO_DEFAULT",
                    "@Value property reference has no default value",
                    FindingSeverity.WARNING,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Autowired} is placed directly on a field instead of using constructor
     *  injection. Field injection bypasses the constructor, making the class harder to
     *  test, obscures dependencies, and prevents fields from being declared {@code final}. */
    public static final FindingRule SPRING_FIELD_INJECTION =
            rule(
                    "SPRING_FIELD_INJECTION",
                    "@Autowired field injection used instead of constructor injection",
                    FindingSeverity.INFO,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @RequestMapping} annotation on a handler method omits the {@code method}
     *  attribute, so the endpoint accepts all HTTP verbs (GET, POST, PUT, DELETE, …).
     *  This widens the attack surface and contradicts REST conventions. */
    public static final FindingRule SPRING_REQUEST_MAPPING_NO_METHOD =
            rule(
                    "SPRING_REQUEST_MAPPING_NO_METHOD",
                    "@RequestMapping method has no HTTP method constraint",
                    FindingSeverity.INFO,
                    FindingCategory.API_SURFACE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @ConfigurationProperties} class is missing {@code @Validated}.
     *  Without it, Bean Validation annotations ({@code @NotNull}, {@code @Min}, …) on
     *  the properties fields are silently ignored at startup. */
    public static final FindingRule SPRING_CONFIGURATION_PROPERTIES_NOT_VALIDATED =
            rule(
                    "SPRING_CONFIGURATION_PROPERTIES_NOT_VALIDATED",
                    "@ConfigurationProperties class has no @Validated annotation",
                    FindingSeverity.INFO,
                    FindingCategory.VALIDATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code management.endpoints.web.exposure.include} exposes one or more high-risk
     *  actuator endpoints ({@code env}, {@code heapdump}, {@code shutdown}, …) that can
     *  leak credentials, dump the heap, or terminate the process if reached unauthenticated. */
    public static final FindingRule SPRING_ACTUATOR_ENDPOINT_EXPOSED_PROD =
            rule(
                    "SPRING_ACTUATOR_ENDPOINT_EXPOSED_PROD",
                    "Sensitive actuator endpoints are exposed",
                    FindingSeverity.WARNING,
                    FindingCategory.ACTUATOR,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A native SQL query string is assembled using Java string concatenation rather than
     *  JDBC/JPA named parameters, creating a potential SQL injection vulnerability. */
    public static final FindingRule SPRING_SQL_INJECTION_QUERY_CONCATENATION =
            rule(
                    "SPRING_SQL_INJECTION_QUERY_CONCATENATION",
                    "Native SQL query built with string concatenation",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A sensitive value (password, token, credential, …) is passed to a logging call,
     *  which may write it to log files or aggregation systems that are not access-controlled
     *  to the same degree as the secret store. */
    public static final FindingRule SPRING_LOGGING_PII_EXPOSURE =
            rule(
                    "SPRING_LOGGING_PII_EXPOSURE",
                    "Sensitive value may be written to logs",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A service method accesses a lazy-loaded JPA association outside of a transaction
     *  boundary. When open-in-view is disabled, this will throw
     *  {@code LazyInitializationException} at runtime. */
    public static final FindingRule SPRING_JPA_LAZY_LOADING_OUTSIDE_TRANSACTION =
            rule(
                    "SPRING_JPA_LAZY_LOADING_OUTSIDE_TRANSACTION",
                    "Service method may trigger lazy loading outside a transaction",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code spring.datasource.hikari.maximum-pool-size} is set to {@code 1} or less.
     *  A pool this small serialises all database access through a single connection,
     *  causing severe throughput degradation under any concurrent load. */
    public static final FindingRule SPRING_CONNECTION_POOL_MISCONFIGURED =
            rule(
                    "SPRING_CONNECTION_POOL_MISCONFIGURED",
                    "HikariCP connection pool configuration looks misconfigured",
                    FindingSeverity.WARNING,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Async} is used but no custom {@code Executor} or {@code TaskExecutor} bean
     *  is configured. Spring falls back to {@code SimpleAsyncTaskExecutor}, which creates
     *  a new thread for every invocation and provides no back-pressure or queue bounds. */
    public static final FindingRule SPRING_ASYNC_EXECUTOR_NOT_CONFIGURED =
            rule(
                    "SPRING_ASYNC_EXECUTOR_NOT_CONFIGURED",
                    "@Async used without a custom executor configured",
                    FindingSeverity.WARNING,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Multiple {@code @Scheduled} methods are present but no dedicated
     *  {@code TaskScheduler} bean is registered. By default, Spring uses a single-threaded
     *  scheduler, so a slow job can delay all other scheduled tasks. */
    public static final FindingRule SPRING_SCHEDULED_EXECUTOR_SERVICE_NOT_CONFIGURED =
            rule(
                    "SPRING_SCHEDULED_EXECUTOR_SERVICE_NOT_CONFIGURED",
                    "Multiple @Scheduled methods without a dedicated TaskScheduler",
                    FindingSeverity.WARNING,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @FeignClient} has no {@code fallback} or {@code fallbackFactory} attribute
     *  and no circuit-breaker configuration. Any transient upstream failure propagates
     *  directly to the caller, and the default read timeout is infinite. */
    public static final FindingRule SPRING_FEIGN_NO_FALLBACK_OR_TIMEOUT =
            rule(
                    "SPRING_FEIGN_NO_FALLBACK_OR_TIMEOUT",
                    "@FeignClient has no fallback or timeout configuration",
                    FindingSeverity.WARNING,
                    FindingCategory.HTTP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code RestTemplate} {@code @Bean} method does not call {@code setErrorHandler},
     *  leaving the default behaviour of throwing {@code HttpClientErrorException} or
     *  {@code HttpServerErrorException} on non-2xx responses. Error details from downstream
     *  services are lost or inconsistently handled at different call sites. */
    public static final FindingRule SPRING_RESTTEMPLATE_NO_HTTP_STATUS_HANDLER =
            rule(
                    "SPRING_RESTTEMPLATE_NO_HTTP_STATUS_HANDLER",
                    "RestTemplate used without HTTP status error handling",
                    FindingSeverity.WARNING,
                    FindingCategory.HTTP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Transactional} annotation explicitly sets
     *  {@code isolation = Isolation.READ_UNCOMMITTED}. This allows reading uncommitted
     *  (dirty) data from concurrent transactions and is almost never the right choice
     *  outside of very specific analytical workloads. */
    public static final FindingRule SPRING_TRANSACTION_ISOLATION_READ_UNCOMMITTED =
            rule(
                    "SPRING_TRANSACTION_ISOLATION_READ_UNCOMMITTED",
                    "@Transactional uses READ_UNCOMMITTED isolation",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Timed} is used on a Spring Boot 3.x project. {@code @Observed} (Micrometer
     *  Observation API) supersedes {@code @Timed} on Spring Boot 3+ because it produces
     *  both a timer metric and a distributed-trace span with a single annotation. */
    public static final FindingRule SPRING_TIMED_PREFER_OBSERVED =
            rule(
                    "SPRING_TIMED_PREFER_OBSERVED",
                    "@Timed used on Spring Boot 3+ — prefer @Observed",
                    FindingSeverity.INFO,
                    FindingCategory.OBSERVABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Scheduled} method has neither {@code @Timed} nor {@code @Observed}.
     *  Scheduled jobs run in the background and are invisible to distributed tracing unless
     *  explicitly instrumented. */
    public static final FindingRule SPRING_SCHEDULED_NO_OBSERVABILITY =
            rule(
                    "SPRING_SCHEDULED_NO_OBSERVABILITY",
                    "@Scheduled method has no observability annotation",
                    FindingSeverity.INFO,
                    FindingCategory.OBSERVABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A messaging listener method ({@code @KafkaListener}, {@code @RabbitListener},
     *  {@code @JmsListener}, {@code @SqsListener}) has neither {@code @Timed} nor
     *  {@code @Observed}. Without instrumentation, consumer lag and processing failures
     *  are invisible to observability tooling. */
    public static final FindingRule SPRING_LISTENER_NO_OBSERVABILITY =
            rule(
                    "SPRING_LISTENER_NO_OBSERVABILITY",
                    "Messaging listener has no observability annotation",
                    FindingSeverity.INFO,
                    FindingCategory.OBSERVABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Testing ───────────────────────────────────────────────────────────────

    /** {@code @SpringBootTest} loads the entire application context, but the test class only
     *  injects a controller (suggesting {@code @WebMvcTest}) or a repository (suggesting
     *  {@code @DataJpaTest}). Using a slice annotation is significantly faster and more focused. */
    public static final FindingRule SPRING_TEST_SPRINGBOOTTEST_OVERUSED =
            rule(
                    "SPRING_TEST_SPRINGBOOTTEST_OVERUSED",
                    "@SpringBootTest used where a slice test would suffice",
                    FindingSeverity.WARNING,
                    FindingCategory.TESTING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An integration test class injects a {@code Repository} but has no class-level
     *  {@code @Transactional}. Without it, each test method that writes to the database
     *  leaves rows behind, causing order-dependent failures. */
    public static final FindingRule SPRING_TEST_NO_TRANSACTIONAL_ROLLBACK =
            rule(
                    "SPRING_TEST_NO_TRANSACTIONAL_ROLLBACK",
                    "Integration test uses a repository without @Transactional rollback",
                    FindingSeverity.WARNING,
                    FindingCategory.TESTING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A test class declares more than five {@code @MockBean} fields. Each {@code @MockBean}
     *  replaces a real bean in the application context and forces a context reload, slowing
     *  the suite. It also signals that the class under test has too many dependencies. */
    public static final FindingRule SPRING_TEST_MOCKBEAN_OVERUSE =
            rule(
                    "SPRING_TEST_MOCKBEAN_OVERUSE",
                    "Excessive @MockBean usage forces context reloads",
                    FindingSeverity.INFO,
                    FindingCategory.TESTING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring-managed test class calls {@code .now()} (e.g. {@code LocalDateTime.now()})
     *  without injecting a fixed {@code Clock}. Time-sensitive assertions are non-deterministic
     *  and can fail around midnight, month boundaries, or DST transitions. */
    public static final FindingRule SPRING_TEST_FIXED_CLOCK_MISSING =
            rule(
                    "SPRING_TEST_FIXED_CLOCK_MISSING",
                    "Test uses wall-clock time without a fixed Clock",
                    FindingSeverity.INFO,
                    FindingCategory.TESTING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @SpringBootTest} defaults to {@code webEnvironment = MOCK}, which initialises a
     *  full mock servlet environment. If the test class does not inject {@code MockMvc},
     *  {@code WebTestClient}, or {@code TestRestTemplate}, that overhead is wasted. */
    public static final FindingRule SPRING_TEST_SPRINGBOOTTEST_WEBENV_NONE_MISSING =
            rule(
                    "SPRING_TEST_SPRINGBOOTTEST_WEBENV_NONE_MISSING",
                    "@SpringBootTest starts mock web layer that the test does not use",
                    FindingSeverity.INFO,
                    FindingCategory.TESTING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Caching ───────────────────────────────────────────────────────────────

    /** {@code @Cacheable} is placed on a {@code void} method. Spring will attempt to cache a
     *  {@code null} return value; depending on the {@code CacheManager} this either throws an
     *  exception at runtime or silently stores {@code null} and returns it on subsequent calls,
     *  breaking the method's contract entirely. */
    public static final FindingRule SPRING_CACHEABLE_VOID_RETURN =
            rule(
                    "SPRING_CACHEABLE_VOID_RETURN",
                    "@Cacheable on a void method caches null and skips later executions",
                    FindingSeverity.ERROR,
                    FindingCategory.CACHING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Cacheable} or {@code @CachePut} returns a mutable collection type
     *  ({@code List}, {@code Map}, {@code Set}, etc.). Callers that mutate the returned
     *  collection are directly mutating the cached instance, causing subsequent cache hits to
     *  return corrupt data. */
    public static final FindingRule SPRING_CACHEABLE_MUTABLE_RETURN_TYPE =
            rule(
                    "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE",
                    "@Cacheable returns a mutable collection — callers can corrupt the cache",
                    FindingSeverity.WARNING,
                    FindingCategory.CACHING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A cache annotation ({@code @Cacheable}, {@code @CacheEvict}, or {@code @CachePut}) is
     *  placed on a private method. Spring's proxy-based AOP cannot intercept private methods,
     *  so the annotation is silently ignored at runtime. */
    public static final FindingRule SPRING_CACHE_ON_PRIVATE_METHOD =
            rule(
                    "SPRING_CACHE_ON_PRIVATE_METHOD",
                    "Cache annotation on private method will be silently ignored",
                    FindingSeverity.WARNING,
                    FindingCategory.CACHING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Cacheable}, {@code @CacheEvict}, or {@code @CachePut} method is called
     *  directly from within the same class (self-invocation). Because Spring applies caching
     *  through a proxy wrapper around the bean, internal calls bypass the proxy and the
     *  annotation has no effect. */
    public static final FindingRule SPRING_CACHE_SELF_INVOCATION =
            rule(
                    "SPRING_CACHE_SELF_INVOCATION",
                    "Cache annotation bypassed by self-invocation",
                    FindingSeverity.WARNING,
                    FindingCategory.CACHING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @CacheEvict} is placed on a method that has no parameters and does not set
     *  {@code allEntries = true}. Without parameters, Spring uses {@code SimpleKey.EMPTY} as
     *  the eviction key, which only removes the specific entry stored with an empty-key
     *  {@code @Cacheable} call. If the intent is to clear all entries in the cache, add
     *  {@code allEntries = true}. */
    public static final FindingRule SPRING_CACHE_EVICT_WITHOUT_ALL_ENTRIES =
            rule(
                    "SPRING_CACHE_EVICT_WITHOUT_ALL_ENTRIES",
                    "@CacheEvict on no-arg method without allEntries=true may not clear the cache",
                    FindingSeverity.INFO,
                    FindingCategory.CACHING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Cacheable(sync = true)} is combined with an {@code unless} expression or more than
     *  one cache name. Both combinations are explicitly unsupported by Spring's caching
     *  infrastructure and cause an {@code IllegalArgumentException} at runtime when the method
     *  is first invoked. */
    public static final FindingRule SPRING_CACHEABLE_SYNC_INCOMPATIBLE =
            rule(
                    "SPRING_CACHEABLE_SYNC_INCOMPATIBLE",
                    "@Cacheable(sync = true) combined with incompatible attribute (unless or"
                            + " multiple caches)",
                    FindingSeverity.ERROR,
                    FindingCategory.CACHING,
                    FindingRuntimeDetection.RUNTIME_REQUIRED);

    /** A method is annotated with both {@code @CachePut} and {@code @Cacheable}. Spring's
     *  {@code CacheAspectSupport} resolves the conflict by always invoking the method (the
     *  {@code @CachePut} wins), so the {@code @Cacheable} never serves a hit — caching is
     *  silently defeated. Spring's documentation strongly discourages the combination. */
    public static final FindingRule SPRING_CACHEPUT_AND_CACHEABLE_SAME_METHOD =
            rule(
                    "SPRING_CACHEPUT_AND_CACHEABLE_SAME_METHOD",
                    "@CachePut and @Cacheable on the same method silently defeat caching",
                    FindingSeverity.WARNING,
                    FindingCategory.CACHING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Transaction practices ─────────────────────────────────────────────────

    /** {@code @Transactional} (or {@code javax.transaction.Transactional}) appears on a
     *  {@code private} method. Spring's proxy-based AOP cannot intercept private methods;
     *  the annotation is silently ignored and no transaction is started. */
    public static final FindingRule SPRING_TRANSACTIONAL_ON_PRIVATE_METHOD =
            rule(
                    "SPRING_TRANSACTIONAL_ON_PRIVATE_METHOD",
                    "@Transactional on private method is silently ignored by Spring's proxy",
                    FindingSeverity.ERROR,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Transactional} appears on a {@code protected} or package-private method in a
     *  project resolving Spring Boot 1.x/2.x (Spring Framework 5). There the proxy applies
     *  transaction advice only to {@code public} methods, so the annotation is silently ignored
     *  and no transaction is started. Not reported for Boot 3+ / Framework 6.0+, which supports
     *  non-public {@code @Transactional} methods on class-based proxies by default. */
    public static final FindingRule SPRING_TRANSACTIONAL_NON_PUBLIC_METHOD =
            rule(
                    "SPRING_TRANSACTIONAL_NON_PUBLIC_METHOD",
                    "@Transactional on a non-public method is ignored on Spring Boot 2.x proxies",
                    FindingSeverity.ERROR,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Transactional(readOnly = true)} method (or a method inheriting a class-level
     *  read-only transaction) performs persistence writes. Read-only transactions set the
     *  Hibernate flush mode to MANUAL, so dirty-checked updates are never flushed — the writes are
     *  silently lost (or fail late on a read-only connection). */
    public static final FindingRule SPRING_TRANSACTIONAL_READONLY_WITH_WRITES =
            rule(
                    "SPRING_TRANSACTIONAL_READONLY_WITH_WRITES",
                    "Writes inside a readOnly=true transaction are silently dropped",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @TransactionalEventListener} that runs after the transaction commits (the default
     *  {@code AFTER_COMMIT} phase, or {@code AFTER_COMPLETION}) performs persistence writes without
     *  {@code @Transactional(propagation = REQUIRES_NEW)}. There is no active transaction at that
     *  point, so the writes are silently never flushed. */
    public static final FindingRule SPRING_TX_EVENT_LISTENER_WRITE_LOST =
            rule(
                    "SPRING_TX_EVENT_LISTENER_WRITE_LOST",
                    "Writes in an after-commit @TransactionalEventListener are silently lost",
                    FindingSeverity.ERROR,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Transactional} method declares a checked exception in its {@code throws} clause
     *  but the annotation has no {@code rollbackFor}. Spring rolls back only on
     *  {@code RuntimeException}/{@code Error} by default, so a thrown checked exception commits the
     *  partial transaction. */
    public static final FindingRule SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK =
            rule(
                    "SPRING_TRANSACTIONAL_CHECKED_EXCEPTION_NO_ROLLBACK",
                    "@Transactional commits on a checked exception without rollbackFor",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An eligible transactional method is called directly from the same class where crossing the
     *  Spring AOP proxy would visibly change transaction context or interceptor semantics. */
    public static final FindingRule SPRING_TRANSACTIONAL_SELF_INVOCATION =
            rule(
                    "SPRING_TRANSACTIONAL_SELF_INVOCATION",
                    "@Transactional method called via self-invocation — proxy is bypassed",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A method is annotated with both {@code @Async} and {@code @Transactional}. The async
     *  interceptor runs first, so the transaction interceptor executes on the worker thread and
     *  starts a NEW, independent transaction there — decoupled from any transaction the caller
     *  holds. The caller cannot roll it back and never observes its failure. */
    public static final FindingRule SPRING_ASYNC_TRANSACTIONAL =
            rule(
                    "SPRING_ASYNC_TRANSACTIONAL",
                    "@Async and @Transactional on the same method — independent transaction on the"
                            + " async thread",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Security practices ────────────────────────────────────────────────────

    /** A private method is annotated with {@code @PreAuthorize}, {@code @PostAuthorize},
     *  {@code @Secured}, or {@code @RolesAllowed}. Spring Security's AOP proxy cannot
     *  intercept private methods; the authorization check is silently skipped. */
    public static final FindingRule SPRING_PREAUTHORIZE_ON_PRIVATE_METHOD =
            rule(
                    "SPRING_PREAUTHORIZE_ON_PRIVATE_METHOD",
                    "Security annotation on private method is silently ignored by Spring's proxy",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Observability gaps ────────────────────────────────────────────────────

    /** An {@code @Async} method's return type is not {@code void}, {@code Future},
     *  {@code CompletableFuture}, {@code ListenableFuture}, {@code Mono}, or {@code Flux}.
     *  Spring's async proxy discards the actual return value; the caller always receives
     *  {@code null} or a failed future. */
    public static final FindingRule SPRING_ASYNC_NON_FUTURE_RETURN =
            rule(
                    "SPRING_ASYNC_NON_FUTURE_RETURN",
                    "@Async method has a non-Future return type — caller always receives null",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Observability gaps ────────────────────────────────────────────────────

    /** An {@code @Async} method has no {@code @Observed} or {@code @Timed} annotation.
     *  Background work dispatched via {@code @Async} is common in service layers and represents
     *  a distinct unit of work that should appear in distributed traces and metrics. */
    public static final FindingRule SPRING_ASYNC_NO_OBSERVABILITY =
            rule(
                    "SPRING_ASYNC_NO_OBSERVABILITY",
                    "@Async method has no observability annotation",
                    FindingSeverity.INFO,
                    FindingCategory.OBSERVABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An {@code @EventListener} or {@code @TransactionalEventListener} method has no
     *  {@code @Observed} or {@code @Timed} annotation. Application events that trigger
     *  significant work (sending emails, updating projections, triggering workflows) are
     *  invisible to distributed traces and dashboards without instrumentation. */
    public static final FindingRule SPRING_EVENT_LISTENER_NO_OBSERVABILITY =
            rule(
                    "SPRING_EVENT_LISTENER_NO_OBSERVABILITY",
                    "@EventListener method has no observability annotation",
                    FindingSeverity.INFO,
                    FindingCategory.OBSERVABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Observed} is placed on a private method. Spring's proxy-based AOP cannot
     *  intercept private methods, so the annotation is silently ignored and no observation
     *  span is created at runtime. */
    public static final FindingRule SPRING_OBSERVED_ON_PRIVATE_METHOD =
            rule(
                    "SPRING_OBSERVED_ON_PRIVATE_METHOD",
                    "@Observed on private method will be silently ignored",
                    FindingSeverity.WARNING,
                    FindingCategory.OBSERVABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code WebClient} is constructed directly via {@code WebClient.create(...)} or
     *  {@code WebClient.builder().build()} instead of being built from the auto-configured
     *  {@code WebClient.Builder} bean. The auto-configured builder has Micrometer tracing,
     *  HTTP client metrics, and observation propagation pre-wired. Manual construction
     *  bypasses all of that. */
    public static final FindingRule SPRING_WEBCLIENT_MANUALLY_CONSTRUCTED =
            rule(
                    "SPRING_WEBCLIENT_MANUALLY_CONSTRUCTED",
                    "WebClient constructed manually — bypasses auto-configured observability",
                    FindingSeverity.INFO,
                    FindingCategory.OBSERVABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code spring.autoconfigure.exclude} removes a Spring Security auto-configuration class,
     *  bypassing the default security filter chain for that profile. */
    public static final FindingRule SPRING_SECURITY_AUTOCONFIGURE_EXCLUDED =
            rule(
                    "SPRING_SECURITY_AUTOCONFIGURE_EXCLUDED",
                    "Spring Security auto-configuration excluded in a profile",
                    FindingSeverity.WARNING,
                    FindingCategory.PROFILE_DRIFT,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** The default profile configures a non-embedded datasource URL, but no test profile
     *  overrides {@code spring.datasource.url}, so integration tests may hit the real database. */
    public static final FindingRule SPRING_DATASOURCE_NO_TEST_OVERRIDE =
            rule(
                    "SPRING_DATASOURCE_NO_TEST_OVERRIDE",
                    "Default datasource has no test-profile override",
                    FindingSeverity.WARNING,
                    FindingCategory.PROFILE_DRIFT,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** An embedded H2 datasource URL appears in a profile that does not look like a test,
     *  local, or development profile, suggesting an in-memory database could be used in staging
     *  or production. */
    public static final FindingRule SPRING_H2_IN_NON_TEST_PROFILE =
            rule(
                    "SPRING_H2_IN_NON_TEST_PROFILE",
                    "Embedded H2 database configured outside a test or local profile",
                    FindingSeverity.WARNING,
                    FindingCategory.PROFILE_DRIFT,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** {@code spring.flyway.enabled=false} in a test profile means schema migrations are never
     *  executed during CI, so migration errors are discovered only in production. */
    public static final FindingRule SPRING_FLYWAY_DISABLED_IN_TEST =
            rule(
                    "SPRING_FLYWAY_DISABLED_IN_TEST",
                    "Flyway migrations disabled in test profile",
                    FindingSeverity.INFO,
                    FindingCategory.PROFILE_DRIFT,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** A scheduling-related property (e.g. {@code spring.task.scheduling.enabled=false} or
     *  {@code spring.quartz.auto-startup=false}) is set to a disabled value in a test profile,
     *  meaning scheduled task logic is never exercised during CI runs. */
    public static final FindingRule SPRING_SCHEDULING_DISABLED_IN_TEST =
            rule(
                    "SPRING_SCHEDULING_DISABLED_IN_TEST",
                    "Scheduling disabled in test profile — scheduled tasks not tested",
                    FindingSeverity.INFO,
                    FindingCategory.PROFILE_DRIFT,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** An explicit dependency overrides the Spring Boot BOM and pins {@code org.hibernate:hibernate-core}
     *  to a version below 6.x while the resolved Spring Boot version is 3.x, which ships Hibernate 6.
     *  The mismatch causes runtime failures at startup. Only detectable with Gradle model data. */
    public static final FindingRule SPRING_HIBERNATE_VERSION_MISMATCH =
            rule(
                    "SPRING_HIBERNATE_VERSION_MISMATCH",
                    "Hibernate version is incompatible with the resolved Spring Boot version",
                    FindingSeverity.ERROR,
                    FindingCategory.DEPENDENCY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** The detected Spring Boot version is 3.x but the Java version (from Gradle toolchain or
     *  build-file hint) is below 17. Spring Boot 3 requires Java 17 as a minimum; the
     *  application will fail to start on Java 11 or earlier. */
    public static final FindingRule SPRING_BOOT3_REQUIRES_JAVA17 =
            rule(
                    "SPRING_BOOT3_REQUIRES_JAVA17",
                    "Spring Boot 3.x requires Java 17 or later",
                    FindingSeverity.ERROR,
                    FindingCategory.DEPENDENCY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code spring.threads.virtual.enabled=true} is configured but the detected Java version
     *  is below 21. Virtual threads (Project Loom) require Java 21 or later; on older JVMs
     *  Spring Boot may fail to start or silently fall back to platform threads. */
    public static final FindingRule SPRING_VIRTUAL_THREADS_JAVA_TOO_OLD =
            rule(
                    "SPRING_VIRTUAL_THREADS_JAVA_TOO_OLD",
                    "Virtual threads enabled but Java version is too old",
                    FindingSeverity.WARNING,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A raw {@code new Thread(...).start()} is created inside a Spring-managed component
     *  ({@code @Service}, {@code @Component}, {@code @Controller}, {@code @Repository}).
     *  Manual threads run outside Spring's lifecycle: they lack transaction context, security
     *  context, MDC logging, and unified error handling. */
    public static final FindingRule SPRING_UNMANAGED_THREAD =
            rule(
                    "SPRING_UNMANAGED_THREAD",
                    "Unmanaged thread created manually inside Spring component",
                    FindingSeverity.WARNING,
                    FindingCategory.OBSERVABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Transactional} method contains a catch block that catches {@code RuntimeException}
     *  or {@code Exception} without rethrowing, which silently prevents Spring from triggering
     *  an automatic rollback, leaving the database in a potentially inconsistent state. */
    public static final FindingRule SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED =
            rule(
                    "SPRING_TRANSACTIONAL_EXCEPTION_SWALLOWED",
                    "@Transactional method swallows exception, preventing rollback",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An outbound HTTP call ({@code RestTemplate}, {@code WebClient}, {@code HttpClient},
     *  {@code @FeignClient}) is made inside a {@code @Transactional} method. This holds an
     *  open database connection for the duration of the network round-trip, which can exhaust
     *  the connection pool under load. */
    public static final FindingRule SPRING_TRANSACTIONAL_HTTP_CALL =
            rule(
                    "SPRING_TRANSACTIONAL_HTTP_CALL",
                    "Outbound HTTP call inside @Transactional method",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @RestController} method returns a JPA {@code @Entity} type directly (or wrapped
     *  in {@code ResponseEntity<Entity>} / {@code List<Entity>}) instead of a dedicated DTO.
     *  This exposes internal persistence structure, lazy-loading proxies, and potentially
     *  sensitive columns, and breaks API evolution. */
    public static final FindingRule SPRING_ENTITY_EXPOSED_IN_API =
            rule(
                    "SPRING_ENTITY_EXPOSED_IN_API",
                    "JPA entity returned directly from REST controller",
                    FindingSeverity.WARNING,
                    FindingCategory.API_SURFACE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code System.out.println()} or {@code System.err.println()} is used in production
     *  source code. These calls bypass the application's logging framework and its configuration
     *  for log levels, correlation IDs, log shipping, and structured output. */
    public static final FindingRule SPRING_SYSTEM_OUT_PRINTLN =
            rule(
                    "SPRING_SYSTEM_OUT_PRINTLN",
                    "System.out.println used instead of logger",
                    FindingSeverity.WARNING,
                    FindingCategory.OBSERVABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Profile-specific configuration files ({@code application-prod.properties}, etc.) were
     *  detected. Static analysis cannot determine which runtime profiles will be active, so
     *  analysis of profile-specific values is advisory only. */
    public static final FindingRule SPRING_PROFILE_SPECIFIC_CONFIG =
            rule(
                    "SPRING_PROFILE_SPECIFIC_CONFIG",
                    "Profile-specific configuration files detected",
                    FindingSeverity.INFO,
                    FindingCategory.PROFILE_DRIFT,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** Two or more Flyway migration scripts share the same version number. Flyway will fail
     *  at startup because version numbers must be unique across all configured locations. */
    public static final FindingRule SPRING_FLYWAY_DUPLICATE_VERSION =
            rule(
                    "SPRING_FLYWAY_DUPLICATE_VERSION",
                    "Duplicate Flyway migration version detected",
                    FindingSeverity.ERROR,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Reactive API types ({@code Mono}, {@code Flux}, or WebFlux imports) were found in the
     *  source but the build appears to be a Servlet/MVC application without the WebFlux
     *  starter. Mixing reactive and blocking code paths can cause subtle threading issues. */
    public static final FindingRule SPRING_REACTIVE_API_IN_SERVLET_APP =
            rule(
                    "SPRING_REACTIVE_API_IN_SERVLET_APP",
                    "Reactive API usage in Servlet application",
                    FindingSeverity.INFO,
                    FindingCategory.API_SURFACE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring-managed component ({@code @Service}, {@code @Controller}, {@code @Repository},
     *  etc.) injects {@code ApplicationContext} as a field. This is the service-locator
     *  anti-pattern: it bypasses compile-time dependency checking, hides real dependencies
     *  from the class signature, and tightly couples the code to the Spring framework API. */
    public static final FindingRule SPRING_APPLICATION_CONTEXT_INJECTED =
            rule(
                    "SPRING_APPLICATION_CONTEXT_INJECTED",
                    "ApplicationContext injected as service locator",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An {@code @EventListener} (or {@code @TransactionalEventListener}) method does not have
     *  {@code @Async}. By default, Spring dispatches events synchronously on the publisher's
     *  thread. A slow listener (sending an email, calling a remote API, performing a heavy
     *  computation) will block the HTTP request thread that published the event, increasing
     *  latency for the original caller. */
    public static final FindingRule SPRING_EVENT_LISTENER_BLOCKING =
            rule(
                    "SPRING_EVENT_LISTENER_BLOCKING",
                    "@EventListener runs synchronously on the publisher thread",
                    FindingSeverity.INFO,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Cacheable} is used in the project but no explicit cache provider with TTL support
     *  (Caffeine, Redis, JCache) is configured via {@code spring.cache.type},
     *  {@code spring.cache.caffeine.spec}, or {@code spring.cache.redis.*}. The default
     *  Spring Boot cache implementation ({@code ConcurrentHashMap}) has no eviction or TTL
     *  policy; cached values accumulate indefinitely, leading to memory growth and stale data. */
    public static final FindingRule SPRING_CACHEABLE_NO_TTL_PROVIDER =
            rule(
                    "SPRING_CACHEABLE_NO_TTL_PROVIDER",
                    "@Cacheable used without a cache provider that supports TTL",
                    FindingSeverity.WARNING,
                    FindingCategory.CACHING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A class has methods annotated with {@code @Cacheable} for read operations but no method
     *  in the same class has {@code @CacheEvict} or {@code @CachePut}. Update or delete
     *  operations that modify the underlying data will not automatically invalidate cached
     *  results, causing clients to receive stale data. */
    public static final FindingRule SPRING_CACHEABLE_NO_EVICTION =
            rule(
                    "SPRING_CACHEABLE_NO_EVICTION",
                    "@Cacheable reads without matching @CacheEvict or @CachePut in class",
                    FindingSeverity.WARNING,
                    FindingCategory.CACHING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A string literal that looks like a hardcoded absolute file system path ({@code /var/…},
     *  {@code /tmp/…}, {@code C:\…}, etc.) is passed to {@code new File(…)} or
     *  {@code Paths.get(…)}. In containerised or horizontally-scaled deployments the path may
     *  not exist or data written there is lost when the container restarts. */
    public static final FindingRule SPRING_HARDCODED_FILE_PATH =
            rule(
                    "SPRING_HARDCODED_FILE_PATH",
                    "Hardcoded absolute file system path used in application code",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A class annotated with {@code @Entity} is also annotated with Lombok's {@code @Data}.
     *  {@code @Data} auto-generates {@code equals()}, {@code hashCode()}, and {@code toString()}
     *  over all fields. On lazy-loaded associations this eagerly initialises the entire object
     *  graph and can cause infinite recursion ({@code StackOverflowError}) when two entities
     *  reference each other. */
    public static final FindingRule SPRING_LOMBOK_DATA_ON_ENTITY =
            rule(
                    "SPRING_LOMBOK_DATA_ON_ENTITY",
                    "Lombok @Data on JPA entity — equals/hashCode/toString risk",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code RestTemplate} is constructed via the no-arg constructor {@code new RestTemplate()}.
     *  The default constructor uses {@code SimpleClientHttpRequestFactory} which has no connect or
     *  read timeout, allowing threads to block indefinitely when a downstream service hangs and
     *  eventually starving the thread pool. */
    public static final FindingRule SPRING_REST_TEMPLATE_NO_TIMEOUT =
            rule(
                    "SPRING_REST_TEMPLATE_NO_TIMEOUT",
                    "RestTemplate constructed without explicit timeout configuration",
                    FindingSeverity.WARNING,
                    FindingCategory.HTTP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Scope("prototype")} bean is injected directly as a field or constructor
     *  parameter into a singleton bean ({@code @Service}, {@code @Component}, etc.).
     *  Spring instantiates the prototype once at startup and reuses the same instance for
     *  the lifetime of the singleton, defeating the per-use semantics and causing
     *  shared-state bugs under concurrent load. */
    public static final FindingRule SPRING_PROTOTYPE_BEAN_IN_SINGLETON =
            rule(
                    "SPRING_PROTOTYPE_BEAN_IN_SINGLETON",
                    "Prototype-scoped bean injected directly into singleton — loses prototype"
                            + " semantics",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A class that implements {@code javax.servlet.Filter} or {@code jakarta.servlet.Filter}
     *  is annotated with {@code @Component}. Spring Boot auto-registers every {@code @Component}
     *  filter into the main servlet filter chain regardless of any
     *  {@code SecurityFilterChain} restrictions, causing the filter to execute for every
     *  request instead of only the intended subset. */
    public static final FindingRule SPRING_FILTER_COMPONENT_REGISTRATION_LEAK =
            rule(
                    "SPRING_FILTER_COMPONENT_REGISTRATION_LEAK",
                    "@Component on Servlet Filter causes unintended global registration",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code @Async} methods are present and Spring Security is on the classpath, but no
     *  {@code DelegatingSecurityContextAsyncTaskExecutor} or
     *  {@code DelegatingSecurityContextExecutor} is configured. Spring Security stores the
     *  authenticated principal in a {@code ThreadLocal}; the new thread spawned by
     *  {@code @Async} has no access to it, causing silent {@code AccessDeniedException}
     *  or an empty {@code SecurityContextHolder} inside the async method. */
    public static final FindingRule SPRING_ASYNC_SECURITY_CONTEXT_LOST =
            rule(
                    "SPRING_ASYNC_SECURITY_CONTEXT_LOST",
                    "@Async method loses SecurityContext — authenticated user not propagated",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code spring-boot-devtools} appears on the runtime classpath. DevTools enables
     *  remote restart endpoints, file-system watchers, and live-reload servers that add
     *  CPU overhead and expose restart/reload attack surfaces in production containers. */
    public static final FindingRule SPRING_DEVTOOLS_IN_PRODUCTION =
            rule(
                    "SPRING_DEVTOOLS_IN_PRODUCTION",
                    "spring-boot-devtools is on the runtime classpath",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code MessageDigest.getInstance()} is called with a fast general-purpose algorithm
     *  ({@code "MD5"}, {@code "SHA-1"}, or {@code "SHA-256"}) in a password/credential-handling
     *  context (the enclosing method or class name mentions password, credential, login, …).
     *  Fast hashes are unsuitable for password storage: an attacker with a modern GPU can try
     *  billions of candidates per second against a leaked hash. Non-password uses (checksums,
     *  ETags, content addressing) are not flagged. */
    public static final FindingRule SPRING_WEAK_PASSWORD_HASH =
            rule(
                    "SPRING_WEAK_PASSWORD_HASH",
                    "Weak hashing algorithm used — unsuitable for password storage",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code spring.h2.console.enabled=true} is set in a production-oriented profile.
     *  The H2 web console accepts arbitrary SQL through a JDBC connection and, when reachable,
     *  is a direct path to remote code execution via {@code SCRIPT}, {@code RUNSCRIPT}, or
     *  Java-stored procedures. Even when bound to localhost, it is routinely exposed through
     *  forwarded ports, reverse proxies, or Spring Security misconfiguration. */
    public static final FindingRule SPRING_H2_CONSOLE_ENABLED_PROD =
            rule(
                    "SPRING_H2_CONSOLE_ENABLED_PROD",
                    "H2 web console enabled in a production-oriented profile",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An {@code X509TrustManager} implementation whose {@code checkServerTrusted} or
     *  {@code checkClientTrusted} body is empty (no statements, never throws), or a
     *  {@code HostnameVerifier} whose {@code verify(...)} method unconditionally returns
     *  {@code true}. Both patterns disable TLS certificate / hostname validation, allowing
     *  any man-in-the-middle proxy to intercept HTTPS traffic with a self-signed certificate. */
    public static final FindingRule SPRING_INSECURE_TRUST_MANAGER =
            rule(
                    "SPRING_INSECURE_TRUST_MANAGER",
                    "TLS validation disabled — TrustManager or HostnameVerifier accepts everything",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An XML parser factory ({@code DocumentBuilderFactory}, {@code SAXParserFactory},
     *  {@code XMLInputFactory}, or {@code TransformerFactory}) is constructed without
     *  calling the corresponding {@code setFeature} / {@code setProperty} calls that
     *  disable external entity expansion and DOCTYPE declarations. Such a parser is
     *  vulnerable to XML External Entity (XXE) attacks: arbitrary local-file disclosure,
     *  internal-network SSRF, and (with deep nesting) denial-of-service. */
    public static final FindingRule SPRING_XXE_VULNERABLE_PARSER =
            rule(
                    "SPRING_XXE_VULNERABLE_PARSER",
                    "XML parser created without disabling external entities (XXE)",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Polymorphic deserialization of untrusted input is enabled. Detected patterns include
     *  Jackson's {@code ObjectMapper.enableDefaultTyping(...)} or
     *  {@code activateDefaultTyping(LaissezFaireTypeValidator.instance, ...)}, raw
     *  {@code new ObjectInputStream(...)} for Java serialization, and SnakeYAML's
     *  {@code new Yaml()} default constructor. The Jackson and Java-serialization patterns are
     *  well-known remote-code-execution vectors for attacker-controlled input. The SnakeYAML
     *  constructor allowed arbitrary class instantiation on SnakeYAML 1.x (CVE-2022-1471);
     *  SnakeYAML 2.x (the Spring Boot 3.1+ default) rejects global tags by default, but
     *  {@code SafeConstructor}/explicit {@code LoaderOptions} remain preferable for untrusted
     *  input. */
    public static final FindingRule SPRING_INSECURE_DESERIALIZATION =
            rule(
                    "SPRING_INSECURE_DESERIALIZATION",
                    "Insecure deserialization enabled — possible remote code execution",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring Security configuration disables built-in HTTP response headers, e.g.
     *  {@code .headers(h -> h.disable())}, {@code .frameOptions().disable()},
     *  {@code .contentTypeOptions().disable()}, {@code .httpStrictTransportSecurity().disable()},
     *  or {@code .contentSecurityPolicy(...).disable()}. These headers are cheap,
     *  browser-enforced defenses against clickjacking, content sniffing, and TLS downgrade.
     *  ({@code .xssProtection().disable()} is deliberately NOT flagged: the X-XSS-Protection
     *  header is deprecated by browsers, and Spring Security 5.8+/6 already defaults it to
     *  {@code 0} per OWASP guidance.) */
    public static final FindingRule SPRING_SECURITY_HEADERS_DISABLED =
            rule(
                    "SPRING_SECURITY_HEADERS_DISABLED",
                    "Spring Security HTTP response headers disabled",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring Security {@code SecurityFilterChain} configures
     *  {@code .anyRequest().permitAll()} or {@code .requestMatchers("/**").permitAll()}.
     *  Either pattern grants public access to every endpoint and is almost always a
     *  copy/paste accident or an unfinished migration from the deprecated
     *  {@code WebSecurityConfigurerAdapter}. */
    public static final FindingRule SPRING_PERMIT_ALL_ANY_REQUEST =
            rule(
                    "SPRING_PERMIT_ALL_ANY_REQUEST",
                    "Spring Security permitAll() applied to every request",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring Security {@code SecurityFilterChain} explicitly permits the H2 console
     *  path ({@code "/h2-console/**"} or {@code "/h2-console"}) without authentication.
     *  When combined with {@code spring.h2.console.enabled=true} this exposes an
     *  unauthenticated SQL shell to the network. */
    public static final FindingRule SPRING_H2_CONSOLE_PERMITALL =
            rule(
                    "SPRING_H2_CONSOLE_PERMITALL",
                    "H2 console path permitted without authentication in security configuration",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring-managed component ({@code @Service}, {@code @Component}, {@code @Repository},
     *  {@code @Controller}) declares a {@code static} non-{@code final} field of a mutable
     *  collection type ({@code List}, {@code Map}, {@code Set}, etc.). The field is shared
     *  across all threads and all requests. Without explicit synchronization every concurrent
     *  write is a data race; horizontal scaling makes the problem worse because each JVM
     *  instance has its own copy with no coordination. */
    public static final FindingRule SPRING_STATIC_MUTABLE_FIELD =
            rule(
                    "SPRING_STATIC_MUTABLE_FIELD",
                    "Static mutable collection field in Spring-managed component",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Transactional} annotation is placed directly on a {@code @RestController}
     *  or {@code @Controller} class or one of its handler methods. Controllers are
     *  responsible for HTTP concerns (parsing, routing, serialisation); managing database
     *  transactions in the same layer holds a connection open for the entire HTTP processing
     *  time, including Jackson serialisation, which is outside the intended transaction scope. */
    public static final FindingRule SPRING_TRANSACTIONAL_ON_CONTROLLER =
            rule(
                    "SPRING_TRANSACTIONAL_ON_CONTROLLER",
                    "@Transactional placed on a controller class or handler method",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @RestController} or {@code @Controller} class directly injects a
     *  {@code Repository} (field or constructor parameter), bypassing the service layer.
     *  This couples the HTTP layer to persistence, prevents reuse of business logic, and
     *  makes it impossible to add cross-cutting concerns (transactions, caching, auditing)
     *  in a single place. */
    public static final FindingRule SPRING_REPOSITORY_IN_CONTROLLER =
            rule(
                    "SPRING_REPOSITORY_IN_CONTROLLER",
                    "Repository injected directly into controller — service layer bypassed",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring-managed component calls {@code .block()}, {@code .blockFirst()}, or
     *  {@code .blockLast()} on a reactive stream while WebFlux is the active (or unresolved)
     *  server stack. In a WebFlux application these calls can block an event-loop worker and
     *  prevent it from processing other requests. Deliberate blocking boundaries in a resolved
     *  Servlet/MVC application are not reported by this rule. */
    public static final FindingRule SPRING_WEBFLUX_BLOCKING_CALL =
            rule(
                    "SPRING_WEBFLUX_BLOCKING_CALL",
                    "Blocking call inside Spring-managed component — event-loop thread hazard",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring-managed execution path calls {@code Thread.sleep()} directly. The severity is
     *  raised for WebFlux, HTTP handlers, scheduled work, async methods, and message listeners;
     *  generic component methods remain informational because a bounded backoff can be
     *  intentional. */
    public static final FindingRule SPRING_MANAGED_THREAD_SLEEP =
            rule(
                    "SPRING_MANAGED_THREAD_SLEEP",
                    "Thread.sleep() in a Spring-managed execution path",
                    FindingSeverity.INFO,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Injection / RCE (Tier A) ──────────────────────────────────────────────

    /** An OS command is executed via {@code Runtime.getRuntime().exec(...)} or
     *  {@code new ProcessBuilder(...)} where an argument is assembled with string
     *  concatenation rather than a fixed literal. Concatenating caller-influenced data into a
     *  shell command is the classic OS command-injection vector. */
    public static final FindingRule SPRING_COMMAND_INJECTION =
            rule(
                    "SPRING_COMMAND_INJECTION",
                    "OS command built with string concatenation — possible command injection",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring Expression Language (SpEL) expression is parsed from a value built with string
     *  concatenation: {@code parser.parseExpression("..." + value)}. SpEL can invoke arbitrary
     *  methods and constructors, so evaluating an attacker-influenced expression is a direct
     *  remote-code-execution vector. */
    public static final FindingRule SPRING_SPEL_INJECTION =
            rule(
                    "SPRING_SPEL_INJECTION",
                    "SpEL expression parsed from concatenated input — possible RCE",
                    FindingSeverity.ERROR,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A file system path passed to {@code new File(...)}, {@code Paths.get(...)},
     *  {@code Path.of(...)}, or a {@code new FileInputStream(...)} is assembled with string
     *  concatenation involving a variable. Without canonicalisation and an allowlist this
     *  enables path-traversal ({@code ../../etc/passwd}) to read or write arbitrary files. */
    public static final FindingRule SPRING_PATH_TRAVERSAL =
            rule(
                    "SPRING_PATH_TRAVERSAL",
                    "File path built with concatenation — possible path traversal",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An outbound request target ({@code new URL(...)}, {@code URI.create(...)}, or a
     *  {@code RestTemplate}/{@code WebClient} call) is assembled with string concatenation
     *  involving a variable. If the variable is request-influenced, an attacker can redirect
     *  the call to internal hosts (cloud metadata endpoints, internal admin APIs) — a
     *  server-side request forgery (SSRF). */
    public static final FindingRule SPRING_SSRF_USER_URL =
            rule(
                    "SPRING_SSRF_USER_URL",
                    "Outbound URL built with concatenation — possible SSRF",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A redirect target is built from concatenated input: a returned
     *  {@code "redirect:" + value} view name, or {@code response.sendRedirect(... + value)}.
     *  If the value is attacker-influenced this is an open-redirect used for phishing and
     *  OAuth token theft. */
    public static final FindingRule SPRING_OPEN_REDIRECT =
            rule(
                    "SPRING_OPEN_REDIRECT",
                    "Redirect target built from concatenated input — possible open redirect",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Cryptography (Tier B) ─────────────────────────────────────────────────

    /** {@code new Random()} or {@code Math.random()} is used inside a method or class whose name
     *  indicates security-sensitive value generation (token, password, secret, salt, nonce, OTP,
     *  session id, API key). {@code java.util.Random} is a linear congruential generator whose
     *  output is predictable from a few samples; security values must use {@code SecureRandom}. */
    public static final FindingRule SPRING_INSECURE_RANDOM_FOR_SECURITY =
            rule(
                    "SPRING_INSECURE_RANDOM_FOR_SECURITY",
                    "Predictable java.util.Random used for a security-sensitive value",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code Cipher.getInstance(...)} (or {@code KeyGenerator}/{@code SecretKeyFactory}) is
     *  given a broken or weak algorithm: DES, DESede/3DES, RC2, RC4, Blowfish, the ECB block
     *  mode, or the bare {@code "AES"} transformation (which defaults to ECB). ECB leaks
     *  plaintext structure; the legacy ciphers are cryptographically broken. */
    public static final FindingRule SPRING_WEAK_CIPHER_ALGORITHM =
            rule(
                    "SPRING_WEAK_CIPHER_ALGORITHM",
                    "Weak or broken cipher algorithm/mode (DES, RC4, ECB, bare AES)",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code SecretKeySpec} or {@code IvParameterSpec} is constructed from a hardcoded value
     *  ({@code "literal".getBytes(...)} or an inline byte-array literal). A key or IV baked into
     *  source code is visible to anyone with the artifact and cannot be rotated without a
     *  redeploy, defeating the purpose of encryption. */
    public static final FindingRule SPRING_HARDCODED_ENCRYPTION_KEY =
            rule(
                    "SPRING_HARDCODED_ENCRYPTION_KEY",
                    "Hardcoded encryption key or IV in source code",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Thread safety (Tier C) ────────────────────────────────────────────────

    /** A Spring-managed singleton ({@code @Service}, {@code @Component}, {@code @Repository},
     *  {@code @Controller}, {@code @RestController}) declares an instance field of a
     *  non-thread-safe formatter type ({@code SimpleDateFormat}, {@code DateFormat},
     *  {@code NumberFormat}, {@code DecimalFormat}). Because the bean is a singleton shared by
     *  all request threads, concurrent {@code format}/{@code parse} calls corrupt internal
     *  state and silently return wrong results. */
    public static final FindingRule SPRING_NON_THREAD_SAFE_FORMATTER_FIELD =
            rule(
                    "SPRING_NON_THREAD_SAFE_FORMATTER_FIELD",
                    "Non-thread-safe formatter as a field in a Spring singleton",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Resource exhaustion / startup (Tier D) ────────────────────────────────

    /** An unbounded {@code repository.findAll()} (no {@code Pageable}/{@code Sort}/{@code Example}
     *  argument) is called from a {@code @Service}, {@code @Component}, {@code @Controller}, or
     *  {@code @RestController}. On a large table this loads every row into memory at once,
     *  risking {@code OutOfMemoryError} and long GC pauses. */
    public static final FindingRule SPRING_UNBOUNDED_FINDALL =
            rule(
                    "SPRING_UNBOUNDED_FINDALL",
                    "Unbounded repository.findAll() can load an entire table into memory",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A class annotated with {@code @Entity} has no field or accessor annotated with
     *  {@code @Id}, {@code @EmbeddedId}, or {@code @IdClass}. Hibernate cannot map an entity
     *  without an identifier and throws at startup, so the application context fails to load. */
    public static final FindingRule SPRING_ENTITY_MISSING_ID =
            rule(
                    "SPRING_ENTITY_MISSING_ID",
                    "@Entity has no @Id — Hibernate mapping fails at startup",
                    FindingSeverity.ERROR,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code spring.servlet.multipart.max-file-size} or {@code max-request-size} is explicitly
     *  set to {@code -1}, which removes Spring Boot's default upload cap (1MB file / 10MB request)
     *  and makes the size unlimited. A client can then stream an arbitrarily large upload and
     *  exhaust disk or memory — an availability (DoS) risk. */
    public static final FindingRule SPRING_MULTIPART_NO_MAX_SIZE =
            rule(
                    "SPRING_MULTIPART_NO_MAX_SIZE",
                    "Multipart upload size limit set to unlimited (-1)",
                    FindingSeverity.WARNING,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Spring Boot 3 / Jakarta / Spring Security 6 migration ─────────────────

    /** A class extends {@code WebSecurityConfigurerAdapter}, which was deprecated in Spring
     *  Security 5.7 and removed in Spring Security 6 (Spring Boot 3). Code that still relies on
     *  it will not compile against Spring Boot 3 and must be migrated to the component-based
     *  {@code SecurityFilterChain} model. */
    public static final FindingRule SPRING_SECURITY_WEBSECURITYCONFIGURERADAPTER =
            rule(
                    "SPRING_SECURITY_WEBSECURITYCONFIGURERADAPTER",
                    "WebSecurityConfigurerAdapter was removed in Spring Security 6",
                    FindingSeverity.WARNING,
                    FindingCategory.MIGRATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring Security HTTP configuration uses {@code antMatchers(...)}, {@code mvcMatchers(...)},
     *  or {@code regexMatchers(...)}. All three were removed in Spring Security 6 (Spring Boot 3)
     *  and replaced by the unified {@code requestMatchers(...)}. */
    public static final FindingRule SPRING_SECURITY_ANTMATCHERS_REMOVED =
            rule(
                    "SPRING_SECURITY_ANTMATCHERS_REMOVED",
                    "antMatchers/mvcMatchers/regexMatchers were removed in Spring Security 6",
                    FindingSeverity.WARNING,
                    FindingCategory.MIGRATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A class is annotated with {@code @EnableGlobalMethodSecurity}. Its replacement,
     *  {@code @EnableMethodSecurity}, was introduced in Spring Security 5.6; the old annotation
     *  was deprecated in 5.8 and REMOVED in Spring Security 6 (Spring Boot 3), so the class no
     *  longer compiles after the upgrade. */
    public static final FindingRule SPRING_SECURITY_ENABLE_GLOBAL_METHOD_SECURITY =
            rule(
                    "SPRING_SECURITY_ENABLE_GLOBAL_METHOD_SECURITY",
                    "@EnableGlobalMethodSecurity was removed in Spring Security 6",
                    FindingSeverity.WARNING,
                    FindingCategory.MIGRATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A source file in a Spring Boot 3 project imports from the legacy {@code javax.persistence},
     *  {@code javax.servlet}, {@code javax.validation}, {@code javax.annotation}, or related EE
     *  namespaces. Spring Boot 3 moved to the {@code jakarta.*} namespace; the {@code javax.*}
     *  types no longer resolve. Only reported when the detected Spring Boot version is 3.x or
     *  later. */
    public static final FindingRule SPRING_JAKARTA_NAMESPACE_ON_BOOT3 =
            rule(
                    "SPRING_JAKARTA_NAMESPACE_ON_BOOT3",
                    "Legacy javax.* import in a Spring Boot 3 project (should be jakarta.*)",
                    FindingSeverity.WARNING,
                    FindingCategory.MIGRATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A configuration file sets the deprecated {@code spring.profiles} property to activate or
     *  group profiles. It was deprecated in Spring Boot 2.4 and removed in Spring Boot 3 in
     *  favour of {@code spring.config.activate.on-profile} and {@code spring.profiles.group}. */
    public static final FindingRule SPRING_PROFILES_PROPERTY_DEPRECATED =
            rule(
                    "SPRING_PROFILES_PROPERTY_DEPRECATED",
                    "Deprecated spring.profiles property — use spring.config.activate.on-profile",
                    FindingSeverity.INFO,
                    FindingCategory.MIGRATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A configuration file references the {@code httptrace} actuator endpoint (e.g. in
     *  {@code management.endpoints.web.exposure.include}). In Spring Boot 3 this endpoint was
     *  renamed to {@code httpexchanges}, so the old id silently exposes nothing. */
    public static final FindingRule SPRING_ACTUATOR_HTTPTRACE_RENAMED =
            rule(
                    "SPRING_ACTUATOR_HTTPTRACE_RENAMED",
                    "Actuator 'httptrace' endpoint was renamed to 'httpexchanges' in Spring Boot 3",
                    FindingSeverity.INFO,
                    FindingCategory.MIGRATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Additional security rules ─────────────────────────────────────────────

    /** A JDBC datasource URL embeds credentials directly in the connection string via the
     *  {@code user=}/{@code password=} query parameters (e.g.
     *  {@code jdbc:postgresql://host/db?user=admin&password=secret}). The credentials are then
     *  stored in plain text in configuration and surface in connection logs. */
    public static final FindingRule SPRING_JDBC_URL_EMBEDDED_CREDENTIALS =
            rule(
                    "SPRING_JDBC_URL_EMBEDDED_CREDENTIALS",
                    "JDBC URL embeds credentials in the connection string",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** The default in-memory user password ({@code spring.security.user.password}) is set to a
     *  plain-text literal rather than an environment-variable reference or secret placeholder. */
    public static final FindingRule SPRING_DEFAULT_USER_PASSWORD_LITERAL =
            rule(
                    "SPRING_DEFAULT_USER_PASSWORD_LITERAL",
                    "spring.security.user.password is set to a literal value",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An {@code Authorization} request header (or a bearer/JWT token read from it) is passed to a
     *  logging call. Authorization headers carry credentials and bearer tokens that should never
     *  be written to log files or aggregation systems. */
    public static final FindingRule SPRING_LOGGING_AUTH_HEADER =
            rule(
                    "SPRING_LOGGING_AUTH_HEADER",
                    "Authorization header or bearer token may be written to logs",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code BCryptPasswordEncoder} is constructed with an explicit strength (log rounds)
     *  argument below 10, weakening the work factor below the Spring Security default. */
    public static final FindingRule SPRING_BCRYPT_LOW_STRENGTH =
            rule(
                    "SPRING_BCRYPT_LOW_STRENGTH",
                    "BCryptPasswordEncoder configured with a strength below the default of 10",
                    FindingSeverity.INFO,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Additional reliability rules ──────────────────────────────────────────

    /** A {@code RestTemplate} (with a request-factory argument) or {@code RestClient.create(...)}
     *  is instantiated inside a method body rather than reused as a singleton bean/field. A fresh
     *  client — and its connection pool — is then created on every invocation. (The no-arg
     *  {@code new RestTemplate()} case is covered by {@link #SPRING_REST_TEMPLATE_NO_TIMEOUT}.) */
    public static final FindingRule SPRING_RESTTEMPLATE_NEW_PER_REQUEST =
            rule(
                    "SPRING_RESTTEMPLATE_NEW_PER_REQUEST",
                    "HTTP client instantiated per request instead of reused as a bean",
                    FindingSeverity.WARNING,
                    FindingCategory.HTTP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring Data {@code @Query} method returns a {@code List} (or {@code Collection}) and
     *  declares no {@code Pageable} parameter, so the query has no {@code LIMIT}. On a large table
     *  this materialises every matching row into the heap. */
    public static final FindingRule SPRING_JPA_QUERY_NO_PAGINATION =
            rule(
                    "SPRING_JPA_QUERY_NO_PAGINATION",
                    "@Query returning a collection has no Pageable parameter (no LIMIT)",
                    FindingSeverity.INFO,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A method annotated {@code @Transactional(propagation = REQUIRES_NEW)} is invoked from
     *  inside a loop. Each iteration suspends the current transaction and opens a brand-new one,
     *  consuming an additional connection from the pool per iteration and risking pool
     *  exhaustion. */
    public static final FindingRule SPRING_REQUIRES_NEW_IN_LOOP =
            rule(
                    "SPRING_REQUIRES_NEW_IN_LOOP",
                    "@Transactional(REQUIRES_NEW) method invoked inside a loop",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Async / scheduling enablement & proxy semantics ──────────────────────

    /** One or more {@code @Scheduled} methods exist in the project, but no class is annotated with
     *  {@code @EnableScheduling}. Spring Boot does not enable scheduling automatically, so the
     *  {@code @Scheduled} triggers are parsed but never registered — the jobs silently never run. */
    public static final FindingRule SPRING_SCHEDULED_WITHOUT_ENABLE_SCHEDULING =
            rule(
                    "SPRING_SCHEDULED_WITHOUT_ENABLE_SCHEDULING",
                    "@Scheduled is used but @EnableScheduling is missing — jobs never run",
                    FindingSeverity.ERROR,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** One or more {@code @Async} methods exist in the project, but no class is annotated with
     *  {@code @EnableAsync}. Spring Boot does not enable async processing automatically, so the
     *  annotated methods run synchronously on the caller's thread despite the annotation. */
    public static final FindingRule SPRING_ASYNC_WITHOUT_ENABLE_ASYNC =
            rule(
                    "SPRING_ASYNC_WITHOUT_ENABLE_ASYNC",
                    "@Async is used but @EnableAsync is missing — methods run synchronously",
                    FindingSeverity.WARNING,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Scheduled} method declares one or more parameters. Spring requires scheduled
     *  methods to be no-arg and throws {@code IllegalStateException} ("Only no-arg methods may be
     *  annotated with @Scheduled") while registering the task at startup. */
    public static final FindingRule SPRING_SCHEDULED_METHOD_INVALID_SIGNATURE =
            rule(
                    "SPRING_SCHEDULED_METHOD_INVALID_SIGNATURE",
                    "@Scheduled method has parameters — startup fails (must be no-arg)",
                    FindingSeverity.ERROR,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An {@code @Async} method is called directly (without an external receiver) from within the
     *  same class. The self-invocation bypasses Spring's AOP proxy, so the method runs synchronously
     *  on the caller's thread instead of being dispatched to the async executor. */
    public static final FindingRule SPRING_ASYNC_SELF_INVOCATION =
            rule(
                    "SPRING_ASYNC_SELF_INVOCATION",
                    "@Async method called via self-invocation — runs synchronously, proxy bypassed",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An injection annotation ({@code @Autowired}, {@code @Inject}, {@code @Resource}, or
     *  {@code @Value}) is placed on a {@code static} field of a Spring-managed component. Spring's
     *  dependency injection operates on instances and cannot populate static fields, so the field
     *  stays {@code null} (or its initializer value) and the first use throws
     *  {@code NullPointerException}. */
    public static final FindingRule SPRING_INJECTION_ON_STATIC_FIELD =
            rule(
                    "SPRING_INJECTION_ON_STATIC_FIELD",
                    "Injection annotation on a static field is silently ignored — field stays null",
                    FindingSeverity.ERROR,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A method is annotated with both {@code @PostConstruct} and {@code @Transactional}. The
     *  transactional proxy is not yet in place while the bean's {@code @PostConstruct} callback
     *  runs, so no transaction is started and the annotation has no effect during initialization. */
    public static final FindingRule SPRING_TRANSACTIONAL_ON_POSTCONSTRUCT =
            rule(
                    "SPRING_TRANSACTIONAL_ON_POSTCONSTRUCT",
                    "@Transactional on a @PostConstruct method has no effect during initialization",
                    FindingSeverity.WARNING,
                    FindingCategory.TRANSACTION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Silent-failure & startup-crash rules (catalog review 2026-07) ─────────

    /** {@code @Retryable}/{@code @Recover} (spring-retry) are used, but no class is annotated
     *  with {@code @EnableRetry}. Spring Boot does not auto-configure spring-retry, so without
     *  the enabler the annotations are silently inert: methods execute exactly once and
     *  {@code @Recover} callbacks never run. */
    public static final FindingRule SPRING_RETRYABLE_WITHOUT_ENABLE_RETRY =
            rule(
                    "SPRING_RETRYABLE_WITHOUT_ENABLE_RETRY",
                    "@Retryable is used but @EnableRetry is missing — no retries happen",
                    FindingSeverity.WARNING,
                    FindingCategory.EXCEPTION_HANDLING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Scheduled(cron = ...)} literal is not a valid Spring cron expression: Spring
     *  requires exactly six space-separated fields (seconds first) or a supported macro
     *  ({@code @hourly}, {@code @daily}, ...). A five-field Unix crontab or seven-field Quartz
     *  expression makes task registration throw {@code IllegalStateException} at startup and the
     *  application context fails to load. */
    public static final FindingRule SPRING_SCHEDULED_CRON_INVALID_EXPRESSION =
            rule(
                    "SPRING_SCHEDULED_CRON_INVALID_EXPRESSION",
                    "@Scheduled cron expression is invalid — startup fails (6 fields required)",
                    FindingSeverity.ERROR,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code spring.profiles.active} or {@code spring.profiles.include} appears in a
     *  profile-specific configuration file or an {@code on-profile} document. Since the Spring
     *  Boot 2.4 config-data model (all of Boot 3.x), these keys are invalid there: startup fails
     *  with {@code InvalidConfigDataPropertyException} whenever that profile is activated. */
    public static final FindingRule SPRING_PROFILES_ACTIVE_IN_PROFILE_SPECIFIC_FILE =
            rule(
                    "SPRING_PROFILES_ACTIVE_IN_PROFILE_SPECIFIC_FILE",
                    "spring.profiles.active in a profile-specific file fails at startup",
                    FindingSeverity.ERROR,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** A {@code @OneToOne} association declares both {@code mappedBy} and
     *  {@code fetch = FetchType.LAZY}. Hibernate cannot honour LAZY on the inverse (non-owning)
     *  side of a one-to-one without bytecode enhancement — the foreign key lives in the other
     *  table, so Hibernate must query it anyway to decide between {@code null} and a proxy. The
     *  association silently loads eagerly. */
    public static final FindingRule SPRING_JPA_ONETOONE_MAPPEDBY_LAZY_IGNORED =
            rule(
                    "SPRING_JPA_ONETOONE_MAPPEDBY_LAZY_IGNORED",
                    "LAZY on the inverse side of @OneToOne is silently ignored",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code spring.sql.init.mode=always} is set in a production-oriented profile. Spring Boot
     *  then executes {@code schema.sql}/{@code data.sql} (or the configured script locations)
     *  against the real datasource on EVERY startup; non-idempotent scripts duplicate or
     *  overwrite data, or abort startup. */
    public static final FindingRule SPRING_SQL_INIT_ALWAYS_PROD =
            rule(
                    "SPRING_SQL_INIT_ALWAYS_PROD",
                    "spring.sql.init.mode=always re-runs SQL init scripts in production",
                    FindingSeverity.WARNING,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.ACTIVE_PROFILE_RUNTIME_MAY_DETECT);

    /** A test class uses {@code @MockBean}/{@code @SpyBean}
     *  (org.springframework.boot.test.mock.mockito) on a project resolving Spring Boot 3.4+.
     *  Both annotations are deprecated for removal in favour of {@code @MockitoBean}/
     *  {@code @MockitoSpyBean} (Spring Framework 6.2 bean overrides) and are removed in Spring
     *  Boot 4, so the tests stop compiling on the next major upgrade. */
    public static final FindingRule SPRING_MOCKBEAN_DEPRECATED =
            rule(
                    "SPRING_MOCKBEAN_DEPRECATED",
                    "@MockBean/@SpyBean are deprecated since Spring Boot 3.4 — use @MockitoBean",
                    FindingSeverity.INFO,
                    FindingCategory.MIGRATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Liquibase ({@code org.liquibase:liquibase-core}) is on the classpath but no changelog file
     *  exists at the configured {@code spring.liquibase.change-log} location (default
     *  {@code classpath:/db/changelog/db.changelog-master.yaml}). Spring Boot fails at startup
     *  with "Cannot find changelog location". */
    public static final FindingRule SPRING_LIQUIBASE_MISSING_CHANGELOG =
            rule(
                    "SPRING_LIQUIBASE_MISSING_CHANGELOG",
                    "Liquibase is enabled but the changelog file was not found",
                    FindingSeverity.ERROR,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A class annotated {@code @Entity} (or {@code @Embeddable}) declares constructors but none
     *  of them is no-arg, and no Lombok annotation generates one. JPA/Hibernate require a no-arg
     *  constructor to materialise entities; the first SELECT that loads the entity throws
     *  {@code org.hibernate.InstantiationException} ("No default constructor for entity"). */
    public static final FindingRule SPRING_JPA_ENTITY_NO_NOARG_CONSTRUCTOR =
            rule(
                    "SPRING_JPA_ENTITY_NO_NOARG_CONSTRUCTOR",
                    "@Entity has no no-arg constructor — Hibernate fails on the first load",
                    FindingSeverity.ERROR,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.RUNTIME_REQUIRED);

    /** An explicit {@code @PathVariable("name")} on a handler parameter matches no {@code {name}}
     *  variable in the merged class+method mapping template. Spring throws
     *  {@code MissingPathVariableException} (HTTP 500) on every invocation of the handler. */
    public static final FindingRule SPRING_PATH_VARIABLE_TEMPLATE_MISMATCH =
            rule(
                    "SPRING_PATH_VARIABLE_TEMPLATE_MISMATCH",
                    "@PathVariable name matches no {variable} in the mapping — 500 on every call",
                    FindingSeverity.ERROR,
                    FindingCategory.API_SURFACE,
                    FindingRuntimeDetection.RUNTIME_REQUIRED);

    /** A servlet {@code Cookie} is created and added to the response, but {@code setHttpOnly(true)}
     *  is never called in the file. Servlet cookies default to {@code httpOnly=false} (and
     *  {@code secure=false}), leaving them readable from JavaScript (XSS exfiltration) and sent
     *  over plain HTTP. */
    public static final FindingRule SPRING_COOKIE_MISSING_HTTPONLY =
            rule(
                    "SPRING_COOKIE_MISSING_HTTPONLY",
                    "Cookie added to the response without HttpOnly (and possibly Secure)",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** An archive entry name ({@code ZipEntry.getName()}) flows into {@code new File(dir, name)}
     *  or {@code Path.resolve(name)} without canonical-path containment validation. A malicious
     *  archive whose entry names contain {@code ../} sequences then writes files outside the
     *  extraction directory — the "Zip Slip" vulnerability (CWE-22). */
    public static final FindingRule SPRING_ZIP_SLIP =
            rule(
                    "SPRING_ZIP_SLIP",
                    "Archive entry name used in a file path without validation (Zip Slip)",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Two component-scanned classes share the same simple name (in different packages) and
     *  neither declares an explicit bean name. Spring's default bean-name generator derives the
     *  name from the simple class name, so registration fails at startup with
     *  {@code ConflictingBeanDefinitionException}. */
    public static final FindingRule SPRING_BEAN_NAME_COLLISION =
            rule(
                    "SPRING_BEAN_NAME_COLLISION",
                    "Two component classes share a simple name — startup fails with"
                            + " ConflictingBeanDefinitionException",
                    FindingSeverity.ERROR,
                    FindingCategory.STARTUP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @Scheduled} annotation declares zero or more than one trigger attribute
     *  ({@code cron}, {@code fixedDelay}/{@code fixedDelayString},
     *  {@code fixedRate}/{@code fixedRateString}). Spring requires exactly one trigger and throws
     *  {@code IllegalStateException} while registering the task, so the application context fails
     *  to start. */
    public static final FindingRule SPRING_SCHEDULED_TRIGGER_MISSING_OR_CONFLICTING =
            rule(
                    "SPRING_SCHEDULED_TRIGGER_MISSING_OR_CONFLICTING",
                    "@Scheduled needs exactly one trigger attribute — startup fails otherwise",
                    FindingSeverity.ERROR,
                    FindingCategory.SCHEDULING,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code final} class is annotated {@code @Entity}. Hibernate cannot subclass a final
     *  entity to create lazy proxies, so lazy {@code @ManyToOne}/{@code @OneToOne} references to
     *  it and {@code getReferenceById(...)} silently load eagerly (Hibernate logs HHH000305 at
     *  startup). */
    public static final FindingRule SPRING_JPA_FINAL_ENTITY =
            rule(
                    "SPRING_JPA_FINAL_ENTITY",
                    "final @Entity cannot be proxied — lazy references load eagerly",
                    FindingSeverity.WARNING,
                    FindingCategory.PERSISTENCE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** {@code management.endpoint.env.show-values} or
     *  {@code management.endpoint.configprops.show-values} is set to {@code always}, unmasking
     *  every secret value on the {@code /actuator/env} and {@code /actuator/configprops}
     *  endpoints (Spring Boot 3 sanitizes them by default). */
    public static final FindingRule SPRING_ACTUATOR_SHOW_VALUES_ALWAYS =
            rule(
                    "SPRING_ACTUATOR_SHOW_VALUES_ALWAYS",
                    "Actuator show-values=always unmasks secrets on env/configprops",
                    FindingSeverity.WARNING,
                    FindingCategory.ACTUATOR,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    // ── Previously unregistered findings (catalog review 4) ──────────────────
    // These were emitted through the legacy rule-less Finding constructor, so they had no rule
    // ID, no catalog entry, and could not be suppressed or configured per rule.

    /** Inbound HTTP endpoints ({@code @RestController}, {@code @RequestMapping}, …) exist in the
     *  source, but the resolved runtime stack is non-web (or could not be determined). The
     *  endpoints are then never served. */
    public static final FindingRule SPRING_INBOUND_ENDPOINTS_IN_NON_WEB_APP =
            rule(
                    "SPRING_INBOUND_ENDPOINTS_IN_NON_WEB_APP",
                    "HTTP endpoints exist but the application is not a web application",
                    FindingSeverity.WARNING,
                    FindingCategory.API_SURFACE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A web runtime stack (Servlet MVC or WebFlux) was detected but no inbound HTTP endpoints
     *  were found — the embedded server starts and serves nothing. */
    public static final FindingRule SPRING_WEB_STACK_WITHOUT_ENDPOINTS =
            rule(
                    "SPRING_WEB_STACK_WITHOUT_ENDPOINTS",
                    "Web stack detected but no inbound HTTP endpoints were found",
                    FindingSeverity.INFO,
                    FindingCategory.API_SURFACE,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Configured or outbound URLs carry credential-like query parameters
     *  ({@code ?password=}, {@code ?token=}, …). Full URLs are routinely written to proxy, CDN,
     *  and application logs, so the credential leaks into log storage. */
    public static final FindingRule SPRING_OUTBOUND_URL_CREDENTIALS_IN_QUERY =
            rule(
                    "SPRING_OUTBOUND_URL_CREDENTIALS_IN_QUERY",
                    "Outbound URL carries credentials in query parameters",
                    FindingSeverity.WARNING,
                    FindingCategory.SECURITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Virtual threads are enabled and scheduled work exists, but {@code spring.main.keep-alive}
     *  is not set. A non-web application whose only non-daemon work runs on virtual threads can
     *  exit immediately after startup. */
    public static final FindingRule SPRING_VIRTUAL_THREADS_NO_KEEP_ALIVE =
            rule(
                    "SPRING_VIRTUAL_THREADS_NO_KEEP_ALIVE",
                    "Virtual threads with scheduled work but no spring.main.keep-alive",
                    FindingSeverity.INFO,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Both Spring MVC/Servlet and WebFlux starters are on the classpath. Spring MVC wins unless
     *  {@code spring.main.web-application-type} says otherwise. This can be valid for MVC plus
     *  {@code WebClient}; the occurrence is promoted from INFO to WARNING only when inactive
     *  WebFlux server routing APIs are also detected. */
    public static final FindingRule SPRING_MIXED_MVC_AND_WEBFLUX =
            rule(
                    "SPRING_MIXED_MVC_AND_WEBFLUX",
                    "Both MVC and WebFlux starters present — MVC takes precedence",
                    FindingSeverity.INFO,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** Servlet/web dependencies are present but configuration forces a non-web application type,
     *  so the embedded server never starts despite the dependencies being packaged. */
    public static final FindingRule SPRING_WEB_DEPENDENCIES_IN_NON_WEB_APP =
            rule(
                    "SPRING_WEB_DEPENDENCIES_IN_NON_WEB_APP",
                    "Web dependencies present but application type is non-web",
                    FindingSeverity.INFO,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A configuration property marked deprecated in Spring Boot's configuration metadata is
     *  used. Deprecated properties are removed in later releases, silently losing their effect. */
    public static final FindingRule SPRING_DEPRECATED_CONFIGURATION_PROPERTY =
            rule(
                    "SPRING_DEPRECATED_CONFIGURATION_PROPERTY",
                    "Deprecated Spring Boot configuration property is used",
                    FindingSeverity.WARNING,
                    FindingCategory.MIGRATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A configured property looks application-specific (it is referenced from source) but has no
     *  matching {@code @ConfigurationProperties} metadata, so it is bound ad hoc via
     *  {@code @Value} with no validation or IDE support. */
    public static final FindingRule SPRING_UNMAPPED_CUSTOM_PROPERTY =
            rule(
                    "SPRING_UNMAPPED_CUSTOM_PROPERTY",
                    "Custom property has no @ConfigurationProperties metadata",
                    FindingSeverity.INFO,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A {@code @ConfigurationProperties} prefix is declared in code but no configured property
     *  uses it, so the binding class is populated entirely from defaults. */
    public static final FindingRule SPRING_CONFIGURATION_PROPERTIES_PREFIX_UNUSED =
            rule(
                    "SPRING_CONFIGURATION_PROPERTIES_PREFIX_UNUSED",
                    "@ConfigurationProperties prefix has no configured properties",
                    FindingSeverity.INFO,
                    FindingCategory.CONFIGURATION,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A class is declared in the default (unnamed) package. Spring Boot's component scanning
     *  then scans the entire classpath, and several framework features misbehave. */
    public static final FindingRule SPRING_CLASS_IN_DEFAULT_PACKAGE =
            rule(
                    "SPRING_CLASS_IN_DEFAULT_PACKAGE",
                    "Class declared in the default package",
                    FindingSeverity.WARNING,
                    FindingCategory.MAINTAINABILITY,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** No {@code @SpringBootApplication} class was found under {@code src/main/java}. Either the
     *  project is not a Spring Boot application, or the entry point lives outside the scanned
     *  source root — in which case the analysis is necessarily incomplete. */
    public static final FindingRule SPRING_NO_MAIN_APPLICATION_CLASS =
            rule(
                    "SPRING_NO_MAIN_APPLICATION_CLASS",
                    "No @SpringBootApplication class was found",
                    FindingSeverity.WARNING,
                    FindingCategory.STARTUP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** More than one {@code @SpringBootApplication} class exists. Each defines its own component
     *  scan root, and tests may bootstrap an unintended one. */
    public static final FindingRule SPRING_MULTIPLE_MAIN_APPLICATION_CLASSES =
            rule(
                    "SPRING_MULTIPLE_MAIN_APPLICATION_CLASSES",
                    "Multiple @SpringBootApplication classes were found",
                    FindingSeverity.INFO,
                    FindingCategory.STARTUP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    /** A Spring stereotype component lives outside the main application class's package tree.
     *  Default component scanning starts at the application package, so the bean is never
     *  registered unless an explicit {@code @ComponentScan} includes it. */
    public static final FindingRule SPRING_COMPONENT_OUTSIDE_MAIN_PACKAGE =
            rule(
                    "SPRING_COMPONENT_OUTSIDE_MAIN_PACKAGE",
                    "Component lives outside the main application package — not scanned",
                    FindingSeverity.WARNING,
                    FindingCategory.STARTUP,
                    FindingRuntimeDetection.NOT_NORMALLY_DETECTED);

    private FindingRules() {}

    private static FindingRule rule(
            String ruleId,
            String title,
            FindingSeverity severity,
            FindingCategory category,
            FindingRuntimeDetection runtimeDetection) {
        return new FindingRule(ruleId, title, severity, category, runtimeDetection);
    }
}

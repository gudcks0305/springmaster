package com.robbanhoglund.springbootanalyzer.analyzer.http;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildInfo;
import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildModuleResolver;
import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingConfidence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingFactory;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingOccurrence;
import com.robbanhoglund.springbootanalyzer.analyzer.model.FindingRules;
import com.robbanhoglund.springbootanalyzer.analyzer.model.HighlightRange;
import com.robbanhoglund.springbootanalyzer.analyzer.model.SourceLocation;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.ApplicationProperty;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.ConfigurationAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.ActuatorEndpointExposure;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.ConfiguredUrl;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.EndpointSource;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.HttpSurfaceAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.HttpSurfaceSummary;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.InboundEndpoint;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.OutboundEndpoint;
import com.robbanhoglund.springbootanalyzer.analyzer.model.http.UrlKind;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.ModuleRuntimeStackAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.RuntimeStackAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.model.runtime.WebStack;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.stereotype.Component;

@Component
public class HttpSurfaceAnalyzer {

    private static final Pattern PLACEHOLDER_PATTERN =
            Pattern.compile("\\$\\{([^}:]+)(?::[^}]*)?}");
    private static final Pattern URL_WITH_QUERY_PATTERN =
            Pattern.compile(
                    "([?&])(token|key|secret|password|access_token)=([^&]+)",
                    Pattern.CASE_INSENSITIVE);
    private static final Set<String> SENSITIVE_NAME_MARKERS =
            Set.of(
                    "password",
                    "passwd",
                    "secret",
                    "token",
                    "api-key",
                    "apikey",
                    "private-key",
                    "credential",
                    "authorization",
                    "client-secret",
                    "access-key",
                    "refresh-token");
    private static final Set<String> INBOUND_MAPPING_ANNOTATIONS =
            Set.of(
                    "RequestMapping",
                    "GetMapping",
                    "PostMapping",
                    "PutMapping",
                    "PatchMapping",
                    "DeleteMapping");

    public Result analyze(
            Path repositoryRoot,
            ConfigurationAnalysis configurationAnalysis,
            BuildInfo buildInfo,
            WebStack webStack) {
        return analyze(
                JavaSources.from(repositoryRoot), configurationAnalysis, buildInfo, webStack);
    }

    public Result analyze(
            JavaSources javaSources,
            ConfigurationAnalysis configurationAnalysis,
            BuildInfo buildInfo,
            WebStack webStack) {
        return analyzeInternal(javaSources, configurationAnalysis, buildInfo, webStack, List.of());
    }

    public Result analyze(
            JavaSources javaSources,
            ConfigurationAnalysis configurationAnalysis,
            BuildInfo buildInfo,
            RuntimeStackAnalysis runtimeStackAnalysis) {
        return analyzeInternal(
                javaSources,
                configurationAnalysis,
                buildInfo,
                runtimeStackAnalysis.webStack(),
                runtimeStackAnalysis.modules());
    }

    private Result analyzeInternal(
            JavaSources javaSources,
            ConfigurationAnalysis configurationAnalysis,
            BuildInfo buildInfo,
            WebStack webStack,
            List<ModuleRuntimeStackAnalysis> moduleRuntimeStacks) {
        BaseUrlCatalog baseUrlCatalog = new BaseUrlCatalog(configurationAnalysis);
        List<ConfiguredUrl> configuredUrls = detectConfiguredUrls(configurationAnalysis);
        List<ActuatorEndpointExposure> actuatorExposures =
                detectActuatorExposures(configurationAnalysis);
        SourceSurface sourceSurface = scanJavaSources(javaSources, baseUrlCatalog);

        HttpSurfaceSummary summary =
                new HttpSurfaceSummary(
                        sourceSurface.inboundEndpoints().size(),
                        sourceSurface.outboundEndpoints().size(),
                        configuredUrls.size(),
                        actuatorExposures.size(),
                        sourceSurface.inboundEndpoints().stream()
                                .map(InboundEndpoint::path)
                                .filter(Objects::nonNull)
                                .map(this::basePathOf)
                                .filter(value -> !value.isBlank())
                                .distinct()
                                .toList(),
                        Stream.concat(
                                        configuredUrls.stream().map(ConfiguredUrl::host),
                                        sourceSurface.outboundEndpoints().stream()
                                                .map(OutboundEndpoint::host))
                                .filter(value -> value != null && !value.isBlank())
                                .distinct()
                                .toList());

        List<Finding> findings = new ArrayList<>();
        addHttpFindings(
                buildInfo,
                webStack,
                moduleRuntimeStacks,
                sourceSurface.inboundEndpoints(),
                configuredUrls,
                actuatorExposures,
                sourceSurface.outboundEndpoints(),
                findings);

        return new Result(
                new HttpSurfaceAnalysis(
                        summary,
                        List.copyOf(sourceSurface.inboundEndpoints()),
                        List.copyOf(sourceSurface.outboundEndpoints()),
                        List.copyOf(configuredUrls),
                        List.copyOf(actuatorExposures)),
                List.copyOf(findings));
    }

    private List<ConfiguredUrl> detectConfiguredUrls(ConfigurationAnalysis configurationAnalysis) {
        if (configurationAnalysis == null || configurationAnalysis.properties() == null) {
            return List.of();
        }

        List<ConfiguredUrl> configuredUrls = new ArrayList<>();
        for (ApplicationProperty property : configurationAnalysis.properties()) {
            if (property.value() == null || property.value().isBlank()) {
                continue;
            }
            ConfiguredUrlMetadata metadata =
                    classifyConfiguredUrl(
                            property.name(), property.value(), property.valueRedacted());
            UrlKind kind = metadata.kind();
            if (kind == null) {
                continue;
            }

            String value =
                    property.valueRedacted()
                            ? property.value()
                            : sanitizeUrlValue(property.value());
            configuredUrls.add(
                    new ConfiguredUrl(
                            property.name(),
                            value,
                            property.valueRedacted(),
                            metadata.host() != null
                                    ? metadata.host()
                                    : hostForValue(property.name(), property.value(), kind),
                            metadata.referencedPropertyName(),
                            property.sourceFile(),
                            property.line(),
                            property.profile(),
                            kind));
        }
        return List.copyOf(configuredUrls);
    }

    private List<ActuatorEndpointExposure> detectActuatorExposures(
            ConfigurationAnalysis configurationAnalysis) {
        if (configurationAnalysis == null || configurationAnalysis.properties() == null) {
            return List.of();
        }

        List<ActuatorEndpointExposure> exposures = new ArrayList<>();
        for (ApplicationProperty property : configurationAnalysis.properties()) {
            if (property.name() == null || property.value() == null) {
                continue;
            }
            if (!property.name().equals("management.endpoints.web.exposure.include")
                    && !property.name().equals("management.endpoints.web.exposure.exclude")
                    && !property.name().equals("management.endpoints.web.base-path")
                    && !property.name().equals("management.server.port")) {
                continue;
            }

            List<String> exposedEndpoints =
                    property.value().equals("[redacted]") ? List.of() : splitCsv(property.value());
            exposures.add(
                    new ActuatorEndpointExposure(
                            property.name(),
                            property.value(),
                            property.sourceFile(),
                            property.line(),
                            property.profile(),
                            exposedEndpoints));
        }
        return List.copyOf(exposures);
    }

    private SourceSurface scanJavaSources(JavaSources javaSources, BaseUrlCatalog baseUrlCatalog) {
        List<InboundEndpoint> inboundEndpoints = new ArrayList<>();
        List<OutboundEndpoint> outboundEndpoints = new ArrayList<>();

        for (JavaSources.JavaFile sourceFile : javaSources.primaryFiles()) {
            if (sourceFile.compilationUnit() == null) {
                continue;
            }
            parseSourceFile(sourceFile, inboundEndpoints, outboundEndpoints, baseUrlCatalog);
        }
        return new SourceSurface(List.copyOf(inboundEndpoints), List.copyOf(outboundEndpoints));
    }

    private void parseSourceFile(
            JavaSources.JavaFile sourceFile,
            List<InboundEndpoint> inboundEndpoints,
            List<OutboundEndpoint> outboundEndpoints,
            BaseUrlCatalog baseUrlCatalog) {
        CompilationUnit compilationUnit = sourceFile.compilationUnit();
        String packageName =
                compilationUnit
                        .getPackageDeclaration()
                        .map(declaration -> declaration.getNameAsString())
                        .orElse("");
        String relativePath = sourceFile.relativePath();

        Map<String, String> valueFieldIndex = buildValueFieldIndex(compilationUnit);

        for (ClassOrInterfaceDeclaration type :
                compilationUnit.findAll(ClassOrInterfaceDeclaration.class)) {
            String className =
                    packageName.isBlank()
                            ? type.getNameAsString()
                            : packageName + "." + type.getNameAsString();
            collectInboundEndpoints(type, className, relativePath, inboundEndpoints);
            collectFeignEndpoints(type, className, relativePath, outboundEndpoints, baseUrlCatalog);
        }

        for (MethodCallExpr callExpr : compilationUnit.findAll(MethodCallExpr.class)) {
            collectOutboundEndpoint(callExpr, relativePath, baseUrlCatalog, valueFieldIndex)
                    .ifPresent(outboundEndpoints::add);
            collectFunctionalRoute(callExpr, relativePath, packageName)
                    .ifPresent(inboundEndpoints::add);
        }

        for (ObjectCreationExpr newExpr : compilationUnit.findAll(ObjectCreationExpr.class)) {
            collectSocketEndpoint(newExpr, relativePath, valueFieldIndex)
                    .ifPresent(outboundEndpoints::add);
        }
    }

    private void collectInboundEndpoints(
            ClassOrInterfaceDeclaration type,
            String className,
            String relativePath,
            List<InboundEndpoint> inboundEndpoints) {
        if (!hasAnyAnnotation(type, Set.of("RestController", "Controller"))) {
            return;
        }

        List<String> classPaths = annotationPaths(type.getAnnotations());
        if (classPaths.isEmpty()) {
            classPaths = List.of("");
        }

        for (MethodDeclaration method : type.getMethods()) {
            List<AnnotationExpr> methodAnnotations =
                    method.getAnnotations().stream()
                            .filter(
                                    annotation ->
                                            INBOUND_MAPPING_ANNOTATIONS.contains(
                                                    simpleName(annotation.getNameAsString())))
                            .toList();
            if (methodAnnotations.isEmpty()) {
                continue;
            }

            for (AnnotationExpr annotation : methodAnnotations) {
                String httpMethod = httpMethodFor(annotation);
                List<String> methodPaths = annotationPaths(List.of(annotation));
                if (methodPaths.isEmpty()) {
                    methodPaths = List.of("");
                }

                for (String classPath : classPaths) {
                    for (String methodPath : methodPaths) {
                        inboundEndpoints.add(
                                new InboundEndpoint(
                                        httpMethod,
                                        combinePaths(classPath, methodPath),
                                        className,
                                        method.getNameAsString(),
                                        relativePath,
                                        method.getBegin()
                                                .map(position -> position.line)
                                                .orElse(null),
                                        annotationStringValue(annotation, "produces"),
                                        annotationStringValue(annotation, "consumes"),
                                        method.getParameters().stream()
                                                .map(
                                                        parameter ->
                                                                parameter.getAnnotations().stream()
                                                                        .map(
                                                                                expr ->
                                                                                        "@"
                                                                                                + simpleName(
                                                                                                        expr
                                                                                                                .getNameAsString())
                                                                                                + " "
                                                                                                + parameter
                                                                                                        .getNameAsString())
                                                                        .findFirst()
                                                                        .orElse(
                                                                                parameter
                                                                                        .getNameAsString()))
                                                .toList(),
                                        EndpointSource.SPRING_MVC_ANNOTATION));
                    }
                }
            }
        }
    }

    private void collectFeignEndpoints(
            ClassOrInterfaceDeclaration type,
            String className,
            String relativePath,
            List<OutboundEndpoint> outboundEndpoints,
            BaseUrlCatalog baseUrlCatalog) {
        for (AnnotationExpr annotation : type.getAnnotations()) {
            if (!"FeignClient".equals(simpleName(annotation.getNameAsString()))
                    || !annotation.isNormalAnnotationExpr()) {
                continue;
            }
            String urlValue = annotationStringValue(annotation, "url");
            String propertyName = placeholderName(urlValue);
            BaseUrlMatch baseUrlMatch =
                    propertyName == null ? null : baseUrlCatalog.byProperty(propertyName);
            outboundEndpoints.add(
                    new OutboundEndpoint(
                            "HTTP",
                            urlValue == null ? "Feign client" : sanitizeUrlValue(urlValue),
                            baseUrlMatch != null
                                    ? baseUrlMatch.host()
                                    : hostForValue(propertyName, urlValue, UrlKind.HTTP_URL),
                            baseUrlMatch != null ? baseUrlMatch.baseUrl() : null,
                            baseUrlMatch != null
                                    ? sanitizeUrlValue(baseUrlMatch.baseUrl())
                                    : sanitizeUrlValue(urlValue),
                            "Feign",
                            relativePath,
                            annotation.getBegin().map(position -> position.line).orElse(null),
                            className,
                            null,
                            propertyName != null,
                            propertyName));
        }
    }

    private Optional<InboundEndpoint> collectFunctionalRoute(
            MethodCallExpr callExpr, String relativePath, String packageName) {
        String methodName = callExpr.getNameAsString();
        if (!List.of("GET", "POST", "PUT", "PATCH", "DELETE").contains(methodName)) {
            return Optional.empty();
        }
        if (callExpr.getArguments().isEmpty()) {
            return Optional.empty();
        }

        Optional<String> path = stringValue(callExpr.getArgument(0));
        if (path.isEmpty()) {
            return Optional.empty();
        }

        if (callExpr.findAncestor(MethodCallExpr.class)
                        .map(
                                ancestor ->
                                        ancestor.getNameAsString().equals("route")
                                                || ancestor.getNameAsString()
                                                        .equals("routeBuilder"))
                        .orElse(false)
                || callExpr.toString().contains("RequestPredicates.")) {
            return Optional.of(
                    new InboundEndpoint(
                            methodName,
                            path.get(),
                            packageName.isBlank()
                                    ? "RouterFunction"
                                    : packageName + ".RouterFunction",
                            "functional route",
                            relativePath,
                            callExpr.getBegin().map(position -> position.line).orElse(null),
                            null,
                            null,
                            List.of(),
                            EndpointSource.WEBFLUX_FUNCTIONAL_ROUTE));
        }
        return Optional.empty();
    }

    private Optional<OutboundEndpoint> collectOutboundEndpoint(
            MethodCallExpr callExpr,
            String relativePath,
            BaseUrlCatalog baseUrlCatalog,
            Map<String, String> valueFieldIndex) {
        String methodName = callExpr.getNameAsString();
        if (List.of(
                        "getForObject",
                        "getForEntity",
                        "postForObject",
                        "postForEntity",
                        "exchange",
                        "execute")
                .contains(methodName)) {
            Optional<String> url = extractUrlArgument(callExpr, 0, valueFieldIndex);
            if (url.isPresent()) {
                return Optional.of(
                        outboundEndpointFor(
                                "RestTemplate",
                                restTemplateMethod(methodName, callExpr),
                                url.get(),
                                relativePath,
                                callExpr,
                                baseUrlCatalog));
            }
        }

        if ("baseUrl".equals(methodName) || "uri".equals(methodName)) {
            Optional<String> value = extractUrlArgument(callExpr, 0, valueFieldIndex);
            if (value.isPresent()) {
                String clientType = resolveClientType(callExpr).orElse("HTTP client");
                String httpMethod =
                        inferHttpMethod(callExpr)
                                .orElse(methodName.equals("uri") ? "REQUEST" : "BASE_URL");
                return Optional.of(
                        outboundEndpointFor(
                                clientType,
                                httpMethod,
                                value.get(),
                                relativePath,
                                callExpr,
                                baseUrlCatalog));
            }
        }

        if ("newBuilder".equals(methodName)
                && callExpr.toString().contains("HttpRequest.newBuilder")) {
            Optional<String> value = extractUrlArgument(callExpr, 0, valueFieldIndex);
            if (value.isPresent()) {
                return Optional.of(
                        outboundEndpointFor(
                                "HttpClient",
                                inferHttpRequestBuilderMethod(callExpr).orElse("REQUEST"),
                                value.get(),
                                relativePath,
                                callExpr,
                                baseUrlCatalog));
            }
        }

        if ("open".equals(methodName)) {
            Optional<String> scope = callExpr.getScope().map(Expression::toString);
            if (scope.map(s -> s.equals("SocketChannel") || s.equals("AsynchronousSocketChannel"))
                    .orElse(false)) {
                String clientType = scope.get();
                String className =
                        callExpr.findAncestor(ClassOrInterfaceDeclaration.class)
                                .map(ClassOrInterfaceDeclaration::getNameAsString)
                                .orElse(null);
                String callerMethod =
                        callExpr.findAncestor(MethodDeclaration.class)
                                .map(MethodDeclaration::getNameAsString)
                                .orElse(null);
                return Optional.of(
                        new OutboundEndpoint(
                                "CONNECT",
                                null,
                                null,
                                null,
                                null,
                                clientType,
                                relativePath,
                                callExpr.getBegin().map(p -> p.line).orElse(null),
                                className,
                                callerMethod,
                                false,
                                null));
            }
        }

        if ("doHandshake".equals(methodName)) {
            // WebSocketClient.doHandshake(handler, headers, uri) — URI is the last String/URI arg
            for (int i = callExpr.getArguments().size() - 1; i >= 0; i--) {
                Optional<String> url = extractUrlArgument(callExpr, i, valueFieldIndex);
                if (url.isPresent() && looksLikeWebSocketUrl(url.get())) {
                    String className =
                            callExpr.findAncestor(ClassOrInterfaceDeclaration.class)
                                    .map(ClassOrInterfaceDeclaration::getNameAsString)
                                    .orElse(null);
                    String callerMethod =
                            callExpr.findAncestor(MethodDeclaration.class)
                                    .map(MethodDeclaration::getNameAsString)
                                    .orElse(null);
                    return Optional.of(
                            new OutboundEndpoint(
                                    "WS",
                                    url.get(),
                                    tryHostFromUrl(url.get()),
                                    null,
                                    url.get(),
                                    "WebSocket",
                                    relativePath,
                                    callExpr.getBegin().map(p -> p.line).orElse(null),
                                    className,
                                    callerMethod,
                                    false,
                                    null));
                }
            }
        }

        return Optional.empty();
    }

    private Optional<OutboundEndpoint> collectSocketEndpoint(
            ObjectCreationExpr newExpr, String relativePath, Map<String, String> valueFieldIndex) {
        String typeName = newExpr.getType().getNameAsString();
        Integer line = newExpr.getBegin().map(p -> p.line).orElse(null);
        String className =
                newExpr.findAncestor(ClassOrInterfaceDeclaration.class)
                        .map(ClassOrInterfaceDeclaration::getNameAsString)
                        .orElse(null);
        String callerMethod =
                newExpr.findAncestor(MethodDeclaration.class)
                        .map(MethodDeclaration::getNameAsString)
                        .orElse(null);

        return switch (typeName) {
            case "Socket" -> {
                if (newExpr.getArguments().isEmpty()) yield Optional.empty();
                String host = resolveStringArgOrField(newExpr.getArgument(0), valueFieldIndex);
                String port =
                        newExpr.getArguments().size() > 1
                                ? resolvePortArg(newExpr.getArgument(1), valueFieldIndex)
                                : null;
                String url =
                        host != null
                                ? (port != null ? host + ":" + port : host)
                                : (port != null ? ":" + port : null);
                if (url == null) yield Optional.empty();
                yield Optional.of(
                        new OutboundEndpoint(
                                "CONNECT",
                                url,
                                host,
                                null,
                                null,
                                "Socket",
                                relativePath,
                                line,
                                className,
                                callerMethod,
                                false,
                                null));
            }
            case "ServerSocket" -> {
                if (newExpr.getArguments().isEmpty()) yield Optional.empty();
                String port = resolvePortArg(newExpr.getArgument(0), valueFieldIndex);
                if (port == null) yield Optional.empty();
                yield Optional.of(
                        new OutboundEndpoint(
                                "LISTEN",
                                ":" + port,
                                null,
                                null,
                                null,
                                "ServerSocket",
                                relativePath,
                                line,
                                className,
                                callerMethod,
                                false,
                                null));
            }
            case "ReactorNettyWebSocketClient",
                    "StandardWebSocketClient",
                    "JettyWebSocketClient",
                    "SockJsClient",
                    "TomcatWebSocketClient",
                    "UndertowWebSocketClient" ->
                    Optional.of(
                            new OutboundEndpoint(
                                    "WS",
                                    null,
                                    null,
                                    null,
                                    null,
                                    "WebSocket (" + typeName + ")",
                                    relativePath,
                                    line,
                                    className,
                                    callerMethod,
                                    false,
                                    null));
            default -> Optional.empty();
        };
    }

    private String resolveStringArgOrField(Expression arg, Map<String, String> valueFieldIndex) {
        Optional<String> literal = stringValue(arg);
        if (literal.isPresent()) {
            return literal.get();
        }
        if (arg.isNameExpr()) {
            String key = valueFieldIndex.get(arg.asNameExpr().getNameAsString());
            if (key != null) {
                return "${" + key + "}";
            }
        }
        if (arg.isFieldAccessExpr()) {
            String key = valueFieldIndex.get(arg.asFieldAccessExpr().getNameAsString());
            if (key != null) {
                return "${" + key + "}";
            }
        }
        return null;
    }

    private String resolvePortArg(Expression arg, Map<String, String> valueFieldIndex) {
        if (arg.isIntegerLiteralExpr()) {
            return String.valueOf(arg.asIntegerLiteralExpr().asInt());
        }
        if (arg.isNameExpr()) {
            String key = valueFieldIndex.get(arg.asNameExpr().getNameAsString());
            if (key != null) {
                return "${" + key + "}";
            }
        }
        return null;
    }

    private boolean looksLikeWebSocketUrl(String value) {
        if (value == null) {
            return false;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.startsWith("ws://")
                || lower.startsWith("wss://")
                || lower.startsWith("http://")
                || lower.startsWith("https://")
                || lower.startsWith("${");
    }

    private static String tryHostFromUrl(String value) {
        if (value == null || value.startsWith("${")) {
            return null;
        }
        return BaseUrlCatalog.tryHost(value);
    }

    private Map<String, String> buildValueFieldIndex(CompilationUnit compilationUnit) {
        Map<String, String> index = new HashMap<>();
        for (FieldDeclaration field : compilationUnit.findAll(FieldDeclaration.class)) {
            for (AnnotationExpr annotation : field.getAnnotations()) {
                if (!"Value".equals(simpleName(annotation.getNameAsString()))) {
                    continue;
                }
                String valueExpr = annotationSingleOrDefaultStringValue(annotation);
                if (valueExpr == null) {
                    continue;
                }
                Matcher matcher = PLACEHOLDER_PATTERN.matcher(valueExpr);
                if (!matcher.find()) {
                    continue;
                }
                String propertyKey = matcher.group(1);
                for (var variable : field.getVariables()) {
                    index.put(variable.getNameAsString(), propertyKey);
                }
            }
        }
        return index.isEmpty() ? Map.of() : Map.copyOf(index);
    }

    private String annotationSingleOrDefaultStringValue(AnnotationExpr annotation) {
        if (annotation.isSingleMemberAnnotationExpr()) {
            return stringValue(annotation.asSingleMemberAnnotationExpr().getMemberValue())
                    .orElse(null);
        }
        return annotationStringValue(annotation, "value");
    }

    private OutboundEndpoint outboundEndpointFor(
            String clientType,
            String method,
            String rawValue,
            String relativePath,
            MethodCallExpr callExpr,
            BaseUrlCatalog baseUrlCatalog) {
        String propertyName = placeholderName(rawValue);
        String className =
                callExpr.findAncestor(ClassOrInterfaceDeclaration.class)
                        .map(ClassOrInterfaceDeclaration::getNameAsString)
                        .orElse(null);
        String baseUrlHint = baseUrlHint(callExpr);
        BaseUrlMatch baseUrlMatch =
                resolveBaseUrl(
                        rawValue,
                        propertyName,
                        className,
                        relativePath,
                        baseUrlHint,
                        baseUrlCatalog);
        String sanitizedValue = sanitizeUrlValue(rawValue);
        return new OutboundEndpoint(
                method.toUpperCase(Locale.ROOT),
                sanitizedValue,
                baseUrlMatch != null
                        ? baseUrlMatch.host()
                        : hostForValue(propertyName, rawValue, UrlKind.HTTP_URL),
                baseUrlMatch != null ? baseUrlMatch.baseUrl() : null,
                buildFullUrlPreview(rawValue, baseUrlMatch),
                clientType,
                relativePath,
                callExpr.getBegin().map(position -> position.line).orElse(null),
                className,
                callExpr.findAncestor(MethodDeclaration.class)
                        .map(MethodDeclaration::getNameAsString)
                        .orElse(null),
                propertyName != null || baseUrlMatch != null,
                propertyName != null
                        ? propertyName
                        : (baseUrlMatch == null ? null : baseUrlMatch.propertyName()));
    }

    private void addModuleHttpRuntimeFindings(
            List<InboundEndpoint> inboundEndpoints,
            WebStack webStack,
            String modulePath,
            List<Finding> findings) {
        if (!inboundEndpoints.isEmpty()
                && (webStack == WebStack.NON_WEB || webStack == WebStack.UNKNOWN)) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_INBOUND_ENDPOINTS_IN_NON_WEB_APP,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "Inbound HTTP endpoints were detected in code, but module "
                                            + modulePath
                                            + " does not look like a web application.")
                            .whyBadPractice(
                                    "Controller mappings are only served when a web application"
                                            + " context starts. Without a web starter — or with"
                                            + " spring.main.web-application-type=none — no embedded"
                                            + " server is created and the mappings are never"
                                            + " registered.")
                            .possibleImpact(
                                    "Endpoints that look implemented return nothing because no"
                                            + " server is listening; callers see connection"
                                            + " failures rather than HTTP errors.")
                            .recommendation(
                                    "Add spring-boot-starter-web (or webflux) to this module if the"
                                            + " endpoints are meant to be served, or remove the"
                                            + " controllers if it is intentionally non-web.")
                            .evidence(
                                    inboundEndpoints.size()
                                            + " inbound endpoints were detected in module "
                                            + modulePath
                                            + " while its resolved web stack is "
                                            + webStack
                                            + ".")
                            .limitations(
                                    "The module web stack is inferred from static dependencies and"
                                            + " module-owned configuration; a custom server setup"
                                            + " may still serve the endpoints.")
                            .location(inboundEndpoints.get(0).sourceFile())
                            .target("inbound HTTP endpoints")
                            .build());
        }

        if (inboundEndpoints.isEmpty()
                && (webStack == WebStack.SERVLET_MVC
                        || webStack == WebStack.REACTIVE_WEBFLUX
                        || webStack == WebStack.MIXED_MVC_AND_WEBFLUX)) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_WEB_STACK_WITHOUT_ENDPOINTS,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    "Module "
                                            + modulePath
                                            + " has a web runtime stack but no inbound HTTP"
                                            + " endpoints were found.")
                            .whyBadPractice(
                                    "The application starts an embedded web server and holds the"
                                            + " port, but exposes no application endpoints of its"
                                            + " own.")
                            .possibleImpact(
                                    "Wasted memory and an open port with only framework/actuator"
                                            + " endpoints reachable. In a non-web service this is"
                                            + " usually an unintended dependency.")
                            .recommendation(
                                    "Remove the web starter if the module does not serve HTTP, or"
                                            + " set spring.main.web-application-type=none.")
                            .evidence(
                                    "Resolved module "
                                            + modulePath
                                            + " web stack "
                                            + webStack
                                            + " with no @RequestMapping-style inbound endpoints"
                                            + " detected.")
                            .limitations(
                                    "Endpoints registered programmatically (RouterFunction beans,"
                                            + " servlet registrations) may not be detected.")
                            .target("HTTP surface")
                            .location("HTTP surface: " + modulePath)
                            .build());
        }
    }

    private void addHttpFindings(
            BuildInfo buildInfo,
            WebStack webStack,
            List<ModuleRuntimeStackAnalysis> moduleRuntimeStacks,
            List<InboundEndpoint> inboundEndpoints,
            List<ConfiguredUrl> configuredUrls,
            List<ActuatorEndpointExposure> actuatorExposures,
            List<OutboundEndpoint> outboundEndpoints,
            List<Finding> findings) {
        if (moduleRuntimeStacks == null || moduleRuntimeStacks.isEmpty()) {
            addModuleHttpRuntimeFindings(inboundEndpoints, webStack, "repository", findings);
        } else {
            Map<String, List<InboundEndpoint>> inboundByModule =
                    inboundEndpoints.stream()
                            .collect(
                                    Collectors.groupingBy(
                                            endpoint ->
                                                    BuildModuleResolver.modulePathFor(
                                                            endpoint.sourceFile(), buildInfo),
                                            LinkedHashMap::new,
                                            Collectors.toList()));
            for (ModuleRuntimeStackAnalysis moduleRuntime : moduleRuntimeStacks) {
                addModuleHttpRuntimeFindings(
                        inboundByModule.getOrDefault(moduleRuntime.modulePath(), List.of()),
                        moduleRuntime.webStack(),
                        moduleRuntime.modulePath(),
                        findings);
            }
        }

        // Note: the MVC+WebFlux mix is reported once by RuntimeStackAnalyzer as
        // SPRING_MIXED_MVC_AND_WEBFLUX (the web-stack authority); it is not duplicated here.

        long insecureUrlCount =
                Stream.concat(
                                configuredUrls.stream()
                                        .filter(this::isReportablePlainHttpConfiguredUrl)
                                        .map(ConfiguredUrl::value),
                                outboundEndpoints.stream()
                                        .filter(this::isReportablePlainHttpOutbound)
                                        .map(OutboundEndpoint::urlOrTemplate))
                        .filter(Objects::nonNull)
                        .filter(value -> value.startsWith("http://"))
                        .count();
        if (insecureUrlCount > 0) {
            List<FindingOccurrence> occurrences = new ArrayList<>();
            configuredUrls.stream()
                    .filter(this::isReportablePlainHttpConfiguredUrl)
                    .forEach(
                            url ->
                                    occurrences.add(
                                            configuredUrlOccurrence(
                                                    url,
                                                    "Configured plain HTTP URL: "
                                                            + url.propertyName()
                                                            + "="
                                                            + sanitizeUrlValue(url.value()))));
            outboundEndpoints.stream()
                    .filter(this::isReportablePlainHttpOutbound)
                    .forEach(
                            endpoint ->
                                    occurrences.add(
                                            outboundEndpointOccurrence(
                                                    endpoint,
                                                    "Outbound plain HTTP call: "
                                                            + endpoint.method()
                                                            + " "
                                                            + sanitizeUrlValue(
                                                                    endpoint.urlOrTemplate()))));

            FindingFactory.Builder builder =
                    FindingFactory.builder(
                                    FindingRules.SPRING_HTTP_PLAIN_URL, FindingConfidence.HIGH)
                            .shortMessage(
                                    insecureUrlCount
                                            + " external HTTP endpoints use plain http:// instead"
                                            + " of https://.")
                            .whyBadPractice(
                                    "Plain HTTP can expose traffic to interception or modification"
                                            + " outside trusted local environments.")
                            .possibleImpact(
                                    "Credentials, tokens, and business data can cross the network"
                                        + " without transport security when these endpoints are"
                                        + " used outside local or tightly controlled environments.")
                            .recommendation(
                                    "Use HTTPS for external service URLs unless the endpoint is"
                                            + " intentionally local or behind a trusted internal"
                                            + " network.")
                            .evidence(
                                    "Configured URLs and outbound endpoint templates included"
                                            + " external plain HTTP addresses outside localhost and"
                                            + " test-only configuration.")
                            .limitations(
                                    "Static analysis cannot prove the full network topology or"
                                            + " whether an internal transport layer adds encryption"
                                            + " outside the application configuration.")
                            .target("external HTTP URLs")
                            .location("HTTP surface")
                            .occurrences(occurrences);
            if (!occurrences.isEmpty()) {
                builder.sourceLocation(occurrences.get(0).location());
            }
            findings.add(builder.build());
        }

        long querySecretCount =
                Stream.concat(
                                configuredUrls.stream().map(ConfiguredUrl::value),
                                outboundEndpoints.stream().map(OutboundEndpoint::urlOrTemplate))
                        .filter(Objects::nonNull)
                        .filter(value -> URL_WITH_QUERY_PATTERN.matcher(value).find())
                        .count();
        if (querySecretCount > 0) {
            findings.add(
                    FindingFactory.builder(
                                    FindingRules.SPRING_OUTBOUND_URL_CREDENTIALS_IN_QUERY,
                                    FindingConfidence.MEDIUM)
                            .shortMessage(
                                    querySecretCount
                                            + " outbound URLs contain credential-like query"
                                            + " parameters.")
                            .whyBadPractice(
                                    "Query strings are part of the request line, so proxies, load"
                                        + " balancers, CDNs, and the application's own access logs"
                                        + " record them verbatim. A credential placed there is"
                                        + " copied into every one of those log stores.")
                            .possibleImpact(
                                    "API keys and tokens end up in log aggregation systems with"
                                        + " weaker access control than the secret store, and stay"
                                        + " there for the full retention period.")
                            .recommendation(
                                    "Send credentials in an Authorization header or request body"
                                            + " instead of the URL, and rotate any secret that has"
                                            + " already been logged.")
                            .evidence(
                                    querySecretCount
                                            + " configured or outbound URLs matched a"
                                            + " credential-like query parameter pattern.")
                            .limitations(
                                    "Parameter names are matched heuristically; a parameter named"
                                            + " like a credential may hold a harmless value.")
                            .target("outbound URLs")
                            .location("HTTP surface")
                            .build());
        }

        // Note: wildcard actuator exposure is reported by SPRING_ACTUATOR_ENDPOINT_EXPOSED_PROD
        // in ConfigurationFindingAnalyzer; it is not duplicated here.
    }

    private ConfiguredUrlMetadata classifyConfiguredUrl(
            String propertyName, String value, boolean valueRedacted) {
        String normalizedName = propertyName == null ? "" : propertyName.toLowerCase(Locale.ROOT);
        String normalizedValue = value.toLowerCase(Locale.ROOT);
        String referencedPropertyName = placeholderName(value);

        if (valueRedacted && !isSafeLiteralUrl(value)) {
            return ConfiguredUrlMetadata.none();
        }
        if (isSensitivePropertyName(normalizedName) && !isSafeLiteralUrl(value)) {
            return ConfiguredUrlMetadata.none();
        }
        if (referencedPropertyName != null) {
            if (normalizedName.endsWith(".url")
                    || normalizedName.endsWith(".uri")
                    || normalizedName.endsWith(".endpoint")
                    || normalizedName.endsWith(".base-url")
                    || normalizedName.equals("spring.flyway.url")) {
                return new ConfiguredUrlMetadata(
                        UrlKind.PROPERTY_REFERENCE, null, referencedPropertyName);
            }
            if (normalizedName.contains("provider")) {
                return ConfiguredUrlMetadata.none();
            }
        }
        if (normalizedValue.startsWith("jdbc:") || normalizedName.equals("spring.datasource.url")) {
            return new ConfiguredUrlMetadata(UrlKind.JDBC_URL, null, referencedPropertyName);
        }
        if (normalizedValue.startsWith("http://")
                || normalizedValue.startsWith("https://")
                || normalizedValue.startsWith("ws://")
                || normalizedValue.startsWith("wss://")) {
            if (normalizedName.contains("issuer-uri")
                    || normalizedName.contains("introspection-uri")) {
                return new ConfiguredUrlMetadata(
                        UrlKind.OAUTH_OIDC_URL, null, referencedPropertyName);
            }
            if (normalizedName.contains("zipkin") || normalizedName.contains("otlp")) {
                return new ConfiguredUrlMetadata(
                        UrlKind.OBSERVABILITY_ENDPOINT, null, referencedPropertyName);
            }
            return new ConfiguredUrlMetadata(UrlKind.HTTP_URL, null, referencedPropertyName);
        }
        if (normalizedName.equals("spring.mail.host")) {
            return new ConfiguredUrlMetadata(
                    UrlKind.MAIL_HOST, firstHostToken(value), referencedPropertyName);
        }
        if (normalizedName.contains("bootstrap-servers")
                || normalizedName.contains("rabbitmq.host")
                || normalizedName.contains("rabbitmq.addresses")
                || normalizedName.contains("kafka.bootstrap-servers")) {
            return new ConfiguredUrlMetadata(
                    UrlKind.MESSAGE_BROKER_URL, firstHostToken(value), referencedPropertyName);
        }
        if (normalizedName.contains("redis.host")) {
            return new ConfiguredUrlMetadata(
                    UrlKind.REDIS_HOST, firstHostToken(value), referencedPropertyName);
        }
        if (normalizedName.endsWith(".url")
                || normalizedName.endsWith(".base-url")
                || normalizedName.endsWith(".uri")
                || normalizedName.endsWith(".endpoint")) {
            return new ConfiguredUrlMetadata(UrlKind.OTHER, null, referencedPropertyName);
        }
        if ((normalizedName.endsWith(".host")
                        || normalizedName.endsWith(".hosts")
                        || normalizedName.endsWith(".server")
                        || normalizedName.endsWith(".servers"))
                && !normalizedName.endsWith(".provider")
                && !normalizedName.contains("api-key")
                && !normalizedName.contains("api-secret")
                && !normalizedName.endsWith(".secret")) {
            return new ConfiguredUrlMetadata(
                    UrlKind.OTHER, firstHostToken(value), referencedPropertyName);
        }
        return ConfiguredUrlMetadata.none();
    }

    private String sanitizeUrlValue(String value) {
        if (value == null) {
            return null;
        }
        Matcher matcher = URL_WITH_QUERY_PATTERN.matcher(value);
        return matcher.replaceAll("$1$2=[redacted]");
    }

    private String hostForValue(String propertyName, String value, UrlKind kind) {
        if (value == null || value.isBlank() || value.contains("${")) {
            return null;
        }
        String normalizedName = propertyName == null ? "" : propertyName.toLowerCase(Locale.ROOT);
        if (kind == UrlKind.MAIL_HOST
                || kind == UrlKind.REDIS_HOST
                || kind == UrlKind.MESSAGE_BROKER_URL
                || normalizedName.endsWith(".host")) {
            return firstHostToken(value);
        }
        try {
            if (value.startsWith("jdbc:")) {
                String jdbcValue = value.substring(5);
                if (jdbcValue.startsWith("postgresql://") || jdbcValue.startsWith("mysql://")) {
                    return URI.create("http://" + jdbcValue.substring(jdbcValue.indexOf("://") + 3))
                            .getHost();
                }
                return null;
            }
            URI uri = new URI(value);
            return uri.getHost();
        } catch (URISyntaxException ignored) {
            return null;
        }
    }

    private String firstHostToken(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String candidate = value.split(",")[0].trim();
        int slashIndex = candidate.indexOf('/');
        if (slashIndex >= 0) {
            candidate = candidate.substring(0, slashIndex);
        }
        int colonIndex = candidate.indexOf(':');
        if (colonIndex >= 0) {
            candidate = candidate.substring(0, colonIndex);
        }
        return candidate.isBlank() ? null : candidate;
    }

    private String basePathOf(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        String[] segments = normalized.split("/");
        return segments.length > 1 && !segments[1].isBlank() ? "/" + segments[1] : normalized;
    }

    private Optional<String> resolveClientType(MethodCallExpr callExpr) {
        String rendered = callExpr.toString();
        if (rendered.contains("WebClient")) {
            return Optional.of("WebClient");
        }
        if (rendered.contains("RestClient")) {
            return Optional.of("RestClient");
        }
        if (rendered.contains("OkHttp")) {
            return Optional.of("OkHttp");
        }
        return Optional.empty();
    }

    private Optional<String> inferHttpMethod(MethodCallExpr callExpr) {
        if (List.of("get", "post", "put", "patch", "delete").contains(callExpr.getNameAsString())) {
            return Optional.of(callExpr.getNameAsString().toUpperCase(Locale.ROOT));
        }
        Expression current = callExpr;
        while (current != null) {
            if (current instanceof MethodCallExpr currentCall) {
                String candidate = currentCall.getNameAsString().toUpperCase(Locale.ROOT);
                if (List.of("GET", "POST", "PUT", "PATCH", "DELETE").contains(candidate)) {
                    return Optional.of(candidate);
                }
                current = currentCall.getScope().orElse(null);
            } else {
                current = null;
            }
        }
        return Optional.empty();
    }

    private String restTemplateMethod(String methodName, MethodCallExpr callExpr) {
        return switch (methodName) {
            case "getForObject", "getForEntity" -> "GET";
            case "postForObject", "postForEntity" -> "POST";
            case "exchange" -> extractRequestMethod(callExpr).orElse("REQUEST");
            case "execute" -> "REQUEST";
            default -> "REQUEST";
        };
    }

    private Optional<String> extractRequestMethod(MethodCallExpr callExpr) {
        for (Expression argument : callExpr.getArguments()) {
            String rendered = argument.toString();
            if (rendered.startsWith("HttpMethod.")) {
                return Optional.of(
                        rendered.substring("HttpMethod.".length()).toUpperCase(Locale.ROOT));
            }
            if (rendered.startsWith("RequestMethod.")) {
                return Optional.of(
                        rendered.substring("RequestMethod.".length()).toUpperCase(Locale.ROOT));
            }
        }
        return Optional.empty();
    }

    private Optional<String> inferHttpRequestBuilderMethod(MethodCallExpr callExpr) {
        var current = callExpr.getParentNode().orElse(null);
        while (current != null) {
            if (current instanceof MethodCallExpr currentCall) {
                String name = currentCall.getNameAsString().toUpperCase(Locale.ROOT);
                if (List.of("GET", "POST", "PUT", "DELETE").contains(name)) {
                    return Optional.of(name);
                }
            }
            current = current.getParentNode().orElse(null);
        }
        return Optional.empty();
    }

    private Optional<String> extractUrlArgument(
            MethodCallExpr callExpr, int index, Map<String, String> valueFieldIndex) {
        Optional<String> result = extractUrlArgument(callExpr, index);
        if (result.isPresent()) {
            return result;
        }
        if (callExpr.getArguments().size() <= index) {
            return Optional.empty();
        }
        Expression arg = callExpr.getArgument(index);
        if (arg.isNameExpr()) {
            String key = valueFieldIndex.get(arg.asNameExpr().getNameAsString());
            if (key != null) {
                return Optional.of("${" + key + "}");
            }
        }
        if (arg.isFieldAccessExpr()) {
            String key = valueFieldIndex.get(arg.asFieldAccessExpr().getNameAsString());
            if (key != null) {
                return Optional.of("${" + key + "}");
            }
        }
        return Optional.empty();
    }

    private Optional<String> extractUrlArgument(MethodCallExpr callExpr, int index) {
        if (callExpr.getArguments().size() <= index) {
            return Optional.empty();
        }
        Expression argument = callExpr.getArgument(index);
        Optional<String> literal = stringValue(argument);
        if (literal.isPresent()) {
            return literal;
        }
        if (argument.isMethodCallExpr()
                && "create".equals(argument.asMethodCallExpr().getNameAsString())
                && argument.asMethodCallExpr()
                        .getScope()
                        .map(scope -> scope.toString().equals("URI"))
                        .orElse(false)
                && !argument.asMethodCallExpr().getArguments().isEmpty()) {
            return urlLikeValue(argument.asMethodCallExpr().getArgument(0));
        }
        if (argument.isObjectCreationExpr()
                && argument.asObjectCreationExpr().getType().getNameAsString().equals("URI")
                && !argument.asObjectCreationExpr().getArguments().isEmpty()) {
            return urlLikeValue(argument.asObjectCreationExpr().getArgument(0));
        }
        return Optional.empty();
    }

    private Optional<String> urlLikeValue(Expression expression) {
        Optional<String> literal = stringValue(expression);
        if (literal.isPresent()) {
            return literal;
        }
        if (expression.isBinaryExpr()) {
            return relativePathFromBinaryExpression(expression.asBinaryExpr());
        }
        return Optional.empty();
    }

    private Optional<String> relativePathFromBinaryExpression(BinaryExpr expression) {
        Optional<String> left = relativePathToken(expression.getLeft());
        Optional<String> right = relativePathToken(expression.getRight());
        if (left.isPresent() && right.isPresent()) {
            return Optional.of(combineRelativeUrlParts(left.get(), right.get()));
        }
        return left.isPresent() ? left : right;
    }

    private Optional<String> relativePathToken(Expression expression) {
        Optional<String> literal = stringValue(expression);
        if (literal.isPresent()) {
            String value = literal.get();
            if (value.startsWith("/")) {
                return Optional.of(value);
            }
            return Optional.empty();
        }
        if (expression.isBinaryExpr()) {
            return relativePathFromBinaryExpression(expression.asBinaryExpr());
        }
        if (expression.isNameExpr()
                || expression.isMethodCallExpr()
                || expression.isFieldAccessExpr()) {
            return Optional.of("");
        }
        return Optional.empty();
    }

    private String combineRelativeUrlParts(String left, String right) {
        if (left.isBlank()) {
            return right;
        }
        if (right.isBlank()) {
            return left;
        }
        if (left.endsWith("/") && right.startsWith("/")) {
            return left.substring(0, left.length() - 1) + right;
        }
        if (!left.endsWith("/") && !right.startsWith("/")) {
            return left + "/" + right;
        }
        return left + right;
    }

    private String httpMethodFor(AnnotationExpr annotation) {
        String annotationName = simpleName(annotation.getNameAsString());
        return switch (annotationName) {
            case "GetMapping" -> "GET";
            case "PostMapping" -> "POST";
            case "PutMapping" -> "PUT";
            case "PatchMapping" -> "PATCH";
            case "DeleteMapping" -> "DELETE";
            case "RequestMapping" ->
                    annotationStringValue(annotation, "method") == null
                            ? "ANY"
                            : annotationStringValue(annotation, "method")
                                    .replace("RequestMethod.", "");
            default -> "ANY";
        };
    }

    private List<String> annotationPaths(List<AnnotationExpr> annotations) {
        List<String> paths = new ArrayList<>();
        for (AnnotationExpr annotation : annotations) {
            String annotationName = simpleName(annotation.getNameAsString());
            if (!INBOUND_MAPPING_ANNOTATIONS.contains(annotationName)) {
                continue;
            }
            if (annotation.isSingleMemberAnnotationExpr()) {
                stringValue(annotation.asSingleMemberAnnotationExpr().getMemberValue())
                        .ifPresent(paths::add);
            } else if (annotation.isNormalAnnotationExpr()) {
                for (MemberValuePair pair : annotation.asNormalAnnotationExpr().getPairs()) {
                    if ("value".equals(pair.getNameAsString())
                            || "path".equals(pair.getNameAsString())) {
                        extractStringValues(pair.getValue()).forEach(paths::add);
                    }
                }
            }
        }
        return paths;
    }

    private String annotationStringValue(AnnotationExpr annotation, String memberName) {
        if (!annotation.isNormalAnnotationExpr()) {
            return null;
        }
        for (MemberValuePair pair : annotation.asNormalAnnotationExpr().getPairs()) {
            if (memberName.equals(pair.getNameAsString())) {
                return stringValue(pair.getValue())
                        .orElseGet(
                                () ->
                                        extractStringValues(pair.getValue()).stream()
                                                .collect(Collectors.joining(", ")));
            }
        }
        return null;
    }

    private boolean hasAnyAnnotation(ClassOrInterfaceDeclaration declaration, Set<String> names) {
        return declaration.getAnnotations().stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .anyMatch(names::contains);
    }

    private List<String> extractStringValues(Expression expression) {
        if (expression.isStringLiteralExpr()) {
            return List.of(expression.asStringLiteralExpr().asString());
        }
        if (expression.isArrayInitializerExpr()) {
            return expression.asArrayInitializerExpr().getValues().stream()
                    .map(this::stringValue)
                    .flatMap(Optional::stream)
                    .toList();
        }
        return List.of();
    }

    private Optional<String> stringValue(Expression expression) {
        if (expression.isStringLiteralExpr()) {
            return Optional.of(expression.asStringLiteralExpr().asString());
        }
        return Optional.empty();
    }

    private String combinePaths(String classPath, String methodPath) {
        String left = classPath == null ? "" : classPath.trim();
        String right = methodPath == null ? "" : methodPath.trim();
        if (left.isBlank() && right.isBlank()) {
            return "/";
        }
        String combined =
                (left.startsWith("/") ? left : "/" + left)
                        + (right.isBlank() ? "" : (right.startsWith("/") ? right : "/" + right));
        return combined.replaceAll("//+", "/");
    }

    private List<String> splitCsv(String value) {
        return Stream.of(value.split(","))
                .map(String::trim)
                .filter(entry -> !entry.isBlank())
                .toList();
    }

    private String placeholderName(String value) {
        if (value == null) {
            return null;
        }
        Matcher matcher = PLACEHOLDER_PATTERN.matcher(value);
        return matcher.find() ? matcher.group(1) : null;
    }

    private boolean isSensitivePropertyName(String normalizedName) {
        return SENSITIVE_NAME_MARKERS.stream().anyMatch(normalizedName::contains);
    }

    private boolean isReportablePlainHttpConfiguredUrl(ConfiguredUrl configuredUrl) {
        if (configuredUrl == null
                || configuredUrl.value() == null
                || !configuredUrl.value().startsWith("http://")) {
            return false;
        }
        if (isLocalHost(configuredUrl.host())) {
            return false;
        }
        String profile =
                configuredUrl.profile() == null
                        ? ""
                        : configuredUrl.profile().toLowerCase(Locale.ROOT);
        String sourceFile =
                configuredUrl.sourceFile() == null
                        ? ""
                        : configuredUrl.sourceFile().toLowerCase(Locale.ROOT);
        return !profile.equals("test")
                && !sourceFile.contains("src/test/resources")
                && !configuredUrl.value().toLowerCase(Locale.ROOT).contains("localhost/mock");
    }

    private boolean isReportablePlainHttpOutbound(OutboundEndpoint endpoint) {
        return endpoint != null
                && endpoint.urlOrTemplate() != null
                && endpoint.urlOrTemplate().startsWith("http://")
                && !isLocalHost(endpoint.host());
    }

    private boolean isLocalHost(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String normalized = host.toLowerCase(Locale.ROOT);
        return normalized.equals("localhost")
                || normalized.equals("127.0.0.1")
                || normalized.equals("::1");
    }

    private boolean isSafeLiteralUrl(String value) {
        if (value == null) {
            return false;
        }
        String normalized = value.toLowerCase(Locale.ROOT);
        return normalized.startsWith("http://")
                || normalized.startsWith("https://")
                || normalized.startsWith("ws://")
                || normalized.startsWith("wss://")
                || normalized.startsWith("jdbc:");
    }

    private BaseUrlMatch resolveBaseUrl(
            String rawValue,
            String propertyName,
            String className,
            String sourceFile,
            String baseUrlHint,
            BaseUrlCatalog baseUrlCatalog) {
        if (propertyName != null) {
            BaseUrlMatch direct = baseUrlCatalog.byProperty(propertyName);
            if (direct != null) {
                return direct;
            }
        }
        if (!rawValue.startsWith("/")) {
            return null;
        }
        return baseUrlCatalog.bestMatchForClass(className, sourceFile, baseUrlHint);
    }

    private String baseUrlHint(MethodCallExpr callExpr) {
        for (Expression candidate = callExpr; candidate != null; ) {
            if (candidate instanceof MethodCallExpr currentCall) {
                if ("baseUrl".equals(currentCall.getNameAsString())
                        && !currentCall.getArguments().isEmpty()) {
                    return currentCall.getArgument(0).toString();
                }
                if ("newBuilder".equals(currentCall.getNameAsString())
                        && currentCall.toString().contains("HttpRequest.newBuilder")
                        && !currentCall.getArguments().isEmpty()) {
                    return extractBaseUrlHint(currentCall.getArgument(0));
                }
                candidate = currentCall.getScope().orElse(null);
            } else {
                candidate = null;
            }
        }
        return callExpr.findAncestor(MethodDeclaration.class)
                .map(MethodDeclaration::toString)
                .map(this::bestBaseUrlHintFromMethodBody)
                .orElse(null);
    }

    private String extractBaseUrlHint(Expression expression) {
        if (expression.isMethodCallExpr()
                && "create".equals(expression.asMethodCallExpr().getNameAsString())
                && !expression.asMethodCallExpr().getArguments().isEmpty()) {
            return extractBaseUrlHint(expression.asMethodCallExpr().getArgument(0));
        }
        if (expression.isObjectCreationExpr()
                && !expression.asObjectCreationExpr().getArguments().isEmpty()) {
            return extractBaseUrlHint(expression.asObjectCreationExpr().getArgument(0));
        }
        if (expression.isBinaryExpr()) {
            Expression left = expression.asBinaryExpr().getLeft();
            String leftText = left.toString();
            return leftText.startsWith("\"") ? null : leftText;
        }
        String rendered = expression.toString();
        return rendered.startsWith("\"") ? null : rendered;
    }

    private String bestBaseUrlHintFromMethodBody(String methodBody) {
        if (methodBody == null || methodBody.isBlank()) {
            return null;
        }
        Pattern pattern = Pattern.compile("(\\w+(?:\\.\\w+)*)\\s*\\+\\s*\"/[^\"]*\"");
        Matcher matcher = pattern.matcher(methodBody);
        return matcher.find() ? matcher.group(1) : null;
    }

    private String buildFullUrlPreview(String rawValue, BaseUrlMatch baseUrlMatch) {
        if (baseUrlMatch == null) {
            if (rawValue.startsWith("/")) {
                return null;
            }
            return sanitizeUrlValue(rawValue);
        }
        if (rawValue.startsWith("/")) {
            String combined =
                    baseUrlMatch.baseUrl().endsWith("/")
                            ? baseUrlMatch
                                            .baseUrl()
                                            .substring(0, baseUrlMatch.baseUrl().length() - 1)
                                    + rawValue
                            : baseUrlMatch.baseUrl() + rawValue;
            return sanitizeUrlValue(combined);
        }
        return sanitizeUrlValue(rawValue);
    }

    private String simpleName(String value) {
        int separatorIndex = value.lastIndexOf('.');
        return separatorIndex < 0 ? value : value.substring(separatorIndex + 1);
    }

    private FindingOccurrence configuredUrlOccurrence(ConfiguredUrl configuredUrl, String message) {
        Integer line = configuredUrl.line();
        SourceLocation location =
                new SourceLocation(
                        configuredUrl.sourceFile(),
                        line != null && line > 0 ? line : 0,
                        line != null && line > 0 ? line : 0,
                        null,
                        null,
                        configuredUrl.propertyName(),
                        SourceLocation.inferLanguage(configuredUrl.sourceFile()),
                        null);
        List<HighlightRange> ranges =
                line != null && line > 0
                        ? List.of(new HighlightRange(line, line, null, null, "issue"))
                        : List.of();
        return new FindingOccurrence(message, location, ranges);
    }

    private FindingOccurrence outboundEndpointOccurrence(
            OutboundEndpoint endpoint, String message) {
        Integer line = endpoint.line();
        String symbol =
                Stream.of(endpoint.className(), endpoint.methodName())
                        .filter(Objects::nonNull)
                        .collect(Collectors.joining("#"));
        SourceLocation location =
                new SourceLocation(
                        endpoint.sourceFile(),
                        line != null && line > 0 ? line : 0,
                        line != null && line > 0 ? line : 0,
                        null,
                        null,
                        symbol.isBlank() ? null : symbol,
                        SourceLocation.inferLanguage(endpoint.sourceFile()),
                        null);
        List<HighlightRange> ranges =
                line != null && line > 0
                        ? List.of(new HighlightRange(line, line, null, null, "issue"))
                        : List.of();
        return new FindingOccurrence(message, location, ranges);
    }

    public record Result(HttpSurfaceAnalysis httpSurfaceAnalysis, List<Finding> findings) {}

    private record SourceSurface(
            List<InboundEndpoint> inboundEndpoints, List<OutboundEndpoint> outboundEndpoints) {}

    private record ConfiguredUrlMetadata(UrlKind kind, String host, String referencedPropertyName) {
        static ConfiguredUrlMetadata none() {
            return new ConfiguredUrlMetadata(null, null, null);
        }
    }

    private record BaseUrlMatch(String propertyName, String baseUrl, String host) {}

    private static final class BaseUrlCatalog {
        private final Map<String, BaseUrlMatch> byProperty;
        private final List<Map.Entry<String, BaseUrlMatch>> ranked;

        private BaseUrlCatalog(ConfigurationAnalysis configurationAnalysis) {
            List<Map.Entry<String, BaseUrlMatch>> entries = new ArrayList<>();
            if (configurationAnalysis != null && configurationAnalysis.properties() != null) {
                for (ApplicationProperty property : configurationAnalysis.properties()) {
                    if (property.name() == null
                            || property.value() == null
                            || property.value().isBlank()) {
                        continue;
                    }
                    String normalizedName = property.name().toLowerCase(Locale.ROOT);
                    boolean isHostProp = normalizedName.endsWith(".host");
                    boolean isUrlLike =
                            normalizedName.endsWith(".base-url")
                                    || normalizedName.endsWith(".url")
                                    || normalizedName.endsWith(".uri")
                                    || normalizedName.endsWith(".endpoint");
                    if (!isUrlLike && !isHostProp) {
                        continue;
                    }
                    String value = property.value();
                    String lowerValue = value.toLowerCase(Locale.ROOT);
                    String baseUrl = null;
                    String host = null;
                    if (lowerValue.startsWith("http://") || lowerValue.startsWith("https://")) {
                        baseUrl = value;
                        host = tryHost(value);
                    } else if (isHostProp && !value.contains(" ") && !value.contains("/")) {
                        // Treat raw hostname/IP value from a *.host property
                        host = value.contains(":") ? value.split(":")[0] : value;
                    } else if (!isHostProp) {
                        continue;
                    }
                    if (baseUrl == null && host == null) {
                        continue;
                    }
                    entries.add(
                            Map.entry(
                                    property.name(),
                                    new BaseUrlMatch(property.name(), baseUrl, host)));
                }
            }
            this.byProperty =
                    entries.stream()
                            .collect(
                                    Collectors.toMap(
                                            Map.Entry::getKey,
                                            Map.Entry::getValue,
                                            (left, right) -> left));
            this.ranked = List.copyOf(entries);
        }

        private BaseUrlMatch byProperty(String propertyName) {
            return byProperty.get(propertyName);
        }

        private BaseUrlMatch bestMatchForClass(String className, String sourceFile, String hint) {
            if (ranked.isEmpty()) {
                return null;
            }
            String haystack =
                    ((className == null ? "" : className)
                                    + " "
                                    + (sourceFile == null ? "" : sourceFile)
                                    + " "
                                    + (hint == null ? "" : hint))
                            .toLowerCase(Locale.ROOT);
            int bestScore = 0;
            int secondBestScore = 0;
            BaseUrlMatch bestMatch = null;
            for (Map.Entry<String, BaseUrlMatch> entry : ranked) {
                int score = tokenScore(haystack, entry.getKey());
                if (score > bestScore) {
                    secondBestScore = bestScore;
                    bestScore = score;
                    bestMatch = entry.getValue();
                } else if (score > secondBestScore) {
                    secondBestScore = score;
                }
            }
            if (bestScore == 0) {
                return null;
            }
            return bestScore > secondBestScore ? bestMatch : null;
        }

        private static int tokenScore(String haystack, String propertyName) {
            int score = 0;
            for (String token : propertyName.toLowerCase(Locale.ROOT).split("[^a-z0-9]+")) {
                if (token.length() < 4) {
                    continue;
                }
                if (haystack.contains(token)) {
                    score++;
                }
            }
            return score;
        }

        static String tryHost(String value) {
            try {
                return URI.create(value).getHost();
            } catch (Exception ignored) {
                return null;
            }
        }
    }
}

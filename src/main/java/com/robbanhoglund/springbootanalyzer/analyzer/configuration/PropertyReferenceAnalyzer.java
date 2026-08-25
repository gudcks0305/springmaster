package com.robbanhoglund.springbootanalyzer.analyzer.configuration;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.PropertyReference;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class PropertyReferenceAnalyzer {

    private static final Pattern VALUE_PATTERN = Pattern.compile("\\$\\{([^}:]+)(?::([^}]*))?}");
    private final PropertyNameNormalizer propertyNameNormalizer;

    public PropertyReferenceAnalyzer(PropertyNameNormalizer propertyNameNormalizer) {
        this.propertyNameNormalizer = propertyNameNormalizer;
    }

    public List<PropertyReference> analyze(Path repositoryRoot) {
        return analyze(JavaSources.from(repositoryRoot));
    }

    public List<PropertyReference> analyze(JavaSources javaSources) {
        List<PropertyReference> references = new ArrayList<>();
        for (JavaSources.JavaFile sourceFile : javaSources.primaryFiles()) {
            if (sourceFile.compilationUnit() == null) {
                continue;
            }
            analyzeSourceFile(javaSources.repositoryRoot(), sourceFile, references);
        }
        return List.copyOf(references);
    }

    private void analyzeSourceFile(
            Path repositoryRoot,
            JavaSources.JavaFile sourceFile,
            List<PropertyReference> references) {
        CompilationUnit compilationUnit = sourceFile.compilationUnit();
        String packageName =
                compilationUnit
                        .getPackageDeclaration()
                        .map(declaration -> declaration.getNameAsString())
                        .orElse("");

        for (TypeDeclaration<?> typeDeclaration : compilationUnit.findAll(TypeDeclaration.class)) {
            String className =
                    packageName.isBlank()
                            ? typeDeclaration.getNameAsString()
                            : packageName + "." + typeDeclaration.getNameAsString();

            for (AnnotationExpr annotation : typeDeclaration.findAll(AnnotationExpr.class)) {
                collectAnnotationReference(repositoryRoot, sourceFile.path(), className, annotation)
                        .ifPresent(references::addAll);
            }

            for (MethodCallExpr methodCallExpr : typeDeclaration.findAll(MethodCallExpr.class)) {
                collectMethodReference(repositoryRoot, sourceFile.path(), className, methodCallExpr)
                        .ifPresent(references::add);
            }
        }
    }

    private Optional<List<PropertyReference>> collectAnnotationReference(
            Path repositoryRoot, Path sourceFile, String className, AnnotationExpr annotation) {
        String annotationName = simpleName(annotation.getNameAsString());
        if ("Value".equals(annotationName)) {
            String rawValue =
                    annotation.isSingleMemberAnnotationExpr()
                            ? stringValue(
                                            annotation
                                                    .asSingleMemberAnnotationExpr()
                                                    .getMemberValue())
                                    .orElse(null)
                            : null;
            if (rawValue == null) {
                return Optional.empty();
            }

            Matcher matcher = VALUE_PATTERN.matcher(rawValue);
            if (!matcher.find()) {
                return Optional.empty();
            }
            return Optional.of(
                    List.of(
                            new PropertyReference(
                                    propertyNameNormalizer.normalize(matcher.group(1)),
                                    "@Value",
                                    normalizePath(repositoryRoot, sourceFile),
                                    annotation
                                            .getBegin()
                                            .map(position -> position.line)
                                            .orElse(null),
                                    className,
                                    matcher.group(2),
                                    false,
                                    null,
                                    null)));
        }

        if ("Scheduled".equals(annotationName) && annotation.isNormalAnnotationExpr()) {
            return collectScheduledReferences(repositoryRoot, sourceFile, className, annotation);
        }

        if (!"ConditionalOnProperty".equals(annotationName)
                || !annotation.isNormalAnnotationExpr()) {
            return Optional.empty();
        }

        String prefix = "";
        List<String> names = new ArrayList<>();
        String havingValue = null;
        Boolean matchIfMissing = null;
        for (MemberValuePair pair : annotation.asNormalAnnotationExpr().getPairs()) {
            if ("prefix".equals(pair.getNameAsString())) {
                prefix = stringValue(pair.getValue()).orElse("");
            } else if ("name".equals(pair.getNameAsString())
                    || "value".equals(pair.getNameAsString())) {
                extractStringValues(pair.getValue()).forEach(names::add);
            } else if ("havingValue".equals(pair.getNameAsString())) {
                havingValue = stringValue(pair.getValue()).orElse(null);
            } else if ("matchIfMissing".equals(pair.getNameAsString())
                    && pair.getValue().isBooleanLiteralExpr()) {
                matchIfMissing = pair.getValue().asBooleanLiteralExpr().getValue();
            }
        }

        if (names.isEmpty()) {
            return Optional.empty();
        }

        List<PropertyReference> references = new ArrayList<>();
        for (String name : names) {
            String propertyName = prefix.isBlank() ? name : prefix + "." + name;
            references.add(
                    new PropertyReference(
                            propertyNameNormalizer.normalize(propertyName),
                            "@ConditionalOnProperty",
                            normalizePath(repositoryRoot, sourceFile),
                            annotation.getBegin().map(position -> position.line).orElse(null),
                            className,
                            null,
                            false,
                            havingValue,
                            matchIfMissing));
        }
        return Optional.of(List.copyOf(references));
    }

    private Optional<PropertyReference> collectMethodReference(
            Path repositoryRoot, Path sourceFile, String className, MethodCallExpr methodCallExpr) {
        String methodName = methodCallExpr.getNameAsString();
        if (!methodName.equals("getProperty")
                && !methodName.equals("getRequiredProperty")
                && !methodName.equals("containsProperty")) {
            return Optional.empty();
        }
        if (!looksLikeSpringEnvironmentLookup(methodCallExpr)) {
            return Optional.empty();
        }
        if (methodCallExpr.getArguments().isEmpty()) {
            return Optional.empty();
        }

        Optional<String> propertyName = stringValue(methodCallExpr.getArgument(0));
        if (propertyName.isEmpty()) {
            return Optional.empty();
        }

        String defaultValue = null;
        if ("getProperty".equals(methodName) && methodCallExpr.getArguments().size() > 1) {
            defaultValue = stringValue(methodCallExpr.getArgument(1)).orElse(null);
        }

        return Optional.of(
                new PropertyReference(
                        propertyNameNormalizer.normalize(propertyName.get()),
                        "Environment#" + methodName,
                        normalizePath(repositoryRoot, sourceFile),
                        methodCallExpr.getBegin().map(position -> position.line).orElse(null),
                        className,
                        defaultValue,
                        methodName.equals("getRequiredProperty"),
                        null,
                        null));
    }

    private boolean looksLikeSpringEnvironmentLookup(MethodCallExpr methodCallExpr) {
        Expression scope = methodCallExpr.getScope().orElse(null);
        if (scope == null) {
            return false;
        }
        if (scope instanceof NameExpr nameExpr) {
            String normalized = nameExpr.getNameAsString().toLowerCase();
            return normalized.equals("environment")
                    || normalized.equals("env")
                    || normalized.endsWith("environment");
        }
        if (scope instanceof FieldAccessExpr fieldAccessExpr) {
            String normalized = fieldAccessExpr.toString().toLowerCase();
            return normalized.endsWith(".environment") || normalized.contains("environment");
        }
        if (scope instanceof MethodCallExpr scopeCall) {
            String normalized = scopeCall.getNameAsString().toLowerCase();
            return normalized.equals("getenvironment") || normalized.endsWith("environment");
        }
        String normalized = scope.toString().toLowerCase();
        return normalized.contains("environment");
    }

    private Optional<List<PropertyReference>> collectScheduledReferences(
            Path repositoryRoot, Path sourceFile, String className, AnnotationExpr annotation) {
        List<PropertyReference> references = new ArrayList<>();
        for (MemberValuePair pair : annotation.asNormalAnnotationExpr().getPairs()) {
            String pairName = pair.getNameAsString();
            if (!pairName.equals("fixedDelayString")
                    && !pairName.equals("fixedRateString")
                    && !pairName.equals("cron")) {
                continue;
            }
            Optional<String> rawValue = stringValue(pair.getValue());
            if (rawValue.isEmpty()) {
                continue;
            }
            Matcher matcher = VALUE_PATTERN.matcher(rawValue.get());
            if (!matcher.find()) {
                continue;
            }
            references.add(
                    new PropertyReference(
                            propertyNameNormalizer.normalize(matcher.group(1)),
                            "@Scheduled",
                            normalizePath(repositoryRoot, sourceFile),
                            annotation.getBegin().map(position -> position.line).orElse(null),
                            className,
                            matcher.group(2),
                            false,
                            pairName,
                            null));
        }
        return references.isEmpty() ? Optional.empty() : Optional.of(List.copyOf(references));
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

    private String simpleName(String name) {
        int separatorIndex = name.lastIndexOf('.');
        return separatorIndex < 0 ? name : name.substring(separatorIndex + 1);
    }

    private String normalizePath(Path repositoryRoot, Path sourceFile) {
        return repositoryRoot.relativize(sourceFile).toString().replace('\\', '/');
    }
}

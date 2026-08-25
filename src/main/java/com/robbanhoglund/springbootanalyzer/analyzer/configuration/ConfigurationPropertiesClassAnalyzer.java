package com.robbanhoglund.springbootanalyzer.analyzer.configuration;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.type.Type;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.ConfigurationPropertiesClass;
import com.robbanhoglund.springbootanalyzer.analyzer.model.configuration.CustomPropertyDefinition;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class ConfigurationPropertiesClassAnalyzer {

    private static final Set<String> VALIDATION_ANNOTATIONS =
            Set.of(
                    "NotBlank",
                    "NotNull",
                    "Min",
                    "Max",
                    "DecimalMin",
                    "DecimalMax",
                    "Positive",
                    "PositiveOrZero",
                    "DurationMin",
                    "DurationMax");

    private final PropertyNameNormalizer propertyNameNormalizer;

    public ConfigurationPropertiesClassAnalyzer(PropertyNameNormalizer propertyNameNormalizer) {
        this.propertyNameNormalizer = propertyNameNormalizer;
    }

    public List<ConfigurationPropertiesClass> analyze(Path repositoryRoot) {
        return analyze(JavaSources.from(repositoryRoot));
    }

    /**
     * Extracts configuration contracts from primary and dependency-overlay sources. Dependency
     * contracts are semantic facts used to classify primary configuration; they do not generate
     * standalone source findings here.
     */
    public List<ConfigurationPropertiesClass> analyze(JavaSources javaSources) {
        List<ConfigurationPropertiesClass> classes = new ArrayList<>();
        for (JavaSources.JavaFile sourceFile : javaSources.files()) {
            if (sourceFile.compilationUnit() == null) {
                continue;
            }
            analyzeSourceFile(sourceFile, classes);
        }
        return List.copyOf(classes);
    }

    private void analyzeSourceFile(
            JavaSources.JavaFile sourceFile, List<ConfigurationPropertiesClass> classes) {
        CompilationUnit compilationUnit = sourceFile.compilationUnit();
        String packageName =
                compilationUnit
                        .getPackageDeclaration()
                        .map(declaration -> declaration.getNameAsString())
                        .orElse("");
        Map<String, TypeDeclaration<?>> localTypes = indexLocalTypes(compilationUnit);

        for (TypeDeclaration<?> typeDeclaration : compilationUnit.findAll(TypeDeclaration.class)) {
            findConfigurationPropertiesClass(
                            sourceFile.relativePath(), packageName, typeDeclaration, localTypes)
                    .ifPresent(classes::add);
        }
    }

    private Optional<ConfigurationPropertiesClass> findConfigurationPropertiesClass(
            String relativePath,
            String packageName,
            TypeDeclaration<?> typeDeclaration,
            Map<String, TypeDeclaration<?>> localTypes) {
        String prefix = null;
        for (AnnotationExpr annotation : typeDeclaration.getAnnotations()) {
            if (!"ConfigurationProperties".equals(simpleName(annotation.getNameAsString()))) {
                continue;
            }
            prefix = extractPrefix(annotation).orElse("");
            break;
        }

        if (prefix == null) {
            return Optional.empty();
        }

        List<CustomPropertyDefinition> properties =
                collectProperties(typeDeclaration, "", localTypes, new LinkedHashSet<>());

        String qualifiedClassName =
                packageName.isBlank()
                        ? typeDeclaration.getNameAsString()
                        : packageName + "." + typeDeclaration.getNameAsString();

        return Optional.of(
                new ConfigurationPropertiesClass(
                        prefix,
                        qualifiedClassName,
                        relativePath,
                        cleanJavadoc(
                                typeDeclaration
                                        .getJavadocComment()
                                        .map(comment -> comment.parse().toText())
                                        .orElse(null)),
                        properties));
    }

    private List<CustomPropertyDefinition> collectProperties(
            TypeDeclaration<?> typeDeclaration,
            String currentPrefix,
            Map<String, TypeDeclaration<?>> localTypes,
            Set<String> visitedTypes) {
        List<CustomPropertyDefinition> properties = new ArrayList<>();

        if (!visitedTypes.add(typeDeclaration.getNameAsString())) {
            return List.of();
        }

        if (typeDeclaration instanceof RecordDeclaration recordDeclaration) {
            for (Parameter parameter : recordDeclaration.getParameters()) {
                String propertySegment =
                        propertyNameNormalizer.toKebabCase(parameter.getNameAsString());
                String propertyName = joinPrefix(currentPrefix, propertySegment);
                TypeDeclaration<?> nestedType = resolveNestedType(parameter.getType(), localTypes);
                if (nestedType != null) {
                    properties.addAll(
                            collectProperties(
                                    nestedType,
                                    propertyName,
                                    localTypes,
                                    new LinkedHashSet<>(visitedTypes)));
                } else {
                    properties.add(
                            new CustomPropertyDefinition(
                                    propertyName,
                                    parameter.getNameAsString(),
                                    parameter.getType().asString(),
                                    validationAnnotations(parameter.getAnnotations()),
                                    null));
                }
            }
            return List.copyOf(properties);
        }

        for (FieldDeclaration field : typeDeclaration.getFields()) {
            field.getVariables()
                    .forEach(
                            variable -> {
                                String propertySegment =
                                        propertyNameNormalizer.toKebabCase(
                                                variable.getNameAsString());
                                String propertyName = joinPrefix(currentPrefix, propertySegment);
                                TypeDeclaration<?> nestedType =
                                        resolveNestedType(variable.getType(), localTypes);
                                if (nestedType != null) {
                                    properties.addAll(
                                            collectProperties(
                                                    nestedType,
                                                    propertyName,
                                                    localTypes,
                                                    new LinkedHashSet<>(visitedTypes)));
                                } else {
                                    properties.add(
                                            new CustomPropertyDefinition(
                                                    propertyName,
                                                    variable.getNameAsString(),
                                                    variable.getType().asString(),
                                                    validationAnnotations(field.getAnnotations()),
                                                    cleanJavadoc(
                                                            field.getJavadocComment()
                                                                    .map(
                                                                            comment ->
                                                                                    comment.parse()
                                                                                            .toText())
                                                                    .orElse(null))));
                                }
                            });
        }
        return List.copyOf(properties);
    }

    private Map<String, TypeDeclaration<?>> indexLocalTypes(CompilationUnit compilationUnit) {
        Map<String, TypeDeclaration<?>> types = new LinkedHashMap<>();
        for (TypeDeclaration<?> declaration : compilationUnit.findAll(TypeDeclaration.class)) {
            types.putIfAbsent(declaration.getNameAsString(), declaration);
        }
        return types;
    }

    private TypeDeclaration<?> resolveNestedType(
            Type type, Map<String, TypeDeclaration<?>> localTypes) {
        String simpleTypeName = type.asString().replace("[]", "");
        int genericStart = simpleTypeName.indexOf('<');
        if (genericStart >= 0) {
            simpleTypeName = simpleTypeName.substring(0, genericStart);
        }
        int packageSeparator = simpleTypeName.lastIndexOf('.');
        if (packageSeparator >= 0) {
            simpleTypeName = simpleTypeName.substring(packageSeparator + 1);
        }
        return localTypes.get(simpleTypeName);
    }

    private String joinPrefix(String prefix, String propertySegment) {
        if (prefix == null || prefix.isBlank()) {
            return propertySegment;
        }
        return prefix + "." + propertySegment;
    }

    private List<String> validationAnnotations(NodeList<AnnotationExpr> annotations) {
        List<String> values = new ArrayList<>();
        for (AnnotationExpr annotation : annotations) {
            String name = simpleName(annotation.getNameAsString());
            if (VALIDATION_ANNOTATIONS.contains(name)) {
                values.add(name);
            }
        }
        return List.copyOf(values);
    }

    private Optional<String> extractPrefix(AnnotationExpr annotation) {
        if (annotation.isSingleMemberAnnotationExpr()) {
            return stringValue(annotation.asSingleMemberAnnotationExpr().getMemberValue());
        }
        if (annotation.isNormalAnnotationExpr()) {
            for (MemberValuePair pair : annotation.asNormalAnnotationExpr().getPairs()) {
                if ("prefix".equals(pair.getNameAsString())
                        || "value".equals(pair.getNameAsString())) {
                    return stringValue(pair.getValue());
                }
            }
        }
        return Optional.empty();
    }

    private Optional<String> stringValue(Expression expression) {
        if (expression.isStringLiteralExpr()) {
            return Optional.of(expression.asStringLiteralExpr().asString());
        }
        return Optional.empty();
    }

    private String cleanJavadoc(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.replace(System.lineSeparator(), " ").trim();
    }

    private String simpleName(String name) {
        int separatorIndex = name.lastIndexOf('.');
        return separatorIndex < 0 ? name : name.substring(separatorIndex + 1);
    }
}

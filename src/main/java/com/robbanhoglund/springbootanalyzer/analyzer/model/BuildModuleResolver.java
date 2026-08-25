package com.robbanhoglund.springbootanalyzer.analyzer.model;

import java.util.Comparator;
import java.util.Optional;

/** Resolves repository-relative source/config paths to the deepest declared build module. */
public final class BuildModuleResolver {

    public static final String ROOT_MODULE = ".";
    public static final String DEPENDENCY_OVERLAY = "_springmaster_deps";

    private BuildModuleResolver() {}

    public static String modulePathFor(String repositoryRelativePath, BuildInfo buildInfo) {
        String normalizedPath = normalize(repositoryRelativePath);
        if (isDependencyPath(normalizedPath)) {
            return dependencyRoot(normalizedPath);
        }
        if (buildInfo != null && buildInfo.modules() != null) {
            Optional<String> declaredModule =
                    buildInfo.modules().stream()
                            .map(BuildModuleInfo::path)
                            .filter(path -> path != null && !path.equals(ROOT_MODULE))
                            .map(BuildModuleResolver::normalize)
                            .filter(path -> normalizedPath.startsWith(path + "/"))
                            .max(Comparator.comparingInt(String::length));
            if (declaredModule.isPresent()) {
                return declaredModule.orElseThrow();
            }
        }
        for (String sourceMarker :
                new String[] {"/src/main/java/", "/src/main/resources/", "/src/test/resources/"}) {
            int markerIndex = normalizedPath.indexOf(sourceMarker);
            if (markerIndex > 0) {
                return normalizedPath.substring(0, markerIndex);
            }
        }
        return ROOT_MODULE;
    }

    public static Optional<BuildModuleInfo> moduleFor(
            String repositoryRelativePath, BuildInfo buildInfo) {
        if (buildInfo == null || buildInfo.modules() == null) {
            return Optional.empty();
        }
        String modulePath = modulePathFor(repositoryRelativePath, buildInfo);
        return buildInfo.modules().stream()
                .filter(module -> normalize(module.path()).equals(modulePath))
                .findFirst();
    }

    public static boolean isDependencyPath(String repositoryRelativePath) {
        String normalizedPath = normalize(repositoryRelativePath);
        return normalizedPath.equals(DEPENDENCY_OVERLAY)
                || normalizedPath.startsWith(DEPENDENCY_OVERLAY + "/");
    }

    private static String dependencyRoot(String normalizedPath) {
        String[] segments = normalizedPath.split("/");
        return segments.length > 1 ? DEPENDENCY_OVERLAY + "/" + segments[1] : DEPENDENCY_OVERLAY;
    }

    private static String normalize(String path) {
        if (path == null || path.isBlank()) {
            return ROOT_MODULE;
        }
        String normalized = path.replace('\\', '/');
        while (normalized.startsWith("./")) {
            normalized = normalized.substring(2);
        }
        while (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.isBlank() ? ROOT_MODULE : normalized;
    }
}

package com.robbanhoglund.springbootanalyzer.analyzer.model;

import java.util.List;

/** Static build metadata for one root or declared module in a repository build graph. */
public record BuildModuleInfo(
        String path,
        BuildTool buildTool,
        boolean springBootDetected,
        String javaVersionHint,
        List<String> dependencies,
        String springBootVersion,
        String springBootVersionSource,
        String springBootVersionConfidence) {

    public BuildModuleInfo {
        dependencies = dependencies == null ? List.of() : List.copyOf(dependencies);
    }
}

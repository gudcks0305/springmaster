package com.robbanhoglund.springbootanalyzer.analyzer.model;

import java.util.List;

public record BuildInfo(
        BuildTool buildTool,
        boolean springBootDetected,
        String javaVersionHint,
        List<String> dependencies,
        String springBootVersion,
        String springBootVersionSource,
        String springBootVersionConfidence,
        List<BuildModuleInfo> modules) {

    public BuildInfo(
            BuildTool buildTool,
            boolean springBootDetected,
            String javaVersionHint,
            List<String> dependencies,
            String springBootVersion,
            String springBootVersionSource,
            String springBootVersionConfidence) {
        this(
                buildTool,
                springBootDetected,
                javaVersionHint,
                dependencies,
                springBootVersion,
                springBootVersionSource,
                springBootVersionConfidence,
                List.of());
    }

    public BuildInfo {
        dependencies = dependencies == null ? List.of() : List.copyOf(dependencies);
        modules = modules == null ? List.of() : List.copyOf(modules);
    }
}

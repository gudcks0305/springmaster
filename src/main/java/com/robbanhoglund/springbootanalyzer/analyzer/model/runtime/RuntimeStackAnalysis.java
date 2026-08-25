package com.robbanhoglund.springbootanalyzer.analyzer.model.runtime;

import java.util.List;

public record RuntimeStackAnalysis(
        String springBootVersion,
        String springBootVersionSource,
        String javaVersion,
        WebStack webStack,
        String webStackReason,
        VirtualThreadAnalysis virtualThreads,
        String mainClass,
        List<ModuleRuntimeStackAnalysis> modules) {

    public RuntimeStackAnalysis(
            String springBootVersion,
            String springBootVersionSource,
            String javaVersion,
            WebStack webStack,
            String webStackReason,
            VirtualThreadAnalysis virtualThreads,
            String mainClass) {
        this(
                springBootVersion,
                springBootVersionSource,
                javaVersion,
                webStack,
                webStackReason,
                virtualThreads,
                mainClass,
                List.of());
    }

    public RuntimeStackAnalysis {
        modules = modules == null ? List.of() : List.copyOf(modules);
    }
}

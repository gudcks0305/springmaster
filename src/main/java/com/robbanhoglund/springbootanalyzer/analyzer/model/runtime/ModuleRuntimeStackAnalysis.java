package com.robbanhoglund.springbootanalyzer.analyzer.model.runtime;

/** Runtime classification for one build module or independent deployable build root. */
public record ModuleRuntimeStackAnalysis(
        String modulePath,
        String springBootVersion,
        String javaVersion,
        WebStack webStack,
        String webStackReason) {}

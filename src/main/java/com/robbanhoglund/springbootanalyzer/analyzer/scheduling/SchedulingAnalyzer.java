package com.robbanhoglund.springbootanalyzer.analyzer.scheduling;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.robbanhoglund.springbootanalyzer.analyzer.model.scheduling.AsyncMethodEndpoint;
import com.robbanhoglund.springbootanalyzer.analyzer.model.scheduling.ScheduledTaskEndpoint;
import com.robbanhoglund.springbootanalyzer.analyzer.model.scheduling.SchedulingAnalysis;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.stereotype.Component;

@Component
public class SchedulingAnalyzer {

    public SchedulingAnalysis analyze(Path repositoryRoot) {
        return analyze(JavaSources.from(repositoryRoot));
    }

    public SchedulingAnalysis analyze(JavaSources sources) {
        List<ScheduledTaskEndpoint> scheduledTasks = new ArrayList<>();
        List<AsyncMethodEndpoint> asyncMethods = new ArrayList<>();
        AtomicBoolean enableScheduling = new AtomicBoolean(false);
        AtomicBoolean enableAsync = new AtomicBoolean(false);

        for (JavaSources.JavaFile file : sources.primaryFiles()) {
            if (file.compilationUnit() == null) {
                continue;
            }
            collectFromCompilationUnit(
                    file.compilationUnit(),
                    file.relativePath(),
                    scheduledTasks,
                    asyncMethods,
                    enableScheduling,
                    enableAsync);
        }

        return new SchedulingAnalysis(
                List.copyOf(scheduledTasks),
                List.copyOf(asyncMethods),
                enableScheduling.get(),
                enableAsync.get());
    }

    private void collectFromCompilationUnit(
            CompilationUnit cu,
            String relativePath,
            List<ScheduledTaskEndpoint> scheduledTasks,
            List<AsyncMethodEndpoint> asyncMethods,
            AtomicBoolean enableScheduling,
            AtomicBoolean enableAsync) {
        cu.findAll(ClassOrInterfaceDeclaration.class)
                .forEach(
                        cls -> {
                            for (AnnotationExpr annotation : cls.getAnnotations()) {
                                String name = simpleName(annotation.getNameAsString());
                                if (name.equals("EnableScheduling")) enableScheduling.set(true);
                                if (name.equals("EnableAsync")) enableAsync.set(true);
                            }

                            String className = cls.getNameAsString();
                            for (MethodDeclaration method : cls.getMethods()) {
                                Integer line = method.getBegin().map(p -> p.line).orElse(null);

                                for (AnnotationExpr annotation : method.getAnnotations()) {
                                    String name = simpleName(annotation.getNameAsString());
                                    if (name.equals("Scheduled")) {
                                        collectScheduledTask(
                                                annotation,
                                                className,
                                                method.getNameAsString(),
                                                relativePath,
                                                line,
                                                scheduledTasks);
                                    }
                                    if (name.equals("Async") && !method.isPrivate()) {
                                        asyncMethods.add(
                                                new AsyncMethodEndpoint(
                                                        className,
                                                        method.getNameAsString(),
                                                        relativePath,
                                                        line));
                                    }
                                }
                            }
                        });
    }

    private void collectScheduledTask(
            AnnotationExpr annotation,
            String className,
            String methodName,
            String relativePath,
            Integer line,
            List<ScheduledTaskEndpoint> out) {
        String scheduleType = null;
        String scheduleValue = null;
        String zone = null;

        if (annotation.isNormalAnnotationExpr()) {
            for (MemberValuePair pair : annotation.asNormalAnnotationExpr().getPairs()) {
                String key = pair.getNameAsString();
                String val = stringLiteralOrRaw(pair.getValue());
                switch (key) {
                    case "cron" -> {
                        scheduleType = "CRON";
                        scheduleValue = val;
                    }
                    case "fixedRate" -> {
                        scheduleType = "FIXED_RATE";
                        scheduleValue = val;
                    }
                    case "fixedRateString" -> {
                        scheduleType = "FIXED_RATE";
                        scheduleValue = val;
                    }
                    case "fixedDelay" -> {
                        scheduleType = "FIXED_DELAY";
                        scheduleValue = val;
                    }
                    case "fixedDelayString" -> {
                        scheduleType = "FIXED_DELAY";
                        scheduleValue = val;
                    }
                    case "zone" -> zone = val;
                }
            }
        } else if (annotation.isSingleMemberAnnotationExpr()) {
            scheduleType = "CRON";
            scheduleValue =
                    stringLiteralOrRaw(annotation.asSingleMemberAnnotationExpr().getMemberValue());
        }

        out.add(
                new ScheduledTaskEndpoint(
                        className,
                        methodName,
                        relativePath,
                        line,
                        scheduleType != null ? scheduleType : "UNKNOWN",
                        scheduleValue,
                        zone));
    }

    private String stringLiteralOrRaw(Expression expr) {
        if (expr.isStringLiteralExpr()) return expr.asStringLiteralExpr().asString();
        if (expr.isLongLiteralExpr()) return expr.asLongLiteralExpr().getValue();
        if (expr.isIntegerLiteralExpr()) return expr.asIntegerLiteralExpr().getValue();
        if (expr.isArrayInitializerExpr()) {
            ArrayInitializerExpr arr = expr.asArrayInitializerExpr();
            if (!arr.getValues().isEmpty()) return stringLiteralOrRaw(arr.getValues().get(0));
        }
        return expr.toString();
    }

    private static String simpleName(String name) {
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : name;
    }
}

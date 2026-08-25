package com.robbanhoglund.springbootanalyzer;

import com.robbanhoglund.springbootanalyzer.config.AnalyzerProperties;
import java.util.Arrays;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Entry point for the Spring Boot Analyzer service.
 *
 * <p>{@code @EnableConfigurationProperties} binds {@link AnalyzerProperties} from the
 * {@code analyzer.*} namespace.
 *
 * <p>When {@code --worker} is present, the application starts in long-lived JSONL worker mode.
 * When {@code --repo} is present, it starts in single-run CLI mode. Both modes disable the
 * embedded web server and activate their respective Spring profiles. In all other cases the
 * application behaves as a normal Spring Boot web service.
 */
@SpringBootApplication
@EnableConfigurationProperties(AnalyzerProperties.class)
public class SpringBootAnalyzerApplication {

    public static void main(String[] args) {
        boolean workerMode = Arrays.stream(args).anyMatch("--worker"::equals);
        boolean cliMode =
                Arrays.stream(args).anyMatch(a -> a.startsWith("--repo=") || a.equals("--repo"));
        if (workerMode || cliMode) {
            SpringApplication app = new SpringApplication(SpringBootAnalyzerApplication.class);
            app.setWebApplicationType(WebApplicationType.NONE);
            app.setAdditionalProfiles(workerMode ? "worker" : "cli");
            app.run(args);
        } else {
            SpringApplication.run(SpringBootAnalyzerApplication.class, args);
        }
    }
}

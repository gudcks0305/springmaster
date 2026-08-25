package com.robbanhoglund.springbootanalyzer.analyzer;

import static org.assertj.core.api.Assertions.assertThat;

import com.robbanhoglund.springbootanalyzer.analyzer.model.SpringComponentType;
import com.robbanhoglund.springbootanalyzer.analyzer.source.JavaSources;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JavaSourceAnalyzerTest {

    private final JavaSourceAnalyzer analyzer = new JavaSourceAnalyzer();

    @TempDir Path tempDir;

    @Test
    void detectsAnnotatedSpringClasses() throws IOException {
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("DemoApplication.java"),
                """
                package com.example.demo;

                import org.springframework.boot.autoconfigure.SpringBootApplication;

                @SpringBootApplication
                public class DemoApplication {
                }
                """);
        Files.writeString(
                sourceRoot.resolve("GreetingService.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Service;

                @Service
                public class GreetingService {
                }
                """);

        var result = analyzer.analyze(JavaSources.from(tempDir));

        assertThat(result.detectedClasses()).hasSize(2);
        assertThat(result.detectedClasses())
                .extracting(detectedClass -> detectedClass.componentType())
                .containsExactlyInAnyOrder(
                        SpringComponentType.MAIN_APPLICATION, SpringComponentType.SERVICE);
        assertThat(result.findings()).isEmpty();
    }

    @Test
    void reportsDefaultPackageWarningAndSilentlySkipsUnparsableFiles() throws IOException {
        Path sourceRoot = Files.createDirectories(tempDir.resolve("src/main/java"));
        Files.writeString(
                sourceRoot.resolve("NoPackageComponent.java"),
                """
                import org.springframework.stereotype.Component;

                @Component
                public class NoPackageComponent {
                }
                """);
        Files.writeString(
                sourceRoot.resolve("BrokenFile.java"),
                """
                package com.example.broken;

                public class BrokenFile {
                """);

        var result = analyzer.analyze(tempDir);

        assertThat(result.detectedClasses())
                .extracting(detectedClass -> detectedClass.simpleClassName())
                .contains("NoPackageComponent");
        assertThat(result.findings())
                .extracting(finding -> finding.message())
                .anyMatch(message -> message.contains("default package"));
        assertThat(result.findings())
                .extracting(finding -> finding.message())
                .noneMatch(message -> message.contains("Failed to parse"));
    }

    @Test
    void parsesModernJavaSyntaxWithJava25LanguageLevel() throws IOException {
        Path sourceRoot =
                Files.createDirectories(tempDir.resolve("src/main/java/com/example/demo"));
        Files.writeString(
                sourceRoot.resolve("ModernRecord.java"),
                """
                package com.example.demo;

                import org.springframework.stereotype.Component;

                @Component
                public record ModernRecord(String value) {
                }
                """);

        var result = analyzer.analyze(tempDir);

        assertThat(result.detectedClasses())
                .extracting(detectedClass -> detectedClass.simpleClassName())
                .contains("ModernRecord");
        assertThat(result.findings()).isEmpty();
    }
}

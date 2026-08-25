package com.robbanhoglund.springbootanalyzer.analyzer;

import static org.assertj.core.api.Assertions.assertThat;

import com.robbanhoglund.springbootanalyzer.analyzer.model.BuildTool;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BuildFileAnalyzerTest {

    private final BuildFileAnalyzer analyzer = new BuildFileAnalyzer();

    @TempDir Path tempDir;

    @Test
    void detectsGradleSpringBootProject() throws IOException {
        Files.writeString(
                tempDir.resolve("build.gradle"),
                """
                plugins {
                    id 'org.springframework.boot' version '3.5.13'
                }

                java {
                    toolchain {
                        languageVersion = JavaLanguageVersion.of(25)
                    }
                }

                dependencies {
                    implementation 'org.springframework.boot:spring-boot-starter-web'
                    implementation 'com.example:library:1.0.0'
                }
                """);

        var buildInfo = analyzer.analyze(tempDir);

        assertThat(buildInfo.buildTool()).isEqualTo(BuildTool.GRADLE);
        assertThat(buildInfo.springBootDetected()).isTrue();
        assertThat(buildInfo.javaVersionHint()).isEqualTo("25");
        assertThat(buildInfo.dependencies())
                .contains("org.springframework.boot:spring-boot-starter-web");
        assertThat(buildInfo.dependencies()).contains("com.example:library:1.0.0");
        assertThat(buildInfo.springBootVersion()).isEqualTo("3.5.13");
        assertThat(buildInfo.springBootVersionSource()).isEqualTo("Gradle plugins");
        assertThat(buildInfo.springBootVersionConfidence()).isEqualTo("HIGH");
    }

    @Test
    void detectsMavenSpringBootProject() throws IOException {
        Files.writeString(
                tempDir.resolve("pom.xml"),
                """
                <project>
                    <properties>
                        <java.version>25</java.version>
                    </properties>
                    <build>
                        <plugins>
                            <plugin>
                                <groupId>org.springframework.boot</groupId>
                                <artifactId>spring-boot-maven-plugin</artifactId>
                            </plugin>
                        </plugins>
                    </build>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>spring-boot-starter-web</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);

        var buildInfo = analyzer.analyze(tempDir);

        assertThat(buildInfo.buildTool()).isEqualTo(BuildTool.MAVEN);
        assertThat(buildInfo.springBootDetected()).isTrue();
        assertThat(buildInfo.javaVersionHint()).isEqualTo("25");
        assertThat(buildInfo.dependencies())
                .contains("org.springframework.boot:spring-boot-starter-web");
    }

    @Test
    void detectsSpringBootVersionFromMavenParent() throws IOException {
        Files.writeString(
                tempDir.resolve("pom.xml"),
                """
                <project>
                    <parent>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-parent</artifactId>
                        <version>3.5.13</version>
                    </parent>
                </project>
                """);

        var buildInfo = analyzer.analyze(tempDir);

        assertThat(buildInfo.springBootVersion()).isEqualTo("3.5.13");
        assertThat(buildInfo.springBootVersionSource()).isEqualTo("Maven parent");
    }

    @Test
    void detectsSpringBootVersionFromMavenBom() throws IOException {
        Files.writeString(
                tempDir.resolve("pom.xml"),
                """
                <project>
                    <dependencyManagement>
                        <dependencies>
                            <dependency>
                                <groupId>org.springframework.boot</groupId>
                                <artifactId>spring-boot-dependencies</artifactId>
                                <version>3.4.8</version>
                                <type>pom</type>
                                <scope>import</scope>
                            </dependency>
                        </dependencies>
                    </dependencyManagement>
                </project>
                """);

        var buildInfo = analyzer.analyze(tempDir);

        assertThat(buildInfo.springBootVersion()).isEqualTo("3.4.8");
        assertThat(buildInfo.springBootVersionSource()).isEqualTo("Maven BOM");
    }

    @Test
    void aggregatesDeclaredMavenModuleMetadataWithoutScanningUnrelatedProjects()
            throws IOException {
        write(
                "pom.xml",
                """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>1.0.0</version>
                    <packaging>pom</packaging>
                    <modules>
                        <module>app</module>
                        <module>library</module>
                    </modules>
                </project>
                """);
        write(
                "app/pom.xml",
                """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <parent>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-parent</artifactId>
                        <version>3.5.13</version>
                    </parent>
                    <artifactId>app</artifactId>
                    <properties><java.version>25</java.version></properties>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>spring-boot-starter-web</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);
        write(
                "library/pom.xml",
                """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <artifactId>library</artifactId>
                    <dependencies>
                        <dependency>
                            <groupId>io.micrometer</groupId>
                            <artifactId>micrometer-observation</artifactId>
                            <version>1.15.0</version>
                        </dependency>
                    </dependencies>
                </project>
                """);
        write(
                "examples/unrelated/pom.xml",
                """
                <project>
                    <parent>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-parent</artifactId>
                        <version>9.9.9</version>
                    </parent>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>spring-boot-starter-webflux</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);

        var buildInfo = analyzer.analyze(tempDir);

        assertThat(buildInfo.buildTool()).isEqualTo(BuildTool.MAVEN);
        assertThat(buildInfo.springBootDetected()).isTrue();
        assertThat(buildInfo.javaVersionHint()).isEqualTo("25");
        assertThat(buildInfo.springBootVersion()).isEqualTo("3.5.13");
        assertThat(buildInfo.springBootVersionSource()).isEqualTo("Maven parent");
        assertThat(buildInfo.dependencies())
                .contains(
                        "org.springframework.boot:spring-boot-starter-web",
                        "io.micrometer:micrometer-observation:1.15.0")
                .doesNotContain("org.springframework.boot:spring-boot-starter-webflux");
        assertThat(buildInfo.modules())
                .extracting(module -> module.path())
                .containsExactly(".", "app", "library");
        assertThat(buildInfo.modules())
                .filteredOn(module -> module.path().equals("app"))
                .singleElement()
                .satisfies(
                        module -> {
                            assertThat(module.springBootDetected()).isTrue();
                            assertThat(module.springBootVersion()).isEqualTo("3.5.13");
                        });
    }

    @Test
    void aggregatesDeclaredGradleModuleMetadataAndPrefersHigherConfidenceVersion()
            throws IOException {
        write(
                "settings.gradle.kts",
                """
                rootProject.name = "multi"
                include(":app", ":library")
                """);
        write("gradle.properties", "springBoot = 2.7.18\n");
        write("build.gradle.kts", "plugins { java }\n");
        write(
                "app/build.gradle.kts",
                """
                plugins {
                    id("org.springframework.boot") version "3.5.13"
                }
                java {
                    toolchain.languageVersion = JavaLanguageVersion.of(25)
                }
                dependencies {
                    implementation("org.springframework.boot:spring-boot-starter-webflux")
                }
                """);
        write(
                "library/build.gradle",
                """
                dependencies {
                    implementation 'io.micrometer:micrometer-observation:1.15.0'
                }
                """);
        write(
                "fixtures/unrelated/build.gradle",
                """
                plugins { id 'org.springframework.boot' version '9.9.9' }
                dependencies { implementation 'org.springframework.boot:spring-boot-starter-web' }
                """);

        var buildInfo = analyzer.analyze(tempDir);

        assertThat(buildInfo.buildTool()).isEqualTo(BuildTool.GRADLE);
        assertThat(buildInfo.springBootDetected()).isTrue();
        assertThat(buildInfo.javaVersionHint()).isEqualTo("25");
        assertThat(buildInfo.springBootVersion()).isEqualTo("3.5.13");
        assertThat(buildInfo.springBootVersionSource()).isEqualTo("Gradle plugins");
        assertThat(buildInfo.springBootVersionConfidence()).isEqualTo("HIGH");
        assertThat(buildInfo.dependencies())
                .contains(
                        "org.springframework.boot:spring-boot-starter-webflux",
                        "io.micrometer:micrometer-observation:1.15.0")
                .doesNotContain("org.springframework.boot:spring-boot-starter-web");
        assertThat(buildInfo.modules())
                .extracting(module -> module.path())
                .containsExactly(".", "app", "library");
    }

    @Test
    void discoversIndependentBuildRootsWhenRepositoryHasNoRootDescriptor() throws IOException {
        write(
                "initial/pom.xml",
                """
                <project>
                    <parent>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-parent</artifactId>
                        <version>3.5.12</version>
                    </parent>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>spring-boot-starter-web</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);
        write(
                "complete/pom.xml",
                """
                <project>
                    <parent>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-parent</artifactId>
                        <version>3.5.13</version>
                    </parent>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>spring-boot-starter-actuator</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);

        var buildInfo = analyzer.analyze(tempDir);

        assertThat(buildInfo.buildTool()).isEqualTo(BuildTool.MAVEN);
        assertThat(buildInfo.springBootDetected()).isTrue();
        assertThat(buildInfo.dependencies())
                .contains(
                        "org.springframework.boot:spring-boot-starter-actuator",
                        "org.springframework.boot:spring-boot-starter-web");
        assertThat(buildInfo.modules())
                .extracting(module -> module.path())
                .containsExactly(".", "complete", "initial");
    }

    private void write(String relativePath, String content) throws IOException {
        Path file = tempDir.resolve(relativePath);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}

package com.robbanhoglund.springbootanalyzer.analyzer;

import static org.assertj.core.api.Assertions.assertThat;

import com.robbanhoglund.springbootanalyzer.analyzer.model.Finding;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CachingPracticeFindingAnalyzerTest {

    @TempDir Path repoRoot;

    private CachingPracticeFindingAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new CachingPracticeFindingAnalyzer();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void writeSourceFile(String relativePath, String content) throws IOException {
        Path file = repoRoot.resolve(relativePath);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }

    private List<Finding> findings() {
        return analyzer.analyze(repoRoot);
    }

    private void writeMutableListService() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                import java.util.List;
                public class ProductService {
                    @Cacheable("products")
                    public List<String> getAll() { return new java.util.ArrayList<>(); }
                }
                """);
    }

    private static Finding byRule(List<Finding> findings, String ruleId) {
        return findings.stream().filter(f -> ruleId.equals(f.ruleId())).findFirst().orElse(null);
    }

    // ── No sources ────────────────────────────────────────────────────────────

    @Test
    void returnsEmptyListWhenNoMainDirectory() {
        assertThat(findings()).isEmpty();
    }

    // ── SPRING_CACHEABLE_VOID_RETURN ──────────────────────────────────────────

    @Test
    void flagsCacheableOnVoidMethod() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable("products")
                    public void warmCache() {}
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHEABLE_VOID_RETURN");
        assertThat(f).isNotNull();
        assertThat(f.target()).isEqualTo("ProductService#warmCache");
        assertThat(f.message()).contains("void");
    }

    @Test
    void doesNotFlagCacheableOnNonVoidMethod() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable("products")
                    public String getProduct(Long id) { return ""; }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_VOID_RETURN")).isNull();
    }

    // ── SPRING_CACHEABLE_MUTABLE_RETURN_TYPE ──────────────────────────────────

    @Test
    void flagsCacheableReturningList() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                import java.util.List;
                public class ProductService {
                    @Cacheable("products")
                    public List<String> getAll() { return new java.util.ArrayList<>(); }
                }
                """);
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    @Bean
                    ConcurrentMapCacheManager cacheManager() {
                        return new ConcurrentMapCacheManager();
                    }
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE");
        assertThat(f).isNotNull();
        assertThat(f.message()).contains("List");
        assertThat(f.target()).isEqualTo("ProductService#getAll");
    }

    @Test
    void flagsCacheableReturningMap() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/CatalogService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                import java.util.Map;
                public class CatalogService {
                    @Cacheable("catalog")
                    public Map<String, String> getIndex() { return new java.util.HashMap<>(); }
                }
                """);
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.caffeine.CaffeineCacheManager;
                public class CacheConfiguration {
                    @Bean
                    CaffeineCacheManager cacheManager() {
                        return new CaffeineCacheManager();
                    }
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE");
        assertThat(f).isNotNull();
        assertThat(f.message()).contains("Map");
    }

    @Test
    void flagsCacheableListWithCaffeineReferenceStore() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                import java.util.List;
                public class ProductService {
                    @Cacheable("products")
                    public List<String> getAll() { return new java.util.ArrayList<>(); }
                }
                """);
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.caffeine.CaffeineCacheManager;
                public class CacheConfiguration {
                    @Bean
                    CaffeineCacheManager cacheManager() {
                        return new CaffeineCacheManager();
                    }
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE");
        assertThat(f).isNotNull();
        assertThat(f.target()).isEqualTo("ProductService#getAll");
    }

    @Test
    void doesNotFlagMutableReturnWhenProviderIsUnresolved() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                import java.util.List;
                public class ProductService {
                    @Cacheable("products")
                    public List<String> getAll() { return new java.util.ArrayList<>(); }
                }
                """);
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.CacheManager;
                public class CacheConfiguration {
                    @Bean
                    CacheManager cacheManager() { return cacheManagerFromElsewhere(); }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotFlagMutableReturnWhenRedisSerializesValues() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                import java.util.List;
                public class ProductService {
                    @Cacheable("products")
                    public List<String> getAll() { return new java.util.ArrayList<>(); }
                }
                """);
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.data.redis.cache.RedisCacheManager;
                public class CacheConfiguration {
                    @Bean
                    RedisCacheManager cacheManager() {
                        return RedisCacheManager.builder(connectionFactory()).build();
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotFlagImmutableListFactoryWithReferenceStoreManager() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                import java.util.List;
                public class ProductService {
                    @Cacheable("products")
                    public List<String> getAll() { return List.copyOf(List.of("one")); }
                }
                """);
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    @Bean
                    ConcurrentMapCacheManager cacheManager() {
                        return new ConcurrentMapCacheManager();
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotFlagReferenceStoreConfiguredForStoreByValue() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                import java.util.List;
                public class ProductService {
                    @Cacheable("products")
                    public List<String> getAll() { return new java.util.ArrayList<>(); }
                }
                """);
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    @Bean
                    ConcurrentMapCacheManager cacheManager() {
                        ConcurrentMapCacheManager manager = new ConcurrentMapCacheManager();
                        manager.setStoreByValue(true);
                        return manager;
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotTreatUnannotatedCacheManagerMethodNameAsConfiguration() throws IOException {
        writeMutableListService();
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    ConcurrentMapCacheManager cacheManager() {
                        return new ConcurrentMapCacheManager();
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotTreatCommentsOrUnusedManagerLocalsAsProviderProof() throws IOException {
        writeMutableListService();
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.CacheManager;
                import org.springframework.cache.caffeine.CaffeineCacheManager;
                public class CacheConfiguration {
                    @Bean
                    CacheManager cacheManager() {
                        // return new CaffeineCacheManager();
                        CaffeineCacheManager unused = new CaffeineCacheManager();
                        return cacheManagerFromElsewhere();
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotTreatNonCacheManagerBeanAsProviderProof() throws IOException {
        writeMutableListService();
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    @Bean
                    Object cacheProvider() { return new ConcurrentMapCacheManager(); }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotTreatCustomManagerWithSpringSimpleNameAsReferenceStore() throws IOException {
        writeMutableListService();
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import com.acme.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    @Bean
                    ConcurrentMapCacheManager cacheManager() {
                        return new ConcurrentMapCacheManager();
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotTreatCustomCachingConfigurerSuperclassAsSpringOverride() throws IOException {
        writeMutableListService();
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import com.acme.CachingConfigurerSupport;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration extends CachingConfigurerSupport {
                    @Override
                    public ConcurrentMapCacheManager cacheManager() {
                        return new ConcurrentMapCacheManager();
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotFlagMutableReturnWithMethodCacheManagerSelector() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                import java.util.List;
                public class ProductService {
                    @Cacheable(value = "products", cacheManager = "tenantCacheManager")
                    public List<String> getAll() { return new java.util.ArrayList<>(); }
                }
                """);
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    @Bean
                    ConcurrentMapCacheManager cacheManager() {
                        return new ConcurrentMapCacheManager();
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotFlagMutableReturnWithClassCacheResolverSelector() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.CacheConfig;
                import org.springframework.cache.annotation.Cacheable;
                import java.util.List;
                @CacheConfig(cacheResolver = "tenantCacheResolver")
                public class ProductService {
                    @Cacheable("products")
                    public List<String> getAll() { return new java.util.ArrayList<>(); }
                }
                """);
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    @Bean
                    ConcurrentMapCacheManager cacheManager() {
                        return new ConcurrentMapCacheManager();
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotFlagWhenStoreByValueUsesBooleanTrue() throws IOException {
        writeMutableListService();
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    @Bean
                    ConcurrentMapCacheManager cacheManager() {
                        ConcurrentMapCacheManager manager = new ConcurrentMapCacheManager();
                        manager.setStoreByValue(Boolean.TRUE);
                        return manager;
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void doesNotFlagWhenStoreByValueUsesProperty() throws IOException {
        writeMutableListService();
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    @Bean
                    ConcurrentMapCacheManager cacheManager() {
                        ConcurrentMapCacheManager manager = new ConcurrentMapCacheManager();
                        manager.setStoreByValue(cacheProperties().storeByValue());
                        return manager;
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    @Test
    void flagsWhenStoreByValueIsExplicitlyFalse() throws IOException {
        writeMutableListService();
        writeSourceFile(
                "src/main/java/com/example/CacheConfiguration.java",
                """
                package com.example;
                import org.springframework.context.annotation.Bean;
                import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
                public class CacheConfiguration {
                    @Bean
                    ConcurrentMapCacheManager cacheManager() {
                        ConcurrentMapCacheManager manager = new ConcurrentMapCacheManager();
                        manager.setStoreByValue(false);
                        return manager;
                    }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNotNull();
    }

    @Test
    void doesNotFlagCacheableReturningString() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable("products")
                    public String getById(Long id) { return ""; }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_MUTABLE_RETURN_TYPE")).isNull();
    }

    // ── SPRING_CACHE_ON_PRIVATE_METHOD ────────────────────────────────────────

    @Test
    void flagsCacheableOnPrivateMethod() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable("products")
                    private String loadProduct(Long id) { return ""; }
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHE_ON_PRIVATE_METHOD");
        assertThat(f).isNotNull();
        assertThat(f.target()).isEqualTo("ProductService#loadProduct");
        assertThat(f.message()).contains("private");
    }

    @Test
    void flagsCacheEvictOnPrivateMethod() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.CacheEvict;
                public class ProductService {
                    @CacheEvict("products")
                    private void evict(Long id) {}
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHE_ON_PRIVATE_METHOD");
        assertThat(f).isNotNull();
        assertThat(f.message()).contains("CacheEvict");
    }

    @Test
    void doesNotFlagCacheableOnPublicMethod() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable("products")
                    public String getById(Long id) { return ""; }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHE_ON_PRIVATE_METHOD")).isNull();
    }

    // ── SPRING_CACHE_SELF_INVOCATION ──────────────────────────────────────────

    @Test
    void flagsSelfInvocationOfCachedMethod() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable("products")
                    public String getById(Long id) { return ""; }

                    public String getByIdWrapped(Long id) {
                        return getById(id);
                    }
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHE_SELF_INVOCATION");
        assertThat(f).isNotNull();
        assertThat(f.message()).contains("getById");
        assertThat(f.target()).isEqualTo("ProductService#getByIdWrapped");
    }

    @Test
    void flagsExplicitThisSelfInvocationOfCachedMethod() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable("products")
                    public String getById(Long id) { return ""; }

                    public String load(Long id) {
                        return this.getById(id);
                    }
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHE_SELF_INVOCATION");
        assertThat(f).isNotNull();
        assertThat(f.message()).contains("getById");
    }

    @Test
    void doesNotFlagClassWithNoCachedMethods() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                public class ProductService {
                    public String getById(Long id) { return ""; }
                    public String load(Long id) { return getById(id); }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHE_SELF_INVOCATION")).isNull();
    }

    // ── SPRING_CACHE_EVICT_WITHOUT_ALL_ENTRIES ────────────────────────────────

    @Test
    void flagsCacheEvictOnNoArgMethodWithoutAllEntries() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/CacheManager.java",
                """
                package com.example;
                import org.springframework.cache.annotation.CacheEvict;
                public class CacheManager {
                    @CacheEvict("products")
                    public void clearCache() {}
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHE_EVICT_WITHOUT_ALL_ENTRIES");
        assertThat(f).isNotNull();
        assertThat(f.target()).isEqualTo("CacheManager#clearCache");
        assertThat(f.recommendation()).contains("allEntries");
    }

    @Test
    void doesNotFlagCacheEvictWithAllEntriesTrue() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/CacheManager.java",
                """
                package com.example;
                import org.springframework.cache.annotation.CacheEvict;
                public class CacheManager {
                    @CacheEvict(value = "products", allEntries = true)
                    public void clearCache() {}
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHE_EVICT_WITHOUT_ALL_ENTRIES")).isNull();
    }

    @Test
    void doesNotFlagCacheEvictOnMethodWithParameters() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/CacheManager.java",
                """
                package com.example;
                import org.springframework.cache.annotation.CacheEvict;
                public class CacheManager {
                    @CacheEvict("products")
                    public void evictById(Long id) {}
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHE_EVICT_WITHOUT_ALL_ENTRIES")).isNull();
    }

    // ── SPRING_CACHEABLE_SYNC_INCOMPATIBLE ────────────────────────────────────

    @Test
    void flagsCacheableSyncTrueWithUnless() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable(value = "products", sync = true, unless = "#result == null")
                    public String getById(Long id) { return ""; }
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHEABLE_SYNC_INCOMPATIBLE");
        assertThat(f).isNotNull();
        assertThat(f.target()).isEqualTo("ProductService#getById");
        assertThat(f.message()).contains("unless");
    }

    @Test
    void flagsCacheableSyncTrueWithMultipleCacheNames() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable(value = {"products", "catalog"}, sync = true)
                    public String getById(Long id) { return ""; }
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHEABLE_SYNC_INCOMPATIBLE");
        assertThat(f).isNotNull();
        assertThat(f.target()).isEqualTo("ProductService#getById");
        assertThat(f.message()).contains("multiple cache names");
    }

    @Test
    void flagsCacheableSyncTrueWithCacheNamesAndUnless() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable(cacheNames = {"a", "b"}, sync = true, unless = "#result == null")
                    public String getById(Long id) { return ""; }
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHEABLE_SYNC_INCOMPATIBLE");
        assertThat(f).isNotNull();
        assertThat(f.message()).contains("unless").contains("multiple cache names");
    }

    @Test
    void doesNotFlagCacheableSyncTrueWithSingleCacheAndNoUnless() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable(value = "products", sync = true)
                    public String getById(Long id) { return ""; }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_SYNC_INCOMPATIBLE")).isNull();
    }

    @Test
    void doesNotFlagCacheableSyncFalseWithMultipleCaches() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable(value = {"products", "catalog"}, sync = false)
                    public String getById(Long id) { return ""; }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_SYNC_INCOMPATIBLE")).isNull();
    }

    @Test
    void doesNotFlagCacheableWithoutSyncAttribute() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable(value = {"products", "catalog"}, unless = "#result == null")
                    public String getById(Long id) { return ""; }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEABLE_SYNC_INCOMPATIBLE")).isNull();
    }

    // ── SPRING_CACHEPUT_AND_CACHEABLE_SAME_METHOD ─────────────────────────────

    @Test
    void flagsCachePutAndCacheableOnSameMethod() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                import org.springframework.cache.annotation.CachePut;
                public class ProductService {
                    @Cacheable("products")
                    @CachePut("products")
                    public String getAndUpdate(Long id) { return ""; }
                }
                """);

        Finding f = byRule(findings(), "SPRING_CACHEPUT_AND_CACHEABLE_SAME_METHOD");
        assertThat(f).isNotNull();
        assertThat(f.target()).isEqualTo("ProductService#getAndUpdate");
        assertThat(f.message()).contains("CachePut").contains("Cacheable");
    }

    @Test
    void doesNotFlagMethodWithOnlyCacheable() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.Cacheable;
                public class ProductService {
                    @Cacheable("products")
                    public String getById(Long id) { return ""; }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEPUT_AND_CACHEABLE_SAME_METHOD")).isNull();
    }

    @Test
    void doesNotFlagMethodWithOnlyCachePut() throws IOException {
        writeSourceFile(
                "src/main/java/com/example/ProductService.java",
                """
                package com.example;
                import org.springframework.cache.annotation.CachePut;
                public class ProductService {
                    @CachePut("products")
                    public String update(Long id) { return ""; }
                }
                """);

        assertThat(byRule(findings(), "SPRING_CACHEPUT_AND_CACHEABLE_SAME_METHOD")).isNull();
    }
}

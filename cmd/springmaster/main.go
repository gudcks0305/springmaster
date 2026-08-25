// springmaster discovers local Spring repositories and delegates semantic
// analysis to a persistent Java worker pool.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/gudcks0305/springmaster/internal/analyzer"
	"github.com/gudcks0305/springmaster/internal/cache"
	"github.com/gudcks0305/springmaster/internal/graph"
	"github.com/gudcks0305/springmaster/internal/report"
	"github.com/gudcks0305/springmaster/internal/semantic"
	"github.com/gudcks0305/springmaster/internal/snapshot"
	"github.com/gudcks0305/springmaster/internal/workspace"
)

const (
	workerSchemaVersion              = 1
	resultFingerprintVersion         = "springmaster-result-fingerprint-v1"
	maxRuleConfigBytes         int64 = 8 << 20
	maxRunSnapshotRepositories       = 128
	maxRunSnapshotFiles              = 200_000
	maxRunSnapshotBytes        int64 = 1 << 30
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] == "--help" || arguments[0] == "-h" || arguments[0] == "help" {
		writeUsage(stdout)
		return exitClean
	}
	if arguments[0] != "scan" {
		fmt.Fprintf(stderr, "invalid command %q\n", arguments[0])
		writeUsage(stderr)
		return exitInvalidArgs
	}

	options, err := parseScanArgs(arguments[1:])
	if errors.Is(err, errHelp) {
		writeUsage(stdout)
		return exitClean
	}
	if err != nil {
		fmt.Fprintf(stderr, "invalid arguments: %v\n", err)
		writeUsage(stderr)
		return exitInvalidArgs
	}
	return runScan(ctx, options, stdout, stderr)
}

func runScan(ctx context.Context, options scanOptions, stdout, stderr io.Writer) int {
	root, err := filepath.Abs(options.root)
	if err != nil {
		fmt.Fprintf(stderr, "resolve ROOT: %v\n", err)
		return exitOperational
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		fmt.Fprintf(stderr, "canonicalize ROOT: %v\n", err)
		return exitOperational
	}
	workspaceDiagnostics := make([]workspace.Diagnostic, 0)
	repositories, err := workspace.Discover(ctx, root, workspace.Options{
		MaxDepth: options.maxDepth,
		Include:  options.include,
		Exclude:  options.exclude,
		OnDiagnostic: func(diagnostic workspace.Diagnostic) {
			workspaceDiagnostics = append(workspaceDiagnostics, diagnostic)
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "discover repositories: %v\n", err)
		return exitOperational
	}
	writeWorkspaceDiagnostics(stderr, workspaceDiagnostics)
	repositories, dependencyGraph, err := orderByDependencies(ctx, repositories)
	if err != nil {
		fmt.Fprintf(stderr, "build repository dependency graph: %v\n", err)
		return exitOperational
	}
	writeGraphDiagnostics(stderr, dependencyGraph.Diagnostics)
	if len(repositories) == 0 {
		if err := writeReport(options, stdout, report.Aggregate(nil)); err != nil {
			fmt.Fprintf(stderr, "write report: %v\n", err)
			return exitOperational
		}
		return exitClean
	}
	if len(repositories) > maxRunSnapshotRepositories {
		fmt.Fprintf(stderr, "snapshot budget: repository count %d exceeds run limit %d\n", len(repositories), maxRunSnapshotRepositories)
		return exitOperational
	}
	if options.mode == "EXTENDED" && len(repositories) != 1 {
		fmt.Fprintf(stderr, "EXTENDED requires exactly one discovered repository; found %d (scan each repository separately in an isolated environment)\n", len(repositories))
		return exitInvalidArgs
	}
	if err := configureStoragePaths(&options, repositories); err != nil {
		fmt.Fprintf(stderr, "invalid storage path: %v\n", err)
		return exitInvalidArgs
	}
	if options.mode == "EXTENDED" {
		fmt.Fprintln(stderr, "WARNING: EXTENDED executes repository-controlled build logic. --trust-extended is consent, not a sandbox; use a disposable restricted environment.")
	}

	command, err := splitCommand(options.workerCommand)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --worker-command: %v\n", err)
		return exitInvalidArgs
	}
	workerIdentity, err := commandIdentity(command)
	if err != nil {
		fmt.Fprintf(stderr, "identify analyzer worker: %v\n", err)
		return exitOperational
	}
	var resultCache *cache.Store
	resultFingerprint := "cache-disabled"
	if !options.noCache {
		resultFingerprint, err = resultConfigurationFingerprint(command, options.mode)
		if err != nil {
			fmt.Fprintf(stderr, "fingerprint analyzer configuration: %v\n", err)
			return exitOperational
		}
		resultCache, err = cache.Open(options.cacheDir)
		if err != nil {
			fmt.Fprintf(stderr, "open cache: %v\n", err)
			return exitOperational
		}
	}
	runSnapshotRoot, err := createRunSnapshotRoot()
	if err != nil {
		fmt.Fprintf(stderr, "create private snapshot root: %v\n", err)
		return exitOperational
	}
	defer func() { _ = os.Remove(runSnapshotRoot) }()

	results := make([]report.Repository, len(repositories))
	prepared := make([]preparedRepository, len(repositories))
	for index, repository := range repositories {
		results[index] = repositoryReport(repository)
	}
	budget := runSnapshotBudget{
		maxFiles: maxRunSnapshotFiles,
		maxBytes: maxRunSnapshotBytes,
	}
	var budgetErr error
	for index, repository := range repositories {
		remainingFiles := budget.maxFiles - budget.files
		remainingBytes := budget.maxBytes - budget.bytes
		if remainingFiles <= 0 || remainingBytes <= 0 {
			budgetErr = fmt.Errorf(
				"run snapshot budget exceeded (limits: %d entries, %d bytes)",
				budget.maxFiles,
				budget.maxBytes,
			)
			break
		}
		repositorySnapshot, snapshotErr := snapshot.Create(ctx, repository.Path, snapshot.Options{
			DestinationDir: runSnapshotRoot,
			Prefix:         "springmaster-",
			MaxFiles:       min(remainingFiles, snapshot.DefaultMaxFiles),
			MaxTotalBytes:  min(remainingBytes, snapshot.DefaultMaxTotalBytes),
		})
		if snapshotErr != nil {
			if errors.Is(snapshotErr, snapshot.ErrLimitExceeded) {
				budgetErr = fmt.Errorf(
					"run snapshot budget exceeded while preparing repository (limits: %d entries, %d bytes)",
					budget.maxFiles,
					budget.maxBytes,
				)
				break
			}
			results[index].Error = fmt.Sprintf("create snapshot: %v", snapshotErr)
			continue
		}
		prepared[index] = preparedRepository{repository: repository, snapshot: repositorySnapshot}
		if err := budget.add(repositorySnapshot.FileCount, repositorySnapshot.TotalBytes); err != nil {
			budgetErr = err
			break
		}
	}

	if budgetErr != nil {
		for index := range prepared {
			results[index].Error = budgetErr.Error()
			cleanupPreparedSnapshot(&prepared[index], &results[index])
		}
	} else if exactGraph, graphErr := assignSnapshotHashes(ctx, prepared); graphErr != nil {
		for index := range prepared {
			if prepared[index].snapshot != nil && results[index].Error == "" {
				results[index].Error = fmt.Sprintf("build snapshot dependency graph: %v", graphErr)
			}
			cleanupPreparedSnapshot(&prepared[index], &results[index])
		}
	} else if contextErr := materializeDependencyContexts(ctx, exactGraph, prepared, results, &budget); contextErr != nil {
		for index := range prepared {
			results[index].Error = contextErr.Error()
			cleanupPreparedSnapshot(&prepared[index], &results[index])
		}
	}
	for index := range prepared {
		if results[index].Error != "" {
			cleanupPreparedSnapshot(&prepared[index], &results[index])
		}
	}

	misses := make([]int, 0, len(repositories))
	for index := range prepared {
		if prepared[index].snapshot == nil || results[index].Error != "" {
			continue
		}
		prepared[index].cacheKey = analysisCacheKey(workerIdentity, resultFingerprint, options, prepared[index])
		if resultCache != nil {
			cached, found, cacheErr := resultCache.Get(ctx, prepared[index].cacheKey)
			if cacheErr == nil && found {
				findings, extractErr := report.ExtractFindings(cached)
				if extractErr == nil {
					results[index].Status = report.StatusCompleted
					results[index].Result = cached
					results[index].Findings = findings
					cleanupPreparedSnapshot(&prepared[index], &results[index])
					continue
				}
			}
		}
		misses = append(misses, index)
	}

	var pool *analyzer.Pool
	if len(misses) > 0 {
		pool, err = analyzer.NewPool(analyzer.Config{
			Command:               command,
			Workers:               min(options.workers, len(misses)),
			AllowedRoot:           runSnapshotRoot,
			RequireSnapshotMarker: true,
		})
		if err != nil {
			for _, index := range misses {
				results[index].Error = fmt.Sprintf("start analyzer workers: %v", err)
				cleanupPreparedSnapshot(&prepared[index], &results[index])
			}
		} else {
			jobs := make(chan int)
			var group sync.WaitGroup
			workerCount := min(options.workers, len(misses))
			for range workerCount {
				group.Add(1)
				go func() {
					defer group.Done()
					for index := range jobs {
						results[index] = analyzePreparedRepository(
							ctx, pool, resultCache, options, prepared[index])
						cleanupPreparedSnapshot(&prepared[index], &results[index])
					}
				}()
			}
			for _, index := range misses {
				jobs <- index
			}
			close(jobs)
			group.Wait()
		}
	}

	if pool != nil {
		if closeErr := pool.Close(); closeErr != nil {
			fmt.Fprintf(stderr, "close analyzer workers: %v\n", closeErr)
			for _, index := range misses {
				if results[index].Status == report.StatusCompleted {
					results[index].Status = report.StatusFailed
					results[index].Error = fmt.Sprintf("close analyzer workers: %v", closeErr)
				}
			}
		}
	}
	writeCacheDiagnostics(stderr, results)
	for index := range prepared {
		if prepared[index].snapshot == nil {
			continue
		}
		if cleanupErr := prepared[index].snapshot.Cleanup(); cleanupErr != nil {
			results[index].Status = report.StatusFailed
			results[index].Error = fmt.Sprintf("cleanup snapshot: %v", cleanupErr)
		}
	}
	if cleanupErr := os.Remove(runSnapshotRoot); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
		fmt.Fprintf(stderr, "cleanup private snapshot root: %v\n", cleanupErr)
		for index := range results {
			if results[index].Status == report.StatusCompleted {
				results[index].Status = report.StatusFailed
				results[index].Error = fmt.Sprintf("cleanup private snapshot root: %v", cleanupErr)
			}
		}
	}

	aggregated := report.Aggregate(results)
	if err := writeReport(options, stdout, aggregated); err != nil {
		fmt.Fprintf(stderr, "write report: %v\n", err)
		return exitOperational
	}
	result := exitClean
	if aggregated.Summary.Failed > 0 {
		result = exitOperational
	} else if aggregated.MeetsThreshold(options.failOn) {
		result = exitFindings
	}
	return result
}

func createRunSnapshotRoot() (string, error) {
	directory, err := os.MkdirTemp(os.TempDir(), "springmaster-run-")
	if err != nil {
		return "", err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(directory)
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", fmt.Errorf("set private permissions: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return "", fmt.Errorf("canonicalize snapshot root: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("stat snapshot root: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", fmt.Errorf("snapshot root is not a private 0700 directory")
	}
	remove = false
	return canonical, nil
}

type runSnapshotBudget struct {
	files    int
	bytes    int64
	maxFiles int
	maxBytes int64
}

func (budget *runSnapshotBudget) add(files int, bytes int64) error {
	if files < 0 || bytes < 0 || files > budget.maxFiles-budget.files || bytes > budget.maxBytes-budget.bytes {
		return fmt.Errorf(
			"run snapshot budget exceeded (limits: %d entries, %d bytes)",
			budget.maxFiles,
			budget.maxBytes,
		)
	}
	budget.files += files
	budget.bytes += bytes
	return nil
}

func cleanupPreparedSnapshot(prepared *preparedRepository, result *report.Repository) {
	if prepared.context != nil {
		cleanupErr := prepared.context.Cleanup()
		prepared.context = nil
		if cleanupErr != nil {
			result.Status = report.StatusFailed
			result.Error = fmt.Sprintf("cleanup dependency context: %v", cleanupErr)
		}
	}
	if prepared.snapshot == nil {
		return
	}
	cleanupErr := prepared.snapshot.Cleanup()
	prepared.snapshot = nil
	if cleanupErr != nil {
		result.Status = report.StatusFailed
		result.Error = fmt.Sprintf("cleanup snapshot: %v", cleanupErr)
	}
}

type preparedRepository struct {
	repository  workspace.Repository
	snapshot    *snapshot.Snapshot
	context     *semantic.Context
	contentHash string
	cacheKey    string
}

func repositoryReport(repository workspace.Repository) report.Repository {
	return report.Repository{
		ID:        repository.ID,
		Path:      repository.Path,
		Branch:    repository.Branch,
		Head:      repository.Head,
		RemoteURL: repository.RemoteURL,
		Status:    report.StatusFailed,
	}
}

func assignSnapshotHashes(ctx context.Context, prepared []preparedRepository) (*graph.Graph, error) {
	inputs := make([]graph.Repository, 0, len(prepared))
	for index := range prepared {
		if prepared[index].snapshot == nil {
			continue
		}
		prepared[index].contentHash = prepared[index].snapshot.ContentHash
		inputs = append(inputs, graph.Repository{
			ID:          prepared[index].repository.ID,
			Path:        prepared[index].snapshot.Root,
			ContentHash: prepared[index].snapshot.ContentHash,
		})
	}
	if len(inputs) == 0 {
		return nil, nil
	}
	exactGraph, err := graph.Build(ctx, inputs)
	if err != nil {
		return nil, err
	}
	for index := range prepared {
		if prepared[index].snapshot == nil {
			continue
		}
		if effectiveHash := exactGraph.EffectiveHash(prepared[index].repository.ID); effectiveHash != "" {
			prepared[index].contentHash = effectiveHash
		}
	}
	return exactGraph, nil
}

func materializeDependencyContexts(
	ctx context.Context,
	exactGraph *graph.Graph,
	prepared []preparedRepository,
	results []report.Repository,
	budget *runSnapshotBudget,
) error {
	if exactGraph == nil {
		return nil
	}
	roots := make([]semantic.SnapshotRoot, 0, len(prepared))
	for index := range prepared {
		if prepared[index].snapshot != nil {
			roots = append(roots, semantic.SnapshotRoot{
				RepositoryID: prepared[index].repository.ID,
				Root:         prepared[index].snapshot.Root,
			})
		}
	}
	for index := range prepared {
		if prepared[index].snapshot == nil || results[index].Error != "" {
			continue
		}
		dependencies, err := semantic.DependencyClosure(exactGraph, prepared[index].repository.ID)
		if err != nil {
			results[index].Error = fmt.Sprintf("resolve dependency context: %v", err)
			continue
		}
		if len(dependencies) == 0 {
			continue
		}
		remainingFiles := budget.maxFiles - budget.files
		remainingBytes := budget.maxBytes - budget.bytes
		if remainingFiles <= 0 || remainingBytes <= 0 {
			return fmt.Errorf(
				"run snapshot budget exceeded while materializing dependency context (limits: %d entries, %d bytes)",
				budget.maxFiles,
				budget.maxBytes,
			)
		}
		dependencyContext, err := semantic.Materialize(ctx, exactGraph, prepared[index].repository.ID, roots, semantic.Options{
			Mode:          semantic.CopyModeAuto,
			MaxFiles:      min(remainingFiles, 50_000),
			MaxTotalBytes: min(remainingBytes, int64(512<<20)),
		})
		if err != nil {
			results[index].Error = fmt.Sprintf("materialize dependency context: %v", err)
			continue
		}
		prepared[index].context = dependencyContext
		results[index].DependencyContextPath = dependencyContext.Path
		if err := budget.add(dependencyContext.FileCount, dependencyContext.TotalBytes); err != nil {
			return err
		}
		prepared[index].contentHash = combineContentIdentity(
			prepared[index].contentHash,
			dependencyContext.ContentHash,
		)
	}
	return nil
}

func combineContentIdentity(repositoryHash, dependencyContextHash string) string {
	digest := sha256.New()
	writeFingerprintField(digest, "format", "springmaster-analysis-content-v1")
	writeFingerprintField(digest, "repository", repositoryHash)
	writeFingerprintField(digest, "dependency-context", dependencyContextHash)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func analysisCacheKey(workerIdentity, resultFingerprint string, options scanOptions, prepared preparedRepository) string {
	return cache.Key(
		fmt.Sprintf(
			"schema=%d\x00worker=%s\x00repository=%s",
			workerSchemaVersion,
			workerIdentity,
			prepared.repository.ID,
		),
		prepared.contentHash,
		options.mode,
		resultFingerprint,
	)
}

func analyzePreparedRepository(
	parent context.Context,
	pool *analyzer.Pool,
	resultCache *cache.Store,
	options scanOptions,
	prepared preparedRepository,
) (entry report.Repository) {
	repository := prepared.repository
	entry = repositoryReport(repository)
	if prepared.context != nil {
		entry.DependencyContextPath = prepared.context.Path
	}
	ctx, cancel := context.WithTimeout(parent, options.timeout)
	defer cancel()

	response, err := pool.Analyze(ctx, analyzer.Request{
		SchemaVersion:  workerSchemaVersion,
		RequestID:      repository.ID,
		RepositoryPath: prepared.snapshot.Root,
		RepositoryID:   repository.ID,
		RepositoryURL:  repository.RemoteURL,
		Branch:         repository.Branch,
		ContentHash:    prepared.contentHash,
		Mode:           options.mode,
	})
	if err != nil {
		entry.Error = fmt.Sprintf("analyze: %v", err)
		return entry
	}
	if response.Status != "completed" {
		entry.Error = responseError(response)
		return entry
	}
	findings, err := report.ExtractFindings(response.Result)
	if err != nil {
		entry.Error = fmt.Sprintf("decode analyzer result: %v", err)
		return entry
	}
	entry.Status = report.StatusCompleted
	entry.Result = response.Result
	entry.Findings = findings
	if resultCache != nil && response.Result != nil {
		// Cache failure must not discard a completed analysis. The next scan will
		// recompute it instead of trusting a partial entry.
		if err := resultCache.Put(ctx, prepared.cacheKey, response.Result); err != nil {
			entry.CacheWarning = "completed result was not cached (entry too large or cache unavailable)"
		}
	}
	return entry
}

func writeCacheDiagnostics(output io.Writer, repositories []report.Repository) {
	const limit = 20
	written := 0
	omitted := 0
	for _, repository := range repositories {
		if repository.CacheWarning == "" {
			continue
		}
		if written == limit {
			omitted++
			continue
		}
		fmt.Fprintf(output, "cache [%s]: %s\n", repository.ID, repository.CacheWarning)
		written++
	}
	if omitted > 0 {
		fmt.Fprintf(output, "cache: %d additional diagnostics omitted\n", omitted)
	}
}

func orderByDependencies(
	ctx context.Context,
	repositories []workspace.Repository,
) ([]workspace.Repository, *graph.Graph, error) {
	inputs := make([]graph.Repository, 0, len(repositories))
	byID := make(map[string]workspace.Repository, len(repositories))
	for _, repository := range repositories {
		inputs = append(inputs, graph.Repository{
			ID:          repository.ID,
			Path:        repository.Path,
			ContentHash: repository.ContentHash,
		})
		byID[repository.ID] = repository
	}
	dependencyGraph, err := graph.Build(ctx, inputs)
	if err != nil {
		return nil, nil, err
	}
	ordered := make([]workspace.Repository, 0, len(repositories))
	for _, repositoryID := range dependencyGraph.DependencyFirstOrder() {
		repository, exists := byID[repositoryID]
		if !exists {
			return nil, nil, fmt.Errorf("dependency graph returned unknown repository %q", repositoryID)
		}
		ordered = append(ordered, repository)
	}
	return ordered, dependencyGraph, nil
}

func writeGraphDiagnostics(output io.Writer, diagnostics []graph.Diagnostic) {
	const limit = 20
	type groupedDiagnostic struct {
		diagnostic   graph.Diagnostic
		count        int
		repositories map[string]struct{}
	}
	grouped := make(map[string]groupedDiagnostic, len(diagnostics))
	keys := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		key := strings.Join([]string{diagnostic.Code, diagnostic.Message}, "\x00")
		current, exists := grouped[key]
		if !exists {
			keys = append(keys, key)
			current.diagnostic = diagnostic
			current.repositories = make(map[string]struct{})
		}
		current.count++
		current.repositories[diagnostic.RepositoryID] = struct{}{}
		grouped[key] = current
	}
	sort.Strings(keys)
	for index, key := range keys {
		if index == limit {
			fmt.Fprintf(output, "dependency graph: %d additional diagnostic groups omitted\n", len(keys)-limit)
			break
		}
		item := grouped[key]
		repositoryIDs := make([]string, 0, len(item.repositories))
		for repositoryID := range item.repositories {
			repositoryIDs = append(repositoryIDs, repositoryID)
		}
		sort.Strings(repositoryIDs)
		suffix := ""
		if item.count > 1 {
			suffix = fmt.Sprintf(" (x%d)", item.count)
		}
		fmt.Fprintf(
			output,
			"dependency graph [%s] %s: %s%s\n",
			strings.Join(repositoryIDs, ","),
			item.diagnostic.Code,
			item.diagnostic.Message,
			suffix,
		)
	}
}

func writeWorkspaceDiagnostics(output io.Writer, diagnostics []workspace.Diagnostic) {
	const (
		groupLimit   = 20
		exampleLimit = 3
	)
	type group struct {
		code    string
		message string
		paths   []string
	}
	groups := make(map[string]*group)
	keys := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		key := diagnostic.Code + "\x00" + diagnostic.Message
		current := groups[key]
		if current == nil {
			current = &group{code: diagnostic.Code, message: diagnostic.Message}
			groups[key] = current
			keys = append(keys, key)
		}
		current.paths = append(current.paths, diagnostic.Path)
	}
	sort.Strings(keys)
	for index, key := range keys {
		if index == groupLimit {
			fmt.Fprintf(output, "workspace: %d additional diagnostic groups omitted\n", len(keys)-groupLimit)
			break
		}
		current := groups[key]
		sort.Strings(current.paths)
		examples := current.paths
		if len(examples) > exampleLimit {
			examples = examples[:exampleLimit]
		}
		quoted := make([]string, 0, len(examples))
		for _, path := range examples {
			quoted = append(quoted, strconv.Quote(path))
		}
		fmt.Fprintf(
			output,
			"workspace diagnostic %s: %s (%d paths; examples: %s)\n",
			strconv.Quote(current.code),
			strconv.Quote(current.message),
			len(current.paths),
			strings.Join(quoted, ", "),
		)
	}
}

func commandIdentity(command []string) (string, error) {
	digest := sha256.New()
	for index, argument := range command {
		_, _ = fmt.Fprintf(digest, "argument:%d:%d:%s\n", index, len(argument), argument)
		candidate := argument
		if index == 0 && !strings.ContainsRune(candidate, filepath.Separator) {
			resolved, err := exec.LookPath(candidate)
			if err != nil {
				return "", err
			}
			candidate = resolved
		}
		info, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) || info != nil && !info.Mode().IsRegular() {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("stat command artifact %q: %w", candidate, err)
		}
		file, err := os.Open(candidate)
		if err != nil {
			return "", fmt.Errorf("open command artifact %q: %w", candidate, err)
		}
		_, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if copyErr != nil {
			return "", fmt.Errorf("hash command artifact %q: %w", candidate, copyErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close command artifact %q: %w", candidate, closeErr)
		}
	}
	return fmt.Sprintf("%x", digest.Sum(nil)), nil
}

func resultConfigurationFingerprint(command []string, mode string) (string, error) {
	digest := sha256.New()
	writeFingerprintField(digest, "version", resultFingerprintVersion)
	writeFingerprintField(digest, "mode", mode)
	environment := os.Environ()
	for _, entry := range resultAffectingEnvironment(mode, environment) {
		writeFingerprintField(digest, "environment", entry)
	}
	for _, configPath := range ruleConfigCandidates(command, environment) {
		if err := hashRuleConfigState(digest, configPath); err != nil {
			return "", err
		}
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func resultAffectingEnvironment(mode string, environment []string) []string {
	staticNames := map[string]struct{}{
		"HOME": {}, "USERPROFILE": {}, "JAVA_HOME": {},
		"JAVA_TOOL_OPTIONS": {}, "_JAVA_OPTIONS": {}, "JDK_JAVA_OPTIONS": {},
		"LANG": {}, "LC_ALL": {}, "LC_CTYPE": {}, "TZ": {},
	}
	selected := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if !found || name == "" {
			continue
		}
		include := mode == "EXTENDED"
		if !include {
			_, include = staticNames[name]
			include = include || strings.HasPrefix(name, "ANALYZER_") || strings.HasPrefix(name, "SPRING_")
		}
		if include {
			selected = append(selected, entry)
		}
	}
	sort.Strings(selected)
	return selected
}

func ruleConfigCandidates(command, environment []string) []string {
	homes := make(map[string]struct{})
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		homes[home] = struct{}{}
	}
	collectUserHomes(homes, command)
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found || name != "JAVA_TOOL_OPTIONS" && name != "_JAVA_OPTIONS" && name != "JDK_JAVA_OPTIONS" {
			continue
		}
		arguments, err := splitCommand(value)
		if err == nil {
			collectUserHomes(homes, arguments)
		}
	}
	paths := make([]string, 0, len(homes))
	for home := range homes {
		if !filepath.IsAbs(home) {
			if absolute, err := filepath.Abs(home); err == nil {
				home = absolute
			}
		}
		paths = append(paths, filepath.Clean(filepath.Join(home, ".spring-boot-analyzer", "rule-config.json")))
	}
	sort.Strings(paths)
	return paths
}

func collectUserHomes(homes map[string]struct{}, arguments []string) {
	for _, argument := range arguments {
		if value, found := strings.CutPrefix(argument, "-Duser.home="); found && value != "" {
			homes[value] = struct{}{}
		}
	}
}

func hashRuleConfigState(digest io.Writer, path string) error {
	writeFingerprintField(digest, "rule-config-path", path)
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		writeFingerprintField(digest, "rule-config-state", "missing")
		return nil
	}
	if err != nil {
		return errors.New("open rule config for fingerprint")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return errors.New("stat rule config for fingerprint")
	}
	if !before.Mode().IsRegular() {
		writeFingerprintField(digest, "rule-config-state", "non-regular")
		return nil
	}
	if before.Size() > maxRuleConfigBytes {
		return fmt.Errorf("rule config exceeds %d byte fingerprint limit", maxRuleConfigBytes)
	}
	contentsDigest := sha256.New()
	copied, err := io.Copy(contentsDigest, io.LimitReader(file, maxRuleConfigBytes+1))
	if err != nil {
		return errors.New("read rule config for fingerprint")
	}
	if copied > maxRuleConfigBytes {
		return fmt.Errorf("rule config exceeds %d byte fingerprint limit", maxRuleConfigBytes)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("rule config changed while fingerprinting")
	}
	writeFingerprintField(digest, "rule-config-state", "regular")
	writeFingerprintField(digest, "rule-config-size", fmt.Sprintf("%d", copied))
	writeFingerprintField(digest, "rule-config-sha256", hex.EncodeToString(contentsDigest.Sum(nil)))
	return nil
}

func writeFingerprintField(output io.Writer, name, value string) {
	_, _ = fmt.Fprintf(output, "%s:%d:", name, len(value))
	_, _ = io.WriteString(output, value)
	_, _ = io.WriteString(output, "\n")
}

func responseError(response analyzer.Response) string {
	if response.Error == nil {
		return "analyzer returned failed response"
	}
	if response.Error.Code == "" {
		return response.Error.Message
	}
	if response.Error.Message == "" {
		return response.Error.Code
	}
	return response.Error.Code + ": " + response.Error.Message
}

func configureStoragePaths(options *scanOptions, repositories []workspace.Repository) error {
	if !options.noCache && options.cacheDir == "" {
		userCacheDirectory, err := os.UserCacheDir()
		if err != nil {
			return fmt.Errorf("resolve user cache directory: %w", err)
		}
		options.cacheDir = filepath.Join(userCacheDirectory, "springmaster")
	}

	paths := []struct {
		name  string
		value *string
	}{
		{name: "--output", value: &options.output},
	}
	if !options.noCache {
		paths = append(paths, struct {
			name  string
			value *string
		}{name: "--cache-dir", value: &options.cacheDir})
	}
	for _, candidate := range paths {
		if *candidate.value == "" {
			continue
		}
		absolute, err := filepath.Abs(*candidate.value)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", candidate.name, err)
		}
		absolute = filepath.Clean(absolute)
		if candidate.name == "--output" {
			if info, statErr := os.Lstat(absolute); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%s must not be a symlink: %s", candidate.name, absolute)
			} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
				return fmt.Errorf("inspect %s: %w", candidate.name, statErr)
			}
		}
		resolved, err := resolveProspectivePath(*candidate.value)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", candidate.name, err)
		}
		*candidate.value = absolute
		if candidate.name == "--cache-dir" {
			if err := rejectBroadCachePath(resolved, repositories); err != nil {
				return err
			}
		}
		if options.allowSourceWrite {
			continue
		}
		for _, repository := range repositories {
			repositoryRoot, err := filepath.EvalSymlinks(repository.Path)
			if err != nil {
				return fmt.Errorf("resolve repository source %s: %w", repository.Path, err)
			}
			if pathWithin(repositoryRoot, resolved) {
				return fmt.Errorf("%s %s is inside source repository %s (use --allow-source-write only when intentional)", candidate.name, resolved, repository.Path)
			}
		}
	}
	return nil
}

func rejectBroadCachePath(cachePath string, repositories []workspace.Repository) error {
	volumeRoot := filepath.Clean(filepath.VolumeName(cachePath) + string(filepath.Separator))
	if cachePath == volumeRoot {
		return errors.New("--cache-dir must be a dedicated leaf directory, not a filesystem root")
	}
	specialPaths := make([]string, 0, 2)
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if resolved, err := resolveProspectivePath(home); err == nil {
			specialPaths = append(specialPaths, resolved)
		}
	}
	if resolved, err := resolveProspectivePath(os.TempDir()); err == nil {
		specialPaths = append(specialPaths, resolved)
	}
	for _, specialPath := range specialPaths {
		if cachePath == specialPath {
			return errors.New("--cache-dir must be a dedicated leaf directory, not home or the temporary root")
		}
	}
	for _, repository := range repositories {
		repositoryRoot, err := filepath.EvalSymlinks(repository.Path)
		if err != nil {
			return fmt.Errorf("resolve repository source %s: %w", repository.Path, err)
		}
		if pathWithin(cachePath, repositoryRoot) {
			return fmt.Errorf("--cache-dir must not be a source ancestor: %s", cachePath)
		}
	}
	return nil
}

func resolveProspectivePath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absPath = filepath.Clean(absPath)
	ancestor := absPath
	for {
		_, err := os.Lstat(ancestor)
		if err == nil {
			resolvedAncestor, err := filepath.EvalSymlinks(ancestor)
			if err != nil {
				return "", err
			}
			relative, err := filepath.Rel(ancestor, absPath)
			if err != nil {
				return "", err
			}
			return filepath.Clean(filepath.Join(resolvedAncestor, relative)), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", fmt.Errorf("no existing ancestor for %s", path)
		}
		ancestor = parent
	}
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil {
		return false
	}
	return relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func writeReport(options scanOptions, stdout io.Writer, aggregated report.Report) (err error) {
	if options.output != "" {
		return writeReportFile(options, aggregated)
	}
	return renderReport(options, stdout, aggregated)
}

func renderReport(options scanOptions, output io.Writer, aggregated report.Report) error {
	if options.format == "json" {
		return report.WriteJSON(output, aggregated)
	}
	return report.WriteText(output, aggregated)
}

func writeReportFile(options scanOptions, aggregated report.Report) error {
	parent := filepath.Dir(options.output)
	name := filepath.Base(options.output)
	root, err := os.OpenRoot(parent)
	if err != nil {
		return fmt.Errorf("open report directory: %w", err)
	}
	defer root.Close()
	if err := validateReportDestination(root, name); err != nil {
		return err
	}

	temporaryName, temporary, err := createPrivateTemporary(root, name)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = root.Remove(temporaryName)
		}
	}()
	if err := renderReport(options, temporary, aggregated); err != nil {
		temporary.Close()
		return fmt.Errorf("render report: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync report: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close report: %w", err)
	}
	if err := validateReportDestination(root, name); err != nil {
		return err
	}
	if err := root.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("atomically replace report: %w", err)
	}
	removeTemporary = false
	if directory, err := os.Open(parent); err == nil {
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("sync report directory: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close report directory: %w", closeErr)
		}
	}
	return nil
}

func validateReportDestination(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect report destination: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("report destination must not be a symlink: %s", name)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("report destination must be a regular file: %s", name)
	}
	return nil
}

func createPrivateTemporary(root *os.Root, destinationName string) (string, *os.File, error) {
	for range 100 {
		random := make([]byte, 16)
		if _, err := cryptorand.Read(random); err != nil {
			return "", nil, fmt.Errorf("generate report temporary name: %w", err)
		}
		name := "." + destinationName + ".tmp-" + hex.EncodeToString(random)
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return name, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, fmt.Errorf("create report temporary file: %w", err)
		}
	}
	return "", nil, errors.New("create report temporary file: name collisions exhausted")
}

// splitCommand parses only words and quoting. It deliberately does not expand
// variables, redirects, pipelines, globs, or command substitutions: execution
// always goes through exec.Command with the returned argument vector.
func splitCommand(value string) ([]string, error) {
	var words []string
	var word strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if word.Len() > 0 {
			words = append(words, word.String())
			word.Reset()
		}
	}
	for _, character := range value {
		if escaped {
			word.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				word.WriteRune(character)
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if unicode.IsSpace(character) {
			flush()
			continue
		}
		word.WriteRune(character)
	}
	if escaped {
		return nil, errors.New("trailing escape")
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	flush()
	if len(words) == 0 || words[0] == "" {
		return nil, errors.New("command must not be empty")
	}
	return words, nil
}

func writeUsage(output io.Writer) {
	fmt.Fprint(output, `Usage:
  springmaster scan ROOT --worker-command 'java -jar analyzer-worker.jar' [flags]

Flags:
  --worker-command COMMAND  analyzer worker executable and arguments (required)
  --workers N               persistent worker count (default 1)
  --mode MODE               STATIC_ONLY or EXTENDED (default STATIC_ONLY)
  --trust-extended          required consent for EXTENDED; does not sandbox it
  --format FORMAT           text or json (default text)
  --output PATH             write report to PATH
  --fail-on SEVERITY        none, info, warning, or error (default error)
  --include GLOB            include repository path; repeat or comma-separate
  --exclude GLOB            exclude repository path; repeat or comma-separate
  --max-depth N             discovery depth; 0 means unlimited
  --timeout DURATION        per-repository timeout (default 5m)
  --cache-dir PATH          cache directory (default OS user cache/springmaster)
  --no-cache                bypass result cache
  --allow-source-write      allow cache/output inside a discovered repository
  -h, --help                show help
`)
}

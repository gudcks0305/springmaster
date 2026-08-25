// Package graph builds a static, cross-repository dependency and impact graph.
// It reads build descriptors only; it never invokes Maven, Gradle, or a network
// client.
package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	defaultMaxFiles      = 512
	defaultMaxFileBytes  = 1 << 20
	defaultMaxTotalBytes = 16 << 20

	hardMaxFiles      = 4_096
	hardMaxFileBytes  = 8 << 20
	hardMaxTotalBytes = 64 << 20

	effectiveHashVersion = "springmaster-graph-effective-v1"
)

var (
	// ErrInvalidRepository means graph input cannot identify a local directory.
	ErrInvalidRepository = errors.New("invalid graph repository")
	// ErrInvalidOptions means an option is negative or exceeds a fixed bound.
	ErrInvalidOptions = errors.New("invalid graph options")
)

// Repository is the neutral, cycle-free input supplied by a caller. ContentHash
// should describe all source content relevant to that repository.
type Repository struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	ContentHash string `json:"contentHash"`
}

// Options bounds static descriptor discovery. Zero values use conservative
// defaults. Limits are per repository and cannot exceed package hard limits.
type Options struct {
	MaxFiles      int   // Relevant descriptor files read per repository.
	MaxFileBytes  int64 // Bytes read from one descriptor file.
	MaxTotalBytes int64 // Total descriptor bytes read per repository.
}

// BuildSystem identifies descriptor syntax that produced a module.
type BuildSystem string

const (
	BuildSystemMaven  BuildSystem = "maven"
	BuildSystemGradle BuildSystem = "gradle"
)

// Coordinate identifies a publishable Java artifact. Empty fields mean that
// static parsing could not determine that part of the coordinate.
type Coordinate struct {
	GroupID    string `json:"groupId,omitempty"`
	ArtifactID string `json:"artifactId,omitempty"`
	Version    string `json:"version,omitempty"`
}

// String returns the conventional coordinate form without inventing missing
// fields.
func (coordinate Coordinate) String() string {
	if coordinate.GroupID == "" && coordinate.ArtifactID == "" {
		return ""
	}
	if coordinate.Version == "" {
		return coordinate.GroupID + ":" + coordinate.ArtifactID
	}
	return coordinate.GroupID + ":" + coordinate.ArtifactID + ":" + coordinate.Version
}

func (coordinate Coordinate) ga() string {
	if coordinate.GroupID == "" || coordinate.ArtifactID == "" {
		return ""
	}
	return coordinate.GroupID + "\x00" + coordinate.ArtifactID
}

func (coordinate Coordinate) gav() string {
	if coordinate.Version == "" {
		return ""
	}
	return coordinate.ga() + "\x00" + coordinate.Version
}

// Module is an internal build unit. Several modules can belong to one
// Repository; externally visible ordering and impact results remain repo IDs.
type Module struct {
	ID           string      `json:"id"`
	RepositoryID string      `json:"repositoryId"`
	Path         string      `json:"path"`
	RelativePath string      `json:"relativePath"`
	BuildSystem  BuildSystem `json:"buildSystem"`
	Coordinate   Coordinate  `json:"coordinate"`
	ProjectName  string      `json:"projectName,omitempty"`
	ProjectPath  string      `json:"projectPath,omitempty"`
}

// DependencyKind describes the build declaration that created a dependency.
type DependencyKind string

const (
	DependencyMaven       DependencyKind = "maven_dependency"
	DependencyMavenParent DependencyKind = "maven_parent"
	DependencyMavenBOM    DependencyKind = "maven_bom"
	DependencyGradle      DependencyKind = "gradle_dependency"
	DependencyGradleProj  DependencyKind = "gradle_project"
	DependencyGradleAlias DependencyKind = "gradle_catalog_alias"
	DependencyGradleBuild DependencyKind = "gradle_included_build"
)

// DependencyResolution tells callers whether a declaration was linked to a
// local module. External is a fully parsed non-local declaration; unresolved
// means static parsing could not safely identify its target.
type DependencyResolution string

const (
	ResolutionLocal      DependencyResolution = "local"
	ResolutionExternal   DependencyResolution = "external"
	ResolutionUnresolved DependencyResolution = "unresolved"
)

// Dependency points from a dependent source module to a dependency target
// module. This direction is deliberate: Graph.Order is still dependency-first.
type Dependency struct {
	SourceModuleID     string               `json:"sourceModuleId"`
	SourceRepositoryID string               `json:"sourceRepositoryId"`
	TargetModuleID     string               `json:"targetModuleId,omitempty"`
	TargetRepositoryID string               `json:"targetRepositoryId,omitempty"`
	Kind               DependencyKind       `json:"kind"`
	Coordinate         Coordinate           `json:"coordinate,omitempty"`
	ProjectPath        string               `json:"projectPath,omitempty"`
	SourcePath         string               `json:"sourcePath,omitempty"`
	Resolution         DependencyResolution `json:"resolution"`
	Dynamic            bool                 `json:"dynamic,omitempty"`
	Reason             string               `json:"reason,omitempty"`
}

// Diagnostic reports a non-fatal descriptor limitation or malformed input. No
// source content is copied into messages.
type Diagnostic struct {
	RepositoryID string `json:"repositoryId"`
	ModuleID     string `json:"moduleId,omitempty"`
	Path         string `json:"path,omitempty"`
	Code         string `json:"code"`
	Message      string `json:"message"`
}

// CycleGroup is a strongly connected group of internal modules. RepositoryIDs
// is the de-duplicated owner list for reporting.
type CycleGroup struct {
	ModuleIDs     []string `json:"moduleIds"`
	RepositoryIDs []string `json:"repositoryIds"`
}

// Impact is the repository-level effect of one or more changed repositories.
// Direct are one-hop dependents; Transitive excludes changed and direct IDs;
// All is Direct plus Transitive, all deterministically sorted.
type Impact struct {
	Changed    []string `json:"changed"`
	Direct     []string `json:"direct"`
	Transitive []string `json:"transitive"`
	All        []string `json:"all"`
}

// Graph is an immutable-by-convention static result. Dependencies use
// dependent-to-dependency direction. Order contains every input repository once
// in dependency-first order; IDs in an unavoidable cycle are lexical within
// their dependency-first condensation position.
type Graph struct {
	Repositories          []Repository      `json:"repositories"`
	Modules               []Module          `json:"modules"`
	Dependencies          []Dependency      `json:"dependencies"`
	Diagnostics           []Diagnostic      `json:"diagnostics"`
	Order                 []string          `json:"order"`
	Cycles                []CycleGroup      `json:"cycles"`
	EffectiveHashes       map[string]string `json:"effectiveHashes"`
	ModuleEffectiveHashes map[string]string `json:"moduleEffectiveHashes"`
}

// Build parses local descriptors with default limits.
func Build(ctx context.Context, repositories []Repository) (*Graph, error) {
	return BuildWithOptions(ctx, repositories, Options{})
}

// BuildWithOptions parses local Maven and Gradle descriptors. Build evaluation,
// Maven/Gradle execution, and network access are intentionally absent.
func BuildWithOptions(ctx context.Context, repositories []Repository, options Options) (*Graph, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	options, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}

	inputs, sortedRepositories, err := normalizeRepositories(repositories)
	if err != nil {
		return nil, err
	}

	result := &Graph{
		Repositories:          sortedRepositories,
		Modules:               make([]Module, 0),
		Dependencies:          make([]Dependency, 0),
		Diagnostics:           make([]Diagnostic, 0),
		Order:                 make([]string, 0, len(sortedRepositories)),
		Cycles:                make([]CycleGroup, 0),
		EffectiveHashes:       make(map[string]string, len(sortedRepositories)),
		ModuleEffectiveHashes: make(map[string]string),
	}

	specifications := make([]moduleSpecification, 0)
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		files, diagnostics, err := discoverDescriptorFiles(ctx, input, options)
		if err != nil {
			return nil, err
		}
		result.Diagnostics = append(result.Diagnostics, diagnostics...)

		mavenModules, mavenDiagnostics, err := parseMavenRepository(ctx, input, files)
		if err != nil {
			return nil, err
		}
		gradleModules, gradleDiagnostics, err := parseGradleRepository(ctx, input, files)
		if err != nil {
			return nil, err
		}
		specifications = append(specifications, mavenModules...)
		specifications = append(specifications, gradleModules...)
		result.Diagnostics = append(result.Diagnostics, mavenDiagnostics...)
		result.Diagnostics = append(result.Diagnostics, gradleDiagnostics...)
	}

	moduleByID := make(map[string]Module, len(specifications))
	for _, specification := range specifications {
		if _, duplicate := moduleByID[specification.Module.ID]; duplicate {
			result.Diagnostics = append(result.Diagnostics, Diagnostic{
				RepositoryID: specification.Module.RepositoryID,
				ModuleID:     specification.Module.ID,
				Path:         specification.Module.RelativePath,
				Code:         "duplicate_module",
				Message:      "descriptor produced a duplicate internal module ID",
			})
			continue
		}
		moduleByID[specification.Module.ID] = specification.Module
		result.Modules = append(result.Modules, specification.Module)
	}
	sort.Slice(result.Modules, func(left, right int) bool { return result.Modules[left].ID < result.Modules[right].ID })

	indexes := newLocalIndexes(result.Modules)
	for _, specification := range specifications {
		if _, accepted := moduleByID[specification.Module.ID]; !accepted {
			continue
		}
		for _, declaration := range specification.Declarations {
			dependency := resolveDeclaration(declaration, moduleByID, indexes)
			result.Dependencies = append(result.Dependencies, dependency)
			if dependency.Resolution == ResolutionUnresolved {
				result.Diagnostics = append(result.Diagnostics, Diagnostic{
					RepositoryID: dependency.SourceRepositoryID,
					ModuleID:     dependency.SourceModuleID,
					Path:         dependency.SourcePath,
					Code:         "unresolved_dependency",
					Message:      dependency.Reason,
				})
			}
		}
	}
	sortDependencies(result.Dependencies)
	sortDiagnostics(result.Diagnostics)

	result.Cycles = findCycleGroups(result.Modules, result.Dependencies)
	for _, group := range result.Cycles {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{
			RepositoryID: strings.Join(group.RepositoryIDs, ","),
			Code:         "dependency_cycle",
			Message:      "local dependency cycle: " + strings.Join(group.RepositoryIDs, ", "),
		})
	}
	sortDiagnostics(result.Diagnostics)
	result.Order = dependencyFirstRepositoryOrder(result.Repositories, result.Dependencies)
	result.ModuleEffectiveHashes, result.EffectiveHashes = calculateEffectiveHashes(result.Repositories, result.Modules, result.Dependencies)
	return result, nil
}

// EffectiveHash returns a repository content identity extended with all local
// dependency identities. It is empty for an unknown repository ID.
func (graph *Graph) EffectiveHash(repositoryID string) string {
	if graph == nil {
		return ""
	}
	return graph.EffectiveHashes[repositoryID]
}

// DependencyFirstOrder returns a copy of Graph.Order.
func (graph *Graph) DependencyFirstOrder() []string {
	if graph == nil {
		return nil
	}
	return append([]string(nil), graph.Order...)
}

// Impact returns direct and transitive local dependents of changed repository
// IDs. Unknown IDs are ignored; Changed contains known IDs only.
func (graph *Graph) Impact(changedRepositoryIDs []string) Impact {
	if graph == nil {
		return Impact{Changed: []string{}, Direct: []string{}, Transitive: []string{}, All: []string{}}
	}
	known := make(map[string]struct{}, len(graph.Repositories))
	for _, repository := range graph.Repositories {
		known[repository.ID] = struct{}{}
	}
	changed := make(map[string]struct{})
	for _, repositoryID := range changedRepositoryIDs {
		if _, exists := known[repositoryID]; exists {
			changed[repositoryID] = struct{}{}
		}
	}
	reverse := make(map[string]map[string]struct{})
	for _, dependency := range graph.Dependencies {
		if dependency.Resolution != ResolutionLocal || dependency.TargetRepositoryID == "" || dependency.SourceRepositoryID == dependency.TargetRepositoryID {
			continue
		}
		if reverse[dependency.TargetRepositoryID] == nil {
			reverse[dependency.TargetRepositoryID] = make(map[string]struct{})
		}
		reverse[dependency.TargetRepositoryID][dependency.SourceRepositoryID] = struct{}{}
	}

	direct := make(map[string]struct{})
	for repositoryID := range changed {
		for dependent := range reverse[repositoryID] {
			if _, isChanged := changed[dependent]; !isChanged {
				direct[dependent] = struct{}{}
			}
		}
	}
	visited := make(map[string]struct{}, len(changed)+len(direct))
	queue := make([]string, 0, len(changed)+len(direct))
	for repositoryID := range changed {
		visited[repositoryID] = struct{}{}
		queue = append(queue, repositoryID)
	}
	sort.Strings(queue)
	all := make(map[string]struct{})
	for len(queue) > 0 {
		repositoryID := queue[0]
		queue = queue[1:]
		dependents := sortedSet(reverse[repositoryID])
		for _, dependent := range dependents {
			if _, seen := visited[dependent]; seen {
				continue
			}
			visited[dependent] = struct{}{}
			queue = append(queue, dependent)
			if _, isChanged := changed[dependent]; !isChanged {
				all[dependent] = struct{}{}
			}
		}
	}
	transitive := make(map[string]struct{})
	for repositoryID := range all {
		if _, directDependent := direct[repositoryID]; !directDependent {
			transitive[repositoryID] = struct{}{}
		}
	}
	return Impact{
		Changed:    sortedSet(changed),
		Direct:     sortedSet(direct),
		Transitive: sortedSet(transitive),
		All:        sortedSet(all),
	}
}

// Impacted returns all direct and transitive dependent repository IDs.
func (graph *Graph) Impacted(changedRepositoryIDs []string) []string {
	return graph.Impact(changedRepositoryIDs).All
}

type repositoryInput struct {
	Repository
	root string
}

func normalizeOptions(options Options) (Options, error) {
	if options.MaxFiles == 0 {
		options.MaxFiles = defaultMaxFiles
	}
	if options.MaxFileBytes == 0 {
		options.MaxFileBytes = defaultMaxFileBytes
	}
	if options.MaxTotalBytes == 0 {
		options.MaxTotalBytes = defaultMaxTotalBytes
	}
	if options.MaxFiles < 1 || options.MaxFiles > hardMaxFiles ||
		options.MaxFileBytes < 1 || options.MaxFileBytes > hardMaxFileBytes ||
		options.MaxTotalBytes < 1 || options.MaxTotalBytes > hardMaxTotalBytes {
		return Options{}, fmt.Errorf("%w: max files <= %d, max file bytes <= %d, max total bytes <= %d", ErrInvalidOptions, hardMaxFiles, hardMaxFileBytes, hardMaxTotalBytes)
	}
	return options, nil
}

func normalizeRepositories(repositories []Repository) ([]repositoryInput, []Repository, error) {
	inputs := make([]repositoryInput, 0, len(repositories))
	sorted := make([]Repository, 0, len(repositories))
	seen := make(map[string]struct{}, len(repositories))
	for _, repository := range repositories {
		repository.ID = strings.TrimSpace(repository.ID)
		repository.Path = strings.TrimSpace(repository.Path)
		if repository.ID == "" || repository.Path == "" {
			return nil, nil, fmt.Errorf("%w: ID and Path are required", ErrInvalidRepository)
		}
		if _, duplicate := seen[repository.ID]; duplicate {
			return nil, nil, fmt.Errorf("%w: duplicate ID %q", ErrInvalidRepository, repository.ID)
		}
		root, err := filepath.Abs(repository.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: resolve %q: %v", ErrInvalidRepository, repository.Path, err)
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			if err != nil {
				return nil, nil, fmt.Errorf("%w: %q: %v", ErrInvalidRepository, repository.Path, err)
			}
			return nil, nil, fmt.Errorf("%w: %q is not a directory", ErrInvalidRepository, repository.Path)
		}
		seen[repository.ID] = struct{}{}
		inputs = append(inputs, repositoryInput{Repository: repository, root: filepath.Clean(root)})
		sorted = append(sorted, repository)
	}
	sort.Slice(inputs, func(left, right int) bool { return inputs[left].ID < inputs[right].ID })
	sort.Slice(sorted, func(left, right int) bool { return sorted[left].ID < sorted[right].ID })
	return inputs, sorted, nil
}

type moduleSpecification struct {
	Module       Module
	Declarations []dependencyDeclaration
}

type dependencyDeclaration struct {
	SourceModuleID     string
	SourceRepositoryID string
	Kind               DependencyKind
	Coordinate         Coordinate
	ProjectPath        string
	SourcePath         string
	Dynamic            bool
	Reason             string
	ExplicitTargetID   string
}

type localIndexes struct {
	byGA          map[string][]string
	byGAV         map[string][]string
	byProjectPath map[string][]string
	byProjectName map[string][]string
}

func newLocalIndexes(modules []Module) localIndexes {
	indexes := localIndexes{
		byGA:          make(map[string][]string),
		byGAV:         make(map[string][]string),
		byProjectPath: make(map[string][]string),
		byProjectName: make(map[string][]string),
	}
	for _, module := range modules {
		if key := module.Coordinate.ga(); key != "" {
			indexes.byGA[key] = append(indexes.byGA[key], module.ID)
		}
		if key := module.Coordinate.gav(); key != "" {
			indexes.byGAV[key] = append(indexes.byGAV[key], module.ID)
		}
		if module.ProjectPath != "" {
			key := module.RepositoryID + "\x00" + module.ProjectPath
			indexes.byProjectPath[key] = append(indexes.byProjectPath[key], module.ID)
		}
		if module.ProjectName != "" {
			indexes.byProjectName[module.ProjectName] = append(indexes.byProjectName[module.ProjectName], module.ID)
		}
	}
	for _, collection := range []map[string][]string{indexes.byGA, indexes.byGAV, indexes.byProjectPath, indexes.byProjectName} {
		for key := range collection {
			sort.Strings(collection[key])
		}
	}
	return indexes
}

func resolveDeclaration(declaration dependencyDeclaration, modules map[string]Module, indexes localIndexes) Dependency {
	dependency := Dependency{
		SourceModuleID:     declaration.SourceModuleID,
		SourceRepositoryID: declaration.SourceRepositoryID,
		Kind:               declaration.Kind,
		Coordinate:         declaration.Coordinate,
		ProjectPath:        declaration.ProjectPath,
		SourcePath:         declaration.SourcePath,
		Dynamic:            declaration.Dynamic,
		Reason:             declaration.Reason,
		Resolution:         ResolutionExternal,
	}
	if declaration.ExplicitTargetID != "" {
		if target, exists := modules[declaration.ExplicitTargetID]; exists {
			dependency.TargetModuleID = target.ID
			dependency.TargetRepositoryID = target.RepositoryID
			dependency.Resolution = ResolutionLocal
			dependency.Reason = ""
			return dependency
		}
		dependency.Resolution = ResolutionUnresolved
		if dependency.Reason == "" {
			dependency.Reason = "declared local module was not discovered"
		}
		return dependency
	}
	if declaration.ProjectPath != "" {
		candidateIDs := indexes.byProjectPath[declaration.SourceRepositoryID+"\x00"+declaration.ProjectPath]
		if len(candidateIDs) == 0 {
			candidateIDs = indexes.byProjectName[projectNameFromPath(declaration.ProjectPath)]
		}
		return resolveCandidateIDs(dependency, candidateIDs, modules, "project name is ambiguous or unavailable")
	}
	if declaration.Coordinate.GroupID == "" || declaration.Coordinate.ArtifactID == "" {
		dependency.Resolution = ResolutionUnresolved
		if dependency.Reason == "" {
			dependency.Reason = "dependency coordinate is incomplete"
		}
		return dependency
	}
	if declaration.Coordinate.Version != "" && !declaration.Dynamic {
		if candidateIDs := indexes.byGAV[declaration.Coordinate.gav()]; len(candidateIDs) > 0 {
			return resolveCandidateIDs(dependency, candidateIDs, modules, "published coordinate is ambiguous")
		}
		// A concrete local version mismatch is a parsed external dependency, not
		// an unresolved declaration.
		if candidateIDs := indexes.byGA[declaration.Coordinate.ga()]; len(candidateIDs) > 0 {
			if len(candidateIDs) == 1 && modules[candidateIDs[0]].Coordinate.Version == "" {
				return resolveCandidateIDs(dependency, candidateIDs, modules, "published coordinate is ambiguous")
			}
			return dependency
		}
	}
	return resolveCandidateIDs(dependency, indexes.byGA[declaration.Coordinate.ga()], modules, "published coordinate is ambiguous or unavailable")
}

func resolveCandidateIDs(dependency Dependency, candidateIDs []string, modules map[string]Module, unavailableReason string) Dependency {
	if preferred := dependencyBuildSystem(dependency.Kind); preferred != "" && len(candidateIDs) > 1 {
		filtered := make([]string, 0, len(candidateIDs))
		for _, candidateID := range candidateIDs {
			if modules[candidateID].BuildSystem == preferred {
				filtered = append(filtered, candidateID)
			}
		}
		if len(filtered) > 0 {
			candidateIDs = filtered
		}
	}
	if len(candidateIDs) > 1 {
		first := modules[candidateIDs[0]]
		sameLogicalTarget := true
		for _, candidateID := range candidateIDs[1:] {
			candidate := modules[candidateID]
			if candidate.RepositoryID != first.RepositoryID || filepath.Clean(candidate.Path) != filepath.Clean(first.Path) {
				sameLogicalTarget = false
				break
			}
		}
		if sameLogicalTarget {
			candidateIDs = candidateIDs[:1]
		}
	}
	if len(candidateIDs) == 1 {
		target := modules[candidateIDs[0]]
		dependency.TargetModuleID = target.ID
		dependency.TargetRepositoryID = target.RepositoryID
		dependency.Resolution = ResolutionLocal
		dependency.Reason = ""
		return dependency
	}
	if len(candidateIDs) > 1 {
		dependency.Resolution = ResolutionUnresolved
		dependency.Reason = unavailableReason
		return dependency
	}
	if dependency.Dynamic {
		dependency.Resolution = ResolutionUnresolved
		if dependency.Reason == "" {
			dependency.Reason = "dynamic dependency has no unique local target"
		}
	}
	return dependency
}

func dependencyBuildSystem(kind DependencyKind) BuildSystem {
	switch kind {
	case DependencyMaven, DependencyMavenParent, DependencyMavenBOM:
		return BuildSystemMaven
	case DependencyGradle, DependencyGradleProj, DependencyGradleAlias, DependencyGradleBuild:
		return BuildSystemGradle
	default:
		return ""
	}
}

func sortDependencies(dependencies []Dependency) {
	sort.Slice(dependencies, func(left, right int) bool {
		leftKey := strings.Join([]string{dependencies[left].SourceModuleID, string(dependencies[left].Kind), dependencies[left].Coordinate.String(), dependencies[left].ProjectPath, dependencies[left].TargetModuleID, dependencies[left].SourcePath}, "\x00")
		rightKey := strings.Join([]string{dependencies[right].SourceModuleID, string(dependencies[right].Kind), dependencies[right].Coordinate.String(), dependencies[right].ProjectPath, dependencies[right].TargetModuleID, dependencies[right].SourcePath}, "\x00")
		return leftKey < rightKey
	})
}

func sortDiagnostics(diagnostics []Diagnostic) {
	sort.Slice(diagnostics, func(left, right int) bool {
		leftKey := strings.Join([]string{diagnostics[left].RepositoryID, diagnostics[left].ModuleID, diagnostics[left].Path, diagnostics[left].Code, diagnostics[left].Message}, "\x00")
		rightKey := strings.Join([]string{diagnostics[right].RepositoryID, diagnostics[right].ModuleID, diagnostics[right].Path, diagnostics[right].Code, diagnostics[right].Message}, "\x00")
		return leftKey < rightKey
	})
}

func projectNameFromPath(projectPath string) string {
	projectPath = strings.Trim(projectPath, ":")
	if projectPath == "" {
		return ""
	}
	parts := strings.Split(projectPath, ":")
	return parts[len(parts)-1]
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func hashParts(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

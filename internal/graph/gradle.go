package graph

import (
	"context"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	gradleRootNamePattern = regexp.MustCompile(`(?m)\brootProject\s*\.\s*name\s*=\s*["']([^"']+)["']`)
	gradleIncludePattern  = regexp.MustCompile(`(?ms)\binclude\s*(?:\(([^)]*)\)|((?:\s*["'][^"']+["']\s*,?)+))`)
	gradleQuotedPattern   = regexp.MustCompile(`["']([^"']+)["']`)
	gradleProjectDirRE    = regexp.MustCompile(`(?ms)\bproject\s*\(\s*["']([^"']+)["']\s*\)\s*\.\s*projectDir\s*=\s*file\s*\(\s*["']([^"']+)["']\s*\)`)
	gradleProjectRefRE    = regexp.MustCompile(`(?ms)\bproject\s*\(\s*(?:path\s*=\s*)?["']([^"']+)["']`)
	gradleCoordinateRE    = regexp.MustCompile(`["']\s*([A-Za-z0-9_.-]+\s*:\s*[A-Za-z0-9_.-]+(?:\s*:\s*[^"']+)?)\s*["']`)
	gradleAssignmentRE    = regexp.MustCompile(`(?m)^\s*(?:project\s*\.\s*)?%s\s*=\s*["']([^"']+)["']`)
	gradleSetRE           = regexp.MustCompile(`(?m)^\s*%s\s*\.set\s*\(\s*["']([^"']+)["']\s*\)`)
	gradleArchiveNameRE   = regexp.MustCompile(`(?m)^\s*(?:archivesBaseName|archivesName)\s*=\s*["']([^"']+)["']|(?m)\barchivesName\s*\.set\s*\(\s*["']([^"']+)["']\s*\)`)
	tomlModuleRE          = regexp.MustCompile(`\bmodule\s*=\s*"([^"]+)"`)
	tomlGroupRE           = regexp.MustCompile(`\bgroup\s*=\s*"([^"]+)"`)
	tomlNameRE            = regexp.MustCompile(`\bname\s*=\s*"([^"]+)"`)
	tomlVersionRE         = regexp.MustCompile(`\bversion\s*=\s*"([^"]+)"`)
	tomlVersionRefRE      = regexp.MustCompile(`\bversion\.ref\s*=\s*"([^"]+)"`)
	tomlStrictlyRE        = regexp.MustCompile(`\bstrictly\s*=\s*"([^"]+)"`)
	gradleIncludeBuildRE  = regexp.MustCompile(`(?ms)\bincludeBuild\s*\(\s*["']([^"']+)["']`)
)

type gradleBuildRoot struct {
	directory   string
	settings    descriptorFile
	hasSettings bool
}

type gradleProject struct {
	path      string
	directory string
}

type gradleCatalogLibrary struct {
	coordinate Coordinate
	dynamic    bool
	reason     string
}

func parseGradleRepository(ctx context.Context, input repositoryInput, files descriptorFiles) ([]moduleSpecification, []Diagnostic, error) {
	roots := gradleRoots(files)
	if len(roots) == 0 {
		return nil, nil, nil
	}
	diagnostics := make([]Diagnostic, 0)
	modules := make([]moduleSpecification, 0)
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return nil, diagnostics, err
		}
		parsed, rootDiagnostics := parseGradleRoot(ctx, input, files, root)
		modules = append(modules, parsed...)
		diagnostics = append(diagnostics, rootDiagnostics...)
	}
	return modules, diagnostics, nil
}

func gradleRoots(files descriptorFiles) []gradleBuildRoot {
	byDirectory := make(map[string]gradleBuildRoot)
	for _, file := range files.named("settings.gradle", "settings.gradle.kts") {
		directory := normalizeRelative(filepath.Dir(file.relative))
		existing, found := byDirectory[directory]
		if !found || filepath.Base(file.relative) == "settings.gradle.kts" {
			byDirectory[directory] = gradleBuildRoot{directory: directory, settings: file, hasSettings: true}
		} else {
			_ = existing
		}
	}
	for _, file := range files.named("build.gradle", "build.gradle.kts") {
		directory := normalizeRelative(filepath.Dir(file.relative))
		if containedBySettingsRoot(directory, byDirectory) {
			continue
		}
		if _, found := byDirectory[directory]; !found {
			byDirectory[directory] = gradleBuildRoot{directory: directory}
		}
	}
	roots := make([]gradleBuildRoot, 0, len(byDirectory))
	for _, root := range byDirectory {
		roots = append(roots, root)
	}
	sort.Slice(roots, func(left, right int) bool { return roots[left].directory < roots[right].directory })
	return roots
}

func containedBySettingsRoot(directory string, roots map[string]gradleBuildRoot) bool {
	for rootDirectory, root := range roots {
		if !root.hasSettings {
			continue
		}
		if rootDirectory == "." || directory == rootDirectory || strings.HasPrefix(directory, rootDirectory+"/") {
			return true
		}
	}
	return false
}

func parseGradleRoot(ctx context.Context, input repositoryInput, files descriptorFiles, root gradleBuildRoot) ([]moduleSpecification, []Diagnostic) {
	diagnostics := make([]Diagnostic, 0)
	settingsText := ""
	if root.hasSettings {
		settingsText = stripGradleComments(root.settings.contents)
	}
	rootName := path.Base(root.directory)
	if root.directory == "." {
		rootName = path.Base(input.root)
	}
	if matches := gradleRootNamePattern.FindStringSubmatch(settingsText); len(matches) > 1 {
		rootName = strings.TrimSpace(matches[1])
	}
	projects := []gradleProject{{path: ":", directory: root.directory}}
	projectDirectories := gradleProjectDirectories(settingsText)
	for _, projectPath := range gradleIncludes(settingsText) {
		if projectPath == ":" {
			continue
		}
		directory := defaultGradleProjectDirectory(root.directory, projectPath)
		if override, found := projectDirectories[projectPath]; found {
			directory = joinGradleDirectory(root.directory, override)
		}
		if directory == "" {
			diagnostics = append(diagnostics, Diagnostic{
				RepositoryID: input.ID,
				Path:         root.settings.relative,
				Code:         "gradle_project_outside_repository",
				Message:      "Gradle projectDir escapes repository boundary",
			})
			continue
		}
		projects = append(projects, gradleProject{path: projectPath, directory: directory})
	}
	sort.Slice(projects, func(left, right int) bool { return projects[left].path < projects[right].path })

	properties := gradleProperties(files, root.directory)
	rootBuild := gradleBuildFile(files, root.directory)
	rootDefaults := gradleDefaults(rootBuild.contents, properties)
	catalogs := gradleCatalogs(files, root.directory)
	moduleIDs := make(map[string]string, len(projects))
	modules := make([]moduleSpecification, 0, len(projects))
	for _, project := range projects {
		buildFile := gradleBuildFile(files, project.directory)
		group, groupDynamic, groupFound := gradleAssignedValue(buildFile.contents, "group", properties)
		if !groupFound && project.path != ":" {
			group, groupDynamic = rootDefaults.group, rootDefaults.groupDynamic
		}
		version, versionDynamic, versionFound := gradleAssignedValue(buildFile.contents, "version", properties)
		if !versionFound && project.path != ":" {
			version, versionDynamic = rootDefaults.version, rootDefaults.versionDynamic
		}
		artifact, artifactDynamic := gradleArtifactName(buildFile.contents, properties)
		projectName := rootName
		if project.path != ":" {
			projectName = projectNameFromPath(project.path)
		}
		if artifact == "" {
			artifact = projectName
		}
		moduleID := input.ID + "::gradle:" + root.directory + project.path
		moduleIDs[project.path] = moduleID
		modules = append(modules, moduleSpecification{Module: Module{
			ID:           moduleID,
			RepositoryID: input.ID,
			Path:         filepath.Join(input.root, filepath.FromSlash(project.directory)),
			RelativePath: project.directory,
			BuildSystem:  BuildSystemGradle,
			Coordinate:   Coordinate{GroupID: group, ArtifactID: artifact, Version: version},
			ProjectName:  projectName,
			ProjectPath:  project.path,
		}, Declarations: gradleDeclarations(input, moduleID, buildFile, catalogs)})
		_ = groupDynamic
		_ = versionDynamic
		_ = artifactDynamic
	}

	for index := range modules {
		for declarationIndex := range modules[index].Declarations {
			declaration := &modules[index].Declarations[declarationIndex]
			if declaration.Kind == DependencyGradleProj {
				if target, found := moduleIDs[declaration.ProjectPath]; found {
					declaration.ExplicitTargetID = target
				}
			}
		}
	}
	if root.hasSettings {
		for _, included := range gradleIncludeBuildRE.FindAllStringSubmatch(settingsText, -1) {
			if len(included) < 2 || strings.TrimSpace(included[1]) == "" || len(modules) == 0 {
				continue
			}
			modules[0].Declarations = append(modules[0].Declarations, dependencyDeclaration{
				SourceModuleID:     modules[0].Module.ID,
				SourceRepositoryID: input.ID,
				Kind:               DependencyGradleBuild,
				SourcePath:         root.settings.relative,
				Dynamic:            true,
				Reason:             "Gradle included build requires static composite-build mapping",
			})
		}
	}
	_ = ctx
	return modules, diagnostics
}

type gradleDefaultValues struct {
	group          string
	groupDynamic   bool
	version        string
	versionDynamic bool
}

func gradleDefaults(contents string, properties map[string]string) gradleDefaultValues {
	contents = stripGradleComments(contents)
	group, groupDynamic, _ := gradleAssignedValue(contents, "group", properties)
	version, versionDynamic, _ := gradleAssignedValue(contents, "version", properties)
	for _, name := range []string{"allprojects", "subprojects"} {
		for _, block := range namedGradleBlocks(contents, name) {
			if candidate, dynamic, found := gradleAssignedValue(block, "group", properties); found {
				group, groupDynamic = candidate, dynamic
			}
			if candidate, dynamic, found := gradleAssignedValue(block, "version", properties); found {
				version, versionDynamic = candidate, dynamic
			}
		}
	}
	return gradleDefaultValues{group: group, groupDynamic: groupDynamic, version: version, versionDynamic: versionDynamic}
}

func gradleBuildFile(files descriptorFiles, directory string) descriptorFile {
	for _, name := range []string{"build.gradle.kts", "build.gradle"} {
		candidate := name
		if directory != "." {
			candidate = directory + "/" + name
		}
		if file, found := files.at(candidate); found {
			return file
		}
	}
	return descriptorFile{}
}

func gradleIncludes(contents string) []string {
	set := make(map[string]struct{})
	for _, match := range gradleIncludePattern.FindAllStringSubmatch(contents, -1) {
		for _, part := range match[1:] {
			for _, quoted := range gradleQuotedPattern.FindAllStringSubmatch(part, -1) {
				value := normalizeGradleProjectPath(quoted[1])
				if value != "" {
					set[value] = struct{}{}
				}
			}
		}
	}
	return sortedSet(set)
}

func gradleProjectDirectories(contents string) map[string]string {
	result := make(map[string]string)
	for _, match := range gradleProjectDirRE.FindAllStringSubmatch(contents, -1) {
		if len(match) < 3 {
			continue
		}
		projectPath := normalizeGradleProjectPath(match[1])
		if projectPath != "" {
			result[projectPath] = strings.TrimSpace(match[2])
		}
	}
	return result
}

func normalizeGradleProjectPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, ":") {
		value = ":" + value
	}
	return value
}

func defaultGradleProjectDirectory(root, projectPath string) string {
	parts := strings.Split(strings.Trim(projectPath, ":"), ":")
	return joinGradleDirectory(root, strings.Join(parts, "/"))
}

func joinGradleDirectory(root, value string) string {
	if path.IsAbs(value) {
		return ""
	}
	joined := path.Clean(path.Join(root, value))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return ""
	}
	return normalizeRelative(joined)
}

func gradleProperties(files descriptorFiles, root string) map[string]string {
	result := make(map[string]string)
	file, found := files.at(func() string {
		if root == "." {
			return "gradle.properties"
		}
		return root + "/gradle.properties"
	}())
	if !found {
		return result
	}
	for _, line := range strings.Split(file.contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if index := strings.IndexAny(line, "=:"); index > 0 {
			result[strings.TrimSpace(line[:index])] = strings.TrimSpace(line[index+1:])
		}
	}
	return result
}

func gradleAssignedValue(contents, name string, properties map[string]string) (string, bool, bool) {
	if contents == "" {
		return "", false, false
	}
	assignment := regexp.MustCompile(sprintfPattern(gradleAssignmentRE.String(), regexp.QuoteMeta(name)))
	if match := assignment.FindStringSubmatch(contents); len(match) > 1 {
		value, dynamic := expandGradleValue(match[1], properties)
		return value, dynamic, true
	}
	setter := regexp.MustCompile(sprintfPattern(gradleSetRE.String(), regexp.QuoteMeta(name)))
	if match := setter.FindStringSubmatch(contents); len(match) > 1 {
		value, dynamic := expandGradleValue(match[1], properties)
		return value, dynamic, true
	}
	return "", false, false
}

func sprintfPattern(pattern, name string) string {
	return strings.Replace(pattern, "%s", name, 1)
}

func gradleArtifactName(contents string, properties map[string]string) (string, bool) {
	if contents == "" {
		return "", false
	}
	match := gradleArchiveNameRE.FindStringSubmatch(contents)
	if len(match) == 0 {
		return "", false
	}
	value := ""
	for _, candidate := range match[1:] {
		if candidate != "" {
			value = candidate
			break
		}
	}
	return expandGradleValue(value, properties)
}

func expandGradleValue(value string, properties map[string]string) (string, bool) {
	value = strings.TrimSpace(value)
	for key, replacement := range properties {
		value = strings.ReplaceAll(value, "${"+key+"}", replacement)
	}
	value = strings.TrimSpace(value)
	return value, strings.Contains(value, "$")
}

func gradleDeclarations(input repositoryInput, moduleID string, buildFile descriptorFile, catalogs map[string]map[string]gradleCatalogLibrary) []dependencyDeclaration {
	if buildFile.relative == "" {
		return nil
	}
	blocks := namedGradleBlocks(stripGradleComments(buildFile.contents), "dependencies")
	declarations := make([]dependencyDeclaration, 0)
	for _, block := range blocks {
		for _, match := range gradleProjectRefRE.FindAllStringSubmatch(block, -1) {
			if len(match) < 2 {
				continue
			}
			projectPath := normalizeGradleProjectPath(match[1])
			if projectPath == "" {
				continue
			}
			declarations = append(declarations, dependencyDeclaration{
				SourceModuleID: moduleID, SourceRepositoryID: input.ID, Kind: DependencyGradleProj,
				ProjectPath: projectPath, SourcePath: buildFile.relative,
			})
		}
		for _, match := range gradleCoordinateRE.FindAllStringSubmatch(block, -1) {
			if len(match) < 2 {
				continue
			}
			coordinate, dynamic, valid := parseGradleCoordinate(match[1])
			if !valid {
				continue
			}
			declarations = append(declarations, dependencyDeclaration{
				SourceModuleID: moduleID, SourceRepositoryID: input.ID, Kind: DependencyGradle,
				Coordinate: coordinate, SourcePath: buildFile.relative, Dynamic: dynamic,
				Reason: gradleCoordinateReason(coordinate, dynamic),
			})
		}
		for catalogName, libraries := range catalogs {
			aliasPattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(catalogName) + `\.([A-Za-z_][A-Za-z0-9_.-]*)`)
			for _, match := range aliasPattern.FindAllStringSubmatch(block, -1) {
				if len(match) < 2 || strings.HasPrefix(match[1], "versions.") || strings.HasPrefix(match[1], "bundles.") {
					continue
				}
				library, found := libraries[normalizeCatalogAlias(match[1])]
				declaration := dependencyDeclaration{
					SourceModuleID: moduleID, SourceRepositoryID: input.ID, Kind: DependencyGradleAlias,
					SourcePath: buildFile.relative, Dynamic: true, Reason: "Gradle version catalog alias cannot be resolved statically",
				}
				if found {
					declaration.Coordinate = library.coordinate
					declaration.Dynamic = library.dynamic
					declaration.Reason = library.reason
				}
				declarations = append(declarations, declaration)
			}
		}
	}
	return declarations
}

func parseGradleCoordinate(value string) (Coordinate, bool, bool) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return Coordinate{}, true, false
	}
	coordinate := Coordinate{GroupID: strings.TrimSpace(parts[0]), ArtifactID: strings.TrimSpace(parts[1])}
	if len(parts) > 2 {
		coordinate.Version = strings.TrimSpace(parts[2])
	}
	return coordinate, gradleDynamicCoordinate(coordinate), true
}

func gradleDynamicCoordinate(coordinate Coordinate) bool {
	version := strings.ToLower(coordinate.Version)
	return coordinate.Version == "" || strings.Contains(coordinate.GroupID, "$") || strings.Contains(coordinate.ArtifactID, "$") || strings.Contains(coordinate.Version, "$") || strings.Contains(coordinate.Version, "+") || strings.Contains(version, "latest.") || strings.ContainsAny(coordinate.Version, "[]()")
}

func gradleCoordinateReason(coordinate Coordinate, dynamic bool) string {
	if coordinate.GroupID == "" || coordinate.ArtifactID == "" {
		return "Gradle dependency coordinate is incomplete"
	}
	if dynamic {
		return "Gradle dependency uses a dynamic or unresolved version"
	}
	return ""
}

func gradleCatalogs(files descriptorFiles, root string) map[string]map[string]gradleCatalogLibrary {
	result := make(map[string]map[string]gradleCatalogLibrary)
	for _, file := range files.versionCatalogs() {
		if root != "." && file.relative != root+"/libs.versions.toml" && !strings.HasPrefix(file.relative, root+"/gradle/") {
			continue
		}
		catalogName := "libs"
		base := filepath.Base(file.relative)
		if strings.HasSuffix(base, ".versions.toml") {
			catalogName = strings.TrimSuffix(base, ".versions.toml")
		}
		if catalogName == "" {
			catalogName = "libs"
		}
		result[catalogName] = parseVersionCatalog(file.contents)
	}
	return result
}

func parseVersionCatalog(contents string) map[string]gradleCatalogLibrary {
	versions := make(map[string]string)
	libraries := make(map[string]gradleCatalogLibrary)
	section := ""
	for _, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(stripTomlComment(rawLine))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		index := strings.Index(line, "=")
		if index <= 0 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(line[:index]), "\"")
		value := strings.TrimSpace(line[index+1:])
		switch section {
		case "versions":
			versions[key] = trimTomlString(value)
		case "libraries":
			libraries[normalizeCatalogAlias(key)] = parseCatalogLibrary(value, versions)
		}
	}
	// Resolve version references after all [versions] lines have been seen.
	for alias, library := range libraries {
		if strings.HasPrefix(library.coordinate.Version, "@ref:") {
			name := strings.TrimPrefix(library.coordinate.Version, "@ref:")
			version, found := versions[name]
			if !found || version == "" {
				library.dynamic = true
				library.reason = "Gradle version catalog version.ref is missing"
				library.coordinate.Version = ""
			} else {
				library.coordinate.Version = version
				library.dynamic = gradleDynamicCoordinate(library.coordinate)
				library.reason = gradleCoordinateReason(library.coordinate, library.dynamic)
			}
			libraries[alias] = library
		}
	}
	return libraries
}

func parseCatalogLibrary(value string, versions map[string]string) gradleCatalogLibrary {
	coordinate := Coordinate{}
	if strings.HasPrefix(value, "\"") {
		coordinate, _, _ = parseGradleCoordinate(trimTomlString(value))
	} else if match := tomlModuleRE.FindStringSubmatch(value); len(match) > 1 {
		coordinate, _, _ = parseGradleCoordinate(match[1])
	} else {
		if match := tomlGroupRE.FindStringSubmatch(value); len(match) > 1 {
			coordinate.GroupID = match[1]
		}
		if match := tomlNameRE.FindStringSubmatch(value); len(match) > 1 {
			coordinate.ArtifactID = match[1]
		}
	}
	if match := tomlVersionRE.FindStringSubmatch(value); len(match) > 1 {
		coordinate.Version = match[1]
	}
	if match := tomlStrictlyRE.FindStringSubmatch(value); len(match) > 1 && coordinate.Version == "" {
		coordinate.Version = match[1]
	}
	if match := tomlVersionRefRE.FindStringSubmatch(value); len(match) > 1 {
		coordinate.Version = "@ref:" + match[1]
	}
	library := gradleCatalogLibrary{coordinate: coordinate}
	if strings.HasPrefix(coordinate.Version, "@ref:") {
		return library
	}
	library.dynamic = gradleDynamicCoordinate(coordinate)
	library.reason = gradleCoordinateReason(coordinate, library.dynamic)
	_ = versions
	return library
}

func normalizeCatalogAlias(value string) string {
	return strings.ToLower(strings.NewReplacer("-", ".", "_", ".").Replace(strings.TrimSpace(value)))
}

func trimTomlString(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' {
		if end := strings.LastIndex(value[1:], "\""); end >= 0 {
			return value[1 : end+1]
		}
	}
	return strings.Trim(value, "\"")
}

func stripTomlComment(value string) string {
	inQuote := false
	for index := 0; index < len(value); index++ {
		if value[index] == '"' && (index == 0 || value[index-1] != '\\') {
			inQuote = !inQuote
		}
		if value[index] == '#' && !inQuote {
			return value[:index]
		}
	}
	return value
}

func stripGradleComments(value string) string {
	var output strings.Builder
	output.Grow(len(value))
	inSingle, inDouble, lineComment, blockComment := false, false, false, false
	for index := 0; index < len(value); index++ {
		current := value[index]
		next := byte(0)
		if index+1 < len(value) {
			next = value[index+1]
		}
		if lineComment {
			if current == '\n' {
				lineComment = false
				output.WriteByte(current)
			}
			continue
		}
		if blockComment {
			if current == '*' && next == '/' {
				blockComment = false
				index++
			}
			continue
		}
		if !inSingle && !inDouble && current == '/' && next == '/' {
			lineComment = true
			index++
			continue
		}
		if !inSingle && !inDouble && current == '/' && next == '*' {
			blockComment = true
			index++
			continue
		}
		if current == '\'' && !inDouble && (index == 0 || value[index-1] != '\\') {
			inSingle = !inSingle
		}
		if current == '"' && !inSingle && (index == 0 || value[index-1] != '\\') {
			inDouble = !inDouble
		}
		output.WriteByte(current)
	}
	return output.String()
}

func namedGradleBlocks(value, name string) []string {
	blocks := make([]string, 0)
	for index := 0; index < len(value); {
		position := strings.Index(value[index:], name)
		if position < 0 {
			break
		}
		position += index
		beforeWord := position == 0 || !isGradleIdentifier(value[position-1])
		after := position + len(name)
		afterWord := after >= len(value) || !isGradleIdentifier(value[after])
		if !beforeWord || !afterWord {
			index = after
			continue
		}
		cursor := after
		for cursor < len(value) && (value[cursor] == ' ' || value[cursor] == '\t' || value[cursor] == '\r' || value[cursor] == '\n') {
			cursor++
		}
		if cursor >= len(value) || value[cursor] != '{' {
			index = after
			continue
		}
		if close, found := matchingGradleBrace(value, cursor); found {
			blocks = append(blocks, value[cursor+1:close])
			index = close + 1
		} else {
			break
		}
	}
	return blocks
}

func matchingGradleBrace(value string, open int) (int, bool) {
	depth := 0
	inSingle, inDouble := false, false
	for index := open; index < len(value); index++ {
		current := value[index]
		if current == '\'' && !inDouble && (index == 0 || value[index-1] != '\\') {
			inSingle = !inSingle
			continue
		}
		if current == '"' && !inSingle && (index == 0 || value[index-1] != '\\') {
			inDouble = !inDouble
			continue
		}
		if inSingle || inDouble {
			continue
		}
		switch current {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return index, true
			}
		}
	}
	return 0, false
}

func isGradleIdentifier(value byte) bool {
	return value == '_' || value == '$' || (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9')
}

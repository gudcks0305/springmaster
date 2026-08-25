package graph

import (
	"context"
	"encoding/xml"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var mavenPropertyPattern = regexp.MustCompile(`\$\{([^{}]+)\}`)

type mavenProject struct {
	XMLName              xml.Name             `xml:"project"`
	GroupID              string               `xml:"groupId"`
	ArtifactID           string               `xml:"artifactId"`
	Version              string               `xml:"version"`
	Parent               mavenParent          `xml:"parent"`
	Properties           mavenProperties      `xml:"properties"`
	Dependencies         []mavenDependency    `xml:"dependencies>dependency"`
	DependencyManagement mavenDependencyGroup `xml:"dependencyManagement"`
	Modules              []string             `xml:"modules>module"`
}

type mavenParent struct {
	GroupID      string  `xml:"groupId"`
	ArtifactID   string  `xml:"artifactId"`
	Version      string  `xml:"version"`
	RelativePath *string `xml:"relativePath"`
}

func (parent mavenParent) declared() bool {
	return parent.GroupID != "" || parent.ArtifactID != "" || parent.Version != "" || parent.RelativePath != nil
}

type mavenDependencyGroup struct {
	Dependencies []mavenDependency `xml:"dependencies>dependency"`
}

type mavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Type       string `xml:"type"`
	Scope      string `xml:"scope"`
}

type mavenProperties map[string]string

func (properties *mavenProperties) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	values := make(mavenProperties)
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			var text string
			if err := decoder.DecodeElement(&text, &value); err != nil {
				return err
			}
			values[value.Name.Local] = strings.TrimSpace(text)
		case xml.EndElement:
			if value.Name == start.Name {
				*properties = values
				return nil
			}
		}
	}
}

type rawMavenPom struct {
	file      descriptorFile
	directory string
	project   mavenProject
	parent    *rawMavenPom
	moduleID  string
	resolving bool
	resolved  bool
	effective mavenEffective
}

type mavenEffective struct {
	coordinate   Coordinate
	properties   map[string]string
	managed      map[string]resolvedMavenDependency
	dependencies []resolvedMavenDependency
	boms         []resolvedMavenDependency
}

type resolvedMavenDependency struct {
	coordinate Coordinate
	dynamic    bool
	reason     string
}

type mavenResolver struct {
	input       repositoryInput
	poms        map[string]*rawMavenPom
	diagnostics *[]Diagnostic
}

func parseMavenRepository(ctx context.Context, input repositoryInput, files descriptorFiles) ([]moduleSpecification, []Diagnostic, error) {
	pomFiles := files.named("pom.xml")
	if len(pomFiles) == 0 {
		return nil, nil, nil
	}
	diagnostics := make([]Diagnostic, 0)
	poms := make(map[string]*rawMavenPom, len(pomFiles))
	for _, file := range pomFiles {
		if err := ctx.Err(); err != nil {
			return nil, diagnostics, err
		}
		var project mavenProject
		if err := xml.Unmarshal([]byte(file.contents), &project); err != nil || project.XMLName.Local != "project" {
			diagnostics = append(diagnostics, Diagnostic{
				RepositoryID: input.ID,
				Path:         file.relative,
				Code:         "invalid_maven_pom",
				Message:      "cannot parse pom.xml as a Maven project descriptor",
			})
			continue
		}
		directory := normalizeRelative(filepath.Dir(file.relative))
		moduleID := input.ID + "::maven:" + directory
		poms[file.relative] = &rawMavenPom{file: file, directory: directory, project: project, moduleID: moduleID}
	}
	if len(poms) == 0 {
		return nil, diagnostics, nil
	}

	linkMavenParents(input, poms, &diagnostics)
	resolver := mavenResolver{input: input, poms: poms, diagnostics: &diagnostics}
	keys := sortedMavenPOMKeys(poms)
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, diagnostics, err
		}
		resolver.resolve(poms[key])
	}
	validateMavenModules(input, poms, &diagnostics)

	modules := make([]moduleSpecification, 0, len(poms))
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, diagnostics, err
		}
		pom := poms[key]
		effective := pom.effective
		projectName := effective.coordinate.ArtifactID
		if projectName == "" {
			projectName = path.Base(pom.directory)
			if projectName == "." {
				projectName = ""
			}
		}
		specification := moduleSpecification{Module: Module{
			ID:           pom.moduleID,
			RepositoryID: input.ID,
			Path:         filepath.Join(input.root, filepath.FromSlash(pom.directory)),
			RelativePath: pom.directory,
			BuildSystem:  BuildSystemMaven,
			Coordinate:   effective.coordinate,
			ProjectName:  projectName,
		}}
		if pom.project.Parent.declared() {
			parent := resolveMavenParent(pom.project.Parent, effective.properties, effective.coordinate)
			declaration := dependencyDeclaration{
				SourceModuleID:     pom.moduleID,
				SourceRepositoryID: input.ID,
				Kind:               DependencyMavenParent,
				Coordinate:         parent.coordinate,
				SourcePath:         pom.file.relative,
				Dynamic:            parent.dynamic,
				Reason:             parent.reason,
			}
			if pom.parent != nil {
				declaration.ExplicitTargetID = pom.parent.moduleID
			}
			specification.Declarations = append(specification.Declarations, declaration)
		}
		for _, dependency := range effective.dependencies {
			specification.Declarations = append(specification.Declarations, dependencyDeclaration{
				SourceModuleID:     pom.moduleID,
				SourceRepositoryID: input.ID,
				Kind:               DependencyMaven,
				Coordinate:         dependency.coordinate,
				SourcePath:         pom.file.relative,
				Dynamic:            dependency.dynamic,
				Reason:             dependency.reason,
			})
		}
		for _, dependency := range effective.boms {
			specification.Declarations = append(specification.Declarations, dependencyDeclaration{
				SourceModuleID:     pom.moduleID,
				SourceRepositoryID: input.ID,
				Kind:               DependencyMavenBOM,
				Coordinate:         dependency.coordinate,
				SourcePath:         pom.file.relative,
				Dynamic:            dependency.dynamic,
				Reason:             dependency.reason,
			})
		}
		modules = append(modules, specification)
	}
	return modules, diagnostics, nil
}

func linkMavenParents(input repositoryInput, poms map[string]*rawMavenPom, diagnostics *[]Diagnostic) {
	for _, key := range sortedMavenPOMKeys(poms) {
		pom := poms[key]
		if !pom.project.Parent.declared() {
			continue
		}
		if relative, enabled := mavenParentRelativePath(pom); enabled {
			if parent, found := poms[relative]; found && parent != pom {
				pom.parent = parent
				continue
			}
		}
	}

	// Parent coordinates can point to a local POM outside the conventional
	// relative path. Only link a unique raw coordinate; otherwise retain the
	// declaration for normal graph resolution.
	byGA := make(map[string][]*rawMavenPom)
	for _, key := range sortedMavenPOMKeys(poms) {
		pom := poms[key]
		coordinate := rawMavenCoordinate(pom.project)
		if ga := coordinate.ga(); ga != "" {
			byGA[ga] = append(byGA[ga], pom)
		}
	}
	for _, key := range sortedMavenPOMKeys(poms) {
		pom := poms[key]
		if pom.parent != nil || !pom.project.Parent.declared() {
			continue
		}
		parent := resolveMavenParent(pom.project.Parent, pom.project.Properties, Coordinate{})
		candidates := byGA[parent.coordinate.ga()]
		if len(candidates) == 1 && candidates[0] != pom {
			pom.parent = candidates[0]
		}
	}
	_ = input
	_ = diagnostics
}

func mavenParentRelativePath(pom *rawMavenPom) (string, bool) {
	value := "../pom.xml"
	if pom.project.Parent.RelativePath != nil {
		value = strings.TrimSpace(*pom.project.Parent.RelativePath)
		if value == "" {
			return "", false
		}
	}
	candidate := path.Clean(path.Join(pom.directory, filepath.ToSlash(value)))
	if candidate == ".." || strings.HasPrefix(candidate, "../") || path.IsAbs(candidate) {
		return "", false
	}
	if path.Ext(candidate) == "" {
		candidate = path.Join(candidate, "pom.xml")
	}
	return normalizeRelative(candidate), true
}

func rawMavenCoordinate(project mavenProject) Coordinate {
	properties := resolveMavenProperties(nil, project.Properties, nil)
	return resolveMavenCoordinate(mavenDependency{GroupID: project.GroupID, ArtifactID: project.ArtifactID, Version: project.Version}, properties, Coordinate{}, nil).coordinate
}

func (resolver *mavenResolver) resolve(pom *rawMavenPom) mavenEffective {
	if pom.resolved {
		return pom.effective
	}
	if pom.resolving {
		*resolver.diagnostics = append(*resolver.diagnostics, Diagnostic{
			RepositoryID: resolver.input.ID,
			ModuleID:     pom.moduleID,
			Path:         pom.file.relative,
			Code:         "maven_parent_cycle",
			Message:      "Maven parent relation contains a local cycle",
		})
		return mavenEffective{properties: map[string]string{}, managed: map[string]resolvedMavenDependency{}}
	}
	pom.resolving = true
	parent := mavenEffective{properties: map[string]string{}, managed: map[string]resolvedMavenDependency{}}
	if pom.parent != nil {
		parent = resolver.resolve(pom.parent)
	}

	coordinate := parent.coordinate
	properties := resolveMavenProperties(parent.properties, pom.project.Properties, coordinateVariables(coordinate))
	for iteration := 0; iteration < 4; iteration++ {
		coordinate = resolveMavenCoordinate(mavenDependency{
			GroupID:    fallbackString(pom.project.GroupID, parent.coordinate.GroupID),
			ArtifactID: pom.project.ArtifactID,
			Version:    fallbackString(pom.project.Version, parent.coordinate.Version),
		}, properties, parent.coordinate, nil).coordinate
		properties = resolveMavenProperties(parent.properties, pom.project.Properties, coordinateVariables(coordinate))
	}

	managed := make(map[string]resolvedMavenDependency, len(parent.managed)+len(pom.project.DependencyManagement.Dependencies))
	for key, value := range parent.managed {
		managed[key] = value
	}
	boms := make([]resolvedMavenDependency, 0)
	for _, dependency := range pom.project.DependencyManagement.Dependencies {
		resolved := resolveMavenCoordinate(dependency, properties, coordinate, managed)
		if key := resolved.coordinate.ga(); key != "" {
			managed[key] = resolved
		}
		typeValue, typeDynamic := expandMavenValue(dependency.Type, properties, coordinateVariables(coordinate))
		scopeValue, scopeDynamic := expandMavenValue(dependency.Scope, properties, coordinateVariables(coordinate))
		if typeValue == "pom" && scopeValue == "import" {
			resolved.dynamic = resolved.dynamic || typeDynamic || scopeDynamic
			boms = append(boms, resolved)
		}
	}
	dependencies := make([]resolvedMavenDependency, 0, len(pom.project.Dependencies))
	for _, dependency := range pom.project.Dependencies {
		dependencies = append(dependencies, resolveMavenCoordinate(dependency, properties, coordinate, managed))
	}
	pom.effective = mavenEffective{
		coordinate:   coordinate,
		properties:   properties,
		managed:      managed,
		dependencies: dependencies,
		boms:         boms,
	}
	pom.resolving = false
	pom.resolved = true
	return pom.effective
}

func resolveMavenProperties(parent map[string]string, local mavenProperties, variables map[string]string) map[string]string {
	values := make(map[string]string, len(parent)+len(local))
	for key, value := range parent {
		values[key] = value
	}
	for key, value := range local {
		values[key] = value
	}
	for iteration := 0; iteration < 16; iteration++ {
		changed := false
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			expanded, _ := expandMavenValue(values[key], values, variables)
			if expanded != values[key] {
				values[key] = expanded
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return values
}

func coordinateVariables(coordinate Coordinate) map[string]string {
	return map[string]string{
		"project.groupId":    coordinate.GroupID,
		"pom.groupId":        coordinate.GroupID,
		"groupId":            coordinate.GroupID,
		"project.artifactId": coordinate.ArtifactID,
		"pom.artifactId":     coordinate.ArtifactID,
		"artifactId":         coordinate.ArtifactID,
		"project.version":    coordinate.Version,
		"pom.version":        coordinate.Version,
		"version":            coordinate.Version,
	}
}

func resolveMavenParent(parent mavenParent, properties map[string]string, own Coordinate) resolvedMavenDependency {
	return resolveMavenCoordinate(mavenDependency{
		GroupID: parent.GroupID, ArtifactID: parent.ArtifactID, Version: parent.Version,
	}, properties, own, nil)
}

func resolveMavenCoordinate(dependency mavenDependency, properties map[string]string, own Coordinate, managed map[string]resolvedMavenDependency) resolvedMavenDependency {
	variables := coordinateVariables(own)
	groupID, groupDynamic := expandMavenValue(dependency.GroupID, properties, variables)
	artifactID, artifactDynamic := expandMavenValue(dependency.ArtifactID, properties, variables)
	version, versionDynamic := expandMavenValue(dependency.Version, properties, variables)
	coordinate := Coordinate{GroupID: groupID, ArtifactID: artifactID, Version: version}
	dynamic := groupDynamic || artifactDynamic || versionDynamic || mavenDynamicVersion(version)
	if coordinate.Version == "" && coordinate.ga() != "" && managed != nil {
		if managedDependency, found := managed[coordinate.ga()]; found {
			coordinate.Version = managedDependency.coordinate.Version
			dynamic = dynamic || managedDependency.dynamic
		}
	}
	reason := ""
	if coordinate.GroupID == "" || coordinate.ArtifactID == "" {
		reason = "Maven dependency is missing groupId or artifactId"
	} else if strings.Contains(coordinate.GroupID, "${") || strings.Contains(coordinate.ArtifactID, "${") || strings.Contains(coordinate.Version, "${") {
		reason = "Maven dependency contains an unresolved property"
	} else if coordinate.Version == "" {
		reason = "Maven dependency version is not declared or locally managed"
	}
	return resolvedMavenDependency{coordinate: coordinate, dynamic: dynamic, reason: reason}
}

func expandMavenValue(value string, properties map[string]string, variables map[string]string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	for iteration := 0; iteration < 16; iteration++ {
		changed := false
		value = mavenPropertyPattern.ReplaceAllStringFunc(value, func(match string) string {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(match, "${"), "}"))
			if replacement, found := properties[name]; found && replacement != match {
				changed = true
				return replacement
			}
			if replacement, found := variables[name]; found && replacement != match {
				changed = true
				return replacement
			}
			return match
		})
		if !changed {
			break
		}
	}
	return strings.TrimSpace(value), strings.Contains(value, "${")
}

func mavenDynamicVersion(version string) bool {
	upper := strings.ToUpper(strings.TrimSpace(version))
	return strings.Contains(version, "${") || strings.Contains(version, "+") || strings.ContainsAny(version, "[]()") || upper == "LATEST" || upper == "RELEASE"
}

func validateMavenModules(input repositoryInput, poms map[string]*rawMavenPom, diagnostics *[]Diagnostic) {
	for _, key := range sortedMavenPOMKeys(poms) {
		pom := poms[key]
		for _, value := range pom.project.Modules {
			candidate := path.Clean(path.Join(pom.directory, strings.TrimSpace(filepath.ToSlash(value))))
			if candidate == ".." || strings.HasPrefix(candidate, "../") || path.IsAbs(candidate) {
				*diagnostics = append(*diagnostics, Diagnostic{
					RepositoryID: input.ID,
					ModuleID:     pom.moduleID,
					Path:         pom.file.relative,
					Code:         "maven_module_outside_repository",
					Message:      "Maven module path escapes repository boundary",
				})
				continue
			}
			if path.Ext(candidate) == "" {
				candidate = path.Join(candidate, "pom.xml")
			}
			candidate = normalizeRelative(candidate)
			if _, found := poms[candidate]; !found {
				*diagnostics = append(*diagnostics, Diagnostic{
					RepositoryID: input.ID,
					ModuleID:     pom.moduleID,
					Path:         pom.file.relative,
					Code:         "maven_module_not_found",
					Message:      "declared Maven module has no readable pom.xml",
				})
			}
		}
	}
}

func sortedMavenPOMKeys(poms map[string]*rawMavenPom) []string {
	keys := make([]string, 0, len(poms))
	for key := range poms {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func fallbackString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

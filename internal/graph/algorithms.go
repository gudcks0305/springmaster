package graph

import (
	"sort"
	"strings"
)

func findCycleGroups(modules []Module, dependencies []Dependency) []CycleGroup {
	vertices := make([]string, 0, len(modules))
	owners := make(map[string]string, len(modules))
	for _, module := range modules {
		vertices = append(vertices, module.ID)
		owners[module.ID] = module.RepositoryID
	}
	adjacency := localModuleAdjacency(vertices, dependencies)
	groups := make([]CycleGroup, 0)
	for _, component := range stronglyConnected(vertices, adjacency) {
		if len(component) == 1 {
			selfCycle := false
			for _, target := range adjacency[component[0]] {
				if target == component[0] {
					selfCycle = true
					break
				}
			}
			if !selfCycle {
				continue
			}
		}
		repositories := make(map[string]struct{})
		for _, moduleID := range component {
			repositories[owners[moduleID]] = struct{}{}
		}
		groups = append(groups, CycleGroup{ModuleIDs: component, RepositoryIDs: sortedSet(repositories)})
	}
	sort.Slice(groups, func(left, right int) bool {
		return strings.Join(groups[left].ModuleIDs, "\x00") < strings.Join(groups[right].ModuleIDs, "\x00")
	})
	return groups
}

func dependencyFirstRepositoryOrder(repositories []Repository, dependencies []Dependency) []string {
	vertices := make([]string, 0, len(repositories))
	for _, repository := range repositories {
		vertices = append(vertices, repository.ID)
	}
	adjacency := make(map[string][]string, len(vertices))
	for _, repositoryID := range vertices {
		adjacency[repositoryID] = nil
	}
	for _, dependency := range dependencies {
		if dependency.Resolution != ResolutionLocal || dependency.SourceRepositoryID == dependency.TargetRepositoryID || dependency.TargetRepositoryID == "" {
			continue
		}
		adjacency[dependency.SourceRepositoryID] = append(adjacency[dependency.SourceRepositoryID], dependency.TargetRepositoryID)
	}
	return dependencyFirstCondensedOrder(vertices, adjacency)
}

func localModuleAdjacency(vertices []string, dependencies []Dependency) map[string][]string {
	adjacency := make(map[string][]string, len(vertices))
	for _, vertex := range vertices {
		adjacency[vertex] = nil
	}
	for _, dependency := range dependencies {
		if dependency.Resolution != ResolutionLocal || dependency.TargetModuleID == "" {
			continue
		}
		adjacency[dependency.SourceModuleID] = append(adjacency[dependency.SourceModuleID], dependency.TargetModuleID)
	}
	for vertex, targets := range adjacency {
		adjacency[vertex] = uniqueSorted(targets)
	}
	return adjacency
}

// stronglyConnected uses sorted Tarjan traversal, making component membership
// and output stable across input order and map iteration.
func stronglyConnected(vertices []string, adjacency map[string][]string) [][]string {
	vertices = append([]string(nil), vertices...)
	sort.Strings(vertices)
	index := 0
	indices := make(map[string]int, len(vertices))
	lowlink := make(map[string]int, len(vertices))
	onStack := make(map[string]bool, len(vertices))
	stack := make([]string, 0, len(vertices))
	components := make([][]string, 0)
	var visit func(string)
	visit = func(vertex string) {
		index++
		indices[vertex] = index
		lowlink[vertex] = index
		stack = append(stack, vertex)
		onStack[vertex] = true
		for _, target := range uniqueSorted(adjacency[vertex]) {
			if _, known := indices[target]; !known {
				visit(target)
				if lowlink[target] < lowlink[vertex] {
					lowlink[vertex] = lowlink[target]
				}
			} else if onStack[target] && indices[target] < lowlink[vertex] {
				lowlink[vertex] = indices[target]
			}
		}
		if lowlink[vertex] != indices[vertex] {
			return
		}
		component := make([]string, 0)
		for {
			last := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[last] = false
			component = append(component, last)
			if last == vertex {
				break
			}
		}
		sort.Strings(component)
		components = append(components, component)
	}
	for _, vertex := range vertices {
		if _, known := indices[vertex]; !known {
			visit(vertex)
		}
	}
	sort.Slice(components, func(left, right int) bool {
		return strings.Join(components[left], "\x00") < strings.Join(components[right], "\x00")
	})
	return components
}

func dependencyFirstCondensedOrder(vertices []string, adjacency map[string][]string) []string {
	components := stronglyConnected(vertices, adjacency)
	componentOf := make(map[string]int, len(vertices))
	for index, component := range components {
		for _, vertex := range component {
			componentOf[vertex] = index
		}
	}
	dependenciesByComponent := make([]map[int]struct{}, len(components))
	reverse := make([]map[int]struct{}, len(components))
	for index := range components {
		dependenciesByComponent[index] = make(map[int]struct{})
		reverse[index] = make(map[int]struct{})
	}
	for source, targets := range adjacency {
		for _, target := range targets {
			sourceComponent, targetComponent := componentOf[source], componentOf[target]
			if sourceComponent == targetComponent {
				continue
			}
			dependenciesByComponent[sourceComponent][targetComponent] = struct{}{}
			reverse[targetComponent][sourceComponent] = struct{}{}
		}
	}
	ready := make([]int, 0)
	for index, dependencies := range dependenciesByComponent {
		if len(dependencies) == 0 {
			ready = append(ready, index)
		}
	}
	order := make([]string, 0, len(vertices))
	processed := make(map[int]struct{}, len(components))
	for len(ready) > 0 {
		sort.Slice(ready, func(left, right int) bool {
			return componentKey(components[ready[left]]) < componentKey(components[ready[right]])
		})
		componentIndex := ready[0]
		ready = ready[1:]
		if _, done := processed[componentIndex]; done {
			continue
		}
		processed[componentIndex] = struct{}{}
		order = append(order, components[componentIndex]...)
		for _, dependent := range sortedIntSet(reverse[componentIndex]) {
			delete(dependenciesByComponent[dependent], componentIndex)
			if len(dependenciesByComponent[dependent]) == 0 {
				ready = append(ready, dependent)
			}
		}
	}
	// Condensation is acyclic, but append deterministically if a malformed edge
	// referred to a vertex outside the supplied set.
	if len(order) != len(vertices) {
		seen := make(map[string]struct{}, len(order))
		for _, value := range order {
			seen[value] = struct{}{}
		}
		for _, value := range vertices {
			if _, found := seen[value]; !found {
				order = append(order, value)
			}
		}
	}
	return order
}

func calculateEffectiveHashes(repositories []Repository, modules []Module, dependencies []Dependency) (map[string]string, map[string]string) {
	moduleHashes := make(map[string]string, len(modules))
	contentByRepository := make(map[string]string, len(repositories))
	for _, repository := range repositories {
		contentByRepository[repository.ID] = repository.ContentHash
	}
	vertices := make([]string, 0, len(modules))
	moduleByID := make(map[string]Module, len(modules))
	for _, module := range modules {
		vertices = append(vertices, module.ID)
		moduleByID[module.ID] = module
	}
	adjacency := localModuleAdjacency(vertices, dependencies)
	components := stronglyConnected(vertices, adjacency)
	componentOf := make(map[string]int, len(vertices))
	for index, component := range components {
		for _, moduleID := range component {
			componentOf[moduleID] = index
		}
	}
	componentDependencies := make([]map[int]struct{}, len(components))
	componentDependents := make([]map[int]struct{}, len(components))
	for index := range components {
		componentDependencies[index] = make(map[int]struct{})
		componentDependents[index] = make(map[int]struct{})
	}
	for source, targets := range adjacency {
		for _, target := range targets {
			sourceComponent, targetComponent := componentOf[source], componentOf[target]
			if sourceComponent != targetComponent {
				componentDependencies[sourceComponent][targetComponent] = struct{}{}
				componentDependents[targetComponent][sourceComponent] = struct{}{}
			}
		}
	}
	remainingDependencies := make([]map[int]struct{}, len(componentDependencies))
	for index, dependencies := range componentDependencies {
		remainingDependencies[index] = make(map[int]struct{}, len(dependencies))
		for dependency := range dependencies {
			remainingDependencies[index][dependency] = struct{}{}
		}
	}
	ready := make([]int, 0)
	for index := range components {
		if len(remainingDependencies[index]) == 0 {
			ready = append(ready, index)
		}
	}
	componentHashes := make(map[int]string, len(components))
	for len(ready) > 0 {
		sort.Slice(ready, func(left, right int) bool {
			return componentKey(components[ready[left]]) < componentKey(components[ready[right]])
		})
		componentIndex := ready[0]
		ready = ready[1:]
		parts := []string{effectiveHashVersion, "component"}
		for _, moduleID := range components[componentIndex] {
			module := moduleByID[moduleID]
			parts = append(parts, moduleID, module.RepositoryID, contentByRepository[module.RepositoryID], module.Coordinate.String(), string(module.BuildSystem))
		}
		dependencyHashes := make([]string, 0, len(componentDependencies[componentIndex]))
		for _, dependency := range sortedIntSet(componentDependencies[componentIndex]) {
			dependencyHashes = append(dependencyHashes, componentKey(components[dependency]), componentHashes[dependency])
		}
		parts = append(parts, dependencyHashes...)
		componentHashes[componentIndex] = hashParts(parts...)
		for _, moduleID := range components[componentIndex] {
			moduleHashes[moduleID] = hashParts(effectiveHashVersion, "module", moduleID, componentHashes[componentIndex])
		}
		for _, dependent := range sortedIntSet(componentDependents[componentIndex]) {
			delete(remainingDependencies[dependent], componentIndex)
			if len(remainingDependencies[dependent]) == 0 {
				ready = append(ready, dependent)
			}
		}
	}

	repositoryHashes := make(map[string]string, len(repositories))
	modulesByRepository := make(map[string][]string, len(repositories))
	for _, module := range modules {
		modulesByRepository[module.RepositoryID] = append(modulesByRepository[module.RepositoryID], module.ID)
	}
	for _, repository := range repositories {
		moduleIDs := modulesByRepository[repository.ID]
		sort.Strings(moduleIDs)
		parts := []string{effectiveHashVersion, "repository", repository.ID, repository.ContentHash}
		for _, moduleID := range moduleIDs {
			parts = append(parts, moduleID, moduleHashes[moduleID])
		}
		repositoryHashes[repository.ID] = hashParts(parts...)
	}
	return moduleHashes, repositoryHashes
}

func componentKey(component []string) string {
	return strings.Join(component, "\x00")
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	values = append([]string(nil), values...)
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func sortedIntSet(values map[int]struct{}) []int {
	result := make([]int, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

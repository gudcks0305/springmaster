package graph

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type descriptorFile struct {
	absolute string
	relative string
	contents string
}

type descriptorFiles struct {
	byRelative map[string]descriptorFile
}

func (files descriptorFiles) named(names ...string) []descriptorFile {
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[name] = struct{}{}
	}
	result := make([]descriptorFile, 0)
	for _, file := range files.byRelative {
		if _, found := wanted[filepath.Base(file.relative)]; found {
			result = append(result, file)
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].relative < result[right].relative })
	return result
}

func (files descriptorFiles) versionCatalogs() []descriptorFile {
	result := make([]descriptorFile, 0)
	for _, file := range files.byRelative {
		base := filepath.Base(file.relative)
		if base == "libs.versions.toml" || strings.HasSuffix(base, ".versions.toml") {
			result = append(result, file)
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].relative < result[right].relative })
	return result
}

func (files descriptorFiles) at(relative string) (descriptorFile, bool) {
	file, found := files.byRelative[normalizeRelative(relative)]
	return file, found
}

func (files descriptorFiles) nearest(relativeDirectory string, name string) (descriptorFile, bool) {
	directory := normalizeRelative(relativeDirectory)
	for {
		candidate := name
		if directory != "." {
			candidate = directory + "/" + name
		}
		if file, found := files.at(candidate); found {
			return file, true
		}
		if directory == "." {
			return descriptorFile{}, false
		}
		directory = normalizeRelative(filepath.Dir(directory))
	}
}

func discoverDescriptorFiles(ctx context.Context, input repositoryInput, options Options) (descriptorFiles, []Diagnostic, error) {
	files := descriptorFiles{byRelative: make(map[string]descriptorFile)}
	diagnostics := make([]Diagnostic, 0)
	var totalBytes int64
	entries := 0
	maxEntries := options.MaxFiles * 32
	if maxEntries < 1_024 {
		maxEntries = 1_024
	}

	err := filepath.WalkDir(input.root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			diagnostics = append(diagnostics, Diagnostic{
				RepositoryID: input.ID,
				Path:         displayPath(input.root, current),
				Code:         "descriptor_walk_error",
				Message:      "cannot inspect descriptor path",
			})
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > maxEntries {
			diagnostics = append(diagnostics, Diagnostic{
				RepositoryID: input.ID,
				Code:         "descriptor_walk_limit",
				Message:      fmt.Sprintf("descriptor walk stopped after %d entries", maxEntries),
			})
			return fs.SkipAll
		}
		if entry.IsDir() {
			if current != input.root && ignoredDescriptorDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || !isDescriptorName(entry.Name()) {
			return nil
		}
		if len(files.byRelative) >= options.MaxFiles {
			diagnostics = append(diagnostics, Diagnostic{
				RepositoryID: input.ID,
				Code:         "descriptor_file_limit",
				Message:      fmt.Sprintf("descriptor read limit reached at %d files", options.MaxFiles),
			})
			return fs.SkipAll
		}
		contents, status, err := readDescriptorFile(ctx, current, options.MaxFileBytes, options.MaxTotalBytes, &totalBytes)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			diagnostics = append(diagnostics, Diagnostic{
				RepositoryID: input.ID,
				Path:         displayPath(input.root, current),
				Code:         "descriptor_read_failed",
				Message:      "cannot read descriptor file",
			})
			return nil
		}
		if status != "" {
			diagnostics = append(diagnostics, Diagnostic{
				RepositoryID: input.ID,
				Path:         displayPath(input.root, current),
				Code:         status,
				Message:      descriptorLimitMessage(status),
			})
			return nil
		}
		relative, relErr := filepath.Rel(input.root, current)
		if relErr != nil {
			return relErr
		}
		relative = normalizeRelative(relative)
		files.byRelative[relative] = descriptorFile{absolute: current, relative: relative, contents: string(contents)}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return descriptorFiles{}, diagnostics, ctx.Err()
		}
		return descriptorFiles{}, diagnostics, fmt.Errorf("walk descriptors in %s: %w", input.Path, err)
	}
	return files, diagnostics, nil
}

func readDescriptorFile(ctx context.Context, name string, maxFileBytes, maxTotalBytes int64, totalBytes *int64) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	info, err := os.Stat(name)
	if err != nil {
		return nil, "", err
	}
	if info.Size() > maxFileBytes {
		return nil, "descriptor_file_too_large", nil
	}
	if *totalBytes+info.Size() > maxTotalBytes {
		return nil, "descriptor_total_byte_limit", nil
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(contents)) > maxFileBytes {
		return nil, "descriptor_file_too_large", nil
	}
	if *totalBytes+int64(len(contents)) > maxTotalBytes {
		return nil, "descriptor_total_byte_limit", nil
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	*totalBytes += int64(len(contents))
	return contents, "", nil
}

func descriptorLimitMessage(code string) string {
	switch code {
	case "descriptor_file_too_large":
		return "descriptor file exceeds configured byte limit"
	case "descriptor_total_byte_limit":
		return "descriptor file skipped because repository byte limit was reached"
	default:
		return "descriptor file skipped due to configured limit"
	}
}

func isDescriptorName(name string) bool {
	switch name {
	case "pom.xml", "settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts", "gradle.properties":
		return true
	default:
		return name == "libs.versions.toml" || strings.HasSuffix(name, ".versions.toml")
	}
}

func ignoredDescriptorDirectory(name string) bool {
	switch name {
	case ".git", ".gradle", "build", "target", "node_modules", ".idea", ".svn":
		return true
	default:
		return false
	}
}

func normalizeRelative(value string) string {
	value = filepath.ToSlash(filepath.Clean(value))
	if value == "" || value == "/" {
		return "."
	}
	return value
}

func displayPath(root, current string) string {
	relative, err := filepath.Rel(root, current)
	if err != nil {
		return ""
	}
	return normalizeRelative(relative)
}
